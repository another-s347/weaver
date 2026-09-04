use std::{sync::Arc, time::Duration};

use futures_util::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, RelayMode, RelayUrl, SecretKey, TransportAddr, endpoint::presets,
};
use iroh_relay::{RelayConfig, RelayMap};
use thiserror::Error;
use weaver_config::{ChainExpectation, EncryptedConfigEnvelope, MemberEncryptionKeypair};
use weaver_core::NetworkId;
use weaver_crypto::{
    AdminCertificate, MemberCertificate, MemberRoles, NetworkRootPublic, PreparedJoinRequest,
    SigningKeypair,
};
use weaver_relay_core::{
    BootstrapRedeemRequest, BootstrapRedeemResponse, BootstrapRejectCode, InvitationBundle,
    JoinTicket, bootstrap_alpn,
};
use weaver_store::{
    AtomicBatch, ExpectedVersion, SecretBytes, SecretProtection, SecretStore, SecretStoreError,
    StateStore, StoreError, StoreKey, StoreScope,
};

use crate::{
    CONFIG_ENVELOPE_KEY, CONFIG_HEAD_KEY, CONFIG_SIGNER_CERTIFICATE_KEY, encode_config_head,
    member_secret_id,
};

pub const KEY_PREPARED_JOIN: &[u8] = b"join/prepared/v1";
pub const KEY_MEMBER_CERTIFICATE: &[u8] = b"membership/certificate/v1";
pub const KEY_ENDPOINT_BINDING: &[u8] = b"membership/endpoint-binding/v1";

#[derive(Clone)]
pub struct MembershipStores {
    pub state: Arc<dyn StateStore>,
    pub secrets: Arc<dyn SecretStore>,
    pub allow_insecure_test_stores: bool,
}

pub struct NetworkMembership;

impl NetworkMembership {
    /// Removes only Weaver membership/config state and member secrets for one network.
    /// Application databases and authentication sessions are outside this namespace.
    pub async fn reset(
        stores: &MembershipStores,
        network_id: NetworkId,
    ) -> Result<(), MembershipError> {
        validate_stores(stores)?;
        let scope = StoreScope::member(network_id);
        let mut entries = stores.state.scan_prefix(scope, b"").await?;
        let mut batch = AtomicBatch::new(scope);
        while let Some(entry) = entries.next().await {
            let entry = entry?;
            batch.delete(entry.key, ExpectedVersion::Exact(entry.value.version))?;
        }
        if !batch.is_empty() {
            stores.state.commit(batch).await?;
        }
        for label in [
            b"member-signing".as_slice(),
            b"member-encryption",
            b"endpoint",
        ] {
            match stores
                .secrets
                .delete(&member_secret_id(network_id, label))
                .await
            {
                Ok(()) | Err(SecretStoreError::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    /// Redeems a signed one-time invitation over the restricted bootstrap ALPN and
    /// atomically commits the returned membership. A retry reuses the same prepared
    /// request and endpoint identity, allowing the authority to return the same ticket.
    pub async fn redeem_invitation(
        stores: &MembershipStores,
        expected_root: &NetworkRootPublic,
        invitation: &InvitationBundle,
        now_ms: u64,
        timeout: Duration,
    ) -> Result<weaver_config::ConfigHead, MembershipError> {
        validate_stores(stores)?;
        invitation.verify(expected_root, now_ms)?;
        if invitation.network_id != expected_root.network_id() {
            return Err(MembershipError::BootstrapRejected(
                BootstrapRejectCode::Invalid,
            ));
        }
        let prepared = Self::prepare_join(
            stores,
            invitation.network_id,
            MemberRoles::MEMBER,
            invitation.expires_at_ms,
        )
        .await?;
        let endpoint_secret = load_endpoint(stores, invitation.network_id).await?;
        let relay_url = invitation
            .bootstrap_relay
            .as_deref()
            .map(str::parse::<RelayUrl>)
            .transpose()
            .map_err(|error| MembershipError::Bootstrap(error.to_string()))?;
        let relay_mode = match relay_url.clone() {
            Some(url) => RelayMode::Custom(
                std::iter::once(RelayConfig::new(url, None)).collect::<RelayMap>(),
            ),
            None => RelayMode::Disabled,
        };
        let endpoint = Endpoint::builder(presets::N0)
            .clear_address_lookup()
            .secret_key(endpoint_secret)
            .relay_mode(relay_mode)
            .bind()
            .await
            .map_err(|error| MembershipError::Bootstrap(error.to_string()))?;
        let endpoint_id = iroh::EndpointId::from_bytes(&invitation.bootstrap_endpoint_id)
            .map_err(|error| MembershipError::Bootstrap(error.to_string()))?;
        let transports = invitation
            .bootstrap_direct_addresses
            .iter()
            .copied()
            .map(TransportAddr::Ip)
            .chain(relay_url.map(TransportAddr::Relay));
        let target = EndpointAddr::from_parts(endpoint_id, transports);
        let request = BootstrapRedeemRequest {
            invitation: invitation.clone(),
            prepared,
        }
        .to_bytes()?;
        let exchange = async {
            let connection = endpoint
                .connect(target, &bootstrap_alpn(invitation.network_id))
                .await
                .map_err(|error| MembershipError::Bootstrap(error.to_string()))?;
            if connection.remote_id() != endpoint_id {
                return Err(MembershipError::Bootstrap(
                    "bootstrap endpoint identity mismatch".to_string(),
                ));
            }
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|error| MembershipError::Bootstrap(error.to_string()))?;
            send.write_all(&request)
                .await
                .map_err(|error| MembershipError::Bootstrap(error.to_string()))?;
            send.finish()
                .map_err(|error| MembershipError::Bootstrap(error.to_string()))?;
            let response = recv
                .read_to_end(1024 * 1024)
                .await
                .map_err(|error| MembershipError::Bootstrap(error.to_string()))?;
            BootstrapRedeemResponse::from_bytes(&response).map_err(MembershipError::from)
        };
        let response = tokio::time::timeout(timeout, exchange)
            .await
            .map_err(|_| MembershipError::Bootstrap("bootstrap request timed out".to_string()))??;
        endpoint.close().await;
        match response {
            BootstrapRedeemResponse::Accepted(ticket) => {
                Self::join(stores, expected_root, &ticket, wall_now_ms()).await
            }
            BootstrapRedeemResponse::Rejected(code) => {
                Err(MembershipError::BootstrapRejected(code))
            }
        }
    }

    /// Creates or resumes a crash-safe join request. Secrets are persisted before the
    /// request references them, and a retry reconstructs the same member identities.
    pub async fn prepare_join(
        stores: &MembershipStores,
        network_id: NetworkId,
        roles: MemberRoles,
        expires_at_ms: u64,
    ) -> Result<PreparedJoinRequest, MembershipError> {
        validate_stores(stores)?;
        let scope = StoreScope::member(network_id);
        if stores
            .state
            .read(scope, &StoreKey::new(CONFIG_HEAD_KEY)?)
            .await?
            .is_some()
        {
            return Err(MembershipError::AlreadyJoined);
        }
        let prepared_key = StoreKey::new(KEY_PREPARED_JOIN)?;
        if let Some(record) = stores.state.read(scope, &prepared_key).await? {
            return Ok(PreparedJoinRequest::from_bytes(&record.bytes)?);
        }

        let signing = load_or_create_signing(stores, network_id).await?;
        let encryption = load_or_create_encryption(stores, network_id).await?;
        let endpoint = load_or_create_endpoint(stores, network_id).await?;
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| MembershipError::RandomnessUnavailable)?;
        let prepared = PreparedJoinRequest::create(
            network_id,
            &signing,
            encryption.public_bytes(),
            *endpoint.public().as_bytes(),
            nonce,
            roles,
            expires_at_ms,
        )?;
        let mut batch = AtomicBatch::new(scope);
        batch.put(prepared_key, prepared.to_bytes(), ExpectedVersion::Missing)?;
        match stores.state.commit(batch).await {
            Ok(_) => Ok(prepared),
            Err(StoreError::VersionConflict { .. }) => stores
                .state
                .read(scope, &StoreKey::new(KEY_PREPARED_JOIN)?)
                .await?
                .ok_or(MembershipError::NotPrepared)
                .and_then(|record| {
                    PreparedJoinRequest::from_bytes(&record.bytes).map_err(MembershipError::from)
                }),
            Err(error) => Err(error.into()),
        }
    }

    /// Verifies a relay-issued ticket and atomically consumes the local prepared request.
    pub async fn join(
        stores: &MembershipStores,
        root: &NetworkRootPublic,
        ticket: &JoinTicket,
        now_ms: u64,
    ) -> Result<weaver_config::ConfigHead, MembershipError> {
        validate_stores(stores)?;
        let network_id = root.network_id();
        let scope = StoreScope::member(network_id);
        let prepared_key = StoreKey::new(KEY_PREPARED_JOIN)?;
        let prepared_record = stores
            .state
            .read(scope, &prepared_key)
            .await?
            .ok_or(MembershipError::NotPrepared)?;
        let prepared = PreparedJoinRequest::from_bytes(&prepared_record.bytes)?;
        let request = prepared.verify(network_id, now_ms)?;
        ticket.verify(
            root,
            network_id,
            request.payload().nonce,
            request.payload().endpoint_id,
            now_ms,
        )?;

        let encryption = load_encryption(stores, network_id).await?;
        if encryption.public_bytes() != request.payload().encryption_public_key {
            return Err(MembershipError::SecretMismatch("member encryption"));
        }
        let endpoint = load_endpoint(stores, network_id).await?;
        if endpoint.public().as_bytes() != &request.payload().endpoint_id {
            return Err(MembershipError::SecretMismatch("endpoint"));
        }
        let signing = load_signing(stores, network_id).await?;
        if signing.public_bytes() != request.payload().signing_public_key {
            return Err(MembershipError::SecretMismatch("member signing"));
        }

        let admin_certificate = AdminCertificate::from_bytes(&ticket.admin_certificate)?;
        let admin = admin_certificate.verify(root, network_id, now_ms, &Default::default())?;
        let envelope = EncryptedConfigEnvelope::from_bytes(&ticket.embedded_config)?;
        let opened = envelope.open_config_with_verified_admin(
            root,
            &admin,
            &encryption,
            ChainExpectation::Checkpoint(ticket.config_head),
            now_ms,
        )?;
        let member = MemberCertificate::from_bytes(&ticket.member_certificate)?;
        if member.payload().member_id != request.payload().member_id
            || member.payload().signing_public_key != request.payload().signing_public_key
            || member.payload().encryption_public_key != request.payload().encryption_public_key
        {
            return Err(MembershipError::TicketMemberMismatch);
        }

        let mut batch = AtomicBatch::new(scope);
        batch.put(
            StoreKey::new(CONFIG_ENVELOPE_KEY)?,
            ticket.embedded_config.clone(),
            ExpectedVersion::Missing,
        )?;
        batch.put(
            StoreKey::new(CONFIG_HEAD_KEY)?,
            encode_config_head(opened.head),
            ExpectedVersion::Missing,
        )?;
        batch.put(
            StoreKey::new(CONFIG_SIGNER_CERTIFICATE_KEY)?,
            ticket.admin_certificate.clone(),
            ExpectedVersion::Missing,
        )?;
        batch.put(
            StoreKey::new(KEY_MEMBER_CERTIFICATE)?,
            ticket.member_certificate.clone(),
            ExpectedVersion::Missing,
        )?;
        batch.put(
            StoreKey::new(KEY_ENDPOINT_BINDING)?,
            ticket.endpoint_binding.clone(),
            ExpectedVersion::Missing,
        )?;
        batch.delete(
            prepared_key,
            ExpectedVersion::Exact(prepared_record.version),
        )?;
        stores.state.commit(batch).await?;
        Ok(opened.head)
    }
}

fn wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

async fn load_or_create_signing(
    stores: &MembershipStores,
    network_id: NetworkId,
) -> Result<SigningKeypair, MembershipError> {
    match load_secret_32(stores, network_id, b"member-signing").await {
        Ok(bytes) => Ok(SigningKeypair::from_bytes(&bytes)),
        Err(MembershipError::Secret(SecretStoreError::NotFound)) => {
            let key = SigningKeypair::generate()?;
            match seal(stores, network_id, b"member-signing", key.to_bytes()).await {
                Ok(()) => Ok(key),
                Err(MembershipError::Secret(SecretStoreError::AlreadyExistsDifferent)) => {
                    load_signing(stores, network_id).await
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

async fn load_or_create_encryption(
    stores: &MembershipStores,
    network_id: NetworkId,
) -> Result<MemberEncryptionKeypair, MembershipError> {
    match load_secret_32(stores, network_id, b"member-encryption").await {
        Ok(bytes) => Ok(MemberEncryptionKeypair::from_secret_bytes(bytes)?),
        Err(MembershipError::Secret(SecretStoreError::NotFound)) => {
            let key = MemberEncryptionKeypair::generate()?;
            match seal(stores, network_id, b"member-encryption", key.secret_bytes()).await {
                Ok(()) => Ok(key),
                Err(MembershipError::Secret(SecretStoreError::AlreadyExistsDifferent)) => {
                    load_encryption(stores, network_id).await
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

async fn load_or_create_endpoint(
    stores: &MembershipStores,
    network_id: NetworkId,
) -> Result<SecretKey, MembershipError> {
    match load_secret_32(stores, network_id, b"endpoint").await {
        Ok(bytes) => Ok(SecretKey::from_bytes(&bytes)),
        Err(MembershipError::Secret(SecretStoreError::NotFound)) => {
            let key = SecretKey::generate();
            match seal(stores, network_id, b"endpoint", key.to_bytes()).await {
                Ok(()) => Ok(key),
                Err(MembershipError::Secret(SecretStoreError::AlreadyExistsDifferent)) => {
                    load_endpoint(stores, network_id).await
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

async fn load_signing(
    stores: &MembershipStores,
    network_id: NetworkId,
) -> Result<SigningKeypair, MembershipError> {
    Ok(SigningKeypair::from_bytes(
        &load_secret_32(stores, network_id, b"member-signing").await?,
    ))
}

async fn load_encryption(
    stores: &MembershipStores,
    network_id: NetworkId,
) -> Result<MemberEncryptionKeypair, MembershipError> {
    Ok(MemberEncryptionKeypair::from_secret_bytes(
        load_secret_32(stores, network_id, b"member-encryption").await?,
    )?)
}

async fn load_endpoint(
    stores: &MembershipStores,
    network_id: NetworkId,
) -> Result<SecretKey, MembershipError> {
    Ok(SecretKey::from_bytes(
        &load_secret_32(stores, network_id, b"endpoint").await?,
    ))
}

async fn load_secret_32(
    stores: &MembershipStores,
    network_id: NetworkId,
    label: &[u8],
) -> Result<[u8; 32], MembershipError> {
    stores
        .secrets
        .open(&member_secret_id(network_id, label))
        .await?
        .expose()
        .try_into()
        .map_err(|_| MembershipError::CorruptSecret)
}

async fn seal(
    stores: &MembershipStores,
    network_id: NetworkId,
    label: &[u8],
    bytes: [u8; 32],
) -> Result<(), MembershipError> {
    stores
        .secrets
        .seal(
            member_secret_id(network_id, label),
            SecretBytes::new(bytes.to_vec()),
        )
        .await?;
    Ok(())
}

fn validate_stores(stores: &MembershipStores) -> Result<(), MembershipError> {
    let state = stores.state.capabilities();
    if !state.atomic_batches
        || (!state.durable_commits && !stores.allow_insecure_test_stores)
        || (stores.secrets.protection() == SecretProtection::InMemoryTestOnly
            && !stores.allow_insecure_test_stores)
    {
        return Err(MembershipError::InsecureStoreCapabilities);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum MembershipError {
    #[error("state/secret stores do not provide required production capabilities")]
    InsecureStoreCapabilities,
    #[error("this node is already joined to the network")]
    AlreadyJoined,
    #[error("no prepared join request exists for this network")]
    NotPrepared,
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("stored secret is corrupt")]
    CorruptSecret,
    #[error("stored {0} secret differs from the prepared request")]
    SecretMismatch(&'static str),
    #[error("ticket member certificate differs from the prepared request")]
    TicketMemberMismatch,
    #[error("bootstrap transport failed: {0}")]
    Bootstrap(String),
    #[error("bootstrap authority rejected the invitation: {0:?}")]
    BootstrapRejected(BootstrapRejectCode),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Secret(#[from] SecretStoreError),
    #[error(transparent)]
    Crypto(#[from] weaver_crypto::CertificateError),
    #[error(transparent)]
    Config(#[from] weaver_config::ConfigError),
    #[error(transparent)]
    Authority(#[from] weaver_relay_core::AuthorityError),
}
