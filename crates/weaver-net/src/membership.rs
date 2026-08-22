use std::sync::Arc;

use iroh::SecretKey;
use thiserror::Error;
use weaver_config::{ChainExpectation, EncryptedConfigEnvelope, MemberEncryptionKeypair};
use weaver_core::NetworkId;
use weaver_crypto::{
    AdminCertificate, MemberCertificate, MemberRoles, NetworkRootPublic, PreparedJoinRequest,
    SigningKeypair,
};
use weaver_relay_core::JoinTicket;
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
