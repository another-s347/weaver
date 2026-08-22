//! Persistent authority state owned by the standalone Weaver relay.

use std::{
    collections::HashSet,
    fmt,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use bytes::Bytes;
use iroh::SecretKey as EndpointSecretKey;
use thiserror::Error;
use weaver_config::{
    AdminKey, ChainExpectation, ConfigHead, ConfigUpdateBatch, EncryptedConfigEnvelope,
    EpochSecrets, MemberEncryptionKeypair, NetworkConfigV1, NetworkPolicy,
    PresenceServiceDescriptor, RelayDescriptor, RelayRoles, ValidatedNetworkConfig,
};
use weaver_core::MemberId;
use weaver_core::NetworkId;
use weaver_crypto::{
    AdminCertificate, AppBinding, AppRegistration, AppRegistrationRequest, EndpointBinding,
    JoinRequest, JoinRequestPayload, MemberCertificate, MemberRoles, NetworkRootKey,
    NetworkRootPublic, OnlineAdminKey, SigningKeypair, VerifiedAdmin,
};
use weaver_store::{
    AtomicBatch, EncryptedFileSecretStore, ExpectedVersion, RedbStateStore, SecretBytes, SecretId,
    SecretStore, SecretStoreError, StateStore, StoreError, StoreKey, StoreScope,
};

const MANIFEST_MAGIC: &[u8; 8] = b"WVRATH\0\x01";
const MANIFEST_FIXED_LEN: usize = 8 + 32 + 32 + 32 + 2;
const KEY_ENVELOPE: &[u8] = b"authority/config/envelope/v1";
const KEY_HEAD: &[u8] = b"authority/config/head/v1";
const KEY_HISTORY_PREFIX: &[u8] = b"authority/config/history/v1/";
const HEAD_LEN: usize = 8 + 8 + 32;
const JOIN_TICKET_MAGIC: &[u8; 8] = b"WVRTKT\0\x01";
const SIGNATURE_LEN: usize = 64;

#[derive(Clone)]
pub struct AuthorityInit {
    pub data_dir: PathBuf,
    pub relay_url: String,
    pub now_ms: u64,
    pub valid_for_ms: u64,
    pub master_key: [u8; 32],
    pub recovery_root_out: Option<PathBuf>,
}

impl fmt::Debug for AuthorityInit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorityInit")
            .field("data_dir", &self.data_dir)
            .field("relay_url", &self.relay_url)
            .field("now_ms", &self.now_ms)
            .field("valid_for_ms", &self.valid_for_ms)
            .field("master_key", &"[redacted]")
            .field("recovery_root_out", &self.recovery_root_out)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityStatus {
    pub network_id: NetworkId,
    pub root_public_key: [u8; 32],
    pub head: ConfigHead,
    pub relay_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinTicket {
    pub network_id: NetworkId,
    pub request_nonce: [u8; 32],
    pub expires_at_ms: u64,
    pub config_head: ConfigHead,
    pub admin_certificate: Bytes,
    pub member_certificate: Bytes,
    pub endpoint_binding: Bytes,
    pub embedded_config: Bytes,
    pub signer_key_id: [u8; 16],
    signed_bytes: Bytes,
    signature: [u8; SIGNATURE_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredApp {
    pub registration: Bytes,
    pub status: AuthorityStatus,
}

impl JoinTicket {
    #[allow(clippy::too_many_arguments)]
    fn issue(
        admin: &OnlineAdminKey,
        network_id: NetworkId,
        request_nonce: [u8; 32],
        expires_at_ms: u64,
        config_head: ConfigHead,
        admin_certificate: Bytes,
        member_certificate: Bytes,
        endpoint_binding: Bytes,
        embedded_config: Bytes,
    ) -> Result<Self, AuthorityError> {
        let mut ticket = Self {
            network_id,
            request_nonce,
            expires_at_ms,
            config_head,
            admin_certificate,
            member_certificate,
            endpoint_binding,
            embedded_config,
            signer_key_id: admin.key_id(),
            signed_bytes: Bytes::new(),
            signature: [0; SIGNATURE_LEN],
        };
        ticket.signed_bytes = Bytes::from(ticket.encode_signed()?);
        ticket.signature = admin.sign_bytes(&ticket.signed_bytes);
        Ok(ticket)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthorityError> {
        if bytes.len() < SIGNATURE_LEN {
            return Err(AuthorityError::InvalidJoinTicket);
        }
        let signed_len = bytes.len() - SIGNATURE_LEN;
        let signed_bytes = Bytes::copy_from_slice(&bytes[..signed_len]);
        let signature = bytes[signed_len..]
            .try_into()
            .map_err(|_| AuthorityError::InvalidJoinTicket)?;
        let mut decoder = TicketDecoder::new(&signed_bytes);
        decoder.magic(JOIN_TICKET_MAGIC)?;
        let network_id = NetworkId::from_bytes(decoder.array()?);
        let request_nonce = decoder.array()?;
        let expires_at_ms = decoder.u64()?;
        let config_head = ConfigHead {
            epoch: decoder.u64()?,
            revision: decoder.u64()?,
            hash: decoder.array()?,
        };
        let admin_certificate = decoder.blob()?;
        let member_certificate = decoder.blob()?;
        let endpoint_binding = decoder.blob()?;
        let embedded_config = decoder.blob()?;
        let signer_key_id = decoder.array()?;
        decoder.finish()?;
        Ok(Self {
            network_id,
            request_nonce,
            expires_at_ms,
            config_head,
            admin_certificate,
            member_certificate,
            endpoint_binding,
            embedded_config,
            signer_key_id,
            signed_bytes,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut out = Vec::with_capacity(self.signed_bytes.len() + SIGNATURE_LEN);
        out.extend_from_slice(&self.signed_bytes);
        out.extend_from_slice(&self.signature);
        Bytes::from(out)
    }

    pub fn verify(
        &self,
        root: &NetworkRootPublic,
        expected_network: NetworkId,
        expected_nonce: [u8; 32],
        expected_endpoint: [u8; 32],
        now_ms: u64,
    ) -> Result<(), AuthorityError> {
        if self.network_id != expected_network
            || root.network_id() != expected_network
            || self.request_nonce != expected_nonce
            || now_ms >= self.expires_at_ms
        {
            return Err(AuthorityError::InvalidJoinTicket);
        }
        let admin_certificate = AdminCertificate::from_bytes(&self.admin_certificate)?;
        let admin = admin_certificate.verify(root, expected_network, now_ms, &HashSet::new())?;
        if self.signer_key_id != admin.payload().key_id {
            return Err(AuthorityError::InvalidJoinTicket);
        }
        admin.verify_bytes(&self.signed_bytes, &self.signature)?;
        let member = MemberCertificate::from_bytes(&self.member_certificate)?;
        let verified_member =
            member.verify_with_admin(&admin, expected_network, now_ms, &HashSet::new())?;
        let endpoint = EndpointBinding::from_bytes(&self.endpoint_binding)?;
        endpoint.verify(
            &verified_member,
            expected_network,
            expected_endpoint,
            now_ms,
        )?;
        let envelope = EncryptedConfigEnvelope::from_bytes(&self.embedded_config)?;
        if envelope.network_id != expected_network
            || envelope.epoch != self.config_head.epoch
            || envelope.revision != self.config_head.revision
            || envelope.envelope_hash() != self.config_head.hash
        {
            return Err(AuthorityError::InvalidJoinTicket);
        }
        Ok(())
    }

    fn encode_signed(&self) -> Result<Vec<u8>, AuthorityError> {
        let mut out = Vec::new();
        out.extend_from_slice(JOIN_TICKET_MAGIC);
        out.extend_from_slice(self.network_id.as_bytes());
        out.extend_from_slice(&self.request_nonce);
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&self.config_head.epoch.to_be_bytes());
        out.extend_from_slice(&self.config_head.revision.to_be_bytes());
        out.extend_from_slice(&self.config_head.hash);
        push_ticket_blob(&mut out, &self.admin_certificate)?;
        push_ticket_blob(&mut out, &self.member_certificate)?;
        push_ticket_blob(&mut out, &self.endpoint_binding)?;
        push_ticket_blob(&mut out, &self.embedded_config)?;
        out.extend_from_slice(&self.signer_key_id);
        Ok(out)
    }
}

pub struct InitializedAuthority {
    pub status: AuthorityStatus,
    recovery_root: zeroize::Zeroizing<[u8; 32]>,
}

impl InitializedAuthority {
    pub fn recovery_root_bytes(&self) -> [u8; 32] {
        *self.recovery_root
    }
}

impl fmt::Debug for InitializedAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitializedAuthority")
            .field("status", &self.status)
            .field("recovery_root", &"[redacted]")
            .finish()
    }
}

pub struct Authority {
    data_dir: PathBuf,
    state: RedbStateStore,
    secrets: EncryptedFileSecretStore,
    root_public: NetworkRootPublic,
    online_admin: OnlineAdminKey,
    verified_admin: VerifiedAdmin,
    admin_certificate: Bytes,
    member_encryption: MemberEncryptionKeypair,
    endpoint_secret: EndpointSecretKey,
    config: ValidatedNetworkConfig,
    envelope_record_version: u64,
    head_record_version: u64,
    status: AuthorityStatus,
}

impl Authority {
    pub async fn initialize(
        options: AuthorityInit,
    ) -> Result<InitializedAuthority, AuthorityError> {
        validate_init(&options)?;
        if options.data_dir.exists() {
            return Err(AuthorityError::AlreadyInitialized);
        }
        let parent = options
            .data_dir
            .parent()
            .ok_or(AuthorityError::InvalidDataDirectory)?;
        std::fs::create_dir_all(parent).map_err(io_error)?;
        let staging = staging_path(&options.data_dir)?;
        std::fs::create_dir(&staging).map_err(io_error)?;

        let result = initialize_staging(&staging, &options).await;
        match result {
            Ok(initialized) => {
                let finalized = (|| {
                    if let Some(path) = &options.recovery_root_out {
                        write_recovery_root(path, &initialized.recovery_root)?;
                    }
                    sync_directory(&staging)?;
                    std::fs::rename(&staging, &options.data_dir).map_err(io_error)?;
                    sync_directory(parent)
                })();
                if let Err(error) = finalized {
                    let _ = std::fs::remove_dir_all(&staging);
                    return Err(error);
                }
                Ok(initialized)
            }
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging);
                Err(error)
            }
        }
    }

    pub async fn open(
        data_dir: impl AsRef<Path>,
        master_key: [u8; 32],
        now_ms: u64,
    ) -> Result<Self, AuthorityError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        let manifest = read_manifest(&data_dir.join("authority.manifest"))?;
        let root_public = NetworkRootPublic::from_bytes(&manifest.root_public_key)?;
        if root_public.network_id() != manifest.network_id {
            return Err(AuthorityError::CorruptState);
        }
        let state = RedbStateStore::open(data_dir.join("state.redb"))?;
        let secrets = EncryptedFileSecretStore::open(data_dir.join("secrets"), master_key)?;
        let encryption_secret = secrets
            .open(&secret_id(manifest.network_id, b"member-encryption"))
            .await?;
        let encryption_bytes: [u8; 32] = encryption_secret
            .expose()
            .try_into()
            .map_err(|_| AuthorityError::CorruptState)?;
        let encryption = MemberEncryptionKeypair::from_secret_bytes(encryption_bytes)?;
        let endpoint_secret = secrets
            .open(&secret_id(manifest.network_id, b"endpoint"))
            .await?;
        let endpoint_bytes: [u8; 32] = endpoint_secret
            .expose()
            .try_into()
            .map_err(|_| AuthorityError::CorruptState)?;
        let endpoint_secret = EndpointSecretKey::from_bytes(&endpoint_bytes);
        let admin_secret = secrets
            .open(&secret_id(manifest.network_id, b"online-admin"))
            .await?;
        let admin_bytes: [u8; 32] = admin_secret
            .expose()
            .try_into()
            .map_err(|_| AuthorityError::CorruptState)?;
        let online_admin = OnlineAdminKey::from_bytes(&admin_bytes);
        let scope = StoreScope::authority(manifest.network_id);
        let envelope_record = state
            .read(scope, &StoreKey::new(KEY_ENVELOPE)?)
            .await?
            .ok_or(AuthorityError::CorruptState)?;
        let envelope = EncryptedConfigEnvelope::from_bytes(&envelope_record.bytes)?;
        let stored_head = state
            .read(scope, &StoreKey::new(KEY_HEAD)?)
            .await?
            .ok_or(AuthorityError::CorruptState)?;
        let stored_head_value = decode_head(&stored_head.bytes)?;
        if envelope.envelope_hash() != stored_head_value.hash {
            return Err(AuthorityError::CorruptState);
        }
        let admin_certificate = AdminCertificate::from_bytes(&manifest.admin_certificate)?;
        let manifest_admin =
            admin_certificate.verify(&root_public, manifest.network_id, now_ms, &HashSet::new())?;
        if manifest_admin.payload().public_key != online_admin.public_bytes() {
            return Err(AuthorityError::CorruptState);
        }
        let opened = if envelope.revision == 0 {
            if envelope.envelope_hash() != manifest.genesis_hash {
                return Err(AuthorityError::CorruptState);
            }
            envelope.open_config(
                &root_public,
                manifest.network_id,
                &encryption,
                ChainExpectation::Genesis,
                now_ms,
            )?
        } else {
            envelope.open_config_with_verified_admin(
                &root_public,
                &manifest_admin,
                &encryption,
                ChainExpectation::Checkpoint(stored_head_value),
                now_ms,
            )?
        };
        if stored_head_value != opened.head {
            return Err(AuthorityError::CorruptState);
        }
        let authority_endpoint = *endpoint_secret.public().as_bytes();
        let authority_member = opened
            .config
            .as_config()
            .endpoint_bindings
            .iter()
            .filter_map(|raw| EndpointBinding::from_bytes(raw).ok())
            .find(|binding| binding.payload().endpoint_id == authority_endpoint)
            .map(|binding| binding.payload().member_id);
        let authority_role_valid = authority_member.is_some_and(|member_id| {
            opened.config.as_config().members.iter().any(|raw| {
                MemberCertificate::from_bytes(raw).is_ok_and(|member| {
                    member.payload().member_id == member_id
                        && member.payload().roles.contains(MemberRoles::AUTHORITY)
                })
            })
        });
        if !authority_role_valid {
            return Err(AuthorityError::CorruptState);
        }
        let history_key = history_key(opened.head.revision)?;
        match state.read(scope, &history_key).await? {
            Some(record) if record.bytes == envelope_record.bytes => {}
            Some(_) => return Err(AuthorityError::CorruptState),
            None => {
                // Schema-v1 authorities initially retained only the current envelope.
                // Seed the current revision without weakening validation of the signed head.
                let mut migration = AtomicBatch::new(scope);
                migration.put(
                    history_key,
                    envelope_record.bytes.clone(),
                    ExpectedVersion::Missing,
                )?;
                state.commit(migration).await?;
            }
        }
        let verified_admin =
            opened
                .config
                .verified_admin(&root_public, online_admin.key_id(), now_ms)?;
        if verified_admin.payload().public_key != online_admin.public_bytes() {
            return Err(AuthorityError::CorruptState);
        }
        let relay_url = opened
            .config
            .as_config()
            .relays
            .first()
            .map(|relay| relay.url.clone())
            .unwrap_or_default();
        let status = AuthorityStatus {
            network_id: manifest.network_id,
            root_public_key: manifest.root_public_key,
            head: opened.head,
            relay_url,
        };
        Ok(Self {
            data_dir,
            state,
            secrets,
            root_public,
            online_admin,
            verified_admin: manifest_admin,
            admin_certificate: manifest.admin_certificate,
            member_encryption: encryption,
            endpoint_secret,
            config: opened.config,
            envelope_record_version: envelope_record.version,
            head_record_version: stored_head.version,
            status,
        })
    }

    pub fn status(&self) -> &AuthorityStatus {
        &self.status
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn stores(&self) -> (&RedbStateStore, &EncryptedFileSecretStore) {
        (&self.state, &self.secrets)
    }

    pub fn config(&self) -> &ValidatedNetworkConfig {
        &self.config
    }

    pub fn endpoint_secret_key(&self) -> EndpointSecretKey {
        self.endpoint_secret.clone()
    }

    pub fn allowed_member_endpoints(&self) -> Result<HashSet<iroh::EndpointId>, AuthorityError> {
        self.config
            .as_config()
            .endpoint_bindings
            .iter()
            .map(|raw| {
                let binding = EndpointBinding::from_bytes(raw)?;
                iroh::EndpointId::from_bytes(&binding.payload().endpoint_id)
                    .map_err(|_| AuthorityError::CorruptState)
            })
            .collect()
    }

    /// Returns every retained revision after an authenticated caller's known head.
    ///
    /// The supplied base must match the authority's stored history exactly. This rejects
    /// invented heads and lets consumers apply the returned envelopes as a strict chain.
    pub async fn config_updates_after(
        &self,
        base_head: ConfigHead,
    ) -> Result<ConfigUpdateBatch, AuthorityError> {
        if base_head.revision > self.status.head.revision
            || base_head.epoch > self.status.head.epoch
        {
            return Err(AuthorityError::UnknownConfigHead);
        }
        let scope = StoreScope::authority(self.status.network_id);
        let base = self
            .state
            .read(scope, &history_key(base_head.revision)?)
            .await?
            .ok_or(AuthorityError::UnknownConfigHead)?;
        let base_envelope = EncryptedConfigEnvelope::from_bytes(&base.bytes)?;
        if base_envelope.epoch != base_head.epoch
            || base_envelope.revision != base_head.revision
            || base_envelope.envelope_hash() != base_head.hash
        {
            return Err(AuthorityError::UnknownConfigHead);
        }
        let mut envelopes = Vec::new();
        for revision in base_head.revision + 1..=self.status.head.revision {
            let record = self
                .state
                .read(scope, &history_key(revision)?)
                .await?
                .ok_or(AuthorityError::HistoryUnavailable)?;
            envelopes.push(record.bytes);
        }
        Ok(ConfigUpdateBatch::new(
            self.status.network_id,
            base_head,
            envelopes,
        )?)
    }

    /// Atomically commits the next authority configuration revision.
    ///
    /// The current online admin must be authorized by the current snapshot. Both the
    /// envelope and head use exact version preconditions, so concurrent writers cannot
    /// silently fork the authority chain.
    pub async fn commit_config(
        &mut self,
        next_config: NetworkConfigV1,
        now_ms: u64,
    ) -> Result<AuthorityStatus, AuthorityError> {
        let recipients = active_recipient_keys(&next_config)?;
        let envelope = EncryptedConfigEnvelope::seal_next_config(
            &self.root_public,
            &self.online_admin,
            &self.config,
            self.status.head,
            &next_config,
            &recipients,
            now_ms,
        )?;
        let opened = envelope.open_next_config(
            &self.root_public,
            &self.config,
            &self.member_encryption,
            self.status.head,
            now_ms,
        )?;
        let scope = StoreScope::authority(self.status.network_id);
        let envelope_key = StoreKey::new(KEY_ENVELOPE)?;
        let head_key = StoreKey::new(KEY_HEAD)?;
        let mut batch = AtomicBatch::new(scope);
        batch.put(
            envelope_key.clone(),
            envelope.to_bytes(),
            ExpectedVersion::Exact(self.envelope_record_version),
        )?;
        batch.put(
            head_key.clone(),
            encode_head(opened.head),
            ExpectedVersion::Exact(self.head_record_version),
        )?;
        batch.put(
            history_key(opened.head.revision)?,
            envelope.to_bytes(),
            ExpectedVersion::Missing,
        )?;
        self.state.commit(batch).await?;
        let envelope_record = self
            .state
            .read(scope, &envelope_key)
            .await?
            .ok_or(AuthorityError::CorruptState)?;
        let head_record = self
            .state
            .read(scope, &head_key)
            .await?
            .ok_or(AuthorityError::CorruptState)?;
        if envelope_record.bytes != envelope.to_bytes()
            || decode_head(&head_record.bytes)? != opened.head
        {
            return Err(AuthorityError::CorruptState);
        }
        self.envelope_record_version = envelope_record.version;
        self.head_record_version = head_record.version;
        self.config = opened.config;
        self.status.head = opened.head;
        self.status.relay_url = self
            .config
            .as_config()
            .relays
            .first()
            .map(|relay| relay.url.clone())
            .unwrap_or_default();
        Ok(self.status.clone())
    }

    pub async fn invite_member(
        &mut self,
        request: &JoinRequest,
        endpoint_binding: &EndpointBinding,
        granted_roles: MemberRoles,
        now_ms: u64,
        valid_for_ms: u64,
    ) -> Result<JoinTicket, AuthorityError> {
        let request = request.verify(self.status.network_id, now_ms)?;
        if !request.payload().requested_roles.contains(granted_roles) || granted_roles.bits() == 0 {
            return Err(AuthorityError::InvalidOptions);
        }
        let expires_at_ms = now_ms
            .checked_add(valid_for_ms)
            .ok_or(AuthorityError::InvalidOptions)?
            .min(request.payload().expires_at_ms)
            .min(self.verified_admin.payload().expires_at_ms)
            .min(self.config.as_config().expires_at_ms);
        if expires_at_ms <= now_ms {
            return Err(AuthorityError::InvalidOptions);
        }
        if endpoint_binding.payload().network_id != self.status.network_id
            || endpoint_binding.payload().member_id != request.payload().member_id
            || endpoint_binding.payload().endpoint_id != request.payload().endpoint_id
            || endpoint_binding.payload().sequence != 0
            || endpoint_binding.payload().expires_at_ms < expires_at_ms
        {
            return Err(AuthorityError::InvalidJoinRequest);
        }
        ensure_join_is_unique(self.config.as_config(), request.payload())?;
        let serial = next_serial(self.config.as_config())?;
        let member = MemberCertificate::issue_by_admin(
            &self.online_admin,
            self.verified_admin.payload(),
            request.payload().signing_public_key,
            request.payload().encryption_public_key,
            granted_roles,
            serial,
            now_ms,
            expires_at_ms,
        )?;
        let verified_member = member.verify_with_admin(
            &self.verified_admin,
            self.status.network_id,
            now_ms,
            &HashSet::new(),
        )?;
        endpoint_binding.verify(
            &verified_member,
            self.status.network_id,
            request.payload().endpoint_id,
            now_ms,
        )?;

        let mut next = self.config.as_config().clone();
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or(AuthorityError::InvalidOptions)?;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(AuthorityError::InvalidOptions)?;
        next.previous_hash = self.status.head.hash;
        next.issued_at_ms = now_ms;
        next.epoch_secrets = EpochSecrets::generate()?;
        next.members.push(member.to_bytes());
        next.endpoint_bindings.push(endpoint_binding.to_bytes());
        let status = self.commit_config(next, now_ms).await?;
        let envelope = self
            .state
            .read(
                StoreScope::authority(self.status.network_id),
                &StoreKey::new(KEY_ENVELOPE)?,
            )
            .await?
            .ok_or(AuthorityError::CorruptState)?
            .bytes;
        JoinTicket::issue(
            &self.online_admin,
            self.status.network_id,
            request.payload().nonce,
            expires_at_ms,
            status.head,
            self.admin_certificate.clone(),
            member.to_bytes(),
            endpoint_binding.to_bytes(),
            envelope,
        )
    }

    pub async fn revoke_member(
        &mut self,
        member_id: MemberId,
        now_ms: u64,
    ) -> Result<AuthorityStatus, AuthorityError> {
        let mut next = self.config.as_config().clone();
        let position = next
            .members
            .iter()
            .position(|raw| {
                MemberCertificate::from_bytes(raw)
                    .map(|member| member.payload().member_id == member_id)
                    .unwrap_or(false)
            })
            .ok_or(AuthorityError::MemberNotFound)?;
        let removed = MemberCertificate::from_bytes(&next.members[position])?;
        if removed.payload().encryption_public_key == self.member_encryption.public_bytes() {
            return Err(AuthorityError::CannotRevokeAuthorityMember);
        }
        next.members.remove(position);
        next.endpoint_bindings.retain(|raw| {
            EndpointBinding::from_bytes(raw)
                .map(|binding| binding.payload().member_id != member_id)
                .unwrap_or(false)
        });
        next.app_bindings.retain(|raw| {
            weaver_crypto::AppBinding::from_bytes(raw)
                .map(|binding| binding.payload().subject != member_id)
                .unwrap_or(false)
        });
        let revoked_endpoints = self
            .config
            .as_config()
            .endpoint_bindings
            .iter()
            .filter_map(|raw| EndpointBinding::from_bytes(raw).ok())
            .filter(|binding| binding.payload().member_id == member_id)
            .map(|binding| binding.payload().endpoint_id)
            .collect::<HashSet<_>>();
        next.relays
            .retain(|relay| !revoked_endpoints.contains(&relay.endpoint_id));
        next.presence_services
            .retain(|service| !revoked_endpoints.contains(&service.endpoint_id));
        if next.revoked_serials.contains(&removed.payload().serial) {
            return Err(AuthorityError::MemberNotFound);
        }
        next.revoked_serials.push(removed.payload().serial);
        next.revoked_serials.sort_unstable();
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or(AuthorityError::InvalidOptions)?;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(AuthorityError::InvalidOptions)?;
        next.previous_hash = self.status.head.hash;
        next.issued_at_ms = now_ms;
        next.epoch_secrets = EpochSecrets::generate()?;
        self.commit_config(next, now_ms).await
    }

    pub async fn register_app(
        &mut self,
        request: &AppRegistrationRequest,
        now_ms: u64,
    ) -> Result<RegisteredApp, AuthorityError> {
        let request = request.verify(self.status.network_id)?;
        if self.config.as_config().apps.iter().any(|raw| {
            AppRegistration::from_bytes(raw)
                .map(|app| app.payload().app_addr == request.payload().app_addr)
                .unwrap_or(false)
        }) {
            return Err(AuthorityError::ApplicationAlreadyRegistered);
        }
        let registration = AppRegistration::issue_by_admin(
            &self.online_admin,
            self.verified_admin.payload(),
            &request,
        )?;
        let mut next = self.config.as_config().clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(AuthorityError::InvalidOptions)?;
        next.previous_hash = self.status.head.hash;
        next.issued_at_ms = now_ms;
        next.apps.push(registration.to_bytes());
        let status = self.commit_config(next, now_ms).await?;
        Ok(RegisteredApp {
            registration: registration.to_bytes(),
            status,
        })
    }

    pub async fn authorize_app_binding(
        &mut self,
        binding: &AppBinding,
        now_ms: u64,
    ) -> Result<AuthorityStatus, AuthorityError> {
        let mut next = self.config.as_config().clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(AuthorityError::InvalidOptions)?;
        next.previous_hash = self.status.head.hash;
        next.issued_at_ms = now_ms;
        next.app_bindings.push(binding.to_bytes());
        self.commit_config(next, now_ms).await
    }

    /// Adds or atomically updates an infrastructure endpoint already authorized as a
    /// relay/bootstrap member. Re-registering the same endpoint is the URL/role rotation
    /// transaction; rotating its key uses invite(new) -> register(new) -> remove(old).
    pub async fn register_relay(
        &mut self,
        endpoint_id: iroh::EndpointId,
        url: String,
        roles: RelayRoles,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<AuthorityStatus, AuthorityError> {
        let known_role_bits = RelayRoles::DATA_RELAY
            .union(RelayRoles::BOOTSTRAP)
            .union(RelayRoles::PRESENCE)
            .bits();
        if roles.bits() == 0
            || roles.bits() & !known_role_bits != 0
            || expires_at_ms <= now_ms
            || expires_at_ms > self.config.as_config().expires_at_ms
            || url.parse::<iroh::RelayUrl>().is_err()
        {
            return Err(AuthorityError::InvalidOptions);
        }
        let endpoint_bytes = *endpoint_id.as_bytes();
        let binding = self
            .config
            .as_config()
            .endpoint_bindings
            .iter()
            .filter_map(|raw| EndpointBinding::from_bytes(raw).ok())
            .find(|binding| binding.payload().endpoint_id == endpoint_bytes)
            .ok_or(AuthorityError::MemberNotFound)?;
        let member = self
            .config
            .as_config()
            .members
            .iter()
            .filter_map(|raw| MemberCertificate::from_bytes(raw).ok())
            .find(|member| member.payload().member_id == binding.payload().member_id)
            .ok_or(AuthorityError::MemberNotFound)?;
        if !member.payload().roles.contains(MemberRoles::RELAY)
            || (roles.contains(RelayRoles::BOOTSTRAP)
                && !member.payload().roles.contains(MemberRoles::BOOTSTRAP))
            || expires_at_ms > member.payload().expires_at_ms
            || expires_at_ms > binding.payload().expires_at_ms
        {
            return Err(AuthorityError::InvalidOptions);
        }

        let mut next = self.config.as_config().clone();
        next.relays
            .retain(|relay| relay.endpoint_id != endpoint_bytes);
        next.presence_services
            .retain(|service| service.endpoint_id != endpoint_bytes);
        next.relays.push(RelayDescriptor {
            endpoint_id: endpoint_bytes,
            url: url.clone(),
            roles,
            expires_at_ms,
        });
        if roles.contains(RelayRoles::PRESENCE) {
            next.presence_services.push(PresenceServiceDescriptor {
                endpoint_id: endpoint_bytes,
                url,
                expires_at_ms,
            });
        }
        next.relays.sort_by_key(|relay| relay.endpoint_id);
        next.presence_services
            .sort_by_key(|service| service.endpoint_id);
        prepare_next_revision(&mut next, self.status.head, now_ms)?;
        self.commit_config(next, now_ms).await
    }

    pub async fn remove_relay(
        &mut self,
        endpoint_id: iroh::EndpointId,
        now_ms: u64,
    ) -> Result<AuthorityStatus, AuthorityError> {
        let endpoint_bytes = *endpoint_id.as_bytes();
        let mut next = self.config.as_config().clone();
        let before = next.relays.len();
        next.relays
            .retain(|relay| relay.endpoint_id != endpoint_bytes);
        next.presence_services
            .retain(|service| service.endpoint_id != endpoint_bytes);
        if next.relays.len() == before {
            return Err(AuthorityError::RelayNotFound);
        }
        prepare_next_revision(&mut next, self.status.head, now_ms)?;
        self.commit_config(next, now_ms).await
    }
}

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("authority data directory already exists")]
    AlreadyInitialized,
    #[error("authority data directory has no parent")]
    InvalidDataDirectory,
    #[error("relay URL or validity interval is invalid")]
    InvalidOptions,
    #[error("authority persistent state is corrupt or incomplete")]
    CorruptState,
    #[error("join request conflicts with existing membership or has inconsistent bindings")]
    InvalidJoinRequest,
    #[error("join ticket is malformed, expired or does not match the prepared request")]
    InvalidJoinTicket,
    #[error("member does not exist in the current configuration")]
    MemberNotFound,
    #[error("the online authority cannot revoke the member holding its config decryption key")]
    CannotRevokeAuthorityMember,
    #[error("application is already registered in this network")]
    ApplicationAlreadyRegistered,
    #[error("relay endpoint does not exist in the current configuration")]
    RelayNotFound,
    #[error("the requested configuration head is not part of this authority chain")]
    UnknownConfigHead,
    #[error("the authority no longer retains every configuration revision after this head")]
    HistoryUnavailable,
    #[error("authority filesystem operation failed: {0}")]
    Io(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Secret(#[from] SecretStoreError),
    #[error(transparent)]
    Crypto(#[from] weaver_crypto::CertificateError),
    #[error(transparent)]
    Config(#[from] weaver_config::ConfigError),
    #[error(transparent)]
    Snapshot(#[from] weaver_config::SnapshotError),
}

struct Manifest {
    network_id: NetworkId,
    root_public_key: [u8; 32],
    genesis_hash: [u8; 32],
    admin_certificate: Bytes,
}

async fn initialize_staging(
    staging: &Path,
    options: &AuthorityInit,
) -> Result<InitializedAuthority, AuthorityError> {
    let expires_at_ms = options
        .now_ms
        .checked_add(options.valid_for_ms)
        .ok_or(AuthorityError::InvalidOptions)?;
    let root = NetworkRootKey::generate()?;
    let root_public = root.public();
    let network_id = root_public.network_id();
    let member_signing = SigningKeypair::generate()?;
    let online_admin = OnlineAdminKey::generate()?;
    let admin_certificate = AdminCertificate::issue(
        &root,
        online_admin.public_bytes(),
        u32::MAX,
        2,
        options.now_ms,
        expires_at_ms,
    )?;
    let member_encryption = MemberEncryptionKeypair::generate()?;
    let endpoint = EndpointSecretKey::generate();
    let member = MemberCertificate::issue(
        &root,
        member_signing.public_bytes(),
        member_encryption.public_bytes(),
        MemberRoles::MEMBER
            .union(MemberRoles::SERVICE)
            .union(MemberRoles::RELAY)
            .union(MemberRoles::BOOTSTRAP)
            .union(MemberRoles::AUTHORITY),
        1,
        options.now_ms,
        expires_at_ms,
    )?;
    let endpoint_binding = EndpointBinding::issue(
        &member_signing,
        member.payload(),
        *endpoint.public().as_bytes(),
        0,
        expires_at_ms,
    )?;
    let config = NetworkConfigV1 {
        network_id,
        epoch: 0,
        revision: 0,
        previous_hash: [0; 32],
        issued_at_ms: options.now_ms,
        expires_at_ms,
        admin_keys: vec![AdminKey {
            certificate: admin_certificate.to_bytes(),
        }],
        members: vec![member.to_bytes()],
        endpoint_bindings: vec![endpoint_binding.to_bytes()],
        revoked_serials: Vec::new(),
        apps: Vec::new(),
        app_bindings: Vec::new(),
        relays: vec![RelayDescriptor {
            endpoint_id: *endpoint.public().as_bytes(),
            url: options.relay_url.clone(),
            roles: RelayRoles::DATA_RELAY
                .union(RelayRoles::BOOTSTRAP)
                .union(RelayRoles::PRESENCE),
            expires_at_ms,
        }],
        presence_services: vec![PresenceServiceDescriptor {
            endpoint_id: *endpoint.public().as_bytes(),
            url: options.relay_url.clone(),
            expires_at_ms,
        }],
        epoch_secrets: EpochSecrets::generate()?,
        policies: NetworkPolicy::default(),
    };
    let envelope =
        EncryptedConfigEnvelope::seal_config(&root, &config, &[member_encryption.public_bytes()])?;
    let head = ConfigHead {
        epoch: 0,
        revision: 0,
        hash: envelope.envelope_hash(),
    };

    let secrets = EncryptedFileSecretStore::open(staging.join("secrets"), options.master_key)?;
    seal_secret(
        &secrets,
        network_id,
        b"online-admin",
        &online_admin.to_bytes(),
    )
    .await?;
    seal_secret(
        &secrets,
        network_id,
        b"member-signing",
        &member_signing.to_bytes(),
    )
    .await?;
    seal_secret(
        &secrets,
        network_id,
        b"member-encryption",
        &member_encryption.secret_bytes(),
    )
    .await?;
    seal_secret(&secrets, network_id, b"endpoint", &endpoint.to_bytes()).await?;

    let state = RedbStateStore::open(staging.join("state.redb"))?;
    let mut batch = AtomicBatch::new(StoreScope::authority(network_id));
    batch.put(
        StoreKey::new(KEY_ENVELOPE)?,
        envelope.to_bytes(),
        ExpectedVersion::Missing,
    )?;
    batch.put(
        StoreKey::new(KEY_HEAD)?,
        encode_head(head),
        ExpectedVersion::Missing,
    )?;
    batch.put(
        history_key(head.revision)?,
        envelope.to_bytes(),
        ExpectedVersion::Missing,
    )?;
    state.commit(batch).await?;

    write_manifest(
        &staging.join("authority.manifest"),
        &Manifest {
            network_id,
            root_public_key: root_public.as_bytes(),
            genesis_hash: head.hash,
            admin_certificate: admin_certificate.to_bytes(),
        },
    )?;
    Ok(InitializedAuthority {
        status: AuthorityStatus {
            network_id,
            root_public_key: root_public.as_bytes(),
            head,
            relay_url: options.relay_url.clone(),
        },
        recovery_root: zeroize::Zeroizing::new(root.to_bytes()),
    })
}

async fn seal_secret(
    store: &EncryptedFileSecretStore,
    network_id: NetworkId,
    label: &[u8],
    value: &[u8],
) -> Result<(), AuthorityError> {
    store
        .seal(
            secret_id(network_id, label),
            SecretBytes::new(value.to_vec()),
        )
        .await?;
    Ok(())
}

fn validate_init(options: &AuthorityInit) -> Result<(), AuthorityError> {
    if options.valid_for_ms == 0
        || options.relay_url.is_empty()
        || options.relay_url.len() > 2048
        || !options.relay_url.is_ascii()
    {
        return Err(AuthorityError::InvalidOptions);
    }
    Ok(())
}

fn secret_id(network_id: NetworkId, label: &[u8]) -> SecretId {
    let mut hasher = blake3::Hasher::new_derive_key("weaver.authority.secret-id.v1");
    hasher.update(network_id.as_bytes());
    hasher.update(label);
    SecretId::from_bytes(*hasher.finalize().as_bytes())
}

fn active_recipient_keys(config: &NetworkConfigV1) -> Result<Vec<[u8; 32]>, AuthorityError> {
    config
        .members
        .iter()
        .map(|raw| {
            MemberCertificate::from_bytes(raw)
                .map(|certificate| certificate.payload().encryption_public_key)
                .map_err(Into::into)
        })
        .collect()
}

fn ensure_join_is_unique(
    config: &NetworkConfigV1,
    request: &JoinRequestPayload,
) -> Result<(), AuthorityError> {
    for raw in &config.members {
        let member = MemberCertificate::from_bytes(raw)?;
        if member.payload().member_id == request.member_id
            || member.payload().signing_public_key == request.signing_public_key
            || member.payload().encryption_public_key == request.encryption_public_key
        {
            return Err(AuthorityError::InvalidJoinRequest);
        }
    }
    for raw in &config.endpoint_bindings {
        let endpoint = EndpointBinding::from_bytes(raw)?;
        if endpoint.payload().endpoint_id == request.endpoint_id {
            return Err(AuthorityError::InvalidJoinRequest);
        }
    }
    Ok(())
}

fn prepare_next_revision(
    config: &mut NetworkConfigV1,
    current: ConfigHead,
    now_ms: u64,
) -> Result<(), AuthorityError> {
    config.revision = config
        .revision
        .checked_add(1)
        .ok_or(AuthorityError::InvalidOptions)?;
    config.previous_hash = current.hash;
    config.issued_at_ms = now_ms;
    Ok(())
}

fn next_serial(config: &NetworkConfigV1) -> Result<u64, AuthorityError> {
    let mut maximum = config.revoked_serials.iter().copied().max().unwrap_or(0);
    for raw in &config.admin_keys {
        maximum = maximum.max(
            AdminCertificate::from_bytes(&raw.certificate)?
                .payload()
                .serial,
        );
    }
    for raw in &config.members {
        maximum = maximum.max(MemberCertificate::from_bytes(raw)?.payload().serial);
    }
    maximum.checked_add(1).ok_or(AuthorityError::InvalidOptions)
}

fn push_ticket_blob(out: &mut Vec<u8>, blob: &[u8]) -> Result<(), AuthorityError> {
    let len = u32::try_from(blob.len()).map_err(|_| AuthorityError::InvalidJoinTicket)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(blob);
    Ok(())
}

struct TicketDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TicketDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], AuthorityError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(AuthorityError::InvalidJoinTicket)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AuthorityError::InvalidJoinTicket)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], AuthorityError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AuthorityError::InvalidJoinTicket)
    }

    fn u32(&mut self) -> Result<u32, AuthorityError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, AuthorityError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn blob(&mut self) -> Result<Bytes, AuthorityError> {
        let len = usize::try_from(self.u32()?).map_err(|_| AuthorityError::InvalidJoinTicket)?;
        if len == 0 || len > weaver_store::MAX_VALUE_LEN {
            return Err(AuthorityError::InvalidJoinTicket);
        }
        Ok(Bytes::copy_from_slice(self.take(len)?))
    }

    fn magic(&mut self, expected: &[u8]) -> Result<(), AuthorityError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(AuthorityError::InvalidJoinTicket)
        }
    }

    fn finish(self) -> Result<(), AuthorityError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(AuthorityError::InvalidJoinTicket)
        }
    }
}

fn staging_path(target: &Path) -> Result<PathBuf, AuthorityError> {
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(AuthorityError::InvalidDataDirectory)?;
    let mut random = [0; 12];
    getrandom::fill(&mut random).map_err(|error| AuthorityError::Io(error.to_string()))?;
    Ok(target.with_file_name(format!(".{name}.initializing-{}", hexless(&random))))
}

fn write_manifest(path: &Path, manifest: &Manifest) -> Result<(), AuthorityError> {
    let mut file = private_new_file(path)?;
    file.write_all(MANIFEST_MAGIC).map_err(io_error)?;
    file.write_all(manifest.network_id.as_bytes())
        .map_err(io_error)?;
    file.write_all(&manifest.root_public_key)
        .map_err(io_error)?;
    file.write_all(&manifest.genesis_hash).map_err(io_error)?;
    let certificate_len = u16::try_from(manifest.admin_certificate.len())
        .map_err(|_| AuthorityError::CorruptState)?;
    file.write_all(&certificate_len.to_be_bytes())
        .map_err(io_error)?;
    file.write_all(&manifest.admin_certificate)
        .map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn write_recovery_root(path: &Path, recovery_root: &[u8; 32]) -> Result<(), AuthorityError> {
    let parent = path.parent().ok_or(AuthorityError::InvalidDataDirectory)?;
    std::fs::create_dir_all(parent).map_err(io_error)?;
    let mut file = private_new_file(path)?;
    file.write_all(b"WVRROOT\0\x01").map_err(io_error)?;
    file.write_all(recovery_root).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    sync_directory(parent)
}

fn read_manifest(path: &Path) -> Result<Manifest, AuthorityError> {
    let bytes = std::fs::read(path).map_err(|_| AuthorityError::CorruptState)?;
    if bytes.len() < MANIFEST_FIXED_LEN || &bytes[..8] != MANIFEST_MAGIC {
        return Err(AuthorityError::CorruptState);
    }
    let certificate_len = u16::from_be_bytes(
        bytes[104..106]
            .try_into()
            .map_err(|_| AuthorityError::CorruptState)?,
    ) as usize;
    if certificate_len == 0 || bytes.len() != MANIFEST_FIXED_LEN + certificate_len {
        return Err(AuthorityError::CorruptState);
    }
    Ok(Manifest {
        network_id: NetworkId::from_bytes(
            bytes[8..40]
                .try_into()
                .map_err(|_| AuthorityError::CorruptState)?,
        ),
        root_public_key: bytes[40..72]
            .try_into()
            .map_err(|_| AuthorityError::CorruptState)?,
        genesis_hash: bytes[72..104]
            .try_into()
            .map_err(|_| AuthorityError::CorruptState)?,
        admin_certificate: Bytes::copy_from_slice(&bytes[106..]),
    })
}

fn encode_head(head: ConfigHead) -> Bytes {
    let mut out = Vec::with_capacity(HEAD_LEN);
    out.extend_from_slice(&head.epoch.to_be_bytes());
    out.extend_from_slice(&head.revision.to_be_bytes());
    out.extend_from_slice(&head.hash);
    Bytes::from(out)
}

fn history_key(revision: u64) -> Result<StoreKey, AuthorityError> {
    let mut key = Vec::with_capacity(KEY_HISTORY_PREFIX.len() + 8);
    key.extend_from_slice(KEY_HISTORY_PREFIX);
    key.extend_from_slice(&revision.to_be_bytes());
    Ok(StoreKey::new(key)?)
}

fn decode_head(bytes: &[u8]) -> Result<ConfigHead, AuthorityError> {
    if bytes.len() != HEAD_LEN {
        return Err(AuthorityError::CorruptState);
    }
    Ok(ConfigHead {
        epoch: u64::from_be_bytes(
            bytes[..8]
                .try_into()
                .map_err(|_| AuthorityError::CorruptState)?,
        ),
        revision: u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| AuthorityError::CorruptState)?,
        ),
        hash: bytes[16..]
            .try_into()
            .map_err(|_| AuthorityError::CorruptState)?,
    })
}

#[cfg(unix)]
fn private_new_file(path: &Path) -> Result<File, AuthorityError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)
}

#[cfg(not(unix))]
fn private_new_file(path: &Path) -> Result<File, AuthorityError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_error)
}

fn sync_directory(path: &Path) -> Result<(), AuthorityError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

fn io_error(error: impl std::fmt::Display) -> AuthorityError {
    AuthorityError::Io(error.to_string())
}

fn hexless(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey as TestEndpointKey;
    use weaver_crypto::{AppRole, AppRootKey};

    fn options(data_dir: PathBuf, master_key: [u8; 32]) -> AuthorityInit {
        AuthorityInit {
            data_dir,
            relay_url: "https://relay.example.test".to_owned(),
            now_ms: 1_000,
            valid_for_ms: 86_400_000,
            master_key,
            recovery_root_out: None,
        }
    }

    #[tokio::test]
    async fn initialization_commits_complete_directory_and_reopens() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("network-a");
        let initialized = Authority::initialize(options(target.clone(), [0x31; 32]))
            .await
            .unwrap();
        assert!(target.join("authority.manifest").is_file());
        assert!(target.join("state.redb").is_file());
        let opened = Authority::open(&target, [0x31; 32], 2_000).await.unwrap();
        assert_eq!(opened.status(), &initialized.status);
        assert_eq!(opened.status().head.revision, 0);
        let recovered_root = NetworkRootKey::from_bytes(&initialized.recovery_root_bytes());
        assert_eq!(
            recovered_root.public().as_bytes(),
            initialized.status.root_public_key
        );
    }

    #[tokio::test]
    async fn relay_registration_rotation_and_removal_are_signed_revisions() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("network-a");
        Authority::initialize(options(target.clone(), [0x35; 32]))
            .await
            .unwrap();
        let mut authority = Authority::open(&target, [0x35; 32], 2_000).await.unwrap();
        let endpoint = authority.endpoint_secret_key().public();
        let status = authority
            .register_relay(
                endpoint,
                "https://relay-rotated.example.test".to_owned(),
                RelayRoles::DATA_RELAY.union(RelayRoles::PRESENCE),
                80_000_000,
                3_000,
            )
            .await
            .unwrap();
        assert_eq!(status.head.revision, 1);
        assert_eq!(authority.config().as_config().relays.len(), 1);
        assert_eq!(authority.config().as_config().presence_services.len(), 1);
        assert_eq!(
            authority.config().as_config().relays[0].url,
            "https://relay-rotated.example.test"
        );

        let status = authority.remove_relay(endpoint, 4_000).await.unwrap();
        assert_eq!(status.head.revision, 2);
        assert!(authority.config().as_config().relays.is_empty());
        assert!(authority.config().as_config().presence_services.is_empty());
        drop(authority);

        let reopened = Authority::open(&target, [0x35; 32], 5_000).await.unwrap();
        assert_eq!(reopened.status().head.revision, 2);
        assert!(reopened.config().as_config().relays.is_empty());
    }

    #[tokio::test]
    async fn initialization_refuses_existing_target_without_modifying_it() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("network-a");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("owner-data"), b"keep").unwrap();
        assert!(matches!(
            Authority::initialize(options(target.clone(), [0x41; 32])).await,
            Err(AuthorityError::AlreadyInitialized)
        ));
        assert_eq!(std::fs::read(target.join("owner-data")).unwrap(), b"keep");
    }

    #[tokio::test]
    async fn wrong_master_key_and_incomplete_directory_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("network-a");
        Authority::initialize(options(target.clone(), [0x51; 32]))
            .await
            .unwrap();
        assert!(matches!(
            Authority::open(&target, [0x52; 32], 2_000).await,
            Err(AuthorityError::Secret(
                SecretStoreError::AuthenticationFailed
            ))
        ));

        let incomplete = temp.path().join("incomplete");
        std::fs::create_dir(&incomplete).unwrap();
        assert!(matches!(
            Authority::open(&incomplete, [0x51; 32], 2_000).await,
            Err(AuthorityError::CorruptState)
        ));
    }

    #[tokio::test]
    async fn recovery_root_is_external_create_new_and_precedes_directory_commit() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("network-a");
        let recovery = temp.path().join("offline/network-a.root");
        let mut init = options(target.clone(), [0x61; 32]);
        init.recovery_root_out = Some(recovery.clone());
        let initialized = Authority::initialize(init).await.unwrap();
        let bytes = std::fs::read(&recovery).unwrap();
        assert_eq!(&bytes[..9], b"WVRROOT\0\x01");
        assert_eq!(&bytes[9..], &initialized.recovery_root_bytes());
        assert!(target.is_dir());

        let refused_target = temp.path().join("network-b");
        let mut refused = options(refused_target.clone(), [0x62; 32]);
        refused.recovery_root_out = Some(recovery);
        assert!(matches!(
            Authority::initialize(refused).await,
            Err(AuthorityError::Io(_))
        ));
        assert!(!refused_target.exists());
    }

    #[test]
    fn init_debug_never_exposes_master_key() {
        let init = options(PathBuf::from("network-a"), [0xab; 32]);
        let debug = format!("{init:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("171"));
        assert!(!debug.contains("ab"));
    }

    #[tokio::test]
    async fn online_admin_commit_is_atomic_monotonic_and_reopens() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("network-a");
        let initialized = Authority::initialize(options(target.clone(), [0x71; 32]))
            .await
            .unwrap();
        let genesis_head = initialized.status.head;
        let mut first = Authority::open(&target, [0x71; 32], 2_000).await.unwrap();
        let stale_envelope_version = first.envelope_record_version;

        let mut next = first.config().as_config().clone();
        next.revision = 1;
        next.previous_hash = first.status().head.hash;
        next.issued_at_ms = 2_000;
        next.relays[0].url = "https://new-relay.example.test".to_owned();
        next.presence_services[0].url = "https://new-relay.example.test/presence".to_owned();
        let committed = first.commit_config(next, 2_000).await.unwrap();
        assert_eq!(committed.head.revision, 1);
        assert_eq!(committed.relay_url, "https://new-relay.example.test");
        let updates = first.config_updates_after(genesis_head).await.unwrap();
        assert_eq!(updates.base_head, genesis_head);
        assert_eq!(updates.envelopes.len(), 1);
        assert_eq!(
            EncryptedConfigEnvelope::from_bytes(&updates.envelopes[0])
                .unwrap()
                .envelope_hash(),
            committed.head.hash
        );
        let mut invented = genesis_head;
        invented.hash[0] ^= 1;
        assert!(matches!(
            first.config_updates_after(invented).await,
            Err(AuthorityError::UnknownConfigHead)
        ));

        let mut revision_two = first.config().as_config().clone();
        revision_two.revision = 2;
        revision_two.previous_hash = first.status().head.hash;
        revision_two.issued_at_ms = 2_100;
        first.envelope_record_version = stale_envelope_version;
        assert!(matches!(
            first.commit_config(revision_two, 2_100).await,
            Err(AuthorityError::Store(StoreError::VersionConflict { .. }))
        ));
        drop(first);
        let reopened = Authority::open(&target, [0x71; 32], 2_500).await.unwrap();
        assert_eq!(reopened.status().head.revision, 1);
        assert_eq!(
            reopened.status().relay_url,
            "https://new-relay.example.test"
        );
    }

    #[tokio::test]
    async fn invite_commits_member_and_embeds_candidate_decryptable_config() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("network-a");
        let initialized = Authority::initialize(options(target.clone(), [0x81; 32]))
            .await
            .unwrap();
        let root = NetworkRootKey::from_bytes(&initialized.recovery_root_bytes());
        let mut authority = Authority::open(&target, [0x81; 32], 2_000).await.unwrap();
        let signing = SigningKeypair::generate().unwrap();
        let encryption = MemberEncryptionKeypair::generate().unwrap();
        let endpoint = TestEndpointKey::generate();
        let nonce = [0x82; 32];
        let request = JoinRequest::create(
            initialized.status.network_id,
            &signing,
            encryption.public_bytes(),
            *endpoint.public().as_bytes(),
            nonce,
            MemberRoles::MEMBER,
            20_000,
        )
        .unwrap();
        let binding = EndpointBinding::issue_for_join(
            &signing,
            initialized.status.network_id,
            *endpoint.public().as_bytes(),
            0,
            20_000,
        )
        .unwrap();
        let ticket = authority
            .invite_member(&request, &binding, MemberRoles::MEMBER, 2_000, 10_000)
            .await
            .unwrap();
        assert_eq!(ticket.config_head.revision, 1);
        assert_eq!(ticket.config_head.epoch, 1);
        let ticket = JoinTicket::from_bytes(&ticket.to_bytes()).unwrap();
        ticket
            .verify(
                &root.public(),
                initialized.status.network_id,
                nonce,
                *endpoint.public().as_bytes(),
                2_500,
            )
            .unwrap();
        let admin_certificate = AdminCertificate::from_bytes(&ticket.admin_certificate).unwrap();
        let admin = admin_certificate
            .verify(
                &root.public(),
                initialized.status.network_id,
                2_500,
                &HashSet::new(),
            )
            .unwrap();
        let envelope = EncryptedConfigEnvelope::from_bytes(&ticket.embedded_config).unwrap();
        let opened = envelope
            .open_config_with_verified_admin(
                &root.public(),
                &admin,
                &encryption,
                ChainExpectation::Checkpoint(ticket.config_head),
                2_500,
            )
            .unwrap();
        assert!(opened.config.as_config().members.iter().any(|raw| {
            MemberCertificate::from_bytes(raw)
                .map(|member| member.payload().member_id == request.payload().member_id)
                .unwrap_or(false)
        }));

        assert!(matches!(
            authority
                .invite_member(&request, &binding, MemberRoles::MEMBER, 2_500, 10_000)
                .await,
            Err(AuthorityError::InvalidJoinRequest)
        ));
        let mut tampered = ticket.to_bytes().to_vec();
        tampered[40] ^= 1;
        let tampered = JoinTicket::from_bytes(&tampered).unwrap();
        assert!(
            tampered
                .verify(
                    &root.public(),
                    initialized.status.network_id,
                    nonce,
                    *endpoint.public().as_bytes(),
                    2_500
                )
                .is_err()
        );

        let revoked = authority
            .revoke_member(request.payload().member_id, 3_000)
            .await
            .unwrap();
        assert_eq!(revoked.head.revision, 2);
        assert_eq!(revoked.head.epoch, 2);
        let future = authority
            .state
            .read(
                StoreScope::authority(initialized.status.network_id),
                &StoreKey::new(KEY_ENVELOPE).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let future = EncryptedConfigEnvelope::from_bytes(&future.bytes).unwrap();
        assert_eq!(
            future.open_config_with_verified_admin(
                &root.public(),
                &admin,
                &encryption,
                ChainExpectation::Checkpoint(revoked.head),
                3_000,
            ),
            Err(weaver_config::ConfigError::NoRecipientWrap)
        );
        assert!(!authority.config().as_config().members.iter().any(|raw| {
            MemberCertificate::from_bytes(raw)
                .map(|member| member.payload().member_id == request.payload().member_id)
                .unwrap_or(false)
        }));
    }

    #[tokio::test]
    async fn app_registration_and_binding_are_sequential_admin_transactions() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("network-a");
        let initialized = Authority::initialize(options(target.clone(), [0x91; 32]))
            .await
            .unwrap();
        let mut authority = Authority::open(&target, [0x91; 32], 2_000).await.unwrap();
        let app_root = AppRootKey::generate().unwrap();
        let request =
            AppRegistrationRequest::create(&app_root, initialized.status.network_id, 0x10);
        let registered = authority.register_app(&request, 2_000).await.unwrap();
        assert_eq!(registered.status.head.revision, 1);
        assert_eq!(registered.status.head.epoch, 0);
        assert!(matches!(
            authority.register_app(&request, 2_100).await,
            Err(AuthorityError::ApplicationAlreadyRegistered)
        ));

        let authority_member =
            MemberCertificate::from_bytes(authority.config().as_config().members.first().unwrap())
                .unwrap();
        let binding = AppBinding::issue(
            &app_root,
            initialized.status.network_id,
            authority_member.payload().member_id,
            AppRole::Server,
            None,
            10_000,
            Vec::new(),
        )
        .unwrap();
        let bound = authority
            .authorize_app_binding(&binding, 2_200)
            .await
            .unwrap();
        assert_eq!(bound.head.revision, 2);
        assert_eq!(bound.head.epoch, 0);
        assert_eq!(authority.config().as_config().apps.len(), 1);
        assert_eq!(authority.config().as_config().app_bindings.len(), 1);
        assert!(
            authority
                .authorize_app_binding(&binding, 2_300)
                .await
                .is_err()
        );
    }
}
