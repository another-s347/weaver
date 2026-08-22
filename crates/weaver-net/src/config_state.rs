use bytes::Bytes;
use thiserror::Error;
use weaver_config::{
    ChainExpectation, ConfigHead, ConfigUpdateBatch, EncryptedConfigEnvelope,
    MemberEncryptionKeypair, ValidatedNetworkConfig,
};
use weaver_core::NetworkId;
use weaver_crypto::{AdminCertificate, NetworkRootPublic};
use weaver_store::{AtomicBatch, ExpectedVersion, StateStore, StoreError, StoreKey, StoreScope};

pub const CONFIG_ENVELOPE_KEY: &[u8] = b"config/envelope/v1";
pub const CONFIG_HEAD_KEY: &[u8] = b"config/head/v1";
pub const CONFIG_SIGNER_CERTIFICATE_KEY: &[u8] = b"config/signer-certificate/v1";
pub const CONFIG_HISTORY_KEY_PREFIX: &[u8] = b"config/history/v1/";

/// A validated member-side configuration checkpoint backed by an injected state store.
///
/// Updates are fully validated in memory and then the envelope, head, and certificate
/// needed to reopen that envelope are replaced in one compare-and-swap batch.
pub struct PersistedConfigState<S> {
    store: S,
    root: NetworkRootPublic,
    encryption: MemberEncryptionKeypair,
    config: ValidatedNetworkConfig,
    head: ConfigHead,
    envelope_version: u64,
    head_version: u64,
    signer_version: u64,
}

impl<S: StateStore> PersistedConfigState<S> {
    pub async fn open(
        store: S,
        root: NetworkRootPublic,
        encryption: MemberEncryptionKeypair,
        now_ms: u64,
    ) -> Result<Self, ConfigStateError> {
        let network_id = root.network_id();
        let scope = StoreScope::member(network_id);
        let envelope_record = store
            .read(scope, &StoreKey::new(CONFIG_ENVELOPE_KEY)?)
            .await?
            .ok_or(ConfigStateError::NotJoined)?;
        let head_record = store
            .read(scope, &StoreKey::new(CONFIG_HEAD_KEY)?)
            .await?
            .ok_or(ConfigStateError::NotJoined)?;
        let signer_record = store
            .read(scope, &StoreKey::new(CONFIG_SIGNER_CERTIFICATE_KEY)?)
            .await?
            .ok_or(ConfigStateError::NotJoined)?;
        let envelope = EncryptedConfigEnvelope::from_bytes(&envelope_record.bytes)?;
        let head = decode_head(&head_record.bytes)?;
        let signer = AdminCertificate::from_bytes(&signer_record.bytes)?;
        let verified_signer = signer.verify(&root, network_id, now_ms, &Default::default())?;
        let opened = envelope.open_config_with_verified_admin(
            &root,
            &verified_signer,
            &encryption,
            ChainExpectation::Checkpoint(head),
            now_ms,
        )?;
        seed_history(
            &store,
            scope,
            opened.head.revision,
            envelope_record.bytes.clone(),
        )
        .await?;
        Ok(Self {
            store,
            root,
            encryption,
            config: opened.config,
            head: opened.head,
            envelope_version: envelope_record.version,
            head_version: head_record.version,
            signer_version: signer_record.version,
        })
    }

    pub fn network_id(&self) -> NetworkId {
        self.root.network_id()
    }

    pub fn head(&self) -> ConfigHead {
        self.head
    }

    pub fn config(&self) -> &ValidatedNetworkConfig {
        &self.config
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub async fn apply(
        &mut self,
        updates: &ConfigUpdateBatch,
        now_ms: u64,
    ) -> Result<ConfigHead, ConfigStateError> {
        if updates.network_id != self.network_id() || updates.base_head != self.head {
            return Err(ConfigStateError::BaseHeadMismatch);
        }
        if updates.envelopes.is_empty() {
            return Ok(self.head);
        }

        // Reparse the transport object to enforce its bounds and exact chain shape even
        // when it was constructed directly by an in-process caller.
        let updates = ConfigUpdateBatch::from_bytes(&updates.to_bytes()?)?;
        let mut current_config = self.config.clone();
        let mut current_head = self.head;
        let mut final_envelope = None;
        let mut final_signer = None;
        for raw in &updates.envelopes {
            let envelope = EncryptedConfigEnvelope::from_bytes(raw)?;
            let signer = current_config
                .as_config()
                .admin_keys
                .iter()
                .find_map(|admin| {
                    AdminCertificate::from_bytes(&admin.certificate)
                        .ok()
                        .filter(|certificate| {
                            certificate.payload().key_id == envelope.signer_key_id
                        })
                        .map(|_| admin.certificate.clone())
                })
                .ok_or(ConfigStateError::MissingSignerCertificate)?;
            let opened = envelope.open_next_config(
                &self.root,
                &current_config,
                &self.encryption,
                current_head,
                now_ms,
            )?;
            current_config = opened.config;
            current_head = opened.head;
            final_envelope = Some(raw.clone());
            final_signer = Some(signer);
        }

        let final_envelope = final_envelope.expect("non-empty update batch");
        let final_signer = final_signer.expect("non-empty update batch");
        let scope = StoreScope::member(self.network_id());
        let envelope_key = StoreKey::new(CONFIG_ENVELOPE_KEY)?;
        let head_key = StoreKey::new(CONFIG_HEAD_KEY)?;
        let signer_key = StoreKey::new(CONFIG_SIGNER_CERTIFICATE_KEY)?;
        let mut batch = AtomicBatch::new(scope);
        batch.put(
            envelope_key.clone(),
            final_envelope.clone(),
            ExpectedVersion::Exact(self.envelope_version),
        )?;
        batch.put(
            head_key.clone(),
            encode_head(current_head),
            ExpectedVersion::Exact(self.head_version),
        )?;
        batch.put(
            signer_key.clone(),
            final_signer,
            ExpectedVersion::Exact(self.signer_version),
        )?;
        for raw in &updates.envelopes {
            let envelope = EncryptedConfigEnvelope::from_bytes(raw)?;
            batch.put(
                history_key(envelope.revision)?,
                raw.clone(),
                ExpectedVersion::Missing,
            )?;
        }
        self.store.commit(batch).await?;

        let envelope_record = self
            .store
            .read(scope, &envelope_key)
            .await?
            .ok_or(ConfigStateError::CommitLost)?;
        let head_record = self
            .store
            .read(scope, &head_key)
            .await?
            .ok_or(ConfigStateError::CommitLost)?;
        let signer_record = self
            .store
            .read(scope, &signer_key)
            .await?
            .ok_or(ConfigStateError::CommitLost)?;
        if envelope_record.bytes != final_envelope
            || decode_head(&head_record.bytes)? != current_head
        {
            return Err(ConfigStateError::CommitLost);
        }
        self.config = current_config;
        self.head = current_head;
        self.envelope_version = envelope_record.version;
        self.head_version = head_record.version;
        self.signer_version = signer_record.version;
        Ok(self.head)
    }

    pub async fn updates_after(
        &self,
        base_head: ConfigHead,
    ) -> Result<ConfigUpdateBatch, ConfigStateError> {
        if base_head.revision > self.head.revision || base_head.epoch > self.head.epoch {
            return Err(ConfigStateError::UnknownHead);
        }
        let scope = StoreScope::member(self.network_id());
        let base = self
            .store
            .read(scope, &history_key(base_head.revision)?)
            .await?
            .ok_or(ConfigStateError::UnknownHead)?;
        let base_envelope = EncryptedConfigEnvelope::from_bytes(&base.bytes)?;
        if base_envelope.epoch != base_head.epoch
            || base_envelope.revision != base_head.revision
            || base_envelope.envelope_hash() != base_head.hash
        {
            return Err(ConfigStateError::UnknownHead);
        }
        let mut envelopes = Vec::new();
        for revision in base_head.revision + 1..=self.head.revision {
            let record = self
                .store
                .read(scope, &history_key(revision)?)
                .await?
                .ok_or(ConfigStateError::HistoryUnavailable)?;
            envelopes.push(record.bytes);
        }
        Ok(ConfigUpdateBatch::new(
            self.network_id(),
            base_head,
            envelopes,
        )?)
    }
}

#[derive(Debug, Error)]
pub enum ConfigStateError {
    #[error("node has no complete joined configuration checkpoint")]
    NotJoined,
    #[error("configuration update base does not equal the persisted head")]
    BaseHeadMismatch,
    #[error("current configuration does not contain the update signer's certificate")]
    MissingSignerCertificate,
    #[error("configuration commit could not be read back exactly")]
    CommitLost,
    #[error("stored configuration head is malformed")]
    MalformedHead,
    #[error("requested configuration head is unknown to this member")]
    UnknownHead,
    #[error("member does not retain a complete revision chain after the requested head")]
    HistoryUnavailable,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Config(#[from] weaver_config::ConfigError),
    #[error(transparent)]
    Crypto(#[from] weaver_crypto::CertificateError),
}

fn history_key(revision: u64) -> Result<StoreKey, StoreError> {
    let mut key = Vec::with_capacity(CONFIG_HISTORY_KEY_PREFIX.len() + 8);
    key.extend_from_slice(CONFIG_HISTORY_KEY_PREFIX);
    key.extend_from_slice(&revision.to_be_bytes());
    StoreKey::new(key)
}

async fn seed_history<S: StateStore>(
    store: &S,
    scope: StoreScope,
    revision: u64,
    envelope: Bytes,
) -> Result<(), ConfigStateError> {
    let key = history_key(revision)?;
    if let Some(existing) = store.read(scope, &key).await? {
        return if existing.bytes == envelope {
            Ok(())
        } else {
            Err(ConfigStateError::HistoryUnavailable)
        };
    }
    let mut batch = AtomicBatch::new(scope);
    batch.put(key.clone(), envelope.clone(), ExpectedVersion::Missing)?;
    match store.commit(batch).await {
        Ok(_) => Ok(()),
        Err(StoreError::VersionConflict { .. }) => match store.read(scope, &key).await? {
            Some(existing) if existing.bytes == envelope => Ok(()),
            _ => Err(ConfigStateError::HistoryUnavailable),
        },
        Err(error) => Err(error.into()),
    }
}

pub fn encode_head(head: ConfigHead) -> Bytes {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&head.epoch.to_be_bytes());
    out.extend_from_slice(&head.revision.to_be_bytes());
    out.extend_from_slice(&head.hash);
    Bytes::from(out)
}

pub fn decode_head(bytes: &[u8]) -> Result<ConfigHead, ConfigStateError> {
    if bytes.len() != 48 {
        return Err(ConfigStateError::MalformedHead);
    }
    Ok(ConfigHead {
        epoch: u64::from_be_bytes(bytes[0..8].try_into().expect("checked length")),
        revision: u64::from_be_bytes(bytes[8..16].try_into().expect("checked length")),
        hash: bytes[16..48].try_into().expect("checked length"),
    })
}
