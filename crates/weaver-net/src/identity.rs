use std::fmt;

use bytes::Bytes;
use iroh::{EndpointId, SecretKey};
use thiserror::Error;
use weaver_core::{AppAddr, DeviceId, NetworkId};
use weaver_store::{
    AtomicBatch, ExpectedVersion, SecretBytes, SecretId, SecretStore, SecretStoreError, StateStore,
    StoreError, StoreKey, StoreScope, ensure_supported_schema,
};

const IDENTITY_KEY_PREFIX: &[u8] = b"identity/client/v1/";
const RECORD_MAGIC: &[u8; 8] = b"WVRID\0\0\x01";
const RECORD_LEN: usize = RECORD_MAGIC.len() + 32 + 32 + 32;

/// Stable client identity restored from separate state and secret stores.
pub struct PersistentClientIdentity {
    secret_key: SecretKey,
    device_id: DeviceId,
    secret_id: SecretId,
}

impl PersistentClientIdentity {
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.secret_key.public()
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }
}

impl fmt::Debug for PersistentClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentClientIdentity")
            .field("endpoint_id", &self.endpoint_id())
            .field("device_id", &self.device_id)
            .field("secret_key", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error(transparent)]
    State(#[from] StoreError),
    #[error(transparent)]
    Secret(#[from] SecretStoreError),
    #[error("persistent client identity record is corrupt")]
    CorruptRecord,
    #[error("stored endpoint secret does not match its committed public identity")]
    SecretPublicKeyMismatch,
    #[error("stored DeviceId does not match the network/app/endpoint identity derivation")]
    DeviceIdMismatch,
    #[error("identity creation lost a race but no committed identity could be read")]
    MissingAfterConcurrentCreate,
}

/// Loads a client identity or creates it using the crash-safe secret-first sequence.
///
/// A new secret is sealed and read back before the state record referencing it is
/// atomically committed. A crash can therefore leave only an unreferenced secret, never a
/// committed state record pointing to a missing secret.
pub async fn load_or_create_client_identity(
    state_store: &dyn StateStore,
    secret_store: &dyn SecretStore,
    network_id: NetworkId,
    app_addr: AppAddr,
) -> Result<PersistentClientIdentity, IdentityError> {
    ensure_supported_schema(state_store).await?;
    let scope = StoreScope::member(network_id);
    let key = identity_key(app_addr)?;
    if let Some(identity) =
        load_existing(state_store, secret_store, scope, &key, network_id, app_addr).await?
    {
        return Ok(identity);
    }

    let secret_key = SecretKey::generate();
    let endpoint_id = secret_key.public();
    let device_id = derive_device_id(network_id, app_addr, endpoint_id);
    let secret_id = derive_secret_id(network_id, app_addr, endpoint_id);
    secret_store
        .seal(
            secret_id.clone(),
            SecretBytes::new(secret_key.to_bytes().to_vec()),
        )
        .await?;
    let confirmed = secret_store.open(&secret_id).await?;
    if confirmed.expose() != secret_key.to_bytes() {
        return Err(IdentityError::SecretPublicKeyMismatch);
    }

    let record = encode_record(&secret_id, endpoint_id, device_id);
    let mut batch = AtomicBatch::new(scope);
    batch.put(key.clone(), record, ExpectedVersion::Missing)?;
    match state_store.commit(batch).await {
        Ok(_) => Ok(PersistentClientIdentity {
            secret_key,
            device_id,
            secret_id,
        }),
        Err(StoreError::VersionConflict { .. }) => {
            let winner =
                load_existing(state_store, secret_store, scope, &key, network_id, app_addr)
                    .await?
                    .ok_or(IdentityError::MissingAfterConcurrentCreate)?;
            if winner.secret_id != secret_id {
                // This secret is known not to be referenced by the winning record.
                secret_store.delete(&secret_id).await?;
            }
            Ok(winner)
        }
        // The backend may have durably committed and then lost the acknowledgement. Keep
        // the secret; startup GC can remove it if it is truly unreferenced.
        Err(error) => Err(error.into()),
    }
}

async fn load_existing(
    state_store: &dyn StateStore,
    secret_store: &dyn SecretStore,
    scope: StoreScope,
    key: &StoreKey,
    network_id: NetworkId,
    app_addr: AppAddr,
) -> Result<Option<PersistentClientIdentity>, IdentityError> {
    let Some(record) = state_store.read(scope, key).await? else {
        return Ok(None);
    };
    let (secret_id, committed_endpoint, device_id) = decode_record(&record.bytes)?;
    let secret = secret_store.open(&secret_id).await?;
    let secret_bytes: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| IdentityError::CorruptRecord)?;
    let secret_key = SecretKey::from_bytes(&secret_bytes);
    if secret_key.public() != committed_endpoint {
        return Err(IdentityError::SecretPublicKeyMismatch);
    }
    if derive_device_id(network_id, app_addr, committed_endpoint) != device_id {
        return Err(IdentityError::DeviceIdMismatch);
    }
    Ok(Some(PersistentClientIdentity {
        secret_key,
        device_id,
        secret_id,
    }))
}

fn identity_key(app_addr: AppAddr) -> Result<StoreKey, StoreError> {
    let mut key = Vec::with_capacity(IDENTITY_KEY_PREFIX.len() + 32);
    key.extend_from_slice(IDENTITY_KEY_PREFIX);
    key.extend_from_slice(app_addr.as_bytes());
    StoreKey::new(key)
}

fn derive_device_id(network_id: NetworkId, app_addr: AppAddr, endpoint_id: EndpointId) -> DeviceId {
    let mut hasher = blake3::Hasher::new_derive_key("weaver.device.v1");
    hasher.update(network_id.as_bytes());
    hasher.update(app_addr.as_bytes());
    hasher.update(endpoint_id.as_bytes());
    DeviceId::from_bytes(*hasher.finalize().as_bytes())
}

fn derive_secret_id(network_id: NetworkId, app_addr: AppAddr, endpoint_id: EndpointId) -> SecretId {
    let mut hasher = blake3::Hasher::new_derive_key("weaver.secret.endpoint.v1");
    hasher.update(network_id.as_bytes());
    hasher.update(app_addr.as_bytes());
    hasher.update(endpoint_id.as_bytes());
    SecretId::from_bytes(*hasher.finalize().as_bytes())
}

fn encode_record(secret_id: &SecretId, endpoint_id: EndpointId, device_id: DeviceId) -> Bytes {
    let mut bytes = Vec::with_capacity(RECORD_LEN);
    bytes.extend_from_slice(RECORD_MAGIC);
    bytes.extend_from_slice(secret_id.as_bytes());
    bytes.extend_from_slice(endpoint_id.as_bytes());
    bytes.extend_from_slice(device_id.as_bytes());
    Bytes::from(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<(SecretId, EndpointId, DeviceId), IdentityError> {
    if bytes.len() != RECORD_LEN || &bytes[..RECORD_MAGIC.len()] != RECORD_MAGIC {
        return Err(IdentityError::CorruptRecord);
    }
    let secret_offset = RECORD_MAGIC.len();
    let endpoint_offset = secret_offset + 32;
    let device_offset = endpoint_offset + 32;
    let secret_id = SecretId::from_bytes(
        bytes[secret_offset..endpoint_offset]
            .try_into()
            .map_err(|_| IdentityError::CorruptRecord)?,
    );
    let endpoint_id = EndpointId::from_bytes(
        bytes[endpoint_offset..device_offset]
            .try_into()
            .map_err(|_| IdentityError::CorruptRecord)?,
    )
    .map_err(|_| IdentityError::CorruptRecord)?;
    let device_id = DeviceId::from_bytes(
        bytes[device_offset..]
            .try_into()
            .map_err(|_| IdentityError::CorruptRecord)?,
    );
    Ok((secret_id, endpoint_id, device_id))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use weaver_store::{
        MemorySecretStore, MemoryStateStore, RedbStateStore, SecretStore, StateStore, StoreScope,
    };

    use super::*;

    const NETWORK: NetworkId = NetworkId::from_bytes([0x11; 32]);
    const APP: AppAddr = AppAddr::from_bytes([0x22; 32]);

    #[tokio::test]
    async fn identity_is_stable_across_reopen() {
        let state = MemoryStateStore::new();
        let secrets = MemorySecretStore::default();
        let first = load_or_create_client_identity(&state, &secrets, NETWORK, APP)
            .await
            .unwrap();
        let reopened = load_or_create_client_identity(&state, &secrets, NETWORK, APP)
            .await
            .unwrap();

        assert_eq!(first.endpoint_id(), reopened.endpoint_id());
        assert_eq!(first.device_id(), reopened.device_id());
        assert_eq!(
            first.secret_key().to_bytes(),
            reopened.secret_key().to_bytes()
        );
    }

    #[tokio::test]
    async fn identity_state_survives_real_database_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.redb");
        let secrets = MemorySecretStore::default();
        let endpoint_id;
        let device_id;
        {
            let state = RedbStateStore::open(&path).unwrap();
            let identity = load_or_create_client_identity(&state, &secrets, NETWORK, APP)
                .await
                .unwrap();
            endpoint_id = identity.endpoint_id();
            device_id = identity.device_id();
        }

        let reopened = RedbStateStore::open(path).unwrap();
        let identity = load_or_create_client_identity(&reopened, &secrets, NETWORK, APP)
            .await
            .unwrap();
        assert_eq!(identity.endpoint_id(), endpoint_id);
        assert_eq!(identity.device_id(), device_id);
    }

    #[tokio::test]
    async fn identities_are_scoped_by_network_and_app() {
        let state = MemoryStateStore::new();
        let secrets = MemorySecretStore::default();
        let first = load_or_create_client_identity(&state, &secrets, NETWORK, APP)
            .await
            .unwrap();
        let other_network = load_or_create_client_identity(
            &state,
            &secrets,
            NetworkId::from_bytes([0x33; 32]),
            APP,
        )
        .await
        .unwrap();
        let other_app = load_or_create_client_identity(
            &state,
            &secrets,
            NETWORK,
            AppAddr::from_bytes([0x44; 32]),
        )
        .await
        .unwrap();

        assert_ne!(first.endpoint_id(), other_network.endpoint_id());
        assert_ne!(first.device_id(), other_network.device_id());
        assert_ne!(first.endpoint_id(), other_app.endpoint_id());
        assert_ne!(first.device_id(), other_app.device_id());
    }

    #[tokio::test]
    async fn missing_referenced_secret_fails_closed() {
        let state = MemoryStateStore::new();
        let secrets = MemorySecretStore::default();
        let identity = load_or_create_client_identity(&state, &secrets, NETWORK, APP)
            .await
            .unwrap();
        secrets.delete(identity.secret_id()).await.unwrap();

        assert!(matches!(
            load_or_create_client_identity(&state, &secrets, NETWORK, APP).await,
            Err(IdentityError::Secret(SecretStoreError::NotFound))
        ));
    }

    #[tokio::test]
    async fn concurrent_creation_converges_on_one_identity() {
        let state = Arc::new(MemoryStateStore::new());
        let secrets = Arc::new(MemorySecretStore::default());
        let first = {
            let state = state.clone();
            let secrets = secrets.clone();
            tokio::spawn(async move {
                load_or_create_client_identity(&*state, &*secrets, NETWORK, APP).await
            })
        };
        let second = {
            let state = state.clone();
            let secrets = secrets.clone();
            tokio::spawn(async move {
                load_or_create_client_identity(&*state, &*secrets, NETWORK, APP).await
            })
        };
        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();

        assert_eq!(first.endpoint_id(), second.endpoint_id());
        assert_eq!(first.device_id(), second.device_id());
        let key = identity_key(APP).unwrap();
        assert!(
            state
                .read(StoreScope::member(NETWORK), &key)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn corrupt_record_is_rejected_before_secret_use() {
        let state = MemoryStateStore::new();
        let secrets = MemorySecretStore::default();
        let key = identity_key(APP).unwrap();
        let mut batch = AtomicBatch::new(StoreScope::member(NETWORK));
        batch
            .put(
                key,
                Bytes::from_static(b"corrupt"),
                ExpectedVersion::Missing,
            )
            .unwrap();
        state.commit(batch).await.unwrap();

        assert!(matches!(
            load_or_create_client_identity(&state, &secrets, NETWORK, APP).await,
            Err(IdentityError::CorruptRecord)
        ));
    }
}
