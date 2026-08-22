//! Injectable persistence interfaces for Weaver.
//!
//! Versioned state and secret material are deliberately separated. Backends persist
//! opaque bytes only; protocol validation, encryption and schema migrations stay in
//! Weaver's trusted layers.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::Arc,
};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{StreamExt, stream, stream::BoxStream};
use thiserror::Error;
use tokio::sync::Mutex;
use weaver_core::NetworkId;
use zeroize::Zeroizing;

mod redb_store;
mod secret_file;

pub use redb_store::RedbStateStore;
pub use secret_file::EncryptedFileSecretStore;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;
pub const MAX_KEY_LEN: usize = 1024;
pub const MAX_VALUE_LEN: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateStoreCapabilities {
    pub atomic_batches: bool,
    pub durable_commits: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretProtection {
    InMemoryTestOnly,
    ExternalKeyEncrypted,
    SystemProtected,
}

/// Library-created namespace. It cannot be constructed from an arbitrary application string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreScope {
    kind: ScopeKind,
    network_id: NetworkId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ScopeKind {
    Member,
    Authority,
}

impl StoreScope {
    pub const fn member(network_id: NetworkId) -> Self {
        Self {
            kind: ScopeKind::Member,
            network_id,
        }
    }

    pub const fn authority(network_id: NetworkId) -> Self {
        Self {
            kind: ScopeKind::Authority,
            network_id,
        }
    }

    pub const fn network_id(self) -> NetworkId {
        self.network_id
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreKey(Bytes);

impl StoreKey {
    pub fn new(bytes: impl Into<Bytes>) -> Result<Self, StoreError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_KEY_LEN {
            return Err(StoreError::InvalidKeyLength(bytes.len()));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StoreKey")
            .field(&String::from_utf8_lossy(&self.0))
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedBytes {
    pub version: u64,
    pub bytes: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEntry {
    pub key: StoreKey,
    pub value: VersionedBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedVersion {
    Any,
    Missing,
    Exact(u64),
}

#[derive(Clone, Debug)]
enum BatchOperation {
    Put {
        key: StoreKey,
        value: Bytes,
        expected: ExpectedVersion,
    },
    Delete {
        key: StoreKey,
        expected: ExpectedVersion,
    },
}

#[derive(Clone, Debug)]
pub struct AtomicBatch {
    scope: StoreScope,
    operations: Vec<BatchOperation>,
    keys: HashSet<StoreKey>,
}

impl AtomicBatch {
    pub fn new(scope: StoreScope) -> Self {
        Self {
            scope,
            operations: Vec::new(),
            keys: HashSet::new(),
        }
    }

    pub fn put(
        &mut self,
        key: StoreKey,
        value: impl Into<Bytes>,
        expected: ExpectedVersion,
    ) -> Result<&mut Self, StoreError> {
        let value = value.into();
        if value.len() > MAX_VALUE_LEN {
            return Err(StoreError::ValueTooLarge(value.len()));
        }
        self.insert_unique(&key)?;
        self.operations.push(BatchOperation::Put {
            key,
            value,
            expected,
        });
        Ok(self)
    }

    pub fn delete(
        &mut self,
        key: StoreKey,
        expected: ExpectedVersion,
    ) -> Result<&mut Self, StoreError> {
        self.insert_unique(&key)?;
        self.operations
            .push(BatchOperation::Delete { key, expected });
        Ok(self)
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    fn insert_unique(&mut self, key: &StoreKey) -> Result<(), StoreError> {
        if !self.keys.insert(key.clone()) {
            return Err(StoreError::DuplicateBatchKey(key.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitVersion(pub u64);

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store key length must be 1..={MAX_KEY_LEN}, got {0}")]
    InvalidKeyLength(usize),
    #[error("store value exceeds {MAX_VALUE_LEN} bytes: {0}")]
    ValueTooLarge(usize),
    #[error("atomic batch contains the key more than once: {0:?}")]
    DuplicateBatchKey(StoreKey),
    #[error("version condition failed for {key:?}: expected {expected:?}, actual {actual:?}")]
    VersionConflict {
        key: StoreKey,
        expected: ExpectedVersion,
        actual: Option<u64>,
    },
    #[error("state store schema {found} is newer than supported schema {supported}")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("state store backend error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait StateStore: Send + Sync + 'static {
    fn capabilities(&self) -> StateStoreCapabilities;

    async fn schema_version(&self) -> Result<u32, StoreError>;

    async fn read(
        &self,
        scope: StoreScope,
        key: &StoreKey,
    ) -> Result<Option<VersionedBytes>, StoreError>;

    async fn scan_prefix(
        &self,
        scope: StoreScope,
        prefix: &[u8],
    ) -> Result<BoxStream<'static, Result<StoredEntry, StoreError>>, StoreError>;

    async fn commit(&self, batch: AtomicBatch) -> Result<CommitVersion, StoreError>;
}

#[async_trait]
impl<T: StateStore + ?Sized> StateStore for Arc<T> {
    fn capabilities(&self) -> StateStoreCapabilities {
        (**self).capabilities()
    }

    async fn schema_version(&self) -> Result<u32, StoreError> {
        (**self).schema_version().await
    }

    async fn read(
        &self,
        scope: StoreScope,
        key: &StoreKey,
    ) -> Result<Option<VersionedBytes>, StoreError> {
        (**self).read(scope, key).await
    }

    async fn scan_prefix(
        &self,
        scope: StoreScope,
        prefix: &[u8],
    ) -> Result<BoxStream<'static, Result<StoredEntry, StoreError>>, StoreError> {
        (**self).scan_prefix(scope, prefix).await
    }

    async fn commit(&self, batch: AtomicBatch) -> Result<CommitVersion, StoreError> {
        (**self).commit(batch).await
    }
}

#[derive(Debug)]
struct MemoryState {
    schema_version: u32,
    next_record_version: u64,
    next_commit_version: u64,
    records: BTreeMap<(StoreScope, StoreKey), VersionedBytes>,
}

#[derive(Clone, Debug)]
pub struct MemoryStateStore {
    state: Arc<Mutex<MemoryState>>,
}

impl Default for MemoryStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStateStore {
    pub fn new() -> Self {
        Self::with_schema_version(CURRENT_SCHEMA_VERSION)
    }

    pub fn with_schema_version(schema_version: u32) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryState {
                schema_version,
                next_record_version: 1,
                next_commit_version: 1,
                records: BTreeMap::new(),
            })),
        }
    }
}

#[async_trait]
impl StateStore for MemoryStateStore {
    fn capabilities(&self) -> StateStoreCapabilities {
        StateStoreCapabilities {
            atomic_batches: true,
            durable_commits: false,
        }
    }

    async fn schema_version(&self) -> Result<u32, StoreError> {
        Ok(self.state.lock().await.schema_version)
    }

    async fn read(
        &self,
        scope: StoreScope,
        key: &StoreKey,
    ) -> Result<Option<VersionedBytes>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .records
            .get(&(scope, key.clone()))
            .cloned())
    }

    async fn scan_prefix(
        &self,
        scope: StoreScope,
        prefix: &[u8],
    ) -> Result<BoxStream<'static, Result<StoredEntry, StoreError>>, StoreError> {
        let entries = self
            .state
            .lock()
            .await
            .records
            .iter()
            .filter(|((entry_scope, key), _)| {
                *entry_scope == scope && key.as_bytes().starts_with(prefix)
            })
            .map(|((_, key), value)| {
                Ok(StoredEntry {
                    key: key.clone(),
                    value: value.clone(),
                })
            })
            .collect::<Vec<_>>();
        Ok(stream::iter(entries).boxed())
    }

    async fn commit(&self, batch: AtomicBatch) -> Result<CommitVersion, StoreError> {
        let mut state = self.state.lock().await;
        for operation in &batch.operations {
            let (key, expected) = match operation {
                BatchOperation::Put { key, expected, .. }
                | BatchOperation::Delete { key, expected } => (key, *expected),
            };
            let actual = state
                .records
                .get(&(batch.scope, key.clone()))
                .map(|value| value.version);
            let valid = match expected {
                ExpectedVersion::Any => true,
                ExpectedVersion::Missing => actual.is_none(),
                ExpectedVersion::Exact(version) => actual == Some(version),
            };
            if !valid {
                return Err(StoreError::VersionConflict {
                    key: key.clone(),
                    expected,
                    actual,
                });
            }
        }

        for operation in batch.operations {
            match operation {
                BatchOperation::Put { key, value, .. } => {
                    let version = state.next_record_version;
                    state.next_record_version += 1;
                    state.records.insert(
                        (batch.scope, key),
                        VersionedBytes {
                            version,
                            bytes: value,
                        },
                    );
                }
                BatchOperation::Delete { key, .. } => {
                    state.records.remove(&(batch.scope, key));
                }
            }
        }
        let commit = CommitVersion(state.next_commit_version);
        state.next_commit_version += 1;
        Ok(commit)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SecretId([u8; 32]);

impl SecretId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretId([redacted-id])")
    }
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([redacted])")
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretStoreError {
    #[error("secret was not found")]
    NotFound,
    #[error("refusing to overwrite an existing secret with different bytes")]
    AlreadyExistsDifferent,
    #[error("secret ciphertext authentication failed")]
    AuthenticationFailed,
    #[error("secret store backend error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait SecretStore: Send + Sync + 'static {
    fn protection(&self) -> SecretProtection;

    async fn seal(&self, id: SecretId, plaintext: SecretBytes) -> Result<(), SecretStoreError>;

    async fn open(&self, id: &SecretId) -> Result<SecretBytes, SecretStoreError>;

    async fn delete(&self, id: &SecretId) -> Result<(), SecretStoreError>;
}

#[async_trait]
impl<T: SecretStore + ?Sized> SecretStore for Arc<T> {
    fn protection(&self) -> SecretProtection {
        (**self).protection()
    }

    async fn seal(&self, id: SecretId, plaintext: SecretBytes) -> Result<(), SecretStoreError> {
        (**self).seal(id, plaintext).await
    }

    async fn open(&self, id: &SecretId) -> Result<SecretBytes, SecretStoreError> {
        (**self).open(id).await
    }

    async fn delete(&self, id: &SecretId) -> Result<(), SecretStoreError> {
        (**self).delete(id).await
    }
}

#[derive(Clone, Default)]
pub struct MemorySecretStore {
    secrets: Arc<Mutex<HashMap<SecretId, Zeroizing<Vec<u8>>>>>,
}

impl fmt::Debug for MemorySecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemorySecretStore")
            .field("contents", &"[redacted]")
            .finish()
    }
}

#[async_trait]
impl SecretStore for MemorySecretStore {
    fn protection(&self) -> SecretProtection {
        SecretProtection::InMemoryTestOnly
    }

    async fn seal(&self, id: SecretId, plaintext: SecretBytes) -> Result<(), SecretStoreError> {
        let mut secrets = self.secrets.lock().await;
        if let Some(existing) = secrets.get(&id) {
            return if existing.as_slice() == plaintext.expose() {
                Ok(())
            } else {
                Err(SecretStoreError::AlreadyExistsDifferent)
            };
        }
        secrets.insert(id, plaintext.0);
        Ok(())
    }

    async fn open(&self, id: &SecretId) -> Result<SecretBytes, SecretStoreError> {
        self.secrets
            .lock()
            .await
            .get(id)
            .map(|secret| SecretBytes::new(secret.to_vec()))
            .ok_or(SecretStoreError::NotFound)
    }

    async fn delete(&self, id: &SecretId) -> Result<(), SecretStoreError> {
        self.secrets.lock().await.remove(id);
        Ok(())
    }
}

pub async fn ensure_supported_schema(store: &dyn StateStore) -> Result<(), StoreError> {
    let found = store.schema_version().await?;
    if found > CURRENT_SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: &'static str) -> StoreKey {
        StoreKey::new(value).unwrap()
    }

    #[tokio::test]
    async fn failed_precondition_rolls_back_entire_batch() {
        let store = MemoryStateStore::new();
        let scope = StoreScope::member(NetworkId::from_bytes([1; 32]));
        let mut initial = AtomicBatch::new(scope);
        initial
            .put(
                key("head"),
                Bytes::from_static(b"v1"),
                ExpectedVersion::Missing,
            )
            .unwrap();
        store.commit(initial).await.unwrap();

        let mut conflicting = AtomicBatch::new(scope);
        conflicting
            .put(
                key("head"),
                Bytes::from_static(b"v2"),
                ExpectedVersion::Exact(999),
            )
            .unwrap()
            .put(
                key("envelope/2"),
                Bytes::from_static(b"must-not-commit"),
                ExpectedVersion::Missing,
            )
            .unwrap();
        assert!(matches!(
            store.commit(conflicting).await,
            Err(StoreError::VersionConflict { .. })
        ));

        assert_eq!(
            store
                .read(scope, &key("head"))
                .await
                .unwrap()
                .unwrap()
                .bytes,
            b"v1"[..]
        );
        assert!(
            store
                .read(scope, &key("envelope/2"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn network_and_authority_scopes_are_isolated() {
        let store = MemoryStateStore::new();
        let network_a = NetworkId::from_bytes([0xa; 32]);
        let network_b = NetworkId::from_bytes([0xb; 32]);
        let scopes = [
            StoreScope::member(network_a),
            StoreScope::member(network_b),
            StoreScope::authority(network_a),
        ];

        for (index, scope) in scopes.into_iter().enumerate() {
            let mut batch = AtomicBatch::new(scope);
            batch
                .put(
                    key("same-key"),
                    Bytes::from(vec![index as u8]),
                    ExpectedVersion::Missing,
                )
                .unwrap();
            store.commit(batch).await.unwrap();
        }

        for (index, scope) in scopes.into_iter().enumerate() {
            assert_eq!(
                store
                    .read(scope, &key("same-key"))
                    .await
                    .unwrap()
                    .unwrap()
                    .bytes,
                [index as u8].as_slice()
            );
        }
    }

    #[tokio::test]
    async fn prefix_scan_is_scoped_and_sorted() {
        let store = MemoryStateStore::new();
        let scope = StoreScope::member(NetworkId::from_bytes([2; 32]));
        let mut batch = AtomicBatch::new(scope);
        batch
            .put(
                key("cfg/2"),
                Bytes::from_static(b"2"),
                ExpectedVersion::Missing,
            )
            .unwrap()
            .put(
                key("cfg/1"),
                Bytes::from_static(b"1"),
                ExpectedVersion::Missing,
            )
            .unwrap()
            .put(
                key("peer/1"),
                Bytes::from_static(b"p"),
                ExpectedVersion::Missing,
            )
            .unwrap();
        store.commit(batch).await.unwrap();

        let entries = store
            .scan_prefix(scope, b"cfg/")
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.key.as_bytes())
                .collect::<Vec<_>>(),
            vec![b"cfg/1".as_slice(), b"cfg/2".as_slice()]
        );
    }

    #[tokio::test]
    async fn secret_seal_is_idempotent_but_never_overwrites() {
        let store = MemorySecretStore::default();
        let id = SecretId::from_bytes([7; 32]);
        store
            .seal(id.clone(), SecretBytes::new(b"secret".to_vec()))
            .await
            .unwrap();
        store
            .seal(id.clone(), SecretBytes::new(b"secret".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            store.open(&id).await.unwrap().expose(),
            b"secret".as_slice()
        );
        assert_eq!(
            store
                .seal(id.clone(), SecretBytes::new(b"different".to_vec()))
                .await,
            Err(SecretStoreError::AlreadyExistsDifferent)
        );
        store.delete(&id).await.unwrap();
        assert!(matches!(
            store.open(&id).await,
            Err(SecretStoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn newer_schema_is_rejected() {
        let store = MemoryStateStore::with_schema_version(CURRENT_SCHEMA_VERSION + 1);
        assert!(matches!(
            ensure_supported_schema(&store).await,
            Err(StoreError::SchemaTooNew { .. })
        ));
    }
}
