use std::{path::Path, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{StreamExt, stream, stream::BoxStream};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{
    AtomicBatch, BatchOperation, CommitVersion, ExpectedVersion, ScopeKind, StateStore,
    StateStoreCapabilities, StoreError, StoreKey, StoreScope, StoredEntry, VersionedBytes,
};

const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("weaver_records_v1");
const META: TableDefinition<&str, u64> = TableDefinition::new("weaver_meta_v1");
const META_SCHEMA_VERSION: &str = "schema_version";
const META_NEXT_RECORD_VERSION: &str = "next_record_version";
const META_NEXT_COMMIT_VERSION: &str = "next_commit_version";
const SCOPE_PREFIX_LEN: usize = 33;

/// Crash-safe, durable StateStore backed by redb ACID transactions.
#[derive(Clone, Debug)]
pub struct RedbStateStore {
    database: Arc<Database>,
}

impl RedbStateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(backend)?;
        }
        let database = Database::create(path).map_err(backend)?;
        initialize(&database)?;
        Ok(Self {
            database: Arc::new(database),
        })
    }
}

fn initialize(database: &Database) -> Result<(), StoreError> {
    let write = database.begin_write().map_err(backend)?;
    {
        let _records = write.open_table(RECORDS).map_err(backend)?;
        let mut meta = write.open_table(META).map_err(backend)?;
        let schema_version = meta
            .get(META_SCHEMA_VERSION)
            .map_err(backend)?
            .map(|version| version.value());
        match schema_version {
            Some(version) if version > crate::CURRENT_SCHEMA_VERSION as u64 => {
                return Err(StoreError::SchemaTooNew {
                    found: version as u32,
                    supported: crate::CURRENT_SCHEMA_VERSION,
                });
            }
            Some(_) => {}
            None => {
                meta.insert(META_SCHEMA_VERSION, crate::CURRENT_SCHEMA_VERSION as u64)
                    .map_err(backend)?;
                meta.insert(META_NEXT_RECORD_VERSION, 1).map_err(backend)?;
                meta.insert(META_NEXT_COMMIT_VERSION, 1).map_err(backend)?;
            }
        }
    }
    write.commit().map_err(backend)
}

#[async_trait]
impl StateStore for RedbStateStore {
    fn capabilities(&self) -> StateStoreCapabilities {
        StateStoreCapabilities {
            atomic_batches: true,
            durable_commits: true,
        }
    }

    async fn schema_version(&self) -> Result<u32, StoreError> {
        let database = self.database.clone();
        run_blocking(move || {
            let read = database.begin_read().map_err(backend)?;
            let meta = read.open_table(META).map_err(backend)?;
            let version = meta
                .get(META_SCHEMA_VERSION)
                .map_err(backend)?
                .ok_or_else(|| StoreError::Backend("missing schema version".into()))?
                .value();
            u32::try_from(version)
                .map_err(|_| StoreError::Backend("schema version exceeds u32".into()))
        })
        .await
    }

    async fn read(
        &self,
        scope: StoreScope,
        key: &StoreKey,
    ) -> Result<Option<VersionedBytes>, StoreError> {
        let database = self.database.clone();
        let composite = composite_key(scope, key);
        run_blocking(move || {
            let read = database.begin_read().map_err(backend)?;
            let table = read.open_table(RECORDS).map_err(backend)?;
            table
                .get(composite.as_slice())
                .map_err(backend)?
                .map(|value| decode_value(value.value()))
                .transpose()
        })
        .await
    }

    async fn scan_prefix(
        &self,
        scope: StoreScope,
        prefix: &[u8],
    ) -> Result<BoxStream<'static, Result<StoredEntry, StoreError>>, StoreError> {
        let database = self.database.clone();
        let scope_prefix = scope_prefix(scope);
        let prefix = prefix.to_vec();
        let entries = run_blocking(move || {
            let read = database.begin_read().map_err(backend)?;
            let table = read.open_table(RECORDS).map_err(backend)?;
            let mut entries = Vec::new();
            for entry in table.iter().map_err(backend)? {
                let (key, value) = entry.map_err(backend)?;
                let key = key.value();
                if key.starts_with(&scope_prefix) && key[SCOPE_PREFIX_LEN..].starts_with(&prefix) {
                    entries.push(Ok(StoredEntry {
                        key: StoreKey::new(key[SCOPE_PREFIX_LEN..].to_vec())?,
                        value: decode_value(value.value())?,
                    }));
                }
            }
            Ok(entries)
        })
        .await?;
        Ok(stream::iter(entries).boxed())
    }

    async fn commit(&self, batch: AtomicBatch) -> Result<CommitVersion, StoreError> {
        let database = self.database.clone();
        run_blocking(move || commit_sync(&database, batch)).await
    }
}

fn commit_sync(database: &Database, batch: AtomicBatch) -> Result<CommitVersion, StoreError> {
    let write = database.begin_write().map_err(backend)?;
    let commit_version;
    {
        let mut records = write.open_table(RECORDS).map_err(backend)?;
        let mut meta = write.open_table(META).map_err(backend)?;

        for operation in &batch.operations {
            let (key, expected) = match operation {
                BatchOperation::Put { key, expected, .. }
                | BatchOperation::Delete { key, expected } => (key, *expected),
            };
            let composite = composite_key(batch.scope, key);
            let actual = records
                .get(composite.as_slice())
                .map_err(backend)?
                .map(|value| decode_value(value.value()).map(|value| value.version))
                .transpose()?;
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

        let mut next_record = metadata_value(&meta, META_NEXT_RECORD_VERSION)?;
        commit_version = metadata_value(&meta, META_NEXT_COMMIT_VERSION)?;
        for operation in batch.operations {
            match operation {
                BatchOperation::Put { key, value, .. } => {
                    let composite = composite_key(batch.scope, &key);
                    let encoded = encode_value(next_record, &value);
                    records
                        .insert(composite.as_slice(), encoded.as_slice())
                        .map_err(backend)?;
                    next_record = next_record
                        .checked_add(1)
                        .ok_or_else(|| StoreError::Backend("record version overflow".into()))?;
                }
                BatchOperation::Delete { key, .. } => {
                    let composite = composite_key(batch.scope, &key);
                    records.remove(composite.as_slice()).map_err(backend)?;
                }
            }
        }
        meta.insert(META_NEXT_RECORD_VERSION, next_record)
            .map_err(backend)?;
        meta.insert(
            META_NEXT_COMMIT_VERSION,
            commit_version
                .checked_add(1)
                .ok_or_else(|| StoreError::Backend("commit version overflow".into()))?,
        )
        .map_err(backend)?;
    }
    // redb defaults to Durability::Immediate: successful return is a durable commit.
    write.commit().map_err(backend)?;
    Ok(CommitVersion(commit_version))
}

fn metadata_value(
    meta: &impl ReadableTable<&'static str, u64>,
    key: &'static str,
) -> Result<u64, StoreError> {
    meta.get(key)
        .map_err(backend)?
        .map(|value| value.value())
        .ok_or_else(|| StoreError::Backend(format!("missing metadata key {key}")))
}

fn scope_prefix(scope: StoreScope) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SCOPE_PREFIX_LEN);
    bytes.push(match scope.kind {
        ScopeKind::Member => 0,
        ScopeKind::Authority => 1,
    });
    bytes.extend_from_slice(scope.network_id.as_bytes());
    bytes
}

fn composite_key(scope: StoreScope, key: &StoreKey) -> Vec<u8> {
    let mut bytes = scope_prefix(scope);
    bytes.extend_from_slice(key.as_bytes());
    bytes
}

fn encode_value(version: u64, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + value.len());
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn decode_value(value: &[u8]) -> Result<VersionedBytes, StoreError> {
    if value.len() < 8 {
        return Err(StoreError::Backend("truncated redb record".into()));
    }
    let version = u64::from_be_bytes(value[..8].try_into().expect("checked length"));
    Ok(VersionedBytes {
        version,
        bytes: Bytes::copy_from_slice(&value[8..]),
    })
}

async fn run_blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| StoreError::Backend(format!("redb worker failed: {error}")))?
}

fn backend(error: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use weaver_core::NetworkId;

    use super::*;

    fn key(value: &'static str) -> StoreKey {
        StoreKey::new(value).unwrap()
    }

    #[tokio::test]
    async fn committed_state_survives_database_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.redb");
        let scope = StoreScope::member(NetworkId::from_bytes([0x61; 32]));
        let first_version;
        {
            let store = RedbStateStore::open(&path).unwrap();
            assert!(store.capabilities().durable_commits);
            let mut batch = AtomicBatch::new(scope);
            batch
                .put(
                    key("identity"),
                    Bytes::from_static(b"persistent"),
                    ExpectedVersion::Missing,
                )
                .unwrap();
            store.commit(batch).await.unwrap();
            first_version = store
                .read(scope, &key("identity"))
                .await
                .unwrap()
                .unwrap()
                .version;
        }

        let reopened = RedbStateStore::open(&path).unwrap();
        let value = reopened
            .read(scope, &key("identity"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(value.version, first_version);
        assert_eq!(value.bytes, b"persistent"[..]);
    }

    #[tokio::test]
    async fn redb_conflict_is_atomic_across_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("atomic.redb");
        let scope = StoreScope::authority(NetworkId::from_bytes([0x62; 32]));
        {
            let store = RedbStateStore::open(&path).unwrap();
            let mut initial = AtomicBatch::new(scope);
            initial
                .put(
                    key("head"),
                    Bytes::from_static(b"1"),
                    ExpectedVersion::Missing,
                )
                .unwrap();
            store.commit(initial).await.unwrap();

            let mut rejected = AtomicBatch::new(scope);
            rejected
                .put(
                    key("head"),
                    Bytes::from_static(b"2"),
                    ExpectedVersion::Exact(999),
                )
                .unwrap()
                .put(
                    key("ticket/consumed"),
                    Bytes::from_static(b"yes"),
                    ExpectedVersion::Missing,
                )
                .unwrap();
            assert!(matches!(
                store.commit(rejected).await,
                Err(StoreError::VersionConflict { .. })
            ));
        }

        let reopened = RedbStateStore::open(path).unwrap();
        assert_eq!(
            reopened
                .read(scope, &key("head"))
                .await
                .unwrap()
                .unwrap()
                .bytes,
            b"1"[..]
        );
        assert!(
            reopened
                .read(scope, &key("ticket/consumed"))
                .await
                .unwrap()
                .is_none()
        );
    }
}
