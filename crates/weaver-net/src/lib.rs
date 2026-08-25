//! Iroh-backed virtual reliable byte streams and tonic adapters.
//!
//! This crate implements the first A/B/C vertical slice: A and C use the same relay B as a
//! fallback while protected discovery can add direct IP paths. Callers can construct nodes
//! from validated signed configuration and run authenticated background config sync, while
//! the tonic demo retains an explicit allowlist and local [`PeerDescriptor`] as development
//! bootstrap scaffolding.
//!
//! [`VirtualTcpStream`] is one QUIC bidirectional stream. QUIC provides reliable,
//! strictly ordered, non-duplicated delivery, congestion control, flow control and
//! transparent path changes for the lifetime of its connection. It does not promise to
//! survive loss of the whole QUIC connection or a process restart; that would require a
//! resumable application protocol and is intentionally not presented as TCP semantics.

mod config_state;
mod identity;
mod membership;
mod network_handle;

pub use config_state::{
    CONFIG_ENVELOPE_KEY, CONFIG_HEAD_KEY, CONFIG_HISTORY_KEY_PREFIX, CONFIG_SIGNER_CERTIFICATE_KEY,
    ConfigStateError, PersistedConfigState, decode_head as decode_config_head,
    encode_head as encode_config_head,
};
pub use identity::{IdentityError, PersistentClientIdentity, load_or_create_client_identity};
pub use membership::{
    KEY_ENDPOINT_BINDING, KEY_MEMBER_CERTIFICATE, KEY_PREPARED_JOIN, MembershipError,
    MembershipStores, NetworkMembership,
};
pub use network_handle::{
    NetworkHandle, NetworkHandleError, NetworkHandleOpenOptions, VirtualNetwork, member_secret_id,
};

use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_util::Stream;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use iroh_relay::{RelayConfig, RelayMap};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Mutex as AsyncMutex, Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
};
use tonic::transport::server::Connected;
use tracing::{debug, info, warn};
use weaver_config::{ConfigHead, ConfigUpdateBatch};
use weaver_core::{AppAddr, ClientAddr, DeviceId, NetworkId, ScopedVirtualAddr, ServerAddr};
use weaver_crypto::{AppBinding, AppRole, CertificateError, EndpointBinding, SigningKeypair};
use weaver_discovery::{
    DiscoveryCandidate, EncryptedPresenceRecord, MAX_PRESENCE_TTL_MS, PresenceDirectory,
    WeaverAddressLookup,
};
use weaver_store::StateStore;

const RELIABLE_STREAM_ALPN_PREFIX: &[u8] = b"weaver/tcp/1/";
const RELIABLE_STREAM_PREFACE: &[u8; 20] = b"weaver-tcp-stream-v1";
const DATAGRAM_ALPN_PREFIX: &[u8] = b"weaver/udp/1/";
const DATAGRAM_PREFACE: &[u8; 20] = b"weaver-udp-assoc-v1!";
const PREFACE_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_STREAM_HANDLERS_PER_CONNECTION: usize = 128;
const OPEN_RESPONSE_ACCEPTED: u8 = 0;
const OPEN_RESPONSE_NOT_AUTHORIZED: u8 = 1;
const OPEN_RESPONSE_NETWORK_MISMATCH: u8 = 2;
const OPEN_RESPONSE_ADDRESS_MISMATCH: u8 = 3;
const OPEN_RESPONSE_PROTOCOL_ERROR: u8 = 4;
const OPEN_REQUEST_LEN: usize = RELIABLE_STREAM_PREFACE.len() + 32 * 4;
const CONFIG_SYNC_ALPN_PREFIX: &[u8] = b"weaver/config-sync/1/";
const CONFIG_SYNC_REQUEST_MAGIC: &[u8; 16] = b"WVR-SYNC-REQ-v1\0";
const CONFIG_SYNC_REQUEST_LEN: usize = 16 + 32 + 8 + 8 + 32;
const CONFIG_SYNC_RESPONSE_OK: u8 = 0;
const CONFIG_SYNC_RESPONSE_REJECTED: u8 = 1;
const MAX_CONFIG_SYNC_RESPONSE: usize = 16 * 1024 * 1024;
const PRESENCE_ALPN_PREFIX: &[u8] = b"weaver/presence/1/";
const PRESENCE_REQUEST_MAGIC: &[u8; 16] = b"WVR-PRS-REQ-v1!!";
const PRESENCE_REQUEST_HEADER_LEN: usize = 16 + 32 + 1 + 8 + 24 + 8 + 4;
const PRESENCE_RESPONSE_HEADER_LEN: usize = 1 + 8 + 4;
const PRESENCE_OP_PUBLISH: u8 = 1;
const PRESENCE_OP_QUERY: u8 = 2;
const PRESENCE_RESPONSE_OK: u8 = 0;
const PRESENCE_RESPONSE_NOT_FOUND: u8 = 1;
const PRESENCE_RESPONSE_REJECTED: u8 = 2;
const MAX_PRESENCE_RECORD_BYTES: usize = 16 * 1024;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[async_trait::async_trait]
pub trait ConfigUpdateSource: Send + Sync + 'static {
    async fn updates_after(
        &self,
        authenticated_peer: EndpointId,
        base_head: ConfigHead,
    ) -> Result<ConfigUpdateBatch, BoxError>;
}

#[async_trait::async_trait]
pub trait OpaquePresenceStore: Send + Sync + 'static {
    async fn publish(
        &self,
        authenticated_peer: EndpointId,
        epoch: u64,
        opaque_key: [u8; 24],
        expires_at_ms: u64,
        record: Bytes,
    ) -> Result<(), BoxError>;

    async fn query(
        &self,
        authenticated_peer: EndpointId,
        epoch: u64,
        opaque_key: [u8; 24],
        now_ms: u64,
    ) -> Result<Option<(u64, Bytes)>, BoxError>;
}

#[derive(Debug)]
struct StoredPresence {
    owner: EndpointId,
    expires_at_ms: u64,
    record: Bytes,
}

/// Bounded in-memory storage for short-lived opaque presence records. The relay can index
/// and expire these bytes but cannot decrypt the signed virtual address or route candidates.
#[derive(Debug)]
pub struct MemoryOpaquePresenceStore {
    capacity: usize,
    records: std::sync::Mutex<HashMap<(u64, [u8; 24]), StoredPresence>>,
}

impl MemoryOpaquePresenceStore {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "presence capacity must be non-zero");
        Self {
            capacity,
            records: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl OpaquePresenceStore for MemoryOpaquePresenceStore {
    async fn publish(
        &self,
        authenticated_peer: EndpointId,
        epoch: u64,
        opaque_key: [u8; 24],
        expires_at_ms: u64,
        record: Bytes,
    ) -> Result<(), BoxError> {
        let now_ms = config_wall_now_ms();
        if record.is_empty()
            || record.len() > MAX_PRESENCE_RECORD_BYTES
            || expires_at_ms <= now_ms
            || expires_at_ms.saturating_sub(now_ms) > MAX_PRESENCE_TTL_MS
        {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid opaque presence record",
            )));
        }
        let mut records = self.records.lock().expect("presence store mutex poisoned");
        records.retain(|_, value| value.expires_at_ms > now_ms);
        let key = (epoch, opaque_key);
        if let Some(current) = records.get(&key)
            && current.owner != authenticated_peer
        {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "opaque presence key is owned by another endpoint",
            )));
        }
        if !records.contains_key(&key) && records.len() >= self.capacity {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "opaque presence store is full",
            )));
        }
        records.insert(
            key,
            StoredPresence {
                owner: authenticated_peer,
                expires_at_ms,
                record,
            },
        );
        Ok(())
    }

    async fn query(
        &self,
        _authenticated_peer: EndpointId,
        epoch: u64,
        opaque_key: [u8; 24],
        now_ms: u64,
    ) -> Result<Option<(u64, Bytes)>, BoxError> {
        let mut records = self.records.lock().expect("presence store mutex poisoned");
        records.retain(|_, value| value.expires_at_ms > now_ms);
        Ok(records
            .get(&(epoch, opaque_key))
            .map(|value| (value.expires_at_ms, value.record.clone())))
    }
}

/// Mutable configuration checkpoint consumed by the background sync runtime.
///
/// The default implementation below delegates to [`PersistedConfigState`], whose storage is
/// still supplied by the embedding application through [`StateStore`].
#[async_trait::async_trait]
pub trait ConfigSyncState: Send + 'static {
    fn head(&self) -> ConfigHead;

    /// Supplies the latest signed member set for anti-entropy fanout. Implementations
    /// without a validated topology may leave the original seed list unchanged.
    fn config_peers(&self, _local_endpoint: EndpointId) -> Option<Vec<ConfigPeerDescriptor>> {
        None
    }

    async fn apply_updates(
        &mut self,
        updates: &ConfigUpdateBatch,
        now_ms: u64,
    ) -> Result<ConfigHead, BoxError>;
}

#[async_trait::async_trait]
impl<S: StateStore> ConfigSyncState for PersistedConfigState<S> {
    fn head(&self) -> ConfigHead {
        self.head()
    }

    async fn apply_updates(
        &mut self,
        updates: &ConfigUpdateBatch,
        now_ms: u64,
    ) -> Result<ConfigHead, BoxError> {
        self.apply(updates, now_ms)
            .await
            .map_err(|error| Box::new(error) as BoxError)
    }
}

pub struct LiveConfigState<S> {
    persisted: PersistedConfigState<S>,
    authorizer: Arc<LiveConfigAuthorizer>,
    config_changes: watch::Sender<Arc<weaver_config::ValidatedNetworkConfig>>,
}

impl<S: StateStore> LiveConfigState<S> {
    pub fn new(persisted: PersistedConfigState<S>, authorizer: Arc<LiveConfigAuthorizer>) -> Self {
        let (config_changes, _) = watch::channel(authorizer.config());
        Self {
            persisted,
            authorizer,
            config_changes,
        }
    }

    pub fn persisted(&self) -> &PersistedConfigState<S> {
        &self.persisted
    }

    pub fn head(&self) -> ConfigHead {
        self.persisted.head()
    }

    pub fn config(&self) -> &weaver_config::ValidatedNetworkConfig {
        self.persisted.config()
    }

    pub fn subscribe_config(&self) -> watch::Receiver<Arc<weaver_config::ValidatedNetworkConfig>> {
        self.config_changes.subscribe()
    }
}

#[async_trait::async_trait]
impl<S: StateStore> ConfigSyncState for LiveConfigState<S> {
    fn head(&self) -> ConfigHead {
        self.persisted.head()
    }

    fn config_peers(&self, local_endpoint: EndpointId) -> Option<Vec<ConfigPeerDescriptor>> {
        Some(config_peer_descriptors(
            self.persisted.config(),
            local_endpoint,
        ))
    }

    async fn apply_updates(
        &mut self,
        updates: &ConfigUpdateBatch,
        now_ms: u64,
    ) -> Result<ConfigHead, BoxError> {
        let head = self.persisted.apply(updates, now_ms).await?;
        let config = Arc::new(self.persisted.config().clone());
        self.authorizer
            .update(config.clone())
            .map_err(|error| Box::new(error) as BoxError)?;
        self.config_changes.send_replace(config);
        Ok(head)
    }
}

pub struct MemberConfigSource<S> {
    state: Arc<AsyncMutex<LiveConfigState<S>>>,
}

impl<S> MemberConfigSource<S> {
    pub fn new(state: Arc<AsyncMutex<LiveConfigState<S>>>) -> Self {
        Self { state }
    }
}

impl<S> std::fmt::Debug for MemberConfigSource<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberConfigSource").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl<S: StateStore> ConfigUpdateSource for MemberConfigSource<S> {
    async fn updates_after(
        &self,
        _authenticated_peer: EndpointId,
        base_head: ConfigHead,
    ) -> Result<ConfigUpdateBatch, BoxError> {
        self.state
            .lock()
            .await
            .persisted()
            .updates_after(base_head)
            .await
            .map_err(|error| Box::new(error) as BoxError)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ConfigSyncOptions {
    pub interval: Duration,
    pub retry_min: Duration,
    pub retry_max: Duration,
}

impl Default for ConfigSyncOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigSyncEvent {
    Applied {
        previous: ConfigHead,
        current: ConfigHead,
        envelopes: usize,
    },
    UpToDate {
        head: ConfigHead,
    },
    Failed {
        head: ConfigHead,
        error: String,
        retry_in: Duration,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigSyncRuntimeError {
    #[error("configuration sync runtime has stopped")]
    Stopped,
}

/// Handle for a continuously running configuration sync loop.
pub struct ConfigSyncRuntime {
    trigger: mpsc::Sender<()>,
    events: mpsc::Receiver<ConfigSyncEvent>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ConfigSyncRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigSyncRuntime").finish_non_exhaustive()
    }
}

impl ConfigSyncRuntime {
    /// Requests an immediate sync, coalescing bursts such as multiple interface callbacks.
    pub fn trigger(&self) -> Result<(), ConfigSyncRuntimeError> {
        match self.trigger.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => Err(ConfigSyncRuntimeError::Stopped),
        }
    }

    pub async fn next_event(&mut self) -> Option<ConfigSyncEvent> {
        self.events.recv().await
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(Duration::from_secs(1), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for ConfigSyncRuntime {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PresenceSyncOptions {
    pub publish_interval: Duration,
    pub query_interval: Duration,
    pub record_ttl: Duration,
}

impl Default for PresenceSyncOptions {
    fn default() -> Self {
        Self {
            publish_interval: Duration::from_secs(60),
            query_interval: Duration::from_secs(15),
            record_ttl: Duration::from_millis(DEFAULT_PRESENCE_RUNTIME_TTL_MS),
        }
    }
}

const DEFAULT_PRESENCE_RUNTIME_TTL_MS: u64 = 120_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresenceSyncEvent {
    Published {
        candidate_count: usize,
    },
    Refreshed {
        queried: usize,
        applied: usize,
    },
    Failed {
        operation: &'static str,
        error: String,
    },
}

pub struct PresenceSyncRuntime {
    trigger: mpsc::Sender<()>,
    events: mpsc::Receiver<PresenceSyncEvent>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for PresenceSyncRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresenceSyncRuntime")
            .finish_non_exhaustive()
    }
}

impl PresenceSyncRuntime {
    pub fn trigger(&self) -> Result<(), ConfigSyncRuntimeError> {
        match self.trigger.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => Err(ConfigSyncRuntimeError::Stopped),
        }
    }

    pub async fn next_event(&mut self) -> Option<PresenceSyncEvent> {
        self.events.recv().await
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(Duration::from_secs(1), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for PresenceSyncRuntime {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Continuously publishes the local encrypted route record and pulls opaque records for
/// every endpoint authorized by the current signed configuration.
#[allow(clippy::too_many_arguments)]
pub fn spawn_presence_sync(
    dialer: WeaverDialer,
    target: ConfigPeerDescriptor,
    config: Arc<weaver_config::ValidatedNetworkConfig>,
    signing: Arc<SigningKeypair>,
    directory: Arc<PresenceDirectory>,
    lookup: Arc<WeaverAddressLookup>,
    options: PresenceSyncOptions,
) -> PresenceSyncRuntime {
    spawn_presence_sync_inner(
        dialer,
        target,
        PresenceConfigView::Static(config),
        signing,
        directory,
        lookup,
        options,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_live_presence_sync(
    dialer: WeaverDialer,
    target: ConfigPeerDescriptor,
    config: Arc<LiveConfigAuthorizer>,
    signing: Arc<SigningKeypair>,
    directory: Arc<PresenceDirectory>,
    lookup: Arc<WeaverAddressLookup>,
    options: PresenceSyncOptions,
) -> PresenceSyncRuntime {
    spawn_presence_sync_inner(
        dialer,
        target,
        PresenceConfigView::Live(config),
        signing,
        directory,
        lookup,
        options,
    )
}

#[derive(Clone)]
enum PresenceConfigView {
    Static(Arc<weaver_config::ValidatedNetworkConfig>),
    Live(Arc<LiveConfigAuthorizer>),
}

impl PresenceConfigView {
    fn current(&self) -> Arc<weaver_config::ValidatedNetworkConfig> {
        match self {
            Self::Static(config) => config.clone(),
            Self::Live(config) => config.config(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_presence_sync_inner(
    dialer: WeaverDialer,
    target: ConfigPeerDescriptor,
    config_view: PresenceConfigView,
    signing: Arc<SigningKeypair>,
    directory: Arc<PresenceDirectory>,
    lookup: Arc<WeaverAddressLookup>,
    options: PresenceSyncOptions,
) -> PresenceSyncRuntime {
    let config = config_view.current();
    assert!(!options.publish_interval.is_zero());
    assert!(!options.query_interval.is_zero());
    assert!(!options.record_ttl.is_zero());
    assert!(options.record_ttl.as_millis() <= u128::from(MAX_PRESENCE_TTL_MS));
    assert_eq!(config.as_config().network_id, dialer.network_id);
    assert_eq!(directory.network_id(), dialer.network_id);
    assert_eq!(lookup.network_id(), dialer.network_id);
    assert_eq!(target.network_id, dialer.network_id);

    let mut publications = lookup.subscribe_publications();
    let (trigger_tx, mut trigger_rx) = mpsc::channel(1);
    let (event_tx, event_rx) = mpsc::channel(32);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut publish_tick = tokio::time::interval(options.publish_interval);
        publish_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut query_tick = tokio::time::interval(options.query_interval);
        query_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut sequence = config_wall_now_ms();
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = publish_tick.tick() => {
                    let config = config_view.current();
                    let current_target = current_presence_target(&target, &config);
                    publish_current_presence(
                        &dialer, &current_target, &config, &signing, &publications,
                        options.record_ttl, &mut sequence, &event_tx,
                    ).await;
                }
                changed = publications.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let config = config_view.current();
                    let current_target = current_presence_target(&target, &config);
                    publish_current_presence(
                        &dialer, &current_target, &config, &signing, &publications,
                        options.record_ttl, &mut sequence, &event_tx,
                    ).await;
                }
                _ = query_tick.tick() => {
                    let config = config_view.current();
                    let current_target = current_presence_target(&target, &config);
                    refresh_remote_presence(
                        &dialer, &current_target, &config, &directory, &event_tx,
                    ).await;
                }
                trigger = trigger_rx.recv() => {
                    if trigger.is_none() {
                        break;
                    }
                    let config = config_view.current();
                    let current_target = current_presence_target(&target, &config);
                    publish_current_presence(
                        &dialer, &current_target, &config, &signing, &publications,
                        options.record_ttl, &mut sequence, &event_tx,
                    ).await;
                    refresh_remote_presence(
                        &dialer, &current_target, &config, &directory, &event_tx,
                    ).await;
                }
            }
        }
    });
    PresenceSyncRuntime {
        trigger: trigger_tx,
        events: event_rx,
        shutdown: Some(shutdown_tx),
        task: Some(task),
    }
}

fn current_presence_target(
    fallback: &ConfigPeerDescriptor,
    config: &weaver_config::ValidatedNetworkConfig,
) -> ConfigPeerDescriptor {
    ConfigPeerDescriptor::first_presence_service(config).unwrap_or_else(|_| fallback.clone())
}

#[allow(clippy::too_many_arguments)]
async fn publish_current_presence(
    dialer: &WeaverDialer,
    target: &ConfigPeerDescriptor,
    config: &weaver_config::ValidatedNetworkConfig,
    signing: &SigningKeypair,
    publications: &watch::Receiver<Option<iroh::address_lookup::EndpointData>>,
    ttl: Duration,
    sequence: &mut u64,
    events: &mpsc::Sender<PresenceSyncEvent>,
) {
    let Some(data) = publications.borrow().clone() else {
        return;
    };
    let candidates = data
        .addrs()
        .take(16)
        .filter_map(|address| match address {
            TransportAddr::Ip(address) => Some(DiscoveryCandidate::Ip(*address)),
            TransportAddr::Relay(url) => Some(DiscoveryCandidate::Relay(url.to_string())),
            _ => None,
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return;
    }
    let now_ms = config_wall_now_ms();
    let ttl_ms = ttl.as_millis().min(u128::from(u64::MAX)) as u64;
    let expires_at_ms = now_ms
        .saturating_add(ttl_ms)
        .min(config.as_config().expires_at_ms);
    *sequence = (*sequence).max(now_ms).saturating_add(1);
    let result = EncryptedPresenceRecord::seal(
        config,
        signing,
        dialer.endpoint.id(),
        dialer.local_bindings.iter().collect(),
        candidates.clone(),
        0,
        *sequence,
        now_ms,
        expires_at_ms,
    )
    .map_err(|error| NetworkError::Presence(Box::new(error)));
    let result = match result {
        Ok(record) => {
            dialer
                .publish_presence(target, &record, expires_at_ms)
                .await
        }
        Err(error) => Err(error),
    };
    let event = match result {
        Ok(()) => PresenceSyncEvent::Published {
            candidate_count: candidates.len(),
        },
        Err(error) => PresenceSyncEvent::Failed {
            operation: "publish",
            error: error.to_string(),
        },
    };
    let _ = events.try_send(event);
}

async fn refresh_remote_presence(
    dialer: &WeaverDialer,
    target: &ConfigPeerDescriptor,
    config: &weaver_config::ValidatedNetworkConfig,
    directory: &PresenceDirectory,
    events: &mpsc::Sender<PresenceSyncEvent>,
) {
    let mut endpoint_ids = Vec::new();
    for raw in &config.as_config().endpoint_bindings {
        let binding = match EndpointBinding::from_bytes(raw) {
            Ok(binding) => binding,
            Err(error) => {
                let _ = events.try_send(PresenceSyncEvent::Failed {
                    operation: "query",
                    error: error.to_string(),
                });
                return;
            }
        };
        match EndpointId::from_bytes(&binding.payload().endpoint_id) {
            Ok(endpoint_id) if endpoint_id != dialer.endpoint.id() => {
                endpoint_ids.push(endpoint_id)
            }
            Ok(_) => {}
            Err(error) => {
                let _ = events.try_send(PresenceSyncEvent::Failed {
                    operation: "query",
                    error: error.to_string(),
                });
                return;
            }
        }
    }
    endpoint_ids.sort_unstable_by_key(|endpoint| *endpoint.as_bytes());
    endpoint_ids.dedup();
    let mut applied = 0;
    for endpoint_id in &endpoint_ids {
        let (epoch, opaque_key) = EncryptedPresenceRecord::lookup_key(config, *endpoint_id);
        match dialer.query_presence(target, epoch, opaque_key).await {
            Ok(Some(record)) => {
                match directory.apply_encrypted(config, &record, config_wall_now_ms()) {
                    Ok(changed) => applied += usize::from(changed),
                    Err(error) => {
                        let _ = events.try_send(PresenceSyncEvent::Failed {
                            operation: "apply",
                            error: error.to_string(),
                        });
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                let _ = events.try_send(PresenceSyncEvent::Failed {
                    operation: "query",
                    error: error.to_string(),
                });
            }
        }
    }
    directory.purge_expired(config_wall_now_ms());
    let _ = events.try_send(PresenceSyncEvent::Refreshed {
        queried: endpoint_ids.len(),
        applied,
    });
}

pub fn spawn_config_sync<T: ConfigSyncState>(
    dialer: WeaverDialer,
    target: ConfigPeerDescriptor,
    state: Arc<AsyncMutex<T>>,
    options: ConfigSyncOptions,
) -> ConfigSyncRuntime {
    spawn_config_anti_entropy(dialer, vec![target], state, options)
}

/// Pulls the signed revision chain from any configured member, rotating the starting peer
/// after every successful round and failing over within the same round when one is offline
/// or serves an invalid batch.
pub fn spawn_config_anti_entropy<T: ConfigSyncState>(
    dialer: WeaverDialer,
    mut targets: Vec<ConfigPeerDescriptor>,
    state: Arc<AsyncMutex<T>>,
    options: ConfigSyncOptions,
) -> ConfigSyncRuntime {
    assert!(!targets.is_empty(), "at least one config peer is required");
    assert!(
        targets
            .iter()
            .all(|target| target.network_id == dialer.network_id),
        "all config peers must belong to the endpoint virtual network"
    );
    assert!(
        !options.interval.is_zero(),
        "sync interval must be non-zero"
    );
    assert!(
        !options.retry_min.is_zero(),
        "retry minimum must be non-zero"
    );
    assert!(
        options.retry_max >= options.retry_min,
        "retry maximum must be at least retry minimum"
    );
    let (trigger_tx, mut trigger_rx) = mpsc::channel(1);
    let (event_tx, event_rx) = mpsc::channel(32);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut delay = Duration::ZERO;
        let mut retry = options.retry_min;
        let mut start_index = 0_usize;
        loop {
            let timer = tokio::time::sleep(delay);
            tokio::pin!(timer);
            tokio::select! {
                _ = &mut shutdown_rx => break,
                trigger = trigger_rx.recv() => {
                    if trigger.is_none() {
                        break;
                    }
                }
                _ = &mut timer => {}
            }

            let previous = {
                let state = state.lock().await;
                if let Some(current_targets) = state.config_peers(dialer.endpoint.id())
                    && !current_targets.is_empty()
                {
                    targets = current_targets;
                    start_index %= targets.len();
                }
                state.head()
            };
            let mut applied = None;
            let mut last_error = None;
            for offset in 0..targets.len() {
                let index = (start_index + offset) % targets.len();
                match dialer.fetch_config_updates(&targets[index], previous).await {
                    Ok(updates) => {
                        let envelopes = updates.envelopes.len();
                        match state
                            .lock()
                            .await
                            .apply_updates(&updates, config_wall_now_ms())
                            .await
                        {
                            Ok(current) => {
                                applied = Some((current, envelopes));
                                start_index = (index + 1) % targets.len();
                                break;
                            }
                            Err(error) => last_error = Some(error.to_string()),
                        }
                    }
                    Err(error) => last_error = Some(error.to_string()),
                }
            }
            if let Some((current, envelopes)) = applied {
                let event = if current == previous {
                    ConfigSyncEvent::UpToDate { head: current }
                } else {
                    ConfigSyncEvent::Applied {
                        previous,
                        current,
                        envelopes,
                    }
                };
                let _ = event_tx.try_send(event);
                retry = options.retry_min;
                delay = options.interval;
            } else {
                let _ = event_tx.try_send(ConfigSyncEvent::Failed {
                    head: previous,
                    error: last_error.unwrap_or_else(|| "all config peers failed".to_owned()),
                    retry_in: retry,
                });
                delay = retry;
                retry = retry.saturating_mul(2).min(options.retry_max);
            }
        }
    });
    ConfigSyncRuntime {
        trigger: trigger_tx,
        events: event_rx,
        shutdown: Some(shutdown_tx),
        task: Some(task),
    }
}

pub fn config_peer_descriptors(
    config: &weaver_config::ValidatedNetworkConfig,
    local_endpoint: EndpointId,
) -> Vec<ConfigPeerDescriptor> {
    let relay_url = config
        .as_config()
        .relays
        .iter()
        .find(|relay| relay.roles.contains(weaver_config::RelayRoles::DATA_RELAY))
        .and_then(|relay| relay.url.parse().ok());
    let mut peers = config
        .as_config()
        .endpoint_bindings
        .iter()
        .filter_map(|raw| EndpointBinding::from_bytes(raw).ok())
        .filter_map(|binding| EndpointId::from_bytes(&binding.payload().endpoint_id).ok())
        .filter(|endpoint_id| *endpoint_id != local_endpoint)
        .map(|endpoint_id| ConfigPeerDescriptor {
            network_id: config.as_config().network_id,
            endpoint_id,
            relay_url: relay_url.clone(),
            direct_addresses: Vec::new(),
        })
        .collect::<Vec<_>>();
    peers.sort_unstable_by_key(|peer| *peer.endpoint_id.as_bytes());
    peers.dedup_by_key(|peer| peer.endpoint_id);
    peers
}

fn config_wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub fn config_sync_alpn(network_id: NetworkId) -> Vec<u8> {
    let mut alpn = Vec::with_capacity(CONFIG_SYNC_ALPN_PREFIX.len() + 32);
    alpn.extend_from_slice(CONFIG_SYNC_ALPN_PREFIX);
    alpn.extend_from_slice(network_id.as_bytes());
    alpn
}

pub fn presence_alpn(network_id: NetworkId) -> Vec<u8> {
    let mut alpn = Vec::with_capacity(PRESENCE_ALPN_PREFIX.len() + 32);
    alpn.extend_from_slice(PRESENCE_ALPN_PREFIX);
    alpn.extend_from_slice(network_id.as_bytes());
    alpn
}

#[derive(Clone, Copy, Debug)]
struct OpenStreamRequest {
    network_id: NetworkId,
    source: ScopedVirtualAddr,
    destination: ScopedVirtualAddr,
}

impl OpenStreamRequest {
    fn encode(self) -> Result<[u8; OPEN_REQUEST_LEN], NetworkError> {
        self.encode_with_preface(RELIABLE_STREAM_PREFACE)
    }

    fn encode_datagram(self) -> Result<[u8; OPEN_REQUEST_LEN], NetworkError> {
        self.encode_with_preface(DATAGRAM_PREFACE)
    }

    fn encode_with_preface(
        self,
        preface: &[u8; RELIABLE_STREAM_PREFACE.len()],
    ) -> Result<[u8; OPEN_REQUEST_LEN], NetworkError> {
        let (source_app, source_device) = match self.source {
            ScopedVirtualAddr::Client { app, device } => (app, device),
            ScopedVirtualAddr::Server { .. } => {
                return Err(NetworkError::ProtocolViolation(
                    "only client addresses may initiate TCP connections",
                ));
            }
        };
        let destination_app = match self.destination {
            ScopedVirtualAddr::Server { app } => app,
            ScopedVirtualAddr::Client { .. } => {
                return Err(NetworkError::ProtocolViolation(
                    "TCP destination must be a server address",
                ));
            }
        };

        let mut bytes = [0; OPEN_REQUEST_LEN];
        let mut offset = 0;
        let parts: [&[u8]; 5] = [
            preface.as_slice(),
            self.network_id.as_bytes(),
            source_app.as_bytes(),
            source_device.as_bytes(),
            destination_app.as_bytes(),
        ];
        for part in parts {
            bytes[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8; OPEN_REQUEST_LEN]) -> Result<Self, ()> {
        Self::decode_with_preface(bytes, RELIABLE_STREAM_PREFACE)
    }

    fn decode_datagram(bytes: &[u8; OPEN_REQUEST_LEN]) -> Result<Self, ()> {
        Self::decode_with_preface(bytes, DATAGRAM_PREFACE)
    }

    fn decode_with_preface(
        bytes: &[u8; OPEN_REQUEST_LEN],
        preface: &[u8; RELIABLE_STREAM_PREFACE.len()],
    ) -> Result<Self, ()> {
        if &bytes[..RELIABLE_STREAM_PREFACE.len()] != preface {
            return Err(());
        }
        let mut offset = RELIABLE_STREAM_PREFACE.len();
        let mut take_id = || {
            let value = bytes[offset..offset + 32].try_into().expect("fixed length");
            offset += 32;
            value
        };
        Ok(Self {
            network_id: NetworkId::from_bytes(take_id()),
            source: ScopedVirtualAddr::Client {
                app: AppAddr::from_bytes(take_id()),
                device: DeviceId::from_bytes(take_id()),
            },
            destination: ScopedVirtualAddr::Server {
                app: AppAddr::from_bytes(take_id()),
            },
        })
    }
}

/// Returns the ALPN that binds a reliable-stream protocol to one virtual server address.
pub fn tcp_alpn(app_addr: AppAddr) -> Vec<u8> {
    let mut alpn =
        Vec::with_capacity(RELIABLE_STREAM_ALPN_PREFIX.len() + app_addr.as_bytes().len());
    alpn.extend_from_slice(RELIABLE_STREAM_ALPN_PREFIX);
    alpn.extend_from_slice(app_addr.as_bytes());
    alpn
}

pub fn udp_alpn(app_addr: AppAddr) -> Vec<u8> {
    let mut alpn = Vec::with_capacity(DATAGRAM_ALPN_PREFIX.len() + app_addr.as_bytes().len());
    alpn.extend_from_slice(DATAGRAM_ALPN_PREFIX);
    alpn.extend_from_slice(app_addr.as_bytes());
    alpn
}

/// Compatibility alias for tonic users. Tonic runs over the generic reliable stream.
pub fn tonic_alpn(app_addr: AppAddr) -> Vec<u8> {
    tcp_alpn(app_addr)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LocalBinding {
    Server(ServerAddr),
    Client(ClientAddr),
}

impl LocalBinding {
    pub fn scoped(self) -> ScopedVirtualAddr {
        match self {
            Self::Server(address) => address.scoped(),
            Self::Client(address) => address.scoped(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalBindings {
    addresses: HashSet<ScopedVirtualAddr>,
}

impl LocalBindings {
    pub fn control_plane() -> Self {
        Self {
            addresses: HashSet::new(),
        }
    }
    pub fn new(
        bindings: impl IntoIterator<Item = LocalBinding>,
    ) -> Result<Self, LocalBindingsError> {
        let mut addresses = HashSet::new();
        for binding in bindings {
            if !addresses.insert(binding.scoped()) {
                return Err(LocalBindingsError::Duplicate);
            }
        }
        if addresses.is_empty() {
            return Err(LocalBindingsError::Empty);
        }
        Ok(Self { addresses })
    }

    pub fn contains(&self, address: ScopedVirtualAddr) -> bool {
        self.addresses.contains(&address)
    }
    pub fn contains_client(&self, address: ClientAddr) -> bool {
        self.contains(address.scoped())
    }
    pub fn contains_server(&self, address: ServerAddr) -> bool {
        self.contains(address.scoped())
    }
    pub fn iter(&self) -> impl Iterator<Item = ScopedVirtualAddr> + '_ {
        self.addresses.iter().copied()
    }
    pub fn servers(&self) -> impl Iterator<Item = ServerAddr> + '_ {
        self.iter().filter_map(|address| match address {
            ScopedVirtualAddr::Server { app } => Some(ServerAddr::new(app)),
            ScopedVirtualAddr::Client { .. } => None,
        })
    }
    pub fn clients(&self) -> impl Iterator<Item = ClientAddr> + '_ {
        self.iter().filter_map(|address| match address {
            ScopedVirtualAddr::Client { app, device } => Some(ClientAddr::new(app, device)),
            ScopedVirtualAddr::Server { .. } => None,
        })
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LocalBindingsError {
    #[error("at least one local binding is required")]
    Empty,
    #[error("duplicate local binding")]
    Duplicate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerDescriptor {
    pub network_id: NetworkId,
    pub app_addr: AppAddr,
    pub endpoint_id: EndpointId,
    pub relay_url: Option<RelayUrl>,
    pub direct_addresses: Vec<SocketAddr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigPeerDescriptor {
    pub network_id: NetworkId,
    pub endpoint_id: EndpointId,
    pub relay_url: Option<RelayUrl>,
    pub direct_addresses: Vec<SocketAddr>,
}

impl ConfigPeerDescriptor {
    pub fn endpoint_addr(&self) -> EndpointAddr {
        let transports = self
            .direct_addresses
            .iter()
            .copied()
            .map(TransportAddr::Ip)
            .chain(self.relay_url.clone().map(TransportAddr::Relay));
        EndpointAddr::from_parts(self.endpoint_id, transports)
    }

    pub fn first_presence_service(
        config: &weaver_config::ValidatedNetworkConfig,
    ) -> Result<Self, ConfigAuthorizationError> {
        let snapshot = config.as_config();
        let service = snapshot
            .presence_services
            .first()
            .ok_or(ConfigAuthorizationError::NoPresenceService)?;
        let endpoint_id = EndpointId::from_bytes(&service.endpoint_id)
            .map_err(|_| ConfigAuthorizationError::MalformedEndpoint)?;
        let relay_url = service
            .url
            .parse::<RelayUrl>()
            .map_err(|_| ConfigAuthorizationError::MalformedRelayUrl)?;
        Ok(Self {
            network_id: snapshot.network_id,
            endpoint_id,
            relay_url: Some(relay_url),
            direct_addresses: Vec::new(),
        })
    }
}

impl PeerDescriptor {
    pub fn endpoint_addr(&self) -> EndpointAddr {
        let transports = self
            .direct_addresses
            .iter()
            .copied()
            .map(TransportAddr::Ip)
            .chain(self.relay_url.clone().map(TransportAddr::Relay));
        EndpointAddr::from_parts(self.endpoint_id, transports)
    }

    pub fn relay_only(&self) -> Self {
        Self {
            direct_addresses: Vec::new(),
            ..self.clone()
        }
    }
}

#[derive(Clone)]
pub struct NodeConfig {
    pub secret_key: SecretKey,
    pub relay_url: Option<RelayUrl>,
    pub relay_urls: Vec<RelayUrl>,
    pub accept_alpns: Vec<Vec<u8>>,
    pub network_id: NetworkId,
    pub local_bindings: LocalBindings,
    pub allowed_clients: HashMap<EndpointId, HashSet<ScopedVirtualAddr>>,
    pub enable_direct_paths: bool,
    pub address_lookup: Option<Arc<WeaverAddressLookup>>,
    pub config_update_source: Option<Arc<dyn ConfigUpdateSource>>,
    pub allowed_config_peers: HashSet<EndpointId>,
    pub presence_store: Option<Arc<dyn OpaquePresenceStore>>,
    pub allowed_presence_peers: HashSet<EndpointId>,
    pub authorizer: Option<Arc<dyn NetworkAuthorizer>>,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("relay_url", &self.relay_url)
            .field("relay_urls", &self.relay_urls)
            .field("accept_alpns", &self.accept_alpns)
            .field("network_id", &self.network_id)
            .field("local_bindings", &self.local_bindings)
            .field("allowed_clients", &self.allowed_clients)
            .field("enable_direct_paths", &self.enable_direct_paths)
            .field("address_lookup", &self.address_lookup.is_some())
            .field("config_update_source", &self.config_update_source.is_some())
            .field("allowed_config_peers", &self.allowed_config_peers)
            .field("presence_store", &self.presence_store.is_some())
            .field("allowed_presence_peers", &self.allowed_presence_peers)
            .field("authorizer", &self.authorizer.is_some())
            .finish()
    }
}

impl NodeConfig {
    pub fn new(
        secret_key: SecretKey,
        relay_url: Option<RelayUrl>,
        network_id: NetworkId,
        local_bindings: LocalBindings,
        allowed_clients: impl IntoIterator<Item = (EndpointId, ScopedVirtualAddr)>,
    ) -> Self {
        let relay_urls = relay_url.clone().into_iter().collect();
        let accept_alpns = local_bindings
            .servers()
            .flat_map(|server| [tcp_alpn(server.app()), udp_alpn(server.app())])
            .collect();
        Self {
            secret_key,
            relay_url,
            relay_urls,
            accept_alpns,
            network_id,
            local_bindings,
            allowed_clients: collect_client_authorizations(allowed_clients),
            enable_direct_paths: true,
            address_lookup: None,
            config_update_source: None,
            allowed_config_peers: HashSet::new(),
            presence_store: None,
            allowed_presence_peers: HashSet::new(),
            authorizer: None,
        }
    }

    pub fn from_config(
        secret_key: SecretKey,
        config: &weaver_config::ValidatedNetworkConfig,
        local_bindings: LocalBindings,
    ) -> Result<Self, ConfigAuthorizationError> {
        let derived = ConfigAuthorizations::derive(config, secret_key.public(), &local_bindings)?;
        let mut node = Self::new(
            secret_key,
            derived.relay_urls.first().cloned(),
            config.as_config().network_id,
            local_bindings,
            derived
                .allowed_clients
                .into_iter()
                .flat_map(|(endpoint, addresses)| {
                    addresses
                        .into_iter()
                        .map(move |address| (endpoint, address))
                }),
        );
        node.relay_urls = derived.relay_urls;
        node.allowed_config_peers = derived.member_endpoints;
        Ok(node)
    }

    pub fn with_config_update_source(
        mut self,
        source: Arc<dyn ConfigUpdateSource>,
        allowed_peers: impl IntoIterator<Item = EndpointId>,
    ) -> Self {
        self.config_update_source = Some(source);
        self.allowed_config_peers = allowed_peers.into_iter().collect();
        self
    }

    pub fn with_presence_store(
        mut self,
        store: Arc<dyn OpaquePresenceStore>,
        allowed_peers: impl IntoIterator<Item = EndpointId>,
    ) -> Self {
        self.presence_store = Some(store);
        self.allowed_presence_peers = allowed_peers.into_iter().collect();
        self
    }

    /// Adds the live, network-private address lookup used by mDNS and encrypted presence.
    pub fn with_address_lookup(mut self, lookup: Arc<WeaverAddressLookup>) -> Self {
        assert_eq!(
            lookup.network_id(),
            self.network_id,
            "address lookup must be scoped to the node's virtual network"
        );
        self.address_lookup = Some(lookup);
        self
    }

    pub fn with_authorizer(mut self, authorizer: Arc<dyn NetworkAuthorizer>) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    pub fn with_relay_urls(mut self, relay_urls: impl IntoIterator<Item = RelayUrl>) -> Self {
        self.relay_urls = relay_urls.into_iter().collect();
        self.relay_urls.sort_by_key(|left| left.to_string());
        self.relay_urls.dedup();
        self.relay_url = self.relay_urls.first().cloned();
        self
    }
}

pub trait NetworkAuthorizer: Send + Sync + 'static {
    fn allow_config_sync(&self, endpoint_id: EndpointId) -> bool;
    fn allow_presence(&self, endpoint_id: EndpointId) -> bool;
    fn authorized_client_addrs(
        &self,
        endpoint_id: EndpointId,
        destination: ScopedVirtualAddr,
    ) -> HashSet<ScopedVirtualAddr>;
}

#[derive(Debug)]
struct StaticNetworkAuthorizer {
    clients: HashMap<EndpointId, HashSet<ScopedVirtualAddr>>,
    config_peers: HashSet<EndpointId>,
    presence_peers: HashSet<EndpointId>,
}

impl NetworkAuthorizer for StaticNetworkAuthorizer {
    fn allow_config_sync(&self, endpoint_id: EndpointId) -> bool {
        self.config_peers.contains(&endpoint_id)
    }

    fn allow_presence(&self, endpoint_id: EndpointId) -> bool {
        self.presence_peers.contains(&endpoint_id)
    }

    fn authorized_client_addrs(
        &self,
        endpoint_id: EndpointId,
        _destination: ScopedVirtualAddr,
    ) -> HashSet<ScopedVirtualAddr> {
        self.clients.get(&endpoint_id).cloned().unwrap_or_default()
    }
}

/// Hot-swappable authorization view used by a long-lived endpoint. Applying a signed config
/// update changes admission for subsequent connections/streams without tearing down existing
/// reliable streams or replacing the endpoint identity.
#[derive(Debug)]
pub struct LiveConfigAuthorizer {
    network_id: NetworkId,
    local_endpoint: EndpointId,
    config: std::sync::RwLock<Arc<weaver_config::ValidatedNetworkConfig>>,
}

impl LiveConfigAuthorizer {
    pub fn new(
        config: Arc<weaver_config::ValidatedNetworkConfig>,
        local_endpoint: EndpointId,
    ) -> Result<Self, ConfigAuthorizationError> {
        let network_id = config.as_config().network_id;
        configured_member_for_endpoint(&config, local_endpoint)
            .ok_or(ConfigAuthorizationError::LocalEndpointNotMember)?;
        Ok(Self {
            network_id,
            local_endpoint,
            config: std::sync::RwLock::new(config),
        })
    }

    pub fn update(
        &self,
        config: Arc<weaver_config::ValidatedNetworkConfig>,
    ) -> Result<(), ConfigAuthorizationError> {
        if config.as_config().network_id != self.network_id {
            return Err(ConfigAuthorizationError::WrongNetwork);
        }
        *self.config.write().expect("live config lock poisoned") = config;
        Ok(())
    }

    pub fn config(&self) -> Arc<weaver_config::ValidatedNetworkConfig> {
        self.config
            .read()
            .expect("live config lock poisoned")
            .clone()
    }
}

impl NetworkAuthorizer for LiveConfigAuthorizer {
    fn allow_config_sync(&self, endpoint_id: EndpointId) -> bool {
        configured_member_for_endpoint(&self.config(), endpoint_id).is_some()
    }

    fn allow_presence(&self, endpoint_id: EndpointId) -> bool {
        self.allow_config_sync(endpoint_id)
    }

    fn authorized_client_addrs(
        &self,
        endpoint_id: EndpointId,
        destination: ScopedVirtualAddr,
    ) -> HashSet<ScopedVirtualAddr> {
        let config = self.config();
        let Some(source_member) = configured_member_for_endpoint(&config, endpoint_id) else {
            return HashSet::new();
        };
        let Some(local_member) = configured_member_for_endpoint(&config, self.local_endpoint)
        else {
            return HashSet::new();
        };
        let ScopedVirtualAddr::Server { app } = destination else {
            return HashSet::new();
        };
        let now_ms = config_wall_now_ms();
        let mut server_authorized = false;
        let mut clients = HashSet::new();
        for raw in &config.as_config().app_bindings {
            let Ok(binding) = AppBinding::from_bytes(raw) else {
                return HashSet::new();
            };
            let payload = binding.payload();
            if payload.expires_at_ms <= now_ms {
                continue;
            }
            if payload.role == AppRole::Server
                && payload.app_addr == app
                && payload.subject == local_member
            {
                server_authorized = true;
            }
            if payload.role == AppRole::Client
                && payload.subject == source_member
                && let Some(device) = payload.device_id
            {
                clients.insert(ScopedVirtualAddr::Client {
                    app: payload.app_addr,
                    device,
                });
            }
        }
        if server_authorized {
            clients
        } else {
            HashSet::new()
        }
    }
}

fn configured_member_for_endpoint(
    config: &weaver_config::ValidatedNetworkConfig,
    endpoint_id: EndpointId,
) -> Option<weaver_core::MemberId> {
    let now_ms = config_wall_now_ms();
    if config.as_config().expires_at_ms <= now_ms {
        return None;
    }
    let member_id = config
        .as_config()
        .endpoint_bindings
        .iter()
        .filter_map(|raw| EndpointBinding::from_bytes(raw).ok())
        .find(|binding| {
            binding.payload().endpoint_id == *endpoint_id.as_bytes()
                && binding.payload().expires_at_ms > now_ms
        })?
        .payload()
        .member_id;
    config
        .as_config()
        .members
        .iter()
        .filter_map(|raw| weaver_crypto::MemberCertificate::from_bytes(raw).ok())
        .find(|member| {
            member.payload().member_id == member_id && member.payload().expires_at_ms > now_ms
        })
        .map(|member| member.payload().member_id)
}

fn collect_client_authorizations(
    allowed_clients: impl IntoIterator<Item = (EndpointId, ScopedVirtualAddr)>,
) -> HashMap<EndpointId, HashSet<ScopedVirtualAddr>> {
    let mut collected: HashMap<EndpointId, HashSet<ScopedVirtualAddr>> = HashMap::new();
    for (endpoint, address) in allowed_clients {
        collected.entry(endpoint).or_default().insert(address);
    }
    collected
}

struct ConfigAuthorizations {
    relay_urls: Vec<RelayUrl>,
    allowed_clients: HashMap<EndpointId, HashSet<ScopedVirtualAddr>>,
    member_endpoints: HashSet<EndpointId>,
}

impl ConfigAuthorizations {
    fn derive(
        validated: &weaver_config::ValidatedNetworkConfig,
        local_endpoint: EndpointId,
        local_bindings: &LocalBindings,
    ) -> Result<Self, ConfigAuthorizationError> {
        let config = validated.as_config();
        let mut endpoints_by_member: HashMap<weaver_core::MemberId, Vec<EndpointId>> =
            HashMap::new();
        let mut local_member = None;
        for raw in &config.endpoint_bindings {
            let binding = EndpointBinding::from_bytes(raw)?;
            let endpoint = EndpointId::from_bytes(&binding.payload().endpoint_id)
                .map_err(|_| ConfigAuthorizationError::MalformedEndpoint)?;
            endpoints_by_member
                .entry(binding.payload().member_id)
                .or_default()
                .push(endpoint);
            if endpoint == local_endpoint {
                local_member = Some(binding.payload().member_id);
            }
        }
        let local_member = local_member.ok_or(ConfigAuthorizationError::LocalEndpointNotMember)?;
        let mut allowed_clients: HashMap<EndpointId, HashSet<ScopedVirtualAddr>> = HashMap::new();
        let mut authorized_local = HashSet::new();
        for raw in &config.app_bindings {
            let binding = AppBinding::from_bytes(raw)?;
            let payload = binding.payload();
            match payload.role {
                AppRole::Server => {
                    if payload.subject == local_member {
                        authorized_local.insert(ScopedVirtualAddr::Server {
                            app: payload.app_addr,
                        });
                    }
                }
                AppRole::Client => {
                    let device = payload
                        .device_id
                        .ok_or(ConfigAuthorizationError::ClientNotAuthorized)?;
                    if payload.subject == local_member {
                        authorized_local.insert(ScopedVirtualAddr::Client {
                            app: payload.app_addr,
                            device,
                        });
                    }
                    if let Some(endpoints) = endpoints_by_member.get(&payload.subject) {
                        let address = ScopedVirtualAddr::Client {
                            app: payload.app_addr,
                            device,
                        };
                        for endpoint in endpoints {
                            allowed_clients
                                .entry(*endpoint)
                                .or_default()
                                .insert(address);
                        }
                    }
                }
            }
        }
        for address in local_bindings.iter() {
            if !authorized_local.contains(&address) {
                return Err(match address {
                    ScopedVirtualAddr::Server { .. } => {
                        ConfigAuthorizationError::ServerNotAuthorized
                    }
                    ScopedVirtualAddr::Client { .. } => {
                        ConfigAuthorizationError::ClientNotAuthorized
                    }
                });
            }
        }
        let mut relay_urls = config
            .relays
            .iter()
            .filter(|relay| relay.roles.contains(weaver_config::RelayRoles::DATA_RELAY))
            .map(|relay| relay.url.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConfigAuthorizationError::MalformedRelayUrl)?;
        relay_urls.sort_by_key(|left: &RelayUrl| left.to_string());
        relay_urls.dedup();
        Ok(Self {
            relay_urls,
            allowed_clients,
            member_endpoints: endpoints_by_member.values().flatten().copied().collect(),
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigAuthorizationError {
    #[error("credential bytes in validated configuration are malformed: {0}")]
    Credential(#[from] CertificateError),
    #[error("configured endpoint ID is malformed")]
    MalformedEndpoint,
    #[error("configured relay URL is malformed")]
    MalformedRelayUrl,
    #[error("live authorization update belongs to another virtual network")]
    WrongNetwork,
    #[error("validated network configuration contains no presence service")]
    NoPresenceService,
    #[error("local endpoint has no signed binding in this network")]
    LocalEndpointNotMember,
    #[error("local endpoint is not authorized as this application server")]
    ServerNotAuthorized,
    #[error("local endpoint is not authorized as this application client")]
    ClientNotAuthorized,
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("failed to bind iroh endpoint: {0}")]
    Bind(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("endpoint did not become relay-online within {0:?}")]
    OnlineTimeout(Duration),
    #[error("failed to connect to peer: {0}")]
    Connect(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("failed to open a reliable stream: {0}")]
    OpenStream(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("target belongs to network {target}, but this endpoint is bound to {local}")]
    NetworkMismatch { local: NetworkId, target: NetworkId },
    #[error("remote rejected virtual TCP connection: {0}")]
    OpenRejected(&'static str),
    #[error("virtual TCP protocol violation: {0}")]
    ProtocolViolation(&'static str),
    #[error("server address is not bound by this endpoint: {0:?}")]
    ServerNotBound(ServerAddr),
    #[error("listener was already taken for server address {0:?}")]
    ListenerAlreadyTaken(ServerAddr),
    #[error("client source address is not bound by this endpoint: {0:?}")]
    ClientNotBound(ClientAddr),
    #[error("configuration sync request was rejected")]
    ConfigSyncRejected,
    #[error("configuration sync payload failed validation: {0}")]
    ConfigSync(#[source] BoxError),
    #[error("presence service rejected the request")]
    PresenceRejected,
    #[error("presence payload failed validation: {0}")]
    Presence(#[source] BoxError),
    #[error("no authenticated, unexpired presence exists for virtual server address {0}")]
    VirtualAddressUnresolved(AppAddr),
}

pub struct WeaverEndpoint {
    endpoint: Endpoint,
    incoming: HashMap<ServerAddr, Option<mpsc::Receiver<Result<VirtualTcpStream, io::Error>>>>,
    incoming_datagrams:
        HashMap<ServerAddr, Option<mpsc::Receiver<Result<VirtualUdpSocket, io::Error>>>>,
    accept_task: Option<JoinHandle<()>>,
    relay_url: Option<RelayUrl>,
    network_id: NetworkId,
    local_bindings: LocalBindings,
}

impl std::fmt::Debug for WeaverEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeaverEndpoint")
            .field("endpoint_id", &self.endpoint.id())
            .field("network_id", &self.network_id)
            .field("local_bindings", &self.local_bindings)
            .field("relay_url", &self.relay_url)
            .finish_non_exhaustive()
    }
}

impl WeaverEndpoint {
    pub async fn bind(config: NodeConfig) -> Result<Self, NetworkError> {
        let accepts_connections = !config.accept_alpns.is_empty()
            || config.config_update_source.is_some()
            || config.presence_store.is_some();
        let network_id = config.network_id;
        let local_bindings = config.local_bindings.clone();
        let relay_mode = if config.relay_urls.is_empty() {
            RelayMode::Disabled
        } else {
            RelayMode::Custom(
                config
                    .relay_urls
                    .iter()
                    .cloned()
                    .map(|url| RelayConfig::new(url, None))
                    .collect::<RelayMap>(),
            )
        };

        let mut accept_alpns = config.accept_alpns.clone();
        if config.config_update_source.is_some() {
            accept_alpns.push(config_sync_alpn(network_id));
        }
        if config.presence_store.is_some() {
            accept_alpns.push(presence_alpn(network_id));
        }
        let mut builder = Endpoint::builder(presets::N0)
            .clear_address_lookup()
            .secret_key(config.secret_key)
            .alpns(accept_alpns)
            .relay_mode(relay_mode);
        if let Some(lookup) = config.address_lookup.clone() {
            builder = builder.address_lookup(lookup);
        }
        if !config.enable_direct_paths {
            builder = builder.clear_ip_transports();
        }

        let endpoint = builder
            .bind()
            .await
            .map_err(|error| NetworkError::Bind(Box::new(error)))?;

        let mut incoming = HashMap::new();
        let mut incoming_datagrams = HashMap::new();
        let mut incoming_txs = HashMap::new();
        let mut datagram_txs = HashMap::new();
        let mut application_routes = HashMap::new();
        for server in local_bindings.servers() {
            let (tcp_tx, tcp_rx) = mpsc::channel(64);
            let (udp_tx, udp_rx) = mpsc::channel(64);
            incoming.insert(server, Some(tcp_rx));
            incoming_datagrams.insert(server, Some(udp_rx));
            incoming_txs.insert(server, tcp_tx);
            datagram_txs.insert(server, udp_tx);
            application_routes.insert(tcp_alpn(server.app()), (server, false));
            application_routes.insert(udp_alpn(server.app()), (server, true));
        }
        let accept_task = if !accepts_connections {
            None
        } else {
            let endpoint = endpoint.clone();
            let network_id = config.network_id;
            let config_update_source = config.config_update_source;
            let presence_store = config.presence_store;
            let authorizer = config.authorizer.unwrap_or_else(|| {
                Arc::new(StaticNetworkAuthorizer {
                    clients: config.allowed_clients,
                    config_peers: config.allowed_config_peers,
                    presence_peers: config.allowed_presence_peers,
                })
            });
            let services = AcceptServices {
                config_update_source,
                presence_store,
                authorizer,
                incoming_txs,
                datagram_txs,
                application_routes,
            };
            Some(tokio::spawn(async move {
                accept_connections(endpoint, network_id, services).await;
            }))
        };

        Ok(Self {
            endpoint,
            incoming,
            incoming_datagrams,
            accept_task,
            relay_url: config.relay_url,
            network_id,
            local_bindings,
        })
    }

    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub fn local_bindings(&self) -> &LocalBindings {
        &self.local_bindings
    }

    /// Notifies iroh that platform network interfaces changed, triggering path reprobe and
    /// refreshed address publication without replacing application streams.
    pub async fn network_change(&self) {
        self.endpoint.network_change().await;
    }

    pub async fn wait_relay_online(&self, timeout: Duration) -> Result<(), NetworkError> {
        if self.relay_url.is_none() {
            return Ok(());
        }
        tokio::time::timeout(timeout, self.endpoint.online())
            .await
            .map_err(|_| NetworkError::OnlineTimeout(timeout))?;
        Ok(())
    }

    pub fn descriptor(&self, app_addr: AppAddr) -> PeerDescriptor {
        let addr = self.endpoint.addr();
        PeerDescriptor {
            network_id: self.network_id(),
            app_addr,
            endpoint_id: self.endpoint.id(),
            relay_url: self.relay_url.clone(),
            direct_addresses: addr.ip_addrs().copied().collect(),
        }
    }

    /// Takes the reliable-stream listener for one bound server address.
    ///
    /// The returned listener implements both an `accept()` API and `Stream`, so it can be
    /// passed directly to `tonic::transport::Server::serve_with_incoming`.
    pub fn take_tcp_listener(
        &mut self,
        address: ServerAddr,
    ) -> Result<VirtualTcpListener, NetworkError> {
        self.incoming
            .get_mut(&address)
            .ok_or(NetworkError::ServerNotBound(address))?
            .take()
            .map(VirtualTcpListener::new)
            .ok_or(NetworkError::ListenerAlreadyTaken(address))
    }

    pub fn take_udp_listener(
        &mut self,
        address: ServerAddr,
    ) -> Result<VirtualUdpListener, NetworkError> {
        self.incoming_datagrams
            .get_mut(&address)
            .ok_or(NetworkError::ServerNotBound(address))?
            .take()
            .map(VirtualUdpListener::new)
            .ok_or(NetworkError::ListenerAlreadyTaken(address))
    }

    /// Opens a reliable, ordered byte stream to a virtual server address.
    pub async fn connect(
        &self,
        source: ClientAddr,
        target: &PeerDescriptor,
    ) -> Result<VirtualTcpStream, NetworkError> {
        if !self.local_bindings.contains_client(source) {
            return Err(NetworkError::ClientNotBound(source));
        }
        self.dialer().connect(source, target).await
    }

    /// Opens a reliable stream using only the application-visible virtual server address.
    pub async fn connect_virtual(
        &self,
        source: ClientAddr,
        directory: &PresenceDirectory,
        app_addr: AppAddr,
        now_ms: u64,
    ) -> Result<VirtualTcpStream, NetworkError> {
        self.dialer()
            .connect_virtual(source, directory, app_addr, now_ms)
            .await
    }

    pub async fn connect_tonic(
        &self,
        source: ClientAddr,
        target: &PeerDescriptor,
    ) -> Result<VirtualTcpStream, NetworkError> {
        self.connect(source, target).await
    }

    pub async fn connect_udp(
        &self,
        source: ClientAddr,
        target: &PeerDescriptor,
    ) -> Result<VirtualUdpSocket, NetworkError> {
        if !self.local_bindings.contains_client(source) {
            return Err(NetworkError::ClientNotBound(source));
        }
        if target.network_id != self.network_id {
            return Err(NetworkError::NetworkMismatch {
                local: self.network_id,
                target: target.network_id,
            });
        }
        let connection = self
            .endpoint
            .connect(target.endpoint_addr(), &udp_alpn(target.app_addr))
            .await
            .map_err(|error| NetworkError::Connect(Box::new(error)))?;
        if connection.remote_id() != target.endpoint_id {
            return Err(NetworkError::ProtocolViolation(
                "datagram peer identity differs from descriptor",
            ));
        }
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        let peer_addr = ScopedVirtualAddr::Server {
            app: target.app_addr,
        };
        let request = OpenStreamRequest {
            network_id: self.network_id,
            source: source.scoped(),
            destination: peer_addr,
        }
        .encode_datagram()?;
        send.write_all(&request)
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        let mut response = [0];
        recv.read_exact(&mut response)
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        if response[0] != OPEN_RESPONSE_ACCEPTED {
            return Err(NetworkError::OpenRejected(open_response_reason(
                response[0],
            )));
        }
        send.finish()
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        Ok(VirtualUdpSocket::new(
            connection,
            source.scoped(),
            peer_addr,
        ))
    }

    pub async fn connect_udp_virtual(
        &self,
        source: ClientAddr,
        directory: &PresenceDirectory,
        app_addr: AppAddr,
        now_ms: u64,
    ) -> Result<VirtualUdpSocket, NetworkError> {
        let target = discovered_descriptor(self.network_id, directory, app_addr, now_ms)?;
        self.connect_udp(source, &target).await
    }

    pub fn dialer(&self) -> WeaverDialer {
        WeaverDialer {
            endpoint: self.endpoint.clone(),
            network_id: self.network_id(),
            local_bindings: self.local_bindings.clone(),
        }
    }

    pub async fn fetch_config_updates(
        &self,
        target: &ConfigPeerDescriptor,
        base_head: ConfigHead,
    ) -> Result<ConfigUpdateBatch, NetworkError> {
        self.dialer().fetch_config_updates(target, base_head).await
    }

    pub async fn publish_presence(
        &self,
        target: &ConfigPeerDescriptor,
        record: &EncryptedPresenceRecord,
        expires_at_ms: u64,
    ) -> Result<(), NetworkError> {
        self.dialer()
            .publish_presence(target, record, expires_at_ms)
            .await
    }

    pub async fn query_presence(
        &self,
        target: &ConfigPeerDescriptor,
        epoch: u64,
        opaque_key: [u8; 24],
    ) -> Result<Option<EncryptedPresenceRecord>, NetworkError> {
        self.dialer()
            .query_presence(target, epoch, opaque_key)
            .await
    }

    pub fn start_config_sync<T: ConfigSyncState>(
        &self,
        target: ConfigPeerDescriptor,
        state: Arc<AsyncMutex<T>>,
        options: ConfigSyncOptions,
    ) -> ConfigSyncRuntime {
        spawn_config_sync(self.dialer(), target, state, options)
    }

    pub fn start_config_anti_entropy<T: ConfigSyncState>(
        &self,
        targets: Vec<ConfigPeerDescriptor>,
        state: Arc<AsyncMutex<T>>,
        options: ConfigSyncOptions,
    ) -> ConfigSyncRuntime {
        spawn_config_anti_entropy(self.dialer(), targets, state, options)
    }

    pub async fn close(mut self) {
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = task.await;
        }
        self.endpoint.close().await;
    }
}

#[derive(Clone, Debug)]
pub struct WeaverDialer {
    endpoint: Endpoint,
    network_id: NetworkId,
    local_bindings: LocalBindings,
}

impl WeaverDialer {
    /// Cloneable platform-network-change hook for runtimes that keep listeners elsewhere.
    pub async fn network_change(&self) {
        self.endpoint.network_change().await;
    }

    /// Opens one reliable virtual TCP connection using an explicit bound client identity.
    pub async fn connect(
        &self,
        source: ClientAddr,
        target: &PeerDescriptor,
    ) -> Result<VirtualTcpStream, NetworkError> {
        if !self.local_bindings.contains_client(source) {
            return Err(NetworkError::ClientNotBound(source));
        }
        if target.network_id != self.network_id {
            return Err(NetworkError::NetworkMismatch {
                local: self.network_id,
                target: target.network_id,
            });
        }
        let connection = self
            .endpoint
            .connect(target.endpoint_addr(), &tcp_alpn(target.app_addr))
            .await
            .map_err(|error| NetworkError::Connect(Box::new(error)))?;
        let peer = connection.remote_id();
        if peer != target.endpoint_id {
            return Err(NetworkError::Connect(Box::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "connected endpoint identity differs from target descriptor",
            ))));
        }
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        // QUIC does not expose a newly opened stream to the peer until the opener sends
        // data. Send and consume an internal preface so server-first protocols have the
        // same connect/accept behavior they expect from TCP.
        let peer_addr = ScopedVirtualAddr::Server {
            app: target.app_addr,
        };
        let request = OpenStreamRequest {
            network_id: self.network_id,
            source: source.scoped(),
            destination: peer_addr,
        }
        .encode()?;
        send.write_all(&request)
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        let mut response = [0];
        tokio::time::timeout(PREFACE_TIMEOUT, recv.read_exact(&mut response))
            .await
            .map_err(|_| NetworkError::OpenRejected("open response timed out"))?
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        match response[0] {
            OPEN_RESPONSE_ACCEPTED => Ok(VirtualTcpStream::new(
                send,
                recv,
                connection,
                source.scoped(),
                peer_addr,
            )),
            OPEN_RESPONSE_NOT_AUTHORIZED => Err(NetworkError::OpenRejected("not authorized")),
            OPEN_RESPONSE_NETWORK_MISMATCH => Err(NetworkError::OpenRejected("network mismatch")),
            OPEN_RESPONSE_ADDRESS_MISMATCH => {
                Err(NetworkError::OpenRejected("virtual address mismatch"))
            }
            OPEN_RESPONSE_PROTOCOL_ERROR => Err(NetworkError::OpenRejected("protocol error")),
            _ => Err(NetworkError::ProtocolViolation(
                "unknown open response code",
            )),
        }
    }

    pub async fn connect_virtual(
        &self,
        source: ClientAddr,
        directory: &PresenceDirectory,
        app_addr: AppAddr,
        now_ms: u64,
    ) -> Result<VirtualTcpStream, NetworkError> {
        let target = discovered_descriptor(self.network_id, directory, app_addr, now_ms)?;
        self.connect(source, &target).await
    }

    pub async fn connect_tonic(
        &self,
        source: ClientAddr,
        target: &PeerDescriptor,
    ) -> Result<VirtualTcpStream, NetworkError> {
        self.connect(source, target).await
    }

    pub async fn fetch_config_updates(
        &self,
        target: &ConfigPeerDescriptor,
        base_head: ConfigHead,
    ) -> Result<ConfigUpdateBatch, NetworkError> {
        if target.network_id != self.network_id {
            return Err(NetworkError::NetworkMismatch {
                local: self.network_id,
                target: target.network_id,
            });
        }
        let connection = self
            .endpoint
            .connect(target.endpoint_addr(), &config_sync_alpn(self.network_id))
            .await
            .map_err(|error| NetworkError::Connect(Box::new(error)))?;
        if connection.remote_id() != target.endpoint_id {
            return Err(NetworkError::ProtocolViolation(
                "config peer identity differs from descriptor",
            ));
        }
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        send.write_all(&encode_config_sync_request(self.network_id, base_head))
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        send.finish()
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        let mut header = [0_u8; 5];
        recv.read_exact(&mut header)
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        if header[0] != CONFIG_SYNC_RESPONSE_OK {
            return Err(NetworkError::ConfigSyncRejected);
        }
        let len = u32::from_be_bytes(header[1..5].try_into().expect("fixed header")) as usize;
        if len > MAX_CONFIG_SYNC_RESPONSE {
            return Err(NetworkError::ProtocolViolation(
                "config sync response exceeds limit",
            ));
        }
        let mut bytes = vec![0_u8; len];
        recv.read_exact(&mut bytes)
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        let updates = ConfigUpdateBatch::from_bytes(&bytes)
            .map_err(|error| NetworkError::ConfigSync(Box::new(error)))?;
        if updates.network_id != self.network_id || updates.base_head != base_head {
            return Err(NetworkError::ProtocolViolation(
                "config sync response does not match request",
            ));
        }
        Ok(updates)
    }

    pub async fn publish_presence(
        &self,
        target: &ConfigPeerDescriptor,
        record: &EncryptedPresenceRecord,
        expires_at_ms: u64,
    ) -> Result<(), NetworkError> {
        let bytes = record
            .to_bytes()
            .map_err(|error| NetworkError::Presence(Box::new(error)))?;
        let response = self
            .presence_request(
                target,
                PRESENCE_OP_PUBLISH,
                record.epoch(),
                record.opaque_key(),
                expires_at_ms,
                &bytes,
            )
            .await?;
        if response.is_some() {
            return Err(NetworkError::ProtocolViolation(
                "presence publish returned an unexpected payload",
            ));
        }
        Ok(())
    }

    pub async fn query_presence(
        &self,
        target: &ConfigPeerDescriptor,
        epoch: u64,
        opaque_key: [u8; 24],
    ) -> Result<Option<EncryptedPresenceRecord>, NetworkError> {
        let Some(bytes) = self
            .presence_request(target, PRESENCE_OP_QUERY, epoch, opaque_key, 0, &[])
            .await?
        else {
            return Ok(None);
        };
        let record = EncryptedPresenceRecord::from_bytes(&bytes)
            .map_err(|error| NetworkError::Presence(Box::new(error)))?;
        if record.epoch() != epoch || record.opaque_key() != opaque_key {
            return Err(NetworkError::ProtocolViolation(
                "presence response key does not match request",
            ));
        }
        Ok(Some(record))
    }

    async fn presence_request(
        &self,
        target: &ConfigPeerDescriptor,
        operation: u8,
        epoch: u64,
        opaque_key: [u8; 24],
        expires_at_ms: u64,
        body: &[u8],
    ) -> Result<Option<Bytes>, NetworkError> {
        if target.network_id != self.network_id {
            return Err(NetworkError::NetworkMismatch {
                local: self.network_id,
                target: target.network_id,
            });
        }
        if body.len() > MAX_PRESENCE_RECORD_BYTES {
            return Err(NetworkError::ProtocolViolation(
                "presence request exceeds limit",
            ));
        }
        let connection = self
            .endpoint
            .connect(target.endpoint_addr(), &presence_alpn(self.network_id))
            .await
            .map_err(|error| NetworkError::Connect(Box::new(error)))?;
        if connection.remote_id() != target.endpoint_id {
            return Err(NetworkError::ProtocolViolation(
                "presence service identity differs from descriptor",
            ));
        }
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        let header = encode_presence_request(
            self.network_id,
            operation,
            epoch,
            opaque_key,
            expires_at_ms,
            body.len(),
        )?;
        send.write_all(&header)
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        if !body.is_empty() {
            send.write_all(body)
                .await
                .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        }
        send.finish()
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        let mut response = [0_u8; PRESENCE_RESPONSE_HEADER_LEN];
        recv.read_exact(&mut response)
            .await
            .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
        let status = response[0];
        let len = u32::from_be_bytes(response[9..13].try_into().expect("fixed header")) as usize;
        if len > MAX_PRESENCE_RECORD_BYTES {
            return Err(NetworkError::ProtocolViolation(
                "presence response exceeds limit",
            ));
        }
        match status {
            PRESENCE_RESPONSE_OK => {
                if operation == PRESENCE_OP_PUBLISH && len != 0 {
                    return Err(NetworkError::ProtocolViolation(
                        "presence publish response has a payload",
                    ));
                }
                let mut bytes = vec![0_u8; len];
                recv.read_exact(&mut bytes)
                    .await
                    .map_err(|error| NetworkError::OpenStream(Box::new(error)))?;
                Ok((len != 0).then(|| Bytes::from(bytes)))
            }
            PRESENCE_RESPONSE_NOT_FOUND if operation == PRESENCE_OP_QUERY && len == 0 => Ok(None),
            PRESENCE_RESPONSE_REJECTED => Err(NetworkError::PresenceRejected),
            _ => Err(NetworkError::ProtocolViolation("invalid presence response")),
        }
    }
}

fn discovered_descriptor(
    network_id: NetworkId,
    directory: &PresenceDirectory,
    app_addr: AppAddr,
    now_ms: u64,
) -> Result<PeerDescriptor, NetworkError> {
    if directory.network_id() != network_id {
        return Err(NetworkError::NetworkMismatch {
            local: network_id,
            target: directory.network_id(),
        });
    }
    let endpoint_id = directory
        .resolve(ScopedVirtualAddr::Server { app: app_addr }, now_ms)
        .ok_or(NetworkError::VirtualAddressUnresolved(app_addr))?;
    Ok(PeerDescriptor {
        network_id,
        app_addr,
        endpoint_id,
        relay_url: None,
        direct_addresses: Vec::new(),
    })
}

/// Tokio-style listener for incoming reliable virtual connections.
pub struct VirtualTcpListener {
    incoming: mpsc::Receiver<Result<VirtualTcpStream, io::Error>>,
}

impl VirtualTcpListener {
    fn new(incoming: mpsc::Receiver<Result<VirtualTcpStream, io::Error>>) -> Self {
        Self { incoming }
    }

    pub async fn accept(&mut self) -> io::Result<VirtualTcpStream> {
        self.incoming.recv().await.unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "virtual TCP listener closed",
            ))
        })
    }
}

impl std::fmt::Debug for VirtualTcpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualTcpListener").finish_non_exhaustive()
    }
}

impl Stream for VirtualTcpListener {
    type Item = Result<VirtualTcpStream, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.incoming.poll_recv(cx)
    }
}

/// Listener for authenticated QUIC-datagram associations to one virtual server address.
pub struct VirtualUdpListener {
    incoming: mpsc::Receiver<Result<VirtualUdpSocket, io::Error>>,
}

impl VirtualUdpListener {
    fn new(incoming: mpsc::Receiver<Result<VirtualUdpSocket, io::Error>>) -> Self {
        Self { incoming }
    }

    pub async fn accept(&mut self) -> io::Result<VirtualUdpSocket> {
        self.incoming.recv().await.unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "virtual UDP listener closed",
            ))
        })
    }
}

impl std::fmt::Debug for VirtualUdpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualUdpListener").finish_non_exhaustive()
    }
}

/// A connected, message-oriented QUIC DATAGRAM socket.
///
/// Messages preserve boundaries but are not acknowledged or retransmitted and may be
/// lost or observed in a different order. Oversized messages are rejected by QUIC.
pub struct VirtualUdpSocket {
    connection: Connection,
    local_addr: ScopedVirtualAddr,
    peer_addr: ScopedVirtualAddr,
    send_lock: std::sync::Mutex<()>,
}

impl VirtualUdpSocket {
    fn new(
        connection: Connection,
        local_addr: ScopedVirtualAddr,
        peer_addr: ScopedVirtualAddr,
    ) -> Self {
        Self {
            connection,
            local_addr,
            peer_addr,
            send_lock: std::sync::Mutex::new(()),
        }
    }

    pub fn peer_endpoint_id(&self) -> EndpointId {
        self.connection.remote_id()
    }

    pub fn local_addr(&self) -> ScopedVirtualAddr {
        self.local_addr
    }

    pub fn peer_addr(&self) -> ScopedVirtualAddr {
        self.peer_addr
    }

    pub fn send(&self, message: impl Into<Bytes>) -> io::Result<()> {
        let message = message.into();
        let _guard = self
            .send_lock
            .lock()
            .map_err(|_| io::Error::other("datagram send lock poisoned"))?;
        let maximum = self.max_datagram_size().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "peer does not support datagrams",
            )
        })?;
        if message.len() > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "datagram has {} bytes, current maximum is {maximum}",
                    message.len()
                ),
            ));
        }
        if self.connection.datagram_send_buffer_space() < message.len() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "datagram send buffer has insufficient space",
            ));
        }
        self.connection
            .send_datagram(message)
            .map_err(io::Error::other)
    }

    pub async fn send_wait(&self, message: impl Into<Bytes>) -> io::Result<()> {
        let message = message.into();
        let maximum = self.max_datagram_size().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "peer does not support datagrams",
            )
        })?;
        if message.len() > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "datagram has {} bytes, current maximum is {maximum}",
                    message.len()
                ),
            ));
        }
        self.connection
            .send_datagram_wait(message)
            .await
            .map_err(io::Error::other)
    }

    pub fn send_to(&self, message: impl Into<Bytes>, target: ScopedVirtualAddr) -> io::Result<()> {
        if target != self.peer_addr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "connected virtual UDP socket cannot send to a different peer",
            ));
        }
        self.send(message)
    }

    pub async fn recv(&mut self) -> io::Result<Bytes> {
        self.connection
            .read_datagram()
            .await
            .map_err(io::Error::other)
    }

    pub async fn recv_from(&mut self) -> io::Result<(Bytes, ScopedVirtualAddr)> {
        self.recv().await.map(|message| (message, self.peer_addr))
    }

    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    pub fn send_buffer_space(&self) -> usize {
        self.connection.datagram_send_buffer_space()
    }

    pub fn transport_paths(&self) -> Vec<TransportPathStatus> {
        transport_paths(&self.connection)
    }

    pub fn close_reason(&self) -> Option<String> {
        self.connection
            .close_reason()
            .map(|reason| reason.to_string())
    }
}

impl std::fmt::Debug for VirtualUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualUdpSocket")
            .field("peer_endpoint_id", &self.peer_endpoint_id())
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

struct AcceptServices {
    config_update_source: Option<Arc<dyn ConfigUpdateSource>>,
    presence_store: Option<Arc<dyn OpaquePresenceStore>>,
    authorizer: Arc<dyn NetworkAuthorizer>,
    incoming_txs: HashMap<ServerAddr, mpsc::Sender<Result<VirtualTcpStream, io::Error>>>,
    datagram_txs: HashMap<ServerAddr, mpsc::Sender<Result<VirtualUdpSocket, io::Error>>>,
    application_routes: HashMap<Vec<u8>, (ServerAddr, bool)>,
}

async fn accept_connections(endpoint: Endpoint, network_id: NetworkId, services: AcceptServices) {
    while let Some(incoming) = endpoint.accept().await {
        let mut accepting = match incoming.accept() {
            Ok(accepting) => accepting,
            Err(error) => {
                debug!(%error, "discarding malformed incoming QUIC packet");
                continue;
            }
        };
        let alpn = match tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting.alpn()).await {
            Ok(Ok(alpn)) => alpn,
            Ok(Err(error)) => {
                debug!(%error, "discarding incoming connection with invalid ALPN");
                continue;
            }
            Err(_) => {
                debug!("discarding incoming connection after ALPN timeout");
                continue;
            }
        };
        let connection = match tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                warn!(%error, "incoming QUIC handshake failed");
                continue;
            }
            Err(_) => {
                debug!("discarding incoming connection after handshake timeout");
                continue;
            }
        };
        let remote_id = connection.remote_id();
        if alpn == config_sync_alpn(network_id) {
            let Some(source) = services.config_update_source.clone() else {
                connection.close(1u32.into(), b"config sync disabled");
                continue;
            };
            if !services.authorizer.allow_config_sync(remote_id) {
                warn!(%remote_id, "rejecting non-member config sync peer");
                connection.close(1u32.into(), b"config peer not allowed");
                continue;
            }
            tokio::spawn(handle_config_sync_connection(
                connection, network_id, remote_id, source,
            ));
            continue;
        }
        if alpn == presence_alpn(network_id) {
            let Some(store) = services.presence_store.clone() else {
                connection.close(1u32.into(), b"presence disabled");
                continue;
            };
            if !services.authorizer.allow_presence(remote_id) {
                warn!(%remote_id, "rejecting non-member presence peer");
                connection.close(1u32.into(), b"presence peer not allowed");
                continue;
            }
            tokio::spawn(handle_presence_connection(
                connection, network_id, remote_id, store,
            ));
            continue;
        }
        let Some((server_addr, datagram_protocol)) =
            services.application_routes.get(&alpn).copied()
        else {
            connection.close(1u32.into(), b"unknown application binding");
            continue;
        };
        let local_addr = server_addr.scoped();
        let authorized_addrs = services
            .authorizer
            .authorized_client_addrs(remote_id, local_addr);
        if authorized_addrs.is_empty() {
            warn!(%remote_id, "rejecting endpoint absent from the development allowlist");
            connection.close(1u32.into(), b"endpoint not allowed");
            continue;
        }
        info!(%remote_id, "accepted authenticated peer connection");
        if datagram_protocol {
            tokio::spawn(handle_datagram_connection(
                connection,
                network_id,
                local_addr,
                remote_id,
                services.authorizer.clone(),
                services
                    .datagram_txs
                    .get(&server_addr)
                    .expect("bound UDP route")
                    .clone(),
            ));
            continue;
        }
        let tx = services
            .incoming_txs
            .get(&server_addr)
            .expect("bound TCP route")
            .clone();
        let authorizer = services.authorizer.clone();
        tokio::spawn(async move {
            let stream_limit = Arc::new(Semaphore::new(MAX_STREAM_HANDLERS_PER_CONNECTION));
            loop {
                match connection.accept_bi().await {
                    Ok((mut send, mut recv)) => {
                        let Ok(stream_permit) = stream_limit.clone().try_acquire_owned() else {
                            let _ = send.reset(1u32.into());
                            let _ = recv.stop(1u32.into());
                            warn!(%remote_id, "rejecting stream above per-connection limit");
                            continue;
                        };
                        let connection = connection.clone();
                        let tx = tx.clone();
                        let authorizer = authorizer.clone();
                        tokio::spawn(async move {
                            let _stream_permit = stream_permit;
                            let mut request_bytes = [0; OPEN_REQUEST_LEN];
                            let request = match tokio::time::timeout(
                                PREFACE_TIMEOUT,
                                recv.read_exact(&mut request_bytes),
                            )
                            .await
                            {
                                Ok(Ok(_)) => OpenStreamRequest::decode(&request_bytes),
                                _ => Err(()),
                            };
                            let response = match request {
                                Err(()) => OPEN_RESPONSE_PROTOCOL_ERROR,
                                Ok(request) if request.network_id != network_id => {
                                    OPEN_RESPONSE_NETWORK_MISMATCH
                                }
                                Ok(request) if request.destination != local_addr => {
                                    OPEN_RESPONSE_ADDRESS_MISMATCH
                                }
                                Ok(request)
                                    if !authorizer
                                        .authorized_client_addrs(remote_id, local_addr)
                                        .contains(&request.source) =>
                                {
                                    OPEN_RESPONSE_NOT_AUTHORIZED
                                }
                                Ok(_) => OPEN_RESPONSE_ACCEPTED,
                            };
                            if send.write_all(&[response]).await.is_err() {
                                return;
                            }
                            let valid = response == OPEN_RESPONSE_ACCEPTED;
                            if !valid {
                                warn!(%remote_id, response, "rejecting virtual TCP open request");
                                // Finish, rather than reset, the response direction so the
                                // authenticated rejection code is delivered reliably.
                                let _ = send.finish();
                                return;
                            }
                            let stream = VirtualTcpStream::new(
                                send,
                                recv,
                                connection,
                                local_addr,
                                request.expect("accepted request was decoded").source,
                            );
                            let _ = tx.send(Ok(stream)).await;
                        });
                    }
                    Err(error) => {
                        debug!(%remote_id, %error, "peer connection stopped accepting streams");
                        break;
                    }
                }
            }
        });
    }
}

fn encode_presence_request(
    network_id: NetworkId,
    operation: u8,
    epoch: u64,
    opaque_key: [u8; 24],
    expires_at_ms: u64,
    body_len: usize,
) -> Result<[u8; PRESENCE_REQUEST_HEADER_LEN], NetworkError> {
    let body_len = u32::try_from(body_len)
        .map_err(|_| NetworkError::ProtocolViolation("presence request exceeds limit"))?;
    let mut out = [0_u8; PRESENCE_REQUEST_HEADER_LEN];
    out[..16].copy_from_slice(PRESENCE_REQUEST_MAGIC);
    out[16..48].copy_from_slice(network_id.as_bytes());
    out[48] = operation;
    out[49..57].copy_from_slice(&epoch.to_be_bytes());
    out[57..81].copy_from_slice(&opaque_key);
    out[81..89].copy_from_slice(&expires_at_ms.to_be_bytes());
    out[89..93].copy_from_slice(&body_len.to_be_bytes());
    Ok(out)
}

struct PresenceRequest {
    network_id: NetworkId,
    operation: u8,
    epoch: u64,
    opaque_key: [u8; 24],
    expires_at_ms: u64,
    body_len: usize,
}

fn decode_presence_request(
    bytes: &[u8; PRESENCE_REQUEST_HEADER_LEN],
) -> Result<PresenceRequest, ()> {
    if &bytes[..16] != PRESENCE_REQUEST_MAGIC {
        return Err(());
    }
    let request = PresenceRequest {
        network_id: NetworkId::from_bytes(bytes[16..48].try_into().map_err(|_| ())?),
        operation: bytes[48],
        epoch: u64::from_be_bytes(bytes[49..57].try_into().map_err(|_| ())?),
        opaque_key: bytes[57..81].try_into().map_err(|_| ())?,
        expires_at_ms: u64::from_be_bytes(bytes[81..89].try_into().map_err(|_| ())?),
        body_len: u32::from_be_bytes(bytes[89..93].try_into().map_err(|_| ())?) as usize,
    };
    if request.body_len > MAX_PRESENCE_RECORD_BYTES
        || !matches!(request.operation, PRESENCE_OP_PUBLISH | PRESENCE_OP_QUERY)
        || (request.operation == PRESENCE_OP_QUERY
            && (request.body_len != 0 || request.expires_at_ms != 0))
        || (request.operation == PRESENCE_OP_PUBLISH && request.body_len == 0)
    {
        return Err(());
    }
    Ok(request)
}

async fn handle_presence_connection(
    connection: Connection,
    network_id: NetworkId,
    remote_id: EndpointId,
    store: Arc<dyn OpaquePresenceStore>,
) {
    let (mut send, mut recv) = match connection.accept_bi().await {
        Ok(streams) => streams,
        Err(_) => return,
    };
    let mut header = [0_u8; PRESENCE_REQUEST_HEADER_LEN];
    let request = match tokio::time::timeout(PREFACE_TIMEOUT, recv.read_exact(&mut header)).await {
        Ok(Ok(_)) => decode_presence_request(&header).ok(),
        _ => None,
    };
    let result = match request {
        Some(request) if request.network_id == network_id => match request.operation {
            PRESENCE_OP_PUBLISH => {
                let mut bytes = vec![0_u8; request.body_len];
                match recv.read_exact(&mut bytes).await {
                    Ok(_) => match EncryptedPresenceRecord::from_bytes(&bytes) {
                        Ok(record)
                            if record.epoch() == request.epoch
                                && record.opaque_key() == request.opaque_key =>
                        {
                            store
                                .publish(
                                    remote_id,
                                    request.epoch,
                                    request.opaque_key,
                                    request.expires_at_ms,
                                    Bytes::from(bytes),
                                )
                                .await
                                .map(|()| None)
                        }
                        _ => Err(Box::new(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "presence envelope does not match request key",
                        )) as BoxError),
                    },
                    Err(error) => Err(Box::new(error) as BoxError),
                }
            }
            PRESENCE_OP_QUERY => store
                .query(
                    remote_id,
                    request.epoch,
                    request.opaque_key,
                    config_wall_now_ms(),
                )
                .await
                .map(|record| record.map(|(_, bytes)| bytes)),
            _ => unreachable!("decoder validates presence operation"),
        },
        _ => Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed presence request",
        )) as BoxError),
    };
    let (status, body) = match result {
        Ok(Some(bytes)) => (PRESENCE_RESPONSE_OK, bytes),
        Ok(None) if request_operation(&header) == Some(PRESENCE_OP_QUERY) => {
            (PRESENCE_RESPONSE_NOT_FOUND, Bytes::new())
        }
        Ok(None) => (PRESENCE_RESPONSE_OK, Bytes::new()),
        Err(_) => (PRESENCE_RESPONSE_REJECTED, Bytes::new()),
    };
    let mut response = [0_u8; PRESENCE_RESPONSE_HEADER_LEN];
    response[0] = status;
    response[1..9].copy_from_slice(&config_wall_now_ms().to_be_bytes());
    response[9..13].copy_from_slice(&(body.len() as u32).to_be_bytes());
    if send.write_all(&response).await.is_ok() && !body.is_empty() {
        let _ = send.write_all(&body).await;
    }
    let _ = send.finish();
    let _ = send.stopped().await;
}

fn request_operation(header: &[u8; PRESENCE_REQUEST_HEADER_LEN]) -> Option<u8> {
    (&header[..16] == PRESENCE_REQUEST_MAGIC).then_some(header[48])
}

fn open_response_reason(response: u8) -> &'static str {
    match response {
        OPEN_RESPONSE_NOT_AUTHORIZED => "not authorized",
        OPEN_RESPONSE_NETWORK_MISMATCH => "network mismatch",
        OPEN_RESPONSE_ADDRESS_MISMATCH => "virtual address mismatch",
        OPEN_RESPONSE_PROTOCOL_ERROR => "protocol error",
        _ => "unknown response code",
    }
}

async fn handle_datagram_connection(
    connection: Connection,
    network_id: NetworkId,
    local_addr: ScopedVirtualAddr,
    remote_id: EndpointId,
    authorizer: Arc<dyn NetworkAuthorizer>,
    tx: mpsc::Sender<Result<VirtualUdpSocket, io::Error>>,
) {
    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
        return;
    };
    let mut request_bytes = [0; OPEN_REQUEST_LEN];
    let request =
        match tokio::time::timeout(PREFACE_TIMEOUT, recv.read_exact(&mut request_bytes)).await {
            Ok(Ok(_)) => OpenStreamRequest::decode_datagram(&request_bytes),
            _ => Err(()),
        };
    let response = match request {
        Err(()) => OPEN_RESPONSE_PROTOCOL_ERROR,
        Ok(request) if request.network_id != network_id => OPEN_RESPONSE_NETWORK_MISMATCH,
        Ok(request) if request.destination != local_addr => OPEN_RESPONSE_ADDRESS_MISMATCH,
        Ok(request)
            if !authorizer
                .authorized_client_addrs(remote_id, local_addr)
                .contains(&request.source) =>
        {
            OPEN_RESPONSE_NOT_AUTHORIZED
        }
        Ok(_) => OPEN_RESPONSE_ACCEPTED,
    };
    if send.write_all(&[response]).await.is_err() {
        return;
    }
    let _ = send.finish();
    if response != OPEN_RESPONSE_ACCEPTED {
        warn!(%remote_id, response, "rejecting virtual UDP association");
        let _ = send.stopped().await;
        return;
    }
    let peer_addr = request
        .expect("accepted datagram request was decoded")
        .source;
    let _ = tx
        .send(Ok(VirtualUdpSocket::new(connection, local_addr, peer_addr)))
        .await;
}

fn encode_config_sync_request(
    network_id: NetworkId,
    base_head: ConfigHead,
) -> [u8; CONFIG_SYNC_REQUEST_LEN] {
    let mut out = [0_u8; CONFIG_SYNC_REQUEST_LEN];
    out[..16].copy_from_slice(CONFIG_SYNC_REQUEST_MAGIC);
    out[16..48].copy_from_slice(network_id.as_bytes());
    out[48..56].copy_from_slice(&base_head.epoch.to_be_bytes());
    out[56..64].copy_from_slice(&base_head.revision.to_be_bytes());
    out[64..96].copy_from_slice(&base_head.hash);
    out
}

fn decode_config_sync_request(
    bytes: &[u8; CONFIG_SYNC_REQUEST_LEN],
) -> Result<(NetworkId, ConfigHead), ()> {
    if &bytes[..16] != CONFIG_SYNC_REQUEST_MAGIC {
        return Err(());
    }
    Ok((
        NetworkId::from_bytes(bytes[16..48].try_into().map_err(|_| ())?),
        ConfigHead {
            epoch: u64::from_be_bytes(bytes[48..56].try_into().map_err(|_| ())?),
            revision: u64::from_be_bytes(bytes[56..64].try_into().map_err(|_| ())?),
            hash: bytes[64..96].try_into().map_err(|_| ())?,
        },
    ))
}

async fn handle_config_sync_connection(
    connection: Connection,
    network_id: NetworkId,
    remote_id: EndpointId,
    source: Arc<dyn ConfigUpdateSource>,
) {
    let (mut send, mut recv) = match connection.accept_bi().await {
        Ok(streams) => streams,
        Err(_) => return,
    };
    let mut request = [0_u8; CONFIG_SYNC_REQUEST_LEN];
    let decoded = match tokio::time::timeout(PREFACE_TIMEOUT, recv.read_exact(&mut request)).await {
        Ok(Ok(_)) => decode_config_sync_request(&request),
        _ => Err(()),
    };
    let result = match decoded {
        Ok((requested_network, base_head)) if requested_network == network_id => source
            .updates_after(remote_id, base_head)
            .await
            .and_then(|updates| {
                if updates.network_id != network_id || updates.base_head != base_head {
                    return Err(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "config source returned a mismatched batch",
                    )) as BoxError);
                }
                updates
                    .to_bytes()
                    .map_err(|error| Box::new(error) as BoxError)
            }),
        _ => Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed config sync request",
        )) as BoxError),
    };
    match result {
        Ok(bytes) if bytes.len() <= MAX_CONFIG_SYNC_RESPONSE => {
            let mut header = [0_u8; 5];
            header[0] = CONFIG_SYNC_RESPONSE_OK;
            header[1..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
            if send.write_all(&header).await.is_ok() {
                let _ = send.write_all(&bytes).await;
            }
        }
        Ok(_) | Err(_) => {
            let mut header = [0_u8; 5];
            header[0] = CONFIG_SYNC_RESPONSE_REJECTED;
            let _ = send.write_all(&header).await;
        }
    }
    let _ = send.finish();
    // `finish` only queues the FIN. Retain the connection until the peer has consumed
    // the response so a short-lived control request cannot race connection teardown.
    let _ = send.stopped().await;
}

#[derive(Clone, Debug)]
pub struct PeerConnectInfo {
    pub endpoint_id: EndpointId,
    pub virtual_addr: ScopedVirtualAddr,
}

pub struct VirtualTcpStream {
    send: SendStream,
    recv: RecvStream,
    connection: Connection,
    local_addr: ScopedVirtualAddr,
    peer_addr: ScopedVirtualAddr,
    write_shutdown: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportPathKind {
    Direct,
    Relay,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectPathScope {
    Lan,
    Wan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportPathStatus {
    pub kind: TransportPathKind,
    pub selected: bool,
    pub direct_scope: Option<DirectPathScope>,
    pub rtt: Duration,
}

impl VirtualTcpStream {
    fn new(
        send: SendStream,
        recv: RecvStream,
        connection: Connection,
        local_addr: ScopedVirtualAddr,
        peer_addr: ScopedVirtualAddr,
    ) -> Self {
        Self {
            send,
            recv,
            connection,
            local_addr,
            peer_addr,
            write_shutdown: false,
        }
    }

    pub fn peer_endpoint_id(&self) -> EndpointId {
        self.connection.remote_id()
    }

    pub fn local_addr(&self) -> ScopedVirtualAddr {
        self.local_addr
    }

    pub fn peer_addr(&self) -> ScopedVirtualAddr {
        self.peer_addr
    }

    /// Returns an instantaneous, transport-only view of the paths backing this stream.
    /// Path changes do not replace the QUIC connection or this application byte stream.
    pub fn transport_paths(&self) -> Vec<TransportPathStatus> {
        transport_paths(&self.connection)
    }

    pub fn close_reason(&self) -> Option<String> {
        self.connection
            .close_reason()
            .map(|reason| reason.to_string())
    }

    /// Sends FIN and waits until the peer acknowledges all previously written bytes.
    ///
    /// Ordinary [`AsyncWriteExt::shutdown`] only initiates the write-half close, matching
    /// `TcpStream::shutdown(Write)`. This stronger helper is useful when the caller needs
    /// transport-level confirmation before releasing durable state. It does not confirm
    /// application-level processing; protocols needing that must send an application ACK.
    pub async fn finish_and_wait(&mut self) -> io::Result<()> {
        self.shutdown().await?;
        match self.send.stopped().await {
            Ok(None) => Ok(()),
            Ok(Some(code)) => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("peer stopped virtual TCP write half with code {code}"),
            )),
            Err(error) => Err(io::Error::other(error)),
        }
    }
}

fn transport_paths(connection: &Connection) -> Vec<TransportPathStatus> {
    connection
        .paths()
        .iter()
        .map(|path| {
            let kind = if path.is_ip() {
                TransportPathKind::Direct
            } else if path.is_relay() {
                TransportPathKind::Relay
            } else {
                TransportPathKind::Other
            };
            let direct_scope = match path.remote_addr() {
                TransportAddr::Ip(address) => Some(if is_lan_ip(address.ip()) {
                    DirectPathScope::Lan
                } else {
                    DirectPathScope::Wan
                }),
                _ => None,
            };
            TransportPathStatus {
                kind,
                selected: path.is_selected(),
                direct_scope,
                rtt: path.rtt(),
            }
        })
        .collect()
}

fn is_lan_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_private()
                || address.is_link_local()
                || address.is_loopback()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        std::net::IpAddr::V6(address) => {
            address.is_loopback() || address.is_unique_local() || address.is_unicast_link_local()
        }
    }
}

impl std::fmt::Debug for VirtualTcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualTcpStream")
            .field("peer_endpoint_id", &self.peer_endpoint_id())
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

impl Connected for VirtualTcpStream {
    type ConnectInfo = PeerConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        PeerConnectInfo {
            endpoint_id: self.peer_endpoint_id(),
            virtual_addr: self.peer_addr,
        }
    }
}

impl AsyncRead for VirtualTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for VirtualTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.write_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "virtual TCP write half is shut down",
            )));
        }
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if self.write_shutdown {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                self.write_shutdown = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}
