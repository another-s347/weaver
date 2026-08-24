use std::{sync::Arc, time::Duration};

use iroh::{EndpointId, SecretKey};
use thiserror::Error;
use tokio::{sync::Mutex as AsyncMutex, task::JoinHandle};
use weaver_config::MemberEncryptionKeypair;
use weaver_core::{
    AppAddr, ClientAddr, NetworkId, ScopedVirtualAddr, ServerAddr, VirtualAddr, VirtualName,
};
use weaver_crypto::{NetworkRootPublic, SigningKeypair};
use weaver_discovery::{
    DiscoveryError, LanDiscoveryRuntime, MdnsLanDiscovery, PresenceDirectory,
    ProtectedLanDiscovery, WeaverAddressLookup, spawn_lan_discovery_runtime,
};
use weaver_store::{
    SecretId, SecretProtection, SecretStore, SecretStoreError, StateStore, StoreError,
};

use crate::{
    ConfigAuthorizationError, ConfigPeerDescriptor, ConfigStateError, ConfigSyncEvent,
    ConfigSyncOptions, ConfigSyncRuntime, ConfigSyncState, LiveConfigAuthorizer, LiveConfigState,
    MemberConfigSource, NetworkError, NodeConfig, PersistedConfigState, PresenceSyncOptions,
    PresenceSyncRuntime, VirtualTcpListener, VirtualTcpStream, VirtualUdpListener,
    VirtualUdpSocket, WeaverEndpoint, config_peer_descriptors, spawn_config_anti_entropy,
    spawn_live_presence_sync, udp_alpn,
};

#[derive(Clone)]
pub struct NetworkHandleOpenOptions {
    pub root: NetworkRootPublic,
    pub state_store: Arc<dyn StateStore>,
    pub secret_store: Arc<dyn SecretStore>,
    pub config_sync: ConfigSyncOptions,
    pub presence_sync: PresenceSyncOptions,
    /// Allows memory/test-only stores. Production callers should leave this false.
    pub allow_insecure_test_stores: bool,
}

impl std::fmt::Debug for NetworkHandleOpenOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkHandleOpenOptions")
            .field("network_id", &self.root.network_id())
            .field("state_capabilities", &self.state_store.capabilities())
            .field("secret_protection", &self.secret_store.protection())
            .field("config_sync", &self.config_sync)
            .field("presence_sync", &self.presence_sync)
            .field(
                "allow_insecure_test_stores",
                &self.allow_insecure_test_stores,
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalBinding {
    Server(ServerAddr),
    Client(ClientAddr),
}

pub struct NetworkHandle {
    network_id: NetworkId,
    endpoint: WeaverEndpoint,
    authorizer: Arc<LiveConfigAuthorizer>,
    config_state: Arc<AsyncMutex<LiveConfigState<Arc<dyn StateStore>>>>,
    directory: Arc<PresenceDirectory>,
    lan_runtime: Option<LanDiscoveryRuntime>,
    presence_runtime: Option<PresenceSyncRuntime>,
    config_runtime: Option<ConfigSyncRuntime>,
    config_change_task: Option<JoinHandle<()>>,
}

pub type VirtualNetwork = NetworkHandle;

impl std::fmt::Debug for NetworkHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkHandle")
            .field("network_id", &self.network_id)
            .field("endpoint_id", &self.endpoint.id())
            .field("local_addr", &self.endpoint.local_addr())
            .finish_non_exhaustive()
    }
}

impl NetworkHandle {
    pub async fn open_server(
        options: NetworkHandleOpenOptions,
        address: ServerAddr,
    ) -> Result<Self, NetworkHandleError> {
        Self::open(options, LocalBinding::Server(address)).await
    }

    pub async fn open_client(
        options: NetworkHandleOpenOptions,
        address: ClientAddr,
    ) -> Result<Self, NetworkHandleError> {
        Self::open(options, LocalBinding::Client(address)).await
    }

    pub async fn open(
        options: NetworkHandleOpenOptions,
        binding: LocalBinding,
    ) -> Result<Self, NetworkHandleError> {
        validate_store_capabilities(&options)?;
        let network_id = options.root.network_id();
        let endpoint_secret = open_secret_32(
            options.secret_store.as_ref(),
            member_secret_id(network_id, b"endpoint"),
        )
        .await?;
        let endpoint_secret = SecretKey::from_bytes(&endpoint_secret);
        let signing_secret = open_secret_32(
            options.secret_store.as_ref(),
            member_secret_id(network_id, b"member-signing"),
        )
        .await?;
        let signing = Arc::new(SigningKeypair::from_bytes(&signing_secret));
        let encryption_secret = open_secret_32(
            options.secret_store.as_ref(),
            member_secret_id(network_id, b"member-encryption"),
        )
        .await?;
        let encryption = MemberEncryptionKeypair::from_secret_bytes(encryption_secret)?;
        let persisted = PersistedConfigState::open(
            options.state_store.clone(),
            options.root,
            encryption,
            wall_now_ms(),
        )
        .await?;
        let config = Arc::new(persisted.config().clone());
        let authorizer = Arc::new(LiveConfigAuthorizer::new(
            config.clone(),
            endpoint_secret.public(),
        )?);
        let live_state = Arc::new(AsyncMutex::new(LiveConfigState::new(
            persisted,
            authorizer.clone(),
        )));
        let mut config_changes = live_state.lock().await.subscribe_config();
        let source = Arc::new(MemberConfigSource::new(live_state.clone()));
        let lookup = Arc::new(WeaverAddressLookup::new(network_id));

        let mut node = match binding {
            LocalBinding::Server(address) => {
                let mut node =
                    NodeConfig::tcp_server_from_config(endpoint_secret, &config, address.app())?;
                node.accept_alpns.push(udp_alpn(address.app()));
                node
            }
            LocalBinding::Client(address) => {
                let node = NodeConfig::client_from_config(endpoint_secret, &config, address.app())?;
                if node.local_addr != address.scoped() {
                    return Err(NetworkHandleError::ClientAddressMismatch);
                }
                node
            }
        };
        node = node
            .with_address_lookup(lookup.clone())
            .with_authorizer(authorizer.clone())
            .with_config_update_source(source, std::iter::empty());
        let endpoint = WeaverEndpoint::bind(node).await?;

        let protected = ProtectedLanDiscovery::from_config(&config)?;
        let mdns = MdnsLanDiscovery::spawn(
            protected,
            endpoint.id(),
            0,
            Vec::new(),
            wall_now_ms(),
            &tokio::runtime::Handle::current(),
        )?;
        let lan_runtime =
            spawn_lan_discovery_runtime(mdns, lookup.clone(), lookup.subscribe_publications());
        let lan_trigger = lan_runtime.trigger();
        let network_change_dialer = endpoint.dialer();
        let config_change_task = tokio::spawn(async move {
            config_changes.borrow_and_update();
            while config_changes.changed().await.is_ok() {
                let config = config_changes.borrow_and_update().clone();
                if let Ok(protected) = ProtectedLanDiscovery::from_config(&config) {
                    lan_trigger.update_protection(protected).await;
                    network_change_dialer.network_change().await;
                }
            }
        });
        let directory = Arc::new(PresenceDirectory::new(network_id, lookup.clone()));

        let presence_runtime = ConfigPeerDescriptor::first_presence_service(&config)
            .ok()
            .map(|target| {
                spawn_live_presence_sync(
                    endpoint.dialer(),
                    target,
                    authorizer.clone(),
                    signing,
                    directory.clone(),
                    lookup,
                    options.presence_sync,
                )
            });
        let targets = config_peer_descriptors(&config, endpoint.id());
        let config_runtime = (!targets.is_empty()).then(|| {
            spawn_config_anti_entropy(
                endpoint.dialer(),
                targets,
                live_state.clone(),
                options.config_sync,
            )
        });

        Ok(Self {
            network_id,
            endpoint,
            authorizer,
            config_state: live_state,
            directory,
            lan_runtime: Some(lan_runtime),
            presence_runtime,
            config_runtime,
            config_change_task: Some(config_change_task),
        })
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn local_addr(&self) -> ScopedVirtualAddr {
        self.endpoint.local_addr()
    }

    pub fn client_addr(&self) -> Option<ClientAddr> {
        match self.local_addr() {
            ScopedVirtualAddr::Client { app, device } => Some(ClientAddr::new(app, device)),
            ScopedVirtualAddr::Server { .. } => None,
        }
    }

    pub fn take_tcp_listener(&mut self) -> Result<VirtualTcpListener, NetworkHandleError> {
        Ok(self.endpoint.take_tcp_listener()?)
    }

    pub fn take_udp_listener(&mut self) -> Result<VirtualUdpListener, NetworkHandleError> {
        Ok(self.endpoint.take_udp_listener()?)
    }

    pub async fn connect_tcp(
        &self,
        target: VirtualAddr,
    ) -> Result<VirtualTcpStream, NetworkHandleError> {
        let app = self.validate_server_target(target)?;
        let endpoint_id = self.resolve_configured_server(app)?;
        Ok(self
            .endpoint
            .dialer()
            .connect(&crate::PeerDescriptor {
                network_id: self.network_id,
                app_addr: app,
                endpoint_id,
                relay_url: None,
                direct_addresses: Vec::new(),
            })
            .await?)
    }

    /// Resolves a signed, network-scoped virtual DNS name without consulting system DNS.
    pub fn resolve_name(&self, name: &VirtualName) -> Result<ServerAddr, NetworkHandleError> {
        self.authorizer
            .config()
            .resolve_virtual_name(name, wall_now_ms())
            .map(ServerAddr::new)
            .ok_or_else(|| NetworkHandleError::UnknownVirtualName(name.clone()))
    }

    pub async fn connect_tcp_name(
        &self,
        name: &VirtualName,
    ) -> Result<VirtualTcpStream, NetworkHandleError> {
        let address = self.resolve_name(name)?;
        self.connect_tcp(VirtualAddr::server(self.network_id, address))
            .await
    }

    pub async fn connect_udp(
        &self,
        target: VirtualAddr,
    ) -> Result<VirtualUdpSocket, NetworkHandleError> {
        let app = self.validate_server_target(target)?;
        let endpoint_id = self.resolve_configured_server(app)?;
        Ok(self
            .endpoint
            .connect_udp(&crate::PeerDescriptor {
                network_id: self.network_id,
                app_addr: app,
                endpoint_id,
                relay_url: None,
                direct_addresses: Vec::new(),
            })
            .await?)
    }

    pub async fn connect_udp_name(
        &self,
        name: &VirtualName,
    ) -> Result<VirtualUdpSocket, NetworkHandleError> {
        let address = self.resolve_name(name)?;
        self.connect_udp(VirtualAddr::server(self.network_id, address))
            .await
    }

    pub async fn network_change(&self) {
        self.endpoint.network_change().await;
        if let Some(runtime) = &self.lan_runtime {
            runtime.trigger().network_change();
        }
        if let Some(runtime) = &self.presence_runtime {
            let _ = runtime.trigger();
        }
        if let Some(runtime) = &self.config_runtime {
            let _ = runtime.trigger();
        }
    }

    pub async fn next_config_event(&mut self) -> Option<ConfigSyncEvent> {
        match &mut self.config_runtime {
            Some(runtime) => runtime.next_event().await,
            None => None,
        }
    }

    pub async fn config_head(&self) -> weaver_config::ConfigHead {
        self.config_state.lock().await.head()
    }

    /// Validates and atomically applies an externally delivered authority update chain.
    /// Background anti-entropy uses the same state machine.
    pub async fn apply_config_updates(
        &self,
        updates: &weaver_config::ConfigUpdateBatch,
    ) -> Result<weaver_config::ConfigHead, NetworkHandleError> {
        self.config_state
            .lock()
            .await
            .apply_updates(updates, wall_now_ms())
            .await
            .map_err(NetworkHandleError::ConfigSync)
    }

    pub async fn close(mut self) {
        if let Some(task) = self.config_change_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(runtime) = self.config_runtime.take() {
            runtime.shutdown().await;
        }
        if let Some(runtime) = self.presence_runtime.take() {
            runtime.shutdown().await;
        }
        if let Some(runtime) = self.lan_runtime.take() {
            runtime.shutdown().await;
        }
        self.endpoint.close().await;
    }

    fn validate_server_target(&self, target: VirtualAddr) -> Result<AppAddr, NetworkHandleError> {
        if target.network != self.network_id {
            return Err(NetworkHandleError::NetworkMismatch {
                local: self.network_id,
                target: target.network,
            });
        }
        match target.addr {
            ScopedVirtualAddr::Server { app } => Ok(app),
            ScopedVirtualAddr::Client { .. } => Err(NetworkHandleError::TargetMustBeServer),
        }
    }

    fn resolve_configured_server(&self, app: AppAddr) -> Result<EndpointId, NetworkHandleError> {
        if let Some(endpoint) = self
            .directory
            .resolve(ScopedVirtualAddr::Server { app }, wall_now_ms())
        {
            return Ok(endpoint);
        }
        Ok(self.directory.configured_endpoint(
            &self.authorizer.config(),
            ScopedVirtualAddr::Server { app },
            wall_now_ms(),
        )?)
    }
}

pub fn member_secret_id(network_id: NetworkId, label: &[u8]) -> SecretId {
    let mut hasher = blake3::Hasher::new_derive_key("weaver.member.secret-id.v1");
    hasher.update(network_id.as_bytes());
    hasher.update(label);
    SecretId::from_bytes(*hasher.finalize().as_bytes())
}

async fn open_secret_32(
    store: &dyn SecretStore,
    id: SecretId,
) -> Result<[u8; 32], NetworkHandleError> {
    store
        .open(&id)
        .await?
        .expose()
        .try_into()
        .map_err(|_| NetworkHandleError::CorruptSecret)
}

fn validate_store_capabilities(
    options: &NetworkHandleOpenOptions,
) -> Result<(), NetworkHandleError> {
    let state = options.state_store.capabilities();
    if !state.atomic_batches
        || (!state.durable_commits && !options.allow_insecure_test_stores)
        || (options.secret_store.protection() == SecretProtection::InMemoryTestOnly
            && !options.allow_insecure_test_stores)
    {
        return Err(NetworkHandleError::InsecureStoreCapabilities);
    }
    Ok(())
}

fn wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[derive(Debug, Error)]
pub enum NetworkHandleError {
    #[error("state/secret stores do not provide required production capabilities")]
    InsecureStoreCapabilities,
    #[error("stored member secret is corrupt")]
    CorruptSecret,
    #[error("target belongs to network {target}, but this handle is bound to {local}")]
    NetworkMismatch { local: NetworkId, target: NetworkId },
    #[error("this operation requires a virtual server target")]
    TargetMustBeServer,
    #[error("requested client address does not match the authorized device binding")]
    ClientAddressMismatch,
    #[error("virtual DNS name is unknown or expired in this network: {0}")]
    UnknownVirtualName(VirtualName),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Secret(#[from] SecretStoreError),
    #[error(transparent)]
    ConfigState(#[from] ConfigStateError),
    #[error(transparent)]
    Config(#[from] weaver_config::ConfigError),
    #[error(transparent)]
    Authorization(#[from] ConfigAuthorizationError),
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error(transparent)]
    Network(#[from] NetworkError),
    #[error("configuration synchronization failed: {0}")]
    ConfigSync(crate::BoxError),
}
