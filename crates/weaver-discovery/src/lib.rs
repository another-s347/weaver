//! Network-private discovery records and protected LAN tags.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Mutex,
};

use bytes::Bytes;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use iroh::{
    EndpointId, RelayUrl, TransportAddr,
    address_lookup::{
        AddressLookup, EndpointData, EndpointInfo, Error as AddressLookupError, Item,
    },
};
use n0_future::boxed::BoxStream;
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use thiserror::Error;
use tokio::{
    sync::{broadcast, mpsc, oneshot, watch},
    task::JoinHandle,
};
use tokio_stream::{StreamExt, wrappers::WatchStream};
use weaver_config::ValidatedNetworkConfig;
use weaver_core::{AppAddr, DeviceId, MemberId, NetworkId, ScopedVirtualAddr};
use weaver_crypto::{AppBinding, AppRole, EndpointBinding, MemberCertificate, SigningKeypair};

pub const MDNS_SERVICE_TYPE: &str = "_weaver._udp.local";
pub const LAN_SLOT_MS: u64 = 5 * 60 * 1_000;
pub const DEFAULT_PRESENCE_TTL_MS: u64 = 120 * 1_000;
pub const MAX_PRESENCE_TTL_MS: u64 = 5 * 60 * 1_000;
const PRESENCE_MAGIC: &[u8; 8] = b"WVRPRS\0\x02";
const PRESENCE_PAYLOAD_MAGIC: &[u8; 8] = b"WVRPRP\0\x02";
const TAG_LEN: usize = 16;
const OPAQUE_KEY_LEN: usize = 24;
const NONCE_LEN: usize = 24;
const SIGNATURE_LEN: usize = 64;
const MAX_CANDIDATES: usize = 16;
const MAX_VIRTUAL_ADDRS: usize = 256;
const MAX_RELAY_URL_LEN: usize = 2048;
const MAX_PRESENCE_WIRE: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LanTag([u8; TAG_LEN]);

impl LanTag {
    pub fn from_bytes(bytes: [u8; TAG_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; TAG_LEN] {
        &self.0
    }

    pub fn txt_value(&self) -> String {
        let mut value = String::with_capacity(2 + TAG_LEN * 2);
        value.push_str("t=");
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
        }
        value
    }

    pub fn from_txt(value: &str) -> Result<Self, DiscoveryError> {
        let hex = value
            .strip_prefix("t=")
            .ok_or(DiscoveryError::MalformedTag)?;
        if hex.len() != TAG_LEN * 2 {
            return Err(DiscoveryError::MalformedTag);
        }
        let mut bytes = [0_u8; TAG_LEN];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(pair).map_err(|_| DiscoveryError::MalformedTag)?;
            bytes[index] =
                u8::from_str_radix(pair, 16).map_err(|_| DiscoveryError::MalformedTag)?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug)]
pub struct ProtectedLanDiscovery {
    network_id: NetworkId,
    epoch: u64,
    seed: [u8; 32],
    known_endpoints: Vec<EndpointId>,
}

impl ProtectedLanDiscovery {
    pub fn from_config(config: &ValidatedNetworkConfig) -> Result<Self, DiscoveryError> {
        let snapshot = config.as_config();
        let seed = snapshot.epoch_secrets.expose_bytes()[2];
        let mut known_endpoints = Vec::with_capacity(snapshot.endpoint_bindings.len());
        for raw in &snapshot.endpoint_bindings {
            let binding = EndpointBinding::from_bytes(raw)?;
            known_endpoints.push(
                EndpointId::from_bytes(&binding.payload().endpoint_id)
                    .map_err(|_| DiscoveryError::MalformedEndpoint)?,
            );
        }
        Ok(Self {
            network_id: snapshot.network_id,
            epoch: snapshot.epoch,
            seed,
            known_endpoints,
        })
    }

    pub fn tag_for(&self, endpoint: EndpointId, now_ms: u64) -> LanTag {
        self.tag_for_slot(endpoint, now_ms / LAN_SLOT_MS)
    }

    pub fn txt_records(&self, endpoint: EndpointId, now_ms: u64) -> [String; 2] {
        ["v=1".to_owned(), self.tag_for(endpoint, now_ms).txt_value()]
    }

    pub fn match_tag(&self, tag: LanTag, now_ms: u64) -> Option<EndpointId> {
        let current = now_ms / LAN_SLOT_MS;
        let slots = [
            current.saturating_sub(1),
            current,
            current.saturating_add(1),
        ];
        self.known_endpoints.iter().copied().find(|endpoint| {
            slots
                .iter()
                .any(|slot| self.tag_for_slot(*endpoint, *slot) == tag)
        })
    }

    fn tag_for_slot(&self, endpoint: EndpointId, slot: u64) -> LanTag {
        let mut hasher = blake3::Hasher::new_keyed(&self.seed);
        hasher.update(b"weaver.lan-tag.v1\0");
        hasher.update(self.network_id.as_bytes());
        hasher.update(&self.epoch.to_be_bytes());
        hasher.update(&slot.to_be_bytes());
        hasher.update(endpoint.as_bytes());
        let mut tag = [0_u8; TAG_LEN];
        tag.copy_from_slice(&hasher.finalize().as_bytes()[..TAG_LEN]);
        LanTag(tag)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanObservation {
    pub endpoint_id: EndpointId,
    pub addresses: Vec<SocketAddr>,
    pub expired: bool,
}

/// A real `_weaver._udp.local` mDNS publisher/browser whose public instance ID is only
/// the rotating network-private tag. EndpointId and virtual addresses are never placed
/// in DNS names or TXT records.
pub struct MdnsLanDiscovery {
    protected: ProtectedLanDiscovery,
    local_endpoint: EndpointId,
    port: u16,
    addresses: Vec<IpAddr>,
    slot: u64,
    sender: mpsc::Sender<LanObservation>,
    receiver: mpsc::Receiver<LanObservation>,
    guard: DropGuard,
}

impl std::fmt::Debug for MdnsLanDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdnsLanDiscovery")
            .field("network_id", &self.protected.network_id)
            .field("local_endpoint", &self.local_endpoint)
            .field("port", &self.port)
            .field("addresses", &self.addresses)
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

impl MdnsLanDiscovery {
    pub fn spawn(
        protected: ProtectedLanDiscovery,
        local_endpoint: EndpointId,
        port: u16,
        addresses: Vec<IpAddr>,
        now_ms: u64,
        runtime: &tokio::runtime::Handle,
    ) -> Result<Self, DiscoveryError> {
        let (sender, receiver) = mpsc::channel(128);
        let slot = now_ms / LAN_SLOT_MS;
        let guard = spawn_mdns_guard(
            &protected,
            local_endpoint,
            port,
            &addresses,
            now_ms,
            sender.clone(),
            runtime,
        )?;
        Ok(Self {
            protected,
            local_endpoint,
            port,
            addresses,
            slot,
            sender,
            receiver,
            guard,
        })
    }

    pub async fn recv(&mut self) -> Option<LanObservation> {
        self.receiver.recv().await
    }

    /// Rotates the public tag at the five-minute boundary using make-before-break.
    pub fn refresh_tag(
        &mut self,
        now_ms: u64,
        runtime: &tokio::runtime::Handle,
    ) -> Result<bool, DiscoveryError> {
        let slot = now_ms / LAN_SLOT_MS;
        if slot == self.slot {
            return Ok(false);
        }
        let next = spawn_mdns_guard(
            &self.protected,
            self.local_endpoint,
            self.port,
            &self.addresses,
            now_ms,
            self.sender.clone(),
            runtime,
        )?;
        self.guard = next;
        self.slot = slot;
        Ok(true)
    }

    /// Replaces advertised interface addresses after a platform network-change callback.
    pub fn replace_addresses(&mut self, port: u16, addresses: Vec<IpAddr>) {
        self.guard.remove_all();
        self.guard.add(port, addresses.clone());
        self.port = port;
        self.addresses = addresses;
    }

    /// Recreates the publisher/browser after an interface-set change. This is required on
    /// platforms where an mDNS socket does not automatically join multicast on interfaces
    /// created after the original discoverer was spawned.
    pub fn rebind_addresses(
        &mut self,
        port: u16,
        addresses: Vec<IpAddr>,
        now_ms: u64,
        runtime: &tokio::runtime::Handle,
    ) -> Result<(), DiscoveryError> {
        let next = spawn_mdns_guard(
            &self.protected,
            self.local_endpoint,
            port,
            &addresses,
            now_ms,
            self.sender.clone(),
            runtime,
        )?;
        self.guard = next;
        self.port = port;
        self.addresses = addresses;
        self.slot = now_ms / LAN_SLOT_MS;
        Ok(())
    }

    /// Atomically rotates to a newly validated network epoch/member set.
    pub fn replace_protection(
        &mut self,
        protected: ProtectedLanDiscovery,
        now_ms: u64,
        runtime: &tokio::runtime::Handle,
    ) -> Result<(), DiscoveryError> {
        if protected.network_id != self.protected.network_id {
            return Err(DiscoveryError::WrongNetwork);
        }
        let next = spawn_mdns_guard(
            &protected,
            self.local_endpoint,
            self.port,
            &self.addresses,
            now_ms,
            self.sender.clone(),
            runtime,
        )?;
        self.guard = next;
        self.protected = protected;
        self.slot = now_ms / LAN_SLOT_MS;
        Ok(())
    }
}

/// Background bridge from protected mDNS observations/publications to the live iroh lookup.
pub struct LanDiscoveryRuntime {
    refresh: mpsc::Sender<LanDiscoveryCommand>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for LanDiscoveryRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanDiscoveryRuntime")
            .finish_non_exhaustive()
    }
}

impl LanDiscoveryRuntime {
    pub fn trigger(&self) -> LanDiscoveryTrigger {
        LanDiscoveryTrigger {
            refresh: self.refresh.clone(),
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(std::time::Duration::from_secs(1), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}

#[derive(Clone, Debug)]
pub struct LanDiscoveryTrigger {
    refresh: mpsc::Sender<LanDiscoveryCommand>,
}

#[derive(Debug)]
enum LanDiscoveryCommand {
    NetworkChange,
    UpdateProtection(ProtectedLanDiscovery),
}

impl LanDiscoveryTrigger {
    /// Coalesces platform network callbacks and rebuilds mDNS over the current interfaces.
    pub fn network_change(&self) {
        let _ = self.refresh.try_send(LanDiscoveryCommand::NetworkChange);
    }

    pub async fn update_protection(&self, protected: ProtectedLanDiscovery) {
        let _ = self
            .refresh
            .send(LanDiscoveryCommand::UpdateProtection(protected))
            .await;
    }
}

impl Drop for LanDiscoveryRuntime {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Starts automatic mDNS-to-iroh updates, local address republishing and tag rotation.
/// Platform network callbacks should call `WeaverEndpoint::network_change`; the resulting
/// iroh publication is consumed here and replaces the addresses advertised over mDNS.
pub fn spawn_lan_discovery_runtime(
    mut mdns: MdnsLanDiscovery,
    lookup: std::sync::Arc<WeaverAddressLookup>,
    mut publications: watch::Receiver<Option<EndpointData>>,
) -> LanDiscoveryRuntime {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let (refresh_tx, mut refresh_rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        if let Some(data) = publications.borrow_and_update().clone() {
            let _ = update_mdns_addresses(&mut mdns, &data);
        }
        let mut rotation = tokio::time::interval(std::time::Duration::from_secs(30));
        rotation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                observation = mdns.recv() => {
                    let Some(observation) = observation else { break };
                    lookup.apply_lan_observation(observation);
                }
                changed = publications.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    if let Some(data) = publications.borrow_and_update().clone() {
                        let _ = update_mdns_addresses(&mut mdns, &data);
                    }
                }
                command = refresh_rx.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    match command {
                        LanDiscoveryCommand::NetworkChange => {
                            // Debounce bursts from capabilities/link/address callbacks and let the
                            // kernel finish assigning addresses before taking the interface snapshot.
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            let addresses = current_interface_addresses();
                            if !addresses.is_empty() {
                                let _ = mdns.rebind_addresses(
                                    mdns.port,
                                    addresses,
                                    wall_now_ms(),
                                    &tokio::runtime::Handle::current(),
                                );
                            }
                        }
                        LanDiscoveryCommand::UpdateProtection(protected) => {
                            let _ = mdns.replace_protection(
                                protected,
                                wall_now_ms(),
                                &tokio::runtime::Handle::current(),
                            );
                        }
                    }
                }
                _ = rotation.tick() => {
                    let _ = mdns.refresh_tag(wall_now_ms(), &tokio::runtime::Handle::current());
                }
            }
        }
    });
    LanDiscoveryRuntime {
        refresh: refresh_tx,
        shutdown: Some(shutdown_tx),
        task: Some(task),
    }
}

fn current_interface_addresses() -> Vec<IpAddr> {
    let mut addresses = netdev::get_interfaces()
        .into_iter()
        .filter(|interface| interface.is_up() && !interface.is_loopback())
        .flat_map(|interface| interface.ip_addrs())
        .filter(|address| !address.is_unspecified() && !address.is_multicast())
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

fn update_mdns_addresses(
    mdns: &mut MdnsLanDiscovery,
    data: &EndpointData,
) -> Result<(), DiscoveryError> {
    let mut addresses = data.ip_addrs().copied();
    let Some(first) = addresses.next() else {
        return Ok(());
    };
    let port = first.port();
    let mut ips = vec![first.ip()];
    ips.extend(
        addresses
            .filter(|address| address.port() == port)
            .map(|address| address.ip()),
    );
    ips.sort_unstable();
    ips.dedup();
    mdns.rebind_addresses(port, ips, wall_now_ms(), &tokio::runtime::Handle::current())
}

fn spawn_mdns_guard(
    protected: &ProtectedLanDiscovery,
    local_endpoint: EndpointId,
    port: u16,
    addresses: &[IpAddr],
    now_ms: u64,
    sender: mpsc::Sender<LanObservation>,
    runtime: &tokio::runtime::Handle,
) -> Result<DropGuard, DiscoveryError> {
    let tag = protected.tag_for(local_endpoint, now_ms);
    let peer_id = tag_hex(tag);
    let expected_peer_id = peer_id.clone();
    let protected = protected.clone();
    let multicast_interfaces = addresses
        .iter()
        .filter_map(|address| match address {
            IpAddr::V4(address) => Some(*address),
            IpAddr::V6(_) => None,
        })
        .collect();
    let discoverer = Discoverer::new_interactive("weaver".to_owned(), peer_id)
        .with_ip_class(IpClass::Auto)
        .with_multicast_interfaces_v4(multicast_interfaces)
        .with_addrs(port, addresses.iter().copied())
        .with_txt_attributes([
            ("v".to_owned(), Some("1".to_owned())),
            ("t".to_owned(), Some(tag.txt_value()[2..].to_owned())),
        ])
        .map_err(|error| DiscoveryError::Backend(error.to_string()))?
        .with_callback(move |peer_id, peer| {
            if peer_id == expected_peer_id {
                return;
            }
            if let Some(observation) =
                protected_observation(&protected, peer_id, peer, wall_now_ms())
            {
                let _ = sender.try_send(observation);
            }
        });
    discoverer
        .spawn(runtime)
        .map_err(|error| DiscoveryError::Backend(error.to_string()))
}

fn protected_observation(
    protected: &ProtectedLanDiscovery,
    peer_id: &str,
    peer: &Peer,
    now_ms: u64,
) -> Option<LanObservation> {
    if peer.txt_attribute("v") != Some(Some("1")) || peer.txt_attribute("t").flatten()? != peer_id {
        return None;
    }
    let tag = LanTag::from_txt(&format!("t={peer_id}")).ok()?;
    let endpoint_id = protected.match_tag(tag, now_ms)?;
    let addresses = peer
        .addrs()
        .iter()
        .map(|(ip, port)| SocketAddr::new(*ip, *port))
        .collect();
    Some(LanObservation {
        endpoint_id,
        addresses,
        expired: peer.is_expiry(),
    })
}

fn tag_hex(tag: LanTag) -> String {
    tag.txt_value()[2..].to_owned()
}

fn wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn wall_now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

const WEAVER_LOOKUP_PROVENANCE: &str = "weaver_private_discovery";

#[derive(Debug)]
struct LookupEntry {
    lan: Option<Vec<SocketAddr>>,
    presence: Option<Vec<TransportAddr>>,
    sender: watch::Sender<Option<EndpointData>>,
}

impl LookupEntry {
    fn new() -> Self {
        let (sender, _) = watch::channel(None);
        Self {
            lan: None,
            presence: None,
            sender,
        }
    }

    fn publish_merged(&self) {
        let transports = self
            .lan
            .iter()
            .flatten()
            .copied()
            .map(TransportAddr::Ip)
            .chain(self.presence.iter().flatten().cloned())
            .collect::<Vec<_>>();
        let data = (!transports.is_empty()).then(|| EndpointData::new(transports));
        self.sender.send_replace(data);
    }
}

/// A network-scoped, live iroh address lookup.
///
/// Unlike iroh's one-shot memory lookup, a resolver subscription is created even before
/// candidates exist and remains open for later mDNS or encrypted-presence updates. Create
/// one instance per [`NetworkId`]; updates from another network are rejected.
#[derive(Debug)]
pub struct WeaverAddressLookup {
    network_id: NetworkId,
    entries: Mutex<HashMap<EndpointId, LookupEntry>>,
    publications: watch::Sender<Option<EndpointData>>,
    updates: broadcast::Sender<AddressLookupUpdate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressLookupSource {
    ProtectedLan,
    EncryptedPresence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressLookupUpdate {
    pub endpoint_id: EndpointId,
    pub source: AddressLookupSource,
    pub expired: bool,
    pub candidate_count: usize,
}

impl WeaverAddressLookup {
    pub fn new(network_id: NetworkId) -> Self {
        let (publications, _) = watch::channel(None);
        let (updates, _) = broadcast::channel(128);
        Self {
            network_id,
            entries: Mutex::new(HashMap::new()),
            publications,
            updates,
        }
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Subscribes to the local endpoint addresses iroh wants discovery backends to publish.
    pub fn subscribe_publications(&self) -> watch::Receiver<Option<EndpointData>> {
        self.publications.subscribe()
    }

    pub fn subscribe_updates(&self) -> broadcast::Receiver<AddressLookupUpdate> {
        self.updates.subscribe()
    }

    /// Applies a protected mDNS result. Expiry removes only LAN candidates, retaining any
    /// independently authenticated relay/presence candidates.
    pub fn apply_lan_observation(&self, observation: LanObservation) {
        let update = AddressLookupUpdate {
            endpoint_id: observation.endpoint_id,
            source: AddressLookupSource::ProtectedLan,
            expired: observation.expired,
            candidate_count: observation.addresses.len(),
        };
        let mut entries = self.entries.lock().expect("lookup mutex poisoned");
        let entry = entries
            .entry(observation.endpoint_id)
            .or_insert_with(LookupEntry::new);
        entry.lan = if observation.expired || observation.addresses.is_empty() {
            None
        } else {
            Some(observation.addresses)
        };
        entry.publish_merged();
        let _ = self.updates.send(update);
    }

    /// Applies an already decrypted, authenticated and replay-checked presence record.
    pub fn apply_presence(&self, record: &PresenceRecord) -> Result<(), DiscoveryError> {
        if record.network_id != self.network_id {
            return Err(DiscoveryError::WrongNetwork);
        }
        let transports = record
            .candidates
            .iter()
            .map(|candidate| match candidate {
                DiscoveryCandidate::Ip(address) => Ok(TransportAddr::Ip(*address)),
                DiscoveryCandidate::Relay(url) => url
                    .parse::<RelayUrl>()
                    .map(TransportAddr::Relay)
                    .map_err(|_| DiscoveryError::InvalidPresence),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut entries = self.entries.lock().expect("lookup mutex poisoned");
        let entry = entries
            .entry(record.endpoint_id)
            .or_insert_with(LookupEntry::new);
        entry.presence = (!transports.is_empty()).then_some(transports);
        entry.publish_merged();
        let _ = self.updates.send(AddressLookupUpdate {
            endpoint_id: record.endpoint_id,
            source: AddressLookupSource::EncryptedPresence,
            expired: false,
            candidate_count: record.candidates.len(),
        });
        Ok(())
    }

    pub fn clear_presence(&self, endpoint_id: EndpointId) {
        let mut entries = self.entries.lock().expect("lookup mutex poisoned");
        if let Some(entry) = entries.get_mut(&endpoint_id) {
            entry.presence = None;
            entry.publish_merged();
            let _ = self.updates.send(AddressLookupUpdate {
                endpoint_id,
                source: AddressLookupSource::EncryptedPresence,
                expired: true,
                candidate_count: 0,
            });
        }
    }
}

impl AddressLookup for WeaverAddressLookup {
    fn publish(&self, data: &EndpointData) {
        self.publications.send_replace(Some(data.clone()));
    }

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<Item, AddressLookupError>>> {
        let receiver = {
            let mut entries = self.entries.lock().expect("lookup mutex poisoned");
            entries
                .entry(endpoint_id)
                .or_insert_with(LookupEntry::new)
                .sender
                .subscribe()
        };
        let stream = WatchStream::new(receiver).filter_map(move |data| {
            data.map(|data| {
                Ok(Item::new(
                    EndpointInfo::from_parts(endpoint_id, data),
                    WEAVER_LOOKUP_PROVENANCE,
                    Some(wall_now_us()),
                ))
            })
        });
        Some(Box::pin(stream))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryCandidate {
    Ip(SocketAddr),
    Relay(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceRecord {
    pub network_id: NetworkId,
    pub epoch: u64,
    pub virtual_addrs: Vec<ScopedVirtualAddr>,
    pub member_id: MemberId,
    pub endpoint_id: EndpointId,
    pub candidates: Vec<DiscoveryCandidate>,
    pub capabilities: u32,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedPresenceRecord {
    pub epoch: u64,
    pub opaque_key: [u8; OPAQUE_KEY_LEN],
    pub nonce: [u8; NONCE_LEN],
    ciphertext: Bytes,
}

impl EncryptedPresenceRecord {
    /// Returns the network-private directory key used to look up one endpoint without
    /// revealing its EndpointId or virtual address to the directory service.
    pub fn lookup_key(
        config: &ValidatedNetworkConfig,
        endpoint_id: EndpointId,
    ) -> (u64, [u8; OPAQUE_KEY_LEN]) {
        let snapshot = config.as_config();
        let seeds = snapshot.epoch_secrets.expose_bytes();
        (snapshot.epoch, derive_opaque_key(&seeds[0], endpoint_id))
    }

    pub fn opaque_key(&self) -> [u8; OPAQUE_KEY_LEN] {
        self.opaque_key
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        config: &ValidatedNetworkConfig,
        signing: &SigningKeypair,
        endpoint_id: EndpointId,
        virtual_addrs: Vec<ScopedVirtualAddr>,
        candidates: Vec<DiscoveryCandidate>,
        capabilities: u32,
        sequence: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, DiscoveryError> {
        let snapshot = config.as_config();
        if expires_at_ms <= issued_at_ms
            || expires_at_ms - issued_at_ms > MAX_PRESENCE_TTL_MS
            || expires_at_ms > snapshot.expires_at_ms
            || candidates.len() > MAX_CANDIDATES
            || virtual_addrs.is_empty()
            || virtual_addrs.len() > MAX_VIRTUAL_ADDRS
        {
            return Err(DiscoveryError::InvalidPresence);
        }
        validate_candidates(&candidates)?;
        let member = member_for_signer(config, signing.public_bytes())?;
        let unique_addrs = virtual_addrs
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        if unique_addrs.len() != virtual_addrs.len() {
            return Err(DiscoveryError::InvalidPresence);
        }
        for virtual_addr in &virtual_addrs {
            authorize_endpoint_and_addr(
                config,
                member.payload().member_id,
                endpoint_id,
                *virtual_addr,
                issued_at_ms,
            )?;
        }
        let record = PresenceRecord {
            network_id: snapshot.network_id,
            epoch: snapshot.epoch,
            virtual_addrs,
            member_id: member.payload().member_id,
            endpoint_id,
            candidates,
            capabilities,
            sequence,
            issued_at_ms,
            expires_at_ms,
        };
        let payload = encode_presence_payload(&record)?;
        let signature = signing.sign_presence(&payload);
        let mut plaintext = payload;
        plaintext.extend_from_slice(&signature);
        let seeds = snapshot.epoch_secrets.expose_bytes();
        let opaque_key = derive_opaque_key(&seeds[0], endpoint_id);
        let key = derive_presence_key(&seeds[1], snapshot.epoch, &opaque_key);
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| DiscoveryError::RandomnessUnavailable)?;
        let aad = presence_aad(snapshot.epoch, &opaque_key, &nonce);
        let xnonce = XNonce::from(nonce);
        let ciphertext = XChaCha20Poly1305::new((&key).into())
            .encrypt(
                &xnonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| DiscoveryError::EncryptionFailed)?;
        Ok(Self {
            epoch: snapshot.epoch,
            opaque_key,
            nonce,
            ciphertext: Bytes::from(ciphertext),
        })
    }

    pub fn to_bytes(&self) -> Result<Bytes, DiscoveryError> {
        if self.ciphertext.len() > MAX_PRESENCE_WIRE {
            return Err(DiscoveryError::PresenceTooLarge);
        }
        let mut out =
            Vec::with_capacity(8 + 8 + OPAQUE_KEY_LEN + NONCE_LEN + 4 + self.ciphertext.len());
        out.extend_from_slice(PRESENCE_MAGIC);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.opaque_key);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(Bytes::from(out))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DiscoveryError> {
        if bytes.len() > MAX_PRESENCE_WIRE {
            return Err(DiscoveryError::PresenceTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        decoder.magic(PRESENCE_MAGIC)?;
        let epoch = decoder.u64()?;
        let opaque_key = decoder.array()?;
        let nonce = decoder.array()?;
        let len = decoder.u32()? as usize;
        let ciphertext = Bytes::copy_from_slice(decoder.take(len)?);
        decoder.finish()?;
        Ok(Self {
            epoch,
            opaque_key,
            nonce,
            ciphertext,
        })
    }

    pub fn open(
        &self,
        config: &ValidatedNetworkConfig,
        now_ms: u64,
    ) -> Result<PresenceRecord, DiscoveryError> {
        let snapshot = config.as_config();
        if self.epoch != snapshot.epoch {
            return Err(DiscoveryError::WrongEpoch);
        }
        let seeds = snapshot.epoch_secrets.expose_bytes();
        let key = derive_presence_key(&seeds[1], self.epoch, &self.opaque_key);
        let aad = presence_aad(self.epoch, &self.opaque_key, &self.nonce);
        let xnonce = XNonce::from(self.nonce);
        let plaintext = XChaCha20Poly1305::new((&key).into())
            .decrypt(
                &xnonce,
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| DiscoveryError::DecryptionFailed)?;
        if plaintext.len() < SIGNATURE_LEN {
            return Err(DiscoveryError::MalformedWire);
        }
        let payload_len = plaintext.len() - SIGNATURE_LEN;
        let signature: [u8; SIGNATURE_LEN] = plaintext[payload_len..]
            .try_into()
            .map_err(|_| DiscoveryError::MalformedWire)?;
        let payload = &plaintext[..payload_len];
        let record = decode_presence_payload(payload)?;
        if record.network_id != snapshot.network_id
            || record.epoch != snapshot.epoch
            || record.issued_at_ms > now_ms
            || record.expires_at_ms <= now_ms
            || record.expires_at_ms - record.issued_at_ms > MAX_PRESENCE_TTL_MS
            || derive_opaque_key(&seeds[0], record.endpoint_id) != self.opaque_key
        {
            return Err(DiscoveryError::InvalidPresence);
        }
        let member = member_by_id(config, record.member_id)?;
        if member.payload().not_before_ms > now_ms
            || member.payload().expires_at_ms <= now_ms
            || snapshot.revoked_serials.contains(&member.payload().serial)
        {
            return Err(DiscoveryError::InvalidPresence);
        }
        member.verify_presence(payload, &signature)?;
        if record.virtual_addrs.is_empty() || record.virtual_addrs.len() > MAX_VIRTUAL_ADDRS {
            return Err(DiscoveryError::InvalidPresence);
        }
        let unique_addrs = record
            .virtual_addrs
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        if unique_addrs.len() != record.virtual_addrs.len() {
            return Err(DiscoveryError::InvalidPresence);
        }
        for virtual_addr in &record.virtual_addrs {
            authorize_endpoint_and_addr(
                config,
                record.member_id,
                record.endpoint_id,
                *virtual_addr,
                now_ms,
            )?;
        }
        validate_candidates(&record.candidates)?;
        Ok(record)
    }
}

#[derive(Default, Debug)]
pub struct PresenceCache {
    records: HashMap<(NetworkId, ScopedVirtualAddr), PresenceRecord>,
    endpoint_records: HashMap<(NetworkId, EndpointId), PresenceRecord>,
}

impl PresenceCache {
    pub fn apply(&mut self, record: PresenceRecord) -> Result<bool, DiscoveryError> {
        let endpoint_key = (record.network_id, record.endpoint_id);
        if let Some(current) = self.endpoint_records.get(&endpoint_key) {
            if record.sequence < current.sequence
                || (record.sequence == current.sequence && record != *current)
            {
                return Err(DiscoveryError::Rollback);
            }
            if record == *current {
                return Ok(false);
            }
        }
        if record.virtual_addrs.iter().any(|address| {
            self.records
                .get(&(record.network_id, *address))
                .is_some_and(|current| current.endpoint_id != record.endpoint_id)
        }) {
            return Err(DiscoveryError::InvalidPresence);
        }
        if let Some(previous) = self.endpoint_records.insert(endpoint_key, record.clone()) {
            for address in previous.virtual_addrs {
                self.records.remove(&(previous.network_id, address));
            }
        }
        for address in &record.virtual_addrs {
            self.records
                .insert((record.network_id, *address), record.clone());
        }
        Ok(true)
    }

    pub fn get(
        &self,
        network_id: NetworkId,
        virtual_addr: ScopedVirtualAddr,
        now_ms: u64,
    ) -> Option<&PresenceRecord> {
        self.records
            .get(&(network_id, virtual_addr))
            .filter(|record| record.expires_at_ms > now_ms)
    }

    pub fn purge_expired(&mut self, now_ms: u64) -> Vec<EndpointId> {
        let removed = self
            .endpoint_records
            .iter()
            .filter(|(_, record)| record.expires_at_ms <= now_ms)
            .map(|((_, endpoint), _)| *endpoint)
            .collect::<Vec<_>>();
        self.endpoint_records
            .retain(|_, record| record.expires_at_ms > now_ms);
        self.records
            .retain(|_, record| record.expires_at_ms > now_ms);
        removed
    }

    fn contains_endpoint(&self, endpoint_id: EndpointId) -> bool {
        self.endpoint_records
            .keys()
            .any(|(_, endpoint)| *endpoint == endpoint_id)
    }
}

/// Authenticated virtual-address directory backed by encrypted presence records.
#[derive(Debug)]
pub struct PresenceDirectory {
    network_id: NetworkId,
    cache: Mutex<PresenceCache>,
    lookup: std::sync::Arc<WeaverAddressLookup>,
}

impl PresenceDirectory {
    pub fn new(network_id: NetworkId, lookup: std::sync::Arc<WeaverAddressLookup>) -> Self {
        assert_eq!(
            lookup.network_id(),
            network_id,
            "presence directory and address lookup must share a virtual network"
        );
        Self {
            network_id,
            cache: Mutex::new(PresenceCache::default()),
            lookup,
        }
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Decrypts, authenticates, replay-checks and publishes a remote presence atomically
    /// from the caller's perspective. Invalid records never reach iroh.
    pub fn apply_encrypted(
        &self,
        config: &ValidatedNetworkConfig,
        encrypted: &EncryptedPresenceRecord,
        now_ms: u64,
    ) -> Result<bool, DiscoveryError> {
        if config.as_config().network_id != self.network_id {
            return Err(DiscoveryError::WrongNetwork);
        }
        let record = encrypted.open(config, now_ms)?;
        let mut cache = self.cache.lock().expect("presence cache mutex poisoned");
        let changed = cache.apply(record.clone())?;
        if changed {
            self.lookup.apply_presence(&record)?;
        }
        Ok(changed)
    }

    pub fn resolve(&self, address: ScopedVirtualAddr, now_ms: u64) -> Option<EndpointId> {
        self.cache
            .lock()
            .expect("presence cache mutex poisoned")
            .get(self.network_id, address, now_ms)
            .map(|record| record.endpoint_id)
    }

    /// Resolves the signed stable configuration mapping even before a live presence record
    /// has been fetched. This lets the caller derive the opaque directory lookup key from a
    /// virtual address without supplying an EndpointId at the public API boundary.
    pub fn configured_endpoint(
        &self,
        config: &ValidatedNetworkConfig,
        address: ScopedVirtualAddr,
        now_ms: u64,
    ) -> Result<EndpointId, DiscoveryError> {
        if config.as_config().network_id != self.network_id {
            return Err(DiscoveryError::WrongNetwork);
        }
        configured_endpoint(config, address, now_ms)
    }

    pub fn purge_expired(&self, now_ms: u64) {
        let mut cache = self.cache.lock().expect("presence cache mutex poisoned");
        let removed = cache.purge_expired(now_ms);
        for endpoint_id in removed {
            if !cache.contains_endpoint(endpoint_id) {
                self.lookup.clear_presence(endpoint_id);
            }
        }
    }
}

pub fn configured_endpoint(
    config: &ValidatedNetworkConfig,
    address: ScopedVirtualAddr,
    now_ms: u64,
) -> Result<EndpointId, DiscoveryError> {
    let snapshot = config.as_config();
    let mut member_ids = Vec::new();
    for raw in &snapshot.app_bindings {
        let binding = AppBinding::from_bytes(raw)?;
        let payload = binding.payload();
        let matches = match (address, payload.role) {
            (ScopedVirtualAddr::Server { app }, AppRole::Server) => payload.app_addr == app,
            (ScopedVirtualAddr::Client { app, device }, AppRole::Client) => {
                payload.app_addr == app && payload.device_id == Some(device)
            }
            _ => false,
        };
        if matches && now_ms < payload.expires_at_ms {
            member_ids.push(payload.subject);
        }
    }
    member_ids.sort_unstable_by_key(|member| *member.as_bytes());
    member_ids.dedup();
    if member_ids.len() != 1 {
        return Err(DiscoveryError::NotAuthorized);
    }
    let member_id = member_ids[0];
    let mut endpoints = Vec::new();
    for raw in &snapshot.endpoint_bindings {
        let binding = EndpointBinding::from_bytes(raw)?;
        let payload = binding.payload();
        if payload.member_id == member_id && now_ms < payload.expires_at_ms {
            endpoints.push(
                EndpointId::from_bytes(&payload.endpoint_id)
                    .map_err(|_| DiscoveryError::MalformedEndpoint)?,
            );
        }
    }
    endpoints.sort_unstable_by_key(|endpoint| *endpoint.as_bytes());
    endpoints.dedup();
    if endpoints.len() != 1 {
        return Err(DiscoveryError::NotAuthorized);
    }
    Ok(endpoints[0])
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiscoveryError {
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("LAN discovery tag is malformed")]
    MalformedTag,
    #[error("discovery endpoint ID is malformed")]
    MalformedEndpoint,
    #[error("presence wire encoding is malformed")]
    MalformedWire,
    #[error("presence record exceeds protocol limits")]
    PresenceTooLarge,
    #[error("presence record is invalid or expired")]
    InvalidPresence,
    #[error("presence record belongs to another key epoch")]
    WrongEpoch,
    #[error("presence record belongs to another virtual network")]
    WrongNetwork,
    #[error("presence encryption failed")]
    EncryptionFailed,
    #[error("presence decryption or authentication failed")]
    DecryptionFailed,
    #[error("presence sequence would roll back or fork cached state")]
    Rollback,
    #[error("member, endpoint or virtual address is not authorized by current config")]
    NotAuthorized,
    #[error("LAN discovery backend failed: {0}")]
    Backend(String),
    #[error(transparent)]
    Crypto(#[from] weaver_crypto::CertificateError),
}

fn member_for_signer(
    config: &ValidatedNetworkConfig,
    public_key: [u8; 32],
) -> Result<MemberCertificate, DiscoveryError> {
    config
        .as_config()
        .members
        .iter()
        .filter_map(|raw| MemberCertificate::from_bytes(raw).ok())
        .find(|member| member.payload().signing_public_key == public_key)
        .ok_or(DiscoveryError::NotAuthorized)
}

fn member_by_id(
    config: &ValidatedNetworkConfig,
    member_id: MemberId,
) -> Result<MemberCertificate, DiscoveryError> {
    config
        .as_config()
        .members
        .iter()
        .filter_map(|raw| MemberCertificate::from_bytes(raw).ok())
        .find(|member| member.payload().member_id == member_id)
        .ok_or(DiscoveryError::NotAuthorized)
}

fn authorize_endpoint_and_addr(
    config: &ValidatedNetworkConfig,
    member_id: MemberId,
    endpoint_id: EndpointId,
    virtual_addr: ScopedVirtualAddr,
    now_ms: u64,
) -> Result<(), DiscoveryError> {
    let endpoint_allowed = config.as_config().endpoint_bindings.iter().any(|raw| {
        EndpointBinding::from_bytes(raw).is_ok_and(|binding| {
            binding.payload().member_id == member_id
                && binding.payload().endpoint_id == *endpoint_id.as_bytes()
                && binding.payload().expires_at_ms > now_ms
        })
    });
    if !endpoint_allowed {
        return Err(DiscoveryError::NotAuthorized);
    }
    let address_allowed = config.as_config().app_bindings.iter().any(|raw| {
        AppBinding::from_bytes(raw).is_ok_and(|binding| {
            let payload = binding.payload();
            if payload.subject != member_id || payload.expires_at_ms <= now_ms {
                return false;
            }
            match (payload.role, virtual_addr) {
                (AppRole::Server, ScopedVirtualAddr::Server { app }) => payload.app_addr == app,
                (AppRole::Client, ScopedVirtualAddr::Client { app, device }) => {
                    payload.app_addr == app && payload.device_id == Some(device)
                }
                _ => false,
            }
        })
    });
    if address_allowed {
        Ok(())
    } else {
        Err(DiscoveryError::NotAuthorized)
    }
}

fn derive_opaque_key(seed: &[u8; 32], endpoint: EndpointId) -> [u8; OPAQUE_KEY_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(b"weaver.presence-index.v1\0");
    hasher.update(endpoint.as_bytes());
    let mut key = [0_u8; OPAQUE_KEY_LEN];
    key.copy_from_slice(&hasher.finalize().as_bytes()[..OPAQUE_KEY_LEN]);
    key
}

fn derive_presence_key(seed: &[u8; 32], epoch: u64, opaque: &[u8; OPAQUE_KEY_LEN]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(b"weaver.presence-encryption.v1\0");
    hasher.update(&epoch.to_be_bytes());
    hasher.update(opaque);
    *hasher.finalize().as_bytes()
}

fn presence_aad(epoch: u64, opaque: &[u8; OPAQUE_KEY_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 8 + OPAQUE_KEY_LEN + NONCE_LEN);
    aad.extend_from_slice(PRESENCE_MAGIC);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(opaque);
    aad.extend_from_slice(nonce);
    aad
}

fn validate_candidates(candidates: &[DiscoveryCandidate]) -> Result<(), DiscoveryError> {
    if candidates.len() > MAX_CANDIDATES
        || candidates.iter().any(|candidate| matches!(candidate, DiscoveryCandidate::Relay(url) if url.is_empty() || url.len() > MAX_RELAY_URL_LEN))
    {
        return Err(DiscoveryError::InvalidPresence);
    }
    Ok(())
}

fn encode_presence_payload(record: &PresenceRecord) -> Result<Vec<u8>, DiscoveryError> {
    let mut out = Vec::new();
    out.extend_from_slice(PRESENCE_PAYLOAD_MAGIC);
    out.extend_from_slice(record.network_id.as_bytes());
    out.extend_from_slice(&record.epoch.to_be_bytes());
    let address_count =
        u16::try_from(record.virtual_addrs.len()).map_err(|_| DiscoveryError::PresenceTooLarge)?;
    out.extend_from_slice(&address_count.to_be_bytes());
    for address in &record.virtual_addrs {
        encode_virtual_addr(&mut out, *address);
    }
    out.extend_from_slice(record.member_id.as_bytes());
    out.extend_from_slice(record.endpoint_id.as_bytes());
    out.extend_from_slice(&record.capabilities.to_be_bytes());
    out.extend_from_slice(&record.sequence.to_be_bytes());
    out.extend_from_slice(&record.issued_at_ms.to_be_bytes());
    out.extend_from_slice(&record.expires_at_ms.to_be_bytes());
    let count =
        u16::try_from(record.candidates.len()).map_err(|_| DiscoveryError::PresenceTooLarge)?;
    out.extend_from_slice(&count.to_be_bytes());
    for candidate in &record.candidates {
        match candidate {
            DiscoveryCandidate::Ip(SocketAddr::V4(address)) => {
                out.push(1);
                out.extend_from_slice(&address.ip().octets());
                out.extend_from_slice(&address.port().to_be_bytes());
            }
            DiscoveryCandidate::Ip(SocketAddr::V6(address)) => {
                out.push(2);
                out.extend_from_slice(&address.ip().octets());
                out.extend_from_slice(&address.port().to_be_bytes());
            }
            DiscoveryCandidate::Relay(url) => {
                out.push(3);
                let len = u16::try_from(url.len()).map_err(|_| DiscoveryError::PresenceTooLarge)?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(url.as_bytes());
            }
        }
    }
    if out.len() > MAX_PRESENCE_WIRE - SIGNATURE_LEN {
        return Err(DiscoveryError::PresenceTooLarge);
    }
    Ok(out)
}

fn decode_presence_payload(bytes: &[u8]) -> Result<PresenceRecord, DiscoveryError> {
    let mut decoder = Decoder::new(bytes);
    decoder.magic(PRESENCE_PAYLOAD_MAGIC)?;
    let network_id = NetworkId::from_bytes(decoder.array()?);
    let epoch = decoder.u64()?;
    let address_count = decoder.u16()? as usize;
    if address_count == 0 || address_count > MAX_VIRTUAL_ADDRS {
        return Err(DiscoveryError::InvalidPresence);
    }
    let mut virtual_addrs = Vec::with_capacity(address_count);
    for _ in 0..address_count {
        virtual_addrs.push(decode_virtual_addr(&mut decoder)?);
    }
    let member_id = MemberId::from_bytes(decoder.array()?);
    let endpoint_id =
        EndpointId::from_bytes(&decoder.array()?).map_err(|_| DiscoveryError::MalformedEndpoint)?;
    let capabilities = decoder.u32()?;
    let sequence = decoder.u64()?;
    let issued_at_ms = decoder.u64()?;
    let expires_at_ms = decoder.u64()?;
    let count = decoder.u16()? as usize;
    if count > MAX_CANDIDATES {
        return Err(DiscoveryError::InvalidPresence);
    }
    let mut candidates = Vec::with_capacity(count);
    for _ in 0..count {
        candidates.push(match decoder.u8()? {
            1 => DiscoveryCandidate::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(decoder.array::<4>()?)),
                decoder.u16()?,
            )),
            2 => DiscoveryCandidate::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(decoder.array::<16>()?)),
                decoder.u16()?,
            )),
            3 => {
                let len = decoder.u16()? as usize;
                let url = std::str::from_utf8(decoder.take(len)?)
                    .map_err(|_| DiscoveryError::MalformedWire)?
                    .to_owned();
                DiscoveryCandidate::Relay(url)
            }
            _ => return Err(DiscoveryError::MalformedWire),
        });
    }
    decoder.finish()?;
    Ok(PresenceRecord {
        network_id,
        epoch,
        virtual_addrs,
        member_id,
        endpoint_id,
        candidates,
        capabilities,
        sequence,
        issued_at_ms,
        expires_at_ms,
    })
}

fn encode_virtual_addr(out: &mut Vec<u8>, address: ScopedVirtualAddr) {
    match address {
        ScopedVirtualAddr::Server { app } => {
            out.push(1);
            out.extend_from_slice(app.as_bytes());
        }
        ScopedVirtualAddr::Client { app, device } => {
            out.push(2);
            out.extend_from_slice(app.as_bytes());
            out.extend_from_slice(device.as_bytes());
        }
    }
}

fn decode_virtual_addr(decoder: &mut Decoder<'_>) -> Result<ScopedVirtualAddr, DiscoveryError> {
    let kind = decoder.u8()?;
    let app = AppAddr::from_bytes(decoder.array()?);
    match kind {
        1 => Ok(ScopedVirtualAddr::Server { app }),
        2 => Ok(ScopedVirtualAddr::Client {
            app,
            device: DeviceId::from_bytes(decoder.array()?),
        }),
        _ => Err(DiscoveryError::MalformedWire),
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], DiscoveryError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DiscoveryError::MalformedWire)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DiscoveryError::MalformedWire)?;
        self.offset = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], DiscoveryError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DiscoveryError::MalformedWire)
    }
    fn magic(&mut self, expected: &[u8]) -> Result<(), DiscoveryError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(DiscoveryError::MalformedWire)
        }
    }
    fn u8(&mut self) -> Result<u8, DiscoveryError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, DiscoveryError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, DiscoveryError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, DiscoveryError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn finish(self) -> Result<(), DiscoveryError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DiscoveryError::MalformedWire)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use weaver_config::{EpochSecrets, NetworkConfigV1, NetworkPolicy};
    use weaver_crypto::{
        AppBinding, AppRegistration, AppRole, AppRootKey, EndpointBinding, MemberCertificate,
        MemberRoles, NetworkRootKey,
    };

    struct Fixture {
        config: ValidatedNetworkConfig,
        signing: SigningKeypair,
        endpoint: EndpointId,
        address: ScopedVirtualAddr,
        second_address: ScopedVirtualAddr,
    }

    fn fixture(seed: [[u8; 32]; 4]) -> Fixture {
        let root = NetworkRootKey::generate().unwrap();
        let network_id = root.public().network_id();
        let signing = SigningKeypair::generate().unwrap();
        let endpoint = iroh::SecretKey::generate().public();
        let member = MemberCertificate::issue(
            &root,
            signing.public_bytes(),
            [0x44; 32],
            MemberRoles::MEMBER.union(MemberRoles::SERVICE),
            1,
            100,
            20_000_000,
        )
        .unwrap();
        let endpoint_binding = EndpointBinding::issue(
            &signing,
            member.payload(),
            *endpoint.as_bytes(),
            0,
            20_000_000,
        )
        .unwrap();
        let app = AppRootKey::generate().unwrap();
        let registration = AppRegistration::issue(&root, &app, 0);
        let binding = AppBinding::issue(
            &app,
            network_id,
            member.payload().member_id,
            AppRole::Server,
            None,
            20_000_000,
            Vec::new(),
        )
        .unwrap();
        let address = ScopedVirtualAddr::Server {
            app: app.app_addr(),
        };
        let second_app = AppRootKey::generate().unwrap();
        let second_registration = AppRegistration::issue(&root, &second_app, 0);
        let second_binding = AppBinding::issue(
            &second_app,
            network_id,
            member.payload().member_id,
            AppRole::Client,
            Some(DeviceId::from_bytes([0x45; 32])),
            20_000_000,
            Vec::new(),
        )
        .unwrap();
        let second_address = ScopedVirtualAddr::Client {
            app: second_app.app_addr(),
            device: DeviceId::from_bytes([0x45; 32]),
        };
        let config = NetworkConfigV1 {
            network_id,
            epoch: 7,
            revision: 12,
            previous_hash: [0x55; 32],
            issued_at_ms: 100,
            expires_at_ms: 20_000_000,
            admin_keys: Vec::new(),
            members: vec![member.to_bytes()],
            endpoint_bindings: vec![endpoint_binding.to_bytes()],
            revoked_serials: Vec::new(),
            apps: vec![registration.to_bytes(), second_registration.to_bytes()],
            app_bindings: vec![binding.to_bytes(), second_binding.to_bytes()],
            virtual_dns: Vec::new(),
            relays: Vec::new(),
            presence_services: Vec::new(),
            epoch_secrets: EpochSecrets::from_bytes(seed),
            policies: NetworkPolicy::default(),
        }
        .validate(&root.public(), network_id, 1_000)
        .unwrap();
        Fixture {
            config,
            signing,
            endpoint,
            address,
            second_address,
        }
    }

    #[test]
    fn lan_tag_rotates_matches_adjacent_slot_and_is_network_scoped() {
        let first = fixture([[0x71; 32]; 4]);
        let second = fixture([[0x71; 32]; 4]);
        let discovery = ProtectedLanDiscovery::from_config(&first.config).unwrap();
        let other = ProtectedLanDiscovery::from_config(&second.config).unwrap();
        let now = LAN_SLOT_MS * 10 + 123;
        let tag = discovery.tag_for(first.endpoint, now);
        assert_eq!(discovery.txt_records(first.endpoint, now)[0], "v=1");
        assert_eq!(LanTag::from_txt(&tag.txt_value()).unwrap(), tag);
        assert_eq!(discovery.match_tag(tag, now), Some(first.endpoint));
        assert_eq!(
            discovery.match_tag(tag, now + LAN_SLOT_MS),
            Some(first.endpoint)
        );
        assert_eq!(discovery.match_tag(tag, now + LAN_SLOT_MS * 2), None);
        assert_eq!(other.match_tag(tag, now), None);
        assert_ne!(
            discovery.tag_for(first.endpoint, now),
            discovery.tag_for(first.endpoint, now + LAN_SLOT_MS)
        );
    }

    #[test]
    fn encrypted_presence_hides_identity_verifies_signature_and_rejects_rollback() {
        let fixture = fixture([[0x81; 32], [0x82; 32], [0x83; 32], [0x84; 32]]);
        let candidates = vec![
            DiscoveryCandidate::Ip("192.168.1.8:4433".parse().unwrap()),
            DiscoveryCandidate::Ip("[fd00::8]:4433".parse().unwrap()),
            DiscoveryCandidate::Relay("https://relay.example.test".to_owned()),
        ];
        let encrypted = EncryptedPresenceRecord::seal(
            &fixture.config,
            &fixture.signing,
            fixture.endpoint,
            vec![fixture.address, fixture.second_address],
            candidates.clone(),
            0x05,
            9,
            1_000,
            1_000 + DEFAULT_PRESENCE_TTL_MS,
        )
        .unwrap();
        let wire = encrypted.to_bytes().unwrap();
        assert!(!wire.windows(32).any(|window| {
            window == fixture.config.as_config().network_id.as_bytes()
                || window == fixture.address.app_addr().as_bytes()
        }));
        let decoded = EncryptedPresenceRecord::from_bytes(&wire).unwrap();
        let opened = decoded.open(&fixture.config, 2_000).unwrap();
        assert_eq!(opened.endpoint_id, fixture.endpoint);
        assert_eq!(
            opened.virtual_addrs,
            vec![fixture.address, fixture.second_address]
        );
        assert_eq!(opened.candidates, candidates);

        let lookup = std::sync::Arc::new(WeaverAddressLookup::new(
            fixture.config.as_config().network_id,
        ));
        let directory = PresenceDirectory::new(fixture.config.as_config().network_id, lookup);
        assert!(
            directory
                .apply_encrypted(&fixture.config, &decoded, 2_000)
                .unwrap()
        );
        assert!(
            !directory
                .apply_encrypted(&fixture.config, &decoded, 2_000)
                .unwrap()
        );
        assert_eq!(
            directory.resolve(fixture.address, 2_000),
            Some(fixture.endpoint)
        );
        assert_eq!(
            directory.resolve(fixture.second_address, 2_000),
            Some(fixture.endpoint)
        );
        directory.purge_expired(1_000 + DEFAULT_PRESENCE_TTL_MS);
        assert_eq!(directory.resolve(fixture.address, 2_000), None);

        let mut cache = PresenceCache::default();
        assert!(cache.apply(opened.clone()).unwrap());
        assert!(!cache.apply(opened.clone()).unwrap());
        let mut rollback = opened.clone();
        rollback.sequence -= 1;
        assert_eq!(cache.apply(rollback), Err(DiscoveryError::Rollback));
        let mut fork = opened;
        fork.candidates.clear();
        assert_eq!(cache.apply(fork), Err(DiscoveryError::Rollback));

        let mut tampered = wire.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            EncryptedPresenceRecord::from_bytes(&tampered)
                .unwrap()
                .open(&fixture.config, 2_000),
            Err(DiscoveryError::DecryptionFailed)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_mdns_backend_emits_only_matching_protected_tag() {
        let fixture = fixture([[0x91; 32]; 4]);
        let protected = ProtectedLanDiscovery::from_config(&fixture.config).unwrap();
        let now = wall_now_ms();
        let mut publisher = MdnsLanDiscovery::spawn(
            protected.clone(),
            fixture.endpoint,
            43_210,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            now,
            &tokio::runtime::Handle::current(),
        )
        .unwrap();
        let observer_endpoint = iroh::SecretKey::generate().public();
        let observer = MdnsLanDiscovery::spawn(
            protected,
            observer_endpoint,
            0,
            Vec::new(),
            now,
            &tokio::runtime::Handle::current(),
        )
        .unwrap();
        let lookup = std::sync::Arc::new(WeaverAddressLookup::new(
            fixture.config.as_config().network_id,
        ));
        let mut resolved = lookup.resolve(fixture.endpoint).unwrap();
        let (_publication_tx, publication_rx) = watch::channel(None);
        let runtime = spawn_lan_discovery_runtime(observer, lookup, publication_rx);
        let item = tokio::time::timeout(std::time::Duration::from_secs(5), resolved.next())
            .await
            .expect("protected mDNS discovery timed out")
            .expect("address lookup stream closed")
            .expect("address lookup failed");
        assert_eq!(item.endpoint_id(), fixture.endpoint);
        assert!(
            item.endpoint_info()
                .data
                .ip_addrs()
                .any(|address| *address == "127.0.0.1:43210".parse().unwrap())
        );
        // Exercise runtime address updates and tag rotation APIs before dropping guards.
        publisher.replace_addresses(43_211, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert!(
            publisher
                .refresh_tag(now + LAN_SLOT_MS, &tokio::runtime::Handle::current())
                .unwrap()
        );
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn live_lookup_waits_for_late_lan_update_and_merges_presence() {
        let network_id = NetworkId::from_bytes([0xa1; 32]);
        let other_network = NetworkId::from_bytes([0xa2; 32]);
        let endpoint = iroh::SecretKey::generate().public();
        let lookup = WeaverAddressLookup::new(network_id);
        let mut resolved = lookup.resolve(endpoint).expect("lookup is always live");

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), resolved.next())
                .await
                .is_err(),
            "empty lookup must stay pending rather than terminate"
        );

        let direct: SocketAddr = "127.0.0.1:44221".parse().unwrap();
        lookup.apply_lan_observation(LanObservation {
            endpoint_id: endpoint,
            addresses: vec![direct],
            expired: false,
        });
        let item = resolved.next().await.unwrap().unwrap();
        assert_eq!(item.endpoint_id(), endpoint);
        assert_eq!(
            item.endpoint_info()
                .data
                .ip_addrs()
                .copied()
                .collect::<Vec<_>>(),
            vec![direct]
        );

        let record = PresenceRecord {
            network_id,
            epoch: 1,
            virtual_addrs: vec![ScopedVirtualAddr::Server {
                app: AppAddr::from_bytes([0xb1; 32]),
            }],
            member_id: MemberId::from_bytes([0xc1; 32]),
            endpoint_id: endpoint,
            candidates: vec![DiscoveryCandidate::Relay(
                "https://relay.example.test".to_owned(),
            )],
            capabilities: 0,
            sequence: 1,
            issued_at_ms: 1,
            expires_at_ms: 2,
        };
        lookup.apply_presence(&record).unwrap();
        let item = resolved.next().await.unwrap().unwrap();
        assert_eq!(item.endpoint_info().data.ip_addrs().count(), 1);
        assert_eq!(item.endpoint_info().data.relay_urls().count(), 1);

        lookup.apply_lan_observation(LanObservation {
            endpoint_id: endpoint,
            addresses: Vec::new(),
            expired: true,
        });
        let item = resolved.next().await.unwrap().unwrap();
        assert_eq!(item.endpoint_info().data.ip_addrs().count(), 0);
        assert_eq!(item.endpoint_info().data.relay_urls().count(), 1);

        let mut foreign = record;
        foreign.network_id = other_network;
        assert_eq!(
            lookup.apply_presence(&foreign),
            Err(DiscoveryError::WrongNetwork)
        );
    }

    trait AppAddrOf {
        fn app_addr(self) -> AppAddr;
    }

    impl AppAddrOf for ScopedVirtualAddr {
        fn app_addr(self) -> AppAddr {
            match self {
                ScopedVirtualAddr::Server { app } | ScopedVirtualAddr::Client { app, .. } => app,
            }
        }
    }
}
