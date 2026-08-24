//! Privileged end-to-end workload used by `scripts/netem-e2e.sh`.

use std::{
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use iroh::{RelayUrl, SecretKey};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use weaver_config::{EpochSecrets, NetworkConfigV1, NetworkPolicy, ValidatedNetworkConfig};
use weaver_core::{AppAddr, DeviceId, NetworkId, ScopedVirtualAddr};
use weaver_crypto::{
    AppBinding, AppRegistration, AppRole, AppRootKey, EndpointBinding, MemberCertificate,
    MemberRoles, NetworkRootKey, SigningKeypair,
};
use weaver_discovery::{
    AddressLookupSource, AddressLookupUpdate, LanDiscoveryTrigger, MdnsLanDiscovery,
    ProtectedLanDiscovery, WeaverAddressLookup, spawn_lan_discovery_runtime,
};
use weaver_net::{NodeConfig, PeerDescriptor, TransportPathKind, VirtualTcpStream, WeaverEndpoint};

const SERVER_ENDPOINT_SECRET: [u8; 32] = [0x11; 32];
const CLIENT_ENDPOINT_SECRET: [u8; 32] = [0x22; 32];
const SERVER_MEMBER_SECRET: [u8; 32] = [0x31; 32];
const CLIENT_MEMBER_SECRET: [u8; 32] = [0x32; 32];
const ROOT_SECRET: [u8; 32] = [0x41; 32];
const SERVER_APP_SECRET: [u8; 32] = [0x51; 32];
const CLIENT_APP_SECRET: [u8; 32] = [0x52; 32];
const CLIENT_DEVICE: DeviceId = DeviceId::from_bytes([0x61; 32]);
const DATA_CHUNK: usize = 64 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Weaver tc-netem end-to-end benchmark worker")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Server {
        #[arg(long)]
        relay_url: RelayUrl,
    },
    Client {
        #[arg(long)]
        relay_url: RelayUrl,
        #[arg(long)]
        report: PathBuf,
        #[arg(long, default_value_t = 32 * 1024 * 1024)]
        bytes: u64,
        #[arg(long, default_value_t = 32)]
        ping_count: u32,
    },
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    bytes: u64,
    elapsed_ms: u64,
    throughput_mbps: f64,
    relay_rtt_samples: usize,
    relay_rtt_p50_ms: f64,
    relay_rtt_p95_ms: f64,
    direct_rtt_samples: usize,
    direct_rtt_p50_ms: f64,
    direct_rtt_p95_ms: f64,
    network_change_to_direct_ms: Option<u64>,
    initial_path: &'static str,
    final_path: &'static str,
    saw_relay: bool,
    saw_direct: bool,
    peer_identity_stable: bool,
    payload_verified: bool,
    protected_lan_observations: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Server { relay_url } => run_server(relay_url).await,
        Command::Client {
            relay_url,
            report,
            bytes,
            ping_count,
        } => run_client(relay_url, report, bytes, ping_count).await,
    }
}

async fn run_server(relay_url: RelayUrl) -> Result<()> {
    let fixture = fixture()?;
    let server_key = SecretKey::from_bytes(&SERVER_ENDPOINT_SECRET);
    let client_key = SecretKey::from_bytes(&CLIENT_ENDPOINT_SECRET);
    let lookup = Arc::new(WeaverAddressLookup::new(fixture.network_id));
    let publications = lookup.subscribe_publications();
    let mut endpoint = WeaverEndpoint::bind(
        NodeConfig::tcp_server(
            server_key,
            Some(relay_url),
            fixture.network_id,
            fixture.server_app,
            [(client_key.public(), fixture.client_addr)],
        )
        .with_address_lookup(lookup.clone()),
    )
    .await?;
    endpoint.wait_relay_online(Duration::from_secs(15)).await?;
    let discovery = start_discovery(
        &endpoint,
        &fixture.config,
        fixture.server_app,
        lookup,
        publications,
    )?;
    let mut listener = endpoint.take_tcp_listener()?;
    let _network_changes = spawn_network_change_signal(endpoint.dialer(), discovery.trigger());
    println!("SIM_SERVER_READY");

    let mut stream = listener.accept().await?;
    serve_workload(&mut stream).await?;
    discovery.shutdown().await;
    endpoint.close().await;
    Ok(())
}

async fn run_client(
    relay_url: RelayUrl,
    report_path: PathBuf,
    bytes: u64,
    ping_count: u32,
) -> Result<()> {
    if bytes == 0 || ping_count == 0 {
        bail!("--bytes and --ping-count must be non-zero");
    }
    let fixture = fixture()?;
    let lookup = Arc::new(WeaverAddressLookup::new(fixture.network_id));
    let publications = lookup.subscribe_publications();
    let mut lookup_updates = lookup.subscribe_updates();
    let endpoint = WeaverEndpoint::bind(
        NodeConfig::client(
            SecretKey::from_bytes(&CLIENT_ENDPOINT_SECRET),
            Some(relay_url.clone()),
            fixture.network_id,
            fixture.client_app,
            CLIENT_DEVICE,
        )
        .with_address_lookup(lookup.clone()),
    )
    .await?;
    endpoint.wait_relay_online(Duration::from_secs(15)).await?;
    let discovery = start_discovery(
        &endpoint,
        &fixture.config,
        fixture.client_app,
        lookup,
        publications,
    )?;
    let network_changes = spawn_network_change_signal(endpoint.dialer(), discovery.trigger());
    let target = PeerDescriptor {
        network_id: fixture.network_id,
        app_addr: fixture.server_app,
        endpoint_id: SecretKey::from_bytes(&SERVER_ENDPOINT_SECRET).public(),
        relay_url: Some(relay_url),
        direct_addresses: Vec::new(),
    };
    let mut stream = endpoint.connect(&target).await?;
    let peer_before = stream.peer_endpoint_id();
    let initial_path = selected_path(&stream);
    let mut saw_relay = initial_path == "relay";
    let mut saw_direct = initial_path == "direct";
    let mut relay_rtts = ping(&mut stream, ping_count).await?;
    relay_rtts.sort_unstable();

    stream.write_all(b"D").await?;
    stream.write_all(&bytes.to_be_bytes()).await?;
    println!("SIM_CLIENT_READY_FOR_LAN");
    let started = Instant::now();
    let mut migration_latency = None;
    let mut protected_lan_observations = 0_u64;
    let server_endpoint = SecretKey::from_bytes(&SERVER_ENDPOINT_SECRET).public();
    let mut offset = 0_u64;
    let mut chunk = vec![0_u8; DATA_CHUNK];
    while offset < bytes {
        let len = usize::try_from((bytes - offset).min(DATA_CHUNK as u64))?;
        fill_pattern(&mut chunk[..len], offset);
        stream.write_all(&chunk[..len]).await?;
        observe_paths(&stream, &mut saw_relay, &mut saw_direct);
        capture_migration_latency(&network_changes, saw_direct, &mut migration_latency);
        drain_lan_updates(
            &mut lookup_updates,
            server_endpoint,
            &mut protected_lan_observations,
        );
        offset += len as u64;
    }
    stream.flush().await?;

    let migration_deadline = Instant::now() + Duration::from_secs(15);
    while !saw_direct && Instant::now() < migration_deadline {
        observe_paths(&stream, &mut saw_relay, &mut saw_direct);
        capture_migration_latency(&network_changes, saw_direct, &mut migration_latency);
        drain_lan_updates(
            &mut lookup_updates,
            server_endpoint,
            &mut protected_lan_observations,
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut response = [0_u8; 1];
    stream.read_exact(&mut response).await?;
    drain_lan_updates(
        &mut lookup_updates,
        server_endpoint,
        &mut protected_lan_observations,
    );
    let elapsed = started.elapsed();
    let mut direct_rtts = if saw_direct {
        ping(&mut stream, ping_count).await?
    } else {
        Vec::new()
    };
    direct_rtts.sort_unstable();
    stream.write_all(b"Q").await?;
    stream.shutdown().await?;
    let mut eof = Vec::new();
    stream.read_to_end(&mut eof).await?;
    let final_path = selected_path(&stream);
    let report = BenchmarkReport {
        bytes,
        elapsed_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        throughput_mbps: bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0,
        relay_rtt_samples: relay_rtts.len(),
        relay_rtt_p50_ms: percentile_ms(&relay_rtts, 0.50),
        relay_rtt_p95_ms: percentile_ms(&relay_rtts, 0.95),
        direct_rtt_samples: direct_rtts.len(),
        direct_rtt_p50_ms: percentile_ms(&direct_rtts, 0.50),
        direct_rtt_p95_ms: percentile_ms(&direct_rtts, 0.95),
        network_change_to_direct_ms: migration_latency,
        initial_path,
        final_path,
        saw_relay,
        saw_direct,
        peer_identity_stable: stream.peer_endpoint_id() == peer_before,
        payload_verified: response[0] == 0,
        protected_lan_observations,
    };
    let json = serde_json::to_vec_pretty(&report)?;
    tokio::fs::write(&report_path, &json)
        .await
        .with_context(|| format!("failed to write {}", report_path.display()))?;
    println!("{}", String::from_utf8(json).expect("JSON is UTF-8"));
    if !report.saw_relay
        || !report.saw_direct
        || !report.peer_identity_stable
        || !report.payload_verified
        || report.protected_lan_observations == 0
    {
        bail!("relay-to-direct reliability acceptance failed");
    }
    discovery.shutdown().await;
    endpoint.close().await;
    Ok(())
}

async fn ping(stream: &mut VirtualTcpStream, count: u32) -> Result<Vec<Duration>> {
    let mut samples = Vec::with_capacity(count as usize);
    for sequence in 0..count {
        let started = Instant::now();
        stream.write_all(b"P").await?;
        stream.write_all(&u64::from(sequence).to_be_bytes()).await?;
        stream.flush().await?;
        let mut echoed = [0_u8; 8];
        stream.read_exact(&mut echoed).await?;
        if u64::from_be_bytes(echoed) != u64::from(sequence) {
            bail!("ping sequence was corrupted");
        }
        samples.push(started.elapsed());
    }
    Ok(samples)
}

async fn serve_workload(stream: &mut VirtualTcpStream) -> Result<()> {
    loop {
        let command = stream.read_u8().await?;
        match command {
            b'P' => {
                let sequence = stream.read_u64().await?;
                stream.write_u64(sequence).await?;
                stream.flush().await?;
            }
            b'D' => {
                let total = stream.read_u64().await?;
                let mut offset = 0_u64;
                let mut received = vec![0_u8; DATA_CHUNK];
                let mut expected = vec![0_u8; DATA_CHUNK];
                while offset < total {
                    let len = usize::try_from((total - offset).min(DATA_CHUNK as u64))?;
                    stream.read_exact(&mut received[..len]).await?;
                    fill_pattern(&mut expected[..len], offset);
                    if received[..len] != expected[..len] {
                        bail!("reliable stream payload mismatch at offset {offset}");
                    }
                    offset += len as u64;
                }
                stream.write_all(&[0]).await?;
                stream.flush().await?;
            }
            b'Q' => {
                stream.finish_and_wait().await?;
                return Ok(());
            }
            _ => bail!("unknown benchmark command"),
        }
    }
}

fn fill_pattern(bytes: &mut [u8], offset: u64) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        let position = offset + index as u64;
        *byte = (position.wrapping_mul(31).wrapping_add(position / 251) & 0xff) as u8;
    }
}

fn observe_paths(stream: &VirtualTcpStream, relay: &mut bool, direct: &mut bool) {
    for path in stream.transport_paths().iter().filter(|path| path.selected) {
        *relay |= path.kind == TransportPathKind::Relay;
        *direct |= path.kind == TransportPathKind::Direct;
    }
}

fn selected_path(stream: &VirtualTcpStream) -> &'static str {
    stream
        .transport_paths()
        .iter()
        .find(|path| path.selected)
        .map(|path| match path.kind {
            TransportPathKind::Relay => "relay",
            TransportPathKind::Direct => "direct",
            TransportPathKind::Other => "other",
        })
        .unwrap_or("none")
}

fn percentile_ms(samples: &[Duration], percentile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let index = ((samples.len() - 1) as f64 * percentile).round() as usize;
    samples[index].as_secs_f64() * 1_000.0
}

fn capture_migration_latency(
    changes: &tokio::sync::watch::Receiver<Option<Instant>>,
    saw_direct: bool,
    latency: &mut Option<u64>,
) {
    if saw_direct
        && latency.is_none()
        && let Some(changed_at) = *changes.borrow()
    {
        *latency = Some(changed_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
    }
}

fn drain_lan_updates(
    updates: &mut tokio::sync::broadcast::Receiver<AddressLookupUpdate>,
    expected_endpoint: iroh::EndpointId,
    observations: &mut u64,
) {
    loop {
        match updates.try_recv() {
            Ok(update)
                if update.endpoint_id == expected_endpoint
                    && update.source == AddressLookupSource::ProtectedLan
                    && !update.expired
                    && update.candidate_count > 0 =>
            {
                *observations += 1;
            }
            Ok(_) | Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            | Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
        }
    }
}

fn spawn_network_change_signal(
    dialer: weaver_net::WeaverDialer,
    discovery: LanDiscoveryTrigger,
) -> tokio::sync::watch::Receiver<Option<Instant>> {
    let (sender, receiver) = tokio::sync::watch::channel(None);
    tokio::spawn(async move {
        let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        else {
            return;
        };
        while signal.recv().await.is_some() {
            sender.send_replace(Some(Instant::now()));
            dialer.network_change().await;
            discovery.network_change();
        }
    });
    receiver
}

fn start_discovery(
    endpoint: &WeaverEndpoint,
    config: &ValidatedNetworkConfig,
    local_app: AppAddr,
    lookup: Arc<WeaverAddressLookup>,
    publications: tokio::sync::watch::Receiver<Option<iroh::address_lookup::EndpointData>>,
) -> Result<weaver_discovery::LanDiscoveryRuntime> {
    let descriptor = endpoint.descriptor(local_app);
    let port = descriptor
        .direct_addresses
        .first()
        .context("endpoint did not publish a direct UDP address")?
        .port();
    let mut addresses = descriptor
        .direct_addresses
        .iter()
        .filter(|address| address.port() == port)
        .map(|address| address.ip())
        .collect::<Vec<IpAddr>>();
    addresses.sort_unstable();
    addresses.dedup();
    let mdns = MdnsLanDiscovery::spawn(
        ProtectedLanDiscovery::from_config(config)?,
        endpoint.id(),
        port,
        addresses,
        now_ms(),
        &tokio::runtime::Handle::current(),
    )?;
    Ok(spawn_lan_discovery_runtime(mdns, lookup, publications))
}

struct Fixture {
    config: ValidatedNetworkConfig,
    network_id: NetworkId,
    server_app: AppAddr,
    client_app: AppAddr,
    client_addr: ScopedVirtualAddr,
}

fn fixture() -> Result<Fixture> {
    let root = NetworkRootKey::from_bytes(&ROOT_SECRET);
    let network_id = root.public().network_id();
    let server_signing = SigningKeypair::from_bytes(&SERVER_MEMBER_SECRET);
    let client_signing = SigningKeypair::from_bytes(&CLIENT_MEMBER_SECRET);
    let expires = u64::MAX - 1;
    let server_member = MemberCertificate::issue(
        &root,
        server_signing.public_bytes(),
        [0x71; 32],
        MemberRoles::MEMBER.union(MemberRoles::SERVICE),
        1,
        0,
        expires,
    )?;
    let client_member = MemberCertificate::issue(
        &root,
        client_signing.public_bytes(),
        [0x72; 32],
        MemberRoles::MEMBER,
        2,
        0,
        expires,
    )?;
    let server_endpoint = SecretKey::from_bytes(&SERVER_ENDPOINT_SECRET).public();
    let client_endpoint = SecretKey::from_bytes(&CLIENT_ENDPOINT_SECRET).public();
    let server_endpoint_binding = EndpointBinding::issue(
        &server_signing,
        server_member.payload(),
        *server_endpoint.as_bytes(),
        0,
        expires,
    )?;
    let client_endpoint_binding = EndpointBinding::issue(
        &client_signing,
        client_member.payload(),
        *client_endpoint.as_bytes(),
        0,
        expires,
    )?;
    let server_app_key = AppRootKey::from_bytes(&SERVER_APP_SECRET);
    let client_app_key = AppRootKey::from_bytes(&CLIENT_APP_SECRET);
    let server_app = server_app_key.app_addr();
    let client_app = client_app_key.app_addr();
    let server_registration = AppRegistration::issue(&root, &server_app_key, 0);
    let client_registration = AppRegistration::issue(&root, &client_app_key, 0);
    let server_binding = AppBinding::issue(
        &server_app_key,
        network_id,
        server_member.payload().member_id,
        AppRole::Server,
        None,
        expires,
        Vec::new(),
    )?;
    let client_binding = AppBinding::issue(
        &client_app_key,
        network_id,
        client_member.payload().member_id,
        AppRole::Client,
        Some(CLIENT_DEVICE),
        expires,
        Vec::new(),
    )?;
    let config = NetworkConfigV1 {
        network_id,
        epoch: 1,
        revision: 1,
        previous_hash: [0x81; 32],
        issued_at_ms: 0,
        expires_at_ms: expires,
        admin_keys: Vec::new(),
        members: vec![server_member.to_bytes(), client_member.to_bytes()],
        endpoint_bindings: vec![
            server_endpoint_binding.to_bytes(),
            client_endpoint_binding.to_bytes(),
        ],
        revoked_serials: Vec::new(),
        apps: vec![
            server_registration.to_bytes(),
            client_registration.to_bytes(),
        ],
        app_bindings: vec![server_binding.to_bytes(), client_binding.to_bytes()],
        virtual_dns: Vec::new(),
        relays: Vec::new(),
        presence_services: Vec::new(),
        epoch_secrets: EpochSecrets::from_bytes([[0x91; 32]; 4]),
        policies: NetworkPolicy::default(),
    }
    .validate(&root.public(), network_id, now_ms())?;
    Ok(Fixture {
        config,
        network_id,
        server_app,
        client_app,
        client_addr: ScopedVirtualAddr::Client {
            app: client_app,
            device: CLIENT_DEVICE,
        },
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_pattern_is_independent_of_chunk_boundaries() {
        let mut whole = vec![0; 10_000];
        fill_pattern(&mut whole, 0);
        let mut split = vec![0; 10_000];
        fill_pattern(&mut split[..3_333], 0);
        fill_pattern(&mut split[3_333..], 3_333);
        assert_eq!(whole, split);
    }

    #[test]
    fn percentile_uses_sorted_latency_samples() {
        let samples = [
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
            Duration::from_millis(4),
            Duration::from_millis(5),
        ];
        assert_eq!(percentile_ms(&samples, 0.50), 3.0);
        assert_eq!(percentile_ms(&samples, 0.95), 5.0);
        assert_eq!(percentile_ms(&[], 0.95), 0.0);
    }
}
