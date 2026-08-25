use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iroh::SecretKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use weaver_core::{AppAddr, ClientAddr, DeviceId, NetworkId, ScopedVirtualAddr, ServerAddr};
use weaver_discovery::{LanObservation, PresenceDirectory, WeaverAddressLookup};
use weaver_net::{
    LocalBinding, LocalBindings, NetworkError, NodeConfig, PeerDescriptor, WeaverEndpoint,
};

const NETWORK: NetworkId = NetworkId::from_bytes([0xd1; 32]);
const SERVER_APP: AppAddr = AppAddr::from_bytes([0xd2; 32]);
const CLIENT_APP: AppAddr = AppAddr::from_bytes([0xd3; 32]);
const CLIENT_DEVICE: DeviceId = DeviceId::from_bytes([0xd4; 32]);
const CLIENT_ADDR: ScopedVirtualAddr = ScopedVirtualAddr::Client {
    app: CLIENT_APP,
    device: CLIENT_DEVICE,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_started_with_only_endpoint_id_completes_after_live_lan_discovery() -> Result<()> {
    let client_key = SecretKey::generate();
    let server_lookup = Arc::new(WeaverAddressLookup::new(NETWORK));
    let mut local_publication = server_lookup.subscribe_publications();
    let mut server = WeaverEndpoint::bind(
        NodeConfig::new(
            SecretKey::generate(),
            None,
            NETWORK,
            LocalBindings::new([LocalBinding::Server(ServerAddr::new(SERVER_APP))])?,
            [(client_key.public(), CLIENT_ADDR)],
        )
        .with_address_lookup(server_lookup),
    )
    .await?;
    let mut listener = server.take_tcp_listener(ServerAddr::new(SERVER_APP))?;

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if local_publication
                .borrow()
                .as_ref()
                .is_some_and(|data| data.ip_addrs().next().is_some())
            {
                break;
            }
            local_publication
                .changed()
                .await
                .expect("publisher dropped");
        }
    })
    .await
    .context("iroh did not publish its local direct addresses")?;
    let server_addresses = local_publication
        .borrow()
        .as_ref()
        .expect("checked above")
        .ip_addrs()
        .copied()
        .collect::<Vec<_>>();

    let client_lookup = Arc::new(WeaverAddressLookup::new(NETWORK));
    let client = WeaverEndpoint::bind(
        NodeConfig::new(
            client_key,
            None,
            NETWORK,
            LocalBindings::new([LocalBinding::Client(ClientAddr::new(
                CLIENT_APP,
                CLIENT_DEVICE,
            ))])?,
            std::iter::empty(),
        )
        .with_address_lookup(client_lookup.clone()),
    )
    .await?;
    let empty_directory = PresenceDirectory::new(NETWORK, client_lookup.clone());
    assert!(matches!(
        client
            .connect_virtual(ClientAddr::new(CLIENT_APP, CLIENT_DEVICE), &empty_directory, SERVER_APP, 1_000)
            .await,
        Err(NetworkError::VirtualAddressUnresolved(address)) if address == SERVER_APP
    ));
    let other_network = NetworkId::from_bytes([0xee; 32]);
    let foreign_directory = PresenceDirectory::new(
        other_network,
        Arc::new(WeaverAddressLookup::new(other_network)),
    );
    assert!(matches!(
        client
            .connect_virtual(
                ClientAddr::new(CLIENT_APP, CLIENT_DEVICE),
                &foreign_directory,
                SERVER_APP,
                1_000
            )
            .await,
        Err(NetworkError::NetworkMismatch { .. })
    ));
    let target = PeerDescriptor {
        network_id: NETWORK,
        app_addr: SERVER_APP,
        endpoint_id: server.id(),
        relay_url: None,
        direct_addresses: Vec::new(),
    };
    let dialer = client.dialer();
    let connect_task = tokio::spawn(async move {
        dialer
            .connect(ClientAddr::new(CLIENT_APP, CLIENT_DEVICE), &target)
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !connect_task.is_finished(),
        "resolution must remain pending while no candidate is known"
    );

    client_lookup.apply_lan_observation(LanObservation {
        endpoint_id: server.id(),
        addresses: server_addresses,
        expired: false,
    });
    let mut stream = tokio::time::timeout(Duration::from_secs(10), connect_task)
        .await
        .context("connection did not react to late discovery")???;
    let mut accepted = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .context("server did not accept discovered connection")??;

    stream.write_all(b"live-address").await?;
    let mut bytes = [0_u8; 12];
    accepted.read_exact(&mut bytes).await?;
    assert_eq!(&bytes, b"live-address");

    // This is the Android network callback's transport-facing operation. It must preserve
    // the endpoint and any application streams while triggering path reprobe/publication.
    client.network_change().await;
    accepted.write_all(b"still-open").await?;
    let mut ack = [0_u8; 10];
    stream.read_exact(&mut ack).await?;
    assert_eq!(&ack, b"still-open");

    client.close().await;
    server.close().await;
    Ok(())
}
