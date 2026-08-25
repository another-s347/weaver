use std::{net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result};
use iroh::{RelayUrl, SecretKey};
use iroh_relay::server::{RelayConfig, Server as RelayServer, ServerConfig};
use weaver_core::{AppAddr, ClientAddr, DeviceId, NetworkId, ScopedVirtualAddr, ServerAddr};
use weaver_net::{LocalBinding, LocalBindings, NetworkError, NodeConfig, WeaverEndpoint};

const NETWORK: NetworkId = NetworkId::from_bytes([0x91; 32]);
const SERVER_APP: AppAddr = AppAddr::from_bytes([0x92; 32]);
const CLIENT_APP: AppAddr = AppAddr::from_bytes([0x93; 32]);
const CLIENT_DEVICE: DeviceId = DeviceId::from_bytes([0x94; 32]);
const CLIENT_ADDR: ScopedVirtualAddr = ScopedVirtualAddr::Client {
    app: CLIENT_APP,
    device: CLIENT_DEVICE,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_socket_preserves_message_boundaries_over_forced_relay() -> Result<()> {
    let mut relay_config = ServerConfig::default();
    relay_config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let relay = RelayServer::spawn(relay_config).await?;
    let relay_url: RelayUrl = format!(
        "http://{}",
        relay.http_addr().context("relay missing HTTP listener")?
    )
    .parse()?;

    let client_key = SecretKey::generate();
    let wrong_key = SecretKey::generate();
    let server_addr = ServerAddr::new(SERVER_APP);
    let mut server_config = NodeConfig::new(
        SecretKey::generate(),
        Some(relay_url.clone()),
        NETWORK,
        LocalBindings::new([LocalBinding::Server(server_addr)])?,
        [
            (client_key.public(), CLIENT_ADDR),
            (wrong_key.public(), CLIENT_ADDR),
        ],
    );
    server_config.enable_direct_paths = false;
    let mut server = WeaverEndpoint::bind(server_config).await?;
    server.wait_relay_online(Duration::from_secs(10)).await?;
    let target = server.descriptor(SERVER_APP).relay_only();
    let mut listener = server.take_udp_listener(server_addr)?;

    let wrong_source = ClientAddr::new(CLIENT_APP, DeviceId::from_bytes([0xee; 32]));
    let mut wrong_config = NodeConfig::new(
        wrong_key,
        Some(relay_url.clone()),
        NETWORK,
        LocalBindings::new([LocalBinding::Client(wrong_source)])?,
        std::iter::empty(),
    );
    wrong_config.enable_direct_paths = false;
    let wrong = WeaverEndpoint::bind(wrong_config).await?;
    wrong.wait_relay_online(Duration::from_secs(10)).await?;
    assert!(matches!(
        wrong.connect_udp(wrong_source, &target).await,
        Err(NetworkError::OpenRejected("not authorized"))
    ));
    wrong.close().await;

    let source = ClientAddr::new(CLIENT_APP, CLIENT_DEVICE);
    let mut client_config = NodeConfig::new(
        client_key,
        Some(relay_url),
        NETWORK,
        LocalBindings::new([LocalBinding::Client(source)])?,
        std::iter::empty(),
    );
    client_config.enable_direct_paths = false;
    let client = WeaverEndpoint::bind(client_config).await?;
    client.wait_relay_online(Duration::from_secs(10)).await?;

    let server_task = tokio::spawn(async move {
        let mut socket = listener.accept().await?;
        for expected in [b"one".as_slice(), b"two-two".as_slice(), &[0x5a; 900][..]] {
            let received = socket.recv().await?;
            assert_eq!(received.as_ref(), expected);
            socket.send(received)?;
        }
        assert_eq!(socket.recv().await?.as_ref(), b"done");
        Ok::<_, std::io::Error>(())
    });

    let mut socket = client.connect_udp(source, &target).await?;
    let maximum = socket
        .max_datagram_size()
        .context("QUIC datagrams unexpectedly disabled")?;
    assert_eq!(
        socket.send(vec![0_u8; maximum + 1]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        socket
            .send_to(
                b"wrong target".to_vec(),
                ScopedVirtualAddr::Server {
                    app: AppAddr::from_bytes([0xff; 32]),
                },
            )
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    for message in [b"one".as_slice(), b"two-two".as_slice(), &[0x5a; 900][..]] {
        socket.send_to(
            message.to_vec(),
            ScopedVirtualAddr::Server { app: SERVER_APP },
        )?;
        let (echoed, source) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from()).await??;
        assert_eq!(echoed.as_ref(), message);
        assert_eq!(source, ScopedVirtualAddr::Server { app: SERVER_APP });
    }
    socket.send(b"done".to_vec())?;
    server_task.await??;

    client.close().await;
    server.close().await;
    relay.shutdown().await?;
    Ok(())
}
