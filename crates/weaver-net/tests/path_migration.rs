use std::{net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result};
use iroh::{RelayUrl, SecretKey};
use iroh_relay::server::{RelayConfig, Server as RelayServer, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use weaver_core::{AppAddr, ClientAddr, DeviceId, NetworkId, ScopedVirtualAddr, ServerAddr};
use weaver_net::{LocalBinding, LocalBindings, NodeConfig, TransportPathKind, WeaverEndpoint};

const NETWORK: NetworkId = NetworkId::from_bytes([0x81; 32]);
const SERVER_APP: AppAddr = AppAddr::from_bytes([0x82; 32]);
const CLIENT_APP: AppAddr = AppAddr::from_bytes([0x83; 32]);
const CLIENT_DEVICE: DeviceId = DeviceId::from_bytes([0x84; 32]);
const CLIENT_ADDR: ScopedVirtualAddr = ScopedVirtualAddr::Client {
    app: CLIENT_APP,
    device: CLIENT_DEVICE,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn existing_reliable_stream_moves_from_relay_bootstrap_to_direct_path() -> Result<()> {
    let mut relay_config = ServerConfig::default();
    relay_config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let relay = RelayServer::spawn(relay_config).await?;
    let relay_url: RelayUrl = format!(
        "http://{}",
        relay.http_addr().context("relay missing HTTP listener")?
    )
    .parse()?;

    let client_key = SecretKey::generate();
    let server_addr = ServerAddr::new(SERVER_APP);
    let mut server = WeaverEndpoint::bind(NodeConfig::new(
        SecretKey::generate(),
        Some(relay_url.clone()),
        NETWORK,
        LocalBindings::new([LocalBinding::Server(server_addr)])?,
        [(client_key.public(), CLIENT_ADDR)],
    ))
    .await?;
    server.wait_relay_online(Duration::from_secs(10)).await?;
    // The descriptor intentionally withholds direct addresses. The first packets can
    // only bootstrap through B; endpoint address exchange may then add an IP path.
    let target = server.descriptor(SERVER_APP).relay_only();
    let mut listener = server.take_tcp_listener(server_addr)?;
    let source = ClientAddr::new(CLIENT_APP, CLIENT_DEVICE);
    let client = WeaverEndpoint::bind(NodeConfig::new(
        client_key,
        Some(relay_url),
        NETWORK,
        LocalBindings::new([LocalBinding::Client(source)])?,
        std::iter::empty(),
    ))
    .await?;
    client.wait_relay_online(Duration::from_secs(10)).await?;

    let server_task = tokio::spawn(async move {
        let mut stream = listener.accept().await?;
        let mut first = [0_u8; 12];
        stream.read_exact(&mut first).await?;
        assert_eq!(&first, b"before-move!");
        stream.write_all(b"first-ok").await?;
        let mut second = [0_u8; 11];
        stream.read_exact(&mut second).await?;
        assert_eq!(&second, b"after-move!");
        stream.write_all(b"second-ok").await?;
        stream.finish_and_wait().await?;
        Ok::<_, std::io::Error>(())
    });

    let mut stream = client.connect(source, &target).await?;
    let connection_peer = stream.peer_endpoint_id();
    stream.write_all(b"before-move!").await?;
    let mut ack = [0_u8; 8];
    stream.read_exact(&mut ack).await?;
    assert_eq!(&ack, b"first-ok");

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if stream
                .transport_paths()
                .iter()
                .any(|path| path.selected && path.kind == TransportPathKind::Direct)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .context("connection never selected its discovered direct path")?;

    // The application object and authenticated peer are unchanged across path selection.
    assert_eq!(stream.peer_endpoint_id(), connection_peer);
    stream.write_all(b"after-move!").await?;
    let mut second_ack = [0_u8; 9];
    stream.read_exact(&mut second_ack).await?;
    assert_eq!(&second_ack, b"second-ok");
    stream.shutdown().await?;
    server_task.await??;

    client.close().await;
    server.close().await;
    relay.shutdown().await?;
    Ok(())
}
