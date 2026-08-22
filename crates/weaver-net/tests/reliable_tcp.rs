use std::{net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result};
use iroh::{RelayUrl, SecretKey};
use iroh_relay::server::{RelayConfig, Server as RelayServer, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use weaver_core::{AppAddr, DeviceId, NetworkId, ScopedVirtualAddr};
use weaver_net::{NetworkError, NodeConfig, WeaverEndpoint};

const TEST_APP_ADDR: AppAddr = AppAddr::from_bytes([0x54; 32]);
const TEST_NETWORK_ID: NetworkId = NetworkId::from_bytes([0x4e; 32]);
const OTHER_NETWORK_ID: NetworkId = NetworkId::from_bytes([0x99; 32]);
const TEST_CLIENT_APP_ADDR: AppAddr = AppAddr::from_bytes([0x43; 32]);
const TEST_CLIENT_DEVICE_ID: DeviceId = DeviceId::from_bytes([0x44; 32]);
const TEST_CLIENT_ADDR: ScopedVirtualAddr = ScopedVirtualAddr::Client {
    app: TEST_CLIENT_APP_ADDR,
    device: TEST_CLIENT_DEVICE_ID,
};
const PAYLOAD_LEN: usize = 8 * 1024 * 1024 + 137;

fn deterministic_payload() -> Vec<u8> {
    (0..PAYLOAD_LEN)
        .map(|index| {
            let index = index as u64;
            (index.wrapping_mul(31).wrapping_add(index / 251) & 0xff) as u8
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reliable_stream_preserves_bytes_order_and_half_close_over_relay() -> Result<()> {
    let mut relay_config = ServerConfig::default();
    relay_config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let relay = RelayServer::spawn(relay_config).await?;
    let relay_url: RelayUrl = format!(
        "http://{}",
        relay.http_addr().context("relay missing HTTP listener")?
    )
    .parse()?;

    let client_key = SecretKey::generate();
    let wrong_device_key = SecretKey::generate();
    let wrong_network_key = SecretKey::generate();
    let mut server_config = NodeConfig::tcp_server(
        SecretKey::generate(),
        Some(relay_url.clone()),
        TEST_NETWORK_ID,
        TEST_APP_ADDR,
        [
            (client_key.public(), TEST_CLIENT_ADDR),
            (wrong_device_key.public(), TEST_CLIENT_ADDR),
            (wrong_network_key.public(), TEST_CLIENT_ADDR),
        ],
    );
    server_config.enable_direct_paths = false;
    let mut server = WeaverEndpoint::bind(server_config).await?;
    server.wait_relay_online(Duration::from_secs(10)).await?;
    let target = server.descriptor(TEST_APP_ADDR).relay_only();
    let mut listener = server.take_tcp_listener()?;

    let mut client_config = NodeConfig::client(
        client_key,
        Some(relay_url),
        TEST_NETWORK_ID,
        TEST_CLIENT_APP_ADDR,
        TEST_CLIENT_DEVICE_ID,
    );
    client_config.enable_direct_paths = false;
    let client = WeaverEndpoint::bind(client_config).await?;
    client.wait_relay_online(Duration::from_secs(10)).await?;

    let mut other_network_target = target.clone();
    other_network_target.network_id = OTHER_NETWORK_ID;
    assert!(matches!(
        client.connect(&other_network_target).await,
        Err(NetworkError::NetworkMismatch { .. })
    ));

    let mut wrong_device_config = NodeConfig::client(
        wrong_device_key,
        target.relay_url.clone(),
        TEST_NETWORK_ID,
        TEST_CLIENT_APP_ADDR,
        DeviceId::from_bytes([0xee; 32]),
    );
    wrong_device_config.enable_direct_paths = false;
    let wrong_device = WeaverEndpoint::bind(wrong_device_config).await?;
    wrong_device
        .wait_relay_online(Duration::from_secs(10))
        .await?;
    let wrong_device_error = wrong_device.connect(&target).await.unwrap_err();
    assert!(
        matches!(
            wrong_device_error,
            NetworkError::OpenRejected("not authorized")
        ),
        "unexpected wrong-device error: {wrong_device_error:?}"
    );
    wrong_device.close().await;

    let mut wrong_network_config = NodeConfig::client(
        wrong_network_key,
        target.relay_url.clone(),
        OTHER_NETWORK_ID,
        TEST_CLIENT_APP_ADDR,
        TEST_CLIENT_DEVICE_ID,
    );
    wrong_network_config.enable_direct_paths = false;
    let wrong_network = WeaverEndpoint::bind(wrong_network_config).await?;
    wrong_network
        .wait_relay_online(Duration::from_secs(10))
        .await?;
    let wrong_network_error = wrong_network
        .connect(&other_network_target)
        .await
        .unwrap_err();
    assert!(
        matches!(
            wrong_network_error,
            NetworkError::OpenRejected("network mismatch")
        ),
        "unexpected wrong-network error: {wrong_network_error:?}"
    );
    wrong_network.close().await;

    let expected = deterministic_payload();
    let server_expected = expected.clone();
    let server_task = tokio::spawn(async move {
        let mut stream = listener.accept().await?;

        // A true TCP-style accept cannot depend on the client sending application data.
        // Exercise a server-first protocol before the client writes any payload bytes.
        stream.write_all(b"server ready").await?;

        let mut received = Vec::new();
        stream.read_to_end(&mut received).await?;
        assert_eq!(received.len(), PAYLOAD_LEN);
        assert_eq!(
            received, server_expected,
            "stream reordered or corrupted bytes"
        );

        stream.write_all(b"all bytes received in order").await?;
        stream.finish_and_wait().await?;
        Ok::<_, std::io::Error>(())
    });

    let mut stream = client.connect(&target).await?;
    let mut greeting = [0; 12];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(&greeting, b"server ready");

    // Deliberately use irregular write boundaries. The receiver must observe one exact,
    // ordered byte sequence independent of packetization and relay framing.
    let mut offset = 0;
    let mut chunk_len = 1;
    while offset < expected.len() {
        let end = (offset + chunk_len).min(expected.len());
        stream.write_all(&expected[offset..end]).await?;
        offset = end;
        chunk_len = (chunk_len * 17 + 23) % 65_521 + 1;
    }
    stream.shutdown().await?;

    // A write-half close must not close the read half: the server can reply after EOF.
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    assert_eq!(response, b"all bytes received in order");
    let write_after_shutdown = stream.write_all(b"must fail").await.unwrap_err();
    assert_eq!(write_after_shutdown.kind(), std::io::ErrorKind::BrokenPipe);

    server_task.await??;
    client.close().await;
    server.close().await;
    relay.shutdown().await?;
    Ok(())
}
