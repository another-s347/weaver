use std::{net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result};
use hyper_util::rt::TokioIo;
use iroh::{RelayUrl, SecretKey};
use iroh_relay::server::{RelayConfig, Server as RelayServer, ServerConfig};
use tokio::sync::oneshot;
use tonic::{Request, Response, Status, transport::Endpoint};
use tower::service_fn;
use weaver_core::{ClientAddr, ServerAddr};
use weaver_net::{LocalBinding, LocalBindings, NodeConfig, PeerConnectInfo, WeaverEndpoint};
use weaver_tonic_demo::{
    DEMO_APP_ADDR, DEMO_CLIENT_ADDR, DEMO_CLIENT_APP_ADDR, DEMO_CLIENT_DEVICE_ID, DEMO_NETWORK_ID,
    proto::{
        EchoReply, EchoRequest,
        echo_client::EchoClient,
        echo_server::{Echo, EchoServer},
    },
};

#[derive(Debug)]
struct TestEcho {
    server_id: iroh::EndpointId,
    expected_client_id: iroh::EndpointId,
}

#[tonic::async_trait]
impl Echo for TestEcho {
    async fn echo(&self, request: Request<EchoRequest>) -> Result<Response<EchoReply>, Status> {
        let peer = request
            .extensions()
            .get::<PeerConnectInfo>()
            .ok_or_else(|| Status::unauthenticated("missing authenticated endpoint identity"))?;
        if peer.endpoint_id != self.expected_client_id {
            return Err(Status::permission_denied(
                "unexpected client endpoint identity",
            ));
        }
        if peer.virtual_addr != DEMO_CLIENT_ADDR {
            return Err(Status::permission_denied(
                "unexpected authenticated client virtual address",
            ));
        }
        Ok(Response::new(EchoReply {
            message: request.get_ref().message.clone(),
            server_endpoint_id: self.server_id.to_string(),
        }))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tonic_rpc_runs_over_forced_relay_path() -> Result<()> {
    let mut relay_config = ServerConfig::default();
    relay_config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let relay = RelayServer::spawn(relay_config).await?;
    let relay_url: RelayUrl = format!(
        "http://{}",
        relay.http_addr().context("relay missing HTTP listener")?
    )
    .parse()?;

    let client_key = SecretKey::generate();
    let server_addr = ServerAddr::new(DEMO_APP_ADDR);
    let mut server_config = NodeConfig::new(
        SecretKey::generate(),
        Some(relay_url.clone()),
        DEMO_NETWORK_ID,
        LocalBindings::new([LocalBinding::Server(server_addr)])?,
        [(client_key.public(), DEMO_CLIENT_ADDR)],
    );
    server_config.enable_direct_paths = false;
    let mut server_endpoint = WeaverEndpoint::bind(server_config).await?;
    server_endpoint
        .wait_relay_online(Duration::from_secs(10))
        .await?;
    let server_id = server_endpoint.id();
    let expected_client_id = client_key.public();
    let target = server_endpoint.descriptor(DEMO_APP_ADDR).relay_only();
    let incoming = server_endpoint.take_tcp_listener(server_addr)?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let tonic_server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(EchoServer::new(TestEcho {
                server_id,
                expected_client_id,
            }))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let source = ClientAddr::new(DEMO_CLIENT_APP_ADDR, DEMO_CLIENT_DEVICE_ID);
    let mut client_config = NodeConfig::new(
        client_key,
        Some(relay_url),
        DEMO_NETWORK_ID,
        LocalBindings::new([LocalBinding::Client(source)])?,
        std::iter::empty(),
    );
    client_config.enable_direct_paths = false;
    let client_endpoint = WeaverEndpoint::bind(client_config).await?;
    client_endpoint
        .wait_relay_online(Duration::from_secs(10))
        .await?;
    let dialer = client_endpoint.dialer();
    let channel = Endpoint::from_static("http://weaver.virtual")
        .connect_with_connector(service_fn(move |_| {
            let dialer = dialer.clone();
            let target = target.clone();
            async move {
                dialer
                    .connect(source, &target)
                    .await
                    .map(TokioIo::new)
                    .map_err(std::io::Error::other)
            }
        }))
        .await?;

    let mut client = EchoClient::new(channel);
    let response = client
        .echo(EchoRequest {
            message: "A/B/C relay test".into(),
        })
        .await?
        .into_inner();
    assert_eq!(response.message, "A/B/C relay test");
    assert_eq!(response.server_endpoint_id, server_id.to_string());

    drop(client);
    client_endpoint.close().await;
    let _ = shutdown_tx.send(());
    tonic_server.await??;
    server_endpoint.close().await;
    relay.shutdown().await?;
    Ok(())
}
