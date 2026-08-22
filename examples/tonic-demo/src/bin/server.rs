use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use iroh::{EndpointId, RelayUrl};
use tonic::{Request, Response, Status, transport::Server};
use tracing::info;
use tracing_subscriber::EnvFilter;
use weaver_net::{NodeConfig, PeerConnectInfo, WeaverEndpoint};
use weaver_tonic_demo::{
    DEMO_APP_ADDR, DEMO_CLIENT_ADDR, DEMO_NETWORK_ID, load_or_create_dev_identity,
    proto::{
        EchoReply, EchoRequest,
        echo_server::{Echo, EchoServer},
    },
};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = ".weaver/server.key")]
    identity: PathBuf,
    #[arg(long)]
    relay_url: RelayUrl,
    #[arg(long, default_value = ".weaver/server.endpoint.json")]
    descriptor: PathBuf,
    /// Development allowlist. Repeat for each permitted tonic client.
    #[arg(long, required = true)]
    allow_client: Vec<EndpointId>,
}

#[derive(Debug)]
struct EchoService {
    server_endpoint_id: EndpointId,
}

#[tonic::async_trait]
impl Echo for EchoService {
    async fn echo(&self, request: Request<EchoRequest>) -> Result<Response<EchoReply>, Status> {
        let peer = request
            .extensions()
            .get::<PeerConnectInfo>()
            .map(|info| info.endpoint_id.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        info!(%peer, message = %request.get_ref().message, "received tonic request");
        Ok(Response::new(EchoReply {
            message: request.into_inner().message,
            server_endpoint_id: self.server_endpoint_id.to_string(),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let secret_key = load_or_create_dev_identity(&args.identity)
        .with_context(|| format!("failed to load {}", args.identity.display()))?;
    eprintln!("WARNING: demo identity is plaintext mode-0600, not production SecretStore");

    let config = NodeConfig::tonic_server(
        secret_key,
        Some(args.relay_url),
        DEMO_NETWORK_ID,
        DEMO_APP_ADDR,
        args.allow_client
            .into_iter()
            .map(|endpoint_id| (endpoint_id, DEMO_CLIENT_ADDR)),
    );
    let mut endpoint = WeaverEndpoint::bind(config).await?;
    endpoint.wait_relay_online(Duration::from_secs(10)).await?;

    let descriptor = endpoint.descriptor(DEMO_APP_ADDR);
    if let Some(parent) = args.descriptor.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.descriptor, serde_json::to_vec_pretty(&descriptor)?)?;
    println!("server_endpoint_id={}", endpoint.id());
    println!("descriptor={}", args.descriptor.display());

    let incoming = endpoint.take_tcp_listener()?;
    let service = EchoService {
        server_endpoint_id: endpoint.id(),
    };
    Server::builder()
        .add_service(EchoServer::new(service))
        .serve_with_incoming_shutdown(incoming, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("tonic server failed")?;
    endpoint.close().await;
    Ok(())
}
