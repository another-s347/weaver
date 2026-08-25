use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hyper_util::rt::TokioIo;
use iroh::RelayUrl;
use tonic::transport::Endpoint;
use tower::service_fn;
use tracing_subscriber::EnvFilter;
use weaver_net::{NodeConfig, PeerDescriptor, WeaverEndpoint};
use weaver_tonic_demo::{
    DEMO_CLIENT_APP_ADDR, DEMO_CLIENT_DEVICE_ID, DEMO_NETWORK_ID, load_or_create_dev_identity,
    proto::{EchoRequest, echo_client::EchoClient},
};

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Identity {
        #[arg(long, default_value = ".weaver/client.key")]
        identity: PathBuf,
    },
    Call {
        #[arg(long, default_value = ".weaver/client.key")]
        identity: PathBuf,
        #[arg(long)]
        relay_url: RelayUrl,
        #[arg(long, default_value = ".weaver/server.endpoint.json")]
        descriptor: PathBuf,
        #[arg(long, default_value = "hello over Weaver")]
        message: String,
        /// Remove direct candidates to prove the C -> B -> A path.
        #[arg(long)]
        relay_only: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    match Args::parse().command {
        Command::Identity { identity } => {
            let key = load_or_create_dev_identity(&identity)
                .with_context(|| format!("failed to load {}", identity.display()))?;
            println!("client_endpoint_id={}", key.public());
        }
        Command::Call {
            identity,
            relay_url,
            descriptor,
            message,
            relay_only,
        } => {
            let key = load_or_create_dev_identity(&identity)
                .with_context(|| format!("failed to load {}", identity.display()))?;
            eprintln!("WARNING: demo identity is plaintext mode-0600, not production SecretStore");
            let source = weaver_core::ClientAddr::new(DEMO_CLIENT_APP_ADDR, DEMO_CLIENT_DEVICE_ID);
            let mut node_config = NodeConfig::new(
                key,
                Some(relay_url),
                DEMO_NETWORK_ID,
                weaver_net::LocalBindings::new([weaver_net::LocalBinding::Client(source)])?,
                std::iter::empty(),
            );
            node_config.enable_direct_paths = !relay_only;
            let endpoint = WeaverEndpoint::bind(node_config).await?;
            endpoint.wait_relay_online(Duration::from_secs(10)).await?;

            let bytes = std::fs::read(&descriptor)
                .with_context(|| format!("failed to read {}", descriptor.display()))?;
            let target: PeerDescriptor = serde_json::from_slice(&bytes)?;
            let target = if relay_only {
                target.relay_only()
            } else {
                target
            };
            let dialer = endpoint.dialer();
            let connector_target = target.clone();
            let channel = Endpoint::from_static("http://weaver.virtual")
                .connect_with_connector(service_fn(move |_| {
                    let dialer = dialer.clone();
                    let target = connector_target.clone();
                    async move {
                        dialer
                            .connect(source, &target)
                            .await
                            .map(TokioIo::new)
                            .map_err(std::io::Error::other)
                    }
                }))
                .await
                .context("failed to establish tonic channel over Weaver")?;

            let mut client = EchoClient::new(channel);
            let response = client.echo(EchoRequest { message }).await?.into_inner();
            println!("echo={}", response.message);
            println!("server_endpoint_id={}", response.server_endpoint_id);
            endpoint.close().await;
        }
    }
    Ok(())
}
