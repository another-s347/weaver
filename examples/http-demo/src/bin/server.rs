use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use weaver_core::{AppAddr, ServerAddr, VirtualName};
use weaver_crypto::NetworkRootPublic;
use weaver_http_demo::{
    DEFAULT_VIRTUAL_HOST, demo_router, production_open_options, spawn_http_server,
};
use weaver_net::NetworkHandle;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(about = "Serve HTTP/1.1, HTTP/2 and WebSocket over a Weaver virtual host")]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    root_public_key: String,
    #[arg(long)]
    app_addr: AppAddr,
    #[arg(long, default_value = DEFAULT_VIRTUAL_HOST)]
    host: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let root = parse_root(&args.root_public_key)?;
    let options = production_open_options(root, &args.data_dir, read_key(&args.master_key_file)?)?;
    let mut network = NetworkHandle::open_server(options, ServerAddr::new(args.app_addr)).await?;
    let name = VirtualName::new(args.host.clone())?;
    let resolved = network.resolve_name(&name)?;
    if resolved.app() != args.app_addr {
        anyhow::bail!(
            "virtual DNS name {} resolves to {}, not this server's {}",
            name,
            resolved.app(),
            args.app_addr
        );
    }
    let listener = network.take_tcp_listener()?;
    let server = spawn_http_server(listener, demo_router());

    println!("network_id={}", network.network_id());
    println!("http_url=http://{}/", args.host);
    println!("websocket_url=ws://{}/ws", args.host);
    tokio::signal::ctrl_c().await?;
    server.shutdown().await?;
    network.close().await;
    Ok(())
}

fn parse_root(value: &str) -> Result<NetworkRootPublic> {
    let bytes = hex::decode(value).context("root public key is not hexadecimal")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("root public key must contain exactly 32 bytes"))?;
    Ok(NetworkRootPublic::from_bytes(&bytes)?)
}

fn read_key(path: &std::path::Path) -> Result<[u8; 32]> {
    let bytes = Zeroizing::new(
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?,
    );
    bytes
        .as_slice()
        .try_into()
        .context("master key file must contain exactly 32 bytes")
}
