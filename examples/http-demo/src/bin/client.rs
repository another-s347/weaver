use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use clap::{Parser, Subcommand, ValueEnum};
use futures_util::{SinkExt, StreamExt};
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use tokio_tungstenite::tungstenite::Message;
use weaver_core::{AppAddr, ClientAddr, DeviceId};
use weaver_crypto::NetworkRootPublic;
use weaver_http_demo::{
    DEFAULT_VIRTUAL_HOST, WeaverHttpConnector, connect_websocket, http1_client, http2_client,
    production_open_options, virtual_uri,
};
use weaver_net::NetworkHandle;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(about = "Call a readable Weaver virtual host without DNS or IP addresses")]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    root_public_key: String,
    #[arg(long)]
    client_app: AppAddr,
    #[arg(long)]
    device_id: DeviceId,
    #[arg(long, default_value = DEFAULT_VIRTUAL_HOST)]
    host: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Get {
        #[arg(long, default_value = "/")]
        path: String,
        #[arg(long, value_enum, default_value = "http1")]
        version: HttpVersion,
    },
    Post {
        #[arg(long, default_value = "/echo")]
        path: String,
        #[arg(long)]
        body: String,
        #[arg(long, value_enum, default_value = "http1")]
        version: HttpVersion,
    },
    Websocket {
        #[arg(long, default_value = "hello over Weaver WebSocket")]
        message: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum HttpVersion {
    Http1,
    Http2,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let root = parse_root(&args.root_public_key)?;
    let options = production_open_options(root, &args.data_dir, read_key(&args.master_key_file)?)?;
    let network = Arc::new(
        NetworkHandle::open_client(options, ClientAddr::new(args.client_app, args.device_id))
            .await?,
    );
    match args.command {
        Command::Get { path, version } => {
            request(network.clone(), &args.host, path, version, Method::GET, "").await?;
        }
        Command::Post {
            path,
            body,
            version,
        } => {
            request(
                network.clone(),
                &args.host,
                path,
                version,
                Method::POST,
                &body,
            )
            .await?;
        }
        Command::Websocket { message } => {
            let uri = virtual_uri("ws", &args.host, "/ws")?;
            let (mut socket, response) = connect_websocket(network.clone(), uri)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!("status={}", response.status());
            socket.send(Message::Text(message.clone().into())).await?;
            match socket.next().await.transpose()? {
                Some(Message::Text(echoed)) if echoed == message => println!("echo={echoed}"),
                other => bail!("unexpected WebSocket response: {other:?}"),
            }
            socket.close(None).await?;
        }
    }

    let network =
        Arc::try_unwrap(network).map_err(|_| anyhow::anyhow!("network is still in use"))?;
    network.close().await;
    Ok(())
}

async fn request(
    network: Arc<NetworkHandle>,
    host: &str,
    path: String,
    version: HttpVersion,
    method: Method,
    body: &str,
) -> Result<()> {
    let connector = WeaverHttpConnector::new(network);
    let client = match version {
        HttpVersion::Http1 => http1_client(connector),
        HttpVersion::Http2 => http2_client(connector),
    };
    let request = Request::builder()
        .method(method)
        .uri(virtual_uri("http", host, &path)?)
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))?;
    let response = client.request(request).await?;
    println!("status={}", response.status());
    println!("version={:?}", response.version());
    let body = response.into_body().collect().await?.to_bytes();
    println!("body={}", String::from_utf8_lossy(&body));
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
