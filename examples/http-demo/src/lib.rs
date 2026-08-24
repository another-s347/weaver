use std::{
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Extension, WebSocketUpgrade, ws::Message},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{StreamExt, stream};
use http_body_util::Full;
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection},
    },
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
    service::TowerToHyperService,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
};
use tower::Service;
use weaver_core::{VirtualName, VirtualNameError};
use weaver_crypto::NetworkRootPublic;
use weaver_net::{NetworkHandle, PeerConnectInfo, VirtualTcpListener, VirtualTcpStream};
use weaver_store::{EncryptedFileSecretStore, RedbStateStore};

pub const DEFAULT_VIRTUAL_HOST: &str = "weaver.virtual";

#[derive(Debug, thiserror::Error)]
pub enum OpenOptionsError {
    #[error(transparent)]
    State(#[from] weaver_store::StoreError),
    #[error(transparent)]
    Secret(#[from] weaver_store::SecretStoreError),
}

pub fn production_open_options(
    root: NetworkRootPublic,
    data_dir: &std::path::Path,
    master_key: [u8; 32],
) -> Result<weaver_net::NetworkHandleOpenOptions, OpenOptionsError> {
    Ok(weaver_net::NetworkHandleOpenOptions {
        root,
        state_store: Arc::new(RedbStateStore::open(data_dir.join("state.redb"))?),
        secret_store: Arc::new(EncryptedFileSecretStore::open(
            data_dir.join("secrets"),
            master_key,
        )?),
        config_sync: Default::default(),
        presence_sync: Default::default(),
        allow_insecure_test_stores: false,
    })
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VirtualHttpUriError {
    #[error(transparent)]
    InvalidName(#[from] VirtualNameError),
    #[error("virtual HTTP URI must use http or ws")]
    UnsupportedScheme,
    #[error("virtual HTTP URI is missing a host")]
    MissingHost,
    #[error("virtual HTTP URI must not contain a TCP port")]
    PortNotSupported,
}

fn virtual_name_from_uri(uri: &Uri) -> Result<VirtualName, VirtualHttpUriError> {
    if !matches!(uri.scheme_str(), Some("http" | "ws")) {
        return Err(VirtualHttpUriError::UnsupportedScheme);
    }
    if uri.port().is_some() {
        return Err(VirtualHttpUriError::PortNotSupported);
    }
    let host = uri.host().ok_or(VirtualHttpUriError::MissingHost)?;
    Ok(VirtualName::new(host)?)
}

#[derive(Clone)]
pub struct WeaverHttpConnector {
    network: Arc<NetworkHandle>,
}

#[derive(Debug)]
pub struct WeaverHttpConnection(VirtualTcpStream);

impl Connection for WeaverHttpConnection {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AsyncRead for WeaverHttpConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for WeaverHttpConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl WeaverHttpConnector {
    pub fn new(network: Arc<NetworkHandle>) -> Self {
        Self { network }
    }

    pub fn network(&self) -> &Arc<NetworkHandle> {
        &self.network
    }

    async fn connect_uri(&self, uri: Uri) -> io::Result<TokioIo<WeaverHttpConnection>> {
        let name = virtual_name_from_uri(&uri)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.network
            .connect_tcp_name(&name)
            .await
            .map(|stream| TokioIo::new(WeaverHttpConnection(stream)))
            .map_err(io::Error::other)
    }
}

impl Service<Uri> for WeaverHttpConnector {
    type Response = TokioIo<WeaverHttpConnection>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = self.clone();
        Box::pin(async move { connector.connect_uri(uri).await })
    }
}

pub type WeaverHttpClient = Client<WeaverHttpConnector, Full<Bytes>>;

pub fn http1_client(connector: WeaverHttpConnector) -> WeaverHttpClient {
    Client::builder(TokioExecutor::new()).build(connector)
}

pub fn http2_client(connector: WeaverHttpConnector) -> WeaverHttpClient {
    Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build(connector)
}

pub async fn connect_websocket(
    network: Arc<NetworkHandle>,
    uri: Uri,
) -> Result<
    (
        tokio_tungstenite::WebSocketStream<VirtualTcpStream>,
        http::Response<Option<Vec<u8>>>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let name = virtual_name_from_uri(&uri)?;
    let stream = network.connect_tcp_name(&name).await?;
    let (socket, response) = tokio_tungstenite::client_async(uri.to_string(), stream).await?;
    Ok((socket, response))
}

pub fn demo_router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/echo", post(echo))
        .route("/stream", get(streaming))
        .route("/ws", get(websocket))
}

async fn index(
    headers: HeaderMap,
    Extension(peer): Extension<PeerConnectInfo>,
) -> impl IntoResponse {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("missing");
    let mut response = format!("host={host}\npeer={}\n", peer.endpoint_id).into_response();
    response
        .headers_mut()
        .insert("x-weaver-http", HeaderValue::from_static("virtual"));
    response
}

async fn echo(headers: HeaderMap, body: Bytes) -> Response {
    let mut response = body.into_response();
    *response.status_mut() = StatusCode::CREATED;
    if let Some(value) = headers.get("x-echo-token") {
        response.headers_mut().insert("x-echo-token", value.clone());
    }
    response
}

async fn streaming() -> Response {
    let chunks = ["weaver-", "http-", "stream"]
        .into_iter()
        .map(|chunk| Ok::<_, Infallible>(Bytes::from_static(chunk.as_bytes())));
    Response::new(Body::from_stream(stream::iter(chunks)))
}

async fn websocket(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|mut socket| async move {
        while let Some(result) = socket.next().await {
            match result {
                Ok(Message::Text(text)) => {
                    if socket.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Binary(bytes)) => {
                    if socket.send(Message::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(frame)) => {
                    let _ = socket.send(Message::Close(frame)).await;
                    break;
                }
                Ok(Message::Ping(_) | Message::Pong(_)) => {}
                Err(_) => break,
            }
        }
    })
}

pub struct HttpServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

impl HttpServerHandle {
    pub async fn shutdown(mut self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.map_err(io::Error::other)?
    }
}

pub fn spawn_http_server(mut listener: VirtualTcpListener, router: Router) -> HttpServerHandle {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let stream = accepted.map_err(io::Error::other)?;
                    let peer = PeerConnectInfo {
                        endpoint_id: stream.peer_endpoint_id(),
                        virtual_addr: stream.peer_addr(),
                    };
                    let service = router.clone().layer(Extension(peer));
                    connections.spawn(async move {
                        ServerBuilder::new(TokioExecutor::new())
                            .serve_connection_with_upgrades(
                                TokioIo::new(stream),
                                TowerToHyperService::new(service),
                            )
                            .await
                            .map_err(io::Error::other)
                    });
                }
            }
        }
        connections.abort_all();
        while let Some(result) = connections.join_next().await {
            match result {
                Ok(Ok(())) | Err(_) => {}
                Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {}
                Ok(Err(error)) => return Err(error),
            }
        }
        Ok(())
    });
    HttpServerHandle {
        shutdown: Some(shutdown_tx),
        task,
    }
}

pub fn virtual_uri(scheme: &str, alias: &str, path: &str) -> Result<Uri, http::Error> {
    Uri::builder()
        .scheme(scheme)
        .authority(alias)
        .path_and_query(path)
        .build()
}
