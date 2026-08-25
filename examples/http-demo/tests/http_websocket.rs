use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::body::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{Method, Request, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use iroh::RelayUrl;
use iroh_relay::server::{RelayConfig, Server as RelayServer, ServerConfig};
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;
use weaver_config::MemberEncryptionKeypair;
use weaver_core::{ClientAddr, ServerAddr, VirtualName};
use weaver_crypto::{
    AppBinding, AppRegistrationRequest, AppRole, AppRootKey, MemberCertificate, MemberRoles,
    NetworkRootPublic, derive_device_id,
};
use weaver_http_demo::{
    DEFAULT_VIRTUAL_HOST, WeaverHttpConnector, connect_websocket, demo_router, http1_client,
    http2_client, spawn_http_server, virtual_uri,
};
use weaver_net::{
    MembershipStores, NetworkHandle, NetworkHandleOpenOptions, NetworkMembership, member_secret_id,
};
use weaver_relay_core::{Authority, AuthorityInit};
use weaver_store::{MemorySecretStore, MemoryStateStore, SecretStore};

struct JoinedMember {
    state: MemoryStateStore,
    secrets: MemorySecretStore,
    certificate: MemberCertificate,
    signing_public: [u8; 32],
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn readable_virtual_host_supports_http1_http2_streams_and_websocket() -> Result<()> {
    let mut relay_config = ServerConfig::default();
    relay_config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let relay = RelayServer::spawn(relay_config).await?;
    let relay_url: RelayUrl = format!(
        "http://{}",
        relay.http_addr().context("relay missing HTTP listener")?
    )
    .parse()?;

    let now = now_ms();
    let temp = tempfile::tempdir()?;
    let authority_dir = temp.path().join("authority");
    let initialized = Authority::initialize(AuthorityInit {
        data_dir: authority_dir.clone(),
        relay_url: relay_url.to_string(),
        now_ms: now,
        valid_for_ms: 60 * 60 * 1_000,
        master_key: [0x41; 32],
        recovery_root_out: None,
    })
    .await?;
    let root_key = weaver_crypto::NetworkRootKey::from_bytes(&initialized.recovery_root_bytes());
    let root = root_key.public();
    let network_id = root.network_id();
    let mut authority = Authority::open(authority_dir, [0x41; 32], now + 1).await?;

    let server_member = join_member(
        &mut authority,
        root.clone(),
        MemberRoles::MEMBER.union(MemberRoles::SERVICE),
        now + 2,
    )
    .await?;
    let client_member =
        join_member(&mut authority, root.clone(), MemberRoles::MEMBER, now + 3).await?;

    let server_app_root = AppRootKey::generate()?;
    let server_app = server_app_root.app_addr();
    authority
        .register_app(
            &AppRegistrationRequest::create(&server_app_root, network_id, 0),
            now + 4,
        )
        .await?;
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &server_app_root,
                network_id,
                server_member.certificate.payload().member_id,
                AppRole::Server,
                None,
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 5,
        )
        .await?;

    let client_app = server_app;
    let device = derive_device_id(network_id, client_app, &client_member.signing_public);
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &server_app_root,
                network_id,
                client_member.certificate.payload().member_id,
                AppRole::Client,
                Some(device),
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 6,
        )
        .await?;

    apply_updates(&authority, &server_member, &root, now + 7).await?;
    apply_updates(&authority, &client_member, &root, now + 7).await?;

    let server_addr = ServerAddr::new(server_app);
    let mut server = NetworkHandle::open(
        open_options(&server_member, root.clone()),
        [weaver_net::LocalBinding::Server(server_addr)],
    )
    .await?;
    let listener = server.take_tcp_listener(server_addr)?;
    let http_server = spawn_http_server(listener, demo_router());
    let client_network = Arc::new(
        NetworkHandle::open(
            open_options(&client_member, root),
            [weaver_net::LocalBinding::Client(ClientAddr::new(
                client_app, device,
            ))],
        )
        .await?,
    );
    let virtual_name = VirtualName::new(DEFAULT_VIRTUAL_HOST)?;
    let source = ClientAddr::new(client_app, device);
    let connector = WeaverHttpConnector::new(client_network.clone(), source);

    let unresolved = connector
        .clone()
        .oneshot(virtual_uri("http", DEFAULT_VIRTUAL_HOST, "/")?)
        .await
        .expect_err("unsigned local state unexpectedly resolved a virtual name");
    assert!(unresolved.to_string().contains(DEFAULT_VIRTUAL_HOST));

    let dns_now = now_ms();
    authority
        .set_virtual_dns(
            virtual_name.clone(),
            server_app,
            now + 30 * 60 * 1_000,
            dns_now,
        )
        .await?;
    let server_updates = authority
        .config_updates_after(server.config_head().await)
        .await?;
    server.apply_config_updates(&server_updates).await?;
    let client_updates = authority
        .config_updates_after(client_network.config_head().await)
        .await?;
    client_network.apply_config_updates(&client_updates).await?;
    assert_eq!(
        client_network.resolve_name(&virtual_name)?.app(),
        server_app
    );

    let http1 = http1_client(connector.clone());
    let index = Request::builder()
        .uri(virtual_uri("http", DEFAULT_VIRTUAL_HOST, "/")?)
        .body(Full::new(Bytes::new()))?;
    let response = tokio::time::timeout(Duration::from_secs(15), http1.request(index)).await??;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_11);
    assert_eq!(response.headers()["x-weaver-http"], "virtual");
    let body = response.into_body().collect().await?.to_bytes();
    let body = std::str::from_utf8(&body)?;
    assert!(body.contains("host=weaver.virtual"));
    assert!(body.contains(&client_network.endpoint_id().to_string()));

    let payload = Bytes::from(vec![0x5a; 1024 * 1024]);
    let echo = Request::builder()
        .method(Method::POST)
        .uri(virtual_uri("http", DEFAULT_VIRTUAL_HOST, "/echo")?)
        .header("x-echo-token", "signed-config")
        .body(Full::new(payload.clone()))?;
    let response = http1.request(echo).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-echo-token"], "signed-config");
    assert_eq!(response.into_body().collect().await?.to_bytes(), payload);

    let streaming = Request::builder()
        .uri(virtual_uri("http", DEFAULT_VIRTUAL_HOST, "/stream")?)
        .body(Full::new(Bytes::new()))?;
    let mut body = http1.request(streaming).await?.into_body();
    let mut chunks = 0_usize;
    let mut streamed = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            chunks += 1;
            streamed.extend_from_slice(&data);
        }
    }
    assert!(
        chunks >= 2,
        "streaming response was collapsed into one frame"
    );
    assert_eq!(streamed, b"weaver-http-stream");

    let http2 = http2_client(connector.clone());
    let h2 = Request::builder()
        .method(Method::POST)
        .uri(virtual_uri("http", DEFAULT_VIRTUAL_HOST, "/echo")?)
        .body(Full::new(Bytes::from_static(b"HTTP/2 over Weaver")))?;
    let response = http2.request(h2).await?;
    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(
        response.into_body().collect().await?.to_bytes(),
        "HTTP/2 over Weaver"
    );

    let unknown = Request::builder()
        .uri(virtual_uri("http", "unknown.virtual", "/")?)
        .body(Full::new(Bytes::new()))?;
    http1
        .request(unknown)
        .await
        .expect_err("unknown virtual host unexpectedly connected");
    let error = connector
        .clone()
        .oneshot(virtual_uri("http", "unknown.virtual", "/")?)
        .await
        .expect_err("connector resolved an unknown virtual host");
    assert!(error.to_string().contains("unknown.virtual"));

    let (mut websocket, response) = connect_websocket(
        client_network.clone(),
        source,
        virtual_uri("ws", DEFAULT_VIRTUAL_HOST, "/ws")?,
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    websocket
        .send(Message::Text("readable alias".into()))
        .await?;
    assert_eq!(
        websocket.next().await.transpose()?,
        Some(Message::Text("readable alias".into()))
    );
    websocket
        .send(Message::Binary(vec![0, 1, 2, 0xff].into()))
        .await?;
    assert_eq!(
        websocket.next().await.transpose()?,
        Some(Message::Binary(vec![0, 1, 2, 0xff].into()))
    );
    websocket.close(None).await?;

    drop(http1);
    drop(http2);
    drop(connector);
    http_server.shutdown().await?;
    let client = Arc::try_unwrap(client_network)
        .map_err(|_| anyhow::anyhow!("HTTP clients retained the network"))?;
    client.close().await;
    server.close().await;
    relay.shutdown().await?;
    Ok(())
}

async fn join_member(
    authority: &mut Authority,
    root: NetworkRootPublic,
    roles: MemberRoles,
    now: u64,
) -> Result<JoinedMember> {
    let state = MemoryStateStore::new();
    let secrets = MemorySecretStore::default();
    let stores = MembershipStores {
        state: Arc::new(state.clone()),
        secrets: Arc::new(secrets.clone()),
        allow_insecure_test_stores: true,
    };
    let prepared =
        NetworkMembership::prepare_join(&stores, root.network_id(), roles, now + 30 * 60 * 1_000)
            .await?;
    let ticket = authority
        .invite_member(
            &prepared.request,
            &prepared.endpoint_binding,
            roles,
            now,
            30 * 60 * 1_000,
        )
        .await?;
    NetworkMembership::join(&stores, &root, &ticket, now + 1).await?;
    Ok(JoinedMember {
        state,
        secrets,
        certificate: MemberCertificate::from_bytes(&ticket.member_certificate)?,
        signing_public: prepared.request.payload().signing_public_key,
    })
}

async fn apply_updates(
    authority: &Authority,
    member: &JoinedMember,
    root: &NetworkRootPublic,
    now: u64,
) -> Result<()> {
    let secret = member
        .secrets
        .open(&member_secret_id(root.network_id(), b"member-encryption"))
        .await?;
    let secret: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| anyhow::anyhow!("member encryption secret is corrupt"))?;
    let encryption = MemberEncryptionKeypair::from_secret_bytes(secret)?;
    let mut persisted =
        weaver_net::PersistedConfigState::open(member.state.clone(), root.clone(), encryption, now)
            .await?;
    let updates = authority.config_updates_after(persisted.head()).await?;
    persisted.apply(&updates, now).await?;
    Ok(())
}

fn open_options(member: &JoinedMember, root: NetworkRootPublic) -> NetworkHandleOpenOptions {
    NetworkHandleOpenOptions {
        root,
        state_store: Arc::new(member.state.clone()),
        secret_store: Arc::new(member.secrets.clone()),
        config_sync: Default::default(),
        presence_sync: Default::default(),
        allow_insecure_test_stores: true,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}
