use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iroh::SecretKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use weaver_config::{EpochSecrets, NetworkConfigV1, NetworkPolicy};
use weaver_core::{AppAddr, ClientAddr, DeviceId, ScopedVirtualAddr, ServerAddr};
use weaver_crypto::{
    AppBinding, AppRegistration, AppRole, AppRootKey, EndpointBinding, MemberCertificate,
    MemberRoles, NetworkRootKey, SigningKeypair,
};
use weaver_discovery::{PresenceDirectory, WeaverAddressLookup};
use weaver_net::{
    ConfigPeerDescriptor, LocalBinding, LocalBindings, MemoryOpaquePresenceStore, NodeConfig,
    PresenceSyncOptions, WeaverEndpoint, spawn_presence_sync,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn runtime_discovers_virtual_server_through_opaque_service() -> Result<()> {
    let now = now_ms();
    let expires = now + 60 * 60 * 1_000;
    let root = NetworkRootKey::generate()?;
    let network_id = root.public().network_id();
    let server_transport = SecretKey::generate();
    let client_transport = SecretKey::generate();
    let service_transport = SecretKey::generate();
    let server_signing = Arc::new(SigningKeypair::generate()?);
    let client_signing = Arc::new(SigningKeypair::generate()?);
    let service_signing = SigningKeypair::generate()?;

    let server_member = MemberCertificate::issue(
        &root,
        server_signing.public_bytes(),
        [0x11; 32],
        MemberRoles::MEMBER.union(MemberRoles::SERVICE),
        1,
        now.saturating_sub(1),
        expires,
    )?;
    let client_member = MemberCertificate::issue(
        &root,
        client_signing.public_bytes(),
        [0x22; 32],
        MemberRoles::MEMBER,
        2,
        now.saturating_sub(1),
        expires,
    )?;
    let service_member = MemberCertificate::issue(
        &root,
        service_signing.public_bytes(),
        [0x33; 32],
        MemberRoles::MEMBER.union(MemberRoles::SERVICE),
        3,
        now.saturating_sub(1),
        expires,
    )?;
    let endpoint_bindings = vec![
        EndpointBinding::issue(
            &server_signing,
            server_member.payload(),
            *server_transport.public().as_bytes(),
            0,
            expires,
        )?
        .to_bytes(),
        EndpointBinding::issue(
            &client_signing,
            client_member.payload(),
            *client_transport.public().as_bytes(),
            0,
            expires,
        )?
        .to_bytes(),
        EndpointBinding::issue(
            &service_signing,
            service_member.payload(),
            *service_transport.public().as_bytes(),
            0,
            expires,
        )?
        .to_bytes(),
    ];
    let server_app_key = AppRootKey::generate()?;
    let client_app_key = AppRootKey::generate()?;
    let server_app = server_app_key.app_addr();
    let client_app = client_app_key.app_addr();
    let client_device = DeviceId::from_bytes([0x77; 32]);
    let config = NetworkConfigV1 {
        network_id,
        epoch: 1,
        revision: 0,
        previous_hash: [0; 32],
        issued_at_ms: now.saturating_sub(1),
        expires_at_ms: expires,
        admin_keys: Vec::new(),
        members: vec![
            server_member.to_bytes(),
            client_member.to_bytes(),
            service_member.to_bytes(),
        ],
        endpoint_bindings,
        revoked_serials: Vec::new(),
        apps: vec![
            AppRegistration::issue(&root, &server_app_key, 10).to_bytes(),
            AppRegistration::issue(&root, &client_app_key, 11).to_bytes(),
        ],
        app_bindings: vec![
            AppBinding::issue(
                &server_app_key,
                network_id,
                server_member.payload().member_id,
                AppRole::Server,
                None,
                expires,
                Vec::new(),
            )?
            .to_bytes(),
            AppBinding::issue(
                &client_app_key,
                network_id,
                client_member.payload().member_id,
                AppRole::Client,
                Some(client_device),
                expires,
                Vec::new(),
            )?
            .to_bytes(),
        ],
        virtual_dns: Vec::new(),
        relays: Vec::new(),
        presence_services: Vec::new(),
        epoch_secrets: EpochSecrets::from_bytes([[0x41; 32], [0x42; 32], [0x43; 32], [0x44; 32]]),
        policies: NetworkPolicy::default(),
    }
    .validate(&root.public(), network_id, now)?;
    let config = Arc::new(config);

    let store = Arc::new(MemoryOpaquePresenceStore::new(32));
    let members = [server_transport.public(), client_transport.public()];
    let service = WeaverEndpoint::bind(
        NodeConfig::new(
            service_transport,
            None,
            network_id,
            LocalBindings::control_plane(),
            std::iter::empty(),
        )
        .with_presence_store(store, members),
    )
    .await?;
    let service_descriptor = service.descriptor(AppAddr::from_bytes([0x99; 32]));
    let target = ConfigPeerDescriptor {
        network_id,
        endpoint_id: service.id(),
        relay_url: None,
        direct_addresses: service_descriptor.direct_addresses,
    };

    let server_lookup = Arc::new(WeaverAddressLookup::new(network_id));
    let mut server = WeaverEndpoint::bind(
        NodeConfig::from_config(
            server_transport,
            &config,
            LocalBindings::new([LocalBinding::Server(ServerAddr::new(server_app))])?,
        )?
        .with_address_lookup(server_lookup.clone()),
    )
    .await?;
    let mut listener = server.take_tcp_listener(ServerAddr::new(server_app))?;
    let server_directory = Arc::new(PresenceDirectory::new(network_id, server_lookup.clone()));
    let server_runtime = spawn_presence_sync(
        server.dialer(),
        target.clone(),
        config.clone(),
        server_signing,
        server_directory,
        server_lookup,
        fast_options(),
    );

    let client_lookup = Arc::new(WeaverAddressLookup::new(network_id));
    let client = WeaverEndpoint::bind(
        NodeConfig::from_config(
            client_transport,
            &config,
            LocalBindings::new([LocalBinding::Client(ClientAddr::new(
                client_app,
                client_device,
            ))])?,
        )?
        .with_address_lookup(client_lookup.clone()),
    )
    .await?;
    let client_directory = Arc::new(PresenceDirectory::new(network_id, client_lookup.clone()));
    let client_runtime = spawn_presence_sync(
        client.dialer(),
        target,
        config,
        client_signing,
        client_directory.clone(),
        client_lookup,
        fast_options(),
    );

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if client_directory
                .resolve(ScopedVirtualAddr::Server { app: server_app }, now_ms())
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("opaque presence did not resolve the virtual server")?;

    let mut outgoing = client
        .connect_virtual(
            ClientAddr::new(client_app, client_device),
            &client_directory,
            server_app,
            now_ms(),
        )
        .await?;
    let mut incoming = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
    outgoing.write_all(b"virtual-only").await?;
    let mut payload = [0_u8; 12];
    incoming.read_exact(&mut payload).await?;
    assert_eq!(&payload, b"virtual-only");

    client_runtime.shutdown().await;
    server_runtime.shutdown().await;
    client.close().await;
    server.close().await;
    service.close().await;
    Ok(())
}

fn fast_options() -> PresenceSyncOptions {
    PresenceSyncOptions {
        publish_interval: Duration::from_millis(100),
        query_interval: Duration::from_millis(100),
        record_ttl: Duration::from_secs(30),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}
