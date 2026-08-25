use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iroh::SecretKey;
use iroh_relay::server::{RelayConfig, Server as RelayServer, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use weaver_config::{ConfigUpdateBatch, MemberEncryptionKeypair};
use weaver_core::{ClientAddr, ServerAddr, VirtualAddr, VirtualName};
use weaver_crypto::{
    AppBinding, AppRegistrationRequest, AppRole, AppRootKey, MemberRoles, PreparedJoinRequest,
    SigningKeypair, derive_device_id,
};
use weaver_net::{
    CONFIG_ENVELOPE_KEY, CONFIG_HEAD_KEY, CONFIG_SIGNER_CERTIFICATE_KEY, NetworkHandle,
    NetworkHandleError, NetworkHandleOpenOptions, NetworkHandleTransportOptions,
    PersistedConfigState, TransportPathKind, decode_config_head, encode_config_head,
    member_secret_id,
};
use weaver_relay_core::{Authority, AuthorityInit, JoinTicket};
use weaver_store::{
    AtomicBatch, ExpectedVersion, MemorySecretStore, MemoryStateStore, SecretBytes, SecretStore,
    StateStore, StoreKey, StoreScope,
};

struct ProvisionedMember {
    signing: SigningKeypair,
    encryption_secret: [u8; 32],
    ticket: JoinTicket,
    state: MemoryStateStore,
    secrets: MemorySecretStore,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn one_client_connects_multiple_cross_app_servers_on_a_zero_relay_lan() -> Result<()> {
    let now = now_ms();
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join("authority");
    let initialized = Authority::initialize(AuthorityInit {
        data_dir: data_dir.clone(),
        relay_url: "http://127.0.0.1:9".to_owned(),
        now_ms: now,
        valid_for_ms: 60 * 60 * 1_000,
        master_key: [0x51; 32],
        recovery_root_out: None,
    })
    .await?;
    let root = weaver_crypto::NetworkRootKey::from_bytes(&initialized.recovery_root_bytes());
    let root_public = root.public();
    let network_id = root_public.network_id();
    let mut authority = Authority::open(data_dir, [0x51; 32], now + 1).await?;

    let mut first_server_member = invite_member(
        &mut authority,
        network_id,
        MemberRoles::MEMBER.union(MemberRoles::SERVICE),
        0x61,
        now + 2,
    )
    .await?;
    let mut second_server_member = invite_member(
        &mut authority,
        network_id,
        MemberRoles::MEMBER.union(MemberRoles::SERVICE),
        0x62,
        now + 3,
    )
    .await?;
    let mut client_member = invite_member(
        &mut authority,
        network_id,
        MemberRoles::MEMBER,
        0x71,
        now + 4,
    )
    .await?;

    let first_server_app_root = AppRootKey::generate()?;
    let first_server_app = first_server_app_root.app_addr();
    let second_server_app_root = AppRootKey::generate()?;
    let second_server_app = second_server_app_root.app_addr();
    let client_app_root = AppRootKey::generate()?;
    let client_app = client_app_root.app_addr();
    authority
        .register_app(
            &AppRegistrationRequest::create(&first_server_app_root, network_id, 0),
            now + 5,
        )
        .await?;
    authority
        .register_app(
            &AppRegistrationRequest::create(&second_server_app_root, network_id, 0),
            now + 6,
        )
        .await?;
    authority
        .register_app(
            &AppRegistrationRequest::create(&client_app_root, network_id, 0),
            now + 7,
        )
        .await?;
    let first_server_cert = weaver_crypto::MemberCertificate::from_bytes(
        &first_server_member.ticket.member_certificate,
    )?;
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &first_server_app_root,
                network_id,
                first_server_cert.payload().member_id,
                AppRole::Server,
                None,
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 8,
        )
        .await?;
    let second_server_cert = weaver_crypto::MemberCertificate::from_bytes(
        &second_server_member.ticket.member_certificate,
    )?;
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &second_server_app_root,
                network_id,
                second_server_cert.payload().member_id,
                AppRole::Server,
                None,
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 9,
        )
        .await?;
    let client_cert =
        weaver_crypto::MemberCertificate::from_bytes(&client_member.ticket.member_certificate)?;
    let device = derive_device_id(
        network_id,
        client_app,
        &client_member.signing.public_bytes(),
    );
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &client_app_root,
                network_id,
                client_cert.payload().member_id,
                AppRole::Client,
                Some(device),
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 10,
        )
        .await?;

    let gateway_device = derive_device_id(
        network_id,
        client_app,
        &first_server_member.signing.public_bytes(),
    );
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &client_app_root,
                network_id,
                first_server_cert.payload().member_id,
                AppRole::Client,
                Some(gateway_device),
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 11,
        )
        .await?;

    let initial_relay = authority.endpoint_secret_key().public();
    authority.remove_relay(initial_relay, now + 12).await?;

    apply_authority_updates(&authority, &mut first_server_member, &root_public, now + 13).await?;
    apply_authority_updates(
        &authority,
        &mut second_server_member,
        &root_public,
        now + 13,
    )
    .await?;
    apply_authority_updates(&authority, &mut client_member, &root_public, now + 13).await?;
    assert_member_retains_forwardable_history(&first_server_member, &root_public, now + 14).await?;

    let first_server_options = open_options(&first_server_member, root_public.clone());
    let second_server_options = open_options(&second_server_member, root_public.clone());
    let client_options = open_options(&client_member, root_public.clone());
    let first_server_addr = ServerAddr::new(first_server_app);
    let second_server_addr = ServerAddr::new(second_server_app);
    let gateway_source = ClientAddr::new(client_app, gateway_device);
    let mut first_server = NetworkHandle::open(
        first_server_options,
        [
            weaver_net::LocalBinding::Server(first_server_addr),
            weaver_net::LocalBinding::Client(gateway_source),
        ],
    )
    .await?;
    let mut second_server = NetworkHandle::open(
        second_server_options,
        [weaver_net::LocalBinding::Server(second_server_addr)],
    )
    .await?;
    let mut first_tcp_listener = first_server.take_tcp_listener(first_server_addr)?;
    let mut first_udp_listener = first_server.take_udp_listener(first_server_addr)?;
    let mut second_tcp_listener = second_server.take_tcp_listener(second_server_addr)?;
    let mut second_udp_listener = second_server.take_udp_listener(second_server_addr)?;
    assert!(matches!(
        NetworkHandle::open(
            client_options.clone(),
            [weaver_net::LocalBinding::Client(ClientAddr::new(
                client_app,
                weaver_core::DeviceId::from_bytes([0xff; 32])
            ))],
        )
        .await,
        Err(NetworkHandleError::Authorization(_))
    ));
    let source = ClientAddr::new(client_app, device);
    let client =
        NetworkHandle::open(client_options, [weaver_net::LocalBinding::Client(source)]).await?;
    assert!(client.local_bindings().contains_client(source));

    assert_ne!(client_app, first_server_app);
    assert_ne!(client_app, second_server_app);
    let first_target = VirtualAddr::server(network_id, ServerAddr::new(first_server_app));
    let second_target = VirtualAddr::server(network_id, ServerAddr::new(second_server_app));
    assert_cross_app_tcp(
        &client,
        source,
        first_target,
        &mut first_tcp_listener,
        b"first-tcp",
    )
    .await?;
    assert_cross_app_tcp(
        &client,
        source,
        second_target,
        &mut second_tcp_listener,
        b"second-tcp",
    )
    .await?;
    assert_cross_app_udp(
        &client,
        source,
        first_target,
        &mut first_udp_listener,
        "first-udp",
    )
    .await?;
    assert_cross_app_udp(
        &client,
        source,
        second_target,
        &mut second_udp_listener,
        "second-udp",
    )
    .await?;
    assert_cross_app_tcp(
        &first_server,
        gateway_source,
        second_target,
        &mut second_tcp_listener,
        b"multi-role-endpoint",
    )
    .await?;
    assert!(
        first_server
            .local_bindings()
            .contains_server(first_server_addr)
    );
    assert!(
        first_server
            .local_bindings()
            .contains_client(gateway_source)
    );

    let before_revoke = first_server.config_head().await;
    authority
        .revoke_member(client_cert.payload().member_id, now + 15)
        .await?;
    let revocation = authority.config_updates_after(before_revoke).await?;
    first_server.apply_config_updates(&revocation).await?;
    let denied = tokio::time::timeout(
        Duration::from_secs(5),
        client.connect_tcp(source, first_target),
    )
    .await?;
    assert!(denied.is_err(), "revoked client opened a new stream");

    let foreign = VirtualAddr::server(
        weaver_core::NetworkId::from_bytes([0xee; 32]),
        ServerAddr::new(first_server_app),
    );
    assert!(matches!(
        client.connect_tcp(source, foreign).await,
        Err(NetworkHandleError::NetworkMismatch { .. })
    ));

    client.close().await;
    second_server.close().await;
    first_server.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn cold_clients_connect_through_signed_data_relay_without_presence_or_lan() -> Result<()> {
    let mut relay_config = ServerConfig::default();
    relay_config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let relay = RelayServer::spawn(relay_config).await?;
    let relay_url = format!(
        "http://{}",
        relay.http_addr().context("relay missing HTTP listener")?
    );

    let now = now_ms();
    let temp = tempfile::tempdir()?;
    let authority_dir = temp.path().join("authority");
    let initialized = Authority::initialize(AuthorityInit {
        data_dir: authority_dir.clone(),
        relay_url,
        now_ms: now,
        valid_for_ms: 60 * 60 * 1_000,
        master_key: [0x91; 32],
        recovery_root_out: None,
    })
    .await?;
    let root = weaver_crypto::NetworkRootKey::from_bytes(&initialized.recovery_root_bytes());
    let root_public = root.public();
    let network_id = root_public.network_id();
    let mut authority = Authority::open(authority_dir, [0x91; 32], now + 1).await?;

    let mut server_member = invite_member(
        &mut authority,
        network_id,
        MemberRoles::MEMBER.union(MemberRoles::SERVICE),
        0x92,
        now + 2,
    )
    .await?;
    let mut first_client_member = invite_member(
        &mut authority,
        network_id,
        MemberRoles::MEMBER,
        0x93,
        now + 3,
    )
    .await?;
    let mut second_client_member = invite_member(
        &mut authority,
        network_id,
        MemberRoles::MEMBER,
        0x94,
        now + 4,
    )
    .await?;

    let app_root = AppRootKey::generate()?;
    let app = app_root.app_addr();
    authority
        .register_app(
            &AppRegistrationRequest::create(&app_root, network_id, 0),
            now + 5,
        )
        .await?;
    let server_certificate =
        weaver_crypto::MemberCertificate::from_bytes(&server_member.ticket.member_certificate)?;
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &app_root,
                network_id,
                server_certificate.payload().member_id,
                AppRole::Server,
                None,
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 6,
        )
        .await?;

    let first_certificate = weaver_crypto::MemberCertificate::from_bytes(
        &first_client_member.ticket.member_certificate,
    )?;
    let first_device =
        derive_device_id(network_id, app, &first_client_member.signing.public_bytes());
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &app_root,
                network_id,
                first_certificate.payload().member_id,
                AppRole::Client,
                Some(first_device),
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 7,
        )
        .await?;

    let second_certificate = weaver_crypto::MemberCertificate::from_bytes(
        &second_client_member.ticket.member_certificate,
    )?;
    let second_device = derive_device_id(
        network_id,
        app,
        &second_client_member.signing.public_bytes(),
    );
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &app_root,
                network_id,
                second_certificate.payload().member_id,
                AppRole::Client,
                Some(second_device),
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 8,
        )
        .await?;
    let name = VirtualName::new("cold-start.virtual")?;
    authority
        .set_virtual_dns(name.clone(), app, now + 30 * 60 * 1_000, now + 9)
        .await?;

    apply_authority_updates(&authority, &mut server_member, &root_public, now + 10).await?;
    apply_authority_updates(&authority, &mut first_client_member, &root_public, now + 10).await?;
    apply_authority_updates(
        &authority,
        &mut second_client_member,
        &root_public,
        now + 10,
    )
    .await?;

    let relay_only = NetworkHandleTransportOptions {
        disable_direct_paths: true,
    };
    let server_addr = ServerAddr::new(app);
    let mut server = NetworkHandle::open_with_transport_options(
        open_options(&server_member, root_public.clone()),
        [weaver_net::LocalBinding::Server(server_addr)],
        relay_only,
    )
    .await?;
    server.wait_relay_online(Duration::from_secs(10)).await?;
    let mut listener = server.take_tcp_listener(server_addr)?;

    let first_source = ClientAddr::new(app, first_device);
    let first_client = NetworkHandle::open_with_transport_options(
        open_options(&first_client_member, root_public.clone()),
        [weaver_net::LocalBinding::Client(first_source)],
        relay_only,
    )
    .await?;
    let second_source = ClientAddr::new(app, second_device);
    let second_client = NetworkHandle::open_with_transport_options(
        open_options(&second_client_member, root_public),
        [weaver_net::LocalBinding::Client(second_source)],
        relay_only,
    )
    .await?;
    first_client
        .wait_relay_online(Duration::from_secs(10))
        .await?;
    second_client
        .wait_relay_online(Duration::from_secs(10))
        .await?;

    let server_task = tokio::spawn(async move {
        let mut first = listener.accept().await?;
        let mut second = listener.accept().await?;
        tokio::try_join!(
            async move {
                let marker = first.read_u8().await?;
                first.write_u8(marker).await
            },
            async move {
                let marker = second.read_u8().await?;
                second.write_u8(marker).await
            },
        )?;
        Ok::<_, std::io::Error>(())
    });
    let (first_stream, second_stream) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(
            first_client.connect_tcp_name(first_source, &name),
            second_client.connect_tcp_name(second_source, &name),
        )
    })
    .await
    .context("cold relay-only clients did not connect")??;

    for mut stream in [first_stream, second_stream] {
        assert!(
            stream
                .transport_paths()
                .iter()
                .any(|path| path.selected && path.kind == TransportPathKind::Relay)
        );
        stream.write_u8(0xa5).await?;
        assert_eq!(stream.read_u8().await?, 0xa5);
    }
    server_task.await??;

    second_client.close().await;
    first_client.close().await;
    server.close().await;
    relay.shutdown().await?;
    Ok(())
}

async fn assert_cross_app_tcp(
    client: &NetworkHandle,
    source: ClientAddr,
    target: VirtualAddr,
    listener: &mut weaver_net::VirtualTcpListener,
    payload: &[u8],
) -> Result<()> {
    let mut outgoing =
        tokio::time::timeout(Duration::from_secs(10), client.connect_tcp(source, target))
            .await
            .context("cross-application virtual TCP discovery timed out")??;
    let mut incoming = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
    outgoing.write_all(payload).await?;
    let mut received = vec![0_u8; payload.len()];
    incoming.read_exact(&mut received).await?;
    assert_eq!(received, payload);
    assert_eq!(incoming.peer_addr(), source.scoped());
    Ok(())
}

async fn assert_cross_app_udp(
    client: &NetworkHandle,
    source: ClientAddr,
    target: VirtualAddr,
    listener: &mut weaver_net::VirtualUdpListener,
    payload: &str,
) -> Result<()> {
    let outgoing =
        tokio::time::timeout(Duration::from_secs(10), client.connect_udp(source, target)).await??;
    let mut incoming = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
    outgoing.send_wait(payload.to_owned()).await?;
    assert_eq!(incoming.recv().await?, payload);
    assert_eq!(incoming.peer_addr(), source.scoped());
    Ok(())
}

async fn assert_member_retains_forwardable_history(
    member: &ProvisionedMember,
    root: &weaver_crypto::NetworkRootPublic,
    now: u64,
) -> Result<()> {
    let encryption = MemberEncryptionKeypair::from_secret_bytes(member.encryption_secret)?;
    let persisted =
        PersistedConfigState::open(member.state.clone(), root.clone(), encryption, now).await?;
    let updates = persisted.updates_after(member.ticket.config_head).await?;
    assert!(!updates.envelopes.is_empty());
    assert_eq!(updates.base_head, member.ticket.config_head);
    Ok(())
}

async fn invite_member(
    authority: &mut Authority,
    network_id: weaver_core::NetworkId,
    roles: MemberRoles,
    marker: u8,
    now: u64,
) -> Result<ProvisionedMember> {
    let signing = SigningKeypair::generate()?;
    let encryption = MemberEncryptionKeypair::generate()?;
    let transport = SecretKey::generate();
    let prepared = PreparedJoinRequest::create(
        network_id,
        &signing,
        encryption.public_bytes(),
        *transport.public().as_bytes(),
        [marker; 32],
        roles,
        now + 30 * 60 * 1_000,
    )?;
    let ticket = authority
        .invite_member(
            &prepared.request,
            &prepared.endpoint_binding,
            roles,
            now,
            30 * 60 * 1_000,
        )
        .await?;
    let state = MemoryStateStore::new();
    let secrets = MemorySecretStore::default();
    secrets
        .seal(
            member_secret_id(network_id, b"member-signing"),
            SecretBytes::new(signing.to_bytes().to_vec()),
        )
        .await?;
    secrets
        .seal(
            member_secret_id(network_id, b"member-encryption"),
            SecretBytes::new(encryption.secret_bytes().to_vec()),
        )
        .await?;
    secrets
        .seal(
            member_secret_id(network_id, b"endpoint"),
            SecretBytes::new(transport.to_bytes().to_vec()),
        )
        .await?;
    let mut batch = AtomicBatch::new(StoreScope::member(network_id));
    batch.put(
        StoreKey::new(CONFIG_ENVELOPE_KEY)?,
        ticket.embedded_config.clone(),
        ExpectedVersion::Missing,
    )?;
    batch.put(
        StoreKey::new(CONFIG_HEAD_KEY)?,
        encode_config_head(ticket.config_head),
        ExpectedVersion::Missing,
    )?;
    batch.put(
        StoreKey::new(CONFIG_SIGNER_CERTIFICATE_KEY)?,
        ticket.admin_certificate.clone(),
        ExpectedVersion::Missing,
    )?;
    state.commit(batch).await?;
    Ok(ProvisionedMember {
        signing,
        encryption_secret: encryption.secret_bytes(),
        ticket,
        state,
        secrets,
    })
}

async fn apply_authority_updates(
    authority: &Authority,
    member: &mut ProvisionedMember,
    root: &weaver_crypto::NetworkRootPublic,
    now: u64,
) -> Result<()> {
    let head_record = member
        .state
        .read(
            StoreScope::member(root.network_id()),
            &StoreKey::new(CONFIG_HEAD_KEY)?,
        )
        .await?
        .context("member head")?;
    let head = decode_config_head(&head_record.bytes)?;
    let updates: ConfigUpdateBatch = authority.config_updates_after(head).await?;
    let encryption = MemberEncryptionKeypair::from_secret_bytes(member.encryption_secret)?;
    let mut persisted =
        PersistedConfigState::open(member.state.clone(), root.clone(), encryption, now).await?;
    persisted.apply(&updates, now).await?;
    Ok(())
}

fn open_options(
    member: &ProvisionedMember,
    root: weaver_crypto::NetworkRootPublic,
) -> NetworkHandleOpenOptions {
    NetworkHandleOpenOptions {
        root,
        state_store: Arc::new(member.state.clone()),
        secret_store: Arc::new(member.secrets.clone()),
        config_sync: weaver_net::ConfigSyncOptions {
            interval: Duration::from_secs(60),
            retry_min: Duration::from_millis(50),
            retry_max: Duration::from_secs(1),
        },
        presence_sync: weaver_net::PresenceSyncOptions {
            publish_interval: Duration::from_millis(100),
            query_interval: Duration::from_millis(100),
            record_ttl: Duration::from_secs(30),
        },
        allow_insecure_test_stores: true,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}
