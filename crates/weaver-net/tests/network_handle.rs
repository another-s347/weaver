use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iroh::SecretKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use weaver_config::{ConfigUpdateBatch, MemberEncryptionKeypair};
use weaver_core::{ClientAddr, ServerAddr, VirtualAddr};
use weaver_crypto::{
    AppBinding, AppRegistrationRequest, AppRole, AppRootKey, MemberRoles, PreparedJoinRequest,
    SigningKeypair, derive_device_id,
};
use weaver_net::{
    CONFIG_ENVELOPE_KEY, CONFIG_HEAD_KEY, CONFIG_SIGNER_CERTIFICATE_KEY, NetworkHandle,
    NetworkHandleError, NetworkHandleOpenOptions, PersistedConfigState, decode_config_head,
    encode_config_head, member_secret_id,
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
async fn joined_handles_form_a_zero_relay_lan_using_only_virtual_addresses() -> Result<()> {
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

    let mut server_member = invite_member(
        &mut authority,
        network_id,
        MemberRoles::MEMBER.union(MemberRoles::SERVICE),
        0x61,
        now + 2,
    )
    .await?;
    let mut client_member = invite_member(
        &mut authority,
        network_id,
        MemberRoles::MEMBER,
        0x71,
        now + 3,
    )
    .await?;

    let app_root = AppRootKey::generate()?;
    let app = app_root.app_addr();
    authority
        .register_app(
            &AppRegistrationRequest::create(&app_root, network_id, 0),
            now + 4,
        )
        .await?;
    let server_cert =
        weaver_crypto::MemberCertificate::from_bytes(&server_member.ticket.member_certificate)?;
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &app_root,
                network_id,
                server_cert.payload().member_id,
                AppRole::Server,
                None,
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 5,
        )
        .await?;
    let client_cert =
        weaver_crypto::MemberCertificate::from_bytes(&client_member.ticket.member_certificate)?;
    let device = derive_device_id(network_id, app, &client_member.signing.public_bytes());
    authority
        .authorize_app_binding(
            &AppBinding::issue(
                &app_root,
                network_id,
                client_cert.payload().member_id,
                AppRole::Client,
                Some(device),
                now + 30 * 60 * 1_000,
                Vec::new(),
            )?,
            now + 6,
        )
        .await?;

    let initial_relay = authority.endpoint_secret_key().public();
    authority.remove_relay(initial_relay, now + 7).await?;

    apply_authority_updates(&authority, &mut server_member, &root_public, now + 8).await?;
    apply_authority_updates(&authority, &mut client_member, &root_public, now + 8).await?;
    assert_member_retains_forwardable_history(&server_member, &root_public, now + 9).await?;

    let server_options = open_options(&server_member, root_public.clone());
    let client_options = open_options(&client_member, root_public.clone());
    let mut server = NetworkHandle::open_server(server_options, ServerAddr::new(app)).await?;
    let mut tcp_listener = server.take_tcp_listener()?;
    let mut udp_listener = server.take_udp_listener()?;
    assert!(matches!(
        NetworkHandle::open_client(
            client_options.clone(),
            ClientAddr::new(app, weaver_core::DeviceId::from_bytes([0xff; 32])),
        )
        .await,
        Err(NetworkHandleError::ClientAddressMismatch)
    ));
    let client = NetworkHandle::open_client(client_options, ClientAddr::new(app, device)).await?;
    assert_eq!(client.client_addr(), Some(ClientAddr::new(app, device)));

    let target = VirtualAddr::server(network_id, ServerAddr::new(app));
    let mut outgoing = tokio::time::timeout(Duration::from_secs(10), client.connect_tcp(target))
        .await
        .context("virtual TCP discovery timed out")??;
    let mut incoming =
        tokio::time::timeout(Duration::from_secs(5), tcp_listener.accept()).await??;
    outgoing.write_all(b"handle-tcp").await?;
    let mut tcp_payload = [0_u8; 10];
    incoming.read_exact(&mut tcp_payload).await?;
    assert_eq!(&tcp_payload, b"handle-tcp");

    let outgoing_udp =
        tokio::time::timeout(Duration::from_secs(10), client.connect_udp(target)).await??;
    let mut incoming_udp =
        tokio::time::timeout(Duration::from_secs(5), udp_listener.accept()).await??;
    outgoing_udp.send_wait("handle-udp").await?;
    assert_eq!(incoming_udp.recv().await?, "handle-udp");

    let before_revoke = server.config_head().await;
    authority
        .revoke_member(client_cert.payload().member_id, now + 10)
        .await?;
    let revocation = authority.config_updates_after(before_revoke).await?;
    server.apply_config_updates(&revocation).await?;
    let denied = tokio::time::timeout(Duration::from_secs(5), client.connect_tcp(target)).await?;
    assert!(denied.is_err(), "revoked client opened a new stream");

    let foreign = VirtualAddr::server(
        weaver_core::NetworkId::from_bytes([0xee; 32]),
        ServerAddr::new(app),
    );
    assert!(matches!(
        client.connect_tcp(foreign).await,
        Err(NetworkHandleError::NetworkMismatch { .. })
    ));

    client.close().await;
    server.close().await;
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
