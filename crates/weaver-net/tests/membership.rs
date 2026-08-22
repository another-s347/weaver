use std::sync::Arc;

use anyhow::Result;
use weaver_crypto::{MemberRoles, NetworkRootKey};
use weaver_net::{
    MembershipError, MembershipStores, NetworkMembership, PersistedConfigState, member_secret_id,
};
use weaver_relay_core::{Authority, AuthorityInit};
use weaver_store::{MemorySecretStore, MemoryStateStore, SecretStore};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_prepare_join_converges_on_one_identity() -> Result<()> {
    let network_id = weaver_core::NetworkId::from_bytes([0x31; 32]);
    let stores = MembershipStores {
        state: Arc::new(MemoryStateStore::new()),
        secrets: Arc::new(MemorySecretStore::default()),
        allow_insecure_test_stores: true,
    };
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let stores = stores.clone();
        tasks.push(tokio::spawn(async move {
            NetworkMembership::prepare_join(
                &stores,
                network_id,
                MemberRoles::MEMBER,
                now_ms() + 60_000,
            )
            .await
        }));
    }
    let mut requests = Vec::new();
    for task in tasks {
        requests.push(task.await??.to_bytes());
    }
    assert!(requests.windows(2).all(|pair| pair[0] == pair[1]));
    Ok(())
}

#[tokio::test]
async fn sdk_prepare_and_join_are_idempotent_and_atomic() -> Result<()> {
    let now = now_ms();
    let temp = tempfile::tempdir()?;
    let initialized = Authority::initialize(AuthorityInit {
        data_dir: temp.path().join("authority"),
        relay_url: "http://127.0.0.1:9".to_owned(),
        now_ms: now,
        valid_for_ms: 60 * 60 * 1_000,
        master_key: [0x41; 32],
        recovery_root_out: None,
    })
    .await?;
    let root = NetworkRootKey::from_bytes(&initialized.recovery_root_bytes()).public();
    let network_id = root.network_id();
    let stores = MembershipStores {
        state: Arc::new(MemoryStateStore::new()),
        secrets: Arc::new(MemorySecretStore::default()),
        allow_insecure_test_stores: true,
    };

    let prepared = NetworkMembership::prepare_join(
        &stores,
        network_id,
        MemberRoles::MEMBER,
        now + 30 * 60 * 1_000,
    )
    .await?;
    let resumed = NetworkMembership::prepare_join(
        &stores,
        network_id,
        MemberRoles::MEMBER,
        now + 30 * 60 * 1_000,
    )
    .await?;
    assert_eq!(prepared.to_bytes(), resumed.to_bytes());

    let mut authority = Authority::open(temp.path().join("authority"), [0x41; 32], now + 1).await?;
    let ticket = authority
        .invite_member(
            &prepared.request,
            &prepared.endpoint_binding,
            MemberRoles::MEMBER,
            now + 2,
            30 * 60 * 1_000,
        )
        .await?;
    let joined_head = NetworkMembership::join(&stores, &root, &ticket, now + 3).await?;
    assert_eq!(joined_head, ticket.config_head);
    assert!(matches!(
        NetworkMembership::prepare_join(
            &stores,
            network_id,
            MemberRoles::MEMBER,
            now + 30 * 60 * 1_000,
        )
        .await,
        Err(MembershipError::AlreadyJoined)
    ));
    assert!(matches!(
        NetworkMembership::join(&stores, &root, &ticket, now + 4).await,
        Err(MembershipError::NotPrepared)
    ));

    let encryption_bytes: [u8; 32] = stores
        .secrets
        .open(&member_secret_id(network_id, b"member-encryption"))
        .await?
        .expose()
        .try_into()
        .expect("fixed key length");
    let reopened = PersistedConfigState::open(
        stores.state.clone(),
        root,
        weaver_config::MemberEncryptionKeypair::from_secret_bytes(encryption_bytes)?,
        now + 5,
    )
    .await?;
    assert_eq!(reopened.head(), joined_head);
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
}
