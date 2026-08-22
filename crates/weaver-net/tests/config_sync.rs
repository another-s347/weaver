use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use iroh::{EndpointId, SecretKey};
use tokio::sync::Mutex as AsyncMutex;
use weaver_config::{
    ConfigHead, ConfigUpdateBatch, EncryptedConfigEnvelope, MemberEncryptionKeypair,
};
use weaver_core::{AppAddr, DeviceId};
use weaver_crypto::NetworkRootKey;
use weaver_net::{
    BoxError, ConfigPeerDescriptor, ConfigSyncEvent, ConfigSyncOptions, ConfigSyncState,
    ConfigUpdateSource, NetworkError, NodeConfig, WeaverEndpoint,
};

#[derive(Clone)]
struct StaticSource {
    batch: ConfigUpdateBatch,
    authenticated_peers: Arc<Mutex<Vec<EndpointId>>>,
}

#[async_trait::async_trait]
impl ConfigUpdateSource for StaticSource {
    async fn updates_after(
        &self,
        authenticated_peer: EndpointId,
        base_head: ConfigHead,
    ) -> Result<ConfigUpdateBatch, Box<dyn std::error::Error + Send + Sync>> {
        self.authenticated_peers
            .lock()
            .expect("peer log lock")
            .push(authenticated_peer);
        if base_head != self.batch.base_head {
            return Err(
                std::io::Error::new(std::io::ErrorKind::NotFound, "unknown base head").into(),
            );
        }
        Ok(self.batch.clone())
    }
}

#[derive(Clone)]
struct AdvancingSource {
    batch: ConfigUpdateBatch,
    next_head: ConfigHead,
}

#[async_trait::async_trait]
impl ConfigUpdateSource for AdvancingSource {
    async fn updates_after(
        &self,
        _authenticated_peer: EndpointId,
        base_head: ConfigHead,
    ) -> Result<ConfigUpdateBatch, BoxError> {
        if base_head == self.batch.base_head {
            Ok(self.batch.clone())
        } else if base_head == self.next_head {
            Ok(ConfigUpdateBatch::new(
                self.batch.network_id,
                self.next_head,
                Vec::new(),
            )?)
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "unknown head").into())
        }
    }
}

struct FakeConfigState {
    head: ConfigHead,
    next_head: ConfigHead,
}

#[async_trait::async_trait]
impl ConfigSyncState for FakeConfigState {
    fn head(&self) -> ConfigHead {
        self.head
    }

    async fn apply_updates(
        &mut self,
        updates: &ConfigUpdateBatch,
        _now_ms: u64,
    ) -> Result<ConfigHead, BoxError> {
        if updates.base_head != self.head {
            return Err(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "base head mismatch").into(),
            );
        }
        if !updates.envelopes.is_empty() {
            self.head = self.next_head;
        }
        Ok(self.head)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_member_fetches_exact_encrypted_update_chain() -> Result<()> {
    let root = NetworkRootKey::generate()?;
    let network_id = root.public().network_id();
    let encryption = MemberEncryptionKeypair::generate()?;
    let genesis = EncryptedConfigEnvelope::seal(
        &root,
        0,
        0,
        [0; 32],
        b"genesis",
        &[encryption.public_bytes()],
    )?;
    let base_head = ConfigHead {
        epoch: 0,
        revision: 0,
        hash: genesis.envelope_hash(),
    };
    let next = EncryptedConfigEnvelope::seal(
        &root,
        0,
        1,
        base_head.hash,
        b"revision one",
        &[encryption.public_bytes()],
    )?;
    let batch = ConfigUpdateBatch::new(network_id, base_head, vec![next.to_bytes()])?;

    let client_key = SecretKey::generate();
    let client_id = client_key.public();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let source = Arc::new(StaticSource {
        batch: batch.clone(),
        authenticated_peers: observed.clone(),
    });
    let server_key = SecretKey::generate();
    let server_id = server_key.public();
    let server_config = NodeConfig::client(
        server_key,
        None,
        network_id,
        AppAddr::from_bytes([0x51; 32]),
        DeviceId::from_bytes([0x52; 32]),
    )
    .with_config_update_source(source, [client_id]);
    let server = WeaverEndpoint::bind(server_config).await?;
    let descriptor = server.descriptor(AppAddr::from_bytes([0x51; 32]));
    let target = ConfigPeerDescriptor {
        network_id,
        endpoint_id: server_id,
        relay_url: None,
        direct_addresses: descriptor.direct_addresses,
    };

    let client = WeaverEndpoint::bind(NodeConfig::client(
        client_key,
        None,
        network_id,
        AppAddr::from_bytes([0x61; 32]),
        DeviceId::from_bytes([0x62; 32]),
    ))
    .await?;
    let received = client.fetch_config_updates(&target, base_head).await?;
    assert_eq!(received, batch);
    assert_eq!(&*observed.lock().expect("peer log lock"), &[client_id]);

    let outsider = WeaverEndpoint::bind(NodeConfig::client(
        SecretKey::generate(),
        None,
        network_id,
        AppAddr::from_bytes([0x71; 32]),
        DeviceId::from_bytes([0x72; 32]),
    ))
    .await?;
    assert!(matches!(
        outsider.fetch_config_updates(&target, base_head).await,
        Err(NetworkError::Connect(_)) | Err(NetworkError::OpenStream(_))
    ));

    outsider.close().await;
    client.close().await;
    server.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn background_sync_runs_immediately_and_supports_coalesced_trigger() -> Result<()> {
    let root = NetworkRootKey::generate()?;
    let network_id = root.public().network_id();
    let encryption = MemberEncryptionKeypair::generate()?;
    let genesis = EncryptedConfigEnvelope::seal(
        &root,
        0,
        0,
        [0; 32],
        b"genesis",
        &[encryption.public_bytes()],
    )?;
    let base_head = ConfigHead {
        epoch: 0,
        revision: 0,
        hash: genesis.envelope_hash(),
    };
    let next = EncryptedConfigEnvelope::seal(
        &root,
        0,
        1,
        base_head.hash,
        b"revision one",
        &[encryption.public_bytes()],
    )?;
    let next_head = ConfigHead {
        epoch: 0,
        revision: 1,
        hash: next.envelope_hash(),
    };
    let batch = ConfigUpdateBatch::new(network_id, base_head, vec![next.to_bytes()])?;

    let client_key = SecretKey::generate();
    let client_id = client_key.public();
    let server = WeaverEndpoint::bind(
        NodeConfig::client(
            SecretKey::generate(),
            None,
            network_id,
            AppAddr::from_bytes([0x81; 32]),
            DeviceId::from_bytes([0x82; 32]),
        )
        .with_config_update_source(
            Arc::new(AdvancingSource {
                batch: batch.clone(),
                next_head,
            }),
            [client_id],
        ),
    )
    .await?;
    let descriptor = server.descriptor(AppAddr::from_bytes([0x81; 32]));
    let target = ConfigPeerDescriptor {
        network_id,
        endpoint_id: server.id(),
        relay_url: None,
        direct_addresses: descriptor.direct_addresses,
    };
    let client = WeaverEndpoint::bind(NodeConfig::client(
        client_key,
        None,
        network_id,
        AppAddr::from_bytes([0x91; 32]),
        DeviceId::from_bytes([0x92; 32]),
    ))
    .await?;
    let state = Arc::new(AsyncMutex::new(FakeConfigState {
        head: base_head,
        next_head,
    }));
    let unavailable = ConfigPeerDescriptor {
        network_id,
        endpoint_id: SecretKey::generate().public(),
        relay_url: None,
        direct_addresses: Vec::new(),
    };
    let mut runtime = client.start_config_anti_entropy(
        vec![unavailable, target],
        state.clone(),
        ConfigSyncOptions {
            interval: Duration::from_secs(60),
            retry_min: Duration::from_millis(20),
            retry_max: Duration::from_millis(100),
        },
    );

    let first = tokio::time::timeout(Duration::from_secs(5), runtime.next_event()).await?;
    assert_eq!(
        first,
        Some(ConfigSyncEvent::Applied {
            previous: base_head,
            current: next_head,
            envelopes: 1,
        })
    );
    assert_eq!(state.lock().await.head(), next_head);

    runtime.trigger()?;
    runtime.trigger()?;
    let second = tokio::time::timeout(Duration::from_secs(5), runtime.next_event()).await?;
    assert_eq!(second, Some(ConfigSyncEvent::UpToDate { head: next_head }));

    runtime.shutdown().await;
    client.close().await;
    server.close().await;
    Ok(())
}
