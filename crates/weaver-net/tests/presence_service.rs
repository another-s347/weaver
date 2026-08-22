use std::{sync::Arc, time::Duration};

use anyhow::Result;
use iroh::SecretKey;
use weaver_core::{AppAddr, DeviceId, NetworkId};
use weaver_discovery::EncryptedPresenceRecord;
use weaver_net::{
    ConfigPeerDescriptor, MemoryOpaquePresenceStore, NetworkError, NodeConfig, WeaverEndpoint,
};

fn opaque_record(epoch: u64, key: [u8; 24], marker: u8) -> EncryptedPresenceRecord {
    let ciphertext = [marker; 32];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"WVRPRS\0\x01");
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&key);
    bytes.extend_from_slice(&[0x55; 24]);
    bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&ciphertext);
    EncryptedPresenceRecord::from_bytes(&bytes).expect("synthetic opaque envelope")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_members_publish_and_query_opaque_presence() -> Result<()> {
    let network_id = NetworkId::from_bytes([0xa1; 32]);
    let publisher_key = SecretKey::generate();
    let reader_key = SecretKey::generate();
    let outsider_key = SecretKey::generate();
    let service_key = SecretKey::generate();
    let store = Arc::new(MemoryOpaquePresenceStore::new(16));
    let service = WeaverEndpoint::bind(
        NodeConfig::client(
            service_key,
            None,
            network_id,
            AppAddr::from_bytes([0xa2; 32]),
            DeviceId::from_bytes([0xa3; 32]),
        )
        .with_presence_store(store, [publisher_key.public(), reader_key.public()]),
    )
    .await?;
    let descriptor = service.descriptor(AppAddr::from_bytes([0xa2; 32]));
    let target = ConfigPeerDescriptor {
        network_id,
        endpoint_id: service.id(),
        relay_url: None,
        direct_addresses: descriptor.direct_addresses,
    };
    let publisher = WeaverEndpoint::bind(NodeConfig::client(
        publisher_key,
        None,
        network_id,
        AppAddr::from_bytes([0xb1; 32]),
        DeviceId::from_bytes([0xb2; 32]),
    ))
    .await?;
    let reader = WeaverEndpoint::bind(NodeConfig::client(
        reader_key,
        None,
        network_id,
        AppAddr::from_bytes([0xc1; 32]),
        DeviceId::from_bytes([0xc2; 32]),
    ))
    .await?;

    let epoch = 7;
    let key = [0x44; 24];
    let record = opaque_record(epoch, key, 0x66);
    let expires_at_ms = now_ms() + 30_000;
    publisher
        .publish_presence(&target, &record, expires_at_ms)
        .await?;
    let fetched = reader
        .query_presence(&target, epoch, key)
        .await?
        .expect("published record");
    assert_eq!(fetched.to_bytes()?, record.to_bytes()?);
    assert!(
        reader
            .query_presence(&target, epoch, [0x45; 24])
            .await?
            .is_none()
    );

    // The key owner cannot be replaced by a second authenticated member.
    let replacement = opaque_record(epoch, key, 0x77);
    assert!(matches!(
        reader
            .publish_presence(&target, &replacement, expires_at_ms)
            .await,
        Err(NetworkError::PresenceRejected)
    ));

    let outsider = WeaverEndpoint::bind(NodeConfig::client(
        outsider_key,
        None,
        network_id,
        AppAddr::from_bytes([0xd1; 32]),
        DeviceId::from_bytes([0xd2; 32]),
    ))
    .await?;
    assert!(matches!(
        outsider.query_presence(&target, epoch, key).await,
        Err(NetworkError::Connect(_)) | Err(NetworkError::OpenStream(_))
    ));

    let foreign = ConfigPeerDescriptor {
        network_id: NetworkId::from_bytes([0xee; 32]),
        ..target.clone()
    };
    assert!(matches!(
        reader.query_presence(&foreign, epoch, key).await,
        Err(NetworkError::NetworkMismatch { .. })
    ));

    outsider.close().await;
    reader.close().await;
    publisher.close().await;
    service.close().await;
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}
