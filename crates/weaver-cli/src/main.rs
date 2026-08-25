use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use iroh::{EndpointId, RelayUrl, SecretKey as EndpointSecretKey};
use weaver_config::{ConfigUpdateBatch, MemberEncryptionKeypair};
use weaver_core::{AppAddr, NetworkId};
use weaver_crypto::{
    AppBinding, AppRegistrationRequest, AppRole, AppRootKey, MemberCertificate, MemberRoles,
    NetworkRootPublic, SigningKeypair, derive_device_id,
};
use weaver_net::{
    ConfigPeerDescriptor, MembershipStores, NetworkMembership, NodeConfig, PersistedConfigState,
    WeaverEndpoint,
};
use weaver_relay_core::JoinTicket;
use weaver_store::{
    AtomicBatch, EncryptedFileSecretStore, ExpectedVersion, RedbStateStore, SecretBytes, SecretId,
    SecretStore, StateStore, StoreKey, StoreScope,
};
use zeroize::Zeroizing;

const KEY_MEMBER_CERTIFICATE: &[u8] = b"membership/certificate/v1";

#[derive(Debug, Parser)]
#[command(about = "Weaver application-node provisioning CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate network-scoped node keys and a signed .wjr request.
    PrepareJoin(PrepareJoinArgs),
    /// Verify a .wjt ticket, decrypt its config and atomically join the network.
    Join(JoinArgs),
    /// Generate and persist an application root, then emit its signed registration request.
    AppPrepare(AppPrepareArgs),
    /// Sign a server or client application binding for this joined member.
    AppBind(AppBindArgs),
    /// Verify and atomically apply an encrypted configuration revision chain.
    ApplyUpdates(ApplyUpdatesArgs),
    /// Reopen and print this joined node's cryptographically verified config head.
    Status(NodeStatusArgs),
    /// Fetch and apply encrypted config revisions from an authorized network member.
    Sync(SyncArgs),
}

#[derive(Debug, Args)]
struct PrepareJoinArgs {
    #[arg(long)]
    network_id: NetworkId,
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value_t = 24)]
    expires_hours: u64,
    #[arg(long, value_enum, value_delimiter = ',', default_value = "member")]
    roles: Vec<RoleArg>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RoleArg {
    Member,
    Service,
    Relay,
    Bootstrap,
}

#[derive(Debug, Args)]
struct JoinArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    ticket: PathBuf,
    /// Hex-encoded Ed25519 network-root public key obtained out of band.
    #[arg(long)]
    root_public_key: String,
}

#[derive(Debug, Args)]
struct AppPrepareArgs {
    #[arg(long)]
    network_id: NetworkId,
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value_t = 0)]
    policy: u32,
}

#[derive(Debug, Args)]
struct AppBindArgs {
    #[arg(long)]
    network_id: NetworkId,
    #[arg(long)]
    app_addr: AppAddr,
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long, value_enum)]
    role: AppRoleArg,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value_t = 30)]
    valid_days: u64,
}

#[derive(Debug, Args)]
struct ApplyUpdatesArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    updates: PathBuf,
    /// Hex-encoded Ed25519 network-root public key obtained out of band.
    #[arg(long)]
    root_public_key: String,
}

#[derive(Debug, Args)]
struct NodeStatusArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    root_public_key: String,
}

#[derive(Debug, Args)]
struct SyncArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    root_public_key: String,
    /// EndpointId of a relay/bootstrap member present in the signed configuration.
    #[arg(long)]
    peer_endpoint_id: EndpointId,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AppRoleArg {
    Server,
    Client,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::PrepareJoin(args) => prepare_join(args).await,
        Command::Join(args) => join(args).await,
        Command::AppPrepare(args) => app_prepare(args).await,
        Command::AppBind(args) => app_bind(args).await,
        Command::ApplyUpdates(args) => apply_updates(args).await,
        Command::Status(args) => node_status(args).await,
        Command::Sync(args) => sync(args).await,
    }
}

async fn prepare_join(args: PrepareJoinArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let state = RedbStateStore::open(args.data_dir.join("state.redb"))?;
    let secrets = EncryptedFileSecretStore::open(args.data_dir.join("secrets"), *master_key)?;
    let current_time = now_ms()?;
    let expires_at_ms = current_time
        .checked_add(
            args.expires_hours
                .checked_mul(60 * 60 * 1_000)
                .context("--expires-hours is too large")?,
        )
        .context("join request expiry overflow")?;
    let mut roles = MemberRoles::from_bits(0);
    for role in args.roles {
        roles = roles.union(match role {
            RoleArg::Member => MemberRoles::MEMBER,
            RoleArg::Service => MemberRoles::SERVICE,
            RoleArg::Relay => MemberRoles::RELAY,
            RoleArg::Bootstrap => MemberRoles::BOOTSTRAP,
        });
    }
    let stores = MembershipStores {
        state: Arc::new(state),
        secrets: Arc::new(secrets),
        allow_insecure_test_stores: false,
    };
    let prepared =
        NetworkMembership::prepare_join(&stores, args.network_id, roles, expires_at_ms).await?;
    write_new_file(&args.out, &prepared.to_bytes())?;
    println!("request={}", args.out.display());
    println!("member_id={}", prepared.request.payload().member_id);
    println!(
        "endpoint_id={}",
        EndpointId::from_bytes(&prepared.request.payload().endpoint_id)?
    );
    Ok(())
}

async fn join(args: JoinArgs) -> Result<()> {
    let root_bytes = decode_hex_32(&args.root_public_key)?;
    let root = NetworkRootPublic::from_bytes(&root_bytes)?;
    let network_id = root.network_id();
    let master_key = read_master_key(&args.master_key_file)?;
    let state = RedbStateStore::open(args.data_dir.join("state.redb"))?;
    let secrets = EncryptedFileSecretStore::open(args.data_dir.join("secrets"), *master_key)?;
    let ticket = JoinTicket::from_bytes(&std::fs::read(&args.ticket)?)?;
    let endpoint = ticket.endpoint_binding.as_ref();
    let endpoint = weaver_crypto::EndpointBinding::from_bytes(endpoint)?;
    let stores = MembershipStores {
        state: Arc::new(state),
        secrets: Arc::new(secrets),
        allow_insecure_test_stores: false,
    };
    let opened_head = NetworkMembership::join(&stores, &root, &ticket, now_ms()?).await?;
    println!("network_id={network_id}");
    println!("revision={}", opened_head.revision);
    println!("epoch={}", opened_head.epoch);
    println!("head_hash={}", encode_hex(&opened_head.hash));
    println!(
        "endpoint_id={}",
        EndpointId::from_bytes(&endpoint.payload().endpoint_id)?
    );
    Ok(())
}

async fn app_prepare(args: AppPrepareArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let state = RedbStateStore::open(args.data_dir.join("state.redb"))?;
    let secrets = EncryptedFileSecretStore::open(args.data_dir.join("secrets"), *master_key)?;
    let app_root = AppRootKey::generate()?;
    let app_addr = app_root.app_addr();
    let request = AppRegistrationRequest::create(&app_root, args.network_id, args.policy);
    let app_secret_id = app_secret_id(args.network_id, app_addr);
    secrets
        .seal(
            app_secret_id,
            SecretBytes::new(app_root.to_bytes().to_vec()),
        )
        .await?;
    let key = app_request_key(app_addr)?;
    let mut batch = AtomicBatch::new(StoreScope::member(args.network_id));
    batch.put(key, request.to_bytes(), ExpectedVersion::Missing)?;
    state.commit(batch).await?;
    write_new_file(&args.out, &request.to_bytes())?;
    println!("request={}", args.out.display());
    println!("app_addr={app_addr}");
    Ok(())
}

async fn app_bind(args: AppBindArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let state = RedbStateStore::open(args.data_dir.join("state.redb"))?;
    let secrets = EncryptedFileSecretStore::open(args.data_dir.join("secrets"), *master_key)?;
    let app_secret = secrets
        .open(&app_secret_id(args.network_id, args.app_addr))
        .await?;
    let app_secret_bytes: [u8; 32] = app_secret
        .expose()
        .try_into()
        .context("stored application root is corrupt")?;
    let app_root = AppRootKey::from_bytes(&app_secret_bytes);
    if app_root.app_addr() != args.app_addr {
        bail!("stored application root does not derive the requested AppAddr");
    }
    let member_record = state
        .read(
            StoreScope::member(args.network_id),
            &StoreKey::new(KEY_MEMBER_CERTIFICATE)?,
        )
        .await?
        .context("node has not joined this network")?;
    let member = MemberCertificate::from_bytes(&member_record.bytes)?;
    let signing_secret = secrets
        .open(&secret_id(args.network_id, b"member-signing"))
        .await?;
    let signing_bytes: [u8; 32] = signing_secret
        .expose()
        .try_into()
        .context("stored member signing key is corrupt")?;
    let signing = SigningKeypair::from_bytes(&signing_bytes);
    if signing.public_bytes() != member.payload().signing_public_key {
        bail!("stored signing key differs from joined member certificate");
    }
    let current_time = now_ms()?;
    let expires_at_ms = current_time
        .checked_add(
            args.valid_days
                .checked_mul(24 * 60 * 60 * 1_000)
                .context("--valid-days is too large")?,
        )
        .context("application binding expiry overflow")?
        .min(member.payload().expires_at_ms);
    if expires_at_ms <= current_time {
        bail!("joined member certificate is already expired");
    }
    let (role, device_id) = match args.role {
        AppRoleArg::Server => (AppRole::Server, None),
        AppRoleArg::Client => (
            AppRole::Client,
            Some(derive_device_id(
                args.network_id,
                args.app_addr,
                &signing.public_bytes(),
            )),
        ),
    };
    let binding = AppBinding::issue(
        &app_root,
        args.network_id,
        member.payload().member_id,
        role,
        device_id,
        expires_at_ms,
        Vec::new(),
    )?;
    write_new_file(&args.out, &binding.to_bytes())?;
    println!("binding={}", args.out.display());
    if let Some(device_id) = device_id {
        println!("device_id={device_id}");
    }
    Ok(())
}

async fn apply_updates(args: ApplyUpdatesArgs) -> Result<()> {
    let root = NetworkRootPublic::from_bytes(&decode_hex_32(&args.root_public_key)?)?;
    let network_id = root.network_id();
    let master_key = read_master_key(&args.master_key_file)?;
    let state = RedbStateStore::open(args.data_dir.join("state.redb"))?;
    let secrets = EncryptedFileSecretStore::open(args.data_dir.join("secrets"), *master_key)?;
    let encryption_secret = secrets
        .open(&secret_id(network_id, b"member-encryption"))
        .await?;
    let encryption_bytes: [u8; 32] = encryption_secret
        .expose()
        .try_into()
        .context("stored member encryption key is corrupt")?;
    let encryption = MemberEncryptionKeypair::from_secret_bytes(encryption_bytes)?;
    let updates = ConfigUpdateBatch::from_bytes(&std::fs::read(&args.updates)?)?;
    let mut persisted = PersistedConfigState::open(state, root, encryption, now_ms()?).await?;
    let head = persisted.apply(&updates, now_ms()?).await?;
    println!("network_id={network_id}");
    println!("revision={}", head.revision);
    println!("epoch={}", head.epoch);
    Ok(())
}

async fn node_status(args: NodeStatusArgs) -> Result<()> {
    let root = NetworkRootPublic::from_bytes(&decode_hex_32(&args.root_public_key)?)?;
    let network_id = root.network_id();
    let master_key = read_master_key(&args.master_key_file)?;
    let state = RedbStateStore::open(args.data_dir.join("state.redb"))?;
    let secrets = EncryptedFileSecretStore::open(args.data_dir.join("secrets"), *master_key)?;
    let encryption_secret = secrets
        .open(&secret_id(network_id, b"member-encryption"))
        .await?;
    let encryption_bytes: [u8; 32] = encryption_secret
        .expose()
        .try_into()
        .context("stored member encryption key is corrupt")?;
    let encryption = MemberEncryptionKeypair::from_secret_bytes(encryption_bytes)?;
    let persisted = PersistedConfigState::open(state, root, encryption, now_ms()?).await?;
    println!("network_id={network_id}");
    println!("revision={}", persisted.head().revision);
    println!("epoch={}", persisted.head().epoch);
    println!("head_hash={}", encode_hex(&persisted.head().hash));
    Ok(())
}

async fn sync(args: SyncArgs) -> Result<()> {
    let root = NetworkRootPublic::from_bytes(&decode_hex_32(&args.root_public_key)?)?;
    let network_id = root.network_id();
    let master_key = read_master_key(&args.master_key_file)?;
    let state = RedbStateStore::open(args.data_dir.join("state.redb"))?;
    let secrets = EncryptedFileSecretStore::open(args.data_dir.join("secrets"), *master_key)?;
    let encryption_secret = secrets
        .open(&secret_id(network_id, b"member-encryption"))
        .await?;
    let encryption_bytes: [u8; 32] = encryption_secret
        .expose()
        .try_into()
        .context("stored member encryption key is corrupt")?;
    let encryption = MemberEncryptionKeypair::from_secret_bytes(encryption_bytes)?;
    let mut persisted = PersistedConfigState::open(state, root, encryption, now_ms()?).await?;
    let peer_bytes = *args.peer_endpoint_id.as_bytes();
    let relay_url: RelayUrl = persisted
        .config()
        .as_config()
        .relays
        .iter()
        .find(|relay| relay.endpoint_id == peer_bytes)
        .context("peer endpoint is not an authorized relay in the signed configuration")?
        .url
        .parse()
        .context("signed relay URL is invalid")?;

    let endpoint_secret = secrets.open(&secret_id(network_id, b"endpoint")).await?;
    let endpoint_bytes: [u8; 32] = endpoint_secret
        .expose()
        .try_into()
        .context("stored endpoint key is corrupt")?;
    let endpoint_secret = EndpointSecretKey::from_bytes(&endpoint_bytes);
    let endpoint = WeaverEndpoint::bind(NodeConfig::new(
        endpoint_secret,
        Some(relay_url.clone()),
        network_id,
        weaver_net::LocalBindings::control_plane(),
        std::iter::empty(),
    ))
    .await?;
    endpoint
        .wait_relay_online(std::time::Duration::from_secs(10))
        .await?;
    let updates = endpoint
        .fetch_config_updates(
            &ConfigPeerDescriptor {
                network_id,
                endpoint_id: args.peer_endpoint_id,
                relay_url: Some(relay_url),
                direct_addresses: Vec::new(),
            },
            persisted.head(),
        )
        .await?;
    let count = updates.envelopes.len();
    let head = persisted.apply(&updates, now_ms()?).await?;
    endpoint.close().await;
    println!("network_id={network_id}");
    println!("updates={count}");
    println!("revision={}", head.revision);
    println!("epoch={}", head.epoch);
    Ok(())
}

fn secret_id(network_id: NetworkId, label: &[u8]) -> SecretId {
    let mut hasher = blake3::Hasher::new_derive_key("weaver.member.secret-id.v1");
    hasher.update(network_id.as_bytes());
    hasher.update(label);
    SecretId::from_bytes(*hasher.finalize().as_bytes())
}

fn app_secret_id(network_id: NetworkId, app_addr: AppAddr) -> SecretId {
    let mut hasher = blake3::Hasher::new_derive_key("weaver.member.app-root-secret-id.v1");
    hasher.update(network_id.as_bytes());
    hasher.update(app_addr.as_bytes());
    SecretId::from_bytes(*hasher.finalize().as_bytes())
}

fn app_request_key(app_addr: AppAddr) -> Result<StoreKey> {
    let mut key = b"app/request/v1/".to_vec();
    key.extend_from_slice(app_addr.as_bytes());
    Ok(StoreKey::new(key)?)
}

fn read_master_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let key = bytes
        .as_slice()
        .try_into()
        .context("master key file must contain exactly 32 raw bytes")?;
    Ok(Zeroizing::new(key))
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        bail!("root public key must be exactly 64 hexadecimal characters");
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)?;
        out[index] = u8::from_str_radix(text, 16).context("root public key is not hexadecimal")?;
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = private_new_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

#[cfg(unix)]
fn private_new_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn private_new_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().write(true).create_new(true).open(path)?)
}
