use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::Write,
    net::SocketAddr,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use iroh_relay::server::{
    Access, AccessControl, CertConfig, ClientRateLimit, ClientRequest, RelayConfig, Server,
    ServerConfig, TlsConfig,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tracing::info;
use tracing_subscriber::EnvFilter;
use weaver_config::{ConfigHead, ConfigUpdateBatch, RelayRoles};
use weaver_core::{AppAddr, DeviceId, MemberId, ScopedVirtualAddr};
use weaver_crypto::{AppBinding, AppRegistrationRequest, MemberRoles, PreparedJoinRequest};
use weaver_net::{
    ConfigUpdateSource, MemoryOpaquePresenceStore, NetworkAuthorizer, NodeConfig, WeaverEndpoint,
};
use weaver_relay_core::{Authority, AuthorityInit};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(about = "Standalone Weaver relay and virtual-network authority")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Legacy development mode bind address when no subcommand is supplied.
    #[arg(long, default_value = "127.0.0.1:3340")]
    listen: SocketAddr,
}

struct AuthoritySource(Arc<tokio::sync::RwLock<Authority>>);

struct MemberRelayAccess {
    allowed: Arc<std::sync::RwLock<HashSet<iroh::EndpointId>>>,
}

struct AuthorityNetworkAuthorizer {
    allowed: Arc<std::sync::RwLock<HashSet<iroh::EndpointId>>>,
}

impl NetworkAuthorizer for AuthorityNetworkAuthorizer {
    fn allow_config_sync(&self, endpoint_id: iroh::EndpointId) -> bool {
        self.allowed
            .read()
            .expect("authority access lock poisoned")
            .contains(&endpoint_id)
    }

    fn allow_presence(&self, endpoint_id: iroh::EndpointId) -> bool {
        self.allow_config_sync(endpoint_id)
    }

    fn authorized_client_addrs(
        &self,
        _endpoint_id: iroh::EndpointId,
        _destination: ScopedVirtualAddr,
    ) -> HashSet<ScopedVirtualAddr> {
        HashSet::new()
    }
}

impl std::fmt::Debug for MemberRelayAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberRelayAccess")
            .field(
                "allowed_count",
                &self
                    .allowed
                    .read()
                    .expect("relay access lock poisoned")
                    .len(),
            )
            .finish()
    }
}

impl AccessControl for MemberRelayAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        if self
            .allowed
            .read()
            .expect("relay access lock poisoned")
            .contains(&request.endpoint_id())
        {
            Access::Allow
        } else {
            Access::Deny {
                reason: Some("endpoint is not a current member of this virtual network".into()),
            }
        }
    }
}

#[async_trait::async_trait]
impl ConfigUpdateSource for AuthoritySource {
    async fn updates_after(
        &self,
        _authenticated_peer: iroh::EndpointId,
        base_head: ConfigHead,
    ) -> Result<ConfigUpdateBatch, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.0.read().await.config_updates_after(base_head).await?)
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create an isolated virtual network and its revision-zero configuration.
    Init(InitArgs),
    /// Validate and print an initialized authority's current configuration head.
    Status(OpenArgs),
    /// Authorize a prepared node request and atomically commit its membership.
    Invite(InviteArgs),
    /// Revoke a member, rotate the epoch and remove all of its app/endpoint bindings.
    Revoke(RevokeArgs),
    /// Register an application-owner signed virtual address request.
    AppRegister(AppRegisterArgs),
    /// Commit an application-owner signed server/client binding.
    AppBind(AppBindArgs),
    /// Register or update an existing relay member in encrypted network topology.
    RelayRegister(RelayRegisterArgs),
    /// Remove a relay endpoint from encrypted network topology.
    RelayRemove(RelayRemoveArgs),
    /// Export a strict encrypted revision chain after a member's known head.
    ExportUpdates(ExportUpdatesArgs),
    /// Run the data relay, optionally validating a persistent authority first.
    Serve(ServeArgs),
    /// Create a private 32-byte master-key file for encrypted authority secrets.
    Keygen(KeygenArgs),
}

#[derive(Debug, ClapArgs)]
struct InitArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    relay_url: String,
    #[arg(long)]
    master_key_file: PathBuf,
    /// Create-new output for the offline network-root recovery secret.
    #[arg(long)]
    recovery_root_out: PathBuf,
    #[arg(long, default_value_t = 365)]
    valid_days: u64,
}

#[derive(Debug, ClapArgs)]
struct OpenArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
}

#[derive(Debug, ClapArgs)]
struct ServeArgs {
    /// Process role. `auto` selects combined with authority state, otherwise data-relay.
    #[arg(long, value_enum, default_value = "auto")]
    role: ServeRole,
    #[arg(long, default_value = "127.0.0.1:3340")]
    listen: SocketAddr,
    #[arg(long, requires = "master_key_file")]
    data_dir: Option<PathBuf>,
    #[arg(long, requires = "data_dir")]
    master_key_file: Option<PathBuf>,
    /// HTTPS bind address. Production authority mode requires TLS unless explicitly overridden.
    #[arg(long, requires_all = ["tls_cert", "tls_key"])]
    https_listen: Option<SocketAddr>,
    /// PEM certificate chain for the HTTPS relay endpoint.
    #[arg(long, requires_all = ["https_listen", "tls_key"])]
    tls_cert: Option<PathBuf>,
    /// PEM PKCS#8/PKCS#1/SEC1 private key; group/world-readable files are rejected on Unix.
    #[arg(long, requires_all = ["https_listen", "tls_cert"])]
    tls_key: Option<PathBuf>,
    /// Explicit development escape hatch for authority mode without HTTPS.
    #[arg(long, default_value_t = false)]
    allow_insecure_http: bool,
    /// Per-client relay receive rate. Omit for no byte-rate limit.
    #[arg(long)]
    client_bytes_per_second: Option<NonZeroU32>,
    /// Optional burst bytes used with --client-bytes-per-second.
    #[arg(long, requires = "client_bytes_per_second")]
    client_burst_bytes: Option<NonZeroU32>,
    /// Maximum cached relay client keys.
    #[arg(long, default_value_t = 4096)]
    key_cache_capacity: usize,
}

#[derive(Debug, ClapArgs)]
struct InviteArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, value_enum, value_delimiter = ',', default_value = "member")]
    roles: Vec<RoleArg>,
    #[arg(long, default_value_t = 30)]
    valid_days: u64,
}

#[derive(Debug, ClapArgs)]
struct RevokeArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    member_id: MemberId,
}

#[derive(Debug, ClapArgs)]
struct AppRegisterArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, ClapArgs)]
struct AppBindArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    binding: PathBuf,
}

#[derive(Debug, ClapArgs)]
struct RelayRegisterArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    endpoint_id: iroh::EndpointId,
    #[arg(long)]
    url: String,
    #[arg(long, value_enum, value_delimiter = ',', default_value = "data-relay")]
    roles: Vec<RelayRoleArg>,
    #[arg(long, default_value_t = 365)]
    valid_days: u64,
}

#[derive(Debug, ClapArgs)]
struct RelayRemoveArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    endpoint_id: iroh::EndpointId,
}

#[derive(Debug, ClapArgs)]
struct ExportUpdatesArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    master_key_file: PathBuf,
    #[arg(long)]
    base_epoch: u64,
    #[arg(long)]
    base_revision: u64,
    #[arg(long)]
    base_hash: String,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RoleArg {
    Member,
    Service,
    Relay,
    Bootstrap,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RelayRoleArg {
    DataRelay,
    Bootstrap,
    Presence,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ServeRole {
    Auto,
    Authority,
    DataRelay,
    Combined,
}

#[derive(Debug, ClapArgs)]
struct KeygenArgs {
    #[arg(long)]
    out: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Init(args)) => init(args).await,
        Some(Command::Status(args)) => status(args).await,
        Some(Command::Invite(args)) => invite(args).await,
        Some(Command::Revoke(args)) => revoke(args).await,
        Some(Command::AppRegister(args)) => app_register(args).await,
        Some(Command::AppBind(args)) => app_bind(args).await,
        Some(Command::RelayRegister(args)) => relay_register(args).await,
        Some(Command::RelayRemove(args)) => relay_remove(args).await,
        Some(Command::ExportUpdates(args)) => export_updates(args).await,
        Some(Command::Serve(args)) => serve(args).await,
        Some(Command::Keygen(args)) => keygen(args),
        None => {
            serve(ServeArgs {
                role: ServeRole::Auto,
                listen: cli.listen,
                data_dir: None,
                master_key_file: None,
                https_listen: None,
                tls_cert: None,
                tls_key: None,
                allow_insecure_http: true,
                client_bytes_per_second: None,
                client_burst_bytes: None,
                key_cache_capacity: 4096,
            })
            .await
        }
    }
}

async fn init(args: InitArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let valid_for_ms = args
        .valid_days
        .checked_mul(24 * 60 * 60 * 1_000)
        .context("--valid-days is too large")?;
    let initialized = Authority::initialize(AuthorityInit {
        data_dir: args.data_dir,
        relay_url: args.relay_url,
        now_ms: now_ms()?,
        valid_for_ms,
        master_key: *master_key,
        recovery_root_out: Some(args.recovery_root_out.clone()),
    })
    .await
    .context("failed to initialize Weaver authority")?;
    print_status(&initialized.status);
    println!("recovery_root={}", args.recovery_root_out.display());
    Ok(())
}

async fn status(args: OpenArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let authority = Authority::open(args.data_dir, *master_key, now_ms()?)
        .await
        .context("failed to open Weaver authority")?;
    print_status(authority.status());
    Ok(())
}

async fn invite(args: InviteArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let mut authority = Authority::open(args.data_dir, *master_key, now_ms()?)
        .await
        .context("failed to open Weaver authority")?;
    let prepared = PreparedJoinRequest::from_bytes(
        &std::fs::read(&args.request)
            .with_context(|| format!("failed to read {}", args.request.display()))?,
    )?;
    let mut roles = MemberRoles::from_bits(0);
    for role in args.roles {
        roles = roles.union(match role {
            RoleArg::Member => MemberRoles::MEMBER,
            RoleArg::Service => MemberRoles::SERVICE,
            RoleArg::Relay => MemberRoles::RELAY,
            RoleArg::Bootstrap => MemberRoles::BOOTSTRAP,
        });
    }
    let valid_for_ms = args
        .valid_days
        .checked_mul(24 * 60 * 60 * 1_000)
        .context("--valid-days is too large")?;
    let ticket = authority
        .invite_member(
            &prepared.request,
            &prepared.endpoint_binding,
            roles,
            now_ms()?,
            valid_for_ms,
        )
        .await
        .context("failed to authorize member")?;
    write_new_file(&args.out, &ticket.to_bytes())?;
    println!("ticket={}", args.out.display());
    println!("revision={}", ticket.config_head.revision);
    println!("epoch={}", ticket.config_head.epoch);
    Ok(())
}

async fn revoke(args: RevokeArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let mut authority = Authority::open(args.data_dir, *master_key, now_ms()?)
        .await
        .context("failed to open Weaver authority")?;
    let status = authority
        .revoke_member(args.member_id, now_ms()?)
        .await
        .context("failed to revoke member")?;
    print_status(&status);
    Ok(())
}

async fn app_register(args: AppRegisterArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let mut authority = Authority::open(args.data_dir, *master_key, now_ms()?)
        .await
        .context("failed to open Weaver authority")?;
    let request = AppRegistrationRequest::from_bytes(&std::fs::read(&args.request)?)?;
    let registered = authority.register_app(&request, now_ms()?).await?;
    write_new_file(&args.out, &registered.registration)?;
    println!("registration={}", args.out.display());
    println!("revision={}", registered.status.head.revision);
    Ok(())
}

async fn app_bind(args: AppBindArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let mut authority = Authority::open(args.data_dir, *master_key, now_ms()?)
        .await
        .context("failed to open Weaver authority")?;
    let binding = AppBinding::from_bytes(&std::fs::read(&args.binding)?)?;
    let status = authority.authorize_app_binding(&binding, now_ms()?).await?;
    println!("revision={}", status.head.revision);
    println!("epoch={}", status.head.epoch);
    Ok(())
}

async fn relay_register(args: RelayRegisterArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let mut authority = Authority::open(args.data_dir, *master_key, now_ms()?)
        .await
        .context("failed to open Weaver authority")?;
    let mut roles = RelayRoles::from_bits(0);
    for role in args.roles {
        roles = roles.union(match role {
            RelayRoleArg::DataRelay => RelayRoles::DATA_RELAY,
            RelayRoleArg::Bootstrap => RelayRoles::BOOTSTRAP,
            RelayRoleArg::Presence => RelayRoles::PRESENCE,
        });
    }
    let now = now_ms()?;
    let valid_for_ms = args
        .valid_days
        .checked_mul(24 * 60 * 60 * 1_000)
        .context("--valid-days is too large")?;
    let expires_at_ms = now
        .checked_add(valid_for_ms)
        .context("relay validity exceeds u64 milliseconds")?;
    let status = authority
        .register_relay(args.endpoint_id, args.url, roles, expires_at_ms, now)
        .await
        .context("failed to register relay")?;
    print_status(&status);
    Ok(())
}

async fn relay_remove(args: RelayRemoveArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let mut authority = Authority::open(args.data_dir, *master_key, now_ms()?)
        .await
        .context("failed to open Weaver authority")?;
    let status = authority
        .remove_relay(args.endpoint_id, now_ms()?)
        .await
        .context("failed to remove relay")?;
    print_status(&status);
    Ok(())
}

async fn export_updates(args: ExportUpdatesArgs) -> Result<()> {
    let master_key = read_master_key(&args.master_key_file)?;
    let authority = Authority::open(args.data_dir, *master_key, now_ms()?)
        .await
        .context("failed to open Weaver authority")?;
    let updates = authority
        .config_updates_after(ConfigHead {
            epoch: args.base_epoch,
            revision: args.base_revision,
            hash: decode_hex_32(&args.base_hash)?,
        })
        .await
        .context("failed to build configuration update chain")?;
    write_new_file(&args.out, &updates.to_bytes()?)?;
    println!("updates={}", args.out.display());
    println!("count={}", updates.envelopes.len());
    println!("revision={}", authority.status().head.revision);
    Ok(())
}

async fn serve(args: ServeArgs) -> Result<()> {
    if args.key_cache_capacity == 0 {
        anyhow::bail!("--key-cache-capacity must be greater than zero");
    }
    let authority_location = args.data_dir.clone().zip(args.master_key_file.clone());
    let authority = if let Some((data_dir, master_key_file)) = authority_location.as_ref() {
        let master_key = read_master_key(master_key_file)?;
        let authority = Authority::open(data_dir.clone(), *master_key, now_ms()?)
            .await
            .context("authority validation failed; refusing to serve")?;
        info!(network_id = %authority.status().network_id, "authority state validated");
        Some(Arc::new(tokio::sync::RwLock::new(authority)))
    } else {
        None
    };
    let role = match args.role {
        ServeRole::Auto if authority.is_some() => ServeRole::Combined,
        ServeRole::Auto => ServeRole::DataRelay,
        role => role,
    };
    let runs_data_relay = matches!(role, ServeRole::DataRelay | ServeRole::Combined);
    let runs_authority = matches!(role, ServeRole::Authority | ServeRole::Combined);
    if runs_authority && authority.is_none() {
        anyhow::bail!("--role authority/combined requires --data-dir and --master-key-file");
    }
    if runs_data_relay
        && authority.is_some()
        && args.https_listen.is_none()
        && !args.allow_insecure_http
    {
        anyhow::bail!(
            "authority mode requires --https-listen/--tls-cert/--tls-key; use --allow-insecure-http only for isolated development"
        );
    }

    let allowed_members = Arc::new(std::sync::RwLock::new(HashSet::new()));
    if let Some(authority) = authority.as_ref() {
        *allowed_members.write().expect("relay access lock poisoned") =
            authority.read().await.allowed_member_endpoints()?;
    }
    let server = if runs_data_relay {
        let mut relay_config = RelayConfig::new(args.listen);
        relay_config.key_cache_capacity = Some(args.key_cache_capacity);
        if let Some(rate) = args.client_bytes_per_second {
            let mut limit = ClientRateLimit::new(rate);
            limit.max_burst_bytes = args.client_burst_bytes;
            relay_config.limits.client_rx = Some(limit);
        }
        if let (Some(https_listen), Some(cert), Some(key)) = (
            args.https_listen,
            args.tls_cert.as_ref(),
            args.tls_key.as_ref(),
        ) {
            relay_config.tls = Some(TlsConfig::new(
                https_listen,
                CertConfig::Manual {
                    server_config: load_tls_server_config(cert, key)?,
                },
            ));
        }
        if authority.is_some() {
            relay_config.access = Arc::new(MemberRelayAccess {
                allowed: allowed_members.clone(),
            });
        }
        let mut config = ServerConfig::default();
        config.relay = Some(relay_config);
        let server = Server::spawn(config)
            .await
            .context("failed to start relay")?;
        let listen = server.http_addr().context("relay did not bind HTTP")?;
        info!(%listen, ?role, "weaver relay started");
        if let Some(https) = server.https_addr() {
            println!("relay_url=https://{https}");
        } else {
            println!("relay_url=http://{listen}");
            println!("WARNING: relay transport uses plaintext HTTP.");
        }
        if authority.is_none() {
            println!(
                "WARNING: relay has no authority state and allows every authenticated EndpointId."
            );
        }
        Some(server)
    } else {
        info!(
            ?role,
            "authority service starting without a local data relay"
        );
        None
    };

    let config_endpoint = if runs_authority {
        let authority = authority
            .as_ref()
            .expect("role validation requires authority");
        let authority_guard = authority.read().await;
        let network_id = authority_guard.status().network_id;
        let endpoint_secret = authority_guard.endpoint_secret_key();
        let relay_url = authority_guard
            .status()
            .relay_url
            .parse()
            .context("signed relay URL is invalid")?;
        let allowed_peers = authority_guard.allowed_member_endpoints()?;
        drop(authority_guard);
        let config = NodeConfig::client(
            endpoint_secret,
            Some(relay_url),
            network_id,
            AppAddr::from_bytes([0; 32]),
            DeviceId::from_bytes([0; 32]),
        )
        .with_config_update_source(
            Arc::new(AuthoritySource(authority.clone())),
            allowed_peers.clone(),
        )
        .with_presence_store(
            Arc::new(MemoryOpaquePresenceStore::new(4096)),
            allowed_peers,
        )
        .with_authorizer(Arc::new(AuthorityNetworkAuthorizer {
            allowed: allowed_members.clone(),
        }));
        let endpoint = WeaverEndpoint::bind(config)
            .await
            .context("failed to bind authority configuration endpoint")?;
        endpoint
            .wait_relay_online(Duration::from_secs(10))
            .await
            .context("authority configuration endpoint did not reach its signed relay")?;
        println!("config_endpoint_id={}", endpoint.id());
        println!("presence_endpoint_id={}", endpoint.id());
        Some(endpoint)
    } else {
        None
    };

    let reload_task = if let (Some(authority), Some((data_dir, master_key_file))) =
        (authority.as_ref(), authority_location)
    {
        let authority = authority.clone();
        let allowed_members = allowed_members.clone();
        Some(tokio::spawn(async move {
            let Ok(master_key) = read_master_key(&master_key_file) else {
                return;
            };
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Ok(reloaded) =
                    Authority::open(data_dir.clone(), *master_key, now_ms().unwrap_or(0)).await
                else {
                    continue;
                };
                let current_head = authority.read().await.status().head;
                if reloaded.status().head == current_head {
                    continue;
                }
                let Ok(next_allowed) = reloaded.allowed_member_endpoints() else {
                    continue;
                };
                *authority.write().await = reloaded;
                *allowed_members.write().expect("relay access lock poisoned") = next_allowed;
                info!("reloaded signed authority configuration and relay access policy");
            }
        }))
    } else {
        None
    };

    tokio::signal::ctrl_c()
        .await
        .context("ctrl-c handler failed")?;
    if let Some(endpoint) = config_endpoint {
        endpoint.close().await;
    }
    if let Some(task) = reload_task {
        task.abort();
        let _ = task.await;
    }
    if let Some(server) = server {
        server.shutdown().await.context("relay shutdown failed")?;
    }
    Ok(())
}

fn load_tls_server_config(cert_path: &Path, key_path: &Path) -> Result<rustls::ServerConfig> {
    check_private_key_permissions(key_path)?;
    let certificates = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("failed to open TLS certificate {}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse TLS certificate {}", cert_path.display()))?;
    if certificates.is_empty() {
        anyhow::bail!("TLS certificate file contains no certificates");
    }
    let private_key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("failed to parse TLS private key {}", key_path.display()))?;
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .context("failed to configure TLS 1.3 protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("TLS certificate and private key do not form a valid server identity")
}

#[cfg(unix)]
fn check_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect TLS private key {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "TLS private key {} is accessible by group or others; require mode 0600 or stricter",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_key_permissions(path: &Path) -> Result<()> {
    std::fs::metadata(path)
        .with_context(|| format!("failed to inspect TLS private key {}", path.display()))?;
    Ok(())
}

fn keygen(args: KeygenArgs) -> Result<()> {
    let mut key = Zeroizing::new([0_u8; 32]);
    getrandom::fill(key.as_mut()).context("secure randomness is unavailable")?;
    let mut file = private_new_file(&args.out)
        .with_context(|| format!("refusing to replace master key file {}", args.out.display()))?;
    file.write_all(key.as_ref())?;
    file.sync_all()?;
    if let Some(parent) = args.out.parent() {
        File::open(parent)?.sync_all()?;
    }
    println!("master_key_file={}", args.out.display());
    Ok(())
}

fn read_master_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(
        std::fs::read(path)
            .with_context(|| format!("failed to read master key file {}", path.display()))?,
    );
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("master key file must contain exactly 32 raw bytes"))?;
    Ok(Zeroizing::new(key))
}

fn now_ms() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis();
    u64::try_from(millis).context("system clock exceeds u64 milliseconds")
}

fn print_status(status: &weaver_relay_core::AuthorityStatus) {
    println!("network_id={}", status.network_id);
    println!("revision={}", status.head.revision);
    println!("epoch={}", status.head.epoch);
    println!("relay_url={}", status.relay_url);
    println!("root_public_key={}", encode_hex(&status.root_public_key));
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

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        anyhow::bail!("hash must be exactly 64 hexadecimal characters");
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)?;
        out[index] = u8::from_str_radix(text, 16).context("hash is not hexadecimal")?;
    }
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use iroh_relay::http::ProtocolVersion;

    fn request(endpoint_id: iroh::EndpointId) -> ClientRequest {
        let (parts, ()) = http::Request::builder()
            .uri("http://relay.test/relay")
            .body(())
            .unwrap()
            .into_parts();
        ClientRequest::new(endpoint_id, ProtocolVersion::V2, parts)
    }

    #[tokio::test]
    async fn authority_relay_access_denies_non_members() {
        let member = SecretKey::generate().public();
        let outsider = SecretKey::generate().public();
        let access = MemberRelayAccess {
            allowed: Arc::new(std::sync::RwLock::new(HashSet::from([member]))),
        };
        assert_eq!(access.on_connect(&request(member)).await, Access::Allow);
        assert!(matches!(
            access.on_connect(&request(outsider)).await,
            Access::Deny { .. }
        ));
        assert!(!format!("{access:?}").contains(&member.to_string()));
    }
}
