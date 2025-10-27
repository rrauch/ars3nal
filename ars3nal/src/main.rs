use anyhow::anyhow;
use arfs::{ArFs, DriveId, Scope};
use ario_client::{ByteSize, Cache, Client};
use ario_core::network::Network;
use ario_core::wallet::WalletAddress;
use ario_core::{Gateway, GatewayError};
use ars3nal::{Server, ServerHandle, ServerStatus};
use clap::Parser;
use directories::ProjectDirs;
use foyer_cache::{FoyerChunkCache, FoyerMetadataCache};
use futures_lite::StreamExt;
use serde::{Deserialize, Deserializer};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

static PROJECT_DIRS: LazyLock<Option<ProjectDirs>> =
    LazyLock::new(|| ProjectDirs::from("io", "AR", "Ars3nal"));

#[derive(Debug, Parser)]
#[command(version)]
/// Exports one or more ArDrives via S3.
///
/// If no commands are specified,
/// the server process will run and
/// export permabuckets as configured.
struct Arguments {
    /// Path to Config File
    #[arg(long, short = 'c', env, default_value = default_config())]
    config: PathBuf,
    /// Path to Default Data directory.
    /// Can be overridden for each permabucket in the Config File.
    #[arg(long, short = 'd', env, default_value = default_data_dir())]
    data: PathBuf,
    /// Path to Metadata L2 Cache directory.
    /// Can be overridden in the Config File.
    #[arg(long, short = 'm', env, default_value = default_metadata_cache())]
    metadata_cache: PathBuf,
    /// Path to Chunk L2 Cache directory.
    /// Can be overridden in the Config File.
    #[arg(long, short = 'k', env, default_value = default_chunk_cache())]
    chunk_cache: PathBuf,
    /// Default Host to listen on
    #[arg(long, short = 'l', env, default_value = "localhost")]
    host: String,
    /// Default Port to listen on
    #[arg(long, short = 'p', env, default_value = "6767")]
    port: u16,
}

#[derive(Debug, Default, Deserialize)]
struct TomlCachingConfig {
    #[serde(default)]
    metadata_l1_cache_size: Option<ByteSize>,
    #[serde(default)]
    metadata_l2_cache_dir: Option<PathBuf>,
    #[serde(default = "default_metadata_l2_cache")]
    metadata_l2_cache_size: ByteSize,
    #[serde(default)]
    chunk_l1_cache_size: Option<ByteSize>,
    #[serde(default)]
    chunk_l2_cache_dir: Option<PathBuf>,
    #[serde(default = "default_chunk_l2_cache")]
    chunk_l2_cache_size: ByteSize,
}

#[derive(Debug, Default, Deserialize)]
struct TomlSyncingConfig {
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    interval_secs: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    min_initial_wait_secs: Option<Duration>,
}

#[derive(Debug, Default, Deserialize)]
struct TomlRoutemasterConfig {
    #[serde(default = "default_true")]
    netwatch_enabled: bool,
    #[serde(
        default = "default_gateways",
        deserialize_with = "deserialize_gateways"
    )]
    gateways: Vec<Gateway>,
    #[serde(default, deserialize_with = "deserialize_network")]
    network: Network,
}

fn default_true() -> bool {
    true
}

fn default_gateways() -> Vec<Gateway> {
    vec![Gateway::default()]
}

fn deserialize_gateways<'de, D>(deserializer: D) -> Result<Vec<Gateway>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer)?
        .into_iter()
        .map(|s| Gateway::from_str(s.as_str()))
        .collect::<Result<Vec<_>, GatewayError>>()
        .map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn deserialize_network<'de, D>(deserializer: D) -> Result<Network, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    Network::from_str(&str).map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(secs))
}

fn deserialize_duration_option<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_duration(deserializer).map(Some)
}

fn deserialize_drive_id<'de, D>(deserializer: D) -> Result<DriveId, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    DriveId::from_str(&str).map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn deserialize_wallet_address<'de, D>(deserializer: D) -> Result<WalletAddress, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    WalletAddress::from_str(&str).map_err(|e| serde::de::Error::custom(e.to_string()))
}

#[derive(Debug, Default, Deserialize)]
struct TomlServerConfig {
    host: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct TomlPermabucketConfig {
    name: String,
    #[serde(deserialize_with = "deserialize_drive_id")]
    drive_id: DriveId,
    #[serde(deserialize_with = "deserialize_wallet_address")]
    owner: WalletAddress,
    #[serde(default)]
    data_dir: Option<PathBuf>,
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    sync_interval_secs: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    sync_min_initial_wait_secs: Option<Duration>,
}

#[derive(Debug, Default, Deserialize)]
struct TomlConfig {
    #[serde(default)]
    data_dir: Option<PathBuf>,
    #[serde(default)]
    server: TomlServerConfig,
    #[serde(default)]
    routemaster: TomlRoutemasterConfig,
    #[serde(default)]
    caching: TomlCachingConfig,
    #[serde(default)]
    syncing: TomlSyncingConfig,
    #[serde(default, rename = "permabucket")]
    permabuckets: Vec<TomlPermabucketConfig>,
}

#[derive(Debug)]
struct Config {
    listen_host: String,
    listen_port: u16,
    netwatch_enabled: bool,
    gateways: Vec<Gateway>,
    network: Network,
    maybe_metadata_l1_cache_size: Option<ByteSize>,
    metadata_l2_cache_dir: PathBuf,
    metadata_l2_cache_size: ByteSize,
    maybe_chunk_l1_cache_size: Option<ByteSize>,
    chunk_l2_cache_dir: PathBuf,
    chunk_l2_cache_size: ByteSize,
    permabuckets: Vec<PermabucketConfig>,
}

#[derive(Debug)]
struct PermabucketConfig {
    name: String,
    drive_id: DriveId,
    owner: WalletAddress,
    data_dir: PathBuf,
    maybe_sync_interval: Option<Duration>,
    maybe_sync_min_initial_wait: Option<Duration>,
}

impl Config {
    fn new(toml: TomlConfig, arguments: Arguments) -> anyhow::Result<Self> {
        let listen_host = toml.server.host.unwrap_or_else(|| arguments.host);
        let listen_port = toml.server.port.unwrap_or_else(|| arguments.port);

        let data_dir = toml.data_dir.unwrap_or_else(|| arguments.data);

        let maybe_metadata_l1_cache_size = toml.caching.metadata_l1_cache_size;
        let metadata_l2_cache_dir = toml
            .caching
            .metadata_l2_cache_dir
            .unwrap_or_else(|| arguments.metadata_cache);
        let metadata_l2_cache_size = toml.caching.metadata_l2_cache_size;

        let maybe_chunk_l1_cache_size = toml.caching.chunk_l1_cache_size;
        let chunk_l2_cache_dir = toml
            .caching
            .chunk_l2_cache_dir
            .unwrap_or_else(|| arguments.chunk_cache);
        let chunk_l2_cache_size = toml.caching.chunk_l2_cache_size;

        let default_sync_interval = toml.syncing.interval_secs;
        let default_min_sync_wait = toml.syncing.min_initial_wait_secs;

        let permabuckets = toml
            .permabuckets
            .into_iter()
            .map(|pb| {
                Ok(PermabucketConfig {
                    name: pb.name,
                    drive_id: pb.drive_id,
                    owner: pb.owner,
                    data_dir: pb.data_dir.unwrap_or_else(|| data_dir.clone()),
                    maybe_sync_interval: pb
                        .sync_interval_secs
                        .map(|s| Some(s))
                        .unwrap_or_else(|| default_sync_interval.clone()),
                    maybe_sync_min_initial_wait: pb
                        .sync_min_initial_wait_secs
                        .map(|s| Some(s))
                        .unwrap_or_else(|| default_min_sync_wait.clone()),
                })
            })
            .collect::<Result<_, anyhow::Error>>()?;

        Ok(Self {
            listen_host,
            listen_port,
            netwatch_enabled: toml.routemaster.netwatch_enabled,
            gateways: toml.routemaster.gateways,
            network: toml.routemaster.network,
            maybe_metadata_l1_cache_size,
            metadata_l2_cache_dir,
            metadata_l2_cache_size,
            maybe_chunk_l1_cache_size,
            chunk_l2_cache_dir,
            chunk_l2_cache_size,
            permabuckets,
        })
    }
}

fn default_metadata_l2_cache() -> ByteSize {
    ByteSize::mib(256)
}

fn default_chunk_l2_cache() -> ByteSize {
    ByteSize::mib(4096)
}

fn default_config() -> String {
    if let Some(dir) = PROJECT_DIRS.as_ref().map(|p| {
        p.config_dir()
            .join("config.toml")
            .to_string_lossy()
            .to_string()
    }) {
        return dir;
    }
    "/etc/ars3nal/config.toml".to_string()
}

fn default_cache(suffix: &str) -> String {
    if let Some(dir) = PROJECT_DIRS
        .as_ref()
        .map(|p| p.cache_dir().join(suffix).to_string_lossy().to_string())
    {
        return dir;
    }
    format!("/var/cache/ars3nal/{}", suffix)
}

fn default_metadata_cache() -> String {
    default_cache("metadata")
}

fn default_chunk_cache() -> String {
    default_cache("chunk")
}

fn default_data_dir() -> String {
    if let Some(dir) = PROJECT_DIRS
        .as_ref()
        .map(|p| p.data_dir().to_string_lossy().to_string())
    {
        return dir;
    }
    "/var/lib/ars3nal".to_string()
}

fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();
    let (filter, _) = tracing_subscriber::reload::Layer::new(filter);

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::Layer::default())
        .init();

    let arguments = Arguments::parse();
    let config_path = &arguments.config;
    let mut toml_config = None;
    if let Ok(metadata) = std::fs::metadata(&config_path) {
        if metadata.is_file() {
            tracing::info!(
                file = %config_path.display(),
                "reading config from file"
            );
            let config_str = std::fs::read_to_string(config_path)?;
            toml_config = Some(
                toml::from_str(config_str.as_str())
                    .map_err(|err| anyhow!("config file error: {}", err))?,
            );
        }
    }
    let toml_config = toml_config.unwrap_or_else(|| {
        tracing::warn!("no config file found, starting server with default settings");
        TomlConfig::default()
    });

    let config = Config::new(toml_config, arguments)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()?;
    rt.block_on(run(config))?;
    Ok(())
}

async fn run(config: Config) -> anyhow::Result<()> {
    let l2_metadata_cache = FoyerMetadataCache::builder()
        .disk_path(config.metadata_l2_cache_dir)
        .max_disk_space(config.metadata_l2_cache_size.as_u64())
        .build()
        .await?;

    let l2_chunk_cache = FoyerChunkCache::builder()
        .disk_path(config.chunk_l2_cache_dir)
        .max_disk_space(config.chunk_l2_cache_size.as_u64())
        .build()
        .await?;

    let client = Client::builder()
        .gateways(config.gateways)
        .network(config.network)
        .enable_netwatch(config.netwatch_enabled)
        .cache(
            Cache::builder()
                .maybe_metadata_max_mem(config.maybe_metadata_l1_cache_size)
                .maybe_chunk_max_mem(config.maybe_chunk_l1_cache_size)
                .metadata_l2_cache(l2_metadata_cache)
                .chunk_l2_cache(l2_chunk_cache)
                .build(),
        )
        .build()
        .await?;

    let mut server = Server::builder()
        .host(config.listen_host.as_str())
        .port(config.listen_port)
        .build()
        .await?;

    let bucket_count = config.permabuckets.len();

    for bucket in config.permabuckets {
        let arfs = ArFs::builder()
            .client(client.clone())
            .drive_id(bucket.drive_id)
            .db_dir(&bucket.data_dir)
            .scope(Scope::public(bucket.owner))
            .maybe_sync_interval(bucket.maybe_sync_interval)
            .maybe_sync_min_initial(bucket.maybe_sync_min_initial_wait)
            .build()
            .await?;

        server.insert_bucket(bucket.name, arfs)?;
    }

    let handle = server.serve();

    tracing::info!(
        listen_host = config.listen_host,
        listen_port = config.listen_port,
        bucket_count,
        "server started"
    );

    let mut status = handle.status();

    let shutdown = tokio::spawn(shutdown_listener(RunGuard(handle.clone())));

    notify_ready().await;

    while let Some(status) = status.next().await {
        match status {
            ServerStatus::Serving => {
                tracing::debug!("received server status: serving");
            }
            ServerStatus::ShuttingDown => {
                tracing::info!("server shutting down");
                notify_stopping().await;
            }
            ServerStatus::Finished => {
                break;
            }
        }
    }

    shutdown.abort();

    tracing::info!("server shutdown complete");

    Ok(())
}

#[repr(transparent)]
struct RunGuard(ServerHandle);

impl Drop for RunGuard {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

#[cfg(target_os = "linux")]
async fn notify_ready() {
    let _ = tokio::task::spawn_blocking(|| {
        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    })
    .await;
}

#[cfg(target_os = "linux")]
async fn notify_stopping() {
    let _ = tokio::task::spawn_blocking(|| {
        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
    })
    .await;
}

#[cfg(not(target_os = "linux"))]
async fn notify_ready() {}

#[cfg(not(target_os = "linux"))]
async fn notify_stopping() {}

#[cfg(unix)]
fn shutdown_listener(guard: RunGuard) -> impl Future<Output = ()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();

    async move {
        let _guard = guard;
        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("SIGINT received, shutting down")
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, shutting down")
            }
        }
        notify_stopping().await;
    }
}

#[cfg(windows)]
fn shutdown_listener(guard: RunGuard) -> impl Future<Output = ()> {
    use tokio::signal::windows::ctrl_break;
    use tokio::signal::windows::ctrl_c;
    use tokio::signal::windows::ctrl_close;

    let mut ctrl_c = ctrl_c()?;
    let mut ctrl_close = ctrl_close()?;
    let mut ctrl_break = ctrl_break()?;

    async move {
        let _guard = guard;
        tokio::select! {
            _ = ctrl_c.recv() => {
                tracing::info!("CTRL_C received, shutting down")
            }
            _ = ctrl_close.recv() => {
                tracing::info!("CTRL_CLOSE received, shutting down")
            }
            _ = ctrl_break.recv() => {
                tracing::info!("CTRL_BREAK received, shutting down")
            }
        }
    }
}
