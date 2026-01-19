use anyhow::{anyhow, bail};
use arfs::{
    AccessMode, ArFs, CoinGeckoFxService, Direct, DriveId, FxService, KeyRing, PriceAdjustment,
    PriceLimit, Scope, SyncLimit, Turbo, UploadMode,
};
use ario_client::{ByteSize, Cache, Client};
use ario_core::confidential::Confidential;
use ario_core::crypto::keys::KeyType;
use ario_core::jwk::Jwk;
use ario_core::network::Network;
use ario_core::wallet::{Wallet, WalletAddress};
use ario_core::{Gateway, GatewayError};
use ars3nal::{Server, ServerHandle, ServerStatus};
use clap::Parser;
use directories::ProjectDirs;
use foyer_cache::{FoyerChunkCache, FoyerMetadataCache};
use futures_lite::StreamExt;
use s3s::auth::SecretKey;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
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

#[derive(Debug, Deserialize)]
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
    #[serde(default = "default_true")]
    l2_enabled: bool,
    #[serde(default = "default_true")]
    proactive_caching_enabled: bool,
    #[serde(default, deserialize_with = "deserialize_duration_option_days")]
    proactive_caching_interval_days: Option<Duration>,
}

impl Default for TomlCachingConfig {
    fn default() -> Self {
        Self {
            metadata_l1_cache_size: None,
            metadata_l2_cache_dir: None,
            metadata_l2_cache_size: default_metadata_l2_cache(),
            chunk_l1_cache_size: None,
            chunk_l2_cache_dir: None,
            chunk_l2_cache_size: default_chunk_l2_cache(),
            l2_enabled: true,
            proactive_caching_enabled: true,
            proactive_caching_interval_days: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct TomlSyncingConfig {
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    interval_secs: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    min_initial_wait_secs: Option<Duration>,
    #[serde(default = "default_one")]
    max_concurrent_syncs: usize,
}

impl Default for TomlSyncingConfig {
    fn default() -> Self {
        Self {
            interval_secs: None,
            min_initial_wait_secs: None,
            max_concurrent_syncs: 1,
        }
    }
}

#[derive(Debug, Deserialize)]
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

impl Default for TomlRoutemasterConfig {
    fn default() -> Self {
        Self {
            netwatch_enabled: true,
            gateways: default_gateways(),
            network: Network::default(),
        }
    }
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

fn deserialize_access_mode_option<'de, D>(deserializer: D) -> Result<Option<AccessMode>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_access_mode(deserializer).map(Some)
}

fn deserialize_access_mode<'de, D>(deserializer: D) -> Result<AccessMode, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    AccessMode::from_str(&str).map_err(|e| serde::de::Error::custom(e.to_string()))
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

fn deserialize_duration_days<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let days = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(86400 * days))
}

fn deserialize_duration_option_days<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_duration_days(deserializer).map(Some)
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

fn deserialize_wallet_address_option<'de, D>(
    deserializer: D,
) -> Result<Option<WalletAddress>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_wallet_address(deserializer).map(Some)
}

fn deserialize_key_type<'de, D>(deserializer: D) -> Result<KeyType, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    KeyType::from_str(&str).map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn deserialize_key_type_option<'de, D>(deserializer: D) -> Result<Option<KeyType>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_key_type(deserializer).map(Some)
}

fn deserialize_price_adjustment<'de, D>(deserializer: D) -> Result<PriceAdjustment, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    PriceAdjustment::from_str(&str).map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn deserialize_price_limit_option<'de, D>(deserializer: D) -> Result<Option<PriceLimit>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_price_limit(deserializer).map(Some)
}

fn deserialize_price_limit<'de, D>(deserializer: D) -> Result<PriceLimit, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    PriceLimit::from_str(&str).map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn deserialize_price_adjustment_option<'de, D>(
    deserializer: D,
) -> Result<Option<PriceAdjustment>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_price_adjustment(deserializer).map(Some)
}

#[derive(Debug, Deserialize)]
struct TomlServerConfig {
    host: Option<String>,
    port: Option<u16>,
}

impl Default for TomlServerConfig {
    fn default() -> Self {
        Self {
            host: None,
            port: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct TomlUserConfig {
    access_key: String,
    secret_key: SecretKey,
    principal: String,
}

#[derive(Debug)]
enum UploadType {
    Direct,
    Turbo,
}

#[derive(Debug)]
struct UploaderConfig {
    wallet: String,
    mode: UploadType,
    price_adjustment: PriceAdjustment,
    price_limit: Option<PriceLimit>,
}

impl TryFrom<TomlUploaderConfig> for UploaderConfig {
    type Error = anyhow::Error;

    fn try_from(value: TomlUploaderConfig) -> Result<Self, Self::Error> {
        let mode = value.mode.trim();
        let mode = if mode.eq_ignore_ascii_case("direct") {
            UploadType::Direct
        } else if mode.eq_ignore_ascii_case("turbo") {
            UploadType::Turbo
        } else {
            bail!("upload mode '{}' not known", mode);
        };
        Ok(UploaderConfig {
            wallet: value.wallet,
            mode,
            price_adjustment: value.price_adjustment.unwrap_or_default(),
            price_limit: value.price_limit,
        })
    }
}

#[derive(Debug, Deserialize)]
struct TomlUploaderConfig {
    name: String,
    mode: String,
    wallet: String,
    #[serde(default, deserialize_with = "deserialize_price_adjustment_option")]
    price_adjustment: Option<PriceAdjustment>,
    #[serde(default, deserialize_with = "deserialize_price_limit_option")]
    price_limit: Option<PriceLimit>,
}

#[derive(Debug)]
enum WalletConfig {
    JwkFile(PathBuf),
    Mnemonic {
        mnemonic: Confidential<String>,
        passphrase: Option<Confidential<String>>,
        key_type: KeyType,
    },
}

impl WalletConfig {
    async fn try_into_wallet(self) -> anyhow::Result<Wallet> {
        match self {
            Self::JwkFile(jwk) => {
                let bytes = tokio::fs::read(jwk).await?;
                let jwk = Jwk::from_json(&bytes)?;
                Ok(Wallet::from_jwk(&jwk)?)
            }
            Self::Mnemonic {
                mnemonic,
                passphrase,
                key_type,
            } => Ok(Wallet::from_mnemonic(
                &mnemonic,
                passphrase.as_ref(),
                key_type,
            )?),
        }
    }
}

impl TryFrom<TomlWalletConfig> for WalletConfig {
    type Error = anyhow::Error;

    fn try_from(mut value: TomlWalletConfig) -> Result<Self, Self::Error> {
        if let Some(jwk) = value.jwk {
            return Ok(Self::JwkFile(jwk));
        }
        if let Some(mnemonic) = value.mnemonic {
            let key_type = value.key_type.unwrap_or(KeyType::Rsa);
            return Ok(Self::Mnemonic {
                mnemonic,
                passphrase: value.passphrase.take(),
                key_type,
            });
        }
        // invalid config
        bail!(
            "invalid configuration for wallet [{}], check settings",
            value.name
        )
    }
}

#[derive(Debug, Deserialize)]
struct TomlWalletConfig {
    name: String,
    #[serde(default)]
    jwk: Option<PathBuf>,
    #[serde(default)]
    mnemonic: Option<Confidential<String>>,
    #[serde(default)]
    passphrase: Option<Confidential<String>>,
    #[serde(
        default,
        rename = "type",
        deserialize_with = "deserialize_key_type_option"
    )]
    key_type: Option<KeyType>,
}

#[derive(Debug, Deserialize)]
struct TomlPermabucketConfig {
    name: String,
    #[serde(deserialize_with = "deserialize_drive_id")]
    drive_id: DriveId,
    #[serde(default, deserialize_with = "deserialize_wallet_address_option")]
    owner: Option<WalletAddress>,
    #[serde(default)]
    wallet: Option<String>,
    #[serde(default)]
    drive_password: Option<Confidential<String>>,
    #[serde(default)]
    data_dir: Option<PathBuf>,
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    sync_interval_secs: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    sync_min_initial_wait_secs: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_access_mode_option")]
    access_mode: Option<AccessMode>,
    #[serde(default)]
    policy: Option<String>,
    #[serde(default)]
    uploader: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TomlGeneralConfig {
    #[serde(default)]
    data_dir: Option<PathBuf>,
}

impl Default for TomlGeneralConfig {
    fn default() -> Self {
        Self { data_dir: None }
    }
}

#[derive(Debug, Default, Deserialize)]
struct TomlConfig {
    #[serde(default)]
    general: TomlGeneralConfig,
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
    #[serde(default, rename = "user")]
    users: Vec<TomlUserConfig>,
    #[serde(default, rename = "wallet")]
    wallets: Vec<TomlWalletConfig>,
    #[serde(default, rename = "policy")]
    policies: Vec<TomlPolicyConfig>,
    #[serde(default, rename = "uploader")]
    uploaders: Vec<TomlUploaderConfig>,
}

#[derive(Debug)]
struct Config {
    listen_host: String,
    listen_port: u16,
    netwatch_enabled: bool,
    gateways: Vec<Gateway>,
    network: Network,
    l2_cache_enabled: bool,
    maybe_metadata_l1_cache_size: Option<ByteSize>,
    metadata_l2_cache_dir: PathBuf,
    metadata_l2_cache_size: ByteSize,
    maybe_chunk_l1_cache_size: Option<ByteSize>,
    chunk_l2_cache_dir: PathBuf,
    chunk_l2_cache_size: ByteSize,
    wallets: HashMap<String, WalletConfig>,
    uploaders: HashMap<String, UploaderConfig>,
    policies: HashMap<String, PolicyConfig>,
    permabuckets: HashMap<String, PermabucketConfig>,
    max_sync_concurrency: NonZeroUsize,
    proactive_cache_interval: Option<Duration>,
    users: HashMap<String, UserConfig>,
}

#[derive(Debug)]
enum PolicyConfig {
    Json(String),
    Path(PathBuf),
}

impl PolicyConfig {
    async fn try_into_policy_string(self) -> anyhow::Result<String> {
        match self {
            Self::Json(json) => Ok(json),
            Self::Path(path) => Ok(tokio::fs::read_to_string(&path).await?),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TomlPolicyConfig {
    name: String,
    #[serde(default)]
    json: Option<String>,
    #[serde(default)]
    file: Option<PathBuf>,
}

impl TryFrom<TomlPolicyConfig> for PolicyConfig {
    type Error = anyhow::Error;

    fn try_from(value: TomlPolicyConfig) -> Result<Self, Self::Error> {
        if let Some(json) = value.json {
            Ok(PolicyConfig::Json(json))
        } else if let Some(file) = value.file {
            Ok(PolicyConfig::Path(file))
        } else {
            Err(anyhow!(
                "policy [{}] invalid, set either json or file",
                &value.name
            ))
        }
    }
}

#[derive(Debug)]
struct PermabucketConfig {
    drive_id: DriveId,
    scope: PermabucketType,
    data_dir: PathBuf,
    maybe_sync_interval: Option<Duration>,
    maybe_sync_min_initial_wait: Option<Duration>,
    policy: Option<String>,
}

impl PermabucketConfig {
    fn wallet_name(&self) -> Option<&str> {
        match &self.scope {
            PermabucketType::PublicRo(WalletType::NamedWallet(wallet_name))
            | PermabucketType::PublicRw { wallet_name, .. }
            | PermabucketType::PrivateRo { wallet_name, .. }
            | PermabucketType::PrivateRw { wallet_name, .. } => Some(wallet_name.as_str()),
            _ => None,
        }
    }

    fn uploader_name(&self) -> Option<&str> {
        match &self.scope {
            PermabucketType::PublicRw { uploader_name, .. }
            | PermabucketType::PrivateRw { uploader_name, .. } => Some(uploader_name.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug)]
enum WalletType {
    Owner(WalletAddress),
    NamedWallet(String),
}

#[derive(Debug)]
enum PermabucketType {
    PublicRo(WalletType),
    PublicRw {
        wallet_name: String,
        uploader_name: String,
    },
    PrivateRo {
        wallet_name: String,
        drive_password: Confidential<String>,
    },
    PrivateRw {
        wallet_name: String,
        drive_password: Confidential<String>,
        uploader_name: String,
    },
}

impl<'a>
    TryFrom<(
        TomlPermabucketConfig,
        &'a PathBuf,
        Option<&'a Duration>,
        Option<&'a Duration>,
    )> for PermabucketConfig
{
    type Error = anyhow::Error;

    fn try_from(
        (value, default_data_dir, default_sync_interval, default_min_sync_wait): (
            TomlPermabucketConfig,
            &'a PathBuf,
            Option<&'a Duration>,
            Option<&'a Duration>,
        ),
    ) -> Result<Self, Self::Error> {
        let scope = match (
            value.access_mode,
            value.wallet,
            value.uploader,
            value.owner,
            value.drive_password,
        ) {
            (Some(AccessMode::ReadOnly) | None, None, None, Some(owner), None) => {
                PermabucketType::PublicRo(WalletType::Owner(owner))
            }
            (Some(AccessMode::ReadOnly) | None, Some(wallet_name), None, None, None) => {
                PermabucketType::PublicRo(WalletType::NamedWallet(wallet_name))
            }
            (Some(AccessMode::ReadWrite), Some(wallet_name), Some(uploader_name), None, None) => {
                PermabucketType::PublicRw {
                    wallet_name,
                    uploader_name,
                }
            }
            (
                Some(AccessMode::ReadOnly) | None,
                Some(wallet_name),
                None,
                None,
                Some(drive_password),
            ) => PermabucketType::PrivateRo {
                wallet_name,
                drive_password,
            },
            (
                Some(AccessMode::ReadWrite),
                Some(wallet_name),
                Some(uploader_name),
                None,
                Some(drive_password),
            ) => PermabucketType::PrivateRw {
                wallet_name,
                drive_password,
                uploader_name,
            },
            _ => bail!(
                "config error in bucket [{}]: invalid scope related settings, check access_mode, owner, wallet, uploader ...",
                value.name
            ),
        };

        Ok(PermabucketConfig {
            drive_id: value.drive_id,
            scope,
            policy: value.policy,
            data_dir: value.data_dir.unwrap_or_else(|| default_data_dir.clone()),
            maybe_sync_interval: value
                .sync_interval_secs
                .map(|s| Some(s))
                .unwrap_or_else(|| default_sync_interval.map(|d| d.clone())),
            maybe_sync_min_initial_wait: value
                .sync_min_initial_wait_secs
                .map(|s| Some(s))
                .unwrap_or_else(|| default_min_sync_wait.map(|d| d.clone())),
        })
    }
}

#[derive(Debug)]
struct UserConfig {
    secret_key: SecretKey,
    principal: String,
}

impl From<TomlUserConfig> for UserConfig {
    fn from(value: TomlUserConfig) -> Self {
        Self {
            secret_key: value.secret_key,
            principal: value.principal,
        }
    }
}

impl Config {
    fn new(toml: TomlConfig, arguments: Arguments) -> anyhow::Result<Self> {
        let listen_host = toml.server.host.unwrap_or_else(|| arguments.host);
        let listen_port = toml.server.port.unwrap_or_else(|| arguments.port);

        let data_dir = toml.general.data_dir.unwrap_or_else(|| arguments.data);

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

        let wallets = toml
            .wallets
            .into_iter()
            .map(|conf| -> anyhow::Result<(String, WalletConfig)> {
                let name = conf.name.clone();
                let wallet_config = conf.try_into()?;
                Ok((name, wallet_config))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        let uploaders = toml
            .uploaders
            .into_iter()
            .map(|conf| -> anyhow::Result<(String, UploaderConfig)> {
                let name = conf.name.clone();
                if !wallets.contains_key(conf.wallet.as_str()) {
                    bail!("wallet {} not configured", &conf.wallet)
                }
                let uploader_config = conf.try_into()?;
                Ok((name, uploader_config))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        let policies = toml
            .policies
            .into_iter()
            .map(|conf| -> anyhow::Result<(String, PolicyConfig)> {
                let name = conf.name.clone();
                let policy_config = conf.try_into()?;
                Ok((name, policy_config))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        let permabuckets = toml
            .permabuckets
            .into_iter()
            .map(|conf| -> anyhow::Result<(String, PermabucketConfig)> {
                let name = conf.name.clone();
                let permabucket_config = PermabucketConfig::try_from((
                    conf,
                    &data_dir,
                    default_sync_interval.as_ref(),
                    default_min_sync_wait.as_ref(),
                ))?;
                if let Some(wallet_name) = permabucket_config.wallet_name() {
                    if !wallets.contains_key(wallet_name) {
                        bail!("wallet {} not configured", wallet_name)
                    }
                }
                if let Some(uploader_name) = permabucket_config.uploader_name() {
                    if !uploaders.contains_key(uploader_name) {
                        bail!("uploader {} not configured", uploader_name)
                    }
                }
                if let Some(policy_name) = permabucket_config.policy.as_ref() {
                    if !policies.contains_key(policy_name) {
                        bail!("policy {} not configured", policy_name)
                    }
                }
                Ok((name, permabucket_config))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        let users = toml
            .users
            .into_iter()
            .map(|user| (user.access_key.clone(), user.into()))
            .collect::<HashMap<_, _>>();

        Ok(Self {
            listen_host,
            listen_port,
            netwatch_enabled: toml.routemaster.netwatch_enabled,
            gateways: toml.routemaster.gateways,
            network: toml.routemaster.network,
            l2_cache_enabled: toml.caching.l2_enabled,
            maybe_metadata_l1_cache_size,
            metadata_l2_cache_dir,
            metadata_l2_cache_size,
            maybe_chunk_l1_cache_size,
            chunk_l2_cache_dir,
            chunk_l2_cache_size,
            wallets,
            uploaders,
            policies,
            permabuckets,
            users,
            max_sync_concurrency: toml
                .syncing
                .max_concurrent_syncs
                .try_into()
                .map_err(|_| anyhow!("max_concurrent_syncs cannot be zero or negative"))?,
            proactive_cache_interval: if toml.caching.proactive_caching_enabled {
                Some(
                    toml.caching
                        .proactive_caching_interval_days
                        .unwrap_or_else(|| default_proactive_cache_interval()),
                )
            } else {
                None
            },
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

fn default_proactive_cache_interval() -> Duration {
    Duration::from_secs(86400 * 60)
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

fn default_one() -> usize {
    1
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
    rt.block_on(async move { run(config).await })?;
    Ok(())
}

async fn run(config: Config) -> anyhow::Result<()> {
    let (maybe_l2_metadata_cache, maybe_l2_chunk_cache) = if config.l2_cache_enabled {
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

        (Some(l2_metadata_cache), Some(l2_chunk_cache))
    } else {
        (None, None)
    };

    if config.gateways.is_empty() {
        bail!("at least one Gateway is required, cannot proceed");
    }

    let client = Client::builder()
        .gateways(config.gateways)
        .network(config.network)
        .enable_netwatch(config.netwatch_enabled)
        .cache(
            Cache::builder()
                .maybe_metadata_max_mem(config.maybe_metadata_l1_cache_size)
                .maybe_chunk_max_mem(config.maybe_chunk_l1_cache_size)
                .maybe_metadata_l2_cache(maybe_l2_metadata_cache)
                .maybe_chunk_l2_cache(maybe_l2_chunk_cache)
                .build(),
        )
        .build()
        .await?;

    let mut wallets = HashMap::with_capacity(config.wallets.len());
    for (name, conf) in config.wallets {
        wallets.insert(name, conf.try_into_wallet().await?);
    }

    let mut policies = HashMap::with_capacity(config.policies.len());
    for (name, conf) in config.policies {
        policies.insert(name, conf.try_into_policy_string().await?);
    }

    let mut fx_service: Option<Arc<FxService>> = None;

    let mut uploaders = HashMap::with_capacity(config.uploaders.len());
    for (name, conf) in config.uploaders {
        let wallet = wallets
            .get(conf.wallet.as_str())
            .map(|w| w.clone())
            .expect("wallet to be configured");

        let mode: Box<dyn UploadMode + Send + Sync + 'static> = match conf.mode {
            UploadType::Direct => Box::new(Direct::new(
                client.clone(),
                wallet.clone(),
                conf.price_adjustment,
            )),
            UploadType::Turbo => Box::new(Turbo::new()),
        };

        let fx = if let Some(price_limit) = &conf.price_limit {
            if !price_limit.is_native() {
                // fx service required
                if let Some(fx) = fx_service.as_ref() {
                    Some(fx.clone())
                } else {
                    let fx = Arc::new(
                        FxService::builder()
                            .xe_source(CoinGeckoFxService::default())
                            .build()
                            .await?,
                    );
                    fx_service = Some(fx.clone());
                    Some(fx)
                }
            } else {
                None
            }
        } else {
            None
        };

        let uploader = arfs::Uploader::builder()
            .client(client.clone())
            .mode(mode)
            .maybe_price_limit(conf.price_limit)
            .maybe_fx_service(fx)
            .build()?;

        uploaders.insert(name, Arc::new(tokio::sync::Mutex::new(uploader)));
    }

    let mut server = Server::builder()
        .host(config.listen_host.as_str())
        .port(config.listen_port)
        .build()
        .await?;

    let sync_limit = SyncLimit::new(config.max_sync_concurrency);
    let bucket_count = config.permabuckets.len();

    for (name, bucket) in config.permabuckets {
        let scope = match bucket.scope {
            PermabucketType::PublicRo(WalletType::Owner(owner)) => Scope::public(owner),
            PermabucketType::PublicRo(WalletType::NamedWallet(wallet_name)) => {
                let wallet = wallets
                    .get(&wallet_name)
                    .map(|w| w.clone())
                    .expect("wallet to be configured");
                Scope::public(wallet.address())
            }
            PermabucketType::PublicRw {
                wallet_name,
                uploader_name,
            } => {
                let wallet = wallets
                    .get(&wallet_name)
                    .map(|w| w.clone())
                    .expect("wallet to be configured");
                let uploader = uploaders
                    .get(&uploader_name)
                    .map(|u| u.clone())
                    .expect("uploader to be configured");
                Scope::public_rw(wallet, uploader)
            }
            PermabucketType::PrivateRo {
                wallet_name,
                drive_password,
            } => {
                let wallet = wallets
                    .get(&wallet_name)
                    .map(|w| w.clone())
                    .expect("wallet to be configured");
                let key_ring = KeyRing::builder()
                    .drive_id(&bucket.drive_id)
                    .wallet(&wallet)
                    .password(drive_password)
                    .build()?;
                Scope::private(wallet, key_ring)
            }
            PermabucketType::PrivateRw {
                wallet_name,
                uploader_name,
                drive_password,
            } => {
                let wallet = wallets
                    .get(&wallet_name)
                    .map(|w| w.clone())
                    .expect("wallet to be configured");
                let uploader = uploaders
                    .get(&uploader_name)
                    .map(|u| u.clone())
                    .expect("uploader to be configured");
                let key_ring = KeyRing::builder()
                    .drive_id(&bucket.drive_id)
                    .wallet(&wallet)
                    .password(drive_password)
                    .build()?;
                Scope::private_rw(wallet, key_ring, uploader)
            }
        };

        let arfs = ArFs::builder()
            .client(client.clone())
            .drive_id(bucket.drive_id)
            .db_dir(&bucket.data_dir)
            .scope(scope)
            .maybe_sync_interval(bucket.maybe_sync_interval)
            .maybe_sync_min_initial(bucket.maybe_sync_min_initial_wait)
            .maybe_proactive_cache_interval(config.proactive_cache_interval)
            .sync_limit(sync_limit.clone())
            .build()
            .await?;

        server.insert_bucket(&name, arfs)?;
        if let Some(policy_name) = bucket.policy {
            let policy = policies.get(&policy_name).expect("policy to be there");
            server.insert_bucket_policy(&name, policy)?;
        }
    }

    for (access_key, user) in config.users {
        server.insert_user(access_key, user.secret_key, user.principal)?;
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
