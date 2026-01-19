extern crate core;

mod crypto;
mod db;
pub(crate) mod fx;
mod key_ring;
pub(crate) mod resolve;
pub(crate) mod serde_tag;
mod sync;
pub(crate) mod types;
mod vfs;
mod wal;

pub use crate::db::Error as DbError;
pub use crate::fx::FxService;
pub use crate::fx::coingecko::CoinGecko as CoinGeckoFxService;
pub use crate::sync::upload::{Direct, Turbo, UploadMode, Uploader};
pub use crate::vfs::Error as VfsError;
pub use crate::wal::Error as WalError;
pub use ario_client::Error as ClientError;
pub use ario_core::bundle::Owner as BundleOwner;
pub use ario_core::tx::Owner as TxOwner;
pub use sync::Status as SyncStatus;
pub use types::{ArFsVersion, ContentType, Privacy, drive::DriveId, folder::FolderId};
pub use vfs::{
    Directory, File, Inode, InodeId, Name, ReadHandle, Timestamp, Vfs, VfsPath, WriteHandle,
};

use crate::db::{Config as DriveConfig, PageSize};
use crate::db::{Db, Transaction};
use crate::sync::{SyncResult, Syncer};
use crate::types::AuthMode;

use ario_client::{ByteSize, Client};
use ario_core::confidential::{Confidential, NewSecretExt, RevealExt};
use ario_core::tx::TxId;
use ario_core::wallet::{Wallet, WalletAddress};
use ario_core::{BigDecimal, MaybeOwned, money};

use crate::crypto::FileKeyError;
use crate::fx::fiat::{CNY, EUR, GBP, JPY, USD};
pub use crate::key_ring::KeyRing;
use crate::types::file::FileId;
use ario_core::money::{AR, Currency, Money, Winston};
use bon::Builder;
use core::fmt;
use derive_more::Display;
use futures_lite::Stream;
use num_traits::identities::Zero;
use serde_json::Error as JsonError;
use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::ops::{Deref, Div, Mul};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use strum::EnumString;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroize;

static ZERO: LazyLock<BigDecimal> =
    LazyLock::new(|| BigDecimal::from_str("0").expect("0 to be a valid big decimal value"));

static HUNDRED: LazyLock<BigDecimal> =
    LazyLock::new(|| BigDecimal::from_str("100").expect("100 to be a valid big decimal value"));

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    EntityError(#[from] EntityError),
    #[error(transparent)]
    ClientError(#[from] ClientError),
    #[error(transparent)]
    DbError(#[from] DbError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    VfsError(#[from] VfsError),
    #[error(transparent)]
    WalError(#[from] WalError),
    #[error(transparent)]
    SyncError(#[from] sync::Error),
    #[error(transparent)]
    UploadError(#[from] sync::upload::Error),
    #[error("read-only file system")]
    ReadOnlyFileSystem,
    #[error("file is encrypted")]
    EncryptedFile,
    #[error("file key not found")]
    FileKeyNotFound,
    #[error(transparent)]
    FileKeyError(#[from] FileKeyError),
    #[error("unexpected data length: expected '{expected}' but got '{actual}'")]
    UnexpectedDataLength { expected: u64, actual: u64 },
    #[error("file system not synchronized")]
    FileSystemNotSynchronized,
}

#[derive(Error, Debug)]
pub enum EntityError {
    #[error(transparent)]
    ParseError(#[from] types::ParseError),
    #[error(transparent)]
    MetadataError(#[from] MetadataError),
    #[error("status for tx with id '{0}' invalid")]
    InvalidTxStatus(TxId),
    #[error("entity of type '{entity_type}' with details '{details}' not found")]
    NotFound {
        entity_type: &'static str,
        details: String,
    },
    #[error("owner mismatch, expected '{expected}' but found '{actual}'")]
    OwnerMismatch {
        expected: WalletAddress,
        actual: WalletAddress,
    },
    #[error("privacy mode mismatch, expected '{expected}' but found '{actual}'")]
    PrivacyMismatch { expected: Privacy, actual: Privacy },
    #[error("auth mode mismatch, expected '{expected}' but found '{actual}'")]
    AuthModeMismatch { expected: String, actual: String },
    #[error("folder mismatch, expected '{expected}' but found '{actual}'")]
    FolderMismatch {
        expected: FolderId,
        actual: FolderId,
    },
    #[error("file mismatch, expected '{expected}' but found '{actual}'")]
    FileMismatch { expected: FileId, actual: FileId },
    #[error("drive mismatch, expected '{expected}' but found '{actual}'")]
    DriveMismatch { expected: DriveId, actual: DriveId },
    #[error("entity is encrypted")]
    Encrypted,
    #[error("entity decryption failed: {0}")]
    DecryptionError(String),
}

#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("data length '{actual}' exceeds max '{max}'")]
    MaxLengthExceeded { max: usize, actual: usize },
    #[error(transparent)]
    JsonError(#[from] JsonError),
}

#[derive(Debug, Clone, Display)]
#[repr(transparent)]
pub struct ArFs(Arc<ErasedArFs>);

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Limit<T>(Arc<Semaphore>, PhantomData<T>);

#[repr(transparent)]
pub(crate) struct Permit<T>(OwnedSemaphorePermit, PhantomData<T>);

impl<T> Limit<T> {
    pub fn new(max_concurrency: NonZeroUsize) -> Self {
        Self(
            Arc::new(Semaphore::new(max_concurrency.get())),
            PhantomData::default(),
        )
    }

    pub(crate) async fn acquire_permit(&self) -> Result<Permit<T>, sync::Error> {
        Ok(Permit(
            self.0
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| sync::Error::PermitAcquisitionFailed)?,
            PhantomData::default(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct SyncType;
pub type SyncLimit = Limit<SyncType>;
pub type SyncPermit = Permit<SyncType>;

impl Default for SyncLimit {
    fn default() -> Self {
        unsafe { Self::new(NonZeroUsize::new_unchecked(1)) }
    }
}

#[derive(Debug, Clone)]
pub struct UploadType;
pub type UploadLimit = Limit<UploadType>;
pub type UploadPermit = Permit<UploadType>;

impl Default for UploadLimit {
    fn default() -> Self {
        unsafe { Self::new(NonZeroUsize::new_unchecked(1)) }
    }
}

struct SyncSettings {
    sync_interval: Duration,
    sync_min_initial: Duration,
    sync_limit: SyncLimit,
    proactive_cache_interval: Option<Duration>,
}

#[derive(PartialEq, Debug, Clone)]
#[repr(transparent)]
pub struct PriceAdjustment(BigDecimal);

impl Default for PriceAdjustment {
    fn default() -> Self {
        Self(BigDecimal::zero())
    }
}

#[derive(Error, Debug)]
pub enum PriceAdjustmentError {
    #[error("input not valid: '{0}'")]
    InvalidInput(String),
    #[error("price adjustment value must be percentage")]
    NotAPercentage,
    #[error("price adjustment must be explicitly positive or negative. prefix with '+' or '-'")]
    NotPositiveOrNegative,
    #[error("error parsing number: '{0}'")]
    NumberParseError(String),
}

impl FromStr for PriceAdjustment {
    type Err = PriceAdjustmentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut input = s.trim();
        match input.strip_suffix("%") {
            Some(stripped) => input = stripped,
            None => Err(PriceAdjustmentError::NotAPercentage)?,
        }
        let prefix = match input.split_at_checked(1) {
            Some((prefix, value)) => {
                input = value.trim();
                prefix
            }
            _ => Err(PriceAdjustmentError::InvalidInput(s.to_string()))?,
        };

        let sign = match prefix {
            "+" => "",
            "-" => "-",
            _ => Err(PriceAdjustmentError::NotPositiveOrNegative)?,
        };

        if input.is_empty() {
            Err(PriceAdjustmentError::InvalidInput(s.to_string()))?
        }

        let value = BigDecimal::from_str(format!("{}{}", sign, input).as_str())
            .map_err(|e| PriceAdjustmentError::NumberParseError(e.to_string()))?
            .div(HUNDRED.deref());

        Ok(PriceAdjustment(value))
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct PriceLimit {
    price: Price,
    unit: ByteSize,
}

impl PriceLimit {
    pub fn is_native(&self) -> bool {
        self.price.is_native()
    }
}

#[derive(Error, Debug)]
pub enum PriceLimitError {
    #[error("input not valid: '{0}'")]
    InvalidInput(String),
    #[error(transparent)]
    PriceError(#[from] PriceError),
    #[error("error with data unit: '{0}'")]
    UnitError(String),
}

impl FromStr for PriceLimit {
    type Err = PriceLimitError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (price, unit) = s
            .split_once("/")
            .map(|(value, currency)| (value.trim(), currency.trim()))
            .ok_or_else(|| PriceLimitError::InvalidInput(s.to_string()))?;

        let price = Price::from_str(price)?;

        let unit = if unit.chars().next().map_or(false, |c| c.is_numeric()) {
            Cow::Borrowed(unit)
        } else {
            Cow::Owned(format!("1 {}", unit))
        };

        let unit = ByteSize::from_str(unit.as_ref()).map_err(|e| PriceLimitError::UnitError(e))?;

        Ok(Self { price, unit })
    }
}

#[derive(PartialEq, Debug, Clone)]
enum Price {
    AR(Money<AR>),
    Winston(Money<Winston>),
    USD(Money<USD>),
    EUR(Money<EUR>),
    CNY(Money<CNY>),
    JPY(Money<JPY>),
    GBP(Money<GBP>),
}

impl Price {
    fn as_big_decimal(&self) -> &BigDecimal {
        match self {
            Self::AR(money) => money.as_big_decimal(),
            Self::Winston(money) => money.as_big_decimal(),
            Self::USD(money) => money.as_big_decimal(),
            Self::EUR(money) => money.as_big_decimal(),
            Self::CNY(money) => money.as_big_decimal(),
            Self::JPY(money) => money.as_big_decimal(),
            Self::GBP(money) => money.as_big_decimal(),
        }
    }

    fn round_digits(&self) -> i64 {
        match self {
            Self::AR(_) => <AR as Currency>::DECIMAL_POINTS,
            Self::Winston(_) => <Winston as Currency>::DECIMAL_POINTS,
            Self::USD(_) => <USD as Currency>::DECIMAL_POINTS,
            Self::EUR(_) => <EUR as Currency>::DECIMAL_POINTS,
            Self::CNY(_) => <CNY as Currency>::DECIMAL_POINTS,
            Self::JPY(_) => <JPY as Currency>::DECIMAL_POINTS,
            Self::GBP(_) => <GBP as Currency>::DECIMAL_POINTS,
        }
        .into()
    }

    pub fn adjust(&self, adjustment: &PriceAdjustment) -> Result<Self, PriceError> {
        let value = self.as_big_decimal()
            + self
                .as_big_decimal()
                .mul(&adjustment.0)
                .round(self.round_digits());
        Ok(match self {
            Self::AR(_) => Money::<AR>::try_from(value)?.try_into()?,
            Self::Winston(_) => Money::<Winston>::try_from(value)?.try_into()?,
            Self::USD(_) => Money::<USD>::try_from(value)?.try_into()?,
            Self::EUR(_) => Money::<EUR>::try_from(value)?.try_into()?,
            Self::CNY(_) => Money::<CNY>::try_from(value)?.try_into()?,
            Self::JPY(_) => Money::<JPY>::try_from(value)?.try_into()?,
            Self::GBP(_) => Money::<GBP>::try_from(value)?.try_into()?,
        })
    }

    pub fn is_native(&self) -> bool {
        match self {
            Self::AR(_) | Self::Winston(_) => true,
            _ => false,
        }
    }

    pub fn to_winston(&self, fx_service: Option<&FxService>) -> Option<Money<Winston>> {
        match (self, fx_service) {
            (Self::Winston(w), _) => Some(w.clone()),
            (Self::AR(ar), _) => Some(ar.clone().into()),
            (Self::USD(usd), Some(fx)) => Some(fx.convert(usd.clone()).into()),
            (Self::EUR(eur), Some(fx)) => Some(fx.convert(eur.clone()).into()),
            (Self::CNY(cny), Some(fx)) => Some(fx.convert(cny.clone()).into()),
            (Self::JPY(jpy), Some(fx)) => Some(fx.convert(jpy.clone()).into()),
            (Self::GBP(gbp), Some(fx)) => Some(fx.convert(gbp.clone()).into()),
            _ => None,
        }
    }
}

fn check_negative_money<C: Currency>(value: &Money<C>) -> Result<(), PriceError> {
    if value.as_big_decimal() < ZERO.deref() {
        Err(PriceError::NegativePrice(value.to_plain_string()))
    } else {
        Ok(())
    }
}

impl TryFrom<Money<AR>> for Price {
    type Error = PriceError;

    fn try_from(value: Money<AR>) -> Result<Self, Self::Error> {
        check_negative_money(&value)?;
        Ok(Price::AR(value))
    }
}

impl TryFrom<Money<Winston>> for Price {
    type Error = PriceError;

    fn try_from(value: Money<Winston>) -> Result<Self, Self::Error> {
        check_negative_money(&value)?;
        Ok(Price::Winston(value))
    }
}

impl TryFrom<Money<USD>> for Price {
    type Error = PriceError;

    fn try_from(value: Money<USD>) -> Result<Self, Self::Error> {
        check_negative_money(&value)?;
        Ok(Price::USD(value))
    }
}

impl TryFrom<Money<EUR>> for Price {
    type Error = PriceError;

    fn try_from(value: Money<EUR>) -> Result<Self, Self::Error> {
        check_negative_money(&value)?;
        Ok(Price::EUR(value))
    }
}

impl TryFrom<Money<CNY>> for Price {
    type Error = PriceError;

    fn try_from(value: Money<CNY>) -> Result<Self, Self::Error> {
        check_negative_money(&value)?;
        Ok(Price::CNY(value))
    }
}

impl TryFrom<Money<JPY>> for Price {
    type Error = PriceError;

    fn try_from(value: Money<JPY>) -> Result<Self, Self::Error> {
        check_negative_money(&value)?;
        Ok(Price::JPY(value))
    }
}

impl TryFrom<Money<GBP>> for Price {
    type Error = PriceError;

    fn try_from(value: Money<GBP>) -> Result<Self, Self::Error> {
        check_negative_money(&value)?;
        Ok(Price::GBP(value))
    }
}

#[derive(Error, Debug)]
pub enum PriceError {
    #[error(transparent)]
    MoneyError(#[from] money::MoneyError),
    #[error("unsupported or invalid currency: '{0}'")]
    CurrencyError(String),
    #[error("input not valid: '{0}'")]
    InvalidInput(String),
    #[error("price cannot be negative: '{0}'")]
    NegativePrice(String),
}

impl FromStr for Price {
    type Err = PriceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (value, currency) = s
            .split_once(" ")
            .map(|(value, currency)| (value.trim(), currency.trim()))
            .ok_or_else(|| PriceError::InvalidInput(s.to_string()))?;

        let price: Price = if currency.eq_ignore_ascii_case(AR::SYMBOL) {
            Money::<AR>::from_str(value)?.try_into()?
        } else if currency.eq_ignore_ascii_case(Winston::SYMBOL) {
            Money::<Winston>::from_str(value)?.try_into()?
        } else if currency.eq_ignore_ascii_case(USD::SYMBOL) {
            Money::<USD>::from_str(value)?.try_into()?
        } else if currency.eq_ignore_ascii_case(EUR::SYMBOL) {
            Money::<EUR>::from_str(value)?.try_into()?
        } else if currency.eq_ignore_ascii_case(CNY::SYMBOL) {
            Money::<CNY>::from_str(value)?.try_into()?
        } else if currency.eq_ignore_ascii_case(JPY::SYMBOL) {
            Money::<JPY>::from_str(value)?.try_into()?
        } else if currency.eq_ignore_ascii_case(GBP::SYMBOL) {
            Money::<GBP>::from_str(value)?.try_into()?
        } else {
            Err(PriceError::CurrencyError(currency.to_string()))?
        };

        Ok(price)
    }
}

#[derive(Builder, Clone, Debug)]
pub struct CacheSettings {
    #[builder(default = 1000)]
    path_cache_capacity: u64,
    #[builder(default = Duration::from_secs(3600))]
    path_cache_ttl: Duration,
    #[builder(default = 1000)]
    inode_cache_capacity: u64,
    #[builder(default = Duration::from_secs(3600))]
    inode_cache_ttl: Duration,
    #[builder(default = 1000)]
    dir_cache_capacity: u64,
    #[builder(default = Duration::from_secs(3600))]
    dir_cache_ttl: Duration,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[derive(Builder, Clone, Debug)]
pub struct UploadSettings {
    #[builder(default)]
    upload_limit: UploadLimit,
    #[builder(default = Duration::from_secs(300))]
    batch_settle_time: Duration,
}

impl Default for UploadSettings {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[bon::bon]
impl ArFs {
    #[builder(derive(Debug))]
    pub async fn new<'a>(
        client: Client,
        #[builder(with = |db_dir:  &'a (impl AsRef<Path> + ?Sized)| db_dir.as_ref())]
        db_dir: &'a Path,
        #[builder(default)] db_page_size: PageSize,
        #[builder(default = 25)] max_db_connections: u8,
        drive_id: DriveId,
        scope: Scope,
        #[builder(default = Duration::from_secs(900))] sync_interval: Duration,
        #[builder(default = Duration::from_secs(30))] sync_min_initial: Duration,
        #[builder(default)] sync_limit: SyncLimit,
        #[builder(default)] cache_settings: CacheSettings,
        proactive_cache_interval: Option<Duration>,
        #[builder(default)] upload_settings: UploadSettings,
    ) -> Result<Self, Error> {
        tokio::fs::create_dir_all(db_dir).await?;

        let wal_chunk_size = db_page_size.value() - 128;

        let db = Db::new(
            db_dir.join(format!("arfs-{}.sqlite", drive_id)),
            max_db_connections,
            client.clone(),
            &drive_id,
            &scope,
            db_page_size,
        )
        .await?;

        let drive_config = db.read().await?.config().await?;
        if drive_config.drive.privacy() == Privacy::Private {
            if let Some(key_ring) = scope.key_ring()
                && let Some(signature_format) = drive_config.drive.signature_type()
            {
                key_ring.set_signature_format(signature_format);
            }
        }

        let sync_settings = SyncSettings {
            sync_interval,
            sync_min_initial,
            sync_limit,
            proactive_cache_interval,
        };

        let status = Arc::new(Mutex::new(Arc::new(db.read().await?.status().await?)));

        let vfs = Vfs::new(
            client.clone(),
            db.clone(),
            status.clone(),
            cache_settings,
            wal_chunk_size,
            scope.read_only(),
            scope.key_ring().map(|kr| kr.clone()),
        )
        .await?;

        Ok(Self(Arc::new(
            ErasedArFs::new(
                client,
                db,
                drive_id,
                vfs,
                status,
                sync_settings,
                upload_settings,
                drive_config,
                scope,
            )
            .await?,
        )))
    }

    #[inline]
    pub fn name(&self) -> &str {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => inner.name(),
            ErasedArFs::PublicRW(inner) => inner.name(),
            ErasedArFs::PrivateRO(inner) => inner.name(),
            ErasedArFs::PrivateRW(inner) => inner.name(),
        }
    }

    #[inline]
    pub fn version(&self) -> &ArFsVersion {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => inner.version(),
            ErasedArFs::PublicRW(inner) => inner.version(),
            ErasedArFs::PrivateRO(inner) => inner.version(),
            ErasedArFs::PrivateRW(inner) => inner.version(),
        }
    }

    #[inline]
    pub fn drive_id(&self) -> &DriveId {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => inner.drive_id(),
            ErasedArFs::PublicRW(inner) => inner.drive_id(),
            ErasedArFs::PrivateRO(inner) => inner.drive_id(),
            ErasedArFs::PrivateRW(inner) => inner.drive_id(),
        }
    }

    #[inline]
    pub fn created_at(&self) -> &Timestamp {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => inner.created_at(),
            ErasedArFs::PublicRW(inner) => inner.created_at(),
            ErasedArFs::PrivateRO(inner) => inner.created_at(),
            ErasedArFs::PrivateRW(inner) => inner.created_at(),
        }
    }

    #[inline]
    pub fn owner(&self) -> &WalletAddress {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => inner.owner(),
            ErasedArFs::PublicRW(inner) => inner.owner(),
            ErasedArFs::PrivateRO(inner) => inner.owner(),
            ErasedArFs::PrivateRW(inner) => inner.owner(),
        }
    }

    #[inline]
    pub fn access_mode(&self) -> AccessMode {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(_) | ErasedArFs::PrivateRO(_) => AccessMode::ReadOnly,
            ErasedArFs::PublicRW(_) | ErasedArFs::PrivateRW(_) => AccessMode::ReadWrite,
        }
    }

    #[inline]
    pub fn privacy(&self) -> Privacy {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(_) | ErasedArFs::PublicRW(_) => Privacy::Public,
            ErasedArFs::PrivateRO(_) | ErasedArFs::PrivateRW(_) => Privacy::Private,
        }
    }

    #[inline]
    pub fn sync_status(&self) -> impl Stream<Item = SyncStatus> + Send + Unpin {
        self.syncer().status()
    }

    #[inline]
    fn syncer(&self) -> &Syncer {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => &inner.syncer,
            ErasedArFs::PublicRW(inner) => &inner.syncer,
            ErasedArFs::PrivateRO(inner) => &inner.syncer,
            ErasedArFs::PrivateRW(inner) => &inner.syncer,
        }
    }

    #[inline]
    pub async fn sync_now(&self) -> Result<SyncResult, Error> {
        self.syncer().sync_now().await
    }

    #[inline]
    pub fn vfs(&self) -> &Vfs {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => &inner.vfs,
            ErasedArFs::PublicRW(inner) => &inner.vfs,
            ErasedArFs::PrivateRO(inner) => &inner.vfs,
            ErasedArFs::PrivateRW(inner) => &inner.vfs,
        }
    }

    pub fn status(&self) -> Arc<Status> {
        let status = match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => &inner.status,
            ErasedArFs::PublicRW(inner) => &inner.status,
            ErasedArFs::PrivateRO(inner) => &inner.status,
            ErasedArFs::PrivateRW(inner) => &inner.status,
        }
        .lock()
        .expect("lock not to be poisoned");

        status.clone()
    }

    pub async fn discard_changes(&self) -> Result<(), crate::Error> {
        let mut tx = self.write().await?;
        match tx.status().await?.state() {
            Some(State::Permanent) => {
                // nothing to do
                Ok(())
            }
            Some(State::Wal) => {
                tx.discard_wal_changes().await?;
                tx.commit().await?;
                self.vfs().invalidate_cache(None).await;
                Ok(())
            }
            None => Err(Error::FileSystemNotSynchronized),
        }
    }

    #[inline]
    async fn write(&self) -> Result<Transaction<db::ReadWrite>, Error> {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(_) => Err(Error::ReadOnlyFileSystem),
            ErasedArFs::PublicRW(inner) => Ok(inner.db.write().await?),
            ErasedArFs::PrivateRO(_) => Err(Error::ReadOnlyFileSystem),
            ErasedArFs::PrivateRW(inner) => Ok(inner.db.write().await?),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, EnumString, strum::Display)]
pub enum AccessMode {
    #[strum(serialize = "read_only", serialize = "readonly", serialize = "ro")]
    ReadOnly,
    #[strum(serialize = "read_write", serialize = "readwrite", serialize = "rw")]
    ReadWrite,
}

#[derive(Debug, Copy, Clone, PartialEq, strum::Display)]
pub enum Visibility {
    Visible,
    Hidden,
}

#[derive(Debug, Copy, Clone, PartialEq, strum::Display)]
pub enum State {
    Permanent,
    Wal,
}

#[derive(Debug)]
pub enum Status {
    Initial,
    Synchronized {
        last_sync: Timestamp,
    },
    Wal {
        last_sync: Timestamp,
        last_wal_modification: Option<Timestamp>,
    },
}

impl Status {
    pub fn state(&self) -> Option<State> {
        match self {
            Self::Initial => None,
            Self::Synchronized { .. } => Some(State::Permanent),
            Self::Wal { .. } => Some(State::Wal),
        }
    }
}

pub enum Scope {
    Public(Access<WalletAddress, (Wallet, UploadService)>),
    Private(Access<(WalletAddress, KeyRing), (Wallet, KeyRing, UploadService)>),
}

impl Debug for Scope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(Access::ReadOnly(owner)) => {
                f.write_fmt(format_args!("Public,RO,{}", owner))
            }
            Self::Public(Access::ReadWrite((wallet, _))) => {
                let owner = wallet.address();
                f.write_fmt(format_args!("Public,RW,{}", &owner))
            }
            Self::Private(Access::ReadOnly((owner, _))) => {
                f.write_fmt(format_args!("Private,RO,{}", &owner))
            }
            Self::Private(Access::ReadWrite((wallet, _, _))) => {
                let owner = wallet.address();
                f.write_fmt(format_args!("Private,RW,{}", &owner))
            }
        }
    }
}

impl Scope {
    pub fn public(owner: WalletAddress) -> Self {
        Scope::Public(Access::ReadOnly(owner))
    }

    pub fn public_rw(wallet: Wallet, uploader: UploadService) -> Self {
        Scope::Public(Access::ReadWrite((wallet, uploader)))
    }

    pub fn private(wallet: Wallet, key_ring: KeyRing) -> Self {
        Scope::Private(Access::ReadOnly((wallet.address(), key_ring)))
    }

    pub fn private_rw(wallet: Wallet, key_ring: KeyRing, uploader: UploadService) -> Self {
        Scope::Private(Access::ReadWrite((wallet, key_ring, uploader)))
    }

    fn owner(&self) -> MaybeOwned<'_, WalletAddress> {
        match self {
            Self::Public(public) => match public {
                Access::ReadOnly(owner) => owner.into(),
                Access::ReadWrite((wallet, _)) => wallet.address().into(),
            },
            Self::Private(private) => match private {
                Access::ReadOnly((owner, _)) => owner.into(),
                Access::ReadWrite((wallet, _, _)) => wallet.address().into(),
            },
        }
    }

    fn privacy(&self) -> Privacy {
        match self {
            Self::Public(_) => Privacy::Public,
            Self::Private(_) => Privacy::Private,
        }
    }

    fn key_ring(&self) -> Option<&KeyRing> {
        match self {
            Self::Public(_) => None,
            Self::Private(Access::ReadOnly((_, key_ring)))
            | Self::Private(Access::ReadWrite((_, key_ring, _))) => Some(key_ring),
        }
    }

    fn read_only(&self) -> bool {
        match self {
            Self::Public(Access::ReadOnly(_)) | Self::Private(Access::ReadOnly(_)) => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub enum Access<R, W> {
    ReadOnly(R),
    ReadWrite(W),
}

#[derive(Debug, Display)]
enum ErasedArFs {
    PublicRW(ArFsInner<Public, ReadWrite>),
    PublicRO(ArFsInner<Public, ReadOnly>),
    PrivateRW(ArFsInner<Private, ReadWrite>),
    PrivateRO(ArFsInner<Private, ReadOnly>),
}

impl ErasedArFs {
    async fn new(
        client: Client,
        db: Db,
        drive_id: DriveId,
        vfs: Vfs,
        status: Arc<Mutex<Arc<Status>>>,
        sync_settings: SyncSettings,
        upload_settings: UploadSettings,
        drive_config: DriveConfig,
        scope: Scope,
    ) -> Result<Self, Error> {
        Ok(match scope {
            Scope::Public(public) => match public {
                Access::ReadOnly(owner) => Self::PublicRO(
                    ArFsInner::new_public_ro(
                        client,
                        db,
                        drive_id,
                        vfs,
                        status,
                        sync_settings,
                        drive_config,
                        owner,
                    )
                    .await?,
                ),
                Access::ReadWrite((wallet, uploader)) => Self::PublicRW(
                    ArFsInner::new_public_rw(
                        client,
                        db,
                        drive_id,
                        vfs,
                        status,
                        sync_settings,
                        upload_settings,
                        drive_config,
                        wallet,
                        uploader,
                    )
                    .await?,
                ),
            },
            Scope::Private(private) => match private {
                Access::ReadOnly((_, drive_key)) => Self::PrivateRO(
                    ArFsInner::new_private_ro(
                        client,
                        db,
                        drive_id,
                        vfs,
                        status,
                        sync_settings,
                        drive_config,
                        drive_key,
                    )
                    .await?,
                ),
                Access::ReadWrite((wallet, drive_key, uploader)) => Self::PrivateRW(
                    ArFsInner::new_private_rw(
                        client,
                        db,
                        drive_id,
                        vfs,
                        status,
                        sync_settings,
                        upload_settings,
                        drive_config,
                        drive_key,
                        wallet,
                        uploader,
                    )
                    .await?,
                ),
            },
        })
    }
}

impl ArFsInner<Public, ReadOnly> {
    async fn new_public_ro(
        client: Client,
        db: Db,
        drive_id: DriveId,
        vfs: Vfs,
        status: Arc<Mutex<Arc<Status>>>,
        sync_settings: SyncSettings,
        drive_config: DriveConfig,
        owner: WalletAddress,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(Public { owner });
        let mode = Arc::new(ReadOnly);
        let upload_settings = UploadSettings::default();
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            drive_id,
            vfs.clone(),
            privacy.clone(),
            mode.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
            sync_settings.sync_limit,
            sync_settings.proactive_cache_interval,
            upload_settings.upload_limit,
            upload_settings.batch_settle_time,
        )
        .await?;
        Ok(ArFsInner {
            client,
            db,
            vfs,
            status,
            syncer,
            drive_config,
            privacy,
            mode,
        })
    }
}

impl ArFsInner<Public, ReadWrite> {
    async fn new_public_rw(
        client: Client,
        db: Db,
        drive_id: DriveId,
        vfs: Vfs,
        status: Arc<Mutex<Arc<Status>>>,
        sync_settings: SyncSettings,
        upload_settings: UploadSettings,
        drive_config: DriveConfig,
        wallet: Wallet,
        uploader: UploadService,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(Public {
            owner: wallet.address(),
        });
        let mode = Arc::new(ReadWrite(wallet, uploader));
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            drive_id,
            vfs.clone(),
            privacy.clone(),
            mode.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
            sync_settings.sync_limit,
            sync_settings.proactive_cache_interval,
            upload_settings.upload_limit,
            upload_settings.batch_settle_time,
        )
        .await?;
        Ok(ArFsInner {
            client,
            db,
            vfs,
            status,
            syncer,
            drive_config,
            privacy,
            mode,
        })
    }
}

impl ArFsInner<Private, ReadOnly> {
    async fn new_private_ro(
        client: Client,
        db: Db,
        drive_id: DriveId,
        vfs: Vfs,
        status: Arc<Mutex<Arc<Status>>>,
        sync_settings: SyncSettings,
        drive_config: DriveConfig,
        key_ring: KeyRing,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(Private::new(drive_config.owner.clone(), key_ring));
        let mode = Arc::new(ReadOnly);
        let upload_settings = UploadSettings::default();
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            drive_id,
            vfs.clone(),
            privacy.clone(),
            mode.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
            sync_settings.sync_limit,
            sync_settings.proactive_cache_interval,
            upload_settings.upload_limit,
            upload_settings.batch_settle_time,
        )
        .await?;
        Ok(ArFsInner {
            client,
            db,
            vfs,
            status,
            syncer,
            drive_config,
            privacy,
            mode,
        })
    }
}

impl ArFsInner<Private, ReadWrite> {
    async fn new_private_rw(
        client: Client,
        db: Db,
        drive_id: DriveId,
        vfs: Vfs,
        status: Arc<Mutex<Arc<Status>>>,
        sync_settings: SyncSettings,
        upload_settings: UploadSettings,
        drive_config: DriveConfig,
        key_ring: KeyRing,
        wallet: Wallet,
        uploader: UploadService,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(Private::new(drive_config.owner.clone(), key_ring));
        let mode = Arc::new(ReadWrite(wallet, uploader));
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            drive_id,
            vfs.clone(),
            privacy.clone(),
            mode.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
            sync_settings.sync_limit,
            sync_settings.proactive_cache_interval,
            upload_settings.upload_limit,
            upload_settings.batch_settle_time,
        )
        .await?;
        Ok(ArFsInner {
            client,
            db,
            vfs,
            status,
            syncer,
            drive_config,
            privacy,
            mode,
        })
    }
}

impl<PRIVACY, MODE> ArFsInner<PRIVACY, MODE> {
    fn name(&self) -> &str {
        self.drive_config.drive.name()
    }

    fn version(&self) -> &ArFsVersion {
        self.drive_config.drive.header().version()
    }

    fn drive_id(&self) -> &DriveId {
        &self.drive_config.drive.header().as_inner().drive_id
    }

    fn created_at(&self) -> &Timestamp {
        &self.drive_config.drive.header().as_inner().time
    }

    fn display(
        &self,
        f: &mut Formatter<'_>,
        privacy: &'static str,
        mode: &'static str,
        owner: &WalletAddress,
    ) -> fmt::Result {
        writeln!(f, "ArFS Version: {}", self.version())?;
        writeln!(f, "Drive ID: {}", self.drive_id())?;
        writeln!(f, "Owner: {}", &owner)?;
        writeln!(f, "Privacy: {}", privacy)?;
        writeln!(f, "Access Mode: {}", mode)?;
        write!(f, "Created at: {}", self.created_at())
    }
}

pub type UploadService = Arc<tokio::sync::Mutex<Uploader>>;

struct ReadWrite(Wallet, UploadService);

impl Debug for ReadWrite {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let owner = self.0.address();
        f.write_fmt(format_args!("RW({})", &owner))
    }
}

#[derive(Debug)]
struct ReadOnly;

#[derive(Debug)]
struct ArFsInner<PRIVACY, MODE> {
    client: Client,
    db: Db,
    vfs: Vfs,
    status: Arc<Mutex<Arc<Status>>>,
    syncer: Syncer,
    drive_config: DriveConfig,
    privacy: Arc<PRIVACY>,
    mode: Arc<MODE>,
}

#[derive(Debug)]
struct Public {
    owner: WalletAddress,
}

impl<Mode> ArFsInner<Public, Mode> {
    pub fn owner(&self) -> &WalletAddress {
        &self.privacy.owner
    }

    fn display_public(&self, f: &mut fmt::Formatter<'_>, mode: &'static str) -> fmt::Result {
        self.display(f, "Public", mode, self.owner())
    }
}

impl Display for ArFsInner<Public, ReadOnly> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_public(f, "Read Only")
    }
}

impl Display for ArFsInner<Public, ReadWrite> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_public(f, "Read/Write")
    }
}

#[derive(Debug)]
#[repr(transparent)]
struct Password(Confidential<Box<str>>);

impl Deref for Password {
    type Target = Confidential<Box<str>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for Password {
    fn from(mut value: String) -> Self {
        // into_boxed_str() calls shrink_to_fit(), which reallocates if capacity > len.
        // Reallocation would leave a copy of the plaintext password in the old buffer.
        // We handle this case explicitly to zeroize the old buffer before conversion.
        let value = if value.capacity() > value.len() {
            let mut new_string = String::with_capacity(value.len());
            new_string.push_str(&value);
            value.zeroize();
            new_string
        } else {
            value
        };

        Self(value.into_boxed_str().confidential())
    }
}

impl From<Confidential<String>> for Password {
    fn from(value: Confidential<String>) -> Self {
        //todo: convert directly
        value.reveal().to_string().into()
    }
}

#[derive(Debug)]
enum AuthCredentials {
    Password(Password),
}

impl From<&AuthCredentials> for AuthMode {
    fn from(value: &AuthCredentials) -> Self {
        match value {
            AuthCredentials::Password(_) => AuthMode::Password,
        }
    }
}

impl From<Password> for AuthCredentials {
    fn from(value: Password) -> Self {
        AuthCredentials::Password(value)
    }
}

#[derive(Debug)]
struct Private {
    owner: WalletAddress,
    key_ring: KeyRing,
}

impl Private {
    fn new(owner: WalletAddress, key_ring: KeyRing) -> Self {
        Self { owner, key_ring }
    }
}

impl<Mode> ArFsInner<Private, Mode> {
    pub fn owner(&self) -> &WalletAddress {
        &self.privacy.owner
    }
}

impl Display for ArFsInner<Private, ReadOnly> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Private, Read Only")
    }
}

impl Display for ArFsInner<Private, ReadWrite> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Private, Read/Write")
    }
}

#[cfg(test)]
mod tests {
    use crate::types::drive::DriveId;
    use crate::{
        ArFs, Direct, Inode, KeyRing, Price, PriceAdjustment, PriceLimit, Scope, SyncStatus,
        Uploader, VfsPath, resolve,
    };
    use ario_client::{ByteSize, Client};
    use ario_core::jwk::Jwk;
    use ario_core::money::Money;
    use ario_core::network::Network;
    use ario_core::wallet::{Wallet, WalletAddress};
    use ario_core::{BigDecimal, Gateway};
    use futures_lite::AsyncReadExt;
    use futures_lite::stream::StreamExt;
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    async fn init() -> anyhow::Result<(Client, Wallet)> {
        dotenv::dotenv().ok();
        init_tracing();

        let arlocal = std::env::var("ARLOCAL_URL").unwrap();
        let network_id = std::env::var("ARLOCAL_ID").unwrap_or("arlocal".to_string());
        let wallet_jwk = std::env::var("ARLOCAL_WALLET_JWK").unwrap();

        let client = Client::builder()
            .network(Network::Local(network_id.try_into()?))
            .gateways([Gateway::from_str(arlocal.as_str())?])
            .enable_netwatch(false)
            .build()
            .await?;

        let json =
            tokio::fs::read_to_string(<PathBuf as AsRef<Path>>::as_ref(&PathBuf::from(wallet_jwk)))
                .await?;

        let jwk = Jwk::from_json(json.as_str())?;
        let wallet = Wallet::from_jwk(&jwk)?;

        Ok((client, wallet))
    }

    #[ignore]
    #[tokio::test]
    async fn builder() -> anyhow::Result<()> {
        let (client, wallet) = init().await?;
        let drive_owner = wallet.address();

        let (drive_id, _) = resolve::find_drive_ids_by_owner(&client, &drive_owner)
            .try_next()
            .await?
            .unwrap();

        let key_ring = KeyRing::builder()
            .drive_id(&drive_id)
            .wallet(&wallet)
            .password("foo".to_string())
            .build()?;

        let mode = Box::new(Direct::new(
            client.clone(),
            wallet.clone(),
            PriceAdjustment::default(),
        ));

        let uploader = Arc::new(tokio::sync::Mutex::new(
            Uploader::builder()
                .mode(mode)
                .client(client.clone())
                .build()
                .await?,
        ));

        let arfs = ArFs::builder()
            .client(client.clone())
            .db_dir(&PathBuf::from_str("/tmp/")?)
            .scope(Scope::private_rw(wallet, key_ring, uploader))
            .drive_id(drive_id)
            .build()
            .await?;

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn foo() -> anyhow::Result<()> {
        let (client, wallet) = init().await?;
        let drive_owner = wallet.address();

        let mut stream = resolve::find_drive_ids_by_owner(&client, &drive_owner);

        while let Some((drive_id, _)) = stream.try_next().await? {
            let arfs = ArFs::builder()
                .client(client.clone())
                .drive_id(drive_id)
                .db_dir("/tmp/foo/")
                .scope(Scope::public(drive_owner.clone()))
                .sync_min_initial(Duration::from_millis(0))
                .sync_interval(Duration::from_secs(10))
                .build()
                .await?;

            println!("{}", arfs);

            let mut started = false;

            let mut status = arfs.sync_status();
            while let Some(status) = status.next().await {
                match status {
                    SyncStatus::Syncing { .. }
                    | SyncStatus::Uploading { .. }
                    | SyncStatus::ProactiveCaching { .. } => {
                        started = true;
                    }
                    SyncStatus::Dead => {
                        break;
                    }
                    SyncStatus::Idle { .. } => {
                        if started {
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn list_public_drive() -> anyhow::Result<()> {
        dotenv::dotenv().ok();
        init_tracing();

        let client = Client::builder()
            .gateways([Gateway::default()])
            .enable_netwatch(false)
            .build()
            .await?;

        //let drive_owner = WalletAddress::from_str("hT7N1hMVlm168EmTFJR2mr4Qula9rkUZ_6S4JnSLQOc")?;
        //let drive_id = DriveId::from_str("1145e1c7-23a3-4ec3-9f8c-570b1e9a1bc7")?;

        //let drive_owner = WalletAddress::from_str("nP93US2zQ9M8woZM3dptHm-IQYIJLZhvoS3xL7sqUdk")?;
        //let drive_id = DriveId::from_str("094436c7-9d73-4942-97f2-467477d62a81")?;

        //let drive_owner = WalletAddress::from_str("m6eeNI_nADsDdGnpJmy3acX_VurlU_nMLTi05789cl0")?;
        //let drive_id = DriveId::from_str("680630e3-64b0-4c11-8150-d7929619db48")?;

        //let drive_owner = WalletAddress::from_str("2v22SB6hwA_QuXDlXyYRr9nkhwxop1iPXT_ViGLwOwA")?;
        //let drive_id = DriveId::from_str("2e7952b2-6246-41dc-9ee9-fcc138723001")?;

        let drive_owner = WalletAddress::from_str("HGoC7PVku6TzOh0SsITsWMJW8iUcOcdGmPaKm3IhvJQ")?;
        let drive_id = DriveId::from_str("d669b973-d9d2-430d-b2cc-96072054dc1a")?;

        let arfs = ArFs::builder()
            .client(client.clone())
            .drive_id(drive_id)
            .db_dir("/tmp/foo/")
            .scope(Scope::public(drive_owner.clone()))
            .build()
            .await?;

        arfs.sync_now().await?;

        let vfs = arfs.vfs();
        let root = vfs.root();

        let mut dirs = VecDeque::new();
        dirs.push_back((Inode::Root(root), 0));

        while let Some((dir, depth)) = dirs.pop_front() {
            println!(
                "{indent} {path}",
                indent = " ".repeat(depth),
                path = dir.path()
            );
            let mut stream = vfs.list(&dir).await?;
            while let Some(inode) = stream.try_next().await? {
                match inode {
                    Inode::Directory(dir) => {
                        dirs.push_back((Inode::Directory(dir), depth + 1));
                    }
                    Inode::File(file) => {
                        println!(
                            "{indent} {name}:{size}",
                            indent = " ".repeat(depth),
                            name = file.name(),
                            size = file.size(),
                        );
                    }
                    _ => unreachable!(),
                }
            }
        }

        let path = VfsPath::try_from("/1studiooffice166a/Screenshot_2025-09-15_15-45-56.jpg")?;
        if let Some(Inode::File(file)) = vfs.inode_by_path(&path).await? {
            let mut reader = vfs.read_file(&file).await?;
            let mut buf = vec![];
            reader.read_to_end(&mut buf).await?;
            assert_eq!(buf.len(), file.size().as_u64() as usize);
        } else {
            panic!("expected file to exist")
        }
        Ok(())
    }

    #[test]
    fn price_limit() -> anyhow::Result<()> {
        let price_limit_1 = "10 USD/GiB";
        let price_limit_2 = "10000 W/ kb";
        let negative_price_limit = "-10 Ar/gb";
        let invalid_price_limit = "1222 /fsad";

        let price_limit = PriceLimit::from_str(price_limit_1)?;
        assert_eq!(
            price_limit,
            PriceLimit {
                price: Price::USD(Money::from_str("10.0")?),
                unit: ByteSize::gib(1),
            }
        );

        let price_limit = PriceLimit::from_str(price_limit_2)?;
        assert_eq!(
            price_limit,
            PriceLimit {
                price: Price::Winston(Money::from_str("10000")?),
                unit: ByteSize::kb(1),
            }
        );

        let res = PriceLimit::from_str(invalid_price_limit);
        assert!(res.is_err());

        let res = PriceLimit::from_str(negative_price_limit);
        assert!(res.is_err());

        Ok(())
    }

    #[test]
    fn price_adjustment() -> anyhow::Result<()> {
        let price_adjustment_1 = "+10%";
        let price_adjustment_2 = "-5%";
        let invalid_price_adjustment_1 = "10%";
        let invalid_price_adjustment_2 = "+foo%";

        let value = PriceAdjustment::from_str(price_adjustment_1)?;
        assert_eq!(value.0, BigDecimal::from_str("0.1")?);

        let value = PriceAdjustment::from_str(price_adjustment_2)?;
        assert_eq!(value.0, BigDecimal::from_str("-0.05")?);

        let res = PriceAdjustment::from_str(invalid_price_adjustment_1);
        assert!(res.is_err());

        let res = PriceAdjustment::from_str(invalid_price_adjustment_2);
        assert!(res.is_err());

        Ok(())
    }
}
