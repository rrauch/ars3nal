extern crate core;

mod crypto;
mod db;
pub(crate) mod resolve;
pub(crate) mod serde_tag;
mod sync;
pub(crate) mod types;
mod vfs;
mod wal;

pub use crate::db::Error as DbError;
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

use ario_client::Client;
use ario_core::MaybeOwned;
use ario_core::confidential::{Confidential, NewSecretExt, RevealExt, RevealMutExt};
use ario_core::tx::TxId;
use ario_core::wallet::{Wallet, WalletAddress};

use crate::types::file::FileId;
use ario_core::crypto::encryption::DecryptionExt;
use ario_core::crypto::hash::Hasher;
use bon::Builder;
use core::fmt;
use derive_more::Display;
use futures_lite::Stream;
use rsa::rand_core::{CryptoRng, RngCore};
use rsa::signature::hazmat::RandomizedPrehashSigner;
use serde_json::Error as JsonError;
use std::fmt::{Debug, Display, Formatter};
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use strum::EnumString;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroize;

pub use crypto::DriveKey;

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
    #[error("read-only file system")]
    ReadOnlyFileSystem,
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
pub struct SyncLimit(Arc<Semaphore>);

#[repr(transparent)]
pub(crate) struct SyncPermit(OwnedSemaphorePermit);

impl SyncLimit {
    pub fn new(max_concurrency: NonZeroUsize) -> Self {
        Self(Arc::new(Semaphore::new(max_concurrency.get())))
    }

    pub(crate) async fn acquire_permit(&self) -> Result<SyncPermit, sync::Error> {
        Ok(SyncPermit(
            self.0
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| sync::Error::PermitAcquisitionFailed)?,
        ))
    }
}

impl Default for SyncLimit {
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
        )
        .await?;

        Ok(Self(Arc::new(
            ErasedArFs::new(client, db, vfs, status, sync_settings, drive_config, scope).await?,
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
        last_wal_modification: Timestamp,
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

#[derive(Debug)]
pub enum Scope {
    Public(Access<WalletAddress, Wallet>),
    Private(Access<(WalletAddress, DriveKey), (Wallet, DriveKey)>),
}

impl Scope {
    pub fn public(owner: WalletAddress) -> Self {
        Scope::Public(Access::ReadOnly(owner))
    }

    pub fn public_rw(wallet: Wallet) -> Self {
        Scope::Public(Access::ReadWrite(wallet))
    }

    pub fn private(wallet: Wallet, drive_key: DriveKey) -> Self {
        Scope::Private(Access::ReadOnly((wallet.address(), drive_key)))
    }

    pub fn private_rw(wallet: Wallet, drive_key: DriveKey) -> Self {
        Scope::Private(Access::ReadWrite((wallet, drive_key)))
    }

    fn owner(&self) -> MaybeOwned<'_, WalletAddress> {
        match self {
            Self::Public(public) => match public {
                Access::ReadOnly(owner) => owner.into(),
                Access::ReadWrite(wallet) => wallet.address().into(),
            },
            Self::Private(private) => match private {
                Access::ReadOnly((owner, _)) => owner.into(),
                Access::ReadWrite((wallet, _)) => wallet.address().into(),
            },
        }
    }

    fn privacy(&self) -> Privacy {
        match self {
            Self::Public(_) => Privacy::Public,
            Self::Private(_) => Privacy::Private,
        }
    }

    fn drive_key(&self) -> Option<&DriveKey> {
        match self {
            Self::Public(_) => None,
            Self::Private(Access::ReadOnly((_, drive_key)))
            | Self::Private(Access::ReadWrite((_, drive_key))) => Some(drive_key),
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
        vfs: Vfs,
        status: Arc<Mutex<Arc<Status>>>,
        sync_settings: SyncSettings,
        drive_config: DriveConfig,
        scope: Scope,
    ) -> Result<Self, Error> {
        Ok(match scope {
            Scope::Public(public) => match public {
                Access::ReadOnly(owner) => Self::PublicRO(
                    ArFsInner::new_public_ro(
                        client,
                        db,
                        vfs,
                        status,
                        sync_settings,
                        drive_config,
                        owner,
                    )
                    .await?,
                ),
                Access::ReadWrite(wallet) => Self::PublicRW(
                    ArFsInner::new_public_rw(
                        client,
                        db,
                        vfs,
                        status,
                        sync_settings,
                        drive_config,
                        wallet,
                    )
                    .await?,
                ),
            },
            Scope::Private(private) => match private {
                Access::ReadOnly((_, drive_key)) => Self::PrivateRO(
                    ArFsInner::new_private_ro(
                        client,
                        db,
                        vfs,
                        status,
                        sync_settings,
                        drive_config,
                        drive_key,
                    )
                    .await?,
                ),
                Access::ReadWrite((wallet, drive_key)) => Self::PrivateRW(
                    ArFsInner::new_private_rw(
                        client,
                        db,
                        vfs,
                        status,
                        sync_settings,
                        drive_config,
                        drive_key,
                        wallet,
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
        vfs: Vfs,
        status: Arc<Mutex<Arc<Status>>>,
        sync_settings: SyncSettings,
        drive_config: DriveConfig,
        owner: WalletAddress,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(Public { owner });
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            vfs.clone(),
            privacy.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
            sync_settings.sync_limit,
            sync_settings.proactive_cache_interval,
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
            mode: ReadOnly,
        })
    }
}

impl ArFsInner<Public, ReadWrite> {
    async fn new_public_rw(
        client: Client,
        db: Db,
        vfs: Vfs,
        status: Arc<Mutex<Arc<Status>>>,
        sync_settings: SyncSettings,
        drive_config: DriveConfig,
        wallet: Wallet,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(Public {
            owner: wallet.address(),
        });
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            vfs.clone(),
            privacy.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
            sync_settings.sync_limit,
            sync_settings.proactive_cache_interval,
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
            mode: ReadWrite(wallet),
        })
    }
}

impl ArFsInner<Private, ReadOnly> {
    async fn new_private_ro(
        client: Client,
        db: Db,
        vfs: Vfs,
        status: Arc<Mutex<Arc<Status>>>,
        sync_settings: SyncSettings,
        drive_config: DriveConfig,
        drive_key: DriveKey,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(Private::new(drive_config.owner.clone(), drive_key));
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            vfs.clone(),
            privacy.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
            sync_settings.sync_limit,
            sync_settings.proactive_cache_interval,
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
            mode: ReadOnly,
        })
    }
}

impl ArFsInner<Private, ReadWrite> {
    async fn new_private_rw(
        client: Client,
        db: Db,
        vfs: Vfs,
        status: Arc<Mutex<Arc<Status>>>,
        sync_settings: SyncSettings,
        drive_config: DriveConfig,
        drive_key: DriveKey,
        wallet: Wallet,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(Private::new(drive_config.owner.clone(), drive_key));
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            vfs.clone(),
            privacy.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
            sync_settings.sync_limit,
            sync_settings.proactive_cache_interval,
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
            mode: ReadWrite(wallet),
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

    async fn vfs(&self) -> Arc<Vfs> {
        todo!()
    }

    fn display(
        &self,
        f: &mut fmt::Formatter<'_>,
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

#[derive(Debug)]
struct ReadWrite(Wallet);

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
    mode: MODE,
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
    drive_key: DriveKey,
}

impl Private {
    fn new(owner: WalletAddress, drive_key: DriveKey) -> Self {
        Self { owner, drive_key }
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
    use crate::{ArFs, DriveKey, Inode, Scope, SyncStatus, VfsPath, resolve};
    use ario_client::Client;
    use ario_core::Gateway;
    use ario_core::jwk::Jwk;
    use ario_core::network::Network;
    use ario_core::wallet::{Wallet, WalletAddress};
    use futures_lite::AsyncReadExt;
    use futures_lite::stream::StreamExt;
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
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

        let drive_key = DriveKey::derive_from(&drive_id, &wallet, "foo".to_string())?;

        let arfs = ArFs::builder()
            .client(client.clone())
            .db_dir(&PathBuf::from_str("/tmp/foo/")?)
            .scope(Scope::private_rw(wallet, drive_key))
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
                    SyncStatus::Syncing { .. } | SyncStatus::ProactiveCaching { .. } => {
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
}
