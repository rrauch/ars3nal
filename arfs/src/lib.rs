extern crate core;

mod db;
pub(crate) mod serde_tag;
mod sync;
pub(crate) mod types;
mod vfs;

pub use ario_core::bundle::Owner as BundleOwner;
pub use ario_core::tx::Owner as TxOwner;
pub use types::{ArFsVersion, ContentType, Privacy};
pub use vfs::{Directory, File, Inode, Timestamp, Vfs};

use crate::db::Db;
use crate::db::Error as DbError;
use crate::sync::Syncer;
use crate::types::drive::{DriveEntity, DriveHeader, DriveId, DriveKind};
use crate::types::folder::{FolderEntity, FolderId, FolderKind};
use crate::types::{AuthMode, Entity, HasId, Header, Metadata, Model, ParseError};
use crate::vfs::Error as VfsError;
use ario_client::Client;
use ario_client::Error as ClientError;
use ario_client::data_reader::DataReader;
use ario_client::graphql::{
    SortOrder, TagFilter, TxQuery, TxQueryFilterCriteria, TxQueryItem, WithTxResponseFields,
};
use ario_client::location::Arl;
use ario_client::tx::Status as TxStatus;
use ario_core::confidential::{Confidential, NewSecretExt};
use ario_core::tag::Tag;
use ario_core::tx::TxId;
use ario_core::wallet::{Wallet, WalletAddress};
use ario_core::{JsonValue, MaybeOwned};
use core::fmt;
use derive_more::Display;
use futures_lite::{AsyncReadExt, Stream, StreamExt};
use serde_json::Error as JsonError;
use std::fmt::{Debug, Display, Formatter};
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use strum::EnumString;
use thiserror::Error;
use zeroize::Zeroize;

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
    SyncError(#[from] sync::Error),
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
    #[error("drive mismatch, expected '{expected}' but found '{actual}'")]
    DriveMismatch { expected: DriveId, actual: DriveId },
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

struct SyncSettings {
    sync_interval: Duration,
    sync_min_initial: Duration,
}

#[bon::bon]
impl ArFs {
    #[builder(derive(Debug))]
    pub async fn new<'a>(
        client: Client,
        #[builder(with = |db_dir:  &'a (impl AsRef<Path> + ?Sized)| db_dir.as_ref())]
        db_dir: &'a Path,
        #[builder(default = 25)] max_db_connections: u8,
        drive_id: DriveId,
        scope: Scope,
        #[builder(default = Duration::from_secs(900))] sync_interval: Duration,
        #[builder(default = Duration::from_secs(60))] sync_min_initial: Duration,
    ) -> Result<Self, Error> {
        tokio::fs::create_dir_all(db_dir).await?;
        let db = Db::new(
            db_dir.join(format!("arfs-{}.sqlite", drive_id)),
            max_db_connections,
            client.clone(),
            &drive_id,
            &scope,
        )
        .await?;

        let (drive_id, item) =
            find_drive_by_id_owner(&client, &drive_id, scope.owner().as_ref()).await?;
        let location = client.location_by_item_id(&item.id()).await?;
        let drive = drive_entity(
            &client,
            &drive_id,
            &location,
            scope.owner().as_ref(),
            scope.as_private(),
        )
        .await?;

        let sync_settings = SyncSettings {
            sync_interval,
            sync_min_initial,
        };

        Ok(Self(Arc::new(
            ErasedArFs::new(client, db, sync_settings, drive, scope).await?,
        )))
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
}

#[derive(Debug, Copy, Clone, PartialEq, EnumString, strum::Display)]
pub enum AccessMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug)]
pub enum Scope {
    Public(Access<WalletAddress, Wallet>),
    Private(Access<Credentials, Credentials>),
}

impl Scope {
    pub fn public(owner: WalletAddress) -> Self {
        Scope::Public(Access::ReadOnly(owner))
    }

    pub fn public_rw(wallet: Wallet) -> Self {
        Scope::Public(Access::ReadWrite(wallet))
    }

    pub fn private(credentials: Credentials) -> Self {
        Scope::Private(Access::ReadOnly(credentials))
    }

    pub fn private_rw(credentials: Credentials) -> Self {
        Scope::Private(Access::ReadWrite(credentials))
    }

    fn owner(&self) -> MaybeOwned<'_, WalletAddress> {
        match self {
            Self::Public(public) => match public {
                Access::ReadOnly(owner) => owner.into(),
                Access::ReadWrite(wallet) => wallet.address().into(),
            },
            Self::Private(private) => match private {
                Access::ReadOnly(creds) | Access::ReadWrite(creds) => {
                    (&creds.0.wallet_address).into()
                }
            },
        }
    }

    fn privacy(&self) -> Privacy {
        match self {
            Self::Public(_) => Privacy::Public,
            Self::Private(_) => Privacy::Private,
        }
    }

    fn as_private(&self) -> Option<&Private> {
        match self {
            Self::Public(_) => None,
            Self::Private(private) => match private {
                Access::ReadOnly(creds) | Access::ReadWrite(creds) => Some(&creds.0),
            },
        }
    }
}

#[derive(Debug)]
pub enum Access<R, W> {
    ReadOnly(R),
    ReadWrite(W),
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Credentials(Private);

impl Credentials {
    pub fn with_password<P: Into<Password>>(wallet: Wallet, password: P) -> Self {
        Self(Private {
            wallet_address: wallet.address(),
            wallet,
            auth: password.into().into(),
        })
    }
}

#[derive(Debug, Display)]
enum ErasedArFs {
    PublicRW(ArFsInner<Public, ReadWrite<Wallet>>),
    PublicRO(ArFsInner<Public, ReadOnly>),
    PrivateRW(ArFsInner<Private, ReadWrite>),
    PrivateRO(ArFsInner<Private, ReadOnly>),
}

impl ErasedArFs {
    async fn new(
        client: Client,
        db: Db,
        sync_settings: SyncSettings,
        drive: DriveEntity,
        scope: Scope,
    ) -> Result<Self, Error> {
        Ok(match scope {
            Scope::Public(public) => match public {
                Access::ReadOnly(owner) => Self::PublicRO(
                    ArFsInner::new_public_ro(client, db, sync_settings, drive, owner).await?,
                ),
                Access::ReadWrite(wallet) => Self::PublicRW(
                    ArFsInner::new_public_rw(client, db, sync_settings, drive, wallet).await?,
                ),
            },
            Scope::Private(private) => match private {
                Access::ReadOnly(creds) => Self::PrivateRO(
                    ArFsInner::new_private_ro(client, db, sync_settings, drive, creds).await?,
                ),
                Access::ReadWrite(creds) => Self::PrivateRW(
                    ArFsInner::new_private_rw(client, db, sync_settings, drive, creds).await?,
                ),
            },
        })
    }
}

impl ArFsInner<Public, ReadOnly> {
    async fn new_public_ro(
        client: Client,
        db: Db,
        sync_settings: SyncSettings,
        drive: DriveEntity,
        owner: WalletAddress,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(Public { owner });
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            privacy.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
        )
        .await?;
        Ok(ArFsInner {
            client,
            db,
            syncer,
            drive,
            privacy,
            mode: ReadOnly,
        })
    }
}

impl ArFsInner<Public, ReadWrite<Wallet>> {
    async fn new_public_rw(
        client: Client,
        db: Db,
        sync_settings: SyncSettings,
        drive: DriveEntity,
        wallet: Wallet,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(Public {
            owner: wallet.address(),
        });
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            privacy.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
        )
        .await?;
        Ok(ArFsInner {
            client,
            db,
            syncer,
            drive,
            privacy,
            mode: ReadWrite(wallet),
        })
    }
}

impl ArFsInner<Private, ReadOnly> {
    async fn new_private_ro(
        client: Client,
        db: Db,
        sync_settings: SyncSettings,
        drive: DriveEntity,
        credentials: Credentials,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(credentials.0);
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            privacy.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
        )
        .await?;
        Ok(ArFsInner {
            client,
            db,
            syncer,
            drive,
            privacy,
            mode: ReadOnly,
        })
    }
}

impl ArFsInner<Private, ReadWrite> {
    async fn new_private_rw(
        client: Client,
        db: Db,
        sync_settings: SyncSettings,
        drive: DriveEntity,
        credentials: Credentials,
    ) -> Result<Self, Error> {
        let privacy = Arc::new(credentials.0);
        let syncer = Syncer::new(
            client.clone(),
            db.clone(),
            privacy.clone(),
            sync_settings.sync_interval,
            sync_settings.sync_min_initial,
        )
        .await?;
        Ok(ArFsInner {
            client,
            db,
            syncer,
            drive,
            privacy,
            mode: ReadWrite::default(),
        })
    }
}

impl<PRIVACY, MODE> ArFsInner<PRIVACY, MODE> {
    fn version(&self) -> &ArFsVersion {
        self.drive.header().version()
    }

    fn drive_id(&self) -> &DriveId {
        &self.drive.header().as_inner().drive_id
    }

    fn created_at(&self) -> &Timestamp {
        &self.drive.header().as_inner().time
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
struct ReadWrite<C = ()>(C);

impl Default for ReadWrite {
    fn default() -> Self {
        Self(())
    }
}

#[derive(Debug)]
struct ReadOnly;

#[derive(Debug)]
struct ArFsInner<PRIVACY, MODE> {
    client: Client,
    db: Db,
    syncer: Syncer,
    drive: DriveEntity,
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

impl<C> Display for ArFsInner<Public, ReadWrite<C>> {
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
    wallet: Wallet,
    wallet_address: WalletAddress,
    auth: AuthCredentials,
}

impl Private {
    fn new(wallet: Wallet, auth: AuthCredentials) -> Self {
        let wallet_address = wallet.address();
        Self {
            wallet,
            wallet_address,
            auth,
        }
    }
}

impl<Mode> ArFsInner<Private, Mode> {
    pub fn owner(&self) -> &WalletAddress {
        &self.privacy.wallet_address
    }

    fn display_private(&self, f: &mut fmt::Formatter<'_>, mode: &'static str) -> fmt::Result {
        match self.privacy.auth {
            AuthCredentials::Password(_) => {
                self.display(f, "Private (Password)", mode, self.owner())
            }
        }
    }
}

impl Display for ArFsInner<Private, ReadOnly> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_private(f, "Read Only")
    }
}

impl Display for ArFsInner<Private, ReadWrite> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_private(f, "Read/Write")
    }
}

type TagsOnly = WithTxResponseFields<false, false, false, false, false, false, true, false>;

fn find_drive_ids_by_owner<'a>(
    client: &'a Client,
    owner: &'a WalletAddress,
) -> impl Stream<Item = Result<(DriveId, TxQueryItem), Error>> + Unpin + 'a {
    client
        .query_transactions_with_fields::<TagsOnly>(
            TxQuery::builder()
                .filter_criteria(
                    TxQueryFilterCriteria::builder()
                        .owners([owner])
                        .tags([TagFilter::builder()
                            .name("Entity-Type")
                            .values(["drive"])
                            .build()])
                        .build(),
                )
                .sort_order(SortOrder::HeightDescending)
                .build(),
        )
        .map(|r| match r {
            Ok(item) => Ok((to_drive_id(&item)?, item)),
            Err(e) => Err(e.into()),
        })
}

fn to_drive_id(item: &TxQueryItem) -> Result<DriveId, Error> {
    let drive_header =
        Header::<DriveHeader, DriveKind>::try_from(item.tags()).map_err(EntityError::ParseError)?;
    Ok(drive_header.into_inner().drive_id)
}

async fn find_drive_by_id_owner<'a>(
    client: &'a Client,
    drive_id: &'a DriveId,
    owner: &'a WalletAddress,
) -> Result<(DriveId, TxQueryItem), Error> {
    client
        .query_transactions_with_fields::<TagsOnly>(
            TxQuery::builder()
                .filter_criteria(
                    TxQueryFilterCriteria::builder()
                        .owners([owner])
                        .tags([
                            TagFilter::builder()
                                .name("Entity-Type")
                                .values(["drive"])
                                .build(),
                            TagFilter::builder()
                                .name("Drive-Id")
                                .values([drive_id.to_string()])
                                .build(),
                        ])
                        .build(),
                )
                .sort_order(SortOrder::HeightDescending)
                .max_results(NonZeroUsize::try_from(1).unwrap())
                .build(),
        )
        .map(|r| match r {
            Ok(item) => Ok((to_drive_id(&item)?, item)),
            Err(e) => Err(Error::from(e)),
        })
        .try_next()
        .await?
        .ok_or(
            EntityError::NotFound {
                entity_type: "drive",
                details: drive_id.to_string(),
            }
            .into(),
        )
}

async fn find_entity_location_by_id_drive<'a, E: Entity + HasId>(
    client: &'a Client,
    id: &E::Id,
    drive_id: &'a DriveId,
) -> Result<Arl, Error>
where
    <E as HasId>::Id: Display,
{
    let item = client
        .query_transactions_with_fields::<TagsOnly>(
            TxQuery::builder()
                .filter_criteria(
                    TxQueryFilterCriteria::builder()
                        .tags([
                            TagFilter::builder()
                                .name("Entity-Type")
                                .values([E::TYPE])
                                .build(),
                            TagFilter::builder()
                                .name("Folder-Id")
                                .values([id.to_string()])
                                .build(),
                            TagFilter::builder()
                                .name("Drive-Id")
                                .values([drive_id.to_string()])
                                .build(),
                        ])
                        .build(),
                )
                .sort_order(SortOrder::HeightDescending)
                .max_results(NonZeroUsize::try_from(1).unwrap())
                .build(),
        )
        .try_next()
        .await?
        .ok_or(EntityError::NotFound {
            entity_type: E::TYPE,
            details: id.to_string(),
        })?;
    client
        .location_by_item_id(&item.id())
        .await
        .map_err(|e| e.into())
}

async fn folder_entity(
    folder_id: &FolderId,
    client: &Client,
    location: &Arl,
    drive_id: &DriveId,
    owner: &WalletAddress,
    private: Option<&Private>,
) -> Result<FolderEntity, Error> {
    let folder_entity =
        read_entity::<FolderKind, 1024>(client, location, drive_id, owner, private).await?;
    if folder_entity.id() != folder_id {
        Err(EntityError::FolderMismatch {
            expected: folder_id.clone(),
            actual: folder_entity.id().clone(),
        })?;
    }
    if folder_entity.drive_id() != drive_id {
        Err(EntityError::DriveMismatch {
            expected: drive_id.clone(),
            actual: folder_entity.drive_id().clone(),
        })?;
    }
    Ok(folder_entity)
}

async fn read_entity<E: Entity, const MAX_METADATA_LEN: usize>(
    client: &Client,
    location: &Arl,
    drive_id: &DriveId,
    owner: &WalletAddress,
    private: Option<&Private>,
) -> Result<Model<E>, Error>
where
    Header<<E as Entity>::Header, E>: for<'a> TryFrom<&'a Vec<Tag<'a>>, Error = ParseError>,
    Metadata<<E as Entity>::Metadata, E>: TryFrom<JsonValue, Error = ParseError>,
{
    if let Some(address) = private.map(|p| p.wallet.address()) {
        if &address != owner {
            Err(EntityError::OwnerMismatch {
                expected: address,
                actual: owner.clone(),
            })?;
        }
    }

    let block_height = match client.tx_status(location.tx_id()).await? {
        Some(TxStatus::Accepted(accepted)) => accepted.block_height,
        _ => Err(EntityError::InvalidTxStatus(location.tx_id().clone()))?,
    };

    let mut reader = client.read_any(location.clone()).await?;
    let item = reader.item();

    if &item.owner() != owner {
        Err(EntityError::OwnerMismatch {
            expected: owner.clone(),
            actual: item.owner(),
        })?;
    }

    if reader.len() > MAX_METADATA_LEN as u64 {
        Err(EntityError::from(MetadataError::MaxLengthExceeded {
            max: MAX_METADATA_LEN,
            actual: reader.len() as usize,
        }))?;
    }

    let mut buf = vec![0u8; reader.len() as usize];
    reader.read_exact(&mut buf).await?;
    drop(reader);
    let metadata: JsonValue =
        serde_json::from_slice(buf.as_slice()).map_err(|e| EntityError::MetadataError(e.into()))?;

    let header = Header::<E::Header, E>::try_from(item.tags()).map_err(EntityError::from)?;

    let metadata = Metadata::<E::Metadata, E>::try_from(metadata).map_err(EntityError::from)?;

    Ok(Model::new(header, metadata, block_height, location.clone()))
}

async fn drive_entity(
    client: &Client,
    drive_id: &DriveId,
    location: &Arl,
    owner: &WalletAddress,
    private: Option<&Private>,
) -> Result<DriveEntity, Error> {
    let drive_entity =
        read_entity::<DriveKind, { 1024 * 1024 }>(client, location, drive_id, owner, private)
            .await?;

    let privacy = private.map(|_| Privacy::Private).unwrap_or(Privacy::Public);
    if drive_entity.header().as_inner().privacy != privacy {
        Err(EntityError::PrivacyMismatch {
            expected: privacy,
            actual: drive_entity.header().as_inner().privacy,
        })?;
    }

    let auth_mode = private.map(|p| AuthMode::from(&p.auth));
    if drive_entity.header().as_inner().auth_mode != auth_mode {
        Err(EntityError::AuthModeMismatch {
            expected: auth_mode
                .map(|a| a.to_string())
                .unwrap_or("None".to_string()),
            actual: drive_entity
                .header()
                .as_inner()
                .auth_mode
                .map(|a| a.to_string())
                .unwrap_or("None".to_string()),
        })?;
    }

    Ok(drive_entity)
}

#[cfg(test)]
mod tests {
    use crate::{ArFs, Credentials, Scope};
    use ario_client::Client;
    use ario_core::Gateway;
    use ario_core::jwk::Jwk;
    use ario_core::network::Network;
    use ario_core::wallet::Wallet;
    use futures_lite::stream::StreamExt;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

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
        let credentials = Credentials::with_password(wallet, "foo".to_string());

        let (drive_id, _) = super::find_drive_ids_by_owner(&client, &drive_owner)
            .try_next()
            .await?
            .unwrap();

        let arfs = ArFs::builder()
            .client(client.clone())
            .db_dir(&PathBuf::from_str("/tmp/foo/")?)
            .drive_id(drive_id)
            .scope(Scope::private_rw(credentials))
            .build()
            .await?;

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn foo() -> anyhow::Result<()> {
        let (client, wallet) = init().await?;
        let drive_owner = wallet.address();

        let mut stream = super::find_drive_ids_by_owner(&client, &drive_owner);

        while let Some((drive_id, _)) = stream.try_next().await? {
            let arfs = ArFs::builder()
                .client(client.clone())
                .drive_id(drive_id)
                .db_dir("/tmp/foo/")
                .scope(Scope::public(drive_owner.clone()))
                .build()
                .await?;
            println!("{}", arfs);
        }
        Ok(())
    }
}
