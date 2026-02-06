use crate::serde_tag::Error as TagError;
use crate::types::drive::{DriveEntity, DriveId, DriveKind};
use crate::types::drive_signature::{DriveSignatureEntity, DriveSignatureKind};
use crate::types::file::{FileEntity, FileKind};
use crate::types::folder::{FolderEntity, FolderKind};
use crate::types::snapshot::{SnapshotEntity, SnapshotKind};
use crate::types::{ArfsEntityId, Entity, HasId, Header, Metadata, Model, ParseError};
use crate::vfs::Stats;
use crate::{InodeId, Privacy, Scope, State, Status, Timestamp, resolve};
use ario_client::location::Arl;
use ario_client::{ByteSize, Client};
use ario_core::BlockNumber;
use ario_core::blob::OwnedBlob;
use ario_core::network::NetworkIdentifier;
use ario_core::tag::Tag;
use ario_core::wallet::WalletAddress;
use chrono::{DateTime, Utc};
use futures_lite::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_sqlite_jsonb::Error as JsonbError;
use sqlx::Transaction as SqlxTransaction;
use sqlx::migrate::MigrateError;
use sqlx::pool::PoolConnection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{ConnectOptions, Connection, Error as SqlxError, Pool, Sqlite, SqliteConnection};
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::Instrument;
use tracing::instrument;
use tracing::log::LevelFilter;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    SqlxError(#[from] SqlxError),
    #[error(transparent)]
    MigrateError(#[from] MigrateError),
    #[error(transparent)]
    DbStateError(#[from] DbStateError),
    #[error(transparent)]
    DataError(#[from] DataError),
}

#[derive(Error, Debug)]
pub enum DbStateError {
    #[error("expected database to empty but contains data")]
    NotEmpty,
    #[error("database does not hold a valid config")]
    NoConfig,
    #[error("wrong privacy mode: expected '{expected}' but got '{actual}'")]
    IncorrectPrivacy { expected: Privacy, actual: Privacy },
    #[error("wrong drive owner: expected '{expected}' but got '{actual}'")]
    IncorrectOwner {
        expected: WalletAddress,
        actual: WalletAddress,
    },
    #[error("wrong drive id: expected '{expected}' but got '{actual}'")]
    IncorrectDriveId { expected: DriveId, actual: DriveId },
    #[error("wrong network id: expected '{expected}' but got '{actual}'")]
    IncorrectNetworkId {
        expected: NetworkIdentifier,
        actual: NetworkIdentifier,
    },
    #[error("invalid page size: '{0}'")]
    InvalidPageSize(String),
    #[error("database not in 'permanent' state")]
    NotInPermanentState,
    #[error("database not in 'wal' state")]
    NotInWalState,
    #[error("database has pending wal entries")]
    HasPendingWalEntries,
    #[error("database state is invalid")]
    InvalidState,
}

#[derive(Error, Debug)]
pub enum DataError {
    #[error("conversion failed: {0}")]
    ConversionError(String),
    #[error("missing data: {0}")]
    MissingData(String),
    #[error(transparent)]
    JsonbError(#[from] JsonbError),
    #[error(transparent)]
    TagError(#[from] TagError),
    #[error(transparent)]
    ParseError(#[from] ParseError),
    #[error("incorrect entity type, expected '{expected}' but got '{actual}'")]
    IncorrectEntityType {
        expected: Cow<'static, str>,
        actual: Cow<'static, str>,
    },
    #[error("id mismatch, expected '{expected}' but got '{actual}'")]
    IdMismatch { expected: String, actual: String },
    #[error("entity type '{0}' is not a valid inode type")]
    NotInodeEntityType(String),
    #[error("not a valid perm_type: '{0}'")]
    InvalidPermType(String),
    #[error("invalid wal entry")]
    InvalidWalEntry,
    #[error("deletion of inode '{0}' failed. (recursive_delete: '{1}')")]
    DeletionFailure(InodeId, bool),
    #[error("VFS root cannot be deleted")]
    RootDeletionAttempt,
    #[error("value '{0}' not valid")]
    InvalidCost(String),
    #[error("invalid item type: '{0}'")]
    InvalidItemType(String),
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub(crate) struct Db(Arc<DbInner>);

#[derive(Debug, Clone)]
struct SqlitePool {
    writer: Pool<Sqlite>,
    reader: Pool<Sqlite>,
}

impl SqlitePool {
    pub async fn read(&self) -> Result<Transaction<ReadOnly>, SqlxError> {
        Ok(Transaction(ReadOnly(self.reader.acquire().await?)))
    }

    pub async fn write(&self) -> Result<Transaction<ReadWrite>, SqlxError> {
        Ok(Transaction(ReadWrite(self.writer.begin().await?)))
    }
}

#[derive(Debug)]
struct DbInner {
    config: Config,
    client: Client,
    pool: SqlitePool,
    db_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum PageSize {
    Ps512 = 512,
    Ps1024 = 1024,
    Ps2048 = 2048,
    Ps4096 = 4096,
    Ps8192 = 8192,
    Ps16384 = 16384,
    Ps32768 = 32768,
    Ps65536 = 65536,
}

impl Default for PageSize {
    fn default() -> Self {
        PageSize::Ps32768
    }
}

impl Display for PageSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value())
    }
}

impl PageSize {
    pub fn value(&self) -> u32 {
        self.clone() as u32
    }
}

impl TryFrom<u32> for PageSize {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            512 => Ok(PageSize::Ps512),
            1024 => Ok(PageSize::Ps1024),
            2048 => Ok(PageSize::Ps2048),
            4096 => Ok(PageSize::Ps4096),
            8192 => Ok(PageSize::Ps8192),
            16384 => Ok(PageSize::Ps16384),
            32768 => Ok(PageSize::Ps32768),
            65536 => Ok(PageSize::Ps65536),
            _ => Err(value),
        }
    }
}

impl Db {
    pub(super) async fn new(
        db_file: PathBuf,
        max_connections: u8,
        client: Client,
        drive_id: &DriveId,
        scope: &Scope,
        page_size: PageSize,
    ) -> Result<Self, super::Error> {
        let (config, pool) = db_init(db_file.as_path(), max_connections, page_size).await?;
        let config = match config {
            Some(config) => {
                check_config(
                    &config,
                    drive_id,
                    scope.owner().as_ref(),
                    scope.privacy(),
                    client.network().id(),
                )?;
                config
            }
            None => bootstrap(&client, &pool, drive_id, scope).await?,
        };

        Ok(Self(Arc::new(DbInner {
            config,
            client,
            pool,
            db_file,
        })))
    }

    pub async fn read(&self) -> Result<Transaction<ReadOnly>, Error> {
        Ok(self.0.pool.read().await?)
    }

    pub async fn write(&self) -> Result<Transaction<ReadWrite>, Error> {
        Ok(self.0.pool.write().await?)
    }
}

#[repr(transparent)]
pub struct ReadOnly(PoolConnection<Sqlite>);

impl AsMut<SqliteConnection> for ReadOnly {
    fn as_mut(&mut self) -> &mut SqliteConnection {
        &mut self.0
    }
}

#[repr(transparent)]
pub struct ReadWrite(SqlxTransaction<'static, Sqlite>);

impl AsMut<SqliteConnection> for ReadWrite {
    #[inline]
    fn as_mut(&mut self) -> &mut SqliteConnection {
        &mut self.0
    }
}

pub(crate) trait Read: AsMut<SqliteConnection> {
    #[inline]
    fn conn(&mut self) -> &mut SqliteConnection {
        self.as_mut()
    }
}
impl Read for Transaction<ReadOnly> {}

pub(crate) trait Write: Read {}
impl Read for Transaction<ReadWrite> {}
impl Write for Transaction<ReadWrite> {}

pub(crate) trait TxScope: AsMut<SqliteConnection> + Send + Sync + Unpin + 'static {}
impl<T: AsMut<SqliteConnection> + Send + Sync + Unpin + 'static> TxScope for T {}

#[repr(transparent)]
pub(crate) struct Transaction<Scope: TxScope>(Scope);

impl Transaction<ReadWrite> {
    #[inline]
    pub async fn commit(self) -> Result<(), Error> {
        Ok(self.0.0.commit().await?)
    }

    #[inline]
    pub async fn rollback(self) -> Result<(), Error> {
        Ok(self.0.0.rollback().await?)
    }
}

impl<Scope: TxScope> AsMut<SqliteConnection> for Transaction<Scope> {
    #[inline]
    fn as_mut(&mut self) -> &mut SqliteConnection {
        self.0.as_mut()
    }
}

impl<C: TxScope> Transaction<C>
where
    Self: Read,
{
    pub async fn config(&mut self) -> Result<Config, Error> {
        get_config(self).await?.ok_or(DbStateError::NoConfig.into())
    }

    pub async fn status(&mut self) -> Result<Status, Error> {
        let (wal_state, last_sync) =
            sqlx::query!("SELECT state, last_sync AS \"last_sync:i64\" FROM config")
                .map(|r| {
                    (
                        r.state
                            .map(|state| match state.as_str() {
                                "P" => Some(State::Permanent),
                                "W" => Some(State::Wal),
                                _ => None,
                            })
                            .flatten(),
                        r.last_sync
                            .map(|ts| DateTime::from_timestamp(ts, 0))
                            .flatten(),
                    )
                })
                .fetch_one(self.conn())
                .await?;

        let last_wal_modification =
            sqlx::query!("SELECT MAX(timestamp) as \"last_mod: i64\" FROM wal")
                .map(|r| {
                    r.last_mod
                        .map(|ts| DateTime::from_timestamp(ts, 0))
                        .flatten()
                })
                .fetch_one(self.conn())
                .await?;

        Ok(match (wal_state, last_sync, last_wal_modification) {
            (Some(State::Wal), Some(last_sync), last_wal_modification) => Status::Wal {
                last_sync,
                last_wal_modification,
            },
            (Some(State::Permanent), Some(last_sync), _) => Status::Synchronized { last_sync },
            (None, _, _) => Status::Initial,
            _ => Err(DbStateError::InvalidState)?,
        })
    }

    pub async fn entity_ids(
        &mut self,
    ) -> Result<impl Stream<Item = Result<ArfsEntityId, Error>> + Unpin + use<'_, C>, Error> {
        let x = sqlx::query!("SELECT entity_type, entity_id FROM entity")
            .fetch(self.conn())
            .filter_map(|r| match r {
                Ok(r) => match r.entity_type.as_str() {
                    <DriveKind as DbEntity>::TYPE => Some(
                        parse_entity_id(r.entity_id.map(Cow::Owned))
                            .map(ArfsEntityId::Drive)
                            .map_err(|e| e.into()),
                    ),
                    <DriveSignatureKind as DbEntity>::TYPE => None,
                    <FileKind as DbEntity>::TYPE => Some(
                        parse_entity_id(r.entity_id.map(Cow::Owned))
                            .map(ArfsEntityId::File)
                            .map_err(|e| e.into()),
                    ),
                    <FolderKind as DbEntity>::TYPE => Some(
                        parse_entity_id(r.entity_id.map(Cow::Owned))
                            .map(ArfsEntityId::Folder)
                            .map_err(|e| e.into()),
                    ),
                    <SnapshotKind as DbEntity>::TYPE => Some(
                        parse_entity_id(r.entity_id.map(Cow::Owned))
                            .map(ArfsEntityId::Snapshot)
                            .map_err(|e| e.into()),
                    ),
                    _ => None,
                },
                Err(err) => Some(Err(err.into())),
            });
        Ok(x)
    }

    pub async fn stats(&mut self) -> Result<Stats, Error> {
        Ok(sqlx::query!(
            "
            SELECT
                COUNT(CASE WHEN inode_type = 'FI' THEN 1 END) as num_files,
                COUNT(CASE WHEN inode_type = 'FO' THEN 1 END) as num_dirs,
                COALESCE(SUM(size), 0) as total_size,
                MAX(last_modified) as \"last_modified: i64\"
            FROM vfs;
        "
        )
        .fetch_one(self.conn())
        .await
        .map(|r| Stats {
            num_files: r.num_files as usize,
            num_dirs: r.num_dirs as usize,
            total_size: ByteSize::b(r.total_size as u64),
            last_modified: Timestamp::from_timestamp(
                r.last_modified.unwrap_or_else(|| Utc::now().timestamp()),
                0,
            )
            .unwrap_or_else(|| Utc::now()),
        })?)
    }
}

impl<C: TxScope> Transaction<C>
where
    Self: Write,
{
    async fn delete_entities(
        &mut self,
        entity_ids: impl Iterator<Item = &ArfsEntityId>,
    ) -> Result<usize, Error> {
        let mut deletions = 0;

        for id in entity_ids {
            let row_id = match id {
                ArfsEntityId::Drive(drive_id) => {
                    get_id_for_entity_id::<DriveKind, _>(drive_id, self).await?
                }
                ArfsEntityId::Folder(folder_id) => {
                    get_id_for_entity_id::<FolderKind, _>(folder_id, self).await?
                }
                ArfsEntityId::File(file_id) => {
                    get_id_for_entity_id::<FileKind, _>(file_id, self).await?
                }
                ArfsEntityId::Snapshot(snapshot_id) => {
                    get_id_for_entity_id::<SnapshotKind, _>(snapshot_id, self).await?
                }
            };
            deletions += delete_entity(row_id, self).await?;
        }

        Ok(deletions)
    }

    pub(crate) async fn delete_orphaned_entities(&mut self) -> Result<(), Error> {
        sqlx::query!(
            "
              DELETE FROM entity
              WHERE id NOT IN (SELECT drive_id
                 FROM config)
              AND entity_type = 'DR';
            "
        )
        .execute(self.conn())
        .await?;

        sqlx::query!(
            "
              DELETE FROM entity
              WHERE id NOT IN (SELECT signature_id
                 FROM config)
              AND entity_type = 'SN';
            "
        )
        .execute(self.conn())
        .await?;

        sqlx::query!(
            "
              DELETE FROM entity
              WHERE id NOT IN (SELECT entity
                 FROM vfs
                 WHERE entity IS NOT NULL)
              AND id NOT IN (SELECT entity FROM vfs_snapshot)
              AND id NOT IN (SELECT entity FROM wal)
              AND entity_type = 'FI';
            "
        )
        .execute(self.conn())
        .await?;

        sqlx::query!(
            "
              DELETE FROM entity
              WHERE id NOT IN (SELECT entity
                 FROM vfs
                 WHERE entity IS NOT NULL)
              AND id NOT IN (SELECT entity FROM vfs_snapshot)
              AND id NOT IN (SELECT entity FROM wal)
              AND id NOT IN (SELECT root_folder_id
                 FROM config)
              AND entity_type = 'FO';
            "
        )
        .execute(self.conn())
        .await?;

        // unsubmitted wal entries that were already deleted are obsolete
        sqlx::query!(
            "
             DELETE FROM wal
             WHERE perm_type = 'W'
             AND upload IS NULL
             AND wal_entity NOT IN (SELECT wal_entity FROM vfs WHERE wal_entity IS NOT NULL);
            "
        )
        .execute(self.conn())
        .await?;

        // fully uploaded wal entries are obsolete
        sqlx::query!(
            "
             DELETE FROM wal
                    WHERE block_height IS NOT NULL;
            "
        )
        .execute(self.conn())
        .await?;

        sqlx::query!(
            "
              DELETE FROM wal_entity
              WHERE id NOT IN (
                SELECT wal_entity
                  FROM vfs
                  WHERE wal_entity IS NOT NULL
              )
              AND id NOT IN (SELECT wal_entity FROM wal);
            "
        )
        .execute(self.conn())
        .await?;

        Ok(())
    }
}

async fn bootstrap(
    client: &Client,
    pool: &SqlitePool,
    drive_id: &DriveId,
    scope: &Scope,
) -> Result<Config, super::Error> {
    let owner = scope.owner();
    let drive_entity =
        resolve::find_drive_by_id_owner(client, drive_id, owner.as_ref(), scope.key_ring(), None)
            .await?;

    if let Some(key_ring) = scope.key_ring()
        && drive_entity.privacy() == Privacy::Private
    {
        if let Some(signature_format) = drive_entity.signature_type() {
            key_ring.set_signature_format(signature_format);
        }
    }

    let root_folder_location = resolve::find_entity_location_by_id_drive::<FolderKind>(
        client,
        drive_entity.root_folder(),
        &drive_id,
        None,
    )
    .await?;

    let root_folder_entity = resolve::folder_entity(
        drive_entity.root_folder(),
        client,
        &root_folder_location,
        &drive_id,
        owner.as_ref(),
        scope.key_ring(),
    )
    .await?;

    let mut tx = pool.write().await.map_err(Error::SqlxError)?;

    insert_entity(&root_folder_entity, &mut tx).await?;
    insert_entity(&drive_entity, &mut tx).await?;

    let config = Config::from(
        drive_entity,
        root_folder_entity,
        None,
        owner.into_owned(),
        client.network().id().clone(),
    );
    insert_config(&config, None, &mut tx).await?;
    tx.commit().await?;

    Ok(config)
}

async fn insert_config<C: Write>(
    config: &Config,
    signature_id: Option<i64>,
    conn: &mut C,
) -> Result<(), Error> {
    let name = config.drive.name();
    let owner = config.owner.as_slice();
    let network_id: &str = config.network_id.as_ref();
    let drive_entity_id = config.drive.id().as_ref();
    let root_folder_entity_id = config.root_folder.id().as_ref();

    let drive_id = sqlx::query!(
        "SELECT id FROM entity WHERE entity_type = 'DR' AND entity_id = ?",
        drive_entity_id,
    )
    .fetch_one(conn.conn())
    .await?
    .id;

    let root_folder_id = sqlx::query!(
        "SELECT id FROM entity WHERE entity_type = 'FO' AND entity_id = ?",
        root_folder_entity_id,
    )
    .fetch_one(conn.conn())
    .await?
    .id;

    sqlx::query!(
        "INSERT INTO config (drive_id, root_folder_id, signature_id, name, owner, network_id, state, last_sync, block_height) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
        drive_id,
        root_folder_id,
        signature_id,
        name,
        owner,
        network_id,
    )
        .execute(conn.conn())
        .await?;
    Ok(())
}

fn check_config(
    config: &Config,
    drive_id: &DriveId,
    owner_address: &WalletAddress,
    privacy: Privacy,
    network_id: &NetworkIdentifier,
) -> Result<(), Error> {
    if config.drive.privacy() != privacy {
        Err(DbStateError::IncorrectPrivacy {
            expected: privacy,
            actual: config.drive.privacy(),
        })?;
    }
    if &config.drive.id() != &drive_id {
        Err(DbStateError::IncorrectDriveId {
            expected: drive_id.clone(),
            actual: config.drive.id().clone(),
        })?;
    }
    if &config.owner != owner_address {
        Err(DbStateError::IncorrectOwner {
            expected: owner_address.clone(),
            actual: config.owner.clone(),
        })?;
    }
    if &config.network_id != network_id {
        Err(DbStateError::IncorrectNetworkId {
            expected: network_id.clone(),
            actual: config.network_id.clone(),
        })?;
    }

    Ok(())
}

struct ConfigRow {
    drive_id: i64,
    root_folder_id: i64,
    signature_id: Option<i64>,
    name: String,
    owner: Vec<u8>,
    network_id: String,
}

struct EntityRow<'a> {
    id: i64,
    entity_type: Cow<'a, str>,
    location: Cow<'a, str>,
    block: i64,
    entity_id: Option<Cow<'a, [u8]>>,
    header: Vec<u8>,
    metadata: Option<Cow<'a, [u8]>>,
    data_location: Option<Cow<'a, str>>,
}

async fn delete_entity<C: Write>(id: i64, tx: &mut C) -> Result<usize, Error> {
    Ok(sqlx::query!("DELETE FROM entity WHERE id = ?", id)
        .execute(tx.conn())
        .await?
        .rows_affected() as usize)
}

pub(crate) async fn get_entity<E: DbEntity, C: Read>(
    id: i64,
    tx: &mut C,
) -> Result<Model<E>, Error> {
    let row = sqlx::query!(
        "SELECT id, entity_type, location, block, entity_id, header, metadata, data_location
             FROM entity
             WHERE id = ? AND entity_type = ?",
        id,
        <E as DbEntity>::TYPE,
    )
    .fetch_one(tx.conn())
    .await
    .map(|r| EntityRow {
        id: r.id,
        entity_type: r.entity_type.into(),
        location: r.location.into(),
        block: r.block,
        entity_id: r.entity_id.map(|id| Cow::from(id)),
        header: r.header.into(),
        metadata: r.metadata.map(|metadata| Cow::from(metadata)),
        data_location: r
            .data_location
            .map(|data_location| Cow::from(data_location)),
    })?;

    Ok(E::try_from_row(row)?)
}

pub(crate) async fn insert_entity<E: DbEntity, C: Write>(
    entity: &Model<E>,
    tx: &mut C,
) -> Result<(i64, Vec<i64>), Error> {
    let row = E::to_row(entity)?;

    let entity_type = <E as DbEntity>::TYPE;
    let location = row.location.deref();
    let entity_id = row.entity_id.as_ref().map(|entity_id| entity_id.deref());
    let header = row.header.deref();
    let metadata = row.metadata.as_ref().map(|metadata| metadata.deref());
    let data_location = row
        .data_location
        .as_ref()
        .map(|data_location| data_location.deref());

    let id = sqlx::query!(
        "
            INSERT INTO entity
                (entity_type, location, block, entity_id, header, metadata, data_location) VALUES
                (?, ?, ?, ?, ?, ?, ?)
            ",
        entity_type,
        location,
        row.block,
        entity_id,
        header,
        metadata,
        data_location,
    )
    .execute(tx.conn())
    .await?
    .last_insert_rowid();

    let superseded = sqlx::query!(
        "
        SELECT id FROM entity WHERE entity_type = ? AND entity_id = ? AND block < ?
        ",
        entity_type,
        entity_id,
        row.block,
    )
    .map(|r| r.id)
    .fetch_all(tx.conn())
    .await?;

    Ok((id, superseded))
}

async fn get_config<C: Read>(tx: &mut C) -> Result<Option<Config>, Error> {
    let config_row: ConfigRow = match sqlx::query_as!(
        ConfigRow,
        "SELECT drive_id, root_folder_id, signature_id, name, owner, network_id FROM config"
    )
    .fetch_optional(tx.conn())
    .await?
    {
        Some(config_row) => config_row,
        None => return Ok(None),
    };

    let drive = get_entity::<DriveKind, _>(config_row.drive_id, tx).await?;
    let root_folder = get_entity::<FolderKind, _>(config_row.root_folder_id, tx).await?;

    let signature: Option<Model<DriveSignatureKind>> = if let Some(sig_id) = config_row.signature_id
    {
        Some(get_entity(sig_id, &mut *tx).await?)
    } else {
        None
    };

    Ok(Some(Config::try_from(
        config_row,
        drive,
        root_folder,
        signature,
    )?))
}

pub(crate) async fn clear_temp_tables<C: Write>(tx: &mut C) -> Result<(), Error> {
    sqlx::query!("DELETE FROM vfs_affected_inodes")
        .execute(tx.conn())
        .await?;
    Ok(())
}

pub(crate) async fn reset_state_if_empty_wal<C: Write>(tx: &mut C) -> Result<(), Error> {
    sqlx::query!(
        "UPDATE config SET state = 'P' WHERE state = 'W' AND (SELECT Count(*) FROM wal) = 0 AND NOT EXISTS(SELECT 1 FROM vfs WHERE perm_type != 'P')"
    )
        .execute(tx.conn())
        .await?;
    sqlx::query!(
        "DELETE FROM vfs_snapshot WHERE (SELECT Count(*) FROM wal) = 0 AND NOT EXISTS(SELECT 1 FROM vfs WHERE perm_type != 'P')"
    )
        .execute(tx.conn())
        .await?;
    Ok(())
}

pub(crate) async fn collect_affected_inode_ids<C: Write>(
    tx: &mut C,
) -> Result<Vec<InodeId>, Error> {
    Ok(sqlx::query!("SELECT DISTINCT(id) FROM vfs_affected_inodes")
        .fetch_all(tx.as_mut())
        .await?
        .into_iter()
        .map(|r| -> Result<InodeId, Error> {
            InodeId::try_from(r.id as u64)
                .map_err(|e| DataError::ConversionError(e.to_string()).into())
        })
        .collect::<Result<Vec<_>, _>>()?)
}

#[derive(Debug)]
pub struct Config {
    pub drive: DriveEntity,
    pub root_folder: FolderEntity,
    pub signature: Option<DriveSignatureEntity>,
    pub owner: WalletAddress,
    pub network_id: NetworkIdentifier,
}

impl Config {
    fn try_from(
        config_row: ConfigRow,
        drive: DriveEntity,
        root_folder: FolderEntity,
        signature: Option<DriveSignatureEntity>,
    ) -> Result<Self, DataError> {
        let owner = WalletAddress::try_from(OwnedBlob::from(config_row.owner))
            .map_err(|e| DataError::ConversionError(e.to_string()))?;
        let network_id = NetworkIdentifier::try_from(config_row.network_id)
            .map_err(|e| DataError::ConversionError(e.to_string()))?;

        Ok(Self {
            drive,
            root_folder,
            signature,
            owner,
            network_id,
        })
    }
}

impl Config {
    fn from(
        drive: DriveEntity,
        root_folder: FolderEntity,
        signature: Option<DriveSignatureEntity>,
        owner: WalletAddress,
        network_id: NetworkIdentifier,
    ) -> Self {
        Self {
            drive,
            root_folder,
            signature,
            owner,
            network_id,
        }
    }
}

#[instrument[skip_all, fields(db_file = %db_file.display())]]
async fn db_init(
    db_file: &Path,
    max_connections: u8,
    page_size: PageSize,
) -> Result<(Option<Config>, SqlitePool), Error> {
    prepare_db(db_file, page_size).await?;

    let writer = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with({
            SqliteConnectOptions::new()
                .create_if_missing(false)
                .filename(db_file)
                .log_statements(LevelFilter::Trace)
                .journal_mode(SqliteJournalMode::Wal)
                .foreign_keys(true)
                .pragma("recursive_triggers", "ON")
                .busy_timeout(Duration::from_millis(100))
                .shared_cache(true)
        })
        .await?;

    let reader = SqlitePoolOptions::new()
        .max_connections(max_connections as u32)
        .connect_with({
            SqliteConnectOptions::new()
                .create_if_missing(false)
                .filename(db_file)
                .log_statements(LevelFilter::Trace)
                .journal_mode(SqliteJournalMode::Wal)
                .foreign_keys(true)
                .pragma("recursive_triggers", "ON")
                .busy_timeout(Duration::from_millis(100))
                .shared_cache(true)
                .pragma("query_only", "ON")
        })
        .await?;

    let pool = SqlitePool { writer, reader };

    let mut tx = pool.write().await?;
    reset_state_if_empty_wal(&mut tx).await?;
    clear_temp_tables(&mut tx).await?;
    tx.commit().await?;

    let mut conn = pool.read().await?;

    let config = get_config(&mut conn).await?;
    if config.is_none() {
        // make sure the database is really empty
        if sqlx::query!(
            "SELECT NOT EXISTS (
                             SELECT 1 FROM entity UNION ALL
                             SELECT 1 FROM vfs UNION ALL
                             SELECT 1 FROM sync_log UNION ALL
                             SELECT 1 FROM config
                             LIMIT 1
                     ) AS is_empty"
        )
        .fetch_one(conn.conn())
        .await?
        .is_empty
            != 1
        {
            Err(DbStateError::NotEmpty)?;
        }
    }

    Ok((config, pool))
}

#[instrument[skip_all, fields(page_size = %page_size)]]
async fn prepare_db(db_file: &Path, page_size: PageSize) -> Result<(), Error> {
    let opts = SqliteConnectOptions::new()
        .create_if_missing(true)
        .filename(db_file)
        .log_statements(LevelFilter::Trace)
        .journal_mode(SqliteJournalMode::Delete)
        .foreign_keys(true)
        .pragma("recursive_triggers", "ON")
        .busy_timeout(Duration::from_millis(1000))
        .shared_cache(false);

    let mut conn = SqliteConnection::connect_with(&opts).await?;

    async { sqlx::migrate!("./migrations").run_direct(&mut conn).await }
        .instrument(tracing::warn_span!("db_migration"))
        .await?;

    async fn get_page_size(conn: &mut SqliteConnection) -> Result<PageSize, Error> {
        Ok(sqlx::query!("PRAGMA page_size")
            .fetch_one(conn)
            .await?
            .page_size
            .map(|c| PageSize::try_from(c as u32).ok())
            .flatten()
            .ok_or(DbStateError::InvalidPageSize(
                "unable to get page_size from database".to_string(),
            ))?)
    }

    let current_page_size = get_page_size(&mut conn).await?;
    conn.close().await?;

    if current_page_size != page_size {
        tracing::info!(
            required = %page_size,
            actual = %current_page_size,
            "database page size needs adjusting",
        );

        {
            let opts = opts.clone().page_size(page_size.value());
            let mut conn = SqliteConnection::connect_with(&opts).await?;
            sqlx::query!("VACUUM").execute(&mut conn).await?;
            conn.close().await?;
        }

        let mut conn = SqliteConnection::connect_with(&opts).await?;
        let current_page_size = get_page_size(&mut conn).await?;
        if current_page_size != page_size {
            tracing::error!(
                required = %page_size,
                actual = %current_page_size,
                "database page size adjustment failed",
            );
        }
        conn.close().await?;
    }
    Ok(())
}

pub(crate) trait DbEntity: Entity + Sized {
    const TYPE: &'static str;

    fn try_from_row(row: EntityRow) -> Result<Model<Self>, DataError>;
    fn to_row(entity: &Model<Self>) -> Result<EntityRow<'_>, DataError>;
}

impl DbEntity for DriveKind {
    const TYPE: &'static str = "DR";

    fn try_from_row(row: EntityRow) -> Result<Model<Self>, DataError> {
        DriveEntity::try_from(row)
    }

    fn to_row(entity: &Model<Self>) -> Result<EntityRow<'_>, DataError> {
        to_row(
            entity,
            Some(entity.id().as_ref().into()),
            Some(entity.metadata()),
            None,
        )
    }
}

impl TryFrom<EntityRow<'_>> for DriveEntity {
    type Error = DataError;

    fn try_from(row: EntityRow) -> Result<Self, Self::Error> {
        from_row::<DriveKind>(row, |header, metadata, location, block, row| {
            let entity_id = parse_entity_id(row.entity_id)?;

            let metadata = metadata.ok_or(DataError::MissingData(format!(
                "metadata is missing for drive_entity '{}'",
                entity_id
            )))?;

            let drive = DriveEntity::new(header, metadata, block, location);

            if drive.id() != &entity_id {
                Err(DataError::IdMismatch {
                    expected: entity_id.to_string(),
                    actual: drive.id().to_string(),
                })?;
            }

            Ok(drive)
        })
    }
}

impl DbEntity for DriveSignatureKind {
    const TYPE: &'static str = "DS";

    fn try_from_row(row: EntityRow) -> Result<Model<Self>, DataError> {
        DriveSignatureEntity::try_from(row)
    }

    fn to_row(entity: &Model<Self>) -> Result<EntityRow<'_>, DataError> {
        to_row(entity, None, None, None)
    }
}

impl TryFrom<EntityRow<'_>> for DriveSignatureEntity {
    type Error = DataError;

    fn try_from(row: EntityRow) -> Result<Self, Self::Error> {
        from_row::<DriveSignatureKind>(row, |header, _, location, block, _| {
            Ok(DriveSignatureEntity::new(
                header,
                Metadata::none(),
                block,
                location,
            ))
        })
    }
}

impl DbEntity for FolderKind {
    const TYPE: &'static str = "FO";

    fn try_from_row(row: EntityRow) -> Result<Model<Self>, DataError> {
        FolderEntity::try_from(row)
    }

    fn to_row(entity: &Model<Self>) -> Result<EntityRow<'_>, DataError> {
        to_row(
            entity,
            Some(entity.id().as_ref().into()),
            Some(entity.metadata()),
            None,
        )
    }
}

impl TryFrom<EntityRow<'_>> for FolderEntity {
    type Error = DataError;

    fn try_from(row: EntityRow<'_>) -> Result<Self, Self::Error> {
        from_row::<FolderKind>(row, |header, metadata, location, block, row| {
            let entity_id = parse_entity_id(row.entity_id)?;

            let metadata = metadata.ok_or(DataError::MissingData(format!(
                "metadata is missing for folder_entity '{}'",
                entity_id
            )))?;

            let folder = FolderEntity::new(header, metadata, block, location);

            if folder.id() != &entity_id {
                Err(DataError::IdMismatch {
                    expected: entity_id.to_string(),
                    actual: folder.id().to_string(),
                })?;
            }

            Ok(folder)
        })
    }
}

impl DbEntity for FileKind {
    const TYPE: &'static str = "FI";

    fn try_from_row(row: EntityRow) -> Result<Model<Self>, DataError> {
        FileEntity::try_from(row)
    }

    fn to_row(entity: &Model<Self>) -> Result<EntityRow<'_>, DataError> {
        to_row(
            entity,
            Some(entity.id().as_ref().into()),
            Some(entity.metadata()),
            entity.data_location().map(|arl| arl.to_string().into()),
        )
    }
}

impl TryFrom<EntityRow<'_>> for FileEntity {
    type Error = DataError;

    fn try_from(row: EntityRow<'_>) -> Result<Self, Self::Error> {
        from_row::<FileKind>(row, |header, metadata, location, block, row| {
            let entity_id = parse_entity_id(row.entity_id)?;

            let metadata = metadata.ok_or(DataError::MissingData(format!(
                "metadata is missing for file_entity '{}'",
                entity_id
            )))?;

            let mut file = FileEntity::new(header, metadata, block, location);

            if file.id() != &entity_id {
                Err(DataError::IdMismatch {
                    expected: entity_id.to_string(),
                    actual: file.id().to_string(),
                })?;
            }

            if let Some(data_location) = row.data_location {
                let data_location = Arl::from_str(data_location.as_ref())
                    .map_err(|e| DataError::ConversionError(e.to_string()))?;
                file.set_data_location(data_location);
            }

            Ok(file)
        })
    }
}

impl DbEntity for SnapshotKind {
    const TYPE: &'static str = "SN";

    fn try_from_row(row: EntityRow) -> Result<Model<Self>, DataError> {
        SnapshotEntity::try_from(row)
    }

    fn to_row(entity: &Model<Self>) -> Result<EntityRow<'_>, DataError> {
        to_row(entity, Some(entity.id().as_ref().into()), None, None)
    }
}

impl TryFrom<EntityRow<'_>> for SnapshotEntity {
    type Error = DataError;

    fn try_from(row: EntityRow<'_>) -> Result<Self, Self::Error> {
        from_row::<SnapshotKind>(row, |header, _, location, block, row| {
            let entity_id = parse_entity_id(row.entity_id)?;

            let snapshot = SnapshotEntity::new(header, Metadata::none(), block, location);

            if snapshot.id() != &entity_id {
                Err(DataError::IdMismatch {
                    expected: entity_id.to_string(),
                    actual: snapshot.id().to_string(),
                })?;
            }

            Ok(snapshot)
        })
    }
}

fn parse_entity_id<ID: TryFrom<Vec<u8>, Error: Display>>(
    input: Option<Cow<'_, [u8]>>,
) -> Result<ID, DataError> {
    input
        .map(|e| ID::try_from(e.into_owned()))
        .transpose()
        .map_err(|e| DataError::ConversionError(e.to_string()))?
        .ok_or(DataError::MissingData("entity_id is missing".to_string()))
}

async fn get_id_for_entity_id<E: DbEntity + HasId<Id: AsRef<[u8]>>, C: Read>(
    entity_id: &<E as HasId>::Id,
    conn: &mut C,
) -> Result<i64, Error> {
    let entity_id = entity_id.as_ref();
    let entity_type = <E as DbEntity>::TYPE;
    Ok(sqlx::query!(
        "SELECT id FROM entity where entity_type = ? AND entity_id = ?",
        entity_type,
        entity_id,
    )
    .fetch_one(conn.conn())
    .await
    .map(|r| r.id)?)
}

fn from_row<E: DbEntity>(
    row: EntityRow<'_>,
    finalize: impl FnOnce(
        Header<<E as Entity>::Header, E>,
        Option<Metadata<<E as Entity>::Metadata, E>>,
        Arl,
        BlockNumber,
        EntityRow<'_>,
    ) -> Result<Model<E>, DataError>,
) -> Result<Model<E>, DataError>
where
    for<'de> <E as Entity>::Header: Deserialize<'de>,
    for<'de> <E as Entity>::Metadata: Deserialize<'de>,
{
    if row.entity_type != <E as DbEntity>::TYPE {
        Err(DataError::IncorrectEntityType {
            expected: <E as DbEntity>::TYPE.into(),
            actual: row.entity_type.clone().into_owned().into(),
        })?;
    }

    let header = Header::<<E as Entity>::Header, E>::try_from(&serde_sqlite_jsonb::from_slice::<
        Vec<Tag<'_>>,
    >(row.header.as_slice())?)?;

    let location = Arl::from_str(row.location.deref())
        .map_err(|e| DataError::ConversionError(e.to_string()))?;

    let block = BlockNumber::from_inner(row.block as u64);

    let metadata = row
        .metadata
        .as_ref()
        .map(|m| serde_sqlite_jsonb::from_slice::<Metadata<<E as Entity>::Metadata, E>>(m.as_ref()))
        .transpose()?;

    finalize(header, metadata, location, block, row)
}

fn to_row<'a, E: DbEntity>(
    entity: &'a Model<E>,
    id: Option<Cow<'a, [u8]>>,
    metadata: Option<&'a Metadata<E::Metadata, E>>,
    data_location: Option<Cow<'a, str>>,
) -> Result<EntityRow<'a>, DataError>
where
    <E as Entity>::Header: Serialize,
    <E as Entity>::Metadata: Serialize,
{
    let header =
        serde_sqlite_jsonb::to_vec(&entity.header().to_tags().map_err(DataError::TagError)?)
            .map_err(DataError::JsonbError)?;

    let metadata = match metadata {
        Some(metadata) => Some(
            serde_sqlite_jsonb::to_vec(metadata)
                .map_err(DataError::JsonbError)?
                .into(),
        ),
        None => None,
    };

    Ok(EntityRow {
        id: 0,
        entity_type: <E as DbEntity>::TYPE.into(),
        location: entity.location().to_string().into(),
        block: *entity.block_height().as_ref() as i64,
        entity_id: id,
        header: header.into(),
        metadata,
        data_location,
    })
}
