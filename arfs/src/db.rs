use crate::serde_tag::Error as TagError;
use crate::sync::{LogEntry as SyncLogEntry, Success as SyncSuccess, SyncResult};
use crate::types::drive::{DriveEntity, DriveId, DriveKind};
use crate::types::drive_signature::{DriveSignatureEntity, DriveSignatureKind};
use crate::types::file::{FileEntity, FileKind};
use crate::types::folder::{FolderEntity, FolderKind};
use crate::types::snapshot::{SnapshotEntity, SnapshotKind};
use crate::types::{Entity, HasId, Header, Metadata, Model, ParseError};
use crate::{Privacy, Scope, resolve};
use ario_client::Client;
use ario_client::location::Arl;
use ario_core::BlockNumber;
use ario_core::blob::OwnedBlob;
use ario_core::network::NetworkIdentifier;
use ario_core::tag::Tag;
use ario_core::wallet::WalletAddress;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_sqlite_jsonb::Error as JsonbError;
use sqlx::Transaction as SqlxTransaction;
use sqlx::migrate::MigrateError;
use sqlx::pool::PoolConnection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{ConnectOptions, Error as SqlxError, Pool, Sqlite, SqliteConnection};
use std::borrow::Cow;
use std::fmt::Display;
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

impl Db {
    pub(super) async fn new(
        db_file: PathBuf,
        max_connections: u8,
        client: Client,
        drive_id: &DriveId,
        scope: &Scope,
    ) -> Result<Self, super::Error> {
        let (config, pool) = db_init(db_file.as_path(), max_connections).await?;
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

trait Read: AsMut<SqliteConnection> {
    #[inline]
    fn conn(&mut self) -> &mut SqliteConnection {
        self.as_mut()
    }
}
impl Read for Transaction<ReadOnly> {}

trait Write: Read {}
impl Read for Transaction<ReadWrite> {}
impl Write for Transaction<ReadWrite> {}

trait TxScope: AsMut<SqliteConnection> + Send + Sync + Unpin + 'static {}
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
    pub async fn entity_by_id<E: Entity + HasId<Id: AsRef<[u8]>>>(
        &mut self,
        id: &<E as HasId>::Id,
    ) -> Result<Model<E>, Error>
    where
        E: DbEntity,
    {
        let id = get_id_for_entity_id::<E, _>(id, self).await?;
        get_entity(id, self).await
    }

    pub async fn latest_sync_log_entry(&mut self) -> Result<Option<SyncLogEntry>, Error> {
        get_latest_sync_log_entry(self).await
    }

    pub async fn config(&mut self) -> Result<Config, Error> {
        get_config(self).await?.ok_or(DbStateError::NoConfig.into())
    }
}

impl<C: TxScope> Transaction<C>
where
    Self: Write,
{
    pub async fn sync_log_entry(&mut self, log_entry: &SyncLogEntry) -> Result<(), Error> {
        insert_sync_log_entry(log_entry, self).await
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
        resolve::find_drive_by_id_owner(client, drive_id, owner.as_ref(), scope.as_private())
            .await?;

    let root_folder_location = resolve::find_entity_location_by_id_drive::<FolderKind>(
        client,
        drive_entity.root_folder(),
        &drive_id,
    )
    .await?;

    let root_folder_entity = resolve::folder_entity(
        drive_entity.root_folder(),
        client,
        &root_folder_location,
        &drive_id,
        owner.as_ref(),
        scope.as_private(),
    )
    .await?;

    let mut tx = pool.write().await.map_err(Error::SqlxError)?;

    insert_entity(&root_folder_entity, &mut tx).await?;
    insert_entity(&drive_entity, &mut tx).await?;

    let config = Config::from(
        drive_entity,
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

    let drive_id = sqlx::query!(
        "SELECT id FROM entity WHERE entity_type = 'DR' AND entity_id = ?",
        drive_entity_id,
    )
    .fetch_one(conn.conn())
    .await?
    .id;

    sqlx::query!(
        "INSERT INTO config (drive_id, signature_id, name, owner, network_id) VALUES (?, ?, ?, ?, ?)",
        drive_id,
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

async fn get_latest_sync_log_entry<C: Read>(conn: &mut C) -> Result<Option<SyncLogEntry>, Error> {
    let row: SyncLogRow = match sqlx::query_as!(
        SyncLogRow,
        "SELECT
             start_time, duration_ms, result, insertions, deletions, modifications, block_height, error
         FROM
             sync_log
         ORDER BY
             start_time
         DESC
         LIMIT 1"
    )
        .fetch_optional(conn.conn())
        .await?
    {
        Some(row) => row,
        None => return Ok(None),
    };

    Ok(Some(row.try_into()?))
}

async fn insert_sync_log_entry<C: Write>(
    sync_log_entry: &SyncLogEntry,
    conn: &mut C,
) -> Result<(), Error> {
    let row = SyncLogRow::from(sync_log_entry);

    sqlx::query!(
        "INSERT INTO sync_log
             (start_time, duration_ms, result, insertions, deletions, modifications, block_height, error)
         VALUES
             (?, ?, ?, ?, ?, ?, ?, ?)",
        row.start_time,
        row.duration_ms,
        row.result,
        row.insertions,
        row.deletions,
        row.modifications,
        row.block_height,
        row.error,
    )
        .execute(conn.conn())
        .await?;
    Ok(())
}

struct SyncLogRow {
    start_time: NaiveDateTime,
    duration_ms: i64,
    result: String,
    insertions: Option<i64>,
    deletions: Option<i64>,
    modifications: Option<i64>,
    block_height: Option<i64>,
    error: Option<String>,
}

impl TryFrom<SyncLogRow> for SyncLogEntry {
    type Error = DataError;

    fn try_from(value: SyncLogRow) -> Result<Self, Self::Error> {
        let start_time = value.start_time.and_utc();
        let duration = Duration::from_millis(value.duration_ms as u64);

        let result = match value.result.as_ref() {
            "S" => SyncResult::OK(SyncSuccess {
                insertions: value.insertions.map(|v| v as usize).unwrap_or_default(),
                deletions: value.deletions.map(|v| v as usize).unwrap_or_default(),
                modifications: value.modifications.map(|v| v as usize).unwrap_or_default(),
                block: BlockNumber::from_inner(
                    value
                        .block_height
                        .ok_or_else(|| DataError::MissingData("block_height not set".to_string()))?
                        as u64,
                ),
            }),
            "E" => SyncResult::Error(value.error),
            other => Err(DataError::ConversionError(format!(
                "invalid result value: '{}'",
                other
            )))?,
        };

        Ok(Self {
            start_time,
            duration,
            result,
        })
    }
}

impl From<&SyncLogEntry> for SyncLogRow {
    fn from(value: &SyncLogEntry) -> Self {
        let (result, block_height, insertions, deletions, modifications, error);

        match &value.result {
            SyncResult::OK(success) => {
                result = "S".into();
                insertions = Some(success.insertions as i64);
                deletions = Some(success.deletions as i64);
                modifications = Some(success.modifications as i64);
                block_height = Some(i64::try_from(*success.block.as_ref()).unwrap_or(i64::MAX));
                error = None;
            }
            SyncResult::Error(err) => {
                result = "E".into();
                insertions = None;
                deletions = None;
                modifications = None;
                block_height = None;
                error = err.as_ref().map(|d| d.into());
            }
        }

        Self {
            start_time: value.start_time.naive_utc(),
            duration_ms: value.duration.as_millis() as i64,
            result,
            insertions,
            deletions,
            modifications,
            block_height,
            error,
        }
    }
}

struct ConfigRow {
    drive_id: i64,
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

async fn get_entity<E: DbEntity, C: Read>(id: i64, tx: &mut C) -> Result<Model<E>, Error> {
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

async fn insert_entity<E: DbEntity, C: Write>(entity: &Model<E>, tx: &mut C) -> Result<i64, Error> {
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

    Ok(sqlx::query!(
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
    .last_insert_rowid())
}

async fn get_config<C: Read>(tx: &mut C) -> Result<Option<Config>, Error> {
    let config_row: ConfigRow = match sqlx::query_as!(
        ConfigRow,
        "SELECT drive_id, signature_id, name, owner, network_id FROM config"
    )
    .fetch_optional(tx.conn())
    .await?
    {
        Some(config_row) => config_row,
        None => return Ok(None),
    };

    let drive = get_entity::<DriveKind, _>(config_row.drive_id, tx).await?;

    let signature: Option<Model<DriveSignatureKind>> = if let Some(sig_id) = config_row.signature_id
    {
        Some(get_entity(sig_id, &mut *tx).await?)
    } else {
        None
    };

    Ok(Some(Config::try_from(config_row, drive, signature)?))
}

async fn clear_temp_tables<C: Write>(tx: &mut C) -> Result<(), Error> {
    sqlx::query!("DELETE FROM vfs_affected_inodes")
        .execute(tx.conn())
        .await?;
    Ok(())
}

#[derive(Debug)]
pub struct Config {
    pub drive: DriveEntity,
    pub signature: Option<DriveSignatureEntity>,
    pub owner: WalletAddress,
    pub network_id: NetworkIdentifier,
}

impl Config {
    fn try_from(
        config_row: ConfigRow,
        drive: DriveEntity,
        signature: Option<DriveSignatureEntity>,
    ) -> Result<Self, DataError> {
        let owner = WalletAddress::try_from(OwnedBlob::from(config_row.owner))
            .map_err(|e| DataError::ConversionError(e.to_string()))?;
        let network_id = NetworkIdentifier::try_from(config_row.network_id)
            .map_err(|e| DataError::ConversionError(e.to_string()))?;

        Ok(Self {
            drive,
            signature,
            owner,
            network_id,
        })
    }
}

impl Config {
    fn from(
        drive: DriveEntity,
        signature: Option<DriveSignatureEntity>,
        owner: WalletAddress,
        network_id: NetworkIdentifier,
    ) -> Self {
        Self {
            drive,
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
) -> Result<(Option<Config>, SqlitePool), Error> {
    let writer = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with({
            SqliteConnectOptions::new()
                .create_if_missing(true)
                .filename(db_file)
                .log_statements(LevelFilter::Trace)
                .journal_mode(SqliteJournalMode::Wal)
                .foreign_keys(true)
                .pragma("recursive_triggers", "ON")
                .busy_timeout(Duration::from_millis(100))
                .shared_cache(true)
        })
        .await?;

    async { sqlx::migrate!("./migrations").run(&writer).await }
        .instrument(tracing::warn_span!("db_migration"))
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

trait DbEntity: Entity + Sized {
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
            Some(entity.data().to_string().into()),
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

            let file = FileEntity::new(header, metadata, block, location);

            if file.id() != &entity_id {
                Err(DataError::IdMismatch {
                    expected: entity_id.to_string(),
                    actual: file.id().to_string(),
                })?;
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
