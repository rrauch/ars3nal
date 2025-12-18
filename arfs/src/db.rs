use crate::serde_tag::Error as TagError;
use crate::sync::{LogEntry as SyncLogEntry, Success as SyncSuccess, SyncResult};
use crate::types::drive::{DriveEntity, DriveId, DriveKind};
use crate::types::drive_signature::{DriveSignatureEntity, DriveSignatureKind};
use crate::types::file::{FileEntity, FileKind};
use crate::types::folder::{FolderEntity, FolderKind};
use crate::types::snapshot::{SnapshotEntity, SnapshotKind};
use crate::types::{
    ArfsEntity, ArfsEntityId, Entity, HasId, HasName, Header, Metadata, Model, ParseError,
};
use crate::vfs::{
    Directory as VfsDirectory, File as VfsFile, InodeId, Name as VfsName, ROOT_INODE_ID, Stats,
};
use crate::wal::{ContentHash, WalFileMetadata};
use crate::{FolderId, Inode, Privacy, Scope, Timestamp, VfsPath, resolve};
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
    #[error("deletion of inode '{0}' failed. (recursive_delete: '{1}')")]
    DeletionFailure(InodeId, bool),
    #[error("VFS root cannot be deleted")]
    RootDeletionAttempt,
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
    /*pub async fn entity_by_id<E: Entity + HasId<Id: AsRef<[u8]>>>(
        &mut self,
        id: &<E as HasId>::Id,
    ) -> Result<Model<E>, Error>
    where
        E: DbEntity,
    {
        let id = get_id_for_entity_id::<E, _>(id, self).await?;
        get_entity(id, self).await
    }*/

    pub async fn latest_sync_log_entry(&mut self) -> Result<Option<SyncLogEntry>, Error> {
        get_latest_sync_log_entry(self).await
    }

    pub async fn last_sync_block_height(&mut self) -> Result<Option<BlockNumber>, Error> {
        Ok(sqlx::query!(
            "SELECT MAX(block_height) as block_height FROM sync_log WHERE result = 'S'"
        )
        .map(|r| r.block_height.map(|b| BlockNumber::from_inner(b as u64)))
        .fetch_optional(self.conn())
        .await?
        .flatten())
    }

    pub async fn config(&mut self) -> Result<Config, Error> {
        get_config(self).await?.ok_or(DbStateError::NoConfig.into())
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

    pub async fn inode_id_by_path(&mut self, path: &str) -> Result<Option<InodeId>, Error> {
        sqlx::query!(
            "SELECT id FROM vfs WHERE path = ? OR (path = ? || '/' AND inode_type = 'FO')",
            path,
            path
        )
        .fetch_optional(self.conn())
        .await?
        .map(|r| InodeId::try_from(r.id as u64))
        .transpose()
        .map_err(|e| DataError::ConversionError(e.to_string()).into())
    }

    pub async fn inode_by_id(&mut self, id: InodeId) -> Result<Option<Inode>, Error> {
        get_inode(*id.deref() as i64, self).await
    }

    pub async fn inodes_by_ids(
        &mut self,
        ids: impl IntoIterator<Item = InodeId>,
    ) -> Result<Vec<Inode>, Error> {
        let mut inodes = vec![];
        for id in ids.into_iter() {
            inodes.push(self.inode_by_id(id).await?.ok_or_else(|| {
                DataError::MissingData(format!("Inode with id '{}' not found", id))
            })?);
        }
        Ok(inodes)
    }

    pub async fn list_dir(&mut self, dir_id: InodeId) -> Result<Vec<InodeId>, Error> {
        Ok(inode_ids_by_parent(*dir_id.deref() as i64, self)
            .await?
            .map(|id| {
                InodeId::try_from(id as u64)
                    .map_err(|e| DataError::ConversionError(e.to_string()).into())
            })
            .collect::<Result<Vec<_>, Error>>()?)
    }

    pub async fn list_root(&mut self) -> Result<Vec<InodeId>, Error> {
        Ok(inode_ids_without_parent(self)
            .await?
            .map(|id| {
                InodeId::try_from(id as u64)
                    .map_err(|e| DataError::ConversionError(e.to_string()).into())
            })
            .collect::<Result<Vec<_>, Error>>()?)
    }

    pub async fn find_inodes(
        &mut self,
        prefix: Option<&str>,
        delimiter: Option<&str>,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<(Vec<InodeId>, bool), Error> {
        let prefix = match prefix {
            Some(prefix) if prefix.starts_with("/") => Cow::Borrowed(prefix),
            Some(prefix) => Cow::Owned(format!("/{}", prefix)),
            None => Cow::Borrowed("/"),
        };

        let start_after = match start_after {
            Some(start_after) if start_after.starts_with("/") => Cow::Borrowed(start_after),
            Some(start_after) => Cow::Owned(format!("/{}", start_after)),
            None => Cow::Borrowed("/"),
        };

        let max_keys = max_keys as i64;
        let mut truncated = false;

        let ids = sqlx::query!(
            "
WITH params AS (SELECT ? AS prefix,
                       ? AS delimiter,
                       ? AS start_after,
                       ? AS max_keys)
SELECT vfs.id
FROM vfs,
     params
WHERE
  -- Base filters
  vfs.path LIKE params.prefix || '%'
  AND vfs.path > params.start_after

  -- S3 Logic Gate: Handles both flat and delimited listing modes
  AND (
    -- Condition for returning a file ('Contents')
    (
        vfs.inode_type = 'FI'
            AND (
            -- True for flat lists (no delimiter)
            params.delimiter IS NULL
                -- True for delimited lists if the file is at the current level
                OR INSTR(SUBSTR(vfs.path, LENGTH(params.prefix) + 1), params.delimiter) = 0
            )
        )
        OR
        -- Condition for returning a folder ('CommonPrefix')
    (
        -- This block is only active when a delimiter is used
        params.delimiter IS NOT NULL
            AND vfs.inode_type = 'FO'
            -- The folder's path must be a \"common prefix\" for deeper items
            AND vfs.path IN (SELECT DISTINCT SUBSTR(vfs_inner.path, 1, LENGTH(bp.prefix) + INSTR(
                SUBSTR(vfs_inner.path, LENGTH(bp.prefix) + 1), bp.delimiter))
                             FROM vfs AS vfs_inner,
                                  params AS bp
                             WHERE vfs_inner.path LIKE bp.prefix || '%' || bp.delimiter || '%')
        )
    )
ORDER BY vfs.path
LIMIT (SELECT max_keys FROM params) + 1;
",
            prefix,
            delimiter,
            start_after,
            max_keys,
        )
        .fetch(self.conn())
        .enumerate()
        .filter_map(|(i, r)| {
            if i >= max_keys as usize {
                truncated = true;
                None
            } else {
                Some(
                    r.map(|r| {
                        InodeId::try_from(r.id as u64)
                            .map_err(|e| DataError::ConversionError(e.to_string()).into())
                    })
                    .map_err(Error::SqlxError)
                    .flatten(),
                )
            }
        })
        .try_collect::<InodeId, Error, Vec<_>>()
        .await?;

        Ok((ids, truncated))
    }

    pub async fn next_proactive_cache_file(
        &mut self,
        cached_cutoff: &DateTime<Utc>,
        attempt_cutoff: &DateTime<Utc>,
    ) -> Result<Option<(InodeId, Option<DateTime<Utc>>, Option<DateTime<Utc>>)>, Error> {
        let cached_cutoff = cached_cutoff.timestamp();
        let attempt_cutoff = attempt_cutoff.timestamp();

        fn convert(
            inode_id: i64,
            last_proactively_cached_at: Option<i64>,
            last_proactive_cache_attempt_at: Option<i64>,
        ) -> Result<(InodeId, Option<DateTime<Utc>>, Option<DateTime<Utc>>), DataError> {
            let inode_id = InodeId::try_from(inode_id as u64)
                .map_err(|e| DataError::ConversionError(e.to_string()))?;

            let last_proactively_cached_at = last_proactively_cached_at
                .map(|l| DateTime::from_timestamp(l, 0))
                .flatten();
            let last_proactive_cache_attempt_at = last_proactive_cache_attempt_at
                .map(|l| DateTime::from_timestamp(l, 0))
                .flatten();
            Ok((
                inode_id,
                last_proactively_cached_at,
                last_proactive_cache_attempt_at,
            ))
        }

        Ok(sqlx::query!(
            "
            SELECT id,
       last_proactively_cached_at as \"last_proactively_cached_at: i64\",
       last_proactive_cache_attempt_at  as \"last_proactive_cache_attempt_at: i64\"
FROM vfs
WHERE inode_type = 'FI'
  AND perm_type = 'P'
  AND (last_proactively_cached_at IS NULL OR last_proactively_cached_at < ?)
  AND (last_proactive_cache_attempt_at IS NULL OR last_proactive_cache_attempt_at < ?)
ORDER BY COALESCE(last_proactive_cache_attempt_at, 0),
         COALESCE(last_proactively_cached_at, 0),
         id
LIMIT 1;",
            cached_cutoff,
            attempt_cutoff
        )
        .fetch_optional(self.conn())
        .await?
        .map(|r| {
            convert(
                r.id,
                r.last_proactively_cached_at,
                r.last_proactive_cache_attempt_at,
            )
        })
        .transpose()?)
    }

    pub async fn wal_file_chunks(
        &mut self,
        wal_file_id: u64,
    ) -> Result<Option<Vec<(usize, Vec<u8>)>>, Error> {
        let wal_file_id = wal_file_id as i64;
        if sqlx::query!(
            "
            SELECT id FROM wal_entity WHERE id = ? AND entity_type = 'FI' LIMIT 1
            ",
            wal_file_id
        )
        .fetch_optional(self.conn())
        .await?
        .is_none()
        {
            return Ok(None);
        };

        Ok(Some(
            sqlx::query!(
                r#"
SELECT c.content_length, c.content_hash
FROM wal_chunks wc
JOIN wal_content c ON wc.content_hash = c.content_hash
WHERE wc.file_id = ?
ORDER BY wc.chunk_nr;
            "#,
                wal_file_id,
            )
            .map(|r| (r.content_length as usize, r.content_hash))
            .fetch_all(self.conn())
            .await?,
        ))
    }

    pub async fn wal_content(
        &mut self,
        content_hash: &ContentHash,
    ) -> Result<Option<Vec<u8>>, Error> {
        let content_hash = content_hash.as_ref();
        Ok(sqlx::query!(
            "
            SELECT content FROM wal_content WHERE content_hash = ?
            ",
            content_hash,
        )
        .map(|r| r.content)
        .fetch_optional(self.conn())
        .await?)
    }
}

impl<C: TxScope> Transaction<C>
where
    Self: Write,
{
    pub async fn sync_log_entry(&mut self, log_entry: &SyncLogEntry) -> Result<(), Error> {
        insert_sync_log_entry(log_entry, self).await
    }

    pub async fn sync_update(
        &mut self,
        mut stream: impl Stream<Item = Result<ArfsEntity, crate::Error>> + Unpin,
    ) -> Result<(usize, usize, usize, Vec<InodeId>), crate::Error> {
        enum Entry<'a> {
            New(i64, Option<&'a FolderId>),
            Updated(
                i64,
                &'a str,
                &'a Timestamp,
                u64,
                Option<&'a FolderId>,
                Vec<i64>,
            ),
            Deleted(Vec<i64>),
        }

        clear_temp_tables(self).await?;

        let mut deleted = 0;
        let mut updated = 0;
        let mut inserted = 0;

        let config = self.config().await?;

        while let Some(entity) = stream.try_next().await? {
            let (entity_id, is_folder, entry) = match entity {
                ArfsEntity::File(ref file) => {
                    let (db_id, superseded) = insert_entity(&file, self).await?;
                    let entry = if file.is_hidden() {
                        Entry::Deleted(superseded)
                    } else if superseded.is_empty() {
                        Entry::New(db_id, Some(file.parent_folder()))
                    } else {
                        Entry::Updated(
                            db_id,
                            file.name(),
                            file.last_modified(),
                            file.size(),
                            Some(file.parent_folder()),
                            superseded,
                        )
                    };
                    (db_id, false, entry)
                }
                ArfsEntity::Folder(ref folder) => {
                    let (db_id, superseded) = insert_entity(&folder, self).await?;
                    let entry = if folder.is_hidden() {
                        Entry::Deleted(superseded)
                    } else if superseded.is_empty() {
                        Entry::New(db_id, folder.parent_folder())
                    } else {
                        Entry::Updated(
                            db_id,
                            folder.name(),
                            folder.timestamp(),
                            0,
                            folder.parent_folder(),
                            superseded,
                        )
                    };
                    (db_id, true, entry)
                }
                _ => continue,
            };

            let mut find_parent = async |parent: Option<&FolderId>| -> Result<Option<i64>, Error> {
                Ok(match parent {
                    Some(folder_id) if folder_id == config.root_folder.id() => None,
                    Some(folder_id) => {
                        let folder_id = folder_id.as_ref();
                        Some(
                            sqlx::query!(
                                "
                                SELECT id FROM entity
                                          WHERE entity_type = 'FO'
                                            AND entity_id = ?
                                          ORDER BY block DESC
                                        LIMIT 1
                                ",
                                folder_id
                            )
                            .map(|r| r.id)
                            .fetch_one(self.conn())
                            .await
                            .map_err(Error::SqlxError)?,
                        )
                    }
                    None => None,
                })
            };

            match entry {
                Entry::New(id, parent) => {
                    let parent = find_parent(parent).await?;
                    insert_arfs_inode(&entity, id, parent, self).await?;
                    inserted += 1;
                }
                Entry::Updated(new_id, name, last_modified, size, parent, superseded) => {
                    let parent = find_parent(parent).await?;
                    let last_modified = last_modified.timestamp();
                    let size = size as i64;
                    for id in superseded {
                        updated += sqlx::query!(
                            "
                               UPDATE vfs SET
                                              entity = ?,
                                              name = ?,
                                              last_modified = ?,
                                              size = ?,
                                              parent = ?
                                          WHERE id = ?
                            ",
                            new_id,
                            name,
                            last_modified,
                            size,
                            parent,
                            id,
                        )
                        .execute(self.conn())
                        .await
                        .map_err(Error::SqlxError)?
                        .rows_affected() as usize;
                    }
                }
                Entry::Deleted(superseded) => {
                    for id in superseded {
                        deleted += sqlx::query!("DELETE FROM vfs WHERE entity = ?", id)
                            .execute(self.conn())
                            .await
                            .map_err(Error::SqlxError)?
                            .rows_affected() as usize;
                    }
                }
            }
        }

        self.delete_orphaned_entities().await?;

        let affected_inode_ids = collect_affected_inode_ids(self)
            .await?
            .map(|id| {
                InodeId::try_from(id as u64)
                    .map_err(|e| DataError::ConversionError(e.to_string()).into())
            })
            .collect::<Result<Vec<_>, Error>>()?;
        clear_temp_tables(self).await?;

        Ok((updated, inserted, deleted, affected_inode_ids))
    }

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

    pub async fn update_proactive_cache_file(
        &mut self,
        inode_id: InodeId,
        last_success: Option<&DateTime<Utc>>,
        last_attempt: Option<&DateTime<Utc>>,
    ) -> Result<(), Error> {
        let inode_id = *inode_id.deref() as i64;
        let last_success = last_success.map(|ts| ts.timestamp());
        let last_attempt = last_attempt.map(|ts| ts.timestamp());

        sqlx::query!(
            "
            UPDATE vfs SET last_proactively_cached_at = ?, last_proactive_cache_attempt_at = ?
            WHERE id = ? AND inode_type = 'FI' AND perm_type = 'P'
        ",
            last_success,
            last_attempt,
            inode_id,
        )
        .execute(self.conn())
        .await?;
        Ok(())
    }

    pub async fn new_wal_dir(
        &mut self,
        path: &VfsPath,
        last_modified: &DateTime<Utc>,
    ) -> Result<(InodeId, Vec<InodeId>), Error> {
        clear_temp_tables(self).await?;
        let (parent, name) = path.split();
        let parent_inode_id = if !parent.is_root() {
            Some(
                self.inode_id_by_path(parent.as_ref())
                    .await?
                    .ok_or_else(|| {
                        DataError::MissingData(format!(
                            "parent directory '{}' missing",
                            parent.as_ref()
                        ))
                    })?,
            )
        } else {
            None
        };

        let name = name.ok_or_else(|| {
            DataError::MissingData("cannot create directory without name".to_string())
        })?;
        let last_modified = last_modified.timestamp();

        let wal_entity_id = sqlx::query!("INSERT INTO wal_entity (entity_type) VALUES ('FO')")
            .execute(self.conn())
            .await?
            .last_insert_rowid();

        let row = VfsRow {
            id: 0,
            inode_type: "FO".into(),
            perm_type: "W".into(),
            entity: None,
            wal_entity: Some(wal_entity_id),
            name: name.as_ref().into(),
            size: 0,
            last_modified,
            parent: parent_inode_id.map(|i| *i as i64),
            path: None,
        };

        let inode_id = InodeId::try_from(insert_vfs_row(&row, self).await?)
            .map_err(|e| DataError::ConversionError(e.to_string()))?;

        let affected_inode_ids = collect_affected_inode_ids(self)
            .await?
            .map(|id| {
                InodeId::try_from(id as u64)
                    .map_err(|e| DataError::ConversionError(e.to_string()).into())
            })
            .collect::<Result<Vec<_>, Error>>()?;
        clear_temp_tables(self).await?;

        Ok((inode_id, affected_inode_ids))
    }

    pub async fn new_wal_file(&mut self, metadata: Option<&WalFileMetadata>) -> Result<u64, Error> {
        let metadata = metadata
            .map(|m| serde_sqlite_jsonb::to_vec(m))
            .transpose()
            .map_err(DataError::JsonbError)?;

        let id = sqlx::query!(
            "INSERT INTO wal_entity (entity_type, metadata) VALUES ('FI', ?)",
            metadata
        )
        .execute(self.conn())
        .await?
        .last_insert_rowid();

        Ok(id as u64)
    }

    pub async fn upsert_vfs_file(
        &mut self,
        path: &VfsPath,
        last_modified: &DateTime<Utc>,
        size: ByteSize,
        wal_entity_id: u64,
    ) -> Result<(InodeId, Vec<InodeId>), Error> {
        clear_temp_tables(self).await?;
        let inode_id = if let Some(inode_id) = self.inode_id_by_path(path.as_ref()).await? {
            // existing vfs entry
            let vfs_row = get_vfs_row(*inode_id.deref() as i64, self)
                .await?
                .ok_or_else(|| {
                    DataError::MissingData(format!("inode with id '{0}' not found", inode_id))
                })?;

            match vfs_row.inode_type.as_ref() {
                <FileKind as DbEntity>::TYPE => {}
                other => Err(DataError::IncorrectEntityType {
                    expected: <FileKind as DbEntity>::TYPE.into(),
                    actual: other.to_string().into(),
                })?,
            }

            let wal_entity_id = wal_entity_id as i64;
            let size = size.as_u64() as i64;
            let last_modified = last_modified.timestamp();
            let id = *inode_id as i64;
            sqlx::query!(
                "
                    UPDATE vfs SET
                                   perm_type = 'W',
                                   entity = NULL,
                                   wal_entity = ?,
                                   size = ?,
                                   last_modified = ?,
                                   last_proactively_cached_at = NULL,
                                   last_proactive_cache_attempt_at = NULL
                        WHERE id = ? AND inode_type = 'FI'
                    ",
                wal_entity_id,
                size,
                last_modified,
                id,
            )
            .execute(self.conn())
            .await?;
            self.delete_orphaned_entities().await?;
            Ok::<_, Error>(inode_id)
        } else {
            // new vfs entry
            let (parent, name) = path.split();
            let parent_id = if !parent.is_root() {
                Some(
                    *self
                        .inode_id_by_path(parent.as_ref())
                        .await?
                        .ok_or_else(|| DataError::MissingData("parent not found".to_string()))?
                        as i64,
                )
            } else {
                None
            };

            let name = name.ok_or_else(|| DataError::MissingData("name not set".to_string()))?;
            let size = size.as_u64() as i64;
            let last_modified = last_modified.timestamp();
            let row = VfsRow {
                id: 0,
                inode_type: "FI".into(),
                perm_type: "W".into(),
                entity: None,
                wal_entity: Some(wal_entity_id as i64),
                name: name.as_ref().into(),
                size,
                last_modified,
                parent: parent_id,
                path: None,
            };

            Ok(InodeId::try_from(insert_vfs_row(&row, self).await?)
                .map_err(|e| DataError::ConversionError(e.to_string()))?)
        }?;

        let affected_inode_ids = collect_affected_inode_ids(self)
            .await?
            .map(|id| {
                InodeId::try_from(id as u64)
                    .map_err(|e| DataError::ConversionError(e.to_string()).into())
            })
            .collect::<Result<Vec<_>, Error>>()?;
        clear_temp_tables(self).await?;

        Ok((inode_id, affected_inode_ids))
    }

    pub async fn insert_wal_content(
        &mut self,
        content_hash: &[u8],
        content: &[u8],
    ) -> Result<(), Error> {
        sqlx::query!(
            "
             INSERT INTO wal_content (content_hash, content)
                VALUES (?, ?)
            ON CONFLICT (content_hash) DO NOTHING
            ",
            content_hash,
            content,
        )
        .execute(self.conn())
        .await?;
        Ok(())
    }

    pub async fn insert_wal_chunk(
        &mut self,
        file_id: u64,
        chunk_no: usize,
        content_hash: &[u8],
    ) -> Result<(), Error> {
        let file_id = file_id as i64;
        let chunk_no = chunk_no as i64;
        sqlx::query!(
            "
             INSERT INTO wal_chunks (file_id, chunk_nr, content_hash)
                VALUES (?, ?, ?)
            ",
            file_id,
            chunk_no,
            content_hash,
        )
        .execute(self.conn())
        .await?;
        Ok(())
    }

    pub async fn delete_inodes(
        &mut self,
        inode_ids: impl Iterator<Item = InodeId>,
        recursive_delete: bool,
    ) -> Result<Vec<InodeId>, Error> {
        clear_temp_tables(self).await?;
        for inode_id in inode_ids {
            self.delete_inode(inode_id, recursive_delete).await?;
        }
        self.delete_orphaned_entities().await?;

        let affected_inode_ids = collect_affected_inode_ids(self)
            .await?
            .map(|id| {
                InodeId::try_from(id as u64)
                    .map_err(|e| DataError::ConversionError(e.to_string()).into())
            })
            .collect::<Result<Vec<_>, Error>>()?;

        clear_temp_tables(self).await?;

        Ok(affected_inode_ids)
    }

    async fn delete_inode(
        &mut self,
        inode_id: InodeId,
        recursive_delete: bool,
    ) -> Result<(), Error> {
        if inode_id == ROOT_INODE_ID {
            Err(DataError::RootDeletionAttempt)?
        }

        let inode_id_int = *inode_id as i64;
        let rows_affected = if recursive_delete {
            sqlx::query!(
                "
                 DELETE FROM vfs
                 WHERE id = ?
                ",
                inode_id_int,
            )
            .execute(self.conn())
            .await?
            .rows_affected()
        } else {
            sqlx::query!(
                "
                 DELETE FROM vfs
                 WHERE id = ?
                    AND (
                      inode_type = 'FI'
                      OR NOT EXISTS (
                        SELECT 1
                        FROM vfs
                         WHERE parent = ?
                      )
                );
                ",
                inode_id_int,
                inode_id_int
            )
            .execute(self.conn())
            .await?
            .rows_affected()
        };

        if rows_affected == 0 {
            Err(DataError::DeletionFailure(inode_id, recursive_delete))?
        }

        Ok(())
    }

    async fn delete_orphaned_entities(&mut self) -> Result<(), Error> {
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
              AND id NOT IN (SELECT root_folder_id
                 FROM config)
              AND entity_type = 'FO';
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
              );
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
        resolve::find_drive_by_id_owner(client, drive_id, owner.as_ref(), scope.as_private())
            .await?;

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
        scope.as_private(),
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
        "INSERT INTO config (drive_id, root_folder_id, signature_id, name, owner, network_id) VALUES (?, ?, ?, ?, ?, ?)",
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

async fn get_latest_sync_log_entry<C: Read>(conn: &mut C) -> Result<Option<SyncLogEntry>, Error> {
    let row: SyncLogRow = match sqlx::query_as!(
        SyncLogRow,
        "SELECT
             start_time as \"start_time: i64\", duration_ms, result, updates, insertions, deletions, block_height, error
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
             (start_time, duration_ms, result, updates, insertions, deletions, block_height, error)
         VALUES
             (?, ?, ?, ?, ?, ?, ?, ?)",
        row.start_time,
        row.duration_ms,
        row.result,
        row.updates,
        row.insertions,
        row.deletions,
        row.block_height,
        row.error,
    )
    .execute(conn.conn())
    .await?;
    Ok(())
}

struct SyncLogRow {
    start_time: i64,
    duration_ms: i64,
    result: String,
    updates: Option<i64>,
    insertions: Option<i64>,
    deletions: Option<i64>,
    block_height: Option<i64>,
    error: Option<String>,
}

impl TryFrom<SyncLogRow> for SyncLogEntry {
    type Error = DataError;

    fn try_from(value: SyncLogRow) -> Result<Self, Self::Error> {
        let start_time = DateTime::from_timestamp(value.start_time, 0)
            .ok_or(DataError::ConversionError("Invalid timestamp".to_string()))?;
        let duration = Duration::from_millis(value.duration_ms as u64);

        let result = match value.result.as_ref() {
            "S" => SyncResult::OK(SyncSuccess {
                updates: value.updates.map(|v| v as usize).unwrap_or_default(),
                insertions: value.insertions.map(|v| v as usize).unwrap_or_default(),
                deletions: value.deletions.map(|v| v as usize).unwrap_or_default(),
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
        let (result, block_height, updates, insertions, deletions, error);

        match &value.result {
            SyncResult::OK(success) => {
                result = "S".into();
                updates = Some(success.updates as i64);
                insertions = Some(success.insertions as i64);
                deletions = Some(success.deletions as i64);
                block_height = Some(i64::try_from(*success.block.as_ref()).unwrap_or(i64::MAX));
                error = None;
            }
            SyncResult::Error(err) => {
                result = "E".into();
                updates = None;
                insertions = None;
                deletions = None;
                block_height = None;
                error = err.as_ref().map(|d| d.into());
            }
        }

        Self {
            start_time: value.start_time.timestamp(),
            duration_ms: value.duration.as_millis() as i64,
            result,
            updates,
            insertions,
            deletions,
            block_height,
            error,
        }
    }
}

struct ConfigRow {
    drive_id: i64,
    root_folder_id: i64,
    signature_id: Option<i64>,
    name: String,
    owner: Vec<u8>,
    network_id: String,
}

struct VfsRow<'a> {
    id: i64,
    inode_type: Cow<'a, str>,
    perm_type: Cow<'a, str>,
    entity: Option<i64>,
    wal_entity: Option<i64>,
    name: Cow<'a, str>,
    size: i64,
    last_modified: i64,
    parent: Option<i64>,
    path: Option<Cow<'a, str>>,
}

impl<'a> From<(&'a FolderEntity, i64, Option<i64>)> for VfsRow<'a> {
    fn from((entity, entity_id, parent_id): (&'a FolderEntity, i64, Option<i64>)) -> Self {
        let last_modified = entity.timestamp().timestamp();
        to_vfs_row(entity, entity_id, 0, last_modified, parent_id)
    }
}

impl<'a> From<(&'a FileEntity, i64, Option<i64>)> for VfsRow<'a> {
    fn from((entity, entity_id, parent_id): (&'a FileEntity, i64, Option<i64>)) -> Self {
        let last_modified = entity.timestamp().timestamp();
        let size = entity.size();
        to_vfs_row(entity, entity_id, size as i64, last_modified, parent_id)
    }
}

fn to_vfs_row<E: DbEntity>(
    entity: &Model<E>,
    entity_id: i64,
    size: i64,
    last_modified: i64,
    parent: Option<i64>,
) -> VfsRow<'_>
where
    E: HasName,
{
    VfsRow {
        id: 0,
        inode_type: <E as DbEntity>::TYPE.into(),
        perm_type: "P".into(),
        entity: Some(entity_id),
        wal_entity: None,
        name: entity.name().into(),
        size,
        last_modified,
        parent,
        path: None,
    }
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

async fn get_vfs_row<C: Read>(inode_id: i64, tx: &mut C) -> Result<Option<VfsRow<'static>>, Error> {
    Ok(sqlx::query!(
        "SELECT
             id, inode_type, perm_type, entity, wal_entity, name, size, last_modified as \"last_modified: i64\", parent, path
         FROM
             vfs
         WHERE
             id = ?",
        inode_id
    )
        .fetch_optional(tx.conn())
        .await?.map(|r| {
        VfsRow {
            id: r.id,
            inode_type: r.inode_type.into(),
            perm_type: r.perm_type.into(),
            entity: r.entity,
            wal_entity: r.wal_entity,
            name: r.name.into(),
            size: r.size,
            last_modified: r.last_modified,
            parent: r.parent,
            path: Some(r.path.into()),
        }
    }))
}

async fn get_inode<C: Read>(inode_id: i64, tx: &mut C) -> Result<Option<Inode>, Error> {
    let vfs_row = match get_vfs_row(inode_id, tx).await? {
        Some(vfs_row) => vfs_row,
        None => return Ok(None),
    };

    let id = InodeId::try_from(vfs_row.id as u64)
        .map_err(|e| DataError::ConversionError(e.to_string()))?;
    let name = VfsName::from_str(vfs_row.name.as_ref())
        .map_err(|e| DataError::ConversionError(e.to_string()))?;
    let last_modified = Timestamp::from_timestamp(vfs_row.last_modified, 0)
        .ok_or_else(|| DataError::ConversionError("timestamp is invalid".to_string()))?;
    let path = vfs_row
        .path
        .ok_or_else(|| DataError::MissingData("path not set".to_string()))?;
    let path = VfsPath::try_from::<str>(path.as_ref())
        .map_err(|e| DataError::ConversionError(e.to_string()))?;

    match vfs_row.perm_type.as_ref() {
        "P" => match vfs_row.inode_type.as_ref() {
            <FileKind as DbEntity>::TYPE => {
                let entity = get_entity::<FileKind, _>(
                    vfs_row
                        .entity
                        .ok_or_else(|| DataError::MissingData("entity not set".to_string()))?,
                    tx,
                )
                .await?;
                Ok(Some(Inode::File(VfsFile::new_permanent(
                    id,
                    name,
                    ByteSize::b(vfs_row.size as u64),
                    last_modified,
                    path,
                    entity,
                ))))
            }
            <FolderKind as DbEntity>::TYPE => {
                let entity = get_entity::<FolderKind, _>(
                    vfs_row
                        .entity
                        .ok_or_else(|| DataError::MissingData("entity not set".to_string()))?,
                    tx,
                )
                .await?;
                Ok(Some(Inode::Directory(VfsDirectory::new_permanent(
                    id,
                    name,
                    last_modified,
                    path,
                    entity,
                ))))
            }
            other => Err(DataError::NotInodeEntityType(other.to_string()))?,
        },
        "W" => {
            match vfs_row.inode_type.as_ref() {
                <FileKind as DbEntity>::TYPE => {
                    let wal_id = vfs_row
                        .wal_entity
                        .ok_or_else(|| DataError::MissingData("wal_entity not set".to_string()))?;

                    let metadata = sqlx::query!(
                        "SELECT metadata from wal_entity WHERE id = ? AND entity_type = 'FI'",
                        wal_id
                    )
                    .fetch_one(tx.conn())
                    .await?
                    .metadata
                    .map(|jsonb| serde_sqlite_jsonb::from_slice::<WalFileMetadata>(&jsonb))
                    .transpose()
                    .map_err(|e| DataError::ConversionError(e.to_string()))?;

                    Ok(Some(Inode::File(VfsFile::new_wal(
                        id,
                        name,
                        ByteSize::b(vfs_row.size as u64),
                        last_modified,
                        path,
                        wal_id as u64,
                        metadata,
                    ))))
                }
                <FolderKind as DbEntity>::TYPE => Ok(Some(Inode::Directory(
                    VfsDirectory::new_wal(id, name, last_modified, path),
                ))),
                other => Err(DataError::NotInodeEntityType(other.to_string()))?,
            }
        }
        other => Err(DataError::InvalidPermType(other.to_string()))?,
    }
}

async fn insert_vfs_row<C: Write>(row: &VfsRow<'_>, tx: &mut C) -> Result<u64, Error> {
    let inode_type = row.inode_type.deref();
    let perm_type = row.perm_type.deref();
    let name = row.name.deref();

    Ok(sqlx::query!(
        "
        INSERT INTO vfs
            (perm_type, inode_type, entity, wal_entity, name, size, last_modified, parent) VALUES
            (?, ?, ?, ?, ?, ?, ?, ?)
        ",
        perm_type,
        inode_type,
        row.entity,
        row.wal_entity,
        name,
        row.size,
        row.last_modified,
        row.parent,
    )
    .execute(tx.conn())
    .await?
    .last_insert_rowid() as u64)
}

async fn insert_arfs_inode<C: Write>(
    entity: &ArfsEntity,
    entity_id: i64,
    parent_entity_id: Option<i64>,
    tx: &mut C,
) -> Result<(u64, String), Error> {
    match entity {
        ArfsEntity::File(e) => insert_inode(e, entity_id, parent_entity_id, tx).await,
        ArfsEntity::Folder(e) => insert_inode(e, entity_id, parent_entity_id, tx).await,
        _ => Err(DataError::IncorrectEntityType {
            expected: "File or Folder".into(),
            actual: "other".into(),
        })?,
    }
}

async fn insert_inode<'a, E: DbEntity, C: Write>(
    entity: &'a Model<E>,
    entity_id: i64,
    parent_entity_id: Option<i64>,
    tx: &mut C,
) -> Result<(u64, String), Error>
where
    VfsRow<'a>: From<(&'a Model<E>, i64, Option<i64>)>,
{
    let parent_id = if let Some(parent_entity_id) = parent_entity_id {
        Some(
            sqlx::query!("SELECT id FROM vfs where entity = ?", parent_entity_id)
                .fetch_one(tx.conn())
                .await?
                .id,
        )
    } else {
        None
    };

    let row = VfsRow::from((entity, entity_id, parent_id));
    let id = insert_vfs_row(&row, tx).await? as i64;

    let path = sqlx::query!("SELECT path FROM vfs WHERE id = ?", id)
        .fetch_one(tx.conn())
        .await?
        .path;
    Ok((id as u64, path))
}

async fn insert_entity<E: DbEntity, C: Write>(
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

async fn clear_temp_tables<C: Write>(tx: &mut C) -> Result<(), Error> {
    sqlx::query!("DELETE FROM vfs_affected_inodes")
        .execute(tx.conn())
        .await?;
    Ok(())
}

async fn collect_affected_inode_ids<C: Write>(
    tx: &mut C,
) -> Result<impl Iterator<Item = i64>, Error> {
    Ok(sqlx::query!("SELECT DISTINCT(id) FROM vfs_affected_inodes")
        .fetch_all(tx.as_mut())
        .await?
        .into_iter()
        .map(|r| r.id))
}

async fn inode_ids_without_parent<C: Read>(tx: &mut C) -> Result<impl Iterator<Item = i64>, Error> {
    Ok(
        sqlx::query!("SELECT id FROM vfs WHERE parent IS NULL ORDER BY name",)
            .fetch_all(tx.as_mut())
            .await?
            .into_iter()
            .map(|r| r.id),
    )
}

async fn inode_ids_by_parent<C: Read>(
    parent_id: i64,
    tx: &mut C,
) -> Result<impl Iterator<Item = i64>, Error> {
    Ok(sqlx::query!(
        "SELECT id FROM vfs WHERE parent = ? ORDER BY name",
        parent_id
    )
    .fetch_all(tx.as_mut())
    .await?
    .into_iter()
    .map(|r| r.id))
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
