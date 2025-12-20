use crate::db::{
    DataError, Error, Read, Transaction, TxScope, Write, clear_temp_tables,
    collect_affected_inode_ids, insert_entity,
};
use crate::sync::{LogEntry, Success, SyncResult};
use crate::types::ArfsEntity;
use crate::vfs::insert_arfs_inode;
use crate::{FolderId, InodeId, Timestamp};
use ario_core::BlockNumber;
use chrono::{DateTime, Utc};
use futures_lite::{Stream, StreamExt};
use std::ops::Deref;
use std::time::Duration;

impl<C: TxScope> Transaction<C>
where
    Self: Read,
{
    pub async fn latest_sync_log_entry(&mut self) -> Result<Option<LogEntry>, Error> {
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
}

impl<C: TxScope> Transaction<C>
where
    Self: Write,
{
    pub async fn sync_log_entry(&mut self, log_entry: &LogEntry) -> Result<(), Error> {
        insert_sync_log_entry(log_entry, self).await?;
        if let SyncResult::OK(success) = &log_entry.result {
            let block_height = *success.block as i64;
            let last_sync = (log_entry.start_time + log_entry.duration).timestamp();
            sqlx::query!(
                "UPDATE config SET last_sync = ?, block_height = ?",
                last_sync,
                block_height
            )
            .execute(self.conn())
            .await?;
        }
        Ok(())
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
}

async fn get_latest_sync_log_entry<C: Read>(conn: &mut C) -> Result<Option<LogEntry>, Error> {
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
    sync_log_entry: &LogEntry,
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

impl TryFrom<SyncLogRow> for LogEntry {
    type Error = DataError;

    fn try_from(value: SyncLogRow) -> Result<Self, Self::Error> {
        let start_time = DateTime::from_timestamp(value.start_time, 0)
            .ok_or(DataError::ConversionError("Invalid timestamp".to_string()))?;
        let duration = Duration::from_millis(value.duration_ms as u64);

        let result = match value.result.as_ref() {
            "S" => SyncResult::OK(Success {
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

impl From<&LogEntry> for SyncLogRow {
    fn from(value: &LogEntry) -> Self {
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
