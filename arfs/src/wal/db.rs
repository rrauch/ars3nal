use crate::db::{
    DataError, DbEntity, DbStateError, Error, Read, Transaction, TxScope, Write, clear_temp_tables,
    collect_affected_inode_ids,
};
use crate::types::file::FileKind;
use crate::vfs::{VfsRow, get_vfs_row, insert_vfs_row};
use crate::wal::{ContentHash, Op, WalDirMetadata, WalFileMetadata};
use crate::{InodeId, State, Timestamp, VfsPath};
use ario_client::ByteSize;
use chrono::{DateTime, Utc};
use std::ops::Deref;

impl<C: TxScope> Transaction<C>
where
    Self: Read,
{
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
    async fn _new_wal_entry(
        &mut self,
        inode_id: InodeId,
        op: Op,
        timestamp: &Timestamp,
    ) -> Result<u64, crate::db::Error> {
        let inode_id = *inode_id as i64;
        let r = sqlx::query!(
            "SELECT perm_type, entity, wal_entity FROM vfs WHERE id = ?",
            inode_id
        )
        .fetch_one(self.conn())
        .await?;

        let op = match op {
            Op::Create => "C",
            Op::Update => "U",
            Op::Delete => "D",
        };

        let timestamp = timestamp.timestamp();
        let id = sqlx::query!(
            "INSERT INTO wal (timestamp, op_type, perm_type, entity, wal_entity) VALUES (?, ?, ?, ?, ?)",
            timestamp,
            op,
            r.perm_type,
            r.entity,
            r.wal_entity,
        ).execute(self.conn()).await?.last_insert_rowid();

        Ok(id as u64)
    }

    pub async fn wal_create(
        &mut self,
        inode_id: InodeId,
        timestamp: &Timestamp,
    ) -> Result<(), crate::db::Error> {
        self._new_wal_entry(inode_id, Op::Create, timestamp).await?;
        Ok(())
    }

    pub async fn wal_update(
        &mut self,
        inode_id: InodeId,
        timestamp: &Timestamp,
    ) -> Result<(), crate::db::Error> {
        self._new_wal_entry(inode_id, Op::Update, timestamp).await?;
        Ok(())
    }

    pub async fn wal_delete(
        &mut self,
        inode_id: InodeId,
        timestamp: &Timestamp,
    ) -> Result<(), crate::db::Error> {
        self._new_wal_entry(inode_id, Op::Delete, timestamp).await?;
        Ok(())
    }

    pub async fn uncommitted_wal_entry_count(&mut self) -> Result<usize, crate::db::Error> {
        Ok(
            sqlx::query!("SELECT COUNT(*) as uncommitted FROM wal WHERE block_height IS NULL")
                .map(|r| r.uncommitted as usize)
                .fetch_one(self.conn())
                .await?,
        )
    }

    pub async fn new_wal_dir(
        &mut self,
        path: &VfsPath,
        metadata: &WalDirMetadata,
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
        let last_modified = metadata.last_modified.timestamp();

        let metadata = Some(serde_sqlite_jsonb::to_vec(metadata).map_err(DataError::JsonbError)?);

        let wal_entity_id = sqlx::query!(
            "INSERT INTO wal_entity (entity_type, metadata) VALUES ('FO', ?)",
            metadata
        )
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

        self.wal_create(inode_id, &Utc::now()).await?;

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

    pub async fn initiate_wal_mode(&mut self) -> Result<(), Error> {
        let can_snapshot = sqlx::query!(
            "SELECT (NOT EXISTS(SELECT 1 FROM vfs_snapshot)
        AND NOT EXISTS(SELECT 1 FROM vfs WHERE perm_type != 'P')) as can_snapshot",
        )
        .map(|r| r.can_snapshot != 0)
        .fetch_one(self.conn())
        .await?;

        if !can_snapshot {
            Err(Error::DbStateError(DbStateError::NotInPermanentState))?
        }

        // create new vfs snapshot
        sqlx::query(
            "INSERT INTO vfs_snapshot (id, inode_type, entity, name, size, last_modified, parent)
     SELECT id, inode_type, entity, name, size, last_modified, parent
     FROM vfs",
        )
        .execute(self.conn())
        .await?;

        sqlx::query!("UPDATE config SET state = 'W'")
            .execute(self.conn())
            .await?;

        Ok(())
    }

    pub async fn discard_wal_changes(&mut self) -> Result<(), Error> {
        if self.status().await?.state() != Some(State::Wal) {
            Err(Error::DbStateError(DbStateError::NotInWalState))?
        }

        sqlx::query!("DELETE FROM vfs;")
            .execute(self.conn())
            .await?;

        sqlx::query!(
            "
            INSERT INTO vfs (id, inode_type, perm_type, entity, name, size, last_modified, parent)
SELECT id, inode_type, 'P', entity, name, size, last_modified, parent
FROM vfs_snapshot;
            "
        )
        .execute(self.conn())
        .await?;

        sqlx::query!("DELETE FROM vfs_snapshot;")
            .execute(self.conn())
            .await?;

        sqlx::query!("DELETE FROM wal;")
            .execute(self.conn())
            .await?;

        sqlx::query!("UPDATE config SET state = 'P';")
            .execute(self.conn())
            .await?;

        self.delete_orphaned_entities().await?;
        clear_temp_tables(self).await?;
        Ok(())
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

    pub async fn new_wal_file(&mut self, metadata: &WalFileMetadata) -> Result<u64, Error> {
        let metadata = Some(serde_sqlite_jsonb::to_vec(metadata).map_err(DataError::JsonbError)?);

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
    ) -> Result<(InodeId, Vec<InodeId>, bool), Error> {
        clear_temp_tables(self).await?;
        let (inode_id, is_new) = if let Some(inode_id) =
            self.inode_id_by_path(path.as_ref()).await?
        {
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
            Ok::<_, Error>((inode_id, false))
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

            Ok((
                InodeId::try_from(insert_vfs_row(&row, self).await?)
                    .map_err(|e| DataError::ConversionError(e.to_string()))?,
                true,
            ))
        }?;

        let affected_inode_ids = collect_affected_inode_ids(self)
            .await?
            .map(|id| {
                InodeId::try_from(id as u64)
                    .map_err(|e| DataError::ConversionError(e.to_string()).into())
            })
            .collect::<Result<Vec<_>, Error>>()?;
        clear_temp_tables(self).await?;

        Ok((inode_id, affected_inode_ids, is_new))
    }
}
