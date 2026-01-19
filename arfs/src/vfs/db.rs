use crate::db::{
    DataError, DbEntity, Error, Read, Transaction, TxScope, Write, clear_temp_tables,
    collect_affected_inode_ids, get_entity,
};
use crate::types::file::{FileEntity, FileKind};
use crate::types::folder::{FolderEntity, FolderKind};
use crate::types::{ArfsEntity, HasName, Model};
use crate::vfs::ROOT_INODE_ID;
use crate::wal::{WalDirMetadata, WalFileMetadata};
use crate::{Directory, File, Inode, InodeId, Name, Timestamp, VfsPath};
use ario_client::ByteSize;
use chrono::Utc;
use futures_lite::StreamExt;
use std::borrow::Cow;
use std::ops::Deref;
use std::str::FromStr;

impl<C: TxScope> Transaction<C>
where
    Self: Read,
{
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
}

impl<C: TxScope> Transaction<C>
where
    Self: Write,
{
    pub async fn delete_inodes(
        &mut self,
        inode_ids: impl Iterator<Item = InodeId>,
        recursive_delete: bool,
    ) -> Result<Vec<InodeId>, Error> {
        clear_temp_tables(self).await?;
        for inode_id in inode_ids {
            let now = Utc::now();
            self.wal_delete(inode_id, &now).await?;
            self.delete_inode(inode_id, recursive_delete).await?;
        }
        self.delete_orphaned_entities().await?;

        let affected_inode_ids = collect_affected_inode_ids(self).await?;

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

async fn inode_ids_without_parent<C: Read>(tx: &mut C) -> Result<impl Iterator<Item = i64>, Error> {
    Ok(
        sqlx::query!("SELECT id FROM vfs WHERE parent IS NULL ORDER BY name",)
            .fetch_all(tx.as_mut())
            .await?
            .into_iter()
            .map(|r| r.id),
    )
}

async fn get_inode<C: Read>(inode_id: i64, tx: &mut C) -> Result<Option<Inode>, Error> {
    let vfs_row = match get_vfs_row(inode_id, tx).await? {
        Some(vfs_row) => vfs_row,
        None => return Ok(None),
    };

    let id = InodeId::try_from(vfs_row.id as u64)
        .map_err(|e| DataError::ConversionError(e.to_string()))?;
    let name = Name::from_str(vfs_row.name.as_ref())
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
                Ok(Some(Inode::File(File::new_permanent(
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
                Ok(Some(Inode::Directory(Directory::new_permanent(
                    id,
                    name,
                    last_modified,
                    path,
                    entity,
                ))))
            }
            other => Err(DataError::NotInodeEntityType(other.to_string()))?,
        },
        "W" => match vfs_row.inode_type.as_ref() {
            <FileKind as DbEntity>::TYPE => {
                let wal_id = vfs_row
                    .wal_entity
                    .ok_or_else(|| DataError::MissingData("wal_entity not set".to_string()))?;

                let jsonb = sqlx::query!(
                    "SELECT metadata from wal_entity WHERE id = ? AND entity_type = 'FI'",
                    wal_id
                )
                .fetch_one(tx.conn())
                .await?
                .metadata;
                let metadata = serde_sqlite_jsonb::from_slice::<WalFileMetadata>(&jsonb)
                    .map_err(|e| DataError::ConversionError(e.to_string()))?;

                Ok(Some(Inode::File(File::new_wal(
                    id,
                    name,
                    ByteSize::b(vfs_row.size as u64),
                    last_modified,
                    path,
                    wal_id as u64,
                    metadata,
                ))))
            }
            <FolderKind as DbEntity>::TYPE => {
                let wal_id = vfs_row
                    .wal_entity
                    .ok_or_else(|| DataError::MissingData("wal_entity not set".to_string()))?;

                let jsonb = sqlx::query!(
                    "SELECT metadata from wal_entity WHERE id = ? AND entity_type = 'FO'",
                    wal_id
                )
                .fetch_one(tx.conn())
                .await?
                .metadata;
                let metadata = serde_sqlite_jsonb::from_slice::<WalDirMetadata>(&jsonb)
                    .map_err(|e| DataError::ConversionError(e.to_string()))?;

                Ok(Some(Inode::Directory(Directory::new_wal(
                    id,
                    name,
                    last_modified,
                    path,
                    metadata,
                ))))
            }
            other => Err(DataError::NotInodeEntityType(other.to_string()))?,
        },
        other => Err(DataError::InvalidPermType(other.to_string()))?,
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

pub(crate) struct VfsRow<'a> {
    pub id: i64,
    pub inode_type: Cow<'a, str>,
    pub perm_type: Cow<'a, str>,
    pub entity: Option<i64>,
    pub wal_entity: Option<i64>,
    pub name: Cow<'a, str>,
    pub size: i64,
    pub last_modified: i64,
    pub parent: Option<i64>,
    pub path: Option<Cow<'a, str>>,
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

pub(crate) async fn insert_vfs_row<C: Write>(row: &VfsRow<'_>, tx: &mut C) -> Result<u64, Error> {
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

pub(crate) async fn insert_arfs_inode<C: Write>(
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

pub(crate) async fn get_vfs_row<C: Read>(
    inode_id: i64,
    tx: &mut C,
) -> Result<Option<VfsRow<'static>>, Error> {
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
