use crate::db::{Db, Read, Transaction, TxScope, Write};
use crate::types::file::FileKind;
use crate::types::folder::FolderKind;
use crate::vfs::Variant;
use crate::{ContentType, Inode, InodeId, Timestamp};
use ario_core::blob::{Blob, OwnedBlob};
use ario_core::crypto::hash::Blake3Hash;
use chrono::{DateTime, Utc};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;
use serde_with::{serde_as, skip_serializing_none};
use std::collections::HashMap;
use thiserror::Error;
use tokio_util::bytes::{Buf, BufMut};

pub(crate) mod file_reader;
pub(crate) mod file_writer;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Wal entry for file with id '{0}' not found")]
    FileNotFound(u64),
    #[error("Wal File Content Hash Error: '{0}'")]
    ContentHashError(String),
    #[error("No content chunk found for wal file offset '{0}'")]
    NoChunkForOffset(u64),
    #[error("content not found for content hash '{0}'")]
    ContentNotFound(String),
    #[error("invalid wal node type; expected '{0}', actual '{1}'")]
    InvalidWalNodeType(String, String),
    #[error("invalid file size, expected '{0}', actual: '{1}'")]
    InvalidFileSize(u64, u64),
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum WalNode {
    File(u64, Option<WalFileMetadata>),
    Directory,
}

#[derive(Debug, Copy, Clone, PartialEq, strum::Display)]
enum Op {
    Create,
    Update,
    Delete,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct ContentHash(Blake3Hash);

impl AsRef<[u8]> for ContentHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub(crate) struct WalFileChunks {
    range_map: RangeMap<u64, ContentHash>,
    len: u64,
}

impl WalFileChunks {
    fn try_from_iter(iter: impl Iterator<Item = (usize, Vec<u8>)>) -> Result<Self, crate::Error> {
        let mut len = 0;

        let range_map = iter
            .map(|(chunk_len, hash)| {
                let chunk_len = chunk_len as u64;
                let range = len..(len + chunk_len);
                len += chunk_len;

                Blake3Hash::try_from(Blob::from(hash))
                    .map(|h| (range, ContentHash(h)))
                    .map_err(|e| Error::ContentHashError(e.to_string()).into())
            })
            .collect::<Result<RangeMap<u64, ContentHash>, crate::Error>>()?;

        Ok(Self { range_map, len })
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct WalFileMetadata {
    pub name: String,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub content_type: Option<ContentType>,
    #[serde(flatten)]
    pub extra: HashMap<String, OwnedBlob>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct WalDirMetadata {
    pub name: String,
    pub last_modified: DateTime<Utc>,
}
