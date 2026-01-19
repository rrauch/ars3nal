use crate::types::file::FileId;
use crate::{ContentType, FolderId};
use ario_client::RawItemId;
use ario_core::blob::{Blob, OwnedBlob};
use ario_core::crypto::hash::Blake3Hash;
use chrono::{DateTime, Utc};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;
use serde_with::{serde_as, skip_serializing_none};
use std::collections::HashMap;
use thiserror::Error;

mod db;
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
    File(u64, WalFileMetadata),
    Directory(WalDirMetadata),
}

#[derive(Debug, Copy, Clone, PartialEq, strum::Display)]
enum Op {
    Create,
    Update,
    Delete,
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
    #[serde_as(as = "DisplayFromStr")]
    pub id: FileId,
    #[serde_as(as = "DisplayFromStr")]
    pub parent: FolderId,
    pub name: String,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub content_type: Option<ContentType>,
    #[serde(flatten)]
    pub extra: HashMap<String, OwnedBlob>,
    #[serde(default)]
    pub existing_data_item_id: Option<RawItemId>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct WalDirMetadata {
    #[serde_as(as = "DisplayFromStr")]
    pub id: FolderId,
    #[serde_as(as = "DisplayFromStr")]
    pub parent: FolderId,
    pub name: String,
    pub last_modified: DateTime<Utc>,
}
