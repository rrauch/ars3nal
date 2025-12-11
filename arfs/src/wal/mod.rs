use ario_core::blob::Blob;
use ario_core::crypto::hash::Blake3Hash;
use rangemap::RangeMap;
use std::ops::Range;
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
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum WalNode {
    File(u64),
    Directory,
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
    fn try_from_iter(
        iter: impl Iterator<Item = (Range<u64>, Vec<u8>)>,
    ) -> Result<Self, crate::Error> {
        let range_map = iter
            .map(|(range, hash)| {
                Blake3Hash::try_from(Blob::from(hash))
                    .map(|h| (range, ContentHash(h)))
                    .map_err(|e| Error::ContentHashError(e.to_string()).into())
            })
            .collect::<Result<RangeMap<u64, ContentHash>, crate::Error>>()?;

        let len = range_map.iter().map(|(r, _)| r.end - r.start).sum();

        Ok(Self { range_map, len })
    }
}
