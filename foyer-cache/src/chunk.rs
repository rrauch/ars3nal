use crate::disk_cache::DiskCache;
use crate::{DEFAULT_MEM_BUF_SIZE, Error};
use ario_client::cache::{Context, L2ChunkCache};
use ario_core::blob::OwnedBlob;
use ario_core::buffer::ByteBuffer;
use ario_core::data::UnauthenticatedTxDataChunk;
use ario_core::tx::TxId;
use bon::bon;
use equivalent::Equivalent;
use foyer::{Code, CodeError};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Clone)]
#[repr(transparent)]
struct Chunk(UnauthenticatedTxDataChunk<'static>);

impl From<UnauthenticatedTxDataChunk<'static>> for Chunk {
    fn from(value: UnauthenticatedTxDataChunk<'static>) -> Self {
        Self(value)
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
struct CacheKey {
    relative_offset: u64,
    tx_id: TxId,
}

impl From<(u64, TxId)> for CacheKey {
    fn from(value: (u64, TxId)) -> Self {
        Self {
            relative_offset: value.0,
            tx_id: value.1,
        }
    }
}

#[derive(Hash)]
struct BorrowedCacheKey<'a> {
    relative_offset: u64,
    tx_id: &'a TxId,
}

impl<'a> From<(u64, &'a TxId)> for BorrowedCacheKey<'a> {
    fn from(value: (u64, &'a TxId)) -> Self {
        Self {
            relative_offset: value.0,
            tx_id: value.1,
        }
    }
}

impl Equivalent<CacheKey> for BorrowedCacheKey<'_> {
    fn equivalent(&self, key: &CacheKey) -> bool {
        self.relative_offset == key.relative_offset && self.tx_id == &key.tx_id
    }
}

#[repr(transparent)]
pub struct FoyerChunkCache(DiskCache<CacheKey, Chunk>);

const CTX_FILE_CONTENT_TYPE: &'static str = "chunk";
const CTX_FILE_COMP_VERSION: usize = 3;

#[bon]
impl FoyerChunkCache {
    #[builder]
    pub async fn new(
        max_disk_space: u64,
        disk_path: impl AsRef<Path>,
        #[builder(default = DEFAULT_MEM_BUF_SIZE)] mem_buf: usize,
    ) -> Result<Self, Error> {
        Ok(Self(
            DiskCache::new(
                "ario_chunk_cache",
                disk_path,
                max_disk_space,
                mem_buf,
                CTX_FILE_CONTENT_TYPE.to_string(),
                CTX_FILE_COMP_VERSION,
            )
            .await?,
        ))
    }
}

impl L2ChunkCache for FoyerChunkCache {
    async fn init(&mut self, ctx: &Context) -> Result<(), std::io::Error> {
        self.0.init(ctx).await.map_err(|e| std::io::Error::other(e))
    }

    async fn get_chunk(
        &self,
        relative_offset: u64,
        tx_id: &TxId,
    ) -> Result<Option<UnauthenticatedTxDataChunk<'static>>, std::io::Error> {
        Ok(self
            .0
            .get(BorrowedCacheKey::from((relative_offset, tx_id)))
            .await?
            .map(|c| c.0))
    }

    async fn insert_chunk(
        &self,
        relative_offset: u64,
        tx_id: TxId,
        value: UnauthenticatedTxDataChunk<'static>,
    ) -> Result<(), std::io::Error> {
        self.0.insert((relative_offset, tx_id), value).await
    }

    async fn invalidate_many<'a>(
        &self,
        iter: impl Iterator<Item = (u64, &'a TxId)> + Send,
    ) -> Result<(), std::io::Error> {
        for key in iter {
            self.0.invalidate(BorrowedCacheKey::from(key)).await?;
        }
        self.0.flush().await;
        Ok(())
    }
}

impl Code for Chunk {
    fn encode(&self, writer: &mut impl Write) -> Result<(), CodeError> {
        let data = self.0.danger_unauthenticated_data();
        data.len().encode(writer)?;
        std::io::copy(&mut data.cursor(), writer).map_err(CodeError::from)?;
        self.0.offset().encode(writer)?;
        Ok(())
    }

    fn decode(reader: &mut impl Read) -> Result<Self, CodeError>
    where
        Self: Sized,
    {
        let chunk = OwnedBlob::from(Vec::<u8>::decode(reader)?);
        let offset = u64::decode(reader)?;

        Ok(UnauthenticatedTxDataChunk::from_byte_buffer(ByteBuffer::from(chunk), offset).into())
    }

    fn estimated_size(&self) -> usize {
        self.0.len() as usize + size_of::<u64>()
    }
}
