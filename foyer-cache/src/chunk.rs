use crate::disk_cache::DiskCache;
use crate::{DEFAULT_MEM_BUF_SIZE, Error};
use ario_client::cache::{Context, L2ChunkCache};
use ario_client::chunk::RawTxDownloadChunk;
use ario_core::blob::OwnedBlob;
use bon::bon;
use foyer::{Code, CodeError};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Clone)]
#[repr(transparent)]
struct Chunk(RawTxDownloadChunk<'static>);

#[repr(transparent)]
pub struct FoyerChunkCache(DiskCache<u128, Chunk>);

const CTX_FILE_CONTENT_TYPE: &'static str = "chunk";
const CTX_FILE_COMP_VERSION: usize = 1;

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
        offset: &u128,
    ) -> Result<Option<RawTxDownloadChunk<'static>>, std::io::Error> {
        Ok(self.0.get(*offset).await?.map(|e| e.0))
    }

    async fn insert_chunk(
        &self,
        offset: u128,
        value: RawTxDownloadChunk<'static>,
    ) -> Result<(), std::io::Error> {
        self.0.insert(offset, Chunk(value)).await
    }

    async fn invalidate_many<'a>(
        &self,
        iter: impl Iterator<Item = &'a u128> + Send,
    ) -> Result<(), std::io::Error> {
        for key in iter {
            self.0.invalidate(*key).await?;
        }
        self.0.flush().await;
        Ok(())
    }
}

impl Code for Chunk {
    fn encode(&self, writer: &mut impl Write) -> Result<(), CodeError> {
        self.0.chunk.len().encode(writer)?;
        writer
            .write_all(self.0.chunk.bytes())
            .map_err(CodeError::from)?;
        self.0.data_path.len().encode(writer)?;
        writer
            .write_all(self.0.data_path.bytes())
            .map_err(CodeError::from)?;
        if let Some(tx_path) = self.0.tx_path.as_ref() {
            tx_path.len().encode(writer)?;
            writer.write_all(tx_path.bytes()).map_err(CodeError::from)?;
        } else {
            0usize.encode(writer)?;
        }
        Ok(())
    }

    fn decode(reader: &mut impl Read) -> Result<Self, CodeError>
    where
        Self: Sized,
    {
        let chunk = OwnedBlob::from(Vec::<u8>::decode(reader)?);
        let data_path = OwnedBlob::from(Vec::<u8>::decode(reader)?);
        let tx_path = OwnedBlob::from(Vec::<u8>::decode(reader)?);
        let tx_path = if tx_path.is_empty() {
            None
        } else {
            Some(tx_path)
        };

        Ok(Chunk(RawTxDownloadChunk {
            chunk,
            data_path,
            tx_path,
        }))
    }

    fn estimated_size(&self) -> usize {
        size_of::<usize>()
            + self.0.chunk.len()
            + size_of::<usize>()
            + self.0.data_path.len()
            + size_of::<usize>()
            + self.0.tx_path.as_ref().map(|b| b.len()).unwrap_or(0)
    }
}
