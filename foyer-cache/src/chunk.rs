use crate::Error;
use ario_client::cache::{Context, L2ChunkCache};
use ario_core::blob::OwnedBlob;
use foyer::{
    AdmitAll, BlockEngineBuilder, Code, CodeError, Compression, DeviceBuilder, FifoPicker,
    FsDeviceBuilder, HybridCache, HybridCacheBuilder, HybridCachePolicy, IoEngineBuilder,
    PsyncIoEngineBuilder, RecoverMode, StorageFilter,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncWrite, AsyncWriteExt};

const CTX_FILE_NAME: &'static str = "_ar_chunk_cache.ctx";
const MAX_CTX_FILE_SIZE: u64 = 1024 * 10;

#[derive(Clone)]
#[repr(transparent)]
struct Chunk(OwnedBlob);

pub struct FoyerChunkCache {
    storage_dir: PathBuf,
    hybrid_cache: HybridCache<u128, Chunk, ahash::RandomState>,
}

impl FoyerChunkCache {
    pub async fn new(max_disk_space: u64, disk_path: impl AsRef<Path>) -> Result<Self, Error> {
        let storage_dir = disk_path.as_ref().to_path_buf();
        let device = FsDeviceBuilder::new(&storage_dir)
            .with_capacity(max_disk_space.min(usize::MAX as u64) as usize)
            .build()
            .map_err(|e| Error::Storage(e.into()))?;

        let hybrid_cache = HybridCacheBuilder::new()
            .with_name("ario_chunk_cache")
            .with_policy(HybridCachePolicy::WriteOnInsertion)
            .memory(1)
            .with_shards(1)
            .with_weighter(|key: &u128, value: &Chunk| size_of::<u128>() + value.0.len())
            .with_hash_builder(ahash::RandomState::with_seeds(
                3442754392483298543,
                2006766938398453135,
                131,
                568402945374598573,
            ))
            .storage()
            .with_io_engine(
                PsyncIoEngineBuilder::new()
                    .build()
                    .await
                    .map_err(|e| Error::Storage(e.into()))?,
            )
            .with_engine_config(
                BlockEngineBuilder::new(device)
                    .with_eviction_pickers(vec![Box::<FifoPicker>::default()])
                    .with_admission_filter(StorageFilter::new().with_condition(AdmitAll))
                    .with_reinsertion_filter(StorageFilter::new().with_condition(AdmitAll))
                    .with_tombstone_log(true),
            )
            .with_recover_mode(RecoverMode::Quiet)
            .with_compression(Compression::None)
            .build()
            .await?;

        Ok(Self {
            storage_dir,
            hybrid_cache,
        })
    }

    async fn init_ctx(&mut self, ctx: &Context) -> Result<bool, std::io::Error> {
        let path = self.storage_dir.join(CTX_FILE_NAME);
        if tokio::fs::try_exists(&path).await? {
            let metadata = tokio::fs::metadata(&path).await?;
            if metadata.len() > MAX_CTX_FILE_SIZE {
                return Err(std::io::Error::other("ctx file exceeds max size"));
            }
            let content = tokio::fs::read(&path).await?;
            if Self::check_ctx_file(&content, ctx) {
                return Ok(true);
            }
            tokio::fs::remove_file(&path).await?;
        }
        let mut file = tokio::fs::File::create_new(&path).await?;
        Self::write_ctx_file(&mut file, &ctx).await?;
        file.flush().await?;
        Ok(false)
    }

    fn check_ctx_file(content: &[u8], ctx: &Context) -> bool {
        ctx.network().id().as_bytes() == content
    }

    async fn write_ctx_file<W: AsyncWrite + Unpin>(
        writer: &mut W,
        ctx: &Context,
    ) -> Result<(), std::io::Error> {
        writer.write_all(ctx.network().id().as_bytes()).await
    }
}

impl L2ChunkCache for FoyerChunkCache {
    async fn init(&mut self, ctx: &Context) -> Result<(), std::io::Error> {
        // make sure this cache is suitable / compatible for the provided ctx
        if !self.init_ctx(ctx).await? {
            // not compatible, clear cached entries
            self.hybrid_cache
                .clear()
                .await
                .map_err(|e| std::io::Error::other(e))?;
        }
        Ok(())
    }

    async fn get_chunk_by_offset(
        &self,
        offset: &u128,
    ) -> Result<Option<OwnedBlob>, std::io::Error> {
        Ok(self
            .hybrid_cache
            .get(offset)
            .await
            .map_err(|e| std::io::Error::other(e))?
            .map(|e| e.0.clone()))
    }

    async fn insert_chunk_with_offset(
        &self,
        offset: u128,
        value: OwnedBlob,
    ) -> Result<(), std::io::Error> {
        let _ = self.hybrid_cache.insert(offset, Chunk(value));
        Ok(())
    }

    async fn invalidate_many<'a>(
        &self,
        iter: impl Iterator<Item = &'a u128> + Send,
    ) -> Result<(), std::io::Error> {
        iter.for_each(|key| self.hybrid_cache.remove(key));
        Ok(())
    }
}

impl Code for Chunk {
    fn encode(&self, writer: &mut impl Write) -> Result<(), CodeError> {
        self.0.len().encode(writer)?;
        writer.write_all(self.0.bytes()).map_err(CodeError::from)
    }

    fn decode(reader: &mut impl Read) -> Result<Self, CodeError>
    where
        Self: Sized,
    {
        Ok(Chunk(OwnedBlob::from(Vec::<u8>::decode(reader)?)))
    }

    fn estimated_size(&self) -> usize {
        self.0.len()
    }
}
