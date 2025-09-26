use crate::Cache;
use crate::cache::{Context, Error, HasWeight, InnerCache};
use crate::chunk::{RawTxDownloadChunk, UnauthenticatedTxDownloadChunk, AuthenticatedTxDownloadChunk};
use ario_core::data::{DataRoot, TxDataChunk, AuthenticatedTxDataChunk};
use std::iter;

pub(super) type ChunkCache =
    InnerCache<u128, AuthenticatedTxDataChunk<'static>, Box<DynL2ChunkCache<'static>>>;

#[dynosaur::dynosaur(pub(super) DynL2ChunkCache = dyn(box) L2Cache)]
pub trait L2Cache: Send + Sync {
    fn init(&mut self, ctx: &Context) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn get_chunk(
        &self,
        offset: &u128,
    ) -> impl Future<Output = Result<Option<RawTxDownloadChunk<'static>>, std::io::Error>> + Send;
    fn insert_chunk(
        &self,
        offset: u128,
        value: RawTxDownloadChunk<'static>,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn invalidate(&self, offset: &u128) -> impl Future<Output = Result<(), std::io::Error>> + Send {
        self.invalidate_many(iter::once(offset))
    }
    fn invalidate_many<'a>(
        &self,
        iter: impl Iterator<Item = &'a u128> + Send,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

impl Cache {
    pub(crate) async fn get_chunk(
        &self,
        offset: u128,
        data_root: &DataRoot,
        relative_offset: u64,
        f: impl AsyncFnOnce(u128) -> Result<Option<AuthenticatedTxDownloadChunk<'static>>, crate::Error>,
    ) -> Result<Option<AuthenticatedTxDataChunk<'static>>, crate::Error> {
        let chunk_cache = &self.chunk_cache;
        Ok(chunk_cache
            .l1
            .try_get_with_by_ref(&offset, async {
                if let Some(l2) = self.chunk_cache.l2.as_ref() {
                    if let Some(raw) = l2.get_chunk(&offset).await.map_err(Error::L2Error)? {
                        if let Ok(validated) = UnauthenticatedTxDownloadChunk::from(raw)
                            .authenticate(data_root, relative_offset)
                        {
                            return Ok(Some(validated.chunk));
                        }
                        // entry is invalid
                        l2.invalidate(&offset).await.map_err(Error::L2Error)?;
                    }
                }
                let offset = offset.clone();
                Ok(match f(offset).await? {
                    Some(value) => {
                        if let Some(l2) = self.chunk_cache.l2.as_ref() {
                            l2.insert_chunk(offset, value.clone().into())
                                .await
                                .map_err(Error::L2Error)?;
                        }
                        Some(value.chunk)
                    }
                    None => None,
                })
            })
            .await
            .map_err(Error::CachedError)?)
    }
}

impl HasWeight for u128 {
    fn weigh(&self) -> usize {
        size_of::<Self>()
    }
}

impl<'a, const VALIDATED: bool> HasWeight for TxDataChunk<'a, VALIDATED> {
    fn weigh(&self) -> usize {
        self.len() + size_of_val(self)
    }
}
