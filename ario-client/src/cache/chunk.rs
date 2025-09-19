use crate::Cache;
use crate::cache::{Context, Error, HasWeight, InnerCache};
use ario_core::blob::OwnedBlob;
use std::iter;

pub(super) type ChunkCache = InnerCache<u128, OwnedBlob, Box<DynL2ChunkCache<'static>>>;

#[dynosaur::dynosaur(pub(super) DynL2ChunkCache = dyn(box) L2Cache)]
pub trait L2Cache: Send + Sync {
    fn init(&mut self, ctx: &Context) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn get_chunk_by_offset(
        &self,
        offset: &u128,
    ) -> impl Future<Output = Result<Option<OwnedBlob>, std::io::Error>> + Send;
    fn insert_chunk_with_offset(
        &self,
        offset: u128,
        value: OwnedBlob,
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
    pub(crate) async fn get_chunk_by_offset(
        &self,
        offset: u128,
        f: impl AsyncFnOnce(u128) -> Result<Option<OwnedBlob>, crate::Error>,
    ) -> Result<Option<OwnedBlob>, crate::Error> {
        let chunk_cache = &self.chunk_cache;
        Ok(chunk_cache
            .l1
            .try_get_with_by_ref(&offset, async {
                if let Some(l2) = self.chunk_cache.l2.as_ref() {
                    if let Some(chunk) = l2
                        .get_chunk_by_offset(&offset)
                        .await
                        .map_err(Error::L2Error)?
                    {
                        return Ok(Some(chunk));
                    }
                }
                let offset = offset.clone();
                Ok(match f(offset).await? {
                    Some(value) => {
                        if let Some(l2) = self.chunk_cache.l2.as_ref() {
                            l2.insert_chunk_with_offset(offset, value.clone())
                                .await
                                .map_err(Error::L2Error)?;
                        }
                        Some(value)
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

impl HasWeight for OwnedBlob {
    fn weigh(&self) -> usize {
        self.len() + size_of_val(self)
    }
}
