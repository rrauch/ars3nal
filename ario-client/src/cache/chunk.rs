use crate::Cache;
use crate::cache::{Error, HasWeight, InnerCache};
use ario_core::blob::OwnedBlob;
use std::fmt::Debug;

pub(super) type ChunkCache = InnerCache<u128, OwnedBlob, Box<dyn L2ChunkCache + 'static>>;
pub trait L2ChunkCache: Send + Sync + Debug {}

impl Cache {
    pub(crate) async fn get_chunk_by_offset(
        &self,
        offset: u128,
        f: impl AsyncFnOnce(u128) -> Result<Option<OwnedBlob>, crate::Error>,
    ) -> Result<Option<OwnedBlob>, crate::Error> {
        let chunk_cache = &self.0.chunk_cache;
        Ok(chunk_cache
            .l1
            .try_get_with_by_ref(&offset, async {
                //todo: check l2 here
                let offset = offset.clone();
                f(offset).await
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
