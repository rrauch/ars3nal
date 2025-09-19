mod chunk;
mod metadata;

pub use chunk::L2Cache as L2ChunkCache;
pub use metadata::L2Cache as L2MetadataCache;

use crate::cache::chunk::{ChunkCache, DynL2ChunkCache};
use crate::cache::metadata::MetadataCache;
use ario_core::network::Network;
use bytesize::ByteSize;
use moka::future::Cache as MokaCache;
use moka::future::CacheBuilder as MokaCacheBuilder;
use std::fmt::{Debug, Formatter, Write};
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug)]
pub struct Cache {
    metadata_cache: MetadataCache,
    chunk_cache: ChunkCache,
}

#[derive(Debug)]
pub struct Context {
    network: Network,
}

impl Context {
    pub fn network(&self) -> &Network {
        &self.network
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("cached error: {0}")]
    CachedError(Arc<super::Error>),
    #[error("cache returned invalid response. this is most likely a bug")]
    InvalidCachedResponse,
    #[error(transparent)]
    L2Error(#[from] std::io::Error),
}

#[bon::bon]
impl Cache {
    #[builder]
    pub fn new(
        #[builder(default = ByteSize::mib(8))] metadata_max_mem: ByteSize,
        #[builder(default = Duration::from_secs(3600 * 24))] metadata_max_ttl: Duration,
        #[builder(default = Duration::from_secs(60))] metadata_max_negative_ttl: Duration,
        #[builder(default = ByteSize::mib(16))] chunk_max_mem: ByteSize,
        #[builder(default = Duration::from_secs(3600 * 24))] chunk_max_ttl: Duration,
        #[builder(default = Duration::from_secs(60))] chunk_max_negative_ttl: Duration,
        #[builder(with = |l2: impl L2ChunkCache + 'static| DynL2ChunkCache::new_box(l2))]
        chunk_l2_cache: Option<Box<DynL2ChunkCache<'static>>>,
    ) -> Self {
        let metadata_cache = MetadataCache::new(
            "meta_l1_cache",
            metadata_max_mem,
            metadata_max_ttl,
            metadata_max_negative_ttl,
            None,
        );

        let chunk_cache = ChunkCache::new(
            "chunk_l1_cache",
            chunk_max_mem,
            chunk_max_ttl,
            chunk_max_negative_ttl,
            chunk_l2_cache,
        );

        Self {
            metadata_cache,
            chunk_cache,
        }
    }

    pub(crate) async fn init(&mut self, network: Network) -> Result<(), Error> {
        let ctx = Context { network };

        if let Some(l2) = self.chunk_cache.l2.as_mut() {
            l2.init(&ctx).await?;
        }

        Ok(())
    }
}

struct OptionExpiry {
    some_expiration: Duration,
    none_expiration: Duration,
}

impl<K, V> moka::Expiry<K, Option<V>> for OptionExpiry {
    fn expire_after_create(
        &self,
        _key: &K,
        value: &Option<V>,
        _created_at: Instant,
    ) -> Option<Duration> {
        match value {
            Some(_) => Some(self.some_expiration),
            None => Some(self.none_expiration),
        }
    }
}

struct InnerCache<
    K: HasWeight + Eq + Hash + Send + Sync + 'static,
    V: HasWeight + Send + Sync + Clone + 'static,
    L2: Send + Sync + 'static,
> {
    l1: MokaCache<K, Option<V>>,
    l2: Option<L2>,
}

trait HasWeight {
    fn weigh(&self) -> usize;
}

impl<
    K: HasWeight + Eq + Hash + Send + Sync + 'static,
    V: HasWeight + Send + Sync + Clone + 'static,
    L2: Send + Sync,
> InnerCache<K, V, L2>
{
    fn new(
        name: &str,
        max_mem: ByteSize,
        max_ttl: Duration,
        max_negative_ttl: Duration,
        l2: Option<L2>,
    ) -> Self {
        let l1 = MokaCacheBuilder::new(max_mem.0)
            .name(name)
            .weigher(|k: &K, v: &Option<V>| {
                (k.weigh() + v.as_ref().map(|v| v.weigh()).unwrap_or(1)).min(u32::MAX as usize)
                    as u32
            })
            .expire_after(OptionExpiry {
                some_expiration: max_ttl,
                none_expiration: max_negative_ttl,
            })
            .build();
        Self { l1, l2 }
    }
}

impl<
    K: HasWeight + Eq + Hash + Send + Sync + 'static,
    V: HasWeight + Send + Sync + Clone + 'static,
    L2: Send + Sync,
> Debug for InnerCache<K, V, L2>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("InnerCache")
    }
}
