mod chunk;
mod metadata;

use crate::cache::chunk::ChunkCache;
use crate::cache::metadata::MetadataCache;
use bytesize::ByteSize;
use moka::future::Cache as MokaCache;
use moka::future::CacheBuilder as MokaCacheBuilder;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug)]
pub struct Cache(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    metadata_cache: MetadataCache,
    chunk_cache: ChunkCache,
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
}

#[bon::bon]
impl Cache {
    #[builder(derive(Debug))]
    pub fn new(
        #[builder(default = ByteSize::mib(8))] metadata_max_mem: ByteSize,
        #[builder(default = Duration::from_secs(3600 * 24))] metadata_max_ttl: Duration,
        #[builder(default = Duration::from_secs(60))] metadata_max_negative_ttl: Duration,
        #[builder(default = ByteSize::mib(16))] chunk_max_mem: ByteSize,
        #[builder(default = Duration::from_secs(3600 * 24))] chunk_max_ttl: Duration,
        #[builder(default = Duration::from_secs(60))] chunk_max_negative_ttl: Duration,
    ) -> Self {
        let metadata_cache = MetadataCache::new(
            "meta_l1_cache",
            metadata_max_mem,
            metadata_max_ttl,
            metadata_max_negative_ttl,
        );
        let chunk_cache = ChunkCache::new(
            "chunk_l1_cache",
            chunk_max_mem,
            chunk_max_ttl,
            chunk_max_negative_ttl,
        );
        Self(Arc::new(Inner {
            metadata_cache,
            chunk_cache,
        }))
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

#[derive(Debug)]
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
    fn new(name: &str, max_mem: ByteSize, max_ttl: Duration, max_negative_ttl: Duration) -> Self {
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
        Self { l1, l2: None }
    }
}
