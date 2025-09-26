use crate::disk_cache::DiskCache;
use crate::{DEFAULT_MEM_BUF_SIZE, Error};
use ario_client::cache::{Context, L2MetadataCache, Offset};
use ario_core::bundle::{
    Bundle, BundleId, BundleItemAuthenticator, BundleItemId, UnauthenticatedBundleItem,
};
use ario_core::tx::{TxId, UnauthenticatedTx};
use bon::bon;
use equivalent::Equivalent;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::io::Error as IoError;
use std::path::Path;

const CTX_FILE_CONTENT_TYPE: &'static str = "metadata";
const CTX_FILE_COMP_VERSION: usize = 1;

// foyer seems to have problems with types with lifetimes
// so we are using owned types only here
#[derive(PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
enum CacheKey {
    TxId(TxId),
    TxOffset(TxId),
    BundleId(BundleId),
    BundleItem(BundleItemId, BundleId),
}

#[derive(Hash)]
enum BorrowedCacheKey<'a> {
    TxId(&'a TxId),
    TxOffset(&'a TxId),
    BundleId(&'a BundleId),
    BundleItem(&'a BundleItemId, &'a BundleId),
}

impl Equivalent<CacheKey> for BorrowedCacheKey<'_> {
    fn equivalent(&self, key: &CacheKey) -> bool {
        match key {
            CacheKey::TxId(other) => {
                if let Self::TxId(this) = self {
                    *this == other
                } else {
                    false
                }
            }
            CacheKey::TxOffset(other) => {
                if let Self::TxOffset(this) = self {
                    *this == other
                } else {
                    false
                }
            }
            CacheKey::BundleId(other) => {
                if let Self::BundleId(this) = self {
                    *this == other
                } else {
                    false
                }
            }
            CacheKey::BundleItem(other_id, other_bundle) => {
                if let Self::BundleItem(this_id, this_bundle) = self {
                    *this_id == other_id && *this_bundle == other_bundle
                } else {
                    false
                }
            }
        }
    }
}

impl From<(BundleItemId, BundleId)> for CacheKey {
    fn from(value: (BundleItemId, BundleId)) -> Self {
        Self::BundleItem(value.0, value.1)
    }
}

#[derive(Clone, Serialize, Deserialize)]
enum CacheValue {
    Tx(UnauthenticatedTx<'static>),
    TxOffset(Offset),
    Bundle(Bundle),
    BundleItem(
        UnauthenticatedBundleItem<'static>,
        BundleItemAuthenticator<'static>,
    ),
}

impl TryFrom<CacheValue> for UnauthenticatedTx<'static> {
    type Error = ();

    fn try_from(value: CacheValue) -> Result<Self, Self::Error> {
        match value {
            CacheValue::Tx(value) => Ok(value),
            _ => Err(()),
        }
    }
}

impl From<UnauthenticatedTx<'static>> for CacheValue {
    fn from(value: UnauthenticatedTx<'static>) -> Self {
        Self::Tx(value)
    }
}

impl TryFrom<CacheValue> for Offset {
    type Error = ();

    fn try_from(value: CacheValue) -> Result<Self, Self::Error> {
        match value {
            CacheValue::TxOffset(value) => Ok(value),
            _ => Err(()),
        }
    }
}

impl From<Offset> for CacheValue {
    fn from(value: Offset) -> Self {
        Self::TxOffset(value)
    }
}

impl TryFrom<CacheValue> for Bundle {
    type Error = ();

    fn try_from(value: CacheValue) -> Result<Self, Self::Error> {
        match value {
            CacheValue::Bundle(value) => Ok(value),
            _ => Err(()),
        }
    }
}

impl From<Bundle> for CacheValue {
    fn from(value: Bundle) -> Self {
        Self::Bundle(value)
    }
}

impl TryFrom<CacheValue>
    for (
        UnauthenticatedBundleItem<'static>,
        BundleItemAuthenticator<'static>,
    )
{
    type Error = ();

    fn try_from(value: CacheValue) -> Result<Self, Self::Error> {
        match value {
            CacheValue::BundleItem(item, verifier) => Ok((item, verifier)),
            _ => Err(()),
        }
    }
}

impl
    From<(
        UnauthenticatedBundleItem<'static>,
        BundleItemAuthenticator<'static>,
    )> for CacheValue
{
    fn from(
        value: (
            UnauthenticatedBundleItem<'static>,
            BundleItemAuthenticator<'static>,
        ),
    ) -> Self {
        Self::BundleItem(value.0, value.1)
    }
}

pub struct FoyerMetadataCache(DiskCache<CacheKey, CacheValue>);

#[bon]
impl FoyerMetadataCache {
    #[builder]
    pub async fn new(
        max_disk_space: u64,
        disk_path: impl AsRef<Path>,
        #[builder(default = DEFAULT_MEM_BUF_SIZE)] mem_buf: usize,
    ) -> Result<Self, Error> {
        Ok(Self(
            DiskCache::new(
                "ario_metadata_cache",
                disk_path,
                max_disk_space,
                mem_buf,
                CTX_FILE_CONTENT_TYPE.to_string(),
                CTX_FILE_COMP_VERSION,
            )
            .await?,
        ))
    }

    async fn get<T: TryFrom<CacheValue>>(
        &self,
        key: impl Equivalent<CacheKey> + Hash,
    ) -> Result<Option<T>, IoError> {
        self.0
            .get(key)
            .await?
            .map(|e| e.try_into())
            .transpose()
            .map_err(|_| IoError::other("invalid cache entry"))
    }
}

impl L2MetadataCache for FoyerMetadataCache {
    async fn init(&mut self, ctx: &Context) -> Result<(), IoError> {
        self.0.init(ctx).await.map_err(|e| IoError::other(e))
    }

    async fn get_tx(
        &self,
        id: &TxId,
    ) -> Result<Option<UnauthenticatedTx<'static>>, std::io::Error> {
        self.get(BorrowedCacheKey::TxId(id)).await
    }

    async fn insert_tx(&self, tx: UnauthenticatedTx<'static>) -> Result<(), std::io::Error> {
        self.0.insert(CacheKey::TxId(tx.id().clone()), tx).await
    }

    async fn invalidate_tx(&self, id: &TxId) -> Result<(), std::io::Error> {
        self.0.invalidate(BorrowedCacheKey::TxId(id)).await
    }

    async fn get_tx_offset(&self, id: &TxId) -> Result<Option<Offset>, std::io::Error> {
        self.get(BorrowedCacheKey::TxOffset(id)).await
    }

    async fn insert_tx_offset(&self, tx_id: TxId, offset: Offset) -> Result<(), std::io::Error> {
        self.0.insert(CacheKey::TxOffset(tx_id), offset).await
    }

    async fn invalidate_tx_offset(&self, id: &TxId) -> Result<(), std::io::Error> {
        self.0.invalidate(BorrowedCacheKey::TxOffset(id)).await
    }

    async fn get_bundle(&self, bundle_id: &BundleId) -> Result<Option<Bundle>, std::io::Error> {
        self.get(BorrowedCacheKey::BundleId(bundle_id)).await
    }

    async fn insert_bundle(&self, bundle: Bundle) -> Result<(), std::io::Error> {
        self.0
            .insert(CacheKey::BundleId(bundle.id().clone()), bundle)
            .await
    }

    async fn invalidate_bundle(&self, id: &BundleId) -> Result<(), std::io::Error> {
        self.0.invalidate(BorrowedCacheKey::BundleId(id)).await
    }

    async fn get_bundle_item(
        &self,
        item_id: &BundleItemId,
        bundle_id: &BundleId,
    ) -> Result<
        Option<(
            UnauthenticatedBundleItem<'static>,
            BundleItemAuthenticator<'static>,
        )>,
        std::io::Error,
    > {
        self.get(BorrowedCacheKey::BundleItem(item_id, bundle_id))
            .await
    }

    async fn insert_bundle_item(
        &self,
        bundle_item: UnauthenticatedBundleItem<'static>,
        verifier: BundleItemAuthenticator<'static>,
    ) -> Result<(), std::io::Error> {
        self.0
            .insert(
                (bundle_item.id().clone(), bundle_item.bundle_id().clone()),
                (bundle_item, verifier),
            )
            .await
    }

    async fn invalidate_bundle_item(
        &self,
        item_id: &BundleItemId,
        bundle_id: &BundleId,
    ) -> Result<(), std::io::Error> {
        self.0
            .invalidate(BorrowedCacheKey::BundleItem(item_id, bundle_id))
            .await
    }
}
