use crate::Cache;
use crate::cache::Error::L2Error;
use crate::cache::{Context, Error, HasWeight, InnerCache, L2MetadataCache};
use crate::tx::Offset as TxOffset;
use ario_core::bundle::{
    AuthenticatedBundleItem, Bundle, BundleId, BundleItemAuthenticator, BundleItemId,
    UnauthenticatedBundleItem,
};
use ario_core::tx::{AuthenticatedTx, TxId, UnauthenticatedTx};
use maybe_owned::MaybeOwned;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Deref;

pub(super) type MetadataCache = InnerCache<MetaKey, MetaValue, Box<DynL2MetadataCache<'static>>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offset {
    size: u64,
    offset: u128,
}

impl From<Offset> for TxOffset {
    fn from(value: Offset) -> Self {
        TxOffset {
            size: value.size,
            offset: value.offset,
        }
    }
}

impl From<TxOffset> for Offset {
    fn from(value: TxOffset) -> Self {
        Offset {
            size: value.size,
            offset: value.offset,
        }
    }
}

#[dynosaur::dynosaur(pub(super) DynL2MetadataCache = dyn(box) L2Cache)]
pub trait L2Cache: Send + Sync {
    fn init(&mut self, ctx: &Context) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn get_tx(
        &self,
        id: &TxId,
    ) -> impl Future<Output = Result<Option<UnauthenticatedTx<'static>>, std::io::Error>> + Send;

    fn insert_tx(
        &self,
        tx: UnauthenticatedTx<'static>,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn invalidate_tx(&self, id: &TxId) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn get_tx_offset(
        &self,
        id: &TxId,
    ) -> impl Future<Output = Result<Option<Offset>, std::io::Error>> + Send;

    fn insert_tx_offset(
        &self,
        tx_id: TxId,
        offset: Offset,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn invalidate_tx_offset(
        &self,
        id: &TxId,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn get_bundle(
        &self,
        bundle_id: &BundleId,
    ) -> impl Future<Output = Result<Option<Bundle>, std::io::Error>> + Send;

    fn insert_bundle(
        &self,
        bundle: Bundle,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn invalidate_bundle(
        &self,
        id: &BundleId,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn get_bundle_item(
        &self,
        item_id: &BundleItemId,
        bundle_id: &BundleId,
    ) -> impl Future<
        Output = Result<
            Option<(
                UnauthenticatedBundleItem<'static>,
                BundleItemAuthenticator<'static>,
            )>,
            std::io::Error,
        >,
    > + Send;

    fn insert_bundle_item(
        &self,
        bundle_item: UnauthenticatedBundleItem<'static>,
        verifier: BundleItemAuthenticator<'static>,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn invalidate_bundle_item(
        &self,
        item_id: &BundleItemId,
        bundle_id: &BundleId,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

impl Cache {
    pub(crate) async fn get_tx(
        &self,
        tx_id: &TxId,
        f: impl AsyncFnOnce(&TxId) -> Result<Option<AuthenticatedTx<'static>>, crate::Error>,
    ) -> Result<Option<AuthenticatedTx<'static>>, crate::Error> {
        let key = TxByIdKey::from(tx_id);
        Ok(self
            .metadata_cache
            .try_get_value(
                key,
                async |key| f(key.deref()).await,
                async |key, l2| {
                    Ok(
                        match l2
                            .get_tx(key)
                            .await?
                            .map(|tx| tx.authenticate())
                            .transpose()
                        {
                            Ok(r) => r,
                            Err(_) => {
                                // corrupted cache entry
                                l2.invalidate_tx(tx_id).await?;
                                None
                            }
                        },
                    )
                },
                async |_, value, l2| l2.insert_tx(value.invalidate()).await,
            )
            .await?)
    }

    pub(crate) async fn get_tx_offset(
        &self,
        tx_id: &TxId,
        f: impl AsyncFnOnce(&TxId) -> Result<Option<TxOffset>, crate::Error>,
    ) -> Result<Option<TxOffset>, crate::Error> {
        let key = TxOffsetKey::from(tx_id);
        Ok(self
            .metadata_cache
            .try_get_value(
                key,
                async |key| f(key.deref()).await.map(|v| v.map(|o| o.into())),
                async |key, l2| l2.get_tx_offset(key).await,
                async |key, offset, l2| {
                    l2.insert_tx_offset(key.0.clone().into_owned(), offset.into())
                        .await
                },
            )
            .await?
            .map(|o| o.into()))
    }

    pub(crate) async fn get_bundle(
        &self,
        bundle_id: &BundleId,
        f: impl AsyncFnOnce(&TxId) -> Result<Option<Bundle>, crate::Error>,
    ) -> Result<Option<Bundle>, crate::Error> {
        let key = BundleByTxIdKey::from(bundle_id);
        Ok(self
            .metadata_cache
            .try_get_value(
                key,
                async |key| f(key.deref()).await,
                async |key, l2| l2.get_bundle(key).await,
                async |_, value, l2| l2.insert_bundle(value).await,
            )
            .await?)
    }

    pub(crate) async fn get_bundle_item(
        &self,
        item_id: &BundleItemId,
        bundle_id: &BundleId,
        f: impl AsyncFnOnce(
            &BundleItemId,
            &BundleId,
        ) -> Result<
            Option<(
                AuthenticatedBundleItem<'static>,
                BundleItemAuthenticator<'static>,
            )>,
            crate::Error,
        >,
    ) -> Result<
        Option<(
            AuthenticatedBundleItem<'static>,
            BundleItemAuthenticator<'static>,
        )>,
        crate::Error,
    > {
        let key = BundleItemByIdKey(
            MaybeOwned::Borrowed(item_id),
            MaybeOwned::Borrowed(bundle_id),
        );
        Ok(self
            .metadata_cache
            .try_get_value(
                key,
                async |key| {
                    let item_id = key.0.deref();
                    let bundle_id = key.1.deref();
                    f(item_id, bundle_id).await
                },
                async |key, l2| {
                    let item_id = key.0.deref();
                    let bundle_id = key.1.deref();
                    Ok(
                        match l2
                            .get_bundle_item(item_id, bundle_id)
                            .await?
                            .map(|(item, authenticator)| {
                                item.authenticate().map(|item| (item, authenticator))
                            })
                            .transpose()
                        {
                            Ok(r) => r,
                            Err(_) => {
                                // corrupted / invalid cache entry
                                l2.invalidate_bundle_item(item_id, bundle_id).await?;
                                None
                            }
                        },
                    )
                },
                async |key, value, l2| {
                    let item = value.0;
                    let authenticator = value.1;
                    l2.insert_bundle_item(item.invalidate(), authenticator)
                        .await
                },
            )
            .await?)
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub(super) struct MetaKey(MaybeOwnedMetaKey<'static>);

impl HasWeight for MetaKey {
    fn weigh(&self) -> usize {
        size_of_val(&self)
    }
}

impl<'a> ToOwned for MaybeOwnedMetaKey<'a> {
    type Owned = MetaKey;

    fn to_owned(&self) -> Self::Owned {
        match self {
            Self::TxById(o) => MetaKey(MaybeOwnedMetaKey::TxById(o.to_owned())),
            Self::TxOffset(o) => MetaKey(MaybeOwnedMetaKey::TxOffset(o.to_owned())),
            Self::BundleByTxId(o) => MetaKey(MaybeOwnedMetaKey::BundleByTxId(o.to_owned())),
            Self::BundleItemByIdTx(o) => MetaKey(MaybeOwnedMetaKey::BundleItemByIdTx(o.to_owned())),
        }
    }
}

impl<'a> Borrow<MaybeOwnedMetaKey<'a>> for MetaKey {
    fn borrow(&self) -> &MaybeOwnedMetaKey<'a> {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub(super) enum MetaValue {
    Tx(AuthenticatedTx<'static>),
    TxOffset(Offset),
    Bundle(Bundle),
    BundleItem(
        (
            AuthenticatedBundleItem<'static>,
            BundleItemAuthenticator<'static>,
        ),
    ),
}

impl HasWeight for MetaValue {
    fn weigh(&self) -> usize {
        size_of_val(&self)
    }
}

trait Key: PartialEq + Eq + Hash + Clone {
    type Value: Value;
}

trait Value: Clone + Send {
    fn into_meta_value(self) -> MetaValue;
    fn try_from_meta_value(value: MetaValue) -> Option<Self>;
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[repr(transparent)]
struct KeyWrapper<'a, T, Variant = ()>(MaybeOwned<'a, T>, PhantomData<Variant>);
impl<T, Variant> Deref for KeyWrapper<'_, T, Variant> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, Variant> From<T> for KeyWrapper<'static, T, Variant> {
    fn from(value: T) -> Self {
        KeyWrapper(MaybeOwned::Owned(value), PhantomData)
    }
}

impl<'a, T, Variant> From<&'a T> for KeyWrapper<'a, T, Variant> {
    fn from(value: &'a T) -> Self {
        KeyWrapper(MaybeOwned::Borrowed(value), PhantomData)
    }
}

impl<'a, T: Clone, Variant> KeyWrapper<'a, T, Variant> {
    fn to_owned(&self) -> KeyWrapper<'static, T, Variant> {
        KeyWrapper(MaybeOwned::Owned(self.0.clone().into_owned()), PhantomData)
    }
}

type TxByIdKey<'a> = KeyWrapper<'a, TxId>;
impl Key for TxByIdKey<'_> {
    type Value = AuthenticatedTx<'static>;
}

impl<'a> From<TxByIdKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn from(value: TxByIdKey<'a>) -> Self {
        Self::TxById(value)
    }
}

impl<'a> MaybeAsRef<TxByIdKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn maybe_as_ref(&self) -> Option<&TxByIdKey<'a>> {
        match self {
            MaybeOwnedMetaKey::TxById(tx_by_id) => Some(tx_by_id),
            _ => None,
        }
    }
}

impl Value for AuthenticatedTx<'static> {
    fn into_meta_value(self) -> MetaValue {
        MetaValue::Tx(self)
    }

    fn try_from_meta_value(value: MetaValue) -> Option<Self> {
        match value {
            MetaValue::Tx(tx) => Some(tx),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct TxOffsetVariant;

type TxOffsetKey<'a> = KeyWrapper<'a, TxId, TxOffsetVariant>;
impl Key for TxOffsetKey<'_> {
    type Value = Offset;
}

impl<'a> From<TxOffsetKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn from(value: TxOffsetKey<'a>) -> Self {
        Self::TxOffset(value)
    }
}

impl<'a> MaybeAsRef<TxOffsetKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn maybe_as_ref(&self) -> Option<&TxOffsetKey<'a>> {
        match self {
            MaybeOwnedMetaKey::TxOffset(tx_offset) => Some(tx_offset),
            _ => None,
        }
    }
}

impl Value for Offset {
    fn into_meta_value(self) -> MetaValue {
        MetaValue::TxOffset(self)
    }

    fn try_from_meta_value(value: MetaValue) -> Option<Self> {
        match value {
            MetaValue::TxOffset(offset) => Some(offset),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct BundleByTxIdVariant;

type BundleByTxIdKey<'a> = KeyWrapper<'a, TxId, BundleByTxIdVariant>;
impl Key for BundleByTxIdKey<'_> {
    type Value = Bundle;
}

impl<'a> From<BundleByTxIdKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn from(value: BundleByTxIdKey<'a>) -> Self {
        Self::BundleByTxId(value)
    }
}

impl<'a> MaybeAsRef<BundleByTxIdKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn maybe_as_ref(&self) -> Option<&BundleByTxIdKey<'a>> {
        match self {
            MaybeOwnedMetaKey::BundleByTxId(bundle_by_tx_id) => Some(bundle_by_tx_id),
            _ => None,
        }
    }
}

impl Value for Bundle {
    fn into_meta_value(self) -> MetaValue {
        MetaValue::Bundle(self)
    }

    fn try_from_meta_value(value: MetaValue) -> Option<Self> {
        match value {
            MetaValue::Bundle(bundle) => Some(bundle),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct BundleItemByIdKey<'a>(MaybeOwned<'a, BundleItemId>, MaybeOwned<'a, BundleId>);

impl<'a> BundleItemByIdKey<'a> {
    fn to_owned(&self) -> BundleItemByIdKey<'static> {
        BundleItemByIdKey(
            MaybeOwned::Owned(self.0.to_owned().into_owned()),
            MaybeOwned::Owned(self.1.to_owned().into_owned()),
        )
    }
}

impl Key for BundleItemByIdKey<'_> {
    type Value = (
        AuthenticatedBundleItem<'static>,
        BundleItemAuthenticator<'static>,
    );
}

impl<'a> From<BundleItemByIdKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn from(value: BundleItemByIdKey<'a>) -> Self {
        Self::BundleItemByIdTx(value)
    }
}

impl<'a> MaybeAsRef<BundleItemByIdKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn maybe_as_ref(&self) -> Option<&BundleItemByIdKey<'a>> {
        match self {
            MaybeOwnedMetaKey::BundleItemByIdTx(bundle_item_by_id_tx) => Some(bundle_item_by_id_tx),
            _ => None,
        }
    }
}

impl Value
    for (
        AuthenticatedBundleItem<'static>,
        BundleItemAuthenticator<'static>,
    )
{
    fn into_meta_value(self) -> MetaValue {
        MetaValue::BundleItem(self)
    }

    fn try_from_meta_value(value: MetaValue) -> Option<Self> {
        match value {
            MetaValue::BundleItem(this) => Some(this),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum MaybeOwnedMetaKey<'a> {
    TxById(TxByIdKey<'a>),
    TxOffset(TxOffsetKey<'a>),
    BundleByTxId(BundleByTxIdKey<'a>),
    BundleItemByIdTx(BundleItemByIdKey<'a>),
}

trait MaybeAsRef<T: Sized> {
    fn maybe_as_ref(&self) -> Option<&T>;
}

impl MetadataCache {
    async fn try_get_value<'a, T: Key>(
        &self,
        key: T,
        retrieve: impl AsyncFnOnce(&T) -> Result<Option<T::Value>, crate::Error>,
        l2_get: impl AsyncFnOnce(
            &T,
            &Box<DynL2MetadataCache>,
        ) -> Result<Option<T::Value>, std::io::Error>,
        l2_insert: impl AsyncFnOnce(T, T::Value, &Box<DynL2MetadataCache>) -> Result<(), std::io::Error>,
    ) -> Result<Option<T::Value>, Error>
    where
        MaybeOwnedMetaKey<'a>: From<T>,
        MaybeOwnedMetaKey<'a>: MaybeAsRef<T>,
    {
        let key = MaybeOwnedMetaKey::from(key);
        let mut invalidate = false;
        let res = self
            .l1
            .try_get_with_by_ref(&key, async {
                let key = key.maybe_as_ref().expect("key should always match");
                if let Some(l2) = self.l2.as_ref() {
                    if let Some(value) = l2_get(key, l2).await.map_err(L2Error)? {
                        return Ok(Some(value.into_meta_value()));
                    }
                }
                // not in l2, retrieve
                if let Some(value) = retrieve(key).await? {
                    if let Some(l2) = self.l2.as_ref() {
                        l2_insert(key.clone(), value.clone(), l2)
                            .await
                            .map_err(L2Error)?;
                    }
                    return Ok(Some(value.into_meta_value()));
                }
                Ok(None)
            })
            .await
            .map_err(Error::CachedError)?
            .map(|v| {
                T::Value::try_from_meta_value(v).ok_or_else(|| {
                    invalidate = true;
                    Error::InvalidCachedResponse
                })
            })
            .transpose();
        if invalidate {
            self.l1.invalidate(&key).await;
        }
        res
    }
}
