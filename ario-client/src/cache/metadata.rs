use crate::cache::Error::L2Error;
use crate::cache::{Context, Error, HasWeight, InnerCache, L2MetadataCache};
use crate::location::{Arl, BundleItemArl};
use crate::tx::Offset as TxOffset;
use crate::{Cache, RawItemId};
use ario_core::MaybeOwned;
use ario_core::bundle::{
    AuthenticatedBundleItem, Bundle, BundleItemAuthenticator, UnauthenticatedBundleItem,
};
use ario_core::tx::{AuthenticatedTx, TxId, UnauthenticatedTx};
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
        location: &Arl,
    ) -> impl Future<Output = Result<Option<Bundle>, std::io::Error>> + Send;

    fn insert_bundle(
        &self,
        location: Arl,
        bundle: Bundle,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn invalidate_bundle(
        &self,
        location: &Arl,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn get_bundle_item(
        &self,
        location: &BundleItemArl,
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
        location: BundleItemArl,
        bundle_item: UnauthenticatedBundleItem<'static>,
        authenticator: BundleItemAuthenticator<'static>,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn invalidate_bundle_item(
        &self,
        location: &BundleItemArl,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn get_item_location(
        &self,
        item_id: &RawItemId,
    ) -> impl Future<Output = Result<Option<Arl>, std::io::Error>> + Send;

    fn insert_item_location(
        &self,
        item_id: RawItemId,
        location: Arl,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn invalidate_item_location(
        &self,
        item_id: &RawItemId,
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
        location: &Arl,
        f: impl AsyncFnOnce(&Arl) -> Result<Option<Bundle>, crate::Error>,
    ) -> Result<Option<Bundle>, crate::Error> {
        let key = BundleByLocationKey::from(location);
        Ok(self
            .metadata_cache
            .try_get_value(
                key,
                async |key| f(key.deref()).await,
                async |key, l2| l2.get_bundle(key).await,
                async |key, value, l2| {
                    l2.insert_bundle(key.0.into_owned(), value)
                        .await
                },
            )
            .await?)
    }

    pub(crate) async fn get_bundle_item(
        &self,
        location: &BundleItemArl,
        f: impl AsyncFnOnce(
            &BundleItemArl,
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
        let key = BundleItemByLocationKey::from(location);
        Ok(self
            .metadata_cache
            .try_get_value(
                key,
                async |key| f(key.deref()).await,
                async |key, l2| {
                    let location = key.deref();
                    Ok(
                        match l2
                            .get_bundle_item(location)
                            .await?
                            .map(|(item, authenticator)| {
                                item.authenticate().map(|item| (item, authenticator))
                            })
                            .transpose()
                        {
                            Ok(r) => r,
                            Err(_) => {
                                // corrupted / invalid cache entry
                                l2.invalidate_bundle_item(location).await?;
                                None
                            }
                        },
                    )
                },
                async |key, value, l2| {
                    let location = key.deref().clone();
                    let item = value.0;
                    let authenticator = value.1;
                    l2.insert_bundle_item(location, item.invalidate(), authenticator)
                        .await
                },
            )
            .await?)
    }

    pub(crate) async fn get_item_location_if_cached(
        &self,
        raw_id: &RawItemId,
    ) -> Result<Option<Arl>, crate::Error> {
        let key = ItemLocationByRawIdKey::from(raw_id);
        Ok(self
            .metadata_cache
            .try_get_value(
                key,
                async |_| Ok(None),
                async |key, l2| l2.get_item_location(key).await,
                async |key, value, l2| {
                    l2.insert_item_location(key.0.clone().into_owned(), value)
                        .await
                },
            )
            .await?)
    }

    pub(crate) async fn insert_item_location(
        &self,
        raw_id: RawItemId,
        location: Arl,
    ) -> Result<(), crate::Error> {
        if let Some(l2) = self.metadata_cache.l2.as_ref() {
            self.metadata_cache
                .l1
                .insert(
                    MaybeOwnedMetaKey::from(ItemLocationByRawIdKey::from(raw_id.clone()))
                        .to_owned(),
                    Some(location.clone().into_meta_value()),
                )
                .await;

            l2.insert_item_location(raw_id, location)
                .await
                .map_err(L2Error)?;
            Ok(())
        } else {
            self.metadata_cache
                .l1
                .insert(
                    MaybeOwnedMetaKey::from(ItemLocationByRawIdKey::from(raw_id.clone()))
                        .to_owned(),
                    Some(location.into_meta_value()),
                )
                .await;
            Ok(())
        }
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
            Self::BundleByLocation(o) => MetaKey(MaybeOwnedMetaKey::BundleByLocation(o.to_owned())),
            Self::BundleItemByLocation(o) => {
                MetaKey(MaybeOwnedMetaKey::BundleItemByLocation(o.to_owned()))
            }
            Self::ItemLocationByRawId(o) => {
                MetaKey(MaybeOwnedMetaKey::ItemLocationByRawId(o.to_owned()))
            }
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
    ItemLocation(Arl),
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

impl<T: Clone, Variant> KeyWrapper<'_, T, Variant>
where
    T: 'static,
{
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
struct BundleByLocationVariant;

type BundleByLocationKey<'a> = KeyWrapper<'a, Arl, BundleByLocationVariant>;
impl Key for BundleByLocationKey<'_> {
    type Value = Bundle;
}

impl<'a> From<BundleByLocationKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn from(value: BundleByLocationKey<'a>) -> Self {
        Self::BundleByLocation(value)
    }
}

impl<'a> MaybeAsRef<BundleByLocationKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn maybe_as_ref(&self) -> Option<&BundleByLocationKey<'a>> {
        match self {
            MaybeOwnedMetaKey::BundleByLocation(bundle_by_tx_id) => Some(bundle_by_tx_id),
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
struct BundleItemByLocationVariant;

type BundleItemByLocationKey<'a> = KeyWrapper<'a, BundleItemArl, BundleItemByLocationVariant>;

impl Key for BundleItemByLocationKey<'_> {
    type Value = (
        AuthenticatedBundleItem<'static>,
        BundleItemAuthenticator<'static>,
    );
}

impl<'a> From<BundleItemByLocationKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn from(value: BundleItemByLocationKey<'a>) -> Self {
        Self::BundleItemByLocation(value)
    }
}

impl<'a> MaybeAsRef<BundleItemByLocationKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn maybe_as_ref(&self) -> Option<&BundleItemByLocationKey<'a>> {
        match self {
            MaybeOwnedMetaKey::BundleItemByLocation(bundle_item_by_id_tx) => {
                Some(bundle_item_by_id_tx)
            }
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

type ItemLocationByRawIdKey<'a> = KeyWrapper<'a, RawItemId>;

impl<'a> Key for ItemLocationByRawIdKey<'a> {
    type Value = Arl;
}

impl<'a> From<ItemLocationByRawIdKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn from(value: ItemLocationByRawIdKey<'a>) -> Self {
        Self::ItemLocationByRawId(value)
    }
}

impl<'a> MaybeAsRef<ItemLocationByRawIdKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn maybe_as_ref(&self) -> Option<&ItemLocationByRawIdKey<'a>> {
        match self {
            MaybeOwnedMetaKey::ItemLocationByRawId(inner) => Some(inner),
            _ => None,
        }
    }
}

impl Value for Arl {
    fn into_meta_value(self) -> MetaValue {
        MetaValue::ItemLocation(self)
    }

    fn try_from_meta_value(value: MetaValue) -> Option<Self> {
        match value {
            MetaValue::ItemLocation(inner) => Some(inner),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum MaybeOwnedMetaKey<'a> {
    TxById(TxByIdKey<'a>),
    TxOffset(TxOffsetKey<'a>),
    BundleByLocation(BundleByLocationKey<'a>),
    BundleItemByLocation(BundleItemByLocationKey<'a>),
    ItemLocationByRawId(ItemLocationByRawIdKey<'a>),
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
                // Warning: without the pinned box the async closure can lead to a stack overflow if
                // called recursively!
                if let Some(value) = Box::pin(retrieve(key)).await? {
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
