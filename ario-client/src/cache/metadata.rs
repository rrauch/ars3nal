use crate::Cache;
use crate::cache::{Error, HasWeight, InnerCache};
use ario_core::bundle::{Bundle, BundleItemId, BundleItemVerifier, ValidatedBundleItem};
use ario_core::tx::{TxId, ValidatedTx};
use maybe_owned::MaybeOwned;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Deref;

pub(super) type MetadataCache = InnerCache<MetaKey, MetaValue, Box<dyn L2MetaCache + 'static>>;
pub trait L2MetaCache: Send + Sync + Debug {}

impl Cache {
    pub(crate) async fn get_tx_by_id(
        &self,
        tx_id: &TxId,
        f: impl AsyncFnOnce(&TxId) -> Result<Option<ValidatedTx<'static>>, crate::Error>,
    ) -> Result<Option<ValidatedTx<'static>>, crate::Error> {
        let key = TxByIdKey::from(tx_id);
        Ok(self
            .0
            .metadata_cache
            .try_get_value(key, async |key| f(key.deref()).await)
            .await?)
    }

    pub(crate) async fn get_bundle_by_tx_id(
        &self,
        tx_id: &TxId,
        f: impl AsyncFnOnce(&TxId) -> Result<Option<Bundle>, crate::Error>,
    ) -> Result<Option<Bundle>, crate::Error> {
        let key = BundleByTxIdKey::from(tx_id);
        Ok(self
            .0
            .metadata_cache
            .try_get_value(key, async |key| f(key.deref()).await)
            .await?)
    }

    pub(crate) async fn get_bundle_item_by_id_tx(
        &self,
        item_id: &BundleItemId,
        tx_id: &TxId,
        f: impl AsyncFnOnce(
            &BundleItemId,
            &TxId,
        ) -> Result<
            Option<(ValidatedBundleItem<'static>, BundleItemVerifier<'static>)>,
            crate::Error,
        >,
    ) -> Result<Option<(ValidatedBundleItem<'static>, BundleItemVerifier<'static>)>, crate::Error>
    {
        let key = BundleItemByIdTxKey(MaybeOwned::Borrowed(item_id), MaybeOwned::Borrowed(tx_id));
        Ok(self
            .0
            .metadata_cache
            .try_get_value(key, async |key| {
                let item_id = key.0.deref();
                let tx_id = key.1.deref();
                f(item_id, tx_id).await
            })
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
    Tx(ValidatedTx<'static>),
    Bundle(Bundle),
    BundleItem((ValidatedBundleItem<'static>, BundleItemVerifier<'static>)),
}

impl HasWeight for MetaValue {
    fn weigh(&self) -> usize {
        size_of_val(&self)
    }
}

trait Key: PartialEq + Eq + Hash {
    type Value: Value;
}

trait Value: Clone + Send {
    fn into_meta_value(self) -> MetaValue;
    fn try_from_meta_value(value: MetaValue) -> Option<Self>;
}

#[derive(Debug, PartialEq, Eq, Hash)]
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
    type Value = ValidatedTx<'static>;
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

impl Value for ValidatedTx<'static> {
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

#[derive(Debug, PartialEq, Eq, Hash)]
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

#[derive(Debug, PartialEq, Eq, Hash)]
struct BundleItemByIdTxKey<'a>(MaybeOwned<'a, BundleItemId>, MaybeOwned<'a, TxId>);

impl<'a> BundleItemByIdTxKey<'a> {
    fn to_owned(&self) -> BundleItemByIdTxKey<'static> {
        BundleItemByIdTxKey(
            MaybeOwned::Owned(self.0.to_owned().into_owned()),
            MaybeOwned::Owned(self.1.to_owned().into_owned()),
        )
    }
}

impl Key for BundleItemByIdTxKey<'_> {
    type Value = (ValidatedBundleItem<'static>, BundleItemVerifier<'static>);
}

impl<'a> From<BundleItemByIdTxKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn from(value: BundleItemByIdTxKey<'a>) -> Self {
        Self::BundleItemByIdTx(value)
    }
}

impl<'a> MaybeAsRef<BundleItemByIdTxKey<'a>> for MaybeOwnedMetaKey<'a> {
    fn maybe_as_ref(&self) -> Option<&BundleItemByIdTxKey<'a>> {
        match self {
            MaybeOwnedMetaKey::BundleItemByIdTx(bundle_item_by_id_tx) => Some(bundle_item_by_id_tx),
            _ => None,
        }
    }
}

impl Value for (ValidatedBundleItem<'static>, BundleItemVerifier<'static>) {
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
    BundleByTxId(BundleByTxIdKey<'a>),
    BundleItemByIdTx(BundleItemByIdTxKey<'a>),
}

trait MaybeAsRef<T: Sized> {
    fn maybe_as_ref(&self) -> Option<&T>;
}

impl MetadataCache {
    async fn try_get_value<'a, T: Key>(
        &self,
        key: T,
        f: impl AsyncFnOnce(&T) -> Result<Option<T::Value>, crate::Error>,
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
                //todo: check l2 here
                let key = key.maybe_as_ref().expect("key should always match");
                Ok(f(key).await?.map(|v| v.into_meta_value()))
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
