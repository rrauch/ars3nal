use crate::graphql::{TxQuery, TxQueryFilterCriteria, TxQueryId, TxQueryItem};
use crate::{Client, RawItemId};
use ario_core::bundle::{BundleItemId, BundleItemIdError, BundleItemKind};
use ario_core::tx::{TxId, TxIdError, TxKind};
use ario_core::{AuthenticatedItem, ItemId};
use derive_where::derive_where;
use futures_lite::StreamExt;
use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::str::FromStr;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ArlError(#[from] ArlError),
    #[error("item not found")]
    NotFound,
    #[error("item is not a bundle item")]
    NotABundleItem,
    #[error("loop detected in item hierarchy")]
    LoopDetected,
    #[error("item_ids do not match, expected '{expected}' but got '{actual}'")]
    ItemMismatch { expected: ItemId, actual: ItemId },
}

#[derive(Error, Debug)]
pub enum ArlError {
    #[error("not a valid ARL: {0}")]
    Invalid(Url),
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    #[error("tx_id is missing")]
    MissingTxId,
    #[error(transparent)]
    TxIdError(#[from] TxIdError),
    #[error(transparent)]
    BundleItemIdError(#[from] BundleItemIdError),
    #[error("incorrect arl type, not of type '{0}'")]
    IncorrectType(String),
}

impl Client {
    pub(crate) async fn item_by_location(
        &self,
        location: &Arl,
    ) -> Result<Option<AuthenticatedItem<'static>>, super::Error> {
        match location {
            Arl::Tx(tx_arl) => Ok(self.tx_by_id(tx_arl.tx_id()).await?.map(|tx| tx.into())),
            Arl::BundleItem(bundle_item) => Ok(self
                .bundle_item(bundle_item)
                .await?
                .map(|bundle_item| bundle_item.into())),
        }
    }

    pub async fn location_by_item_id(&self, item_id: &ItemId) -> Result<Arl, super::Error> {
        let raw_id = item_id.as_raw_id();

        if let Some(cached) = self.0.cache.get_item_location_if_cached(raw_id).await? {
            return Ok(cached);
        }

        let mut components = vec![];
        let mut root: Arl;
        let mut item_id = item_id.clone();

        loop {
            match item_id {
                ItemId::Tx(tx_id) => {
                    root = tx_id.into();
                    break;
                }
                ItemId::BundleItem(bundle_item_id) => {
                    if components.contains(&bundle_item_id) {
                        Err(Error::LoopDetected)?;
                    }
                    let parent = self.lookup_parent(&bundle_item_id).await?;
                    components.push(bundle_item_id);

                    if let Some(cached) = self
                        .0
                        .cache
                        .get_item_location_if_cached(parent.as_raw_id())
                        .await?
                    {
                        root = cached;
                        break;
                    }

                    item_id = parent;
                }
            }
        }

        if !components.is_empty() {
            components.reverse();
            root = root.append(components.drain(..));
        }

        self.0
            .cache
            .insert_item_location(raw_id.clone(), root.clone())
            .await?;

        Ok(root)
    }

    async fn lookup_parent(&self, bundle_item_id: &BundleItemId) -> Result<ItemId, super::Error> {
        let item = self
            .lookup_item(bundle_item_id.clone())
            .await
            .map(|item| match item {
                TxQueryItem::BundleItem(bundle_item) => Ok(bundle_item),
                _ => Err(Error::NotABundleItem),
            })??;

        self.lookup_item(item.bundled_in)
            .await
            .map(|item| item.into_id())
    }

    async fn lookup_item<I>(&self, item_id: I) -> Result<TxQueryItem, super::Error>
    where
        TxQueryId<'static>: From<I>,
    {
        self.query_transactions(
            TxQuery::builder()
                .filter_criteria(TxQueryFilterCriteria::builder().ids([item_id]).build())
                .max_results(NonZeroUsize::new(1).unwrap())
                .build(),
        )
        .try_next()
        .await?
        .ok_or_else(|| Error::NotFound.into())
    }
}

trait ItemIdExt {
    fn as_raw_id(&self) -> &RawItemId;
}

impl ItemIdExt for ItemId {
    fn as_raw_id(&self) -> &RawItemId {
        let bytes = self.as_slice();
        bytes.try_into().expect("bytes to always be 32 bytes")
    }
}

mod sealed {
    pub trait Sealed {}
}
pub trait ArlType: sealed::Sealed + 'static + Send + Sync {}

impl sealed::Sealed for TxKind {}
impl ArlType for TxKind {}

impl sealed::Sealed for BundleItemKind {}
impl ArlType for BundleItemKind {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Arl {
    Tx(TxArl),
    BundleItem(BundleItemArl),
}

impl Display for Arl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tx(tx) => Display::fmt(tx, f),
            Self::BundleItem(item) => Display::fmt(item, f),
        }
    }
}

impl Serialize for Arl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Tx(tx) => tx.serialize(serializer),
            Self::BundleItem(item) => item.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Arl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let url = Url::deserialize(deserializer)?;
        url.try_into().map_err(serde::de::Error::custom)
    }
}

impl FromStr for Arl {
    type Err = ArlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s)?.try_into()
    }
}

impl TryFrom<Url> for Arl {
    type Error = ArlError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        if url
            .path_segments()
            .map(|s| s.into_iter().count())
            .unwrap_or(0)
            > 0
        {
            Ok(Arl::BundleItem(BundleItemArl::try_from(url)?.into()))
        } else {
            Ok(Arl::Tx(TxArl::try_from(url)?.into()))
        }
    }
}

impl Arl {
    #[inline]
    pub fn depth(&self) -> usize {
        match self {
            Self::Tx(inner) => inner.depth(),
            Self::BundleItem(inner) => inner.depth(),
        }
    }

    #[inline]
    pub fn tx_id(&self) -> &TxId {
        match self {
            Self::Tx(inner) => inner.tx_id(),
            Self::BundleItem(inner) => inner.tx_id(),
        }
    }

    #[inline]
    pub fn item_id(&self) -> &ItemId {
        match self {
            Self::Tx(inner) => inner.item_id(),
            Self::BundleItem(inner) => inner.item_id(),
        }
    }

    #[inline]
    pub fn to_url(&self) -> Url {
        match self {
            Self::Tx(inner) => inner.to_url(),
            Self::BundleItem(inner) => inner.to_url(),
        }
    }

    #[inline]
    pub fn parent(&self) -> Option<Arl> {
        match self {
            Self::Tx(_) => None,
            Self::BundleItem(inner) => Some(inner.parent()),
        }
    }

    fn append(self, iter: impl Iterator<Item = BundleItemId>) -> Self {
        match self {
            Self::Tx(tx) => tx.into_bundle_item(iter).into(),
            Self::BundleItem(mut item) => {
                item.append(iter);
                item.into()
            }
        }
    }

    #[inline]
    pub fn as_tx_arl(&self) -> Option<&TxArl> {
        match self {
            Self::Tx(tx) => Some(tx),
            _ => None,
        }
    }

    #[inline]
    pub fn as_bundle_item_arl(&self) -> Option<&BundleItemArl> {
        match self {
            Self::BundleItem(item) => Some(item),
            _ => None,
        }
    }
}

impl From<&Arl> for Arl {
    fn from(value: &Arl) -> Self {
        value.clone()
    }
}

impl From<TxArl> for Arl {
    fn from(value: TxArl) -> Self {
        Self::Tx(value)
    }
}

impl From<&TxArl> for Arl {
    fn from(value: &TxArl) -> Self {
        value.clone().into()
    }
}

impl From<TxId> for Arl {
    fn from(value: TxId) -> Self {
        TxArl::from(value).into()
    }
}

impl From<&TxId> for Arl {
    fn from(value: &TxId) -> Self {
        TxArl::from(value).into()
    }
}

impl From<BundleItemArl> for Arl {
    fn from(value: BundleItemArl) -> Self {
        Self::BundleItem(value)
    }
}

impl From<&BundleItemArl> for Arl {
    fn from(value: &BundleItemArl) -> Self {
        value.clone().into()
    }
}

#[derive_where(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TypedArl<T: ArlType> {
    inner: Vec<ItemId>,
    _phantom: PhantomData<T>,
}

pub type TxArl = TypedArl<TxKind>;
pub type BundleItemArl = TypedArl<BundleItemKind>;

impl<'a, T: ArlType> TypedArl<T> {
    pub fn depth(&self) -> usize {
        self.inner.len() - 1
    }

    pub fn tx_id(&self) -> &TxId {
        self.inner
            .get(0)
            .expect("first item to be present")
            .as_tx()
            .expect("first item to be a tx")
    }

    pub fn item_id(&self) -> &ItemId {
        self.inner.last().unwrap()
    }

    pub fn to_url(&self) -> Url {
        Url::parse(self.to_string().as_str()).expect("url parsing to never fail")
    }
}

impl TxArl {
    fn into_bundle_item(self, iter: impl Iterator<Item = BundleItemId>) -> BundleItemArl {
        let mut this = BundleItemArl::new_from_inner(self.inner);
        this.append(iter);
        this
    }
}

impl BundleItemArl {
    pub fn bundle_item_id(&self) -> &BundleItemId {
        self.inner
            .last()
            .unwrap()
            .as_bundle_item()
            .expect("item to be bundle item")
    }

    pub fn bundle_items(&self) -> impl Iterator<Item = &BundleItemId> {
        self.inner.iter().skip(1).map(|i| {
            i.as_bundle_item()
                .expect("remaining items to be bundle items")
        })
    }

    pub fn parent(&self) -> Arl {
        let items = self.inner[..self.inner.len() - 1]
            .iter()
            .map(|i| i.clone())
            .collect_vec();
        if items.len() == 1 {
            Arl::Tx(TxArl::new_from_inner(items).into())
        } else {
            Arl::BundleItem(BundleItemArl::new_from_inner(items).into())
        }
    }

    fn append(&mut self, iter: impl Iterator<Item = BundleItemId>) {
        self.inner
            .extend(iter.map(|id| ItemId::BundleItem(id.into())))
    }
}

impl<T: ArlType> Display for TypedArl<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ar://")?;
        for (i, id) in self.inner.iter().enumerate() {
            if i > 0 {
                write!(f, "/")?;
            }
            write!(f, "{}", id)?;
        }
        Ok(())
    }
}

impl<T: ArlType> FromStr for TypedArl<T>
where
    TypedArl<T>: TryFrom<Url, Error = ArlError>,
{
    type Err = ArlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::try_from(Url::from_str(s)?)?)
    }
}

impl TryFrom<Url> for TxArl {
    type Error = ArlError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let parts = Self::extract_parts(url)?;
        if parts.len() != 1 {
            Err(ArlError::IncorrectType("tx".to_string()))?;
        }
        Ok(Self::from_parts(parts))
    }
}

impl TryFrom<Arl> for TxArl {
    type Error = ArlError;

    fn try_from(arl: Arl) -> Result<Self, Self::Error> {
        match arl {
            Arl::Tx(tx) => Ok(tx),
            _ => Err(ArlError::IncorrectType("not a tx".to_string())),
        }
    }
}

impl TryFrom<Url> for BundleItemArl {
    type Error = ArlError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let parts = Self::extract_parts(url)?;
        if parts.len() <= 1 {
            Err(ArlError::IncorrectType("bundle_item".to_string()))?;
        }
        Ok(Self::from_parts(parts))
    }
}

impl TryFrom<Arl> for BundleItemArl {
    type Error = ArlError;

    fn try_from(arl: Arl) -> Result<Self, Self::Error> {
        match arl {
            Arl::BundleItem(item) => Ok(item),
            _ => Err(ArlError::IncorrectType("not a bundle_item".to_string())),
        }
    }
}

impl<T: ArlType> TypedArl<T> {
    fn extract_parts(url: Url) -> Result<Vec<ItemId>, ArlError> {
        if !url.scheme().eq_ignore_ascii_case("ar") {
            Err(ArlError::Invalid(url.clone()))?;
        }

        let tx_id = url
            .domain()
            .map(|d| TxId::from_str(d).map_err(ArlError::from))
            .transpose()?
            .map(|tx| ItemId::from(tx))
            .ok_or_else(|| ArlError::MissingTxId)?;

        let mut parts = vec![tx_id];
        parts.extend(
            url.path_segments()
                .map(|s| {
                    s.into_iter()
                        .map(|part| {
                            Ok(ItemId::from(
                                BundleItemId::from_str(part).map_err(ArlError::from)?,
                            ))
                        })
                        .collect::<Result<Vec<ItemId>, ArlError>>()
                })
                .unwrap_or_else(|| Ok(vec![]))?,
        );

        Ok(parts)
    }

    fn from_parts<V: Into<ItemId>, I: IntoIterator<Item = V>>(iter: I) -> Self {
        Self::new_from_inner(iter.into_iter().map(|v| v.into()).collect_vec())
    }
}

impl<T: ArlType> TypedArl<T> {
    fn new_from_inner(inner: Vec<ItemId>) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }
}

impl<T: ArlType> Serialize for TypedArl<T>
where
    TypedArl<T>: Display,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de, T: ArlType> Deserialize<'de> for TypedArl<T>
where
    TypedArl<T>: TryFrom<Url, Error: Display>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        TypedArl::try_from(Url::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl<'a, T: ArlType> From<&'a TypedArl<T>> for TypedArl<T> {
    fn from(value: &'a TypedArl<T>) -> Self {
        value.clone()
    }
}

impl From<TxId> for TxArl {
    fn from(value: TxId) -> Self {
        Self::from_parts([value])
    }
}

impl From<&TxId> for TxArl {
    fn from(value: &TxId) -> Self {
        value.clone().into()
    }
}

impl From<(TxId, BundleItemId)> for BundleItemArl {
    fn from((tx, item): (TxId, BundleItemId)) -> Self {
        Self::from_parts([ItemId::Tx(tx.into()), ItemId::BundleItem(item.into())])
    }
}

impl From<(&TxId, &BundleItemId)> for BundleItemArl {
    fn from((tx_id, bundle_item_id): (&TxId, &BundleItemId)) -> Self {
        (tx_id.clone(), bundle_item_id.clone()).into()
    }
}

impl From<&(TxId, BundleItemId)> for BundleItemArl {
    fn from(value: &(TxId, BundleItemId)) -> Self {
        (value.0.clone(), value.1.clone()).into()
    }
}
