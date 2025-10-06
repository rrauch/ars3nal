use crate::graphql::{TxQuery, TxQueryFilterCriteria, TxQueryId, TxQueryItem};
use crate::{Client, ItemId};
use ario_core::bundle::{BundleId, BundleItemId, BundleItemIdError};
use ario_core::tx::{TxId, TxIdError};
use derive_where::derive_where;
use futures_lite::StreamExt;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::ops::Deref;
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
}

#[derive(Error, Debug)]
pub enum ArlError {
    #[error("not a valid ARL: {0}")]
    Invalid(Url),
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    #[error("domain is missing")]
    MissingDomain,
    #[error("unsupported domain: '{0}'")]
    UnsupportedDomain(String),
    #[error(transparent)]
    ItemArlError(#[from] ItemArlError),
}

#[derive(Error, Debug)]
pub enum ItemArlError {
    #[error("not an item arl: {0}")]
    NotItemArl(Url),
    #[error(transparent)]
    TxIdError(#[from] TxIdError),
    #[error(transparent)]
    BundleItemIdError(#[from] BundleItemIdError),
}

impl Client {
    pub async fn location_by_item_id(&self, item_id: &ItemId<'_>) -> Result<ItemArl, super::Error> {
        let bytes_id = item_id.as_byte_array();

        if let Some(cached) = self.0.cache.get_item_location_if_cached(bytes_id).await? {
            return Ok(cached);
        }

        let mut components = vec![];
        let mut root: ItemArl;
        let mut item_id = item_id.clone().into_owned();

        loop {
            match item_id {
                ItemId::Tx(tx_id) => {
                    root = tx_id.into_owned().into();
                    break;
                }
                ItemId::BundleItem(bundle_item_id) => {
                    if components.contains(bundle_item_id.deref()) {
                        Err(Error::LoopDetected)?;
                    }
                    let parent = self.lookup_parent(&bundle_item_id).await?;
                    components.push(bundle_item_id.into_owned());

                    if let Some(cached) = self
                        .0
                        .cache
                        .get_item_location_if_cached(parent.as_byte_array())
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
            root.append(components.drain(..));
        }

        self.0
            .cache
            .insert_item_location(bytes_id.clone(), root.clone())
            .await?;

        Ok(root)
    }

    async fn lookup_parent(
        &self,
        bundle_item_id: &BundleItemId,
    ) -> Result<ItemId<'static>, super::Error> {
        let item = self
            .lookup_item(bundle_item_id)
            .await
            .map(|item| match item {
                TxQueryItem::BundleItem(bundle_item) => Ok(bundle_item),
                _ => Err(Error::NotABundleItem),
            })??;

        self.lookup_item(&item.bundled_in)
            .await
            .map(|item| item.into_id())
    }

    async fn lookup_item<'a, I>(&self, item_id: &'a I) -> Result<TxQueryItem, super::Error>
    where
        TxQueryId<'a>: From<&'a I>,
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

#[derive(Debug, Clone)]
pub enum Arl {
    Item(ItemArl),
}

impl Arl {
    pub fn to_url(&self) -> Url {
        match self {
            Self::Item(item) => item.to_url(),
        }
    }
}

impl From<ItemArl> for Arl {
    fn from(value: ItemArl) -> Self {
        Self::Item(value)
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

impl TryFrom<Url> for Arl {
    type Error = ArlError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        if !url.scheme().eq_ignore_ascii_case("ar") {
            Err(ArlError::Invalid(url.clone()))?;
        }

        let domain = url.domain().ok_or(ArlError::MissingDomain)?;

        match domain {
            <ItemArlType as ArlType>::ID => Ok(Self::from(ItemArl::try_from(url)?)),
            unsupported => Err(ArlError::UnsupportedDomain(unsupported.to_string())),
        }
    }
}

impl Display for Arl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Item(item) => Display::fmt(item, f),
        }
    }
}

pub trait ArlType {
    const ID: &'static str;
    type Value: Debug + Clone;
}

#[derive_where(Debug, Clone)]
#[repr(transparent)]
pub struct TypedArl<T: ArlType> {
    inner: T::Value,
    _phantom: PhantomData<T>,
}

impl<T: ArlType> TypedArl<T> {
    fn new_from_inner(inner: T::Value) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }
}

pub struct ItemArlType;
impl ArlType for ItemArlType {
    const ID: &'static str = "item";
    type Value = Vec<ItemId<'static>>;
}

pub type ItemArl = TypedArl<ItemArlType>;

impl Serialize for ItemArl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for ItemArl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor<'de>(PhantomData<&'de ()>);

        impl StringVisitor<'_> {
            fn from_str<E, S: AsRef<str>>(value: S) -> Result<ItemArl, E>
            where
                E: serde::de::Error,
            {
                ItemArl::from_str(value.as_ref()).map_err(serde::de::Error::custom)
            }
        }
        impl<'de> Visitor<'de> for StringVisitor<'de> {
            type Value = ItemArl;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                write!(formatter, "a string value")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Self::from_str(v)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Self::from_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Self::from_str(&v)
            }
        }

        deserializer.deserialize_str(StringVisitor(PhantomData))
    }
}

impl TryFrom<Url> for ItemArl {
    type Error = ArlError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        if !url.scheme().eq_ignore_ascii_case("ar") {
            Err(ArlError::Invalid(url.clone()))?;
        }

        if !url
            .domain()
            .ok_or(ArlError::MissingDomain)?
            .eq_ignore_ascii_case(<ItemArlType as ArlType>::ID)
        {
            Err(ItemArlError::NotItemArl(url.clone()))?;
        }

        let path = url.path().trim_matches('/');

        let parts = path
            .split("/")
            .into_iter()
            .enumerate()
            .map(|(n, part)| {
                Ok(if n == 0 {
                    // tx
                    ItemId::Tx(TxId::from_str(part).map_err(ItemArlError::from)?.into())
                } else {
                    // bundle_item
                    ItemId::BundleItem(
                        BundleItemId::from_str(part)
                            .map_err(ItemArlError::from)?
                            .into(),
                    )
                })
            })
            .collect::<Result<Vec<ItemId<'static>>, ArlError>>()?;

        if parts.is_empty() {
            Err(ArlError::Invalid(url))?;
        }
        Ok(Self::new_from_inner(parts))
    }
}
impl ItemArl {
    pub fn depth(&self) -> usize {
        self.inner.len() - 1
    }

    pub fn tx(&self) -> &TxId {
        self.inner
            .get(0)
            .expect("first item to be present")
            .as_tx()
            .expect("first item to be a tx")
    }

    pub fn bundle_items(&self) -> impl Iterator<Item = &BundleItemId> {
        self.inner.iter().skip(1).map(|i| {
            i.as_bundle_item()
                .expect("remaining items to be bundle items")
        })
    }

    pub fn to_url(&self) -> Url {
        Url::parse(self.to_string().as_str()).expect("url parsing to never fail")
    }

    fn append(&mut self, iter: impl Iterator<Item = BundleItemId>) {
        self.inner
            .extend(iter.map(|id| ItemId::BundleItem(id.into())))
    }
}

impl Display for ItemArl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ar://item/")?;
        for (i, id) in self.inner.iter().enumerate() {
            if i > 0 {
                write!(f, "/")?;
            }
            write!(f, "{}", id)?;
        }
        Ok(())
    }
}

impl From<TxId> for ItemArl {
    fn from(value: TxId) -> Self {
        Self::new_from_inner(vec![ItemId::Tx(value.into())])
    }
}

impl From<(BundleId, BundleItemId)> for ItemArl {
    fn from((tx_id, item_id): (BundleId, BundleItemId)) -> Self {
        Self::new_from_inner(vec![
            ItemId::Tx(tx_id.into()),
            ItemId::BundleItem(item_id.into()),
        ])
    }
}
