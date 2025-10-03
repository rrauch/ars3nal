mod api;
mod bundle;
pub mod cache;
pub mod chunk;
pub mod data_reader;
mod gateway;
#[cfg(feature = "graphql")]
pub mod graphql;
mod price;
mod routemaster;
pub mod tx;
mod wallet;

pub use crate::cache::Cache;
pub use bytesize::ByteSize;
pub use chrono::{DateTime, Utc};
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;

use crate::api::Api;
use crate::routemaster::{Handle, Routemaster};
use ario_core::bundle::{BundleId, BundleItemId, BundleItemIdError};
use ario_core::network::Network;
use ario_core::tx::{TxId, TxIdError};
use ario_core::{Gateway, MaybeOwned};
use derive_where::derive_where;
use itertools::Itertools;
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone)]
pub struct Client(Arc<Inner>);

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    RoutemasterError(#[from] routemaster::Error),
    #[error(transparent)]
    ApiError(#[from] api::Error),
    #[error(transparent)]
    CacheError(#[from] cache::Error),
    #[error(transparent)]
    TxSubmissionError(#[from] tx::TxSubmissionError),
    #[error(transparent)]
    UploadError(#[from] chunk::UploadError),
    #[error(transparent)]
    DownloadError(#[from] chunk::DownloadError),
    #[error(transparent)]
    DataReaderError(#[from] data_reader::Error),
}

#[bon::bon]
impl Client {
    #[builder(derive(Debug))]
    pub async fn new(
        #[builder(default)] network: Network,
        #[builder(default)] reqwest_client: ReqwestClient,
        #[builder(with = |gws: impl IntoIterator<Item=Gateway>| {
            gws.into_iter().collect::<Vec<_>>()
        })]
        gateways: Vec<Gateway>,
        #[builder(default = 10)] max_simultaneous_gateway_checks: usize,
        #[builder(default = Duration::from_secs(30))] startup_timeout: Duration,
        #[builder(default = Duration::from_secs(5))] regular_timeout: Duration,
        #[builder(default = true)] enable_netwatch: bool,
        #[builder(default = true)] allow_api_retry: bool,
        #[builder(default)] mut cache: Cache,
    ) -> Result<Self, Error> {
        let api = Api::new(reqwest_client, network.clone(), allow_api_retry);
        let routemaster = Routemaster::new(
            api.clone(),
            gateways,
            max_simultaneous_gateway_checks,
            startup_timeout,
            regular_timeout,
            enable_netwatch,
        );

        cache.init(network).await?;

        Ok(Self(Arc::new(Inner {
            api,
            routemaster,
            cache,
        })))
    }

    pub(crate) async fn with_gw<T, E: Into<crate::Error>>(
        &self,
        f: impl AsyncFnOnce(&Gateway) -> Result<T, E>,
    ) -> Result<T, Error> {
        let gw_handle = self.0.routemaster.gateway().await?;
        self.with_existing_gw(&gw_handle, f).await
    }

    pub(crate) async fn with_existing_gw<T, E: Into<crate::Error>>(
        &self,
        gw_handle: &Handle<Gateway>,
        f: impl AsyncFnOnce(&Gateway) -> Result<T, E>,
    ) -> Result<T, Error> {
        let start = SystemTime::now();
        let res = f(&gw_handle).await;
        let duration = SystemTime::now().duration_since(start).unwrap_or_default();
        match res {
            Ok(value) => {
                let _ = gw_handle.submit_success(duration).await;
                Ok(value)
            }
            Err(err) => {
                let _ = gw_handle.submit_error(duration).await;
                Err(err.into())
            }
        }
    }

    pub fn network(&self) -> &Network {
        self.0.api.network()
    }
}

#[derive(Debug)]
struct Inner {
    api: Api,
    routemaster: Routemaster,
    cache: Cache,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ItemId<'a> {
    Tx(MaybeOwned<'a, TxId>),
    BundleItem(MaybeOwned<'a, BundleItemId>),
}

impl<'a> ItemId<'a> {
    pub fn as_tx(&self) -> Option<&TxId> {
        match self {
            Self::Tx(tx) => Some(tx.as_ref()),
            _ => None,
        }
    }

    pub fn as_bundle_item(&self) -> Option<&BundleItemId> {
        match self {
            Self::BundleItem(bundle_item) => Some(bundle_item.as_ref()),
            _ => None,
        }
    }

    pub fn into_owned(self) -> ItemId<'static> {
        match self {
            Self::Tx(tx) => ItemId::Tx(tx.into_owned().into()),
            Self::BundleItem(bundle_item) => ItemId::BundleItem(bundle_item.into_owned().into()),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Tx(tx) => tx.as_slice(),
            Self::BundleItem(bundle_item) => bundle_item.as_slice(),
        }
    }
}

impl<'a> Display for ItemId<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tx(tx) => Display::fmt(tx, f),
            Self::BundleItem(bundle_item) => Display::fmt(bundle_item, f),
        }
    }
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
