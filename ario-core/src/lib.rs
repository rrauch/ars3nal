extern crate core;

pub use maybe_owned::MaybeOwned;
pub use rsa::BoxedUint as BigUint;
pub use rsa::Error as RsaError;
pub use serde_json::Error as JsonError;
pub use serde_json::Value as JsonValue;

use crate::base64::{ToBase64, TryFromBase64, TryFromBase64Error};
use crate::blob::Blob;
use crate::bundle::{BundleItem, BundleItemId};
use crate::crypto::hash::TypedDigest;
use crate::crypto::hash::{Sha256, Sha384};
use crate::tag::Tag;
use crate::tx::{Tx, TxId};
use crate::typed::{Typed, WithDisplay, WithSerde};
use crate::wallet::WalletAddress;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error;
use url::Url;

pub mod tx;

pub mod base64;
pub mod blob;
pub mod buffer;
pub mod bundle;
pub mod chunking;
pub mod confidential;
pub mod crypto;
pub mod data;
mod entity;
mod json;
pub mod jwk;
pub mod money;
pub mod network;
pub mod tag;
pub mod typed;
mod validation;
pub mod wallet;

pub struct AddressKind<T>(PhantomData<T>);
pub type Address<T> = TypedDigest<AddressKind<T>, Sha256>;

pub struct BlockKind;
pub type BlockNumber = Typed<BlockKind, u64>;
impl WithSerde for BlockNumber {}
impl WithDisplay for BlockNumber {}

impl BlockNumber {
    pub fn from_inner(number: u64) -> Self {
        Self::new_from_inner(number)
    }
}

impl Copy for BlockNumber {}

pub type BlockId = TypedDigest<BlockKind, Sha384>;

impl Display for BlockId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_base64().as_str())
    }
}

#[derive(Error, Debug)]
pub enum BlockIdError {
    #[error(transparent)]
    Base64Error(#[from] TryFromBase64Error<Infallible>),
    #[error(transparent)]
    BlobError(#[from] blob::Error),
}

impl FromStr for BlockId {
    type Err = BlockIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Blob::try_from_base64(s.as_bytes())?;
        Ok(BlockId::try_from(bytes)?)
    }
}

pub struct GatewayKind;
pub type Gateway = Typed<GatewayKind, Url>;
impl WithDisplay for Gateway {}

impl FromStr for Gateway {
    type Err = GatewayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s)?.try_into()
    }
}

impl TryFrom<Url> for Gateway {
    type Error = GatewayError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        if url.cannot_be_a_base() || !url.has_host() || !["http", "https"].contains(&url.scheme()) {
            return Err(GatewayError::UnsupportedUrl(url.to_string()));
        }
        Ok(Gateway::new_from_inner(url))
    }
}

impl Default for Gateway {
    fn default() -> Self {
        Gateway::new_from_inner(Url::parse("https://arweave.net/").unwrap())
    }
}

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    #[error("unsupported url: '{0}'")]
    UnsupportedUrl(String),
}

pub type AuthenticatedItem<'a> = Item<'a, true>;
pub type UnauthenticatedItem<'a> = Item<'a, false>;

#[derive(Debug, Clone)]
pub enum Item<'a, const AUTHENTICATED: bool> {
    Tx(Tx<'a, AUTHENTICATED>),
    BundleItem(BundleItem<'a, AUTHENTICATED>),
}

impl<'a, const AUTHENTICATED: bool> Item<'a, AUTHENTICATED> {
    #[inline]
    pub fn id(&self) -> ItemId {
        match self {
            Self::Tx(tx) => ItemId::from(tx.id().clone()),
            Self::BundleItem(bundle_item) => ItemId::from(bundle_item.id().clone()),
        }
    }

    #[inline]
    pub fn tags(&self) -> &Vec<Tag<'a>> {
        match self {
            Self::Tx(tx) => tx.tags(),
            Self::BundleItem(item) => item.tags(),
        }
    }

    #[inline]
    pub fn owner(&self) -> WalletAddress {
        match self {
            Self::Tx(tx) => tx.owner().address(),
            Self::BundleItem(item) => item.owner().address(),
        }
    }

    #[inline]
    pub fn into_owned(self) -> Item<'static, AUTHENTICATED> {
        match self {
            Self::Tx(tx) => Item::Tx(tx.into_owned()),
            Self::BundleItem(item) => Item::BundleItem(item.into_owned()),
        }
    }
}

impl<'a, const AUTHENTICATED: bool> From<Tx<'a, AUTHENTICATED>> for Item<'a, AUTHENTICATED> {
    fn from(value: Tx<'a, AUTHENTICATED>) -> Self {
        Self::Tx(value)
    }
}

impl<'a, const AUTHENTICATED: bool> From<BundleItem<'a, AUTHENTICATED>>
    for Item<'a, AUTHENTICATED>
{
    fn from(value: BundleItem<'a, AUTHENTICATED>) -> Self {
        Self::BundleItem(value)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Serialize, Deserialize)]
pub enum ItemId {
    Tx(TxId),
    BundleItem(BundleItemId),
}

impl ItemId {
    pub fn as_tx(&self) -> Option<&TxId> {
        match self {
            Self::Tx(tx) => Some(tx),
            _ => None,
        }
    }

    pub fn as_bundle_item(&self) -> Option<&BundleItemId> {
        match self {
            Self::BundleItem(bundle_item) => Some(bundle_item),
            _ => None,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Tx(tx) => tx.as_slice(),
            Self::BundleItem(bundle_item) => bundle_item.as_slice(),
        }
    }
}

impl Display for ItemId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tx(tx) => Display::fmt(tx, f),
            Self::BundleItem(bundle_item) => Display::fmt(bundle_item, f),
        }
    }
}

impl From<TxId> for ItemId {
    fn from(value: TxId) -> Self {
        Self::Tx(value.into())
    }
}

impl From<BundleItemId> for ItemId {
    fn from(value: BundleItemId) -> Self {
        Self::BundleItem(value.into())
    }
}
