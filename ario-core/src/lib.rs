extern crate core;

use crate::base64::{ToBase64, TryFromBase64, TryFromBase64Error};
use crate::blob::Blob;
use crate::crypto::hash::TypedDigest;
use crate::crypto::hash::{Sha256, Sha384};
use crate::typed::{Typed, WithDisplay, WithSerde};
pub use rsa::BoxedUint as BigUint;
pub use rsa::Error as RsaError;
pub use serde_json::Error as JsonError;
pub use serde_json::Value as JsonValue;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
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
