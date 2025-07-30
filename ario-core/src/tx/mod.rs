mod raw;
mod rsa;
mod v1;
mod v2;

use crate::JsonError;
use crate::base64::ToBase64;
use crate::blob::{AsBlob, Blob, TypedBlob};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher, HasherExt, TypedDigest};
use crate::crypto::hash::{Sha256, Sha384};
use crate::crypto::keys::{PublicKey, SecretKey};
use crate::crypto::rsa::{RsaPss, RsaPublicKey};
use crate::crypto::signature::TypedSignature;
use crate::crypto::{keys, signature};
use crate::money::{CurrencyExt, Money, TypedMoney, Winston};
use crate::tx::raw::{RawTag, RawTxDataError};
use crate::tx::v1::V1TxDataError;
use crate::tx::v2::V2TxDataError;
use crate::typed::{FromInner, Typed};
use crate::wallet::{WalletAddress, WalletKind, WalletPk};
use bigdecimal::BigDecimal;
use mown::Mown;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

pub struct TxKind;
pub struct TxSignatureKind;

pub type TxId = TypedDigest<TxSignatureKind, Sha256>;

impl Display for TxId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_base64().as_str())
    }
}

pub enum Owner<'a> {
    Rsa4096(Mown<'a, WalletPk<RsaPublicKey<4096>>>),
    Rsa2048(Mown<'a, WalletPk<RsaPublicKey<2048>>>),
}

pub enum Signature<'a> {
    Rsa4096(Mown<'a, TxSignature<RsaPss<4096>>>),
    Rsa2048(Mown<'a, TxSignature<RsaPss<2048>>>),
}

pub trait TxSignatureScheme: signature::Scheme {
    type Signer: SecretKey;
    type Verifier: PublicKey;
}

pub type TxSignature<S: TxSignatureScheme> = TypedSignature<TxHash, WalletKind, S>;
//pub type TxHash = TypedDigest<TxKind, Sha384>;
pub enum TxHash {
    DeepHash(Digest<Sha384>),
    Shallow(Digest<Sha256>),
}

impl TxHash {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::DeepHash(h) => h.as_slice(),
            Self::Shallow(h) => h.as_slice(),
        }
    }
}

impl<S: TxSignatureScheme> TxSignature<S> {
    pub fn digest(&self) -> TxId {
        TxId::from_inner(Sha256::digest(self.as_blob()))
    }
}

#[derive(Error, Debug)]
pub enum TxError {
    #[error(transparent)]
    JsonError(#[from] JsonError),
    #[error(transparent)]
    RawDataError(#[from] RawTxDataError),
    #[error(transparent)]
    V1DataError(#[from] V1TxDataError),
    #[error(transparent)]
    V2DataError(#[from] V2TxDataError),
    #[error(transparent)]
    SignatureError(#[from] signature::Error),
    #[error(transparent)]
    Other(anyhow::Error),
}

#[derive(Error, Debug)]
pub enum CommonTxDataError {
    #[error("no owner field found but mandatory")]
    MissingOwner,
    #[error("invalid id: {0}")]
    InvalidId(String),
    #[error("invalid last_tx: {0}")]
    InvalidLastTx(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("invalid quantity: {0}")]
    InvalidQuantity(String),
    #[error("invalid reward: {0}")]
    InvalidReward(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error(transparent)]
    InvalidKey(#[from] keys::KeyError),
    #[error("invalid signature type: {0}")]
    InvalidSignatureType(String),
}

pub(crate) struct CommonData<'a> {
    pub id: TxId,
    pub tags: Vec<Tag<'a>>,
    pub target: Option<WalletAddress>,
    pub quantity: Option<Quantity>,
    pub reward: Reward,
    pub denomination: Option<u32>,
}

impl<'a> CommonData<'a> {
    pub fn try_from_raw(
        raw_id: Blob<'a>,
        raw_tags: Vec<RawTag<'a>>,
        raw_target: Option<Blob<'a>>,
        raw_quantity: Option<BigDecimal>,
        raw_reward: BigDecimal,
        raw_denomination: Option<u32>,
    ) -> Result<Self, CommonTxDataError> {
        let id = TxId::try_from(raw_id).map_err(|e| CommonTxDataError::InvalidId(e.to_string()))?;

        let tags = raw_tags
            .into_iter()
            .map(|t| Tag::from(t))
            .collect::<Vec<_>>();

        let target = raw_target
            .map(WalletAddress::try_from)
            .transpose()
            .map_err(|e| CommonTxDataError::InvalidTarget(e.to_string()))?;

        let quantity = raw_quantity
            .map(|raw| Winston::try_new(raw).and_then(|w| Ok(Quantity::from(w))))
            .transpose()
            .map_err(|e| CommonTxDataError::InvalidQuantity(e.to_string()))?;

        let reward = Reward::from_inner(
            Winston::try_new(raw_reward)
                .map_err(|e| CommonTxDataError::InvalidReward(e.to_string()))?,
        );

        Ok(CommonData {
            id,
            tags,
            target,
            quantity,
            reward,
            denomination: raw_denomination,
        })
    }
}

pub struct TxAnchorKind;
pub type TxAnchor = Typed<TxAnchorKind, [u8; 48]>;

impl Display for TxAnchor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_base64().as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LastTx {
    V1(TxId),
    V2(TxAnchor),
}

impl<'a> TryFrom<Blob<'a>> for LastTx {
    type Error =
        LastTxError<<TxId as TryFrom<Blob<'a>>>::Error, <TxAnchor as TryFrom<Blob<'a>>>::Error>;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        match value.len() {
            32 => Ok(Self::V1(
                TxId::try_from(value).map_err(LastTxError::V1Error)?,
            )),
            48 => Ok(Self::V2(
                TxAnchor::try_from(value).map_err(LastTxError::V2Error)?,
            )),
            invalid => Err(LastTxError::InvalidLength(invalid)),
        }
    }
}

impl Display for LastTx {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1(tx_id) => Display::fmt(tx_id, f),
            Self::V2(tx_anchor) => Display::fmt(tx_anchor, f),
        }
    }
}

impl DeepHashable for LastTx {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        match self {
            Self::V1(tx_id) => tx_id.deep_hash(),
            Self::V2(tx_anchor) => tx_anchor.deep_hash(),
        }
    }
}

impl Hashable for LastTx {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        match self {
            Self::V1(tx_id) => tx_id.feed(hasher),
            Self::V2(tx_anchor) => tx_anchor.feed(hasher),
        }
    }
}

impl AsRef<[u8]> for LastTx {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::V1(tx_id) => tx_id.as_slice(),
            Self::V2(tx_anchor) => tx_anchor.as_slice(),
        }
    }
}

impl AsBlob for LastTx {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::V1(tx_id) => tx_id.as_blob(),
            Self::V2(tx_anchor) => tx_anchor.as_blob(),
        }
    }
}

#[derive(Error, Debug)]
pub enum LastTxError<E1, E2> {
    #[error("last_tx length is invalid, expected either 64 or 43 characters, but found {0}")]
    InvalidLength(usize),
    #[error(transparent)]
    V1Error(E1),
    #[error(transparent)]
    V2Error(E2),
}

#[derive(Debug, Clone, Serialize_repr, Deserialize_repr, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Format {
    V1 = 1,
    V2 = 2,
}

impl Format {
    fn as_u8(&self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }
}

impl Display for Format {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_u8())
    }
}

impl DeepHashable for Format {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::blob(match self {
            Self::V1 => b"1",
            Self::V2 => b"2",
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SignatureType {
    RsaPss,
    EcdsaSecp256k1,
}

impl Default for SignatureType {
    fn default() -> Self {
        Self::RsaPss
    }
}

const RSA_PSS_SIG_TYPE: &'static str = "rsa_pss?";
const ECDSA_SECP256K1_SIG_TYPE: &'static str = "ecdsa_secp256k1?";

impl SignatureType {
    fn as_str(&self) -> &str {
        match self {
            Self::RsaPss => RSA_PSS_SIG_TYPE,
            Self::EcdsaSecp256k1 => ECDSA_SECP256K1_SIG_TYPE,
        }
    }
}

impl Display for SignatureType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SignatureType {
    type Err = CommonTxDataError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            RSA_PSS_SIG_TYPE => Ok(Self::RsaPss),
            ECDSA_SECP256K1_SIG_TYPE => Ok(Self::EcdsaSecp256k1),
            invalid => Err(CommonTxDataError::InvalidSignatureType(invalid.to_string())),
        }
    }
}

impl DeepHashable for SignatureType {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_str().deep_hash()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tag<'a> {
    pub name: TagName<'a>,
    pub value: TagValue<'a>,
}

pub struct TagNameKind;
pub type TagName<'a> = TypedBlob<'a, TagNameKind>;

pub struct TagValueKind;
pub type TagValue<'a> = TypedBlob<'a, TagValueKind>;

impl<'a> From<RawTag<'a>> for Tag<'a> {
    fn from(raw: RawTag<'a>) -> Self {
        Self {
            name: TagName::from_inner(raw.name),
            value: TagValue::from_inner(raw.value),
        }
    }
}

impl DeepHashable for Tag<'_> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::list([self.name.deep_hash(), self.value.deep_hash()])
    }
}

impl Hashable for Tag<'_> {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        self.name.feed(hasher);
        self.value.feed(hasher);
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    TxDataError(#[from] TxDataError),
}

#[derive(Error, Debug)]
pub enum TxDataError {
    #[error(transparent)]
    JsonError(#[from] JsonError),
    #[error("Incorrect last_tx variant found")]
    IncorrectLastTxVariant,
    #[error("Incorrect data length found: expected '{expected}' but found '{actual}'")]
    IncorrectDataLen { actual: u64, expected: u64 },
    #[error("quantity cannot be negative")]
    NegativeQuantity,
    #[error("reward cannot be negative")]
    NegativeReward,
    #[error("quantity is missing but mandatory for this tx")]
    MissingQuantity,
    #[error("target is missing but mandatory for this tx")]
    MissingTarget,
    #[error("tx id does not match the signature")]
    IdSignatureMismatch,
    #[error("tx signature not valid")]
    SignatureError,
}

pub struct EmbeddedDataKind;
pub type EmbeddedData<'a> = TypedBlob<'a, EmbeddedDataKind>;

pub struct TxQuantityKind;
pub type Quantity = TypedMoney<TxQuantityKind, Winston>;

impl Quantity {
    pub(crate) fn from<I: Into<Money<Winston>>>(money: I) -> Self {
        Self::from_inner(money.into())
    }
}

pub struct TxRewardKind;
pub type Reward = TypedMoney<TxRewardKind, Winston>;

impl Reward {
    pub(crate) fn from<I: Into<Money<Winston>>>(money: I) -> Self {
        Self::from_inner(money.into())
    }
}
