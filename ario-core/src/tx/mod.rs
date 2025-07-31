mod raw;
mod rsa;
mod v1;
mod v2;

use crate::base64::ToBase64;
use crate::blob::{AsBlob, Blob, TypedBlob};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher, HasherExt, TypedDigest};
use crate::crypto::hash::{Sha256, Sha384};
use crate::crypto::keys::{PublicKey, SecretKey};
use crate::crypto::rsa::{RsaPss, RsaPublicKey};
use crate::crypto::signature::TypedSignature;
use crate::crypto::{keys, signature};
use crate::json::JsonSource;
use crate::money::{CurrencyExt, Money, TypedMoney, Winston};
use crate::tx::raw::{RawTag, RawTx, RawTxDataError, UnvalidatedRawTx, ValidatedRawTx};
use crate::tx::v1::{UnvalidatedV1Tx, V1Tx, V1TxDataError};
use crate::tx::v2::{UnvalidatedV2Tx, V2Tx, V2TxDataError};
use crate::typed::{FromInner, Typed};
use crate::validation::ValidateExt;
use crate::wallet::{WalletAddress, WalletKind, WalletPk};
use crate::{JsonError, JsonValue};
use bigdecimal::BigDecimal;
use mown::Mown;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
#[repr(transparent)]
pub struct Tx<'a, const VALIDATED: bool = false>(TxInner<'a, VALIDATED>);

#[derive(Debug, Clone, PartialEq)]
enum TxInner<'a, const VALIDATED: bool> {
    V1(V1Tx<'a, VALIDATED>),
    V2(V2Tx<'a, VALIDATED>),
}

impl<'a, const VALIDATED: bool> TxInner<'a, VALIDATED> {
    fn into_owned(self) -> TxInner<'static, VALIDATED> {
        match self {
            Self::V1(v1) => TxInner::V1(v1.into_owned()),
            Self::V2(v2) => TxInner::V2(v2.into_owned()),
        }
    }
}

pub type UnvalidatedTx<'a> = Tx<'a, false>;
pub type ValidatedTx<'a> = Tx<'a, true>;

impl<'a, const VALIDATED: bool> From<V1Tx<'a, VALIDATED>> for Tx<'a, VALIDATED> {
    fn from(value: V1Tx<'a, VALIDATED>) -> Self {
        Self(TxInner::V1(value))
    }
}

impl<'a, const VALIDATED: bool> From<V2Tx<'a, VALIDATED>> for Tx<'a, VALIDATED> {
    fn from(value: V2Tx<'a, VALIDATED>) -> Self {
        Self(TxInner::V2(value))
    }
}

impl<'a, const VALIDATED: bool> TryFrom<Tx<'a, VALIDATED>> for V1Tx<'a, VALIDATED> {
    type Error = Tx<'a, VALIDATED>;

    fn try_from(value: Tx<'a, VALIDATED>) -> Result<Self, Self::Error> {
        match value.0 {
            TxInner::V1(v1) => Ok(v1),
            incorrect => Err(Tx(incorrect)),
        }
    }
}

impl<'a, const VALIDATED: bool> TryFrom<Tx<'a, VALIDATED>> for V2Tx<'a, VALIDATED> {
    type Error = Tx<'a, VALIDATED>;

    fn try_from(value: Tx<'a, VALIDATED>) -> Result<Self, Self::Error> {
        match value.0 {
            TxInner::V2(v2) => Ok(v2),
            incorrect => Err(Tx(incorrect)),
        }
    }
}

impl<'a, const VALIDATED: bool> Tx<'a, VALIDATED> {
    pub fn format(&self) -> Format {
        match &self.0 {
            TxInner::V1(_) => Format::V1,
            TxInner::V2(_) => Format::V2,
        }
    }

    pub fn id(&self) -> &TxId {
        match &self.0 {
            TxInner::V1(tx) => &tx.as_inner().id,
            TxInner::V2(tx) => &tx.as_inner().id,
        }
    }

    pub fn last_tx(&self) -> LastTx<'_> {
        match &self.0 {
            TxInner::V1(tx) => (&tx.as_inner().last_tx).into(),
            TxInner::V2(tx) => LastTx::TxAnchor(Mown::Borrowed(&tx.as_inner().last_tx)),
        }
    }

    pub fn owner(&self) -> Owner<'_> {
        match &self.0 {
            TxInner::V1(tx) => tx.as_inner().signature_data.owner(),
            TxInner::V2(tx) => tx.as_inner().signature_data.owner(),
        }
    }

    pub fn tags(&self) -> &Vec<Tag<'a>> {
        match &self.0 {
            TxInner::V1(tx) => tx.as_inner().tags.as_ref(),
            TxInner::V2(tx) => tx.as_inner().tags.as_ref(),
        }
    }

    pub fn target(&self) -> Option<&WalletAddress> {
        match &self.0 {
            TxInner::V1(tx) => tx.as_inner().target.as_ref(),
            TxInner::V2(tx) => tx.as_inner().target.as_ref(),
        }
    }

    pub fn quantity(&self) -> Option<&Quantity> {
        match &self.0 {
            TxInner::V1(tx) => tx.as_inner().quantity.as_ref(),
            TxInner::V2(tx) => tx.as_inner().quantity.as_ref(),
        }
    }

    pub fn data(&'a self) -> Option<Data<'a>> {
        match &self.0 {
            TxInner::V1(tx) => tx
                .as_inner()
                .data
                .as_ref()
                .map(|d| Data::Embedded(Mown::Borrowed(d))),

            TxInner::V2(tx) => tx.as_inner().data_root.as_ref().map(|dr| {
                Data::External(Mown::Owned(ExternalData {
                    size: tx.as_inner().data_size,
                    root: dr.clone(),
                }))
            }),
        }
    }

    pub fn reward(&self) -> &Reward {
        match &self.0 {
            TxInner::V1(tx) => &tx.as_inner().reward,
            TxInner::V2(tx) => &tx.as_inner().reward,
        }
    }

    pub fn signature(&'a self) -> Signature<'a> {
        match &self.0 {
            TxInner::V1(tx) => tx.as_inner().signature_data.signature(),
            TxInner::V2(tx) => tx.as_inner().signature_data.signature(),
        }
    }

    pub fn is_validated(&self) -> bool {
        VALIDATED
    }

    pub fn into_owned(self) -> Tx<'static, VALIDATED> {
        Tx(self.0.into_owned())
    }
}

pub enum Data<'a> {
    Embedded(Mown<'a, EmbeddedData<'a>>),
    External(Mown<'a, ExternalData<'a>>),
}

pub struct ExternalData<'a> {
    size: u64,
    root: Blob<'a>, //todo
}

impl<'a> ExternalData<'a> {
    pub fn size(&self) -> u64 {
        self.size
    }
}

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error(transparent)]
    V1TxValidationError(#[from] V1TxDataError),
    #[error(transparent)]
    V2TxValidationError(#[from] V2TxDataError),
}

impl<'a> UnvalidatedTx<'a> {
    pub fn validate(self) -> Result<ValidatedTx<'a>, (Self, ValidationError)> {
        match self.0 {
            TxInner::V1(v1) => {
                Ok(Tx(TxInner::V1(v1.validate().map_err(|(v1, err)| {
                    (v1.into(), ValidationError::from(err))
                })?)))
            }
            TxInner::V2(v2) => {
                Ok(Tx(TxInner::V2(v2.validate().map_err(|(v2, err)| {
                    (v2.into(), ValidationError::from(err))
                })?)))
            }
        }
    }
}

impl UnvalidatedTx<'static> {
    pub fn from_json<J: JsonSource>(json: J) -> Result<Self, TxError> {
        RawTx::from_json(json)?.try_into()
    }
}

impl<'a> ValidatedTx<'a> {
    pub fn invalidate(self) -> UnvalidatedTx<'a> {
        match self.0 {
            TxInner::V1(v1) => v1.invalidate().into(),
            TxInner::V2(v2) => v2.invalidate().into(),
        }
    }

    pub fn to_json_string(&self) -> Result<String, JsonError> {
        match &self.0 {
            TxInner::V1(v1) => v1.to_json_string(),
            TxInner::V2(v2) => v2.to_json_string(),
        }
    }

    pub fn to_json(&self) -> Result<JsonValue, JsonError> {
        match &self.0 {
            TxInner::V1(v1) => v1.to_json(),
            TxInner::V2(v2) => v2.to_json(),
        }
    }
}

impl<'a> TryFrom<UnvalidatedRawTx<'a>> for UnvalidatedTx<'a> {
    type Error = TxError;

    fn try_from(value: UnvalidatedRawTx<'a>) -> Result<Self, Self::Error> {
        UnvalidatedTx::try_from(value.validate().map_err(|(_, err)| TxError::from(err))?)
    }
}

impl<'a> TryFrom<ValidatedRawTx<'a>> for UnvalidatedTx<'a> {
    type Error = TxError;

    fn try_from(value: ValidatedRawTx<'a>) -> Result<Self, Self::Error> {
        match value.as_inner().format {
            Format::V1 => Ok(Self(TxInner::V1(UnvalidatedV1Tx::try_from_raw(value)?))),
            Format::V2 => Ok(Self(TxInner::V2(UnvalidatedV2Tx::try_from_raw(value)?))),
        }
    }
}

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

impl<'a> Owner<'a> {
    pub fn address(&self) -> WalletAddress {
        match self {
            Self::Rsa4096(inner) => inner.derive_address(),
            Self::Rsa2048(inner) => inner.derive_address(),
        }
    }
}

impl AsBlob for Owner<'_> {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa4096(rsa) => rsa.as_blob(),
            Self::Rsa2048(rsa) => rsa.as_blob(),
        }
    }
}

pub enum Signature<'a> {
    Rsa4096(Mown<'a, TxSignature<RsaPss<4096>>>),
    Rsa2048(Mown<'a, TxSignature<RsaPss<2048>>>),
}

impl<'a> Signature<'a> {
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::Rsa4096(_) => SignatureType::RsaPss,
            Self::Rsa2048(_) => SignatureType::RsaPss,
        }
    }
}

impl AsBlob for Signature<'_> {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa4096(rsa) => rsa.as_blob(),
            Self::Rsa2048(rsa) => rsa.as_blob(),
        }
    }
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
    ValidationError(#[from] ValidationError),
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

#[derive(Debug, PartialEq)]
pub enum LastTx<'a> {
    TxId(Mown<'a, TxId>),
    TxAnchor(Mown<'a, TxAnchor>),
}

impl<'a> LastTx<'a> {
    pub fn into_owned(self) -> LastTx<'static> {
        match self {
            Self::TxId(id) => LastTx::TxId(Mown::Owned(id.into_owned())),
            Self::TxAnchor(anchor) => LastTx::TxAnchor(Mown::Owned(anchor.into_owned())),
        }
    }
}

impl<'a> Clone for LastTx<'a> {
    fn clone(&self) -> Self {
        match self {
            Self::TxId(Mown::Owned(id)) => Self::TxId(Mown::Owned(id.clone())),
            Self::TxId(Mown::Borrowed(id)) => Self::TxId(Mown::Borrowed(*id)),
            Self::TxAnchor(Mown::Owned(anchor)) => Self::TxAnchor(Mown::Owned(anchor.clone())),
            Self::TxAnchor(Mown::Borrowed(anchor)) => Self::TxAnchor(Mown::Borrowed(*anchor)),
        }
    }
}

impl<'a> From<&'a LastTx<'a>> for LastTx<'a> {
    fn from(value: &'a LastTx<'a>) -> Self {
        match value {
            LastTx::TxId(Mown::Owned(id)) => LastTx::TxId(Mown::Borrowed(id)),
            LastTx::TxId(Mown::Borrowed(id)) => LastTx::TxId(Mown::Borrowed(*id)),
            LastTx::TxAnchor(Mown::Owned(anchor)) => LastTx::TxAnchor(Mown::Borrowed(anchor)),
            LastTx::TxAnchor(Mown::Borrowed(anchor)) => LastTx::TxAnchor(Mown::Borrowed(*anchor)),
        }
    }
}

impl<'a> TryFrom<Blob<'a>> for LastTx<'a> {
    type Error =
        LastTxError<<TxId as TryFrom<Blob<'a>>>::Error, <TxAnchor as TryFrom<Blob<'a>>>::Error>;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        match value.len() {
            32 => Ok(Self::TxId(Mown::Owned(
                TxId::try_from(value).map_err(LastTxError::V1Error)?,
            ))),
            48 => Ok(Self::TxAnchor(Mown::Owned(
                TxAnchor::try_from(value).map_err(LastTxError::V2Error)?,
            ))),
            invalid => Err(LastTxError::InvalidLength(invalid)),
        }
    }
}

impl Display for LastTx<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TxId(tx_id) => Display::fmt(tx_id, f),
            Self::TxAnchor(tx_anchor) => Display::fmt(tx_anchor, f),
        }
    }
}

impl DeepHashable for LastTx<'_> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        match self {
            Self::TxId(tx_id) => tx_id.deep_hash(),
            Self::TxAnchor(tx_anchor) => tx_anchor.deep_hash(),
        }
    }
}

impl Hashable for LastTx<'_> {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        match self {
            Self::TxId(tx_id) => tx_id.feed(hasher),
            Self::TxAnchor(tx_anchor) => tx_anchor.feed(hasher),
        }
    }
}

impl AsRef<[u8]> for LastTx<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::TxId(tx_id) => tx_id.as_slice(),
            Self::TxAnchor(tx_anchor) => tx_anchor.as_slice(),
        }
    }
}

impl AsBlob for LastTx<'_> {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::TxId(tx_id) => tx_id.as_blob(),
            Self::TxAnchor(tx_anchor) => tx_anchor.as_blob(),
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

impl<'a> Tag<'a> {
    pub fn into_owned(self) -> Tag<'static> {
        Tag {
            name: self.name.into_owned(),
            value: self.value.into_owned(),
        }
    }
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

impl<'a> From<Tag<'a>> for RawTag<'a> {
    fn from(value: Tag<'a>) -> Self {
        Self {
            name: value.name.into_inner(),
            value: value.value.into_inner(),
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

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::tx::{Data, Format, SignatureType, UnvalidatedTx};

    static TX_V1: &'static [u8] = include_bytes!("../../testdata/tx_v1.json");
    static TX_V1_2: &'static [u8] = include_bytes!("../../testdata/tx_v1_2.json");
    static TX_V2: &'static [u8] = include_bytes!("../../testdata/tx_v2.json");
    static TX_V2_2: &'static [u8] = include_bytes!("../../testdata/tx_v2_2.json");
    #[test]
    fn v1() -> anyhow::Result<()> {
        let unvalidated = UnvalidatedTx::from_json(TX_V1)?;
        assert!(!unvalidated.is_validated());
        let validated = unvalidated.validate().map_err(|(_, e)| e)?;
        assert!(validated.is_validated());

        assert_eq!(validated.format(), Format::V1);

        assert_eq!(
            validated.id().to_base64(),
            "BNttzDav3jHVnNiV7nYbQv-GY0HQ-4XXsdkE5K9ylHQ"
        );

        assert_eq!(
            validated.signature().signature_type(),
            SignatureType::RsaPss
        );

        assert_eq!(
            validated.owner().address().to_base64(),
            "_qa4arkdjK2X9SjechexnWzTtbOKcPkBPhrDDej6lI8"
        );

        match validated.data() {
            Some(Data::Embedded(data)) => {
                assert_eq!(data.len(), 1033478);
            }
            _ => panic!("invalid data"),
        }

        Ok(())
    }

    #[test]
    fn v1_rountrip() -> anyhow::Result<()> {
        let unvalidated = UnvalidatedTx::from_json(TX_V1_2)?;
        let validated = unvalidated.validate().map_err(|(_, e)| e)?;
        let json = validated.to_json_string()?;
        let unvalidated = UnvalidatedTx::from_json(&json)?;
        let validated_2 = unvalidated.validate().map_err(|(_, e)| e)?;
        assert_eq!(validated, validated_2);
        Ok(())
    }

    #[test]
    fn v2() -> anyhow::Result<()> {
        let unvalidated = UnvalidatedTx::from_json(TX_V2)?;
        assert!(!unvalidated.is_validated());
        let validated = unvalidated.validate().map_err(|(_, e)| e)?;
        assert!(validated.is_validated());

        assert_eq!(validated.format(), Format::V2);

        assert_eq!(
            validated.id().to_base64(),
            "bXGqzNQNmHTeL54cUQ6wPo-MO0thLP44FeAoM93kEwk"
        );

        assert_eq!(
            validated.signature().signature_type(),
            SignatureType::RsaPss
        );

        assert_eq!(
            validated.owner().address().to_base64(),
            "OK_m2Tk41N94KZLl5WQSx_-iNWbvcp8EMfrYsel_QeQ"
        );

        match validated.data() {
            Some(Data::External(data)) => {
                assert_eq!(data.size(), 128355);
            }
            _ => panic!("invalid data"),
        }

        Ok(())
    }

    #[test]
    fn v2_rountrip() -> anyhow::Result<()> {
        let unvalidated = UnvalidatedTx::from_json(TX_V2_2)?;
        let validated = unvalidated.validate().map_err(|(_, e)| e)?;
        let json = validated.to_json_string()?;
        let unvalidated = UnvalidatedTx::from_json(&json)?;
        let validated_2 = unvalidated.validate().map_err(|(_, e)| e)?;
        assert_eq!(validated, validated_2);
        Ok(())
    }
}
