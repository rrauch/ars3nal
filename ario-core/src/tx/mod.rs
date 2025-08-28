mod ecdsa;
mod pss;
mod raw;
pub mod v1;
pub mod v2;

use crate::base64::{ToBase64, TryFromBase64, TryFromBase64Error};
use crate::blob::{AsBlob, Blob};
use crate::crypto::ec::EcPublicKey;
use crate::crypto::ec::ecdsa::Ecdsa;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{
    Digest, Hashable, HashableExt, Hasher, HasherExt, Sha256Hash, TypedDigest,
};
use crate::crypto::hash::{Sha256, Sha384};
use crate::crypto::keys::{PublicKey, SecretKey};
use crate::crypto::rsa::RsaPublicKey;
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::signature::TypedSignature;
use crate::crypto::{keys, signature};
use crate::data::{Data, EmbeddedData, ExternalData};
use crate::json::JsonSource;
use crate::money::{CurrencyExt, Money, MoneyError, TypedMoney, Winston};
use crate::tag::Tag;
use crate::tx::raw::{RawTag, RawTx, RawTxDataError, UnvalidatedRawTx, ValidatedRawTx};
use crate::tx::v1::{UnvalidatedV1Tx, V1Tx, V1TxDataError};
use crate::tx::v2::{TxDraft, UnvalidatedV2Tx, V2Tx, V2TxBuilder, V2TxDataError};
use crate::typed::{FromInner, Typed};
use crate::validation::ValidateExt;
use crate::wallet::{WalletAddress, WalletKind, WalletPk};
use crate::{JsonError, JsonValue, blob};
use bigdecimal::BigDecimal;
use k256::Secp256k1;
use maybe_owned::MaybeOwned;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::convert::Infallible;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::LazyLock;
use thiserror::Error;

static ZERO_WINSTON: LazyLock<Money<Winston>> = LazyLock::new(|| Winston::zero());

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

pub struct TxBuilder;

impl TxBuilder {
    pub fn v2<'a>() -> V2TxBuilder<'a> {
        TxDraft::builder()
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
            TxInner::V2(tx) => tx.as_inner().id(),
        }
    }

    pub fn last_tx(&self) -> LastTx<'_> {
        match &self.0 {
            TxInner::V1(tx) => (&tx.as_inner().last_tx).into(),
            TxInner::V2(tx) => LastTx::TxAnchor(tx.as_inner().last_tx().into()),
        }
    }

    pub fn owner(&self) -> Owner<'_> {
        match &self.0 {
            TxInner::V1(tx) => tx.as_inner().signature_data.owner(),
            TxInner::V2(tx) => tx.as_inner().signature_data().owner(),
        }
    }

    pub fn tags(&self) -> &Vec<Tag<'a>> {
        match &self.0 {
            TxInner::V1(tx) => tx.as_inner().tags.as_ref(),
            TxInner::V2(tx) => tx.as_inner().tags(),
        }
    }

    pub fn target(&self) -> Option<&WalletAddress> {
        match &self.0 {
            TxInner::V1(tx) => tx.as_inner().target.as_ref(),
            TxInner::V2(tx) => tx.as_inner().target(),
        }
    }

    pub fn quantity(&self) -> Option<&Quantity> {
        match &self.0 {
            TxInner::V1(tx) => tx.as_inner().quantity.as_ref(),
            TxInner::V2(tx) => tx.as_inner().quantity(),
        }
    }

    pub fn data(&'a self) -> Option<Data<'a>> {
        match &self.0 {
            TxInner::V1(tx) => tx
                .as_inner()
                .data
                .as_ref()
                .map(|d| Data::Embedded(d.into())),

            TxInner::V2(tx) => tx.as_inner().data_root().map(|dr| {
                Data::External(ExternalData::new(dr.clone(), tx.as_inner().data_size()).into())
            }),
        }
    }

    pub fn reward(&self) -> &Reward {
        match &self.0 {
            TxInner::V1(tx) => &tx.as_inner().reward,
            TxInner::V2(tx) => tx.as_inner().reward(),
        }
    }

    pub fn signature(&'a self) -> Signature<'a> {
        match &self.0 {
            TxInner::V1(tx) => tx.as_inner().signature_data.signature(),
            TxInner::V2(tx) => tx.as_inner().signature_data().signature(),
        }
    }

    pub fn is_validated(&self) -> bool {
        VALIDATED
    }

    pub fn into_owned(self) -> Tx<'static, VALIDATED> {
        Tx(self.0.into_owned())
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

#[derive(Error, Debug)]
pub enum TxIdError {
    #[error(transparent)]
    Base64Error(#[from] TryFromBase64Error<Infallible>),
    #[error(transparent)]
    BlobError(#[from] blob::Error),
}

impl FromStr for TxId {
    type Err = TxIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Blob::try_from_base64(s.as_bytes())?;
        Ok(TxId::try_from(bytes)?)
    }
}

impl Display for TxId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_base64().as_str())
    }
}

pub enum Owner<'a> {
    Rsa4096(MaybeOwned<'a, WalletPk<RsaPublicKey<4096>>>),
    Rsa2048(MaybeOwned<'a, WalletPk<RsaPublicKey<2048>>>),
    Secp256k1(MaybeOwned<'a, WalletPk<EcPublicKey<Secp256k1>>>),
}

impl<'a> Owner<'a> {
    pub fn address(&self) -> WalletAddress {
        match self {
            Self::Rsa4096(inner) => inner.derive_address(),
            Self::Rsa2048(inner) => inner.derive_address(),
            Self::Secp256k1(inner) => inner.derive_address(),
        }
    }
}

impl AsBlob for Owner<'_> {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa4096(rsa) => rsa.as_blob(),
            Self::Rsa2048(rsa) => rsa.as_blob(),
            Self::Secp256k1(ec) => ec.as_blob(),
        }
    }
}

pub enum Signature<'a> {
    Rsa4096(MaybeOwned<'a, TxSignature<RsaPss<4096>>>),
    Rsa2048(MaybeOwned<'a, TxSignature<RsaPss<2048>>>),
    Secp256k1(MaybeOwned<'a, TxSignature<Ecdsa<Secp256k1>>>),
}

impl<'a> Signature<'a> {
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::Rsa4096(_) => SignatureType::RsaPss,
            Self::Rsa2048(_) => SignatureType::RsaPss,
            Self::Secp256k1(_) => SignatureType::EcdsaSecp256k1,
        }
    }

    pub fn digest(&self) -> TxId {
        match self {
            Self::Rsa4096(pss) => pss.digest(),
            Self::Rsa2048(pss) => pss.digest(),
            Self::Secp256k1(ecdsa) => ecdsa.digest(),
        }
    }
}

impl AsBlob for Signature<'_> {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa4096(pss) => pss.as_blob(),
            Self::Rsa2048(pss) => pss.as_blob(),
            Self::Secp256k1(ecdsa) => ecdsa.as_blob(),
        }
    }
}

pub trait TxSignatureScheme: signature::Scheme {
    type Signer: SecretKey;
    type Verifier: PublicKey;
}

pub type TxSignature<S: TxSignatureScheme> = TypedSignature<TxHash, WalletKind, S>;
pub type TxDeepHash = TypedDigest<TxKind, Sha384>;
pub type TxShallowHash = TypedDigest<TxKind, Sha256>;

#[derive(Clone, Debug, PartialEq)]
pub enum TxHash {
    DeepHash(TxDeepHash),
    Shallow(TxShallowHash),
}

impl TxHash {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::DeepHash(h) => h.as_slice(),
            Self::Shallow(h) => h.as_slice(),
        }
    }

    pub(crate) fn to_sign_prehash(&self) -> MaybeOwned<'_, Sha256Hash> {
        match self {
            TxHash::DeepHash(deep_hash) => deep_hash.digest().into(),
            TxHash::Shallow(shallow) => MaybeOwned::Borrowed(shallow),
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
    #[error(transparent)]
    QuantityError(#[from] QuantityError),
    #[error(transparent)]
    RewardError(#[from] RewardError),
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
            .map(|raw| Quantity::try_from(raw))
            .transpose()?;

        let reward = Reward::try_from(raw_reward)?;

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

#[derive(Error, Debug)]
pub enum TxAnchorError {
    #[error(transparent)]
    Base64Error(#[from] TryFromBase64Error<Infallible>),
    #[error(transparent)]
    BlobError(#[from] blob::Error),
}

impl FromStr for TxAnchor {
    type Err = TxAnchorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Blob::try_from_base64(s.as_bytes())?;
        Ok(TxAnchor::try_from(bytes)?)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum LastTx<'a> {
    TxId(MaybeOwned<'a, TxId>),
    TxAnchor(MaybeOwned<'a, TxAnchor>),
}

impl<'a> LastTx<'a> {
    pub fn into_owned(self) -> LastTx<'static> {
        match self {
            Self::TxId(id) => LastTx::TxId(id.into_owned().into()),
            Self::TxAnchor(anchor) => LastTx::TxAnchor(anchor.into_owned().into()),
        }
    }
}

impl<'a> From<&'a LastTx<'a>> for LastTx<'a> {
    fn from(value: &'a LastTx<'a>) -> Self {
        match value {
            LastTx::TxId(tx_id) => LastTx::TxId(tx_id.as_ref().into()),
            LastTx::TxAnchor(tx_anchor) => LastTx::TxAnchor(tx_anchor.as_ref().into()),
        }
    }
}

impl<'a> TryFrom<Blob<'a>> for LastTx<'a> {
    type Error =
        LastTxError<<TxId as TryFrom<Blob<'a>>>::Error, <TxAnchor as TryFrom<Blob<'a>>>::Error>;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        match value.len() {
            32 => Ok(Self::TxId(MaybeOwned::Owned(
                TxId::try_from(value).map_err(LastTxError::V1Error)?,
            ))),
            48 => Ok(Self::TxAnchor(MaybeOwned::Owned(
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

const RSA_PSS_SIG_TYPE: &'static str = "PS256_65537";
const ECDSA_SECP256K1_SIG_TYPE: &'static str = "ES256K";

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

pub struct TxQuantityKind;
pub type Quantity = TypedMoney<TxQuantityKind, Winston>;

impl Quantity {
    pub(crate) fn try_from<I, E>(money: I) -> Result<Self, QuantityError>
    where
        I: TryInto<Money<Winston>, Error = E>,
        E: Into<MoneyError>,
    {
        let money = money.try_into().map_err(|e| e.into())?;
        if &money < ZERO_WINSTON.deref() {
            return Err(QuantityError::NegativeQuantity);
        }
        Ok(Self::from_inner(money))
    }
}

#[derive(Error, Debug)]
pub enum QuantityError {
    #[error("quantity cannot be negative")]
    NegativeQuantity,
    #[error(transparent)]
    InvalidQuantity(#[from] MoneyError),
}

pub struct TxRewardKind;
pub type Reward = TypedMoney<TxRewardKind, Winston>;

impl Reward {
    pub(crate) fn try_from<I, E>(money: I) -> Result<Self, RewardError>
    where
        I: TryInto<Money<Winston>, Error = E>,
        E: Into<MoneyError>,
    {
        let money = money.try_into().map_err(|e| e.into())?;
        if &money < ZERO_WINSTON.deref() {
            return Err(RewardError::NegativeReward);
        }
        Ok(Self::from_inner(money))
    }
}

#[derive(Error, Debug)]
pub enum RewardError {
    #[error("reward cannot be negative")]
    NegativeReward,
    #[error(transparent)]
    InvalidReward(#[from] MoneyError),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transfer {
    target: WalletAddress,
    quantity: Quantity,
}

impl Transfer {
    pub fn new(
        target: WalletAddress,
        quantity: impl TryInto<Money<Winston>, Error: Into<MoneyError>>,
    ) -> Result<Self, QuantityError> {
        Ok(Self {
            target,
            quantity: Quantity::try_from(quantity)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::blob::Blob;
    use crate::crypto::ec::SupportedSecretKey as SupportedEcSecretKey;
    use crate::crypto::keys::SupportedSecretKey;
    use crate::crypto::rsa::SupportedPrivateKey as SupportedRsaPrivateKey;
    use crate::data::VerifiableData;
    use crate::jwk::Jwk;
    use crate::money::{CurrencyExt, Winston};
    use crate::tx::v2::DataRoot;
    use crate::tx::{
        Data, ExternalData, Format, Quantity, Reward, SignatureType, Transfer, Tx, TxAnchor,
        TxBuilder, UnvalidatedTx,
    };
    use crate::typed::FromInner;
    use crate::wallet::{Wallet, WalletAddress, WalletSk};
    use std::str::FromStr;

    static TX_V1: &'static [u8] = include_bytes!("../../testdata/tx_v1.json");
    static TX_V1_2: &'static [u8] = include_bytes!("../../testdata/tx_v1_2.json");
    static TX_V2: &'static [u8] = include_bytes!("../../testdata/tx_v2.json");
    static TX_V2_2: &'static [u8] = include_bytes!("../../testdata/tx_v2_2.json");
    static WALLET_RSA_JWK: &'static [u8] =
        include_bytes!("../../testdata/ar_wallet_tests_PS256_65537_fixture.json");
    static WALLET_EC_JWK: &'static [u8] =
        include_bytes!("../../testdata/ar_wallet_tests_ES256K_fixture.json");
    static UPLOAD_DATA: &'static [u8] =
        include_bytes!("../../testdata/trtu91u1kRVDrZI6WvWVxU3uvEjJRZcls2WSZvYJyBc.data");

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

        assert_eq!(validated.data().unwrap().size(), 1033478);

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

    #[test]
    fn builder_pss() -> anyhow::Result<()> {
        let wallet = match SupportedSecretKey::try_from(&Jwk::from_json(WALLET_RSA_JWK)?)? {
            SupportedSecretKey::Rsa(SupportedRsaPrivateKey::Rsa4096(sk)) => {
                WalletSk::from_inner(sk)
            }
            _ => panic!("wrong key"),
        };

        let target_str = "OK_m2Tk41N94KZLl5WQSx_-iNWbvcp8EMfrYsel_QeQ";

        let data_root = DataRoot::try_from(Blob::from([0u8; 32]))?;
        let data_size = 32u64;

        let data = ExternalData::new(data_root.clone(), data_size);

        let draft = TxBuilder::v2()
            .reward(1234)?
            .tx_anchor(TxAnchor::from_inner([0u8; 48]))
            .transfer(Transfer::new(WalletAddress::from_str(target_str)?, 101)?)
            .data_upload(&data)
            .draft();

        let valid_tx = draft.sign(&wallet)?;
        let json = valid_tx.to_json_string()?;
        let valid_tx = Tx::from_json(&json)?.validate().map_err(|(_, err)| err)?;

        assert_eq!(valid_tx.signature().signature_type(), SignatureType::RsaPss);

        assert_eq!(
            valid_tx.reward(),
            &Reward::try_from(Winston::from_str("1234")?)?,
        );

        assert_eq!(
            valid_tx.target(),
            Some(WalletAddress::from_str(target_str)?).as_ref()
        );

        assert_eq!(
            valid_tx.quantity(),
            Some(Quantity::try_from(Winston::from_str("101")?)?).as_ref()
        );

        let data = match valid_tx.data() {
            Some(Data::External(data)) => data,
            _ => panic!("invalid data"),
        };

        assert_eq!(data.size(), data_size);
        assert_eq!(data.root(), &data_root);

        Ok(())
    }

    #[test]
    fn builder_ecdsa() -> anyhow::Result<()> {
        let wallet = match SupportedSecretKey::try_from(&Jwk::from_json(WALLET_EC_JWK)?)? {
            SupportedSecretKey::Ec(SupportedEcSecretKey::Secp256k1(sk)) => WalletSk::from_inner(sk),
            _ => panic!("wrong key"),
        };

        let target_str = "OK_m2Tk41N94KZLl5WQSx_-iNWbvcp8EMfrYsel_QeQ";

        let draft = TxBuilder::v2()
            .reward(21234)?
            .tx_anchor(TxAnchor::from_inner([0u8; 48]))
            .transfer(Transfer::new(WalletAddress::from_str(target_str)?, 2101)?)
            .draft();

        let valid_tx = draft.sign(&wallet)?;
        let json = valid_tx.to_json_string()?;
        let valid_tx = Tx::from_json(&json)?.validate().map_err(|(_, err)| err)?;

        let owner = valid_tx.owner();
        let _owner_address = owner.address().to_base64();

        assert_eq!(
            valid_tx.signature().signature_type(),
            SignatureType::EcdsaSecp256k1
        );

        assert_eq!(
            valid_tx.reward(),
            &Reward::try_from(Winston::from_str("21234")?)?,
        );

        assert_eq!(
            valid_tx.target(),
            Some(WalletAddress::from_str(target_str)?).as_ref()
        );

        assert_eq!(
            valid_tx.quantity(),
            Some(Quantity::try_from(Winston::from_str("2101")?)?).as_ref()
        );

        assert!(valid_tx.data().is_none());

        Ok(())
    }

    #[test]
    fn upload_pss() -> anyhow::Result<()> {
        let wallet = Wallet::from_jwk(&Jwk::from_json(WALLET_RSA_JWK)?)?;

        let data = VerifiableData::from_single_value(UPLOAD_DATA);

        let draft = TxBuilder::v2()
            .reward(12345)?
            .tx_anchor(TxAnchor::from_inner([0u8; 48]))
            .data_upload(data.external_data())
            .draft();

        let valid_tx = wallet.sign_tx_draft(draft)?;

        assert_eq!(valid_tx.data().unwrap().size(), 683821);
        assert_eq!(
            valid_tx.data().unwrap().data_root().unwrap().to_base64(),
            "ikHHDmOhqnZ5qsNZ7SOoofuaG66A5yRLsTvacad2NMg"
        );

        let json = valid_tx.to_json_string()?;
        let valid_tx = Tx::from_json(&json)?.validate().map_err(|(_, err)| err)?;

        assert_eq!(valid_tx.data().unwrap().size(), 683821);
        assert_eq!(
            valid_tx.data().unwrap().data_root().unwrap().to_base64(),
            "ikHHDmOhqnZ5qsNZ7SOoofuaG66A5yRLsTvacad2NMg"
        );

        Ok(())
    }
}
