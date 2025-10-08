mod raw;
pub mod v1;
pub mod v2;

use crate::base64::{ToBase64, TryFromBase64, TryFromBase64Error};
use crate::blob::{AsBlob, Blob};
use crate::crypto::ec::EcPublicKey;
use crate::crypto::ec::ecdsa::Ecdsa;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher, HasherExt, TypedDigest};
use crate::crypto::hash::{Sha256, Sha384};
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::rsa::{RsaPublicKey, pss};
use crate::crypto::signature;
use crate::crypto::signature::Scheme as SignatureScheme;
use crate::data::{DataItem, EmbeddedDataItem, ExternalDataItem};
use crate::entity::{
    ArEntity, ArEntityHash, ArEntitySignature, MessageFor, Owner as EntityOwner,
    Signature as EntitySignature,
};
use crate::json::JsonSource;
use crate::money::{CurrencyExt, Money, MoneyError, TypedMoney, Winston};
use crate::tag::Tag;
use crate::tx::raw::{RawTag, RawTx, RawTxDataError, UnvalidatedRawTx, ValidatedRawTx};
use crate::tx::v1::{UnauthenticatedV1Tx, V1Tx, V1TxDataError};
use crate::tx::v2::{TxDraft, UnauthenticatedV2Tx, V2Tx, V2TxBuilder, V2TxDataError};
use crate::typed::{FromInner, Typed, WithSerde};
use crate::validation::ValidateExt;
use crate::wallet::{WalletAddress, WalletPk};
use crate::{
    Authenticated, AuthenticationState, JsonError, JsonValue, Unauthenticated, blob, entity,
};
use bigdecimal::BigDecimal;
use hybrid_array::Array;
use hybrid_array::sizes::U48;
use itertools::Either;
use k256::Secp256k1;
use maybe_owned::MaybeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::borrow::Cow;
use std::convert::Infallible;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::LazyLock;
use thiserror::Error;

static ZERO_WINSTON: LazyLock<Money<Winston>> = LazyLock::new(|| Winston::zero());

#[derive(Debug, Clone, PartialEq, Serialize)]
#[repr(transparent)]
pub struct Tx<'a, Auth: AuthenticationState>(TxInner<'a, Auth>);

impl<'a, Auth: AuthenticationState> ArEntity for Tx<'a, Auth> {
    type Id = TxId;
    type Hash = TxHash;

    fn id(&self) -> &Self::Id {
        self.id()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
enum TxInner<'a, Auth: AuthenticationState> {
    V1(V1Tx<'a, Auth>),
    V2(V2Tx<'a, Auth>),
}

impl<'de, 'a> Deserialize<'de> for TxInner<'a, Unauthenticated> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        enum Helper<'a> {
            V1(V1Tx<'a, Unauthenticated>),
            V2(V2Tx<'a, Unauthenticated>),
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(match helper {
            Helper::V1(v1) => TxInner::V1(v1),
            Helper::V2(v2) => TxInner::V2(v2),
        })
    }
}

impl<'a, Auth: AuthenticationState> TxInner<'a, Auth> {
    fn into_owned(self) -> TxInner<'static, Auth> {
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

pub type UnauthenticatedTx<'a> = Tx<'a, Unauthenticated>;

impl<'de, 'a> Deserialize<'de> for UnauthenticatedTx<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(TxInner::deserialize(deserializer)?))
    }
}

pub type AuthenticatedTx<'a> = Tx<'a, Authenticated>;

impl<'a> From<AuthenticatedTx<'a>> for UnauthenticatedTx<'a> {
    fn from(value: AuthenticatedTx<'a>) -> Self {
        value.invalidate()
    }
}

impl<'a, Auth: AuthenticationState> From<V1Tx<'a, Auth>> for Tx<'a, Auth> {
    fn from(value: V1Tx<'a, Auth>) -> Self {
        Self(TxInner::V1(value))
    }
}

impl<'a, Auth: AuthenticationState> From<V2Tx<'a, Auth>> for Tx<'a, Auth> {
    fn from(value: V2Tx<'a, Auth>) -> Self {
        Self(TxInner::V2(value))
    }
}

impl<'a, Auth: AuthenticationState> TryFrom<Tx<'a, Auth>> for V1Tx<'a, Auth> {
    type Error = Tx<'a, Auth>;

    fn try_from(value: Tx<'a, Auth>) -> Result<Self, Self::Error> {
        match value.0 {
            TxInner::V1(v1) => Ok(v1),
            incorrect => Err(Tx(incorrect)),
        }
    }
}

impl<'a, Auth: AuthenticationState> TryFrom<Tx<'a, Auth>> for V2Tx<'a, Auth> {
    type Error = Tx<'a, Auth>;

    fn try_from(value: Tx<'a, Auth>) -> Result<Self, Self::Error> {
        match value.0 {
            TxInner::V2(v2) => Ok(v2),
            incorrect => Err(Tx(incorrect)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Owner<'a> {
    Rsa2048(MaybeOwned<'a, WalletPk<RsaPublicKey<2048>>>),
    Rsa4096(MaybeOwned<'a, WalletPk<RsaPublicKey<4096>>>),
    Secp256k1(MaybeOwned<'a, WalletPk<EcPublicKey<Secp256k1>>>),
}

impl<'a> From<Owner<'a>> for EntityOwner<'a> {
    fn from(value: Owner<'a>) -> Self {
        match value {
            Owner::Rsa2048(o) => Self::Rsa2048(o),
            Owner::Rsa4096(o) => Self::Rsa4096(o),
            Owner::Secp256k1(o) => Self::Secp256k1(o),
        }
    }
}

impl<'a> TryFrom<EntityOwner<'a>> for Owner<'a> {
    type Error = EntityOwner<'a>;

    fn try_from(value: EntityOwner<'a>) -> Result<Self, Self::Error> {
        match value {
            EntityOwner::Rsa2048(o) => Ok(Self::Rsa2048(o)),
            EntityOwner::Rsa4096(o) => Ok(Self::Rsa4096(o)),
            EntityOwner::Secp256k1(o) => Ok(Self::Secp256k1(o)),
            other => Err(other),
        }
    }
}

impl<'a> Owner<'a> {
    pub fn address(&self) -> WalletAddress {
        match self {
            Self::Rsa2048(inner) => inner.derive_address(),
            Self::Rsa4096(inner) => inner.derive_address(),
            Self::Secp256k1(inner) => inner.derive_address(),
        }
    }
}

impl AsBlob for Owner<'_> {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa2048(rsa) => rsa.as_blob(),
            Self::Rsa4096(rsa) => rsa.as_blob(),
            Self::Secp256k1(ec) => ec.as_blob(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Signature<'a> {
    Rsa2048(MaybeOwned<'a, ArEntitySignature<TxHash, RsaPss<2048>>>),
    Rsa4096(MaybeOwned<'a, ArEntitySignature<TxHash, RsaPss<4096>>>),
    Secp256k1(MaybeOwned<'a, ArEntitySignature<TxHash, Ecdsa<Secp256k1>>>),
}

#[derive(Error, Debug)]
pub enum SignatureOwnerError {
    #[error("signature or owner error: {0}")]
    Other(String),
    #[error("unknown or unsupported")]
    Unknown,
}

impl<'a> Signature<'a> {
    pub fn from_raw_autodetect(
        raw_owner: Blob<'a>,
        raw_signature: Blob<'a>,
    ) -> Result<(Signature<'a>, Owner<'a>), SignatureOwnerError> {
        match (raw_owner.len(), raw_signature.len()) {
            (512, 512) | (256, 256) => {
                match entity::pss::from_raw_autodetect(raw_owner, raw_signature)
                    .map(|r| match r {
                        Either::Left(l) => Either::Left(l.into_inner()),
                        Either::Right(r) => Either::Right(r.into_inner()),
                    })
                    .map_err(|e| SignatureOwnerError::Other(e.to_string()))?
                {
                    Either::Left((sig, owner)) => Ok((
                        Signature::try_from(sig).map_err(|_| {
                            SignatureOwnerError::Other("conversion failed".to_string())
                        })?,
                        Owner::try_from(owner).map_err(|_| {
                            SignatureOwnerError::Other("conversion failed".to_string())
                        })?,
                    )),
                    Either::Right((sig, owner)) => Ok((
                        Signature::try_from(sig).map_err(|_| {
                            SignatureOwnerError::Other("conversion failed".to_string())
                        })?,
                        Owner::try_from(owner).map_err(|_| {
                            SignatureOwnerError::Other("conversion failed".to_string())
                        })?,
                    )),
                }
            }
            (32, 64) | (33, 64) | (65, 64) => {
                let (sig, owner) =
                    entity::ecdsa::Secp256k1SignatureData::from_raw(raw_signature, raw_owner)
                        .map(|v| v.into_inner())
                        .map_err(|e| SignatureOwnerError::Other(e.to_string()))?;
                Ok((
                    Signature::try_from(sig)
                        .map_err(|_| SignatureOwnerError::Other("conversion failed".to_string()))?,
                    Owner::try_from(owner)
                        .map_err(|_| SignatureOwnerError::Other("conversion failed".to_string()))?,
                ))
            }
            _ => Err(SignatureOwnerError::Unknown),
        }
    }
}

impl<'a> From<Signature<'a>> for EntitySignature<'a, TxHash> {
    fn from(value: Signature<'a>) -> Self {
        match value {
            Signature::Rsa2048(o) => Self::Rsa2048(o),
            Signature::Rsa4096(o) => Self::Rsa4096(o),
            Signature::Secp256k1(o) => Self::Secp256k1(o),
        }
    }
}

impl<'a> TryFrom<EntitySignature<'a, TxHash>> for Signature<'a> {
    type Error = EntitySignature<'a, TxHash>;

    fn try_from(value: EntitySignature<'a, TxHash>) -> Result<Self, Self::Error> {
        match value {
            EntitySignature::Rsa2048(o) => Ok(Self::Rsa2048(o)),
            EntitySignature::Rsa4096(o) => Ok(Self::Rsa4096(o)),
            EntitySignature::Secp256k1(o) => Ok(Self::Secp256k1(o)),
            other => Err(other),
        }
    }
}

impl AsBlob for Signature<'_> {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa2048(pss) => pss.as_blob(),
            Self::Rsa4096(pss) => pss.as_blob(),
            Self::Secp256k1(ecdsa) => ecdsa.as_blob(),
        }
    }
}

impl<'a, Auth: AuthenticationState> Tx<'a, Auth> {
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
            TxInner::V1(tx) => tx
                .as_inner()
                .signature_data
                .owner()
                .try_into()
                .expect("owner conversion to succeed"),
            TxInner::V2(tx) => tx
                .as_inner()
                .signature_data()
                .owner()
                .try_into()
                .expect("owner conversion to succeed"),
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

    pub fn data_item(&'a self) -> Option<DataItem<'a>> {
        match &self.0 {
            TxInner::V1(tx) => tx
                .as_inner()
                .data_item
                .as_ref()
                .map(|d| DataItem::Embedded(d.into())),

            TxInner::V2(tx) => tx.as_inner().data_root().map(|dr| {
                DataItem::External(
                    ExternalDataItem::new(tx.as_inner().data_size(), dr.clone().into()).into(),
                )
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
            TxInner::V1(tx) => tx
                .as_inner()
                .signature_data
                .signature()
                .try_into()
                .expect("signature conversion to succeed"),
            TxInner::V2(tx) => tx
                .as_inner()
                .signature_data()
                .signature()
                .try_into()
                .expect("signature conversion to succeed"),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        Auth::is_authenticated()
    }

    pub fn into_owned(self) -> Tx<'static, Auth> {
        Tx(self.0.into_owned())
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

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error(transparent)]
    V1TxValidationError(#[from] V1TxDataError),
    #[error(transparent)]
    V2TxValidationError(#[from] V2TxDataError),
}

impl<'a> UnauthenticatedTx<'a> {
    pub fn authenticate(self) -> Result<AuthenticatedTx<'a>, (Self, ValidationError)> {
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

impl UnauthenticatedTx<'static> {
    pub fn from_json<J: JsonSource>(json: J) -> Result<Self, TxError> {
        RawTx::from_json(json)?.try_into()
    }
}

impl<'a> AuthenticatedTx<'a> {
    pub fn invalidate(self) -> UnauthenticatedTx<'a> {
        match self.0 {
            TxInner::V1(v1) => v1.invalidate().into(),
            TxInner::V2(v2) => v2.invalidate().into(),
        }
    }
}

impl<'a> TryFrom<UnvalidatedRawTx<'a>> for UnauthenticatedTx<'a> {
    type Error = TxError;

    fn try_from(value: UnvalidatedRawTx<'a>) -> Result<Self, Self::Error> {
        UnauthenticatedTx::try_from(value.validate().map_err(|(_, err)| TxError::from(err))?)
    }
}

impl<'a> TryFrom<ValidatedRawTx<'a>> for UnauthenticatedTx<'a> {
    type Error = TxError;

    fn try_from(value: ValidatedRawTx<'a>) -> Result<Self, Self::Error> {
        match value.as_inner().format {
            Format::V1 => Ok(Self(TxInner::V1(UnauthenticatedV1Tx::try_from_raw(value)?))),
            Format::V2 => Ok(Self(TxInner::V2(UnauthenticatedV2Tx::try_from_raw(value)?))),
        }
    }
}

pub struct TxKind;
pub struct TxSignatureKind;

pub type TxId = TypedDigest<TxSignatureKind, Sha256>;

impl WithSerde for TxId {}

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

pub(crate) trait TxSignatureScheme: SignatureScheme + SupportedSignatureScheme {}

impl<T> TxSignatureScheme for T where T: SignatureScheme + SupportedSignatureScheme {}

trait SupportedSignatureScheme {}
impl SupportedSignatureScheme for Ecdsa<Secp256k1> {}
impl SupportedSignatureScheme for RsaPss<4096> {}
impl SupportedSignatureScheme for RsaPss<2048> {}

pub type TxSignature<S: TxSignatureScheme> = ArEntitySignature<TxHash, S>;
pub type TxDeepHash = TypedDigest<TxKind, Sha384>;

impl WithSerde for TxDeepHash {}

pub type TxShallowHash = TypedDigest<TxKind, Sha256>;

impl WithSerde for TxShallowHash {}

#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
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
}

impl ArEntityHash for TxHash {}

impl<const BIT: usize> MessageFor<RsaPss<BIT>> for TxHash
where
    for<'a> RsaPss<BIT>: SignatureScheme<Message<'a> = pss::Message<'a>>,
{
    fn message(&self) -> Cow<'_, <RsaPss<BIT> as SignatureScheme>::Message<'_>> {
        match self {
            Self::DeepHash(deep_hash) => Cow::Owned(pss::Message::Regular(deep_hash.as_blob())),
            Self::Shallow(shallow) => Cow::Owned(pss::Message::PreHashed(shallow)),
        }
    }
}

impl MessageFor<Ecdsa<Secp256k1>> for TxHash
where
    for<'a> Ecdsa<Secp256k1>: SignatureScheme<Message<'a> = [u8]>,
{
    fn message(&self) -> Cow<'_, <Ecdsa<Secp256k1> as SignatureScheme>::Message<'_>> {
        match self {
            Self::DeepHash(deep_hash) => Cow::Borrowed(deep_hash.as_slice()),
            Self::Shallow(_) => {
                unreachable!("v1 transaction support RSA signatures only")
            }
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
    #[error("key type '{0}' not supported for operation")]
    UnsupportedKeyType(String),
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
pub type TxAnchor = Typed<TxAnchorKind, Array<u8, U48>>;

impl WithSerde for TxAnchor {}

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

#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize_repr, Deserialize_repr, PartialEq, PartialOrd, Hash)]
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

#[derive(Clone, Debug, PartialEq, Hash)]
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

impl WithSerde for Quantity {}

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

impl WithSerde for Reward {}

impl FromStr for Reward {
    type Err = RewardError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Reward::try_from(s)
    }
}

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
    use crate::chunking::DefaultChunker;
    use crate::crypto::ec::SupportedSecretKey as SupportedEcSecretKey;
    use crate::crypto::keys::SupportedSecretKey;
    use crate::crypto::rsa::SupportedPrivateKey as SupportedRsaPrivateKey;
    use crate::data::{DataRoot, ExternalDataItemAuthenticator};
    use crate::jwk::Jwk;
    use crate::money::{CurrencyExt, Winston};
    use crate::tx::{
        DataItem, ExternalDataItem, Format, Quantity, Reward, SignatureType, Transfer, Tx,
        TxAnchor, TxBuilder, UnauthenticatedTx,
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
        let unauthenticated = UnauthenticatedTx::from_json(TX_V1)?;
        assert!(!unauthenticated.is_authenticated());
        let authenticated = unauthenticated.authenticate().map_err(|(_, e)| e)?;
        assert!(authenticated.is_authenticated());

        assert_eq!(authenticated.format(), Format::V1);

        assert_eq!(
            authenticated.id().to_base64(),
            "BNttzDav3jHVnNiV7nYbQv-GY0HQ-4XXsdkE5K9ylHQ"
        );

        assert_eq!(
            authenticated.signature().signature_type(),
            SignatureType::RsaPss
        );

        assert_eq!(
            authenticated.owner().address().to_base64(),
            "_qa4arkdjK2X9SjechexnWzTtbOKcPkBPhrDDej6lI8"
        );

        match authenticated.data_item() {
            Some(DataItem::Embedded(data)) => {
                assert_eq!(data.len(), 1033478);
            }
            _ => panic!("invalid data"),
        }

        assert_eq!(authenticated.data_item().unwrap().size(), 1033478);

        Ok(())
    }

    #[test]
    fn v1_rountrip() -> anyhow::Result<()> {
        let unauthenticated = UnauthenticatedTx::from_json(TX_V1_2)?;
        let authenticated = unauthenticated.authenticate().map_err(|(_, e)| e)?;
        let json = authenticated.to_json_string()?;
        let unauthenticated = UnauthenticatedTx::from_json(&json)?;
        let authenticated_2 = unauthenticated.authenticate().map_err(|(_, e)| e)?;
        assert_eq!(authenticated, authenticated_2);
        Ok(())
    }

    #[test]
    fn v2() -> anyhow::Result<()> {
        let unauthenticated = UnauthenticatedTx::from_json(TX_V2)?;
        assert!(!unauthenticated.is_authenticated());
        let authenticated = unauthenticated.authenticate().map_err(|(_, e)| e)?;
        assert!(authenticated.is_authenticated());

        assert_eq!(authenticated.format(), Format::V2);

        assert_eq!(
            authenticated.id().to_base64(),
            "bXGqzNQNmHTeL54cUQ6wPo-MO0thLP44FeAoM93kEwk"
        );

        assert_eq!(
            authenticated.signature().signature_type(),
            SignatureType::RsaPss
        );

        assert_eq!(
            authenticated.owner().address().to_base64(),
            "OK_m2Tk41N94KZLl5WQSx_-iNWbvcp8EMfrYsel_QeQ"
        );

        match authenticated.data_item() {
            Some(DataItem::External(data)) => {
                assert_eq!(data.data_size(), 128355);
            }
            _ => panic!("invalid data"),
        }

        Ok(())
    }

    #[test]
    fn v2_rountrip() -> anyhow::Result<()> {
        let unauthenticated = UnauthenticatedTx::from_json(TX_V2_2)?;
        let authenticated = unauthenticated.authenticate().map_err(|(_, e)| e)?;
        let json = authenticated.to_json_string()?;
        let unauthenticated = UnauthenticatedTx::from_json(&json)?;
        let authenticated_2 = unauthenticated.authenticate().map_err(|(_, e)| e)?;
        assert_eq!(authenticated, authenticated_2);
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

        let data = ExternalDataItem::new(data_size, data_root.clone().into());

        let draft = TxBuilder::v2()
            .reward(1234)?
            .tx_anchor(TxAnchor::from_inner([0u8; 48].into()))
            .transfer(Transfer::new(WalletAddress::from_str(target_str)?, 101)?)
            .data_upload((&data).into())
            .draft();

        let authentic_tx = draft.sign(&wallet)?;
        let json = authentic_tx.to_json_string()?;
        let authentic_tx = Tx::from_json(&json)?
            .authenticate()
            .map_err(|(_, err)| err)?;

        assert_eq!(
            authentic_tx.signature().signature_type(),
            SignatureType::RsaPss
        );

        assert_eq!(
            authentic_tx.reward(),
            &Reward::try_from(Winston::from_str("1234")?)?,
        );

        assert_eq!(
            authentic_tx.target(),
            Some(WalletAddress::from_str(target_str)?).as_ref()
        );

        assert_eq!(
            authentic_tx.quantity(),
            Some(Quantity::try_from(Winston::from_str("101")?)?).as_ref()
        );

        let data = match authentic_tx.data_item() {
            Some(DataItem::External(data)) => data,
            _ => panic!("invalid data"),
        };

        assert_eq!(data.data_size(), data_size);
        assert_eq!(data.data_root(), &data_root);

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
            .tx_anchor(TxAnchor::from_inner([0u8; 48].into()))
            .transfer(Transfer::new(WalletAddress::from_str(target_str)?, 2101)?)
            .draft();

        let authentic_tx = draft.sign(&wallet)?;
        let json = authentic_tx.to_json_string()?;
        let authentic_tx = Tx::from_json(&json)?
            .authenticate()
            .map_err(|(_, err)| err)?;

        let owner = authentic_tx.owner();
        let _owner_address = owner.address().to_base64();

        assert_eq!(
            authentic_tx.signature().signature_type(),
            SignatureType::EcdsaSecp256k1
        );

        assert_eq!(
            authentic_tx.reward(),
            &Reward::try_from(Winston::from_str("21234")?)?,
        );

        assert_eq!(
            authentic_tx.target(),
            Some(WalletAddress::from_str(target_str)?).as_ref()
        );

        assert_eq!(
            authentic_tx.quantity(),
            Some(Quantity::try_from(Winston::from_str("2101")?)?).as_ref()
        );

        assert!(authentic_tx.data_item().is_none());

        Ok(())
    }

    #[test]
    fn upload_pss() -> anyhow::Result<()> {
        let wallet = Wallet::from_jwk(&Jwk::from_json(WALLET_RSA_JWK)?)?;

        let data =
            ExternalDataItemAuthenticator::from_single_value(UPLOAD_DATA, DefaultChunker::new());

        let draft = TxBuilder::v2()
            .reward(12345)?
            .tx_anchor(TxAnchor::from_inner([0u8; 48].into()))
            .data_upload(data.data_item().into())
            .draft();

        let authentic_tx = wallet.sign_tx_draft(draft)?;

        assert_eq!(authentic_tx.data_item().unwrap().size(), 683821);
        assert_eq!(
            authentic_tx
                .data_item()
                .unwrap()
                .data()
                .tx_data_root()
                .unwrap()
                .to_base64(),
            "ikHHDmOhqnZ5qsNZ7SOoofuaG66A5yRLsTvacad2NMg"
        );

        let json = authentic_tx.to_json_string()?;
        let authentic_tx = Tx::from_json(&json)?
            .authenticate()
            .map_err(|(_, err)| err)?;

        assert_eq!(authentic_tx.data_item().unwrap().size(), 683821);
        assert_eq!(
            authentic_tx
                .data_item()
                .unwrap()
                .data()
                .tx_data_root()
                .unwrap()
                .to_base64(),
            "ikHHDmOhqnZ5qsNZ7SOoofuaG66A5yRLsTvacad2NMg"
        );

        Ok(())
    }
}
