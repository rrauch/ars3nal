mod v2;

pub use v2::BundleItemDraft;

use crate::base64::{ToBase64, TryFromBase64, TryFromBase64Error};
use crate::blob::{AsBlob, Blob};
use crate::bundle::v2::{
    Bundle as V2Bundle, BundleEntry as V2BundleEntry, BundleItem as V2BundleItem,
    BundleItemDataVerifier as V2BundleItemVerifier, BundleItemProof as V2BundleItemProof,
    MaybeOwnedDataRoot as V2MaybeOwnedDataRoot, SignatureType, V2BundleItemBuilder,
    V2BundleItemHash,
};
use crate::crypto::ec::EcPublicKey;
use crate::crypto::ec::ethereum::{Eip191, Eip712};
use crate::crypto::edwards::multi_aptos::{MultiAptosEd25519, MultiAptosVerifyingKey};
use crate::crypto::edwards::variants::{Aptos, Ed25519HexStr};
use crate::crypto::edwards::{Ed25519, Ed25519VerifyingKey};
use crate::crypto::hash::{HasherExt, Sha256, Sha384, TypedDigest};
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::rsa::{RsaPublicKey, pss};
use crate::crypto::signature::Scheme as SignatureScheme;
use crate::crypto::signature::TypedSignature;
use crate::entity::ecdsa::{Eip191SignatureData, Eip712SignatureData};
use crate::entity::ed25519::{
    AptosSignatureData, Ed25519HexStrSignatureData, Ed25519RegularSignatureData,
};
use crate::entity::multi_aptos::MultiAptosSignatureData;
use crate::entity::pss::Rsa4096SignatureData;
use crate::entity::{
    ArEntity, ArEntityHash, ArEntitySignature, MessageFor, Owner as EntityOwner,
    Signature as EntitySignature,
};
use crate::tag::Tag;
use crate::tx::TxId;
use crate::typed::{FromInner, Typed};
use crate::wallet::{WalletAddress, WalletKind, WalletPk, WalletSk};
use crate::{blob, data, entity};
use futures_lite::AsyncRead;
use k256::Secp256k1;
use maybe_owned::MaybeOwned;
use std::borrow::Cow;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::ops::{Deref, Range};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid header")]
    InvalidHeader,
    #[error("empty bundles are unsupported")]
    EmptyBundle,
    #[error("too many items in bundle: max '{max}', actual '{actual}'")]
    TooManyItems { max: u16, actual: u16 },
    #[error("insufficient number of items in bundle: required '{required}', actual '{actual}'")]
    InsufficientItems { required: u16, actual: u16 },
    #[error("empty items are unsupported")]
    EmptyItem,
    #[error("item exceeds maximum size: max '{max} bytes', actual '{actual} bytes'")]
    ItemExceedsMaxSize { max: u64, actual: u64 },
    #[error("item ID invalid: {0}")]
    InvalidItemId(String),
    #[error("bundle exceeds maximum size: max '{max} bytes', actual '{actual} bytes'")]
    BundleExceedsMaxSize { max: u64, actual: u64 },
    #[error(transparent)]
    BundleItemError(#[from] BundleItemError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum BundleItemError {
    #[error("invalid or unsupported signature type: {0}")]
    InvalidOrUnsupportedSignatureType(String),
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
    #[error("incorrect signature length; expected '{expected}', actual: '{actual}'")]
    IncorrectSignatureLength { expected: usize, actual: usize },
    #[error("incorrect owner length; expected '{expected}', actual: '{actual}'")]
    IncorrectOwnerLength { expected: usize, actual: usize },
    #[error(transparent)]
    IdError(#[from] BundleItemIdError),
    #[error(transparent)]
    EntityError(#[from] entity::Error),
    #[error("invalid wallet address: {0}")]
    InvalidWalletAddress(String),
    #[error("invalid anchor: {0}")]
    InvalidAnchor(String),
    #[error("tag count '{actual}' exceeds maximum '{max}'")]
    MaxTagCountExceeded { max: u16, actual: u16 },
    #[error("tag size '{0}' out of bounds")]
    TagSizeOutOfBounds(u64),
    #[error(transparent)]
    TagError(#[from] TagError),
    #[error("data payload can not be empty")]
    EmptyPayload,
    #[error("bundle item error: {0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum TagError {
    #[error("tag key size '{actual}' exceeds maximum '{max}'")]
    MaxKeySizeExceeded { max: usize, actual: usize },
    #[error("tag value size '{actual}' exceeds maximum '{max}'")]
    MaxValueSizeExceeded { max: usize, actual: usize },
    #[error("incorrect tag count; expected '{expected}', actual: '{actual}'")]
    IncorrectTagCount { expected: usize, actual: usize },
    #[error(transparent)]
    AvroSerError(#[from] serde_avro_fast::ser::SerError),
    #[error(transparent)]
    AvroDeError(#[from] serde_avro_fast::de::DeError),
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Bundle(BundleInner);

pub type BundleId = TxId;

impl Bundle {
    #[inline]
    pub fn read<R: Read>(
        reader: R,
        bundle_type: BundleType,
        bundle_id: BundleId,
    ) -> Result<Self, Error> {
        match bundle_type {
            BundleType::V2 => Ok(Bundle(BundleInner::V2(V2Bundle::read(reader, bundle_id)?))),
        }
    }

    #[inline]
    pub async fn read_async<R: AsyncRead + Unpin>(
        reader: R,
        bundle_type: BundleType,
        bundle_id: BundleId,
    ) -> Result<Self, Error> {
        match bundle_type {
            BundleType::V2 => Ok(Bundle(BundleInner::V2(
                V2Bundle::read_async(reader, bundle_id).await?,
            ))),
        }
    }

    #[inline]
    pub fn id(&self) -> &BundleId {
        match &self.0 {
            BundleInner::V2(b) => b.id(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.0 {
            BundleInner::V2(b) => b.len(),
        }
    }

    #[inline]
    pub fn total_size(&self) -> u64 {
        match &self.0 {
            BundleInner::V2(b) => b.total_size(),
        }
    }

    #[inline]
    pub fn entries(&self) -> impl Iterator<Item = BundleEntry<'_>> {
        match &self.0 {
            BundleInner::V2(b) => b
                .entries()
                .into_iter()
                .map(|e| BundleEntry(BundleEntryInner::V2(e.into()).into())),
        }
    }

    #[inline]
    pub fn bundle_type(&self) -> BundleType {
        match &self.0 {
            BundleInner::V2(_) => BundleType::V2,
        }
    }
}

#[derive(Debug, Clone)]
enum BundleInner {
    V2(V2Bundle),
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct BundleEntry<'a>(MaybeOwned<'a, BundleEntryInner<'a>>);

impl BundleEntry<'_> {
    #[inline]
    fn id(&self) -> &BundleItemId {
        match self.0.deref() {
            BundleEntryInner::V2(e) => &e.id,
        }
    }

    #[inline]
    fn len(&self) -> u64 {
        match self.0.deref() {
            BundleEntryInner::V2(e) => e.len,
        }
    }

    #[inline]
    fn offset(&self) -> u64 {
        match self.0.deref() {
            BundleEntryInner::V2(e) => e.offset,
        }
    }

    #[inline]
    fn into_owned(self) -> BundleEntry<'static> {
        BundleEntry(match self.0.into_owned() {
            BundleEntryInner::V2(e) => BundleEntryInner::V2(e.into_owned().into()).into(),
        })
    }
}

#[derive(Debug, Clone)]
enum BundleEntryInner<'a> {
    V2(MaybeOwned<'a, V2BundleEntry>),
}

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BundleType {
    V2 = 2,
}

impl BundleType {
    /// Detects the `BundleType` based on the supplied transaction `Tag`s.
    ///
    /// Returns: `None` if not a supported bundle type
    pub fn from_tags<'a>(tags: impl IntoIterator<Item = &'a Tag<'a>>) -> Option<BundleType> {
        let mut is_v2 = false;
        let mut is_binary = false;
        tags.into_iter()
            .for_each(|tag| match (tag.name.as_str(), tag.value.as_str()) {
                (Some("Bundle-Version"), Some("2.0.0")) => {
                    is_v2 = true;
                }
                (Some("Bundle-Format"), Some("binary")) => {
                    is_binary = true;
                }
                _ => {}
            });

        if is_v2 && is_binary {
            Some(BundleType::V2)
        } else {
            None
        }
    }

    #[inline]
    fn as_u8(&self) -> u8 {
        match self {
            Self::V2 => 2,
        }
    }
}

impl Display for BundleType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_u8())
    }
}

pub struct BundleItemBuilder;

impl BundleItemBuilder {
    pub fn v2<'a>() -> V2BundleItemBuilder<'a> {
        BundleItemDraft::builder()
    }
}

#[derive(Debug, Clone, PartialEq)]
#[repr(transparent)]
pub struct BundleItem<'a, const VALIDATED: bool = false>(BundleItemInner<'a, VALIDATED>);

impl<'a, const VALIDATED: bool> From<V2BundleItem<'a, VALIDATED>> for BundleItem<'a, VALIDATED> {
    fn from(value: V2BundleItem<'a, VALIDATED>) -> Self {
        Self(BundleItemInner::V2(value))
    }
}

pub type UnvalidatedBundleItem<'a> = BundleItem<'a, false>;
pub type ValidatedBundleItem<'a> = BundleItem<'a, true>;

impl UnvalidatedBundleItem<'static> {
    fn from_inner(
        inner: BundleItemInner<'static, false>,
        expected_id: &BundleItemId,
    ) -> Result<Self, Error> {
        if inner.id() != expected_id {
            return Err(BundleItemError::IdError(BundleItemIdError::IdMismatch {
                expected: expected_id.clone(),
                actual: inner.id().clone(),
            }))?;
        }
        Ok(Self(inner))
    }

    pub fn read<R: Read>(
        reader: R,
        entry: &BundleEntry<'_>,
    ) -> Result<(Self, BundleItemVerifier<'static>), Error> {
        match entry.0.deref() {
            BundleEntryInner::V2(e) => {
                let (item, data_verifier) = V2BundleItem::read(reader, e.len)?;
                let this = Self::from_inner(BundleItemInner::V2(item), entry.id())?;
                Ok((
                    this,
                    BundleItemVerifier(BundleItemVerifierInner::V2(MaybeOwned::Owned(
                        data_verifier,
                    ))),
                ))
            }
        }
    }

    pub async fn read_async<R: AsyncRead + Unpin>(
        reader: R,
        entry: &BundleEntry<'_>,
    ) -> Result<(Self, BundleItemVerifier<'static>), Error> {
        match entry.0.deref() {
            BundleEntryInner::V2(e) => {
                let (item, data_verifier) = V2BundleItem::read_async(reader, e.len).await?;
                let this = Self::from_inner(BundleItemInner::V2(item), entry.id())?;
                Ok((
                    this,
                    BundleItemVerifier(BundleItemVerifierInner::V2(MaybeOwned::Owned(
                        data_verifier,
                    ))),
                ))
            }
        }
    }
}

impl<'a, const VALIDATED: bool> ArEntity for BundleItem<'a, VALIDATED> {
    type Id = BundleItemId;
    type Hash = BundleItemHash;

    fn id(&self) -> &Self::Id {
        self.id()
    }
}

impl<'a, const VALIDATED: bool> BundleItem<'a, VALIDATED> {
    #[inline]
    pub fn id(&self) -> &BundleItemId {
        self.0.id()
    }

    #[inline]
    pub fn data_size(&self) -> u64 {
        self.0.data_size()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum BundleItemInner<'a, const VALIDATED: bool> {
    V2(V2BundleItem<'a, VALIDATED>),
}

impl<'a, const VALIDATED: bool> BundleItemInner<'a, VALIDATED> {
    #[inline]
    fn id(&self) -> &BundleItemId {
        match self {
            Self::V2(v2) => v2.id(),
        }
    }

    #[inline]
    fn data_size(&self) -> u64 {
        match self {
            Self::V2(v2) => v2.data_size(),
        }
    }
}

pub struct BundleItemKind;

pub type BundleItemId = TypedDigest<BundleItemKind, Sha256>;

#[derive(Error, Debug)]
pub enum BundleItemIdError {
    #[error(transparent)]
    Base64Error(#[from] TryFromBase64Error<Infallible>),
    #[error(transparent)]
    BlobError(#[from] blob::Error),
    #[error("id mismatch; expected: '{expected}', actual '{actual}'")]
    IdMismatch {
        expected: BundleItemId,
        actual: BundleItemId,
    },
}

impl FromStr for BundleItemId {
    type Err = BundleItemIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Blob::try_from_base64(s.as_bytes())?;
        Ok(BundleItemId::try_from(bytes)?)
    }
}

impl Display for BundleItemId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_base64().as_str())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum BundleItemHash {
    V2(V2BundleItemHash),
}

impl From<V2BundleItemHash> for BundleItemHash {
    fn from(value: V2BundleItemHash) -> Self {
        Self::V2(value)
    }
}

impl<'a> From<&'a BundleItemHash> for Cow<'a, [u8]> {
    fn from(value: &'a BundleItemHash) -> Self {
        Cow::Borrowed(value.as_slice())
    }
}

impl MessageFor<RsaPss<4096>> for BundleItemHash {
    fn message(&self) -> Cow<'_, <RsaPss<4096> as SignatureScheme>::Message<'_>> {
        Cow::Owned(pss::Message::Regular(
            self.as_slice().as_blob().into_owned(),
        ))
    }
}

impl ArEntityHash for BundleItemHash {}

impl BundleItemHash {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::V2(v2) => v2.as_slice(),
        }
    }
}

pub(crate) trait BundleItemSignatureScheme {
    type SignatureScheme: SignatureScheme;
    type SignatureData: Into<v2::SignatureData>;
    fn signature_type() -> SignatureType;
    fn sign(
        hash: &BundleItemHash,
        signer: &WalletSk<
            <<Self as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer,
        >,
    ) -> Result<Self::SignatureData, BundleItemError>;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct ArweaveScheme;

impl BundleItemSignatureScheme for ArweaveScheme {
    type SignatureScheme = RsaPss<4096>;
    type SignatureData = Rsa4096SignatureData<BundleItemHash>;

    fn signature_type() -> SignatureType {
        SignatureType::RsaPss
    }

    fn sign(
        hash: &BundleItemHash,
        signer: &WalletSk<
            <<Self as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer,
        >,
    ) -> Result<Self::SignatureData, BundleItemError> {
        Ok(Rsa4096SignatureData::<BundleItemHash>::sign(hash, signer)?)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct Ed25519Scheme;

impl BundleItemSignatureScheme for Ed25519Scheme {
    type SignatureScheme = Ed25519;

    type SignatureData = Ed25519RegularSignatureData<BundleItemHash>;

    fn signature_type() -> SignatureType {
        SignatureType::Ed25519
    }

    fn sign(
        hash: &BundleItemHash,
        signer: &WalletSk<
            <<Self as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer,
        >,
    ) -> Result<Self::SignatureData, BundleItemError> {
        Ok(Ed25519RegularSignatureData::<BundleItemHash>::sign(
            hash, signer,
        )?)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct EthereumScheme;

impl BundleItemSignatureScheme for EthereumScheme {
    type SignatureScheme = Eip191;

    type SignatureData = Eip191SignatureData<BundleItemHash>;
    fn signature_type() -> SignatureType {
        SignatureType::Eip191
    }

    fn sign(
        hash: &BundleItemHash,
        signer: &WalletSk<
            <<Self as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer,
        >,
    ) -> Result<Self::SignatureData, BundleItemError> {
        Ok(Eip191SignatureData::<BundleItemHash>::sign(hash, signer)?)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct HexSolanaScheme;

impl BundleItemSignatureScheme for HexSolanaScheme {
    type SignatureScheme = Ed25519HexStr;
    type SignatureData = Ed25519HexStrSignatureData<BundleItemHash>;

    fn signature_type() -> SignatureType {
        SignatureType::Ed25519HexStr
    }

    fn sign(
        hash: &BundleItemHash,
        signer: &WalletSk<
            <<Self as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer,
        >,
    ) -> Result<Self::SignatureData, BundleItemError> {
        Ok(Ed25519HexStrSignatureData::<BundleItemHash>::sign(
            hash, signer,
        )?)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct AptosScheme;

impl BundleItemSignatureScheme for AptosScheme {
    type SignatureScheme = Aptos;
    type SignatureData = AptosSignatureData<BundleItemHash>;
    fn signature_type() -> SignatureType {
        SignatureType::Aptos
    }

    fn sign(
        hash: &BundleItemHash,
        signer: &WalletSk<
            <<Self as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer,
        >,
    ) -> Result<Self::SignatureData, BundleItemError> {
        Ok(AptosSignatureData::<BundleItemHash>::sign(hash, signer)?)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct MultiSigAptosScheme;

impl BundleItemSignatureScheme for MultiSigAptosScheme {
    type SignatureScheme = MultiAptosEd25519;
    type SignatureData = MultiAptosSignatureData<BundleItemHash>;
    fn signature_type() -> SignatureType {
        SignatureType::MultiAptos
    }

    fn sign(
        hash: &BundleItemHash,
        signer: &WalletSk<
            <<Self as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer,
        >,
    ) -> Result<Self::SignatureData, BundleItemError> {
        Ok(MultiAptosSignatureData::<BundleItemHash>::sign(
            hash, signer,
        )?)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct TypedEthereumScheme;

impl BundleItemSignatureScheme for TypedEthereumScheme {
    type SignatureScheme = Eip712;
    type SignatureData = Eip712SignatureData<BundleItemHash>;
    fn signature_type() -> SignatureType {
        SignatureType::Eip712
    }

    fn sign(
        hash: &BundleItemHash,
        signer: &WalletSk<
            <<Self as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer,
        >,
    ) -> Result<Self::SignatureData, BundleItemError> {
        Ok(Eip712SignatureData::<BundleItemHash>::sign(hash, signer)?)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct KyveScheme;

pub type KyveSignatureData = Eip191SignatureData<BundleItemHash, KyveScheme>;

impl BundleItemSignatureScheme for KyveScheme {
    type SignatureScheme = Eip191;
    type SignatureData = KyveSignatureData;
    fn signature_type() -> SignatureType {
        SignatureType::Kyve
    }

    fn sign(
        hash: &BundleItemHash,
        signer: &WalletSk<
            <<Self as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer,
        >,
    ) -> Result<Self::SignatureData, BundleItemError> {
        Ok(KyveSignatureData::sign(hash, signer)?)
    }
}

pub type BundleItemDeepHash = TypedDigest<BundleItemKind, Sha384>;

pub type BundleItemSignature<S: SignatureScheme> = TypedSignature<BundleItemHash, WalletKind, S>;

impl<S: SignatureScheme> BundleItemSignature<S> {
    pub fn digest(&self) -> BundleItemId {
        BundleItemId::from_inner(Sha256::digest(self.as_blob()))
    }
}

pub struct BundleAnchorKind;
pub type BundleAnchor = Typed<BundleAnchorKind, [u8; 32]>;

impl Display for BundleAnchor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_base64().as_str())
    }
}

#[derive(Debug)]
pub enum Owner<'a> {
    Rsa4096(MaybeOwned<'a, WalletPk<RsaPublicKey<4096>>>),
    Secp256k1(MaybeOwned<'a, WalletPk<EcPublicKey<Secp256k1>>>),
    Ed25519(MaybeOwned<'a, WalletPk<Ed25519VerifyingKey>>),
    MultiAptos(MaybeOwned<'a, WalletPk<MultiAptosVerifyingKey>>),
}

impl<'a> From<Owner<'a>> for EntityOwner<'a> {
    #[inline]
    fn from(value: Owner<'a>) -> Self {
        match value {
            Owner::Rsa4096(o) => Self::Rsa4096(o),
            Owner::Secp256k1(o) => Self::Secp256k1(o),
            Owner::Ed25519(o) => Self::Ed25519(o),
            Owner::MultiAptos(o) => Self::MultiAptos(o),
        }
    }
}

impl<'a> TryFrom<EntityOwner<'a>> for Owner<'a> {
    type Error = EntityOwner<'a>;

    #[inline]
    fn try_from(value: EntityOwner<'a>) -> Result<Self, Self::Error> {
        match value {
            EntityOwner::Rsa4096(o) => Ok(Self::Rsa4096(o)),
            EntityOwner::Secp256k1(o) => Ok(Self::Secp256k1(o)),
            EntityOwner::Ed25519(o) => Ok(Self::Ed25519(o)),
            EntityOwner::MultiAptos(o) => Ok(Self::MultiAptos(o)),
            other => Err(other),
        }
    }
}

impl<'a> Owner<'a> {
    #[inline]
    pub fn address(&self) -> WalletAddress {
        match self {
            Self::Rsa4096(inner) => inner.derive_address(),
            Self::Secp256k1(inner) => inner.derive_address(),
            Self::Ed25519(inner) => inner.derive_address(),
            Self::MultiAptos(inner) => inner.derive_address(),
        }
    }
}

impl AsBlob for Owner<'_> {
    #[inline]
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa4096(rsa) => rsa.as_blob(),
            Self::Secp256k1(ec) => ec.as_blob(),
            Self::Ed25519(ed25519) => ed25519.as_blob(),
            Self::MultiAptos(multi) => multi.as_blob(),
        }
    }
}

#[derive(Debug)]
pub enum Signature<'a> {
    Rsa4096(MaybeOwned<'a, ArEntitySignature<BundleItemHash, RsaPss<4096>>>),
    Eip191(MaybeOwned<'a, ArEntitySignature<BundleItemHash, Eip191>>),
    Eip712(MaybeOwned<'a, ArEntitySignature<BundleItemHash, Eip712>>),
    Ed25519(MaybeOwned<'a, ArEntitySignature<BundleItemHash, Ed25519>>),
    Ed25519HexStr(MaybeOwned<'a, ArEntitySignature<BundleItemHash, Ed25519HexStr>>),
    Aptos(MaybeOwned<'a, ArEntitySignature<BundleItemHash, Aptos>>),
    MultiAptos(MaybeOwned<'a, ArEntitySignature<BundleItemHash, MultiAptosEd25519>>),
    Kyve(MaybeOwned<'a, ArEntitySignature<BundleItemHash, Eip191>>),
}

impl<'a> From<Signature<'a>> for EntitySignature<'a, BundleItemHash> {
    #[inline]
    fn from(value: Signature<'a>) -> Self {
        match value {
            Signature::Rsa4096(o) => Self::Rsa4096(o),
            Signature::Eip191(o) => Self::Eip191(o),
            Signature::Eip712(o) => Self::Eip712(o),
            Signature::Ed25519(o) => Self::Ed25519(o),
            Signature::Ed25519HexStr(o) => Self::Ed25519HexStr(o),
            Signature::Aptos(o) => Self::Aptos(o),
            Signature::MultiAptos(o) => Self::MultiAptos(o),
            Signature::Kyve(o) => Self::Kyve(o),
        }
    }
}

impl<'a> TryFrom<EntitySignature<'a, BundleItemHash>> for Signature<'a> {
    type Error = EntitySignature<'a, BundleItemHash>;

    #[inline]
    fn try_from(value: EntitySignature<'a, BundleItemHash>) -> Result<Self, Self::Error> {
        match value {
            EntitySignature::Rsa4096(o) => Ok(Self::Rsa4096(o)),
            EntitySignature::Eip191(o) => Ok(Self::Eip191(o)),
            EntitySignature::Eip712(o) => Ok(Self::Eip712(o)),
            EntitySignature::Ed25519(o) => Ok(Self::Ed25519(o)),
            EntitySignature::Ed25519HexStr(o) => Ok(Self::Ed25519HexStr(o)),
            EntitySignature::Aptos(o) => Ok(Self::Aptos(o)),
            EntitySignature::MultiAptos(o) => Ok(Self::MultiAptos(o)),
            EntitySignature::Kyve(o) => Ok(Self::Kyve(o)),
            other => Err(other),
        }
    }
}

impl AsBlob for Signature<'_> {
    #[inline]
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa4096(pss) => pss.as_blob(),
            Self::Eip191(eip191) => eip191.as_blob(),
            Self::Eip712(eip712) => eip712.as_blob(),
            Self::Ed25519(ed25519) => ed25519.as_blob(),
            Self::Ed25519HexStr(ed25519) => ed25519.as_blob(),
            Self::Aptos(aptos) => aptos.as_blob(),
            Self::MultiAptos(multi) => multi.as_blob(),
            Self::Kyve(kyve) => kyve.as_blob(),
        }
    }
}

impl<'a> Signature<'a> {
    #[inline]
    pub fn digest(&self) -> BundleItemId {
        match self {
            Self::Rsa4096(pss) => pss.digest(),
            Self::Eip191(eip191) => eip191.digest(),
            Self::Eip712(eip712) => eip712.digest(),
            Self::Ed25519(ed25519) => ed25519.digest(),
            Self::Ed25519HexStr(ed25519) => ed25519.digest(),
            Self::Aptos(aptos) => aptos.digest(),
            Self::MultiAptos(multi) => multi.digest(),
            Self::Kyve(kyve) => kyve.digest(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BundledDataItem<'a> {
    data_size: u64,
    data_root: DataRoot<'a>,
}

impl<'a> BundledDataItem<'a> {
    pub fn data_size(&self) -> u64 {
        self.data_size
    }

    pub fn data_root(&self) -> &DataRoot<'a> {
        &self.data_root
    }
}

#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub struct DataRoot<'a>(DataRootInner<'a>);

#[derive(Clone, Debug, PartialEq)]
enum DataRootInner<'a> {
    V2(V2MaybeOwnedDataRoot<'a>),
}

#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct BundleItemVerifier<'a>(BundleItemVerifierInner<'a>);

#[derive(Clone, Debug)]
enum BundleItemVerifierInner<'a> {
    V2(MaybeOwned<'a, V2BundleItemVerifier<'a>>),
}

impl<'a> data::Verifier<BundledDataItem<'a>> for BundleItemVerifier<'a> {
    type Proof<'p>
        = BundleItemDataProof<'p>
    where
        Self: 'p;

    #[inline]
    fn chunks(&self) -> impl Iterator<Item = &Range<u64>> {
        match &self.0 {
            BundleItemVerifierInner::V2(v2) => v2.chunks(),
        }
    }

    #[inline]
    fn proof(&self, range: &Range<u64>) -> Option<MaybeOwned<'_, Self::Proof<'_>>> {
        match &self.0 {
            BundleItemVerifierInner::V2(v2) => v2
                .proof(range)
                .map(|p| BundleItemDataProof(BundleItemDataProofInner::V2(p)).into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub struct BundleItemDataProof<'a>(BundleItemDataProofInner<'a>);

#[derive(Clone, Debug, PartialEq)]
enum BundleItemDataProofInner<'a> {
    V2(MaybeOwned<'a, V2BundleItemProof<'a>>),
}

pub type MaybeOwnedBundledDataItem<'a> = MaybeOwned<'a, BundledDataItem<'a>>;
