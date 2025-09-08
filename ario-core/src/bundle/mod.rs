mod v2;

use crate::base64::{ToBase64, TryFromBase64, TryFromBase64Error};
use crate::blob::{AsBlob, Blob};
use crate::bundle::v2::{
    Bundle as V2Bundle, BundleEntry as V2BundleEntry, BundleItem as V2BundleItem, V2BundleItemHash,
};
use crate::crypto::ec::EcPublicKey;
use crate::crypto::ec::ethereum::{Eip191, Eip712};
use crate::crypto::edwards::variants::{Aptos, Ed25519HexStr};
use crate::crypto::edwards::{Ed25519, Ed25519VerifyingKey};
use crate::crypto::hash::{HasherExt, Sha256, Sha384, TypedDigest};
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::rsa::{RsaPublicKey, pss};
use crate::crypto::signature::Scheme as SignatureScheme;
use crate::crypto::signature::TypedSignature;
use crate::entity::{
    ArEntity, ArEntityHash, ArEntitySignature, MessageFor, Owner as EntityOwner,
    Signature as EntitySignature,
};
use crate::tag::Tag;
use crate::tx::TxId;
use crate::typed::{FromInner, Typed};
use crate::wallet::{WalletAddress, WalletKind, WalletPk};
use crate::{blob, entity};
use futures_lite::AsyncRead;
use k256::Secp256k1;
use maybe_owned::MaybeOwned;
use std::borrow::Cow;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::ops::Deref;
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

#[derive(Debug, Clone, PartialEq)]
#[repr(transparent)]
pub struct BundleItem<'a, const VALIDATED: bool = false>(BundleItemInner<'a, VALIDATED>);

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

    pub fn read<R: Read>(reader: R, entry: &BundleEntry<'_>) -> Result<Self, Error> {
        Self::from_inner(
            match entry.0.deref() {
                BundleEntryInner::V2(e) => BundleItemInner::V2(V2BundleItem::read(reader, e.len)?),
            },
            entry.id(),
        )
    }

    pub async fn read_async<R: AsyncRead + Unpin>(
        reader: R,
        entry: &BundleEntry<'_>,
    ) -> Result<Self, Error> {
        Self::from_inner(
            match entry.0.deref() {
                BundleEntryInner::V2(e) => {
                    BundleItemInner::V2(V2BundleItem::read_async(reader, e.len).await?)
                }
            },
            entry.id(),
        )
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
    pub fn id(&self) -> &BundleItemId {
        self.0.id()
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

pub(crate) trait BundleItemSignatureScheme:
    SignatureScheme + SupportedSignatureScheme
{
}

impl<T> BundleItemSignatureScheme for T where T: SignatureScheme + SupportedSignatureScheme {}

trait SupportedSignatureScheme {}
impl SupportedSignatureScheme for Ed25519 {}
impl SupportedSignatureScheme for Ed25519HexStr {}
impl SupportedSignatureScheme for Aptos {}
impl SupportedSignatureScheme for Eip191 {}
impl SupportedSignatureScheme for Eip712 {}
impl SupportedSignatureScheme for RsaPss<4096> {}

pub type BundleItemDeepHash = TypedDigest<BundleItemKind, Sha384>;

pub type BundleItemSignature<S: BundleItemSignatureScheme> =
    TypedSignature<BundleItemHash, WalletKind, S>;

impl<S: BundleItemSignatureScheme> BundleItemSignature<S> {
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
}

impl<'a> From<Owner<'a>> for EntityOwner<'a> {
    #[inline]
    fn from(value: Owner<'a>) -> Self {
        match value {
            Owner::Rsa4096(o) => Self::Rsa4096(o),
            Owner::Secp256k1(o) => Self::Secp256k1(o),
            Owner::Ed25519(o) => Self::Ed25519(o),
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
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BundledDataItem {
    data_size: u64,
}

impl BundledDataItem {
    pub fn size(&self) -> u64 {
        self.data_size
    }
}

pub type MaybeOwnedBundledDataItem<'a> = MaybeOwned<'a, BundledDataItem>;
