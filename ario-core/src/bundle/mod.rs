mod read;

use crate::base64::{ToBase64, TryFromBase64, TryFromBase64Error};
use crate::blob::{AsBlob, Blob};
use crate::crypto::ec::ecdsa::Ecdsa;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, HashableExt, Hasher, HasherExt, Sha256, Sha384, TypedDigest};
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::signature::TypedSignature;
use crate::entity::ecdsa::EcdsaSignatureData;
use crate::entity::pss::PssSignatureData;
use crate::entity::{ArEntity, ArEntityHash, Owner, Signature, ToSignPrehash};
use crate::tag::Tag;
use crate::typed::{FromInner, Typed};
use crate::wallet::{WalletAddress, WalletKind};
use crate::{blob, entity};
use bytemuck::TransparentWrapper;
use k256::Secp256k1;
use maybe_owned::MaybeOwned;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use thiserror::Error;

const MAX_ITEM_COUNT: u16 = 4096;
const MAX_ITEM_SIZE: u64 = 1024 * 1024 * 1024 * 50;
const MAX_BUNDLE_SIZE: u64 = 1024 * 1024 * 1024 * 250;
const MAX_TAG_COUNT: u16 = 128;
const MAX_TAG_KEY_SIZE: usize = 1024;
const MAX_TAG_VALUE_SIZE: usize = 3072;

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
    #[error("tag count '{0}' exceeds maximum '{max}'", max = MAX_TAG_COUNT)]
    MaxTagCountExceeded(u16),
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
    #[error("tag key size '{0}' exceeds maximum '{max}'", max = MAX_TAG_KEY_SIZE)]
    MaxKeySizeExceeded(usize),
    #[error("tag value size '{0}' exceeds maximum '{max}'", max = MAX_TAG_VALUE_SIZE)]
    MaxValueSizeExceeded(usize),
    #[error("incorrect tag count; expected '{expected}', actual: '{actual}'")]
    IncorrectTagCount { expected: usize, actual: usize },
    #[error(transparent)]
    AvroDeError(#[from] serde_avro_fast::de::DeError),
}

#[derive(Debug, Clone, PartialEq)]
#[repr(transparent)]
pub struct BundleItem<'a, const VALIDATED: bool = false>(BundleItemInner<'a, VALIDATED>);

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
    fn id(&self) -> &BundleItemId {
        match self {
            Self::V2(v2) => v2.id(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct V2BundleItem<'a, const VALIDATED: bool = false> {
    id: BundleItemId,
    inner: V2BundleItemData<'a>,
}

impl<'a, const VALIDATED: bool> V2BundleItem<'a, VALIDATED> {
    fn id(&self) -> &BundleItemId {
        &self.id
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

pub(crate) type V2BundleItemHash = TypedDigest<BundleItemKind, Sha384>;

#[derive(Clone, Debug, PartialEq, TransparentWrapper)]
#[repr(transparent)]
pub struct BundleItemHash(V2BundleItemHash);

impl ToSignPrehash for BundleItemHash {
    type Hasher = Sha256;

    fn to_sign_prehash(&self) -> MaybeOwned<'_, Digest<Self::Hasher>> {
        self.0.digest().into()
    }
}

impl ArEntityHash for BundleItemHash {}

impl BundleItemHash {
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub(crate) trait BundleItemSignatureScheme:
    entity::SignatureScheme + SupportedSignatureScheme
{
}

impl<T> BundleItemSignatureScheme for T where T: entity::SignatureScheme + SupportedSignatureScheme {}

trait SupportedSignatureScheme {}
impl SupportedSignatureScheme for Ecdsa<Secp256k1> {}
impl SupportedSignatureScheme for RsaPss<4096> {}
impl SupportedSignatureScheme for RsaPss<2048> {}

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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct V2BundleItemData<'a> {
    //id: BundleItemId,
    pub anchor: Option<BundleAnchor>,
    pub tags: Vec<Tag<'a>>,
    pub target: Option<WalletAddress>,
    pub data_size: u64,
    //signature_data: V2SignatureData,
    //hash: Option<V2BundleItemHash>,
    pub data_deep_hash: DataDeepHash,
}

struct BundleItemDataKind;
type DataDeepHash = TypedDigest<BundleItemDataKind, Sha384>;

impl<'a> V2BundleItemData<'a> {
    pub fn hash<H: Hasher>(&self) -> V2BundleItemHash {
        let elements = [
            "dataitem".deep_hash(),
            "1".deep_hash(),
            //self.signature_data.signature_type().deep_hash(),
            //self.signature_data.owner().address().deep_hash(),
            self.target.deep_hash(),
            self.anchor.deep_hash(),
            self.tags.deep_hash(),
            self.data_deep_hash.deref().clone(),
        ];
        V2BundleItemHash::from_inner(<() as DeepHashable>::list(elements))
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Format {
    V2 = 2,
}

impl Format {
    fn as_u8(&self) -> u8 {
        match self {
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
            Self::V2 => b"2",
        })
    }
}

//
// 1: ArweaveSigner
// 2: Curve25519
// 3: EthereumSigner
// 4: HexInjectedSolanaSigner
// 5: InjectedAptosSigner
// 6: MultiSignatureAptosSigner
// 7: TypedEthereumSigner
//
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum SignatureType {
    RsaPss = 1,
    EcdsaSecp256k1 = 3,
}

impl SignatureType {
    fn len(&self) -> usize {
        match self {
            Self::RsaPss => 512,
            Self::EcdsaSecp256k1 => 65,
        }
    }

    fn verifier_len(&self) -> usize {
        match self {
            Self::RsaPss => 512,
            Self::EcdsaSecp256k1 => 65,
        }
    }
}

impl Default for SignatureType {
    fn default() -> Self {
        Self::RsaPss
    }
}

impl AsRef<str> for SignatureType {
    fn as_ref(&self) -> &str {
        match self {
            Self::RsaPss => "1",
            Self::EcdsaSecp256k1 => "3",
        }
    }
}

impl From<SignatureType> for u16 {
    fn from(sig_type: SignatureType) -> Self {
        sig_type as u16
    }
}

impl Display for SignatureType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl TryFrom<u16> for SignatureType {
    type Error = BundleItemError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SignatureType::RsaPss),
            3 => Ok(SignatureType::EcdsaSecp256k1),
            invalid => Err(BundleItemError::InvalidOrUnsupportedSignatureType(
                invalid.to_string(),
            )),
        }
    }
}

impl DeepHashable for SignatureType {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_ref().deep_hash()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum V2SignatureData {
    Pss(PssSignatureData<BundleItemHash>),
    Ecdsa(EcdsaSignatureData<BundleItemHash>),
}

impl V2SignatureData {
    pub(super) fn owner(&self) -> Owner<'_> {
        match self {
            Self::Pss(pss) => pss.owner(),
            Self::Ecdsa(ecdsa) => ecdsa.owner(),
        }
    }

    pub(super) fn signature(&self) -> Signature<'_, BundleItemHash> {
        match self {
            Self::Pss(pss) => pss.signature(),
            Self::Ecdsa(ecdsa) => ecdsa.signature(),
        }
    }

    fn verify_sig(&self, hash: &V2BundleItemHash) -> Result<(), BundleItemError> {
        match self {
            Self::Pss(pss) => Ok(pss.verify_sig(BundleItemHash::wrap_ref(hash))?),
            Self::Ecdsa(ecdsa) => Ok(ecdsa.verify_sig(BundleItemHash::wrap_ref(hash))?),
        }
    }

    fn signature_type(&self) -> SignatureType {
        match self {
            Self::Pss(_) => SignatureType::RsaPss,
            Self::Ecdsa(EcdsaSignatureData::Secp256k1 { .. }) => SignatureType::EcdsaSecp256k1,
        }
    }
}

impl<'a> Signature<'a, BundleItemHash> {
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::Rsa4096(_) => SignatureType::RsaPss,
            Self::Rsa2048(_) => SignatureType::RsaPss,
            Self::Secp256k1(_) => SignatureType::EcdsaSecp256k1,
        }
    }

    pub fn digest(&self) -> BundleItemId {
        match self {
            Self::Rsa4096(pss) => pss.digest(),
            Self::Rsa2048(pss) => pss.digest(),
            Self::Secp256k1(ecdsa) => ecdsa.digest(),
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

pub struct V2Index {
    entries: Vec<V2Entry>,
}

impl V2Index {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn total_size(&self) -> u64 {
        self.entries.last().map(|e| e.offset + e.len).unwrap_or(0)
    }
}

impl FromIterator<(BundleItemId, u64)> for V2Index {
    fn from_iter<T: IntoIterator<Item = (BundleItemId, u64)>>(iter: T) -> Self {
        //let mut idx = 0usize;
        let mut size = 0u64;
        let mut entries = iter
            .into_iter()
            .map(|(id, len)| {
                size = size.saturating_add(len);
                V2Entry {
                    id,
                    offset: size.saturating_sub(len),
                    len,
                }
            })
            .collect::<Vec<_>>();

        let header_len = (32 + (entries.len() * 64)) as u64;

        entries
            .iter_mut()
            .for_each(|e| e.offset = e.offset.saturating_add(header_len));

        // todo: validate

        V2Index { entries }
    }
}

struct V2Entry {
    id: BundleItemId,
    offset: u64,
    len: u64,
}

#[cfg(test)]
mod tests {
    use crate::blob::Blob;
    use crate::bundle::{BundleItemId, SignatureType, V2Index};
    use bytes::Buf;
    use futures_lite::{AsyncReadExt, AsyncSeekExt};
    use std::io::{Cursor, SeekFrom};

    static BUNDLE_1: &'static [u8] =
        include_bytes!("../../testdata/nxoCcgVXf1A3yrMMEXAJpa0YUfgl9EONIKNVR6nr-50.bundle");
    #[tokio::test]
    async fn deserialize_bundle() -> anyhow::Result<()> {
        /*let mut buf = vec![0u8; 1024 * 64];
        let mut reader = futures_lite::io::Cursor::new(BUNDLE_1);
        reader.read_exact(&mut buf[..32]).await?;
        let mut cur = Cursor::new(&buf[..32]);
        let num_entries = cur.get_u32_le() as usize;
        let mut entries = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            reader.read_exact(&mut buf[..32]).await?;
            let mut cur = Cursor::new(&buf[..32]);
            let len = cur.get_u64_le();
            reader.read_exact(&mut buf[..32]).await?;
            let id = BundleItemId::try_from(Blob::Slice(&buf[..32]))?;
            entries.push((id, len));
        }
        let index = entries.into_iter().collect::<V2Index>();

        for entry in &index.entries {
            reader.seek(SeekFrom::Start(entry.offset)).await?;
            reader.read_exact(&mut buf[..2]).await?;
            let mut cur = Cursor::new(&buf[..2]);
            let sig_type: SignatureType = cur.get_u16_le().try_into()?;
            reader.read_exact(&mut buf[..sig_type.len()]).await?;
            let sig_bytes = Vec::from(&buf[..sig_type.len()]);
            reader
                .read_exact(&mut buf[..sig_type.verifier_len()])
                .await?;
            let owner_bytes = Vec::from(&buf[..sig_type.verifier_len()]);
            println!("");
        }

        println!("len: {}, total_size: {}", index.len(), index.total_size());*/
        Ok(())
    }
}
