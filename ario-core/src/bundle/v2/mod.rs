pub use item::BundleItem;

use crate::blob::{AsBlob, Blob};
use crate::buffer::{BufMutExt, HeapCircularBuffer};
use crate::bundle::v2::item::RawBundleItem;
use crate::bundle::v2::reader::FlowExt;
use crate::bundle::v2::reader::bundle::BundleReader;
use crate::bundle::v2::tag::to_avro;
use crate::bundle::{
    BundleAnchor, BundleId, BundleItemError, BundleItemHash, BundleItemId, BundleItemKind,
    BundleItemSignatureScheme, Error, KyveSignatureData, Owner, Signature,
};
use crate::chunking::{Chunk, Chunker, MostlyFixedChunker};
use crate::crypto::ec::ethereum::{EthereumAddress, EthereumPublicKeyExt};
use crate::crypto::edwards::multi_aptos;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hasher, Sha256, Sha384, TypedDigest, deep_hash};
use crate::crypto::keys::SecretKey;
use crate::crypto::merkle::{MerkleRoot, MerkleTree, Proof};
use crate::crypto::signature::Scheme as SignatureScheme;
use crate::data::{MerkleDataItemVerifier, MerkleVerifiableDataItem};
use crate::entity;
use crate::entity::ecdsa::{Eip191SignatureData, Eip712SignatureData};
use crate::entity::ed25519::{
    AptosSignatureData, Ed25519HexStrSignatureData, Ed25519RegularSignatureData,
};
use crate::entity::multi_aptos::MultiAptosSignatureData;
use crate::entity::pss::{PssSignatureData, Rsa4096SignatureData};
use crate::tag::Tag;
use crate::typed::FromInner;
use crate::validation::ValidateExt;
use crate::wallet::{WalletAddress, WalletSk};
use bon::Builder;
use bytes::Buf;
use futures_lite::AsyncRead;
use maybe_owned::MaybeOwned;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

mod item;
mod reader;
mod tag;

const MAX_ITEM_COUNT: u16 = 4096;
const MAX_ITEM_SIZE: u64 = 1024 * 1024 * 1024 * 50;
const MAX_BUNDLE_SIZE: u64 = 1024 * 1024 * 1024 * 250;
const MAX_TAG_COUNT: u16 = 128;
const MAX_TAG_KEY_SIZE: usize = 1024;
const MAX_TAG_VALUE_SIZE: usize = 3072;

const DATA_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Bundle {
    id: BundleId,
    entries: Vec<BundleEntry>,
}

impl Bundle {
    #[inline]
    pub fn read<R: Read>(reader: R, bundle_id: BundleId) -> Result<Self, Error> {
        Ok(BundleReader::builder()
            .id(bundle_id)
            .build()
            .process(reader)?)
    }

    #[inline]
    pub async fn read_async<R: AsyncRead + Unpin>(
        reader: R,
        bundle_id: BundleId,
    ) -> Result<Self, Error> {
        Ok(BundleReader::builder()
            .id(bundle_id)
            .build()
            .process_async(reader)
            .await?)
    }

    #[inline]
    pub fn id(&self) -> &BundleId {
        &self.id
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn total_size(&self) -> u64 {
        self.entries.last().map(|e| e.offset + e.len).unwrap_or(0)
    }

    #[inline]
    pub fn entries(&self) -> impl Iterator<Item = &BundleEntry> {
        self.entries.iter()
    }
}

#[derive(Debug, Clone)]
pub struct BundleEntry {
    id: BundleItemId,
    offset: u64,
    len: u64,
}

impl BundleEntry {
    #[inline]
    pub fn id(&self) -> &BundleItemId {
        &self.id
    }

    #[inline]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    #[inline]
    pub fn len(&self) -> u64 {
        self.len
    }
}

#[derive(Builder, Clone, Debug)]
#[builder(
    builder_type(
      name = V2BundleItemBuilder,
      vis = "pub",
    ),
    derive(Clone, Debug),
    finish_fn(
      vis = "",
      name = build_internal,
    )
)]
pub struct BundleItemDraft<'a> {
    #[builder(default)]
    tags: Vec<Tag<'a>>,
    #[builder(skip = Blob::Slice(&[]))]
    tags_blob: Blob<'a>,
    anchor: Option<BundleAnchor>,
    target: Option<WalletAddress>,
    #[builder(into)]
    data_upload: MaybeOwned<'a, ProcessedDataItem>,
}

impl<'a, S: v2_bundle_item_builder::IsComplete> V2BundleItemBuilder<'a, S> {
    pub fn draft(self) -> Result<BundleItemDraft<'a>, BundleItemError> {
        let mut draft = self.build_internal();
        draft.tags_blob = to_avro(&draft.tags)?;
        Ok(draft)
    }
}

impl BundleItemDraft<'_> {
    pub(crate) fn sign<S: BundleItemSignatureScheme>(
        self,
        signer: &WalletSk<
            <<S as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer,
        >,
    ) -> Result<super::ValidatedBundleItem<'static>, BundleItemError>
    where
        WalletSk<<<S as BundleItemSignatureScheme>::SignatureScheme as SignatureScheme>::Signer>:
            BundleItemSigner<S>,
    {
        let signature_data = signer.sign(&self)?;
        let owner = signature_data.owner();
        let signature = signature_data.signature();

        let mut raw = RawBundleItem {
            anchor: self.anchor.as_ref().map(|a| a.as_blob().into_owned()),
            tag_data: self.tags_blob.into_owned(),
            tag_count: self.tags.len(),
            target: self.target.as_ref().map(|t| t.as_blob().into_owned()),
            data_size: self.data_upload.data_verifier.data_item().data_size(),
            data_offset: 0,
            owner: owner.as_blob().into_owned(),
            signature: signature.as_blob().into_owned(),
            signature_type: signature_data.signature_type(),
            data_deep_hash: self.data_upload.data_deep_hash.clone(),
            data_verifier: self.data_upload.data_verifier.clone(),
        };

        let serialized = raw.as_blob();
        raw.data_offset = serialized.len() as u64;

        let (unvalidated, _) = BundleItem::try_from_raw(raw)?;
        let validated = unvalidated.validate().map_err(|(_, e)| e)?;

        Ok(super::ValidatedBundleItem::from(validated))
    }
}

struct BundleItemHashBuilder<'a> {
    owner: Option<Blob<'a>>,
    target: Option<Blob<'a>>,
    anchor: Option<Blob<'a>>,
    tag_data: Blob<'a>,
    data_deep_hash: MaybeOwned<'a, DataDeepHash>,
    signature_type: Option<SignatureType>,
}

impl<'a> BundleItemHashBuilder<'a> {
    pub fn to_hash(&self) -> V2BundleItemHash {
        let elements = [
            "dataitem".deep_hash(),
            "1".deep_hash(),
            self.signature_type.deep_hash(),
            self.owner.deep_hash(),
            self.target.deep_hash(),
            self.anchor.deep_hash(),
            // careful: this differs from how tx's hash tags
            // bundle v2 requires the exact avro-serialized byte representation
            self.tag_data.deep_hash(),
            self.data_deep_hash.as_ref().deref().clone(),
        ];
        V2BundleItemHash::from_inner(<() as DeepHashable>::list(elements))
    }
}

impl<'a> From<&'a BundleItemDraft<'a>> for BundleItemHashBuilder<'a> {
    fn from(draft: &'a BundleItemDraft<'a>) -> Self {
        Self {
            owner: None,
            signature_type: None,
            target: draft.target.as_ref().map(|a| a.as_blob()),
            anchor: draft.anchor.as_ref().map(|a| a.as_blob()),
            tag_data: (&draft.tags_blob).as_blob(),
            data_deep_hash: MaybeOwned::Borrowed(&draft.data_upload.data_deep_hash),
        }
    }
}

trait BundleItemSigner<S> {
    fn sign(&self, data: &BundleItemDraft) -> Result<SignatureData, BundleItemError>;
}

impl<SK: SecretKey, S> BundleItemSigner<S> for WalletSk<SK>
where
    S: BundleItemSignatureScheme,
    <S as BundleItemSignatureScheme>::SignatureScheme: SignatureScheme<Signer = SK>,
{
    fn sign(&self, data: &BundleItemDraft) -> Result<SignatureData, BundleItemError> {
        let pk = self.public_key_impl().clone();
        let pk_blob = pk.as_blob();
        let mut hash_builder = BundleItemHashBuilder::from(data);
        hash_builder.owner = Some(pk_blob);
        hash_builder.signature_type = Some(S::signature_type());
        let hash = BundleItemHash::V2(hash_builder.to_hash());

        Ok(<S as BundleItemSignatureScheme>::sign(&hash, self)?.into())
    }
}

#[derive(Debug, Clone)]
pub struct ProcessedDataItem {
    data_deep_hash: DataDeepHash,
    data_verifier: BundleItemDataVerifier<'static>,
}

impl ProcessedDataItem {
    pub fn verifier(&self) -> super::BundleItemVerifier<'static> {
        self.data_verifier.clone().into()
    }
}

pub struct BundleItemDataProcessor {
    chunker: BundleItemChunker,
    chunks: Vec<Chunk<BundleItemChunker>>,
    hasher: Sha384,
    processed: u64,
}

impl BundleItemDataProcessor {
    pub(crate) fn new() -> Self {
        Self {
            chunker: BundleItemChunker::new(),
            chunks: vec![],
            hasher: Sha384::new(),
            processed: 0,
        }
    }

    pub(crate) fn update(&mut self, input: &mut impl Buf) {
        while input.has_remaining() {
            let chunk = input.chunk();
            self.hasher.update(chunk);
            self.chunks
                .extend(self.chunker.update(&mut std::io::Cursor::new(chunk)));
            self.processed += chunk.len() as u64;
            input.advance(chunk.len());
        }
    }

    pub(crate) fn finalize(mut self) -> ProcessedDataItem {
        let hash = self.hasher.finalize();
        let data_deep_hash =
            DataDeepHash::new_from_inner(deep_hash::from_data_digest(&hash, self.processed));
        self.chunks.extend(self.chunker.finalize());
        let merkle_tree = BundleItemMerkleTree::from_iter(self.chunks.drain(..));
        let data_item = BundleDataItem::new(self.processed, merkle_tree.root().clone().into());
        let data_verifier = BundleItemDataVerifier::from_inner(data_item, Arc::new(merkle_tree));
        ProcessedDataItem {
            data_deep_hash,
            data_verifier,
        }
    }

    pub fn from_single_value<T: AsBlob>(value: T) -> ProcessedDataItem {
        let mut this = Self::new();
        this.update(&mut value.as_blob().buf());
        this.finalize()
    }

    pub async fn try_from_async_reader<T: AsyncRead + Send + Unpin>(
        reader: &mut T,
    ) -> std::io::Result<ProcessedDataItem> {
        let mut this = Self::new();
        let mut buf = HeapCircularBuffer::new(1024 * 64);
        loop {
            buf.reset();
            if buf.fill_async(&mut *reader).await? == 0 {
                break;
            }
            this.update(&mut buf);
        }
        Ok(this.finalize())
    }

    pub fn try_from_reader<T: Read>(reader: &mut T) -> std::io::Result<ProcessedDataItem> {
        let mut this = Self::new();
        let mut buf = HeapCircularBuffer::new(1024 * 64);
        loop {
            buf.reset();
            if buf.fill(&mut *reader)? == 0 {
                break;
            }
            this.update(&mut buf);
        }
        Ok(this.finalize())
    }
}

//
// taken from https://github.com/ar-io/arbundles/blob/master/src/constants.ts
//
//   1: ArweaveSigner
//   2: Curve25519
//   3: EthereumSigner
//   4: HexInjectedSolanaSigner
//   5: InjectedAptosSigner
//   6: MultiSignatureAptosSigner
//   7: TypedEthereumSigner
// 101: KYVE
//
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum SignatureType {
    RsaPss = 1,
    Ed25519 = 2,
    Eip191 = 3,
    Ed25519HexStr = 4,
    Aptos = 5,
    MultiAptos = 6,
    Eip712 = 7,
    Kyve = 101,
}

impl SignatureType {
    fn len(&self) -> usize {
        match self {
            Self::RsaPss => 512,
            Self::Ed25519 => 64,
            Self::Eip191 => 65,
            Self::Ed25519HexStr => 64,
            Self::Aptos => 64,
            Self::MultiAptos => multi_aptos::SERIALIZED_SIGS_SIZE,
            Self::Eip712 => 65,
            Self::Kyve => 65,
        }
    }

    fn verifier_len(&self) -> usize {
        match self {
            Self::RsaPss => 512,
            Self::Ed25519 => 32,
            Self::Eip191 => 65,
            Self::Ed25519HexStr => 32,
            Self::Aptos => 32,
            Self::MultiAptos => multi_aptos::SERIALIZED_OWNERS_SIZE,
            Self::Eip712 => 42,
            Self::Kyve => 65,
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
            Self::Ed25519 => "2",
            Self::Eip191 => "3",
            Self::Ed25519HexStr => "4",
            Self::Aptos => "5",
            Self::MultiAptos => "6",
            Self::Eip712 => "7",
            Self::Kyve => "101",
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
            2 => Ok(SignatureType::Ed25519),
            3 => Ok(SignatureType::Eip191),
            4 => Ok(SignatureType::Ed25519HexStr),
            5 => Ok(SignatureType::Aptos),
            6 => Ok(SignatureType::MultiAptos),
            7 => Ok(SignatureType::Eip712),
            101 => Ok(SignatureType::Kyve),
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

impl<'a> Signature<'a> {
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::Rsa4096(_) => SignatureType::RsaPss,
            Self::Ed25519(_) => SignatureType::Ed25519,
            Self::Eip191(_) => SignatureType::Eip191,
            Self::Ed25519HexStr(_) => SignatureType::Ed25519HexStr,
            Self::Aptos(_) => SignatureType::Aptos,
            Self::MultiAptos(_) => SignatureType::MultiAptos,
            Self::Eip712(_) => SignatureType::Eip712,
            Self::Kyve(_) => SignatureType::Kyve,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum SignatureData {
    Rsa4096(Rsa4096SignatureData<BundleItemHash>),
    Eip191(Eip191SignatureData<BundleItemHash>),
    Eip712(Eip712SignatureData<BundleItemHash>),
    Ed25519(Ed25519RegularSignatureData<BundleItemHash>),
    Ed25519HexStr(Ed25519HexStrSignatureData<BundleItemHash>),
    Aptos(AptosSignatureData<BundleItemHash>),
    MultiAptos(MultiAptosSignatureData<BundleItemHash>),
    Kyve(KyveSignatureData),
}

impl From<Rsa4096SignatureData<BundleItemHash>> for SignatureData {
    fn from(value: Rsa4096SignatureData<BundleItemHash>) -> Self {
        Self::Rsa4096(value)
    }
}

impl From<Eip191SignatureData<BundleItemHash>> for SignatureData {
    fn from(value: Eip191SignatureData<BundleItemHash>) -> Self {
        Self::Eip191(value)
    }
}

impl From<Eip712SignatureData<BundleItemHash>> for SignatureData {
    fn from(value: Eip712SignatureData<BundleItemHash>) -> Self {
        Self::Eip712(value)
    }
}

impl From<Ed25519RegularSignatureData<BundleItemHash>> for SignatureData {
    fn from(value: Ed25519RegularSignatureData<BundleItemHash>) -> Self {
        Self::Ed25519(value)
    }
}

impl From<Ed25519HexStrSignatureData<BundleItemHash>> for SignatureData {
    fn from(value: Ed25519HexStrSignatureData<BundleItemHash>) -> Self {
        Self::Ed25519HexStr(value)
    }
}

impl From<AptosSignatureData<BundleItemHash>> for SignatureData {
    fn from(value: AptosSignatureData<BundleItemHash>) -> Self {
        Self::Aptos(value)
    }
}

impl From<MultiAptosSignatureData<BundleItemHash>> for SignatureData {
    fn from(value: MultiAptosSignatureData<BundleItemHash>) -> Self {
        Self::MultiAptos(value)
    }
}

impl From<KyveSignatureData> for SignatureData {
    fn from(value: KyveSignatureData) -> Self {
        Self::Kyve(value)
    }
}

impl SignatureData {
    #[inline]
    pub(super) fn from_raw<'a>(
        raw_signature: Blob<'a>,
        raw_owner: Blob<'a>,
        hash: &BundleItemHash,
        signature_type: SignatureType,
    ) -> Result<Self, BundleItemError> {
        match signature_type {
            SignatureType::RsaPss => Ok(SignatureData::Rsa4096(PssSignatureData::from_raw(
                raw_owner,
                raw_signature,
            )?)),
            SignatureType::Eip191 => Ok(SignatureData::Eip191(Eip191SignatureData::from_raw(
                raw_signature,
                raw_owner,
            )?)),
            SignatureType::Eip712 => {
                let sig_data = Eip712SignatureData::recover_from_raw(raw_signature, hash)?;

                // raw_owner is supposed to be a string representing the ethereum address of the owner
                let expected_address =
                    EthereumAddress::from_str(str::from_utf8(raw_owner.bytes()).map_err(|e| {
                        BundleItemError::Other(format!(
                            "expected owner to be a string, but parsing failed: {}",
                            e
                        ))
                    })?)
                    .map_err(|e| {
                        BundleItemError::Other(format!(
                            "expected owner to be an ethereum address, but parsing failed: {}",
                            e
                        ))
                    })?;

                let actual_address = if let entity::Owner::Secp256k1(pk) = sig_data.owner() {
                    pk.to_ethereum_address()
                } else {
                    return Err(BundleItemError::Other("expected recovered owner to be a secp256k1 public key, but got something else".to_string()));
                };

                if &expected_address != &actual_address {
                    return Err(BundleItemError::Other(format!(
                        "Ethereum address of owner [{}] does not match recovered address [{}]",
                        expected_address, actual_address
                    )));
                }

                Ok(SignatureData::Eip712(sig_data))
            }
            SignatureType::Ed25519 => Ok(SignatureData::Ed25519(
                Ed25519RegularSignatureData::from_raw(raw_signature, raw_owner)?,
            )),
            SignatureType::Ed25519HexStr => Ok(SignatureData::Ed25519HexStr(
                Ed25519HexStrSignatureData::from_raw(raw_signature, raw_owner)?,
            )),
            SignatureType::Aptos => Ok(SignatureData::Aptos(AptosSignatureData::from_raw(
                raw_signature,
                raw_owner,
            )?)),
            SignatureType::MultiAptos => Ok(SignatureData::MultiAptos(
                MultiAptosSignatureData::from_raw(raw_signature, raw_owner)?,
            )),
            SignatureType::Kyve => Ok(SignatureData::Kyve(Eip191SignatureData::from_raw(
                raw_signature,
                raw_owner,
            )?)),
        }
    }

    #[inline]
    pub(super) fn owner(&self) -> Owner<'_> {
        match self {
            Self::Rsa4096(pss) => pss.owner().try_into().expect("owner conversion to succeed"),
            Self::Eip191(eip191) => eip191
                .owner()
                .try_into()
                .expect("owner conversion to succeed"),
            Self::Eip712(eip712) => eip712
                .owner()
                .try_into()
                .expect("owner conversion to succeed"),
            Self::Ed25519(ed25519) => ed25519
                .owner()
                .try_into()
                .expect("owner conversion to succeed"),
            Self::Ed25519HexStr(ed25519) => ed25519
                .owner()
                .try_into()
                .expect("owner conversion to succeed"),
            Self::Aptos(aptos) => aptos
                .owner()
                .try_into()
                .expect("owner conversion to succeed"),
            Self::MultiAptos(multi) => multi
                .owner()
                .try_into()
                .expect("owner conversion to succeed"),
            Self::Kyve(kyve) => kyve
                .owner()
                .try_into()
                .expect("owner conversion to succeed"),
        }
    }

    #[inline]
    pub(super) fn signature(&self) -> Signature<'_> {
        match self {
            Self::Rsa4096(pss) => pss
                .signature()
                .try_into()
                .expect("signature conversion to succeed"),
            Self::Eip191(eip191) => eip191
                .signature()
                .try_into()
                .expect("signature conversion to succeed"),
            Self::Eip712(eip712) => eip712
                .signature()
                .try_into()
                .expect("signature conversion to succeed"),
            Self::Ed25519(ed25519) => ed25519
                .signature()
                .try_into()
                .expect("signature conversion to succeed"),
            Self::Ed25519HexStr(ed25519) => ed25519
                .signature()
                .try_into()
                .expect("signature conversion to succeed"),
            Self::Aptos(aptos) => aptos
                .signature()
                .try_into()
                .expect("signature conversion to succeed"),
            Self::MultiAptos(multi) => multi
                .signature()
                .try_into()
                .expect("signature conversion to succeed"),
            Self::Kyve(kvye) => kvye
                .signature()
                .try_into()
                .expect("signature conversion to succeed"),
        }
    }

    #[inline]
    fn verify_sig(&self, hash: &BundleItemHash) -> Result<(), BundleItemError> {
        match self {
            Self::Rsa4096(pss) => Ok(pss.verify_sig(hash)?),
            Self::Eip191(eip191) => Ok(eip191.verify_sig(hash)?),
            Self::Eip712(eip712) => Ok(eip712.verify_sig(hash)?),
            Self::Ed25519(ed25519) => Ok(ed25519.verify_sig(hash)?),
            Self::Ed25519HexStr(ed25519) => Ok(ed25519.verify_sig(hash)?),
            Self::Aptos(aptos) => Ok(aptos.verify_sig(hash)?),
            Self::MultiAptos(multi) => Ok(multi.verify_sig(hash)?),
            Self::Kyve(kyve) => Ok(kyve.verify_sig(hash)?),
        }
    }

    #[inline]
    fn signature_type(&self) -> SignatureType {
        match self {
            Self::Rsa4096(_) => SignatureType::RsaPss,
            Self::Eip191(_) => SignatureType::Eip191,
            Self::Eip712(_) => SignatureType::Eip712,
            Self::Ed25519(_) => SignatureType::Ed25519,
            Self::Ed25519HexStr(_) => SignatureType::Ed25519HexStr,
            Self::Aptos(_) => SignatureType::Aptos,
            Self::MultiAptos(_) => SignatureType::MultiAptos,
            Self::Kyve(_) => SignatureType::Kyve,
        }
    }
}

pub(crate) type V2BundleItemHash = TypedDigest<BundleItemKind, Sha384>;

struct BundleItemDataKind;
type DataDeepHash = TypedDigest<BundleItemDataKind, Sha384>;

struct BundleItemTagsKind;
type TagsDeepHash = TypedDigest<BundleItemTagsKind, Sha384>;

type BundleItemChunker = MostlyFixedChunker<Sha256, DATA_CHUNK_SIZE, DATA_CHUNK_SIZE>;
pub(super) type BundleItemMerkleRoot = MerkleRoot<Sha256, BundleItemChunker, 32>;
pub(super) type BundleItemMerkleTree<'a> = MerkleTree<'a, Sha256, BundleItemChunker, 32>;

pub type DataRoot = BundleItemMerkleRoot;
pub(super) type MaybeOwnedDataRoot<'a> = MaybeOwned<'a, DataRoot>;
pub type BundleItemProof<'a> = Proof<'a, Sha256, BundleItemChunker, 32>;

pub type BundleItemDataVerifier<'a> = MerkleDataItemVerifier<'a, Sha256, BundleItemChunker, 32>;

pub type BundleDataItem<'a> = MerkleVerifiableDataItem<'a, Sha256, BundleItemChunker, 32>;

#[cfg(test)]
mod tests {
    use crate::buffer::{BufMutExt, HeapCircularBuffer};
    use crate::bundle::v2::reader::FlowExt;
    use crate::bundle::v2::reader::bundle::BundleReader;
    use crate::bundle::v2::{BundleItem, BundleItemDataProcessor};
    use crate::bundle::{BundleId, BundleItemBuilder, Ed25519Scheme};
    use crate::data::Verifier;
    use crate::jwk::Jwk;
    use crate::validation::ValidateExt;
    use crate::wallet::Wallet;
    use bytes::BytesMut;
    use futures_lite::{AsyncReadExt, AsyncSeekExt};
    use std::io::SeekFrom;
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::LazyLock;

    static ONE_MB: &'static [u8] = include_bytes!("../../../testdata/1mb.bin");

    static BUNDLE_0: &'static [u8] = include_bytes!("../../../testdata/bundle.bundle");

    static BUNDLE_0_ID: LazyLock<BundleId> = LazyLock::new(|| {
        BundleId::from_str("BNttzDav3jHVnNiV7nYbQv-GY0HQ-4XXsdkE5K9ylHQ").unwrap()
    });

    static BUNDLE_1: &'static [u8] =
        include_bytes!("../../../testdata/nxoCcgVXf1A3yrMMEXAJpa0YUfgl9EONIKNVR6nr-50.bundle");

    static BUNDLE_1_ID: LazyLock<BundleId> = LazyLock::new(|| {
        BundleId::from_str("nxoCcgVXf1A3yrMMEXAJpa0YUfgl9EONIKNVR6nr-50").unwrap()
    });

    static BUNDLE_3: &'static [u8] =
        include_bytes!("../../../testdata/Gz9dZaqN2I7AWT0vWGZWi5wlMjbImh13SOIomthyB6M.bundle");

    static BUNDLE_3_ID: LazyLock<BundleId> = LazyLock::new(|| {
        BundleId::from_str("Gz9dZaqN2I7AWT0vWGZWi5wlMjbImh13SOIomthyB6M").unwrap()
    });

    static WALLET_ED25519_JWK: &'static [u8] =
        include_bytes!("../../../testdata/ar_wallet_tests_Ed25519_fixture.json");

    #[tokio::test]
    async fn deserialize_bundle() -> anyhow::Result<()> {
        for (bundle_data, bundle_id) in [
            (BUNDLE_1, BUNDLE_1_ID.deref()),
            (BUNDLE_3, BUNDLE_3_ID.deref()),
        ] {
            let mut input = futures_lite::io::Cursor::new(bundle_data);

            let bundle = BundleReader::builder()
                .id(bundle_id.clone())
                .build()
                .process_async(&mut input)
                .await?;

            for entry in bundle.entries {
                input.seek(SeekFrom::Start(entry.offset)).await?;
                let (item, data_verifier) = BundleItem::read_async(&mut input, entry.len).await?;
                let item = item.validate().map_err(|(_, e)| e)?;
                assert_eq!(item.id(), &entry.id);
                let data_root = data_verifier.data_item().data_root();
                let mut buf = HeapCircularBuffer::new(data_verifier.max_chunk_size());

                // verify content
                for chunk in data_verifier.chunks() {
                    input
                        .seek(SeekFrom::Start(
                            entry.offset + item.data_offset() + chunk.start,
                        ))
                        .await?;
                    buf.reset();
                    let mut reader = input.take(chunk.end - chunk.start);
                    buf.fill_async(&mut reader).await?;
                    input = reader.into_inner();

                    let proof = data_verifier.proof(chunk).unwrap();
                    data_root
                        .verify_data(&mut std::io::Cursor::new(buf.make_contiguous()), &proof)?;
                }
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn build_bundle_item() -> anyhow::Result<()> {
        let wallet = Wallet::from_jwk(&Jwk::from_json(WALLET_ED25519_JWK)?)?;

        let data = BundleItemDataProcessor::from_single_value(ONE_MB);

        let draft = BundleItemBuilder::v2()
            .data_upload((&data).into())
            .draft()?;

        let valid_item = wallet.sign_bundle_item_draft::<Ed25519Scheme>(draft)?;

        assert_eq!(
            valid_item.id().to_string(),
            "FTxzaw_jnVmU3LKOrkmBQ29Mhu9cFWQkhelsI4ZY1y8"
        );
        assert_eq!(valid_item.data_size(), ONE_MB.len() as u64);

        let v2_item = match valid_item {
            super::super::BundleItem::V2(v2) => v2,
        };
        let serialized = v2_item.try_as_blob()?;
        let mut buf = BytesMut::with_capacity(serialized.bytes().len() + ONE_MB.len());
        buf.extend_from_slice(serialized.bytes());
        buf.extend_from_slice(ONE_MB);
        let bytes = buf.freeze();
        let len = bytes.len() as u64;
        let (unvalidated, _) = BundleItem::read(&mut std::io::Cursor::new(&bytes), len)?;
        let item = unvalidated.validate().map_err(|(_, e)| e)?;
        assert_eq!(item.id(), v2_item.id());

        let data_verifier = &data.data_verifier;
        let data_root = data.data_verifier.data_item().data_root();
        let mut input = &mut futures_lite::io::Cursor::new(&bytes);
        let mut buf = HeapCircularBuffer::new(data_verifier.max_chunk_size());
        // verify content
        for chunk in data_verifier.chunks() {
            input
                .seek(SeekFrom::Start(item.data_offset() + chunk.start))
                .await?;
            buf.reset();
            let mut reader = input.take(chunk.end - chunk.start);
            buf.fill_async(&mut reader).await?;
            input = reader.into_inner();

            let proof = data_verifier.proof(chunk).unwrap();
            data_root.verify_data(&mut std::io::Cursor::new(buf.make_contiguous()), &proof)?;
        }

        Ok(())
    }
}
