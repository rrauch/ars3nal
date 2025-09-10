use crate::blob::Blob;
use crate::bundle::TagError::IncorrectTagCount;
use crate::bundle::v2::reader::FlowExt;
use crate::bundle::v2::reader::bundle::BundleReader;
use crate::bundle::v2::reader::item::ItemReader;
use crate::bundle::v2::tag::from_avro;
use crate::bundle::{
    BundleAnchor, BundleId, BundleItemError, BundleItemHash, BundleItemId, BundleItemIdError,
    BundleItemKind, Error, Owner, Signature,
};
use crate::chunking::MostlyFixedChunker;
use crate::crypto::ec::ethereum::{EthereumAddress, EthereumPublicKeyExt};
use crate::crypto::edwards::multi_aptos;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hasher, Sha256, Sha384, TypedDigest};
use crate::crypto::merkle::{MerkleRoot, MerkleTree, Proof};
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
use crate::validation::{SupportsValidation, Valid, Validator};
use crate::wallet::WalletAddress;
use futures_lite::AsyncRead;
use maybe_owned::MaybeOwned;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

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
pub(crate) struct Bundle {
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
pub(super) struct BundleEntry {
    pub id: BundleItemId,
    pub offset: u64,
    pub len: u64,
}

pub struct BundleItemValidator;

impl Validator<BundleItemData<'_>> for BundleItemValidator {
    type Error = BundleItemError;

    fn validate(data: &BundleItemData) -> Result<(), Self::Error> {
        data.signature_data.verify_sig(&data.hash)?;
        let id = data.signature_data.signature().digest();
        if &id != &data.id {
            return Err(BundleItemError::IdError(BundleItemIdError::IdMismatch {
                expected: id,
                actual: data.id.clone(),
            }))?;
        }
        Ok(())
    }
}

pub type ValidatedItem<'a> = BundleItem<'a, true>;
pub type UnvalidatedItem<'a> = BundleItem<'a, false>;

impl<'a> SupportsValidation for UnvalidatedItem<'a> {
    type Unvalidated = BundleItemData<'a>;
    type Validated = ValidatedItem<'a>;
    type Validator = BundleItemValidator;

    fn into_valid(self, _token: Valid<Self>) -> Self::Validated
    where
        Self: Sized,
    {
        BundleItem(self.0)
    }

    fn as_unvalidated(&self) -> &Self::Unvalidated {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub(super) struct BundleItem<'a, const VALIDATED: bool = false>(BundleItemData<'a>);

type BundleItemChunker = MostlyFixedChunker<Sha256, DATA_CHUNK_SIZE, DATA_CHUNK_SIZE>;
type BundleItemMerkleRoot = MerkleRoot<Sha256, BundleItemChunker, 32>;
type BundleItemMerkleTree<'a> = MerkleTree<'a, Sha256, BundleItemChunker, 32>;

type DataRoot = BundleItemMerkleRoot;
pub(super) type MaybeOwnedDataRoot<'a> = MaybeOwned<'a, DataRoot>;
pub(super) type BundleItemProof<'a> = Proof<'a, Sha256, BundleItemChunker, 32>;

pub(super) type BundleItemDataVerifier<'a> =
    MerkleDataItemVerifier<'a, Sha256, BundleItemChunker, 32>;

pub(super) type BundleDataItem<'a> = MerkleVerifiableDataItem<'a, Sha256, BundleItemChunker, 32>;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BundleItemData<'a> {
    id: BundleItemId,
    anchor: Option<BundleAnchor>,
    tags: Vec<Tag<'a>>,
    target: Option<WalletAddress>,
    data_size: u64,
    data_offset: u64,
    signature_data: SignatureData,
    hash: BundleItemHash,
}

impl UnvalidatedItem<'static> {
    #[inline]
    fn try_from_raw(
        raw: RawBundleItem<'static>,
    ) -> Result<(Self, BundleItemDataVerifier<'static>), Error> {
        let hash = BundleItemHash::from(raw.hash());
        let signature_data =
            SignatureData::from_raw(raw.signature, raw.owner, &hash, raw.signature_type)?;
        let id = signature_data.signature().digest();
        let tags = from_avro(&raw.tag_data).map_err(BundleItemError::from)?;
        if tags.len() != raw.tag_count {
            return Err(IncorrectTagCount {
                expected: raw.tag_count,
                actual: tags.len(),
            })
            .map_err(BundleItemError::from)?;
        }
        let item = Self(BundleItemData {
            id,
            anchor: raw
                .anchor
                .map(|blob| BundleAnchor::try_from(blob))
                .transpose()
                .map_err(|e| BundleItemError::InvalidAnchor(e.to_string()))?,
            tags,
            target: raw
                .target
                .map(|blob| WalletAddress::try_from(blob))
                .transpose()
                .map_err(|e| BundleItemError::InvalidWalletAddress(e.to_string()))?,
            data_size: raw.data_size,
            signature_data,
            hash,
            data_offset: raw.data_offset,
        });

        Ok((
            item,
            BundleItemDataVerifier::from_inner(
                BundleDataItem::new(
                    raw.data_size,
                    MaybeOwned::Owned(raw.data_merkle_tree.root().clone()),
                ),
                Arc::new(raw.data_merkle_tree),
            ),
        ))
    }

    pub fn read<R: Read>(
        reader: R,
        len: u64,
    ) -> Result<(Self, BundleItemDataVerifier<'static>), Error> {
        Ok(Self::try_from_raw(
            ItemReader::builder().len(len).build().process(reader)?,
        )?)
    }

    pub async fn read_async<R: AsyncRead + Unpin>(
        reader: R,
        len: u64,
    ) -> Result<(Self, BundleItemDataVerifier<'static>), Error> {
        Ok(Self::try_from_raw(
            ItemReader::builder()
                .len(len)
                .build()
                .process_async(reader)
                .await?,
        )?)
    }
}

impl<'a, const VALIDATED: bool> BundleItem<'a, VALIDATED> {
    pub fn id(&self) -> &BundleItemId {
        &self.0.id
    }
}

pub(crate) type V2BundleItemHash = TypedDigest<BundleItemKind, Sha384>;

struct BundleItemDataKind;
type DataDeepHash = TypedDigest<BundleItemDataKind, Sha384>;

struct BundleItemTagsKind;
type TagsDeepHash = TypedDigest<BundleItemTagsKind, Sha384>;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RawBundleItem<'a> {
    pub anchor: Option<Blob<'a>>,
    pub tag_data: Blob<'a>,
    pub tag_count: usize,
    pub target: Option<Blob<'a>>,
    pub data_size: u64,
    pub data_offset: u64,
    pub owner: Blob<'a>,
    pub signature: Blob<'a>,
    pub signature_type: SignatureType,
    pub data_deep_hash: DataDeepHash,
    pub data_merkle_tree: BundleItemMerkleTree<'a>,
}

impl<'a> RawBundleItem<'a> {
    pub fn hash(&self) -> V2BundleItemHash {
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
            self.data_deep_hash.deref().clone(),
        ];
        V2BundleItemHash::from_inner(<() as DeepHashable>::list(elements))
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
enum SignatureData {
    Rsa4096(Rsa4096SignatureData<BundleItemHash>),
    Eip191(Eip191SignatureData<BundleItemHash>),
    Eip712(Eip712SignatureData<BundleItemHash>),
    Ed25519(Ed25519RegularSignatureData<BundleItemHash>),
    Ed25519HexStr(Ed25519HexStrSignatureData<BundleItemHash>),
    Aptos(AptosSignatureData<BundleItemHash>),
    MultiAptos(MultiAptosSignatureData<BundleItemHash>),
    Kyve(Eip191SignatureData<BundleItemHash>),
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

#[cfg(test)]
mod tests {
    use crate::buffer::{BufMutExt, HeapCircularBuffer};
    use crate::bundle::BundleId;
    use crate::bundle::v2::BundleItem;
    use crate::bundle::v2::reader::FlowExt;
    use crate::bundle::v2::reader::bundle::BundleReader;
    use crate::data::Verifier;
    use crate::validation::ValidateExt;
    use futures_lite::{AsyncReadExt, AsyncSeekExt};
    use std::io::SeekFrom;
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::LazyLock;

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
                            entry.offset + item.0.data_offset + chunk.start,
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
}
