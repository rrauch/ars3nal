use crate::blob::{AsBlob, Blob, OwnedBlob};
use crate::bundle::TagError::IncorrectTagCount;
use crate::bundle::v2::reader::FlowExt;
use crate::bundle::v2::reader::item::ItemReader;
use crate::bundle::v2::tag::{from_avro, to_avro};
use crate::bundle::v2::{
    BundleItemChunker, BundleItemDataVerifier, BundleItemHashBuilder, ContainerLocation,
    DataDeepHash, SignatureData, SignatureType, V2BundleItemHash,
};
use crate::bundle::{
    BundleAnchor, BundleId, BundleItemError, BundleItemHash, BundleItemId, BundleItemIdError,
    Error, TagError,
};
use crate::chunking::DefaultChunker;
use crate::crypto::hash::HashableExt;
use crate::tag::Tag;
use crate::validation::{SupportsValidation, Validator};
use crate::wallet::WalletAddress;
use bytes::{BufMut, BytesMut};
use futures_lite::AsyncRead;
use maybe_owned::MaybeOwned;
use std::io::Read;
use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq)]
pub struct BundleItem<'a, const VALIDATED: bool = false> {
    id: BundleItemId,
    bundle_id: BundleId,
    anchor: Option<BundleAnchor>,
    tags: Vec<Tag<'a>>,
    target: Option<WalletAddress>,
    data_size: u64,
    data_offset: u64,
    signature_data: SignatureData,
    hash: BundleItemHash,
}

impl<'a, const VALIDATED: bool> BundleItem<'a, VALIDATED> {
    #[inline]
    pub fn id(&self) -> &BundleItemId {
        &self.id
    }

    #[inline]
    pub fn bundle_id(&self) -> &BundleId {
        &self.bundle_id
    }

    #[inline]
    pub fn anchor(&self) -> Option<&BundleAnchor> {
        self.anchor.as_ref()
    }

    #[inline]
    pub fn tags(&self) -> &Vec<Tag<'a>> {
        &self.tags
    }

    #[inline]
    pub fn target(&self) -> Option<&WalletAddress> {
        self.target.as_ref()
    }

    #[inline]
    pub fn data_size(&self) -> u64 {
        self.data_size
    }

    #[inline]
    pub fn data_offset(&self) -> u64 {
        self.data_offset
    }
}

pub type ValidatedItem<'a> = BundleItem<'a, true>;

impl ValidatedItem<'_> {
    pub fn try_as_blob(&self) -> Result<OwnedBlob, TagError> {
        let tag_data = to_avro(self.tags.iter())?;
        let owner = self.signature_data.owner();
        let signature = self.signature_data.signature();

        let raw = RawBundleItem {
            anchor: self.anchor.as_ref().map(|a| a.as_blob()),
            tag_data,
            tag_count: self.tags.len(),
            target: self.target.as_ref().map(|t| t.as_blob()),
            data_size: self.data_size,
            data_offset: self.data_offset,
            owner: owner.as_blob(),
            signature: signature.as_blob(),
            signature_type: self.signature_data.signature_type(),
            data_deep_hash: DataDeepHash::new_from_inner(b"".digest()), // dummy value
            data_verifier: BundleItemDataVerifier::from_single_value(
                Blob::Slice(b"".as_slice()),
                BundleItemChunker::new(0, DefaultChunker::chunk_map(self.data_size)),
            ), // dummy value
        };

        Ok(raw.as_blob())
    }
}

pub type UnvalidatedItem<'a> = BundleItem<'a, false>;

impl UnvalidatedItem<'static> {
    #[inline]
    pub(super) fn try_from_raw(
        raw: RawBundleItem<'static>,
        bundle_id: BundleId,
    ) -> Result<(Self, BundleItemDataVerifier<'static>), BundleItemError> {
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
        let item = Self {
            id,
            bundle_id,
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
        };

        Ok((item, raw.data_verifier))
    }

    pub(crate) fn read<R: Read>(
        reader: R,
        len: u64,
        container_location: Option<ContainerLocation>,
        bundle_id: BundleId,
    ) -> Result<(Self, BundleItemDataVerifier<'static>), Error> {
        Ok(Self::try_from_raw(
            ItemReader::builder()
                .len(len)
                .maybe_container_location(container_location)
                .build()
                .process(reader)?,
            bundle_id,
        )?)
    }

    pub(crate) async fn read_async<R: AsyncRead + Unpin>(
        reader: R,
        len: u64,
        container_location: Option<ContainerLocation>,
        bundle_id: BundleId,
    ) -> Result<(Self, BundleItemDataVerifier<'static>), Error> {
        Ok(Self::try_from_raw(
            ItemReader::builder()
                .len(len)
                .maybe_container_location(container_location)
                .build()
                .process_async(reader)
                .await?,
            bundle_id,
        )?)
    }
}

impl<'a> SupportsValidation for UnvalidatedItem<'a> {
    type Validated = ValidatedItem<'a>;
    type Validator = BundleItemValidator;

    fn into_valid(self, _token: BundleItemValidationToken) -> Self::Validated {
        ValidatedItem {
            id: self.id,
            bundle_id: self.bundle_id,
            anchor: self.anchor,
            tags: self.tags,
            target: self.target,
            data_size: self.data_size,
            data_offset: self.data_offset,
            signature_data: self.signature_data,
            hash: self.hash,
        }
    }
}

pub struct BundleItemValidator;
pub struct BundleItemValidationToken(PhantomData<()>);

impl Validator<UnvalidatedItem<'_>> for BundleItemValidator {
    type Error = BundleItemError;
    type Token = BundleItemValidationToken;

    fn validate(data: &UnvalidatedItem) -> Result<Self::Token, Self::Error> {
        data.signature_data.verify_sig(&data.hash)?;
        let id = data.signature_data.signature().digest();
        if &id != &data.id {
            return Err(BundleItemError::IdError(BundleItemIdError::IdMismatch {
                expected: id,
                actual: data.id.clone(),
            }))?;
        }
        Ok(BundleItemValidationToken(PhantomData))
    }
}

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
    pub data_verifier: BundleItemDataVerifier<'a>,
}

impl<'a> RawBundleItem<'a> {
    pub fn hash(&self) -> V2BundleItemHash {
        BundleItemHashBuilder::from(self).to_hash()
    }

    pub fn as_blob(&self) -> OwnedBlob {
        let mut buf = BytesMut::with_capacity(2048);

        // header
        buf.put_u16_le(self.signature_type.into());
        buf.extend_from_slice(self.signature.bytes());
        buf.extend_from_slice(self.owner.bytes());
        match self.target.as_ref() {
            Some(target) => {
                buf.put_u8(0x01);
                buf.extend_from_slice(target);
            }
            None => {
                buf.put_u8(0x00);
            }
        }
        match self.anchor.as_ref() {
            Some(anchor) => {
                buf.put_u8(0x01);
                buf.extend_from_slice(anchor);
            }
            None => {
                buf.put_u8(0x00);
            }
        }
        buf.put_u64_le(self.tag_count as u64);
        buf.put_u64_le(self.tag_data.len() as u64);

        // tags
        buf.extend_from_slice(self.tag_data.bytes());

        buf.freeze().into()
    }
}

impl<'a> From<&'a RawBundleItem<'a>> for BundleItemHashBuilder<'a> {
    fn from(raw: &'a RawBundleItem<'a>) -> Self {
        Self {
            owner: Some(raw.owner.as_blob()),
            target: raw.target.as_ref().map(|b| b.as_blob()),
            anchor: raw.anchor.as_ref().map(|b| b.as_blob()),
            tag_data: raw.tag_data.as_blob(),
            data_deep_hash: MaybeOwned::Borrowed(&raw.data_deep_hash),
            signature_type: Some(raw.signature_type),
        }
    }
}
