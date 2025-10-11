use crate::blob::{AsBlob, Blob, OwnedBlob};
use crate::bundle::TagError::IncorrectTagCount;
use crate::bundle::v2::reader::item::ItemReader;
use crate::bundle::v2::reader::{Flow, FlowExt};
use crate::bundle::v2::tag::{from_avro, to_avro};
use crate::bundle::v2::{
    BundleItemChunker, BundleItemDataAuthenticator, BundleItemHashBuilder, ContainerLocation,
    DataDeepHash, SignatureData, SignatureType, V2BundleItemHash,
};
use crate::bundle::{
    BundleAnchor, BundleId, BundleItemError, BundleItemHash, BundleItemId, BundleItemIdError,
    Error, Owner, TagError,
};
use crate::chunking::DefaultChunker;
use crate::crypto::hash::HashableExt;
use crate::tag::Tag;
use crate::validation::SupportsValidation;
use crate::wallet::WalletAddress;
use crate::{Authenticated, AuthenticationState, ItemId, Unauthenticated};
use bytes::{BufMut, BytesMut};
use futures_lite::AsyncRead;
use itertools::Itertools;
use maybe_owned::MaybeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::Read;
use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq, Hash)]
#[repr(transparent)]
pub struct BundleItem<'a, Auth: AuthenticationState = Unauthenticated>(
    BundleItemInner<'a>,
    PhantomData<Auth>,
);

#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
struct BundleItemInner<'a> {
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

impl<'a, Auth: AuthenticationState> BundleItem<'a, Auth> {
    #[inline]
    pub fn id(&self) -> &BundleItemId {
        &self.0.id
    }

    #[inline]
    pub fn bundle_id(&self) -> &BundleId {
        &self.0.bundle_id
    }

    #[inline]
    pub fn anchor(&self) -> Option<&BundleAnchor> {
        self.0.anchor.as_ref()
    }

    #[inline]
    pub fn tags(&self) -> &Vec<Tag<'a>> {
        &self.0.tags
    }

    #[inline]
    pub fn target(&self) -> Option<&WalletAddress> {
        self.0.target.as_ref()
    }

    #[inline]
    pub fn data_size(&self) -> u64 {
        self.0.data_size
    }

    #[inline]
    pub fn data_offset(&self) -> u64 {
        self.0.data_offset
    }

    #[inline]
    pub fn owner(&self) -> Owner<'_> {
        self.0.signature_data.owner()
    }

    pub fn into_owned(self) -> BundleItem<'static, Auth> {
        BundleItem(
            BundleItemInner {
                id: self.0.id,
                bundle_id: self.0.bundle_id,
                anchor: self.0.anchor,
                tags: self
                    .0
                    .tags
                    .into_iter()
                    .map(|t| t.into_owned())
                    .collect_vec(),
                target: self.0.target.clone(),
                data_size: self.0.data_size,
                data_offset: self.0.data_size,
                signature_data: self.0.signature_data,
                hash: self.0.hash,
            },
            PhantomData,
        )
    }
}

pub type AuthenticatedItem<'a> = BundleItem<'a, Authenticated>;

impl AuthenticatedItem<'_> {
    pub fn try_as_blob(&self) -> Result<OwnedBlob, TagError> {
        let tag_data = to_avro(self.0.tags.iter())?;
        let owner = self.0.signature_data.owner();
        let signature = self.0.signature_data.signature();

        let raw = RawBundleItem {
            anchor: self.0.anchor.as_ref().map(|a| a.as_blob()),
            tag_data,
            tag_count: self.0.tags.len(),
            target: self.0.target.as_ref().map(|t| t.as_blob()),
            data_size: self.0.data_size,
            data_offset: self.0.data_offset,
            owner: owner.as_blob(),
            signature: signature.as_blob(),
            signature_type: self.0.signature_data.signature_type(),
            data_deep_hash: DataDeepHash::new_from_inner(b"".digest()), // dummy value
            data_verifier: BundleItemDataAuthenticator::from_single_value(
                Blob::Slice(b"".as_slice()),
                BundleItemChunker::align(
                    DefaultChunker::chunk_map(self.0.data_size),
                    0,
                    None,
                ),
            ), // dummy value
        };

        Ok(raw.as_blob())
    }
}

impl<'a> AuthenticatedItem<'a> {
    pub fn invalidate(self) -> UnauthenticatedItem<'a> {
        BundleItem(self.0, PhantomData)
    }
}

pub type UnauthenticatedItem<'a> = BundleItem<'a, Unauthenticated>;

impl<'a, Auth: AuthenticationState> Serialize for BundleItem<'a, Auth> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, 'a> Deserialize<'de> for UnauthenticatedItem<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(
            BundleItemInner::deserialize(deserializer)?,
            PhantomData,
        ))
    }
}

impl UnauthenticatedItem<'static> {
    #[inline]
    pub(super) fn try_from_raw(
        raw: RawBundleItem<'static>,
        bundle_id: BundleId,
    ) -> Result<(Self, BundleItemDataAuthenticator<'static>), BundleItemError> {
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
        let item = Self(
            BundleItemInner {
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
            },
            PhantomData,
        );

        Ok((item, raw.data_verifier))
    }

    pub(crate) fn read<R: Read>(
        reader: R,
        len: u64,
        container_location: Option<ContainerLocation>,
        bundle_id: BundleId,
    ) -> Result<(Self, BundleItemDataAuthenticator<'static>), Error> {
        Self::_read::<_, true>(reader, len, container_location, bundle_id)
    }

    pub(crate) fn read_unauthenticated<R: Read>(
        reader: R,
        len: u64,
        container_location: Option<ContainerLocation>,
        bundle_id: BundleId,
    ) -> Result<Self, Error> {
        Self::_read::<_, false>(reader, len, container_location, bundle_id).map(|(item, _)| item)
    }

    fn _read<R: Read, const PROCESS_DATA: bool>(
        reader: R,
        len: u64,
        container_location: Option<ContainerLocation>,
        bundle_id: BundleId,
    ) -> Result<(Self, BundleItemDataAuthenticator<'static>), Error>
    where
        ItemReader<PROCESS_DATA>: Flow<Output = RawBundleItem<'static>>,
    {
        Ok(Self::try_from_raw(
            ItemReader::<PROCESS_DATA>::builder()
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
    ) -> Result<(Self, BundleItemDataAuthenticator<'static>), Error> {
        Self::_read_async::<_, true>(reader, len, container_location, bundle_id).await
    }

    pub(crate) async fn read_async_unauthenticated<R: AsyncRead + Unpin>(
        reader: R,
        len: u64,
        container_location: Option<ContainerLocation>,
        bundle_id: BundleId,
    ) -> Result<Self, Error> {
        Self::_read_async::<_, false>(reader, len, container_location, bundle_id)
            .await
            .map(|(item, _)| item)
    }

    async fn _read_async<R: AsyncRead + Unpin, const PROCESS_DATA: bool>(
        reader: R,
        len: u64,
        container_location: Option<ContainerLocation>,
        bundle_id: ItemId,
    ) -> Result<(Self, BundleItemDataAuthenticator<'static>), Error>
    where
        ItemReader<PROCESS_DATA>: Flow<Output = RawBundleItem<'static>>,
    {
        Ok(Self::try_from_raw(
            ItemReader::<PROCESS_DATA>::builder()
                .len(len)
                .maybe_container_location(container_location)
                .build()
                .process_async(reader)
                .await?,
            bundle_id,
        )?)
    }
}

impl<'a> SupportsValidation for UnauthenticatedItem<'a> {
    type Validated = AuthenticatedItem<'a>;
    type Error = BundleItemError;
    type Reference<'r> = ();

    fn validate_with(
        self,
        _: &Self::Reference<'_>,
    ) -> Result<Self::Validated, (Self, Self::Error)> {
        if let Err(err) = self.0.signature_data.verify_sig(&self.0.hash) {
            return Err((self, err));
        }
        let id = self.0.signature_data.signature().digest();
        if &id != &self.0.id {
            let actual = self.0.id.clone();
            return Err((
                self,
                BundleItemError::IdError(BundleItemIdError::IdMismatch {
                    expected: id,
                    actual,
                }),
            ));
        }
        Ok(BundleItem(self.0, PhantomData))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub data_verifier: BundleItemDataAuthenticator<'a>,
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
