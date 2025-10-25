use crate::blob::{AsBlob, Blob, TypedBlob};
use crate::buffer::{ByteBuffer, TypedByteBuffer};
use crate::bundle::{
    BundleItemAuthenticator, BundleItemDataProof, BundleItemKind, MaybeOwnedBundledDataItem,
};
use crate::chunking::{ChunkMap, Chunker, ChunkerExt, DefaultChunker, MaybeOwnedChunk, TypedChunk};
use crate::crypto::hash::{Hasher, Sha256};
use crate::crypto::merkle;
use crate::crypto::merkle::{DefaultMerkleRoot, DefaultProof, MerkleRoot, MerkleTree, Proof};
use crate::tx::TxKind;
use crate::typed::{FromInner, WithSerde};
use crate::validation::SupportsValidation;
use crate::{Authenticated, AuthenticationState, Unauthenticated, bundle};
use derive_where::derive_where;
use futures_lite::AsyncRead;
use maybe_owned::MaybeOwned;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Deref, Range};
use std::sync::Arc;

pub type DataRoot = DefaultMerkleRoot;
pub type MaybeOwnedDataRoot<'a> = MaybeOwned<'a, DataRoot>;

pub struct ExternalDataKind;
pub type ChunkedData<C: Chunker> = TypedChunk<ExternalDataKind, C>;
pub type DefaultChunkedData = ChunkedData<DefaultChunker>;
pub type MaybeOwnedDefaultChunkedData<'a> = MaybeOwned<'a, DefaultChunkedData>;
pub type ExternalDataItem<'a> = MerkleAuthenticatableDataItem<'a, Sha256, DefaultChunker, 32>;
pub type MaybeOwnedExternalDataItem<'a> = MaybeOwned<'a, ExternalDataItem<'a>>;

#[derive_where(Clone, PartialEq, Hash, Debug)]
pub struct DataChunk<'a, T, Auth: AuthenticationState = Unauthenticated> {
    data: TypedByteBuffer<'a, T>,
    offset: u64,
    _phantom: PhantomData<Auth>,
}

pub type AuthenticatedDataChunk<'a, T> = DataChunk<'a, T, Authenticated>;
pub type UnauthenticatedDataChunk<'a, T> = DataChunk<'a, T, Unauthenticated>;

impl<'a, T, Auth: AuthenticationState> DataChunk<'a, T, Auth> {
    pub fn len(&self) -> u64 {
        self.data.len()
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn range(&self) -> Range<u64> {
        self.offset..(self.offset + self.len())
    }

    pub fn untagged(self) -> DataChunk<'a, (), Auth>
    where
        T: Untaggable,
    {
        DataChunk {
            data: self.data.clone().cast(),
            offset: self.offset,
            _phantom: PhantomData,
        }
    }
}

trait Untaggable {}
impl Untaggable for TxKind {}
impl Untaggable for BundleItemKind {}

impl<'a, T, Auth: AuthenticationState> From<DataChunk<'a, T, Auth>> for DataChunk<'a, (), Auth>
where
    T: Untaggable,
{
    fn from(value: DataChunk<'a, T, Auth>) -> Self {
        value.untagged()
    }
}

impl<'a, T> AuthenticatedDataChunk<'a, T> {
    pub fn authenticated_data(&self) -> TypedByteBuffer<'a, (T, Authenticated)> {
        TypedByteBuffer::cast(self.data.clone().into_untyped())
    }
}

impl<'a, T> AuthenticatedDataChunk<'a, T> {
    pub fn invalidate(self) -> UnauthenticatedDataChunk<'a, T> {
        UnauthenticatedDataChunk::from_byte_buffer(self.data.into_untyped(), self.offset)
    }

    pub fn into_inner(self) -> TypedByteBuffer<'a, T> {
        self.data
    }
}

impl<'a, T> From<AuthenticatedDataChunk<'a, T>> for UnauthenticatedDataChunk<'a, T> {
    fn from(value: AuthenticatedDataChunk<'a, T>) -> Self {
        value.invalidate()
    }
}

#[cfg(feature = "hazmat")]
pub mod hazmat {
    use crate::Unauthenticated;
    use crate::buffer::TypedByteBuffer;
    use crate::data::UnauthenticatedDataChunk;

    impl<'a, T> UnauthenticatedDataChunk<'a, T> {
        pub fn danger_unauthenticated_data(&self) -> TypedByteBuffer<'a, (T, Unauthenticated)> {
            TypedByteBuffer::cast(self.data.clone().into_untyped())
        }
    }
}

impl<'a, T> UnauthenticatedDataChunk<'a, T> {
    #[inline]
    pub fn from_byte_buffer(data: ByteBuffer<'a>, offset: u64) -> Self {
        Self {
            data: TypedByteBuffer::cast(data).into(),
            offset,
            _phantom: PhantomData,
        }
    }
}

pub type TxDataChunk<'a, Auth: AuthenticationState> = DataChunk<'a, TxKind, Auth>;
pub type AuthenticatedTxDataChunk<'a> = AuthenticatedDataChunk<'a, TxKind>;
pub type UnauthenticatedTxDataChunk<'a> = UnauthenticatedDataChunk<'a, TxKind>;

impl<'a> UnauthenticatedTxDataChunk<'a> {
    #[inline]
    pub fn authenticate(
        self,
        proof: &TxDataAuthenticityProof<'_>,
    ) -> Result<AuthenticatedTxDataChunk<'a>, (Self, merkle::ProofError)> {
        self.validate_with(proof)
    }
}

impl<'a> SupportsValidation for UnauthenticatedTxDataChunk<'a> {
    type Validated = AuthenticatedTxDataChunk<'a>;
    type Error = merkle::ProofError;
    type Reference<'r> = TxDataAuthenticityProof<'r>;

    fn validate_with(
        self,
        reference: &Self::Reference<'_>,
    ) -> Result<Self::Validated, (Self, Self::Error)> {
        if let Err(err) = reference
            .data_root
            .authenticate_data(&mut self.data.cursor(), &reference.proof)
        {
            return Err((self, err));
        }
        Ok(DataChunk {
            data: self.data,
            offset: self.offset,
            _phantom: PhantomData,
        })
    }
}

#[derive(Clone, Debug)]
pub struct TxDataAuthenticityProof<'a> {
    data_root: MaybeOwnedDataRoot<'a>,
    proof: MaybeOwned<'a, DefaultProof<'a>>,
}

impl<'a> TxDataAuthenticityProof<'a> {
    pub fn new(
        data_root: impl Into<MaybeOwnedDataRoot<'a>>,
        proof: impl Into<MaybeOwned<'a, DefaultProof<'a>>>,
    ) -> Self {
        Self {
            data_root: data_root.into(),
            proof: proof.into(),
        }
    }
}

pub type BundleItemDataChunk<'a, Auth: AuthenticationState> = DataChunk<'a, BundleItemKind, Auth>;
pub type AuthenticatedBundleItemDataChunk<'a> = AuthenticatedDataChunk<'a, BundleItemKind>;
pub type UnauthenticatedBundleItemDataChunk<'a> = UnauthenticatedDataChunk<'a, BundleItemKind>;

impl<'a> UnauthenticatedBundleItemDataChunk<'a> {
    #[inline]
    pub fn authenticate(
        self,
        proof: &BundleItemDataAuthenticityProof<'_>,
    ) -> Result<AuthenticatedBundleItemDataChunk<'a>, (Self, bundle::Error)> {
        self.validate_with(proof)
    }
}

impl<'a> SupportsValidation for UnauthenticatedBundleItemDataChunk<'a> {
    type Validated = AuthenticatedBundleItemDataChunk<'a>;
    type Error = bundle::Error;
    type Reference<'r> = BundleItemDataAuthenticityProof<'r>;

    fn validate_with(
        self,
        reference: &Self::Reference<'_>,
    ) -> Result<Self::Validated, (Self, Self::Error)> {
        if let Err(err) = reference
            .authenticator
            .authenticate(&mut self.data.cursor(), &reference.proof)
        {
            return Err((self, err));
        }
        Ok(DataChunk {
            data: self.data,
            offset: self.offset,
            _phantom: PhantomData,
        })
    }
}

#[derive(Clone, Debug)]
pub struct BundleItemDataAuthenticityProof<'a> {
    authenticator: BundleItemAuthenticator<'a>,
    proof: BundleItemDataProof<'a>,
}

impl<'a> BundleItemDataAuthenticityProof<'a> {
    pub fn new(authenticator: BundleItemAuthenticator<'a>, proof: BundleItemDataProof<'a>) -> Self {
        Self {
            authenticator,
            proof,
        }
    }
}

pub trait Authenticator<DataItem>: Sized {
    type Proof<'a>
    where
        Self: 'a;

    fn chunks(&self) -> impl Iterator<Item = &Range<u64>>;
    fn proof(&self, range: &Range<u64>) -> Option<MaybeOwned<'_, Self::Proof<'_>>>;
}

pub type ExternalDataItemAuthenticator<'a> =
    MerkleDataItemAuthenticator<'a, Sha256, DefaultChunker, 32>;

impl<'a, H: Hasher + 'a, C: Chunker, const NOTE_SIZE: usize> ChunkMap
    for MerkleDataItemAuthenticator<'a, H, C, NOTE_SIZE>
where
    MerkleTree<'a, H, C, NOTE_SIZE>: ChunkMap,
    <H as Hasher>::Output: Unpin,
    C: Unpin,
{
    fn len(&self) -> usize {
        self.merkle_tree.len()
    }

    fn size(&self) -> u64 {
        self.merkle_tree.size()
    }

    fn max_chunk_size() -> usize
    where
        Self: Sized,
    {
        <MerkleTree<'a, H, C, NOTE_SIZE> as ChunkMap>::max_chunk_size()
    }

    fn chunk_at(&self, pos: u64) -> Option<Range<u64>> {
        self.merkle_tree.chunk_at(pos)
    }

    fn iter(&self) -> Box<dyn Iterator<Item = Range<u64>> + '_> {
        self.merkle_tree.iter()
    }
}

#[derive_where(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MerkleDataItemAuthenticator<'a, H: Hasher + 'a, C: Chunker, const NOTE_SIZE: usize> {
    data_item: MerkleAuthenticatableDataItem<'a, H, C, NOTE_SIZE>,
    merkle_tree: Arc<MerkleTree<'a, H, C, NOTE_SIZE>>,
}

impl<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize>
    MerkleDataItemAuthenticator<'a, H, C, NOTE_SIZE>
{
    pub fn data_item(&self) -> &MerkleAuthenticatableDataItem<'a, H, C, NOTE_SIZE> {
        &self.data_item
    }

    pub fn max_chunk_size(&self) -> usize {
        C::max_chunk_size()
    }

    pub(crate) fn from_inner(
        data_item: MerkleAuthenticatableDataItem<'a, H, C, NOTE_SIZE>,
        merkle_tree: Arc<MerkleTree<'a, H, C, NOTE_SIZE>>,
    ) -> Self {
        Self {
            data_item,
            merkle_tree,
        }
    }

    pub fn from_single_value<T: AsBlob>(value: T, chunker: C) -> Self {
        Self::from_iter(
            chunker
                .single_input(&mut value.as_blob().buf())
                .into_iter()
                .map(|c| MaybeOwned::from(ChunkedData::from_inner(c))),
        )
    }

    pub async fn try_from_async_reader<T: AsyncRead + Send + Unpin>(
        reader: &mut T,
        chunker: C,
    ) -> std::io::Result<Self> {
        Ok(Self::from_iter(
            chunker
                .try_from_async_reader(reader)
                .await?
                .into_iter()
                .map(|c| MaybeOwned::from(ChunkedData::from_inner(c))),
        ))
    }
}

impl<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize>
    Authenticator<MerkleAuthenticatableDataItem<'a, H, C, NOTE_SIZE>>
    for MerkleDataItemAuthenticator<'a, H, C, NOTE_SIZE>
{
    type Proof<'p>
        = Proof<'p, H, C, NOTE_SIZE>
    where
        Self: 'p;

    fn chunks(&self) -> impl Iterator<Item = &Range<u64>> {
        self.merkle_tree.chunks()
    }

    fn proof(&self, range: &Range<u64>) -> Option<MaybeOwned<'_, Self::Proof<'_>>> {
        if let Some(proof) = self.merkle_tree.proof(range.start) {
            if proof.offset() == range {
                return Some(proof.into());
            }
        }
        None
    }
}

impl<
    'a,
    I: Into<MaybeOwned<'a, ChunkedData<C>>>,
    H: Hasher + 'a,
    C: Chunker,
    const NOTE_SIZE: usize,
> FromIterator<I> for MerkleDataItemAuthenticator<'a, H, C, NOTE_SIZE>
{
    fn from_iter<T: IntoIterator<Item = I>>(iter: T) -> Self {
        let mut len = 0;

        let merkle_tree = MerkleTree::from_iter(iter.into_iter().map(|c| {
            let c = c.into();
            len += c.len();
            match c {
                MaybeOwned::Owned(owned) => MaybeOwnedChunk::from(owned.into_inner()),
                MaybeOwned::Borrowed(borrowed) => MaybeOwnedChunk::from(borrowed.as_ref()),
            }
        }));

        Self {
            data_item: MerkleAuthenticatableDataItem::new(
                len,
                MaybeOwned::Owned(merkle_tree.root().clone()),
            ),
            merkle_tree: Arc::new(merkle_tree),
        }
    }
}

#[derive_where(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MerkleAuthenticatableDataItem<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> {
    data_size: u64,
    data_root: MaybeOwned<'a, MerkleRoot<H, C, NOTE_SIZE>>,
}

impl<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize>
    MerkleAuthenticatableDataItem<'a, H, C, NOTE_SIZE>
{
    pub(crate) fn new(
        data_size: u64,
        data_root: MaybeOwned<'a, MerkleRoot<H, C, NOTE_SIZE>>,
    ) -> Self {
        Self {
            data_root,
            data_size,
        }
    }

    pub fn data_size(&self) -> u64 {
        self.data_size
    }

    pub fn data_root(&self) -> &MerkleRoot<H, C, NOTE_SIZE> {
        self.data_root.deref()
    }
}

pub struct EmbeddedDataItemKind;
pub type EmbeddedDataItem<'a> = TypedBlob<'a, EmbeddedDataItemKind>;

impl<'a> WithSerde for EmbeddedDataItem<'a> {}

pub type MaybeOwnedEmbeddedDataItem<'a> = MaybeOwned<'a, EmbeddedDataItem<'a>>;

pub enum DataItem<'a> {
    Embedded(MaybeOwnedEmbeddedDataItem<'a>),
    External(MaybeOwnedExternalDataItem<'a>),
    Bundled(MaybeOwnedBundledDataItem<'a>),
}

impl<'a> DataItem<'a> {
    #[inline]
    pub fn size(&self) -> u64 {
        match self {
            Self::Embedded(d) => d.len() as u64,
            Self::External(d) => d.data_size,
            Self::Bundled(d) => d.data_size(),
        }
    }

    #[inline]
    pub fn data(&self) -> Data<'_> {
        match self {
            Self::Embedded(d) => DataInner::Embedded(MaybeOwned::Borrowed(d.borrow())).into(),
            Self::External(d) => {
                DataInner::TxDataRoot(Some(MaybeOwned::Borrowed(d.data_root.borrow()))).into()
            }
            Self::Bundled(d) => {
                DataInner::BundleItemDataRoot(Some(MaybeOwned::Borrowed(d.data_root().borrow())))
                    .into()
            }
        }
    }

    #[inline]
    pub fn chunk_map(&self) -> Option<Box<dyn ChunkMap + Send + Sync + Unpin>> {
        match self {
            Self::External(_) => Some(Box::new(DefaultChunker::chunk_map(self.size()))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Data<'a>(DataInner<'a>);

impl<'a> From<DataInner<'a>> for Data<'a> {
    fn from(value: DataInner<'a>) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone)]
enum DataInner<'a> {
    Embedded(MaybeOwnedEmbeddedDataItem<'a>),
    TxDataRoot(Option<MaybeOwnedDataRoot<'a>>),
    BundleItemDataRoot(Option<MaybeOwned<'a, bundle::DataRoot<'a>>>),
}

impl<'a> Data<'a> {
    #[inline]
    pub fn as_blob(&self) -> Option<Blob<'_>> {
        if let DataInner::Embedded(embedded) = &self.0 {
            return Some(embedded.as_blob());
        }
        None
    }

    #[inline]
    pub fn tx_data_root(&self) -> Option<&DataRoot> {
        if let DataInner::TxDataRoot(data_root) = &self.0 {
            return data_root.as_ref().map(|d| d.as_ref());
        }
        None
    }

    #[inline]
    pub fn bundle_data_root(&self) -> Option<&bundle::DataRoot> {
        if let DataInner::BundleItemDataRoot(data_root) = &self.0 {
            return data_root.as_ref().map(|d| d.as_ref());
        }
        None
    }
}
