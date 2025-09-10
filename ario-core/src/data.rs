use crate::blob::{AsBlob, Blob, TypedBlob};
use crate::bundle;
use crate::bundle::MaybeOwnedBundledDataItem;
use crate::chunking::{Chunker, ChunkerExt, DefaultChunker, MaybeOwnedChunk, TypedChunk};
use crate::crypto::hash::{Hasher, Sha256};
use crate::crypto::merkle::{DefaultMerkleRoot, MerkleRoot, MerkleTree, Proof};
use crate::typed::FromInner;
use derive_where::derive_where;
use futures_lite::AsyncRead;
use maybe_owned::MaybeOwned;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::ops::{Deref, Range};
use std::sync::Arc;

pub type DataRoot = DefaultMerkleRoot;
pub type MaybeOwnedDataRoot<'a> = MaybeOwned<'a, DataRoot>;

pub struct ExternalDataKind;
pub type ChunkedData<C: Chunker> = TypedChunk<ExternalDataKind, C>;
pub type DefaultChunkedData = ChunkedData<DefaultChunker>;
pub type MaybeOwnedDefaultChunkedData<'a> = MaybeOwned<'a, DefaultChunkedData>;
pub type ExternalDataItem<'a> = MerkleVerifiableDataItem<'a, Sha256, DefaultChunker, 32>;
pub type MaybeOwnedExternalDataItem<'a> = MaybeOwned<'a, ExternalDataItem<'a>>;

pub trait Verifier<DataItem>: Sized {
    type Proof<'a>
    where
        Self: 'a;

    fn chunks(&self) -> impl Iterator<Item = &Range<u64>>;
    fn proof(&self, range: &Range<u64>) -> Option<MaybeOwned<'_, Self::Proof<'_>>>;
}

pub type ExternalDataItemVerifier<'a> = MerkleDataItemVerifier<'a, Sha256, DefaultChunker, 32>;

#[derive_where(Clone, Debug)]
pub struct MerkleDataItemVerifier<'a, H: Hasher + 'a, C: Chunker, const NOTE_SIZE: usize> {
    data_item: MerkleVerifiableDataItem<'a, H, C, NOTE_SIZE>,
    merkle_tree: Arc<MerkleTree<'a, H, C, NOTE_SIZE>>,
}

impl<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize>
    MerkleDataItemVerifier<'a, H, C, NOTE_SIZE>
{
    pub fn data_item(&self) -> &MerkleVerifiableDataItem<'a, H, C, NOTE_SIZE> {
        &self.data_item
    }

    pub fn max_chunk_size(&self) -> usize {
        C::max_chunk_size()
    }

    pub(crate) fn from_inner(
        data_item: MerkleVerifiableDataItem<'a, H, C, NOTE_SIZE>,
        merkle_tree: Arc<MerkleTree<'a, H, C, NOTE_SIZE>>,
    ) -> Self {
        Self {
            data_item,
            merkle_tree,
        }
    }

    pub fn from_single_value<T: AsBlob>(value: T) -> Self {
        Self::from_iter(
            C::new()
                .single_input(&mut value.as_blob().buf())
                .into_iter()
                .map(|c| MaybeOwned::from(ChunkedData::from_inner(c))),
        )
    }

    pub async fn try_from_async_reader<T: AsyncRead + Send + Unpin>(
        reader: &mut T,
    ) -> std::io::Result<Self> {
        Ok(Self::from_iter(
            C::new()
                .try_from_async_reader(reader)
                .await?
                .into_iter()
                .map(|c| MaybeOwned::from(ChunkedData::from_inner(c))),
        ))
    }
}

impl<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize>
    Verifier<MerkleVerifiableDataItem<'a, H, C, NOTE_SIZE>>
    for MerkleDataItemVerifier<'a, H, C, NOTE_SIZE>
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
> FromIterator<I> for MerkleDataItemVerifier<'a, H, C, NOTE_SIZE>
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
            data_item: MerkleVerifiableDataItem::new(
                len,
                MaybeOwned::Owned(merkle_tree.root().clone()),
            ),
            merkle_tree: Arc::new(merkle_tree),
        }
    }
}

#[derive_where(Clone, Debug, PartialEq)]
pub struct MerkleVerifiableDataItem<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> {
    data_size: u64,
    data_root: MaybeOwned<'a, MerkleRoot<H, C, NOTE_SIZE>>,
}

impl<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize>
    MerkleVerifiableDataItem<'a, H, C, NOTE_SIZE>
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
