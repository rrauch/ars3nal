use crate::blob::{AsBlob, Blob, TypedBlob};
use crate::bundle::MaybeOwnedBundledDataItem;
use crate::chunking::{Chunker, ChunkerExt, DefaultChunker, MaybeOwnedChunk, TypedChunk};
use crate::crypto::merkle::{DefaultMerkleRoot, DefaultMerkleTree, DefaultProof};
use crate::typed::FromInner;
use futures_lite::AsyncRead;
use maybe_owned::MaybeOwned;
use std::borrow::Borrow;
use std::ops::Range;
use std::sync::Arc;

pub type DataRoot = DefaultMerkleRoot;
pub type MaybeOwnedDataRoot<'a> = MaybeOwned<'a, DataRoot>;

pub struct ExternalDataKind;
pub type ChunkedData<C: Chunker> = TypedChunk<ExternalDataKind, C>;
pub type DefaultChunkedData = ChunkedData<DefaultChunker>;
pub type MaybeOwnedDefaultChunkedData<'a> = MaybeOwned<'a, DefaultChunkedData>;

pub type MaybeOwnedExternalDataItem<'a> = MaybeOwned<'a, ExternalDataItem<'a>>;

pub trait Verifier<DataItem>: Sized {
    type Proof<'a>
    where
        Self: 'a;

    fn chunks(&self) -> impl Iterator<Item = &Range<u64>>;
    fn proof(&self, range: &Range<u64>) -> Option<&Self::Proof<'_>>;
    fn from_single_value<T: AsBlob>(value: T) -> Self;
    fn try_from_async_reader<T: AsyncRead + Send + Unpin>(
        reader: &mut T,
    ) -> impl Future<Output = std::io::Result<Self>> + Send;
}

#[derive(Clone, Debug)]
pub struct ExternalDataItemVerifier<'a> {
    data_item: ExternalDataItem<'a>,
    merkle_tree: Arc<DefaultMerkleTree<'a>>,
}

impl<'a> ExternalDataItemVerifier<'a> {
    pub fn data_item(&self) -> &ExternalDataItem<'_> {
        &self.data_item
    }
}

impl<'i> Verifier<ExternalDataItem<'i>> for ExternalDataItemVerifier<'i> {
    type Proof<'a>
        = DefaultProof<'a>
    where
        Self: 'a;

    fn chunks(&self) -> impl Iterator<Item = &Range<u64>> {
        self.merkle_tree.chunks()
    }

    fn proof(&self, range: &Range<u64>) -> Option<&Self::Proof<'_>> {
        if let Some(proof) = self.merkle_tree.proof(range.start) {
            if proof.offset() == range {
                return Some(proof);
            }
        }
        None
    }

    fn from_single_value<T: AsBlob>(value: T) -> Self {
        Self::from_iter(
            DefaultChunker::new()
                .single_input(&mut value.as_blob().buf())
                .into_iter()
                .map(|c| MaybeOwnedDefaultChunkedData::from(DefaultChunkedData::from_inner(c))),
        )
    }

    async fn try_from_async_reader<T: AsyncRead + Send + Unpin>(
        reader: &mut T,
    ) -> std::io::Result<Self> {
        Ok(Self::from_iter(
            DefaultChunker::new()
                .try_from_async_reader(reader)
                .await?
                .into_iter()
                .map(|c| MaybeOwnedDefaultChunkedData::from(DefaultChunkedData::from_inner(c))),
        ))
    }
}

impl<'a, I: Into<MaybeOwnedDefaultChunkedData<'a>>> FromIterator<I>
    for ExternalDataItemVerifier<'a>
{
    fn from_iter<T: IntoIterator<Item = I>>(iter: T) -> Self {
        let mut len = 0;

        let merkle_tree = DefaultMerkleTree::from_iter(iter.into_iter().map(|c| {
            let c = c.into();
            len += c.len();
            match c {
                MaybeOwned::Owned(owned) => MaybeOwnedChunk::from(owned.into_inner()),
                MaybeOwned::Borrowed(borrowed) => MaybeOwnedChunk::from(borrowed.as_ref()),
            }
        }));

        Self {
            data_item: ExternalDataItem::new(merkle_tree.root().clone(), len),
            merkle_tree: Arc::new(merkle_tree),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExternalDataItem<'a> {
    data_size: u64,
    data_root: MaybeOwnedDataRoot<'a>,
}

impl<'a> ExternalDataItem<'a> {
    pub fn new(data_root: impl Into<MaybeOwnedDataRoot<'a>>, data_size: u64) -> Self {
        Self {
            data_root: data_root.into(),
            data_size,
        }
    }

    pub fn size(&self) -> u64 {
        self.data_size
    }

    pub fn root(&self) -> &DataRoot {
        &self.data_root
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
    pub fn size(&self) -> u64 {
        match self {
            Self::Embedded(d) => d.len() as u64,
            Self::External(d) => d.data_size,
            Self::Bundled(d) => d.size(),
        }
    }

    pub fn data(&self) -> Data<'_> {
        match self {
            Self::Embedded(d) => DataInner::Embedded(MaybeOwned::Borrowed(d.borrow())).into(),
            Self::External(d) => {
                DataInner::DataRoot(Some(MaybeOwned::Borrowed(d.data_root.borrow()))).into()
            }
            Self::Bundled(_) => DataInner::DataRoot(None).into(),
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
    DataRoot(Option<MaybeOwnedDataRoot<'a>>),
}

impl<'a> Data<'a> {
    pub fn as_blob(&self) -> Option<Blob<'_>> {
        if let DataInner::Embedded(embedded) = &self.0 {
            return Some(embedded.as_blob());
        }
        None
    }

    pub fn data_root(&self) -> Option<&DataRoot> {
        if let DataInner::DataRoot(data_root) = &self.0 {
            return data_root.as_ref().map(|d| d.as_ref());
        }
        None
    }
}
