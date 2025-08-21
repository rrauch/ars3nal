use crate::blob::{AsBlob, Blob, TypedBlob};
use crate::chunking::{Chunker, ChunkerExt, DefaultChunker, MaybeOwnedChunk, TypedChunk};
use crate::crypto::merkle::{DefaultMerkleTree, DefaultProof};
use crate::tx::v2::{DataRoot, MaybeOwnedDataRoot};
use crate::typed::FromInner;
use futures_lite::AsyncRead;
use maybe_owned::MaybeOwned;
use std::ops::Range;
use std::sync::Arc;

pub struct ExternalDataKind;
pub type ChunkedData<C: Chunker> = TypedChunk<ExternalDataKind, C>;
pub type DefaultChunkedData = ChunkedData<DefaultChunker>;
pub type MaybeOwnedDefaultChunkedData<'a> = MaybeOwned<'a, DefaultChunkedData>;

pub type MaybeOwnedExternalData<'a> = MaybeOwned<'a, ExternalData<'a>>;

#[derive(Clone, Debug)]
pub struct VerifiableData<'a> {
    external_data: ExternalData<'a>,
    merkle_tree: Arc<DefaultMerkleTree<'a>>,
}

impl<'a> VerifiableData<'a> {
    pub fn external_data(&self) -> &ExternalData<'_> {
        &self.external_data
    }

    pub fn chunks(&self) -> impl Iterator<Item = &Range<u64>> {
        self.merkle_tree.chunks()
    }

    pub fn proof(&self, range: &Range<u64>) -> Option<&DefaultProof<'_>> {
        if let Some(proof) = self.merkle_tree.proof(range.start) {
            if proof.offset() == range {
                return Some(proof);
            }
        }
        None
    }

    pub fn from_single_value<T: AsBlob>(value: T) -> Self {
        Self::from_iter(
            DefaultChunker::new()
                .single_input(&mut value.as_blob().buf())
                .into_iter()
                .map(|c| MaybeOwnedDefaultChunkedData::from(DefaultChunkedData::from_inner(c))),
        )
    }

    pub async fn try_from_async_reader<T: AsyncRead + Send + Unpin>(
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

impl<'a, I: Into<MaybeOwnedDefaultChunkedData<'a>>> FromIterator<I> for VerifiableData<'a> {
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
            external_data: ExternalData::new(merkle_tree.root().clone(), len),
            merkle_tree: Arc::new(merkle_tree),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExternalData<'a> {
    data_size: u64,
    data_root: MaybeOwnedDataRoot<'a>,
}

impl<'a> ExternalData<'a> {
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

pub struct EmbeddedDataKind;
pub type EmbeddedData<'a> = TypedBlob<'a, EmbeddedDataKind>;

pub type MaybeOwnedEmbeddedData<'a> = MaybeOwned<'a, EmbeddedData<'a>>;

pub enum Data<'a> {
    Embedded(MaybeOwnedEmbeddedData<'a>),
    External(MaybeOwnedExternalData<'a>),
}

impl<'a> Data<'a> {
    pub fn size(&self) -> u64 {
        match self {
            Self::Embedded(d) => d.len() as u64,
            Self::External(d) => d.data_size,
        }
    }

    pub fn as_blob(&self) -> Option<Blob<'_>> {
        match self {
            Self::Embedded(d) => Some(d.as_blob()),
            Self::External(_) => None,
        }
    }

    pub fn data_root(&self) -> Option<&DataRoot> {
        match self {
            Self::Embedded(_) => None,
            Self::External(d) => Some(d.root()),
        }
    }
}
