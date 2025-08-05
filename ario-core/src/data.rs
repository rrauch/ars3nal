use crate::blob::{AsBlob, Blob, TypedBlob};
use crate::chunking::{Chunker, ChunkerExt, DefaultChunker, MaybeOwnedChunk, TypedChunk};
use crate::crypto::merkle::DefaultMerkleTree;
use crate::tx::v2::DataRoot;
use crate::typed::FromInner;
use maybe_owned::MaybeOwned;

pub struct ExternalDataKind;
pub type ChunkedData<C: Chunker> = TypedChunk<ExternalDataKind, C>;
pub type DefaultChunkedData = ChunkedData<DefaultChunker>;
pub type MaybeOwnedDefaultChunkedData<'a> = MaybeOwned<'a, DefaultChunkedData>;

pub type MaybeOwnedExternalData<'a> = MaybeOwned<'a, ExternalData>;

#[derive(Clone, Debug, PartialEq)]
pub struct ExternalData {
    data_size: u64,
    data_root: DataRoot,
}

impl ExternalData {
    pub fn new(data_root: DataRoot, data_size: u64) -> Self {
        Self {
            data_root,
            data_size,
        }
    }

    pub fn size(&self) -> u64 {
        self.data_size
    }

    pub fn root(&self) -> &DataRoot {
        &self.data_root
    }

    pub fn into_inner(self) -> DataRoot {
        self.data_root
    }
}

impl<'a, I: Into<MaybeOwnedDefaultChunkedData<'a>>> FromIterator<I> for ExternalData {
    fn from_iter<T: IntoIterator<Item = I>>(iter: T) -> Self {
        let mut len = 0;

        let tree = DefaultMerkleTree::from_iter(iter.into_iter().map(|c| {
            let c = c.into();
            len += c.len();
            match c {
                MaybeOwned::Owned(owned) => MaybeOwnedChunk::from(owned.into_inner()),
                MaybeOwned::Borrowed(borrowed) => MaybeOwnedChunk::from(borrowed.as_ref()),
            }
        }));

        Self {
            data_size: len,
            data_root: tree.root().clone(),
        }
    }
}

impl<T: AsBlob> From<T> for ExternalData {
    fn from(value: T) -> Self {
        Self::from_iter(
            DefaultChunker::new()
                .single_input(&mut value.as_blob().buf())
                .into_iter()
                .map(|c| MaybeOwnedDefaultChunkedData::from(DefaultChunkedData::from_inner(c))),
        )
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
