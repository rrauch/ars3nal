use crate::blob::{AsBlob, Blob, TypedBlob};
use crate::bundle;
use crate::bundle::MaybeOwnedBundledDataItem;
use crate::chunking::{Chunker, ChunkerExt, DefaultChunker, MaybeOwnedChunk, TypedChunk};
use crate::crypto::hash::{Hasher, Sha256};
use crate::crypto::merkle;
use crate::crypto::merkle::{DefaultMerkleRoot, DefaultProof, MerkleRoot, MerkleTree, Proof};
use crate::typed::{FromInner, WithSerde};
use crate::validation::SupportsValidation;
use derive_where::derive_where;
use futures_lite::AsyncRead;
use maybe_owned::MaybeOwned;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::io::Cursor;
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
pub struct AuthenticatableBlob<'a, T, const AUTHENTICATED: bool = false>(TypedBlob<'a, T>);
pub type AuthenticatedBlob<'a, T> = AuthenticatableBlob<'a, T, true>;
pub type UnauthenticatedBlob<'a, T> = AuthenticatableBlob<'a, T, false>;

impl<'a, T, const AUTHENTICATED: bool> AuthenticatableBlob<'a, T, AUTHENTICATED> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a, T> AsBlob for AuthenticatedBlob<'a, T> {
    fn as_blob(&self) -> Blob<'_> {
        self.0.as_blob()
    }
}

impl<T> AsRef<[u8]> for AuthenticatedBlob<'_, T> {
    fn as_ref(&self) -> &[u8] {
        self.0.bytes()
    }
}

impl<'a, T> UnauthenticatedBlob<'a, T> {
    pub(crate) fn from_inner(inner: TypedBlob<'a, T>) -> Self {
        Self(inner)
    }
}

pub struct TxDataKind;

pub type TxDataChunk<'a, const AUTHENTICATED: bool> =
    AuthenticatableBlob<'a, TxDataKind, AUTHENTICATED>;
pub type AuthenticatedTxDataChunk<'a> = TxDataChunk<'a, true>;

impl<'a> AuthenticatedTxDataChunk<'a> {
    pub fn invalidate(self) -> UnauthenticatedTxDataChunk<'a> {
        TxDataChunk::from_inner(self.0)
    }

    pub fn into_inner(self) -> TypedBlob<'a, TxDataKind> {
        self.0
    }
}

pub type UnauthenticatedTxDataChunk<'a> = TxDataChunk<'a, false>;

impl<'a> UnauthenticatedTxDataChunk<'a> {
    #[inline]
    pub fn from_blob(data: Blob<'a>) -> Self {
        Self(TypedBlob::from_inner(data))
    }

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
            .authenticate_data(&mut Cursor::new(self.0.bytes()), &reference.proof)
        {
            return Err((self, err));
        }
        Ok(AuthenticatableBlob(self.0))
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

pub trait Authenticator<DataItem>: Sized {
    type Proof<'a>
    where
        Self: 'a;

    fn chunks(&self) -> impl Iterator<Item = &Range<u64>>;
    fn proof(&self, range: &Range<u64>) -> Option<MaybeOwned<'_, Self::Proof<'_>>>;
}

pub type ExternalDataItemAuthenticator<'a> =
    MerkleDataItemAuthenticator<'a, Sha256, DefaultChunker, 32>;

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
