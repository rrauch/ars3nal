use crate::location::{Arl, TxArl};
use crate::tx::Offset;
use crate::{Client, location};
use ario_core::buffer::{OwnedTypedByteBufferCursor, TypedByteBuffer};
use ario_core::bundle::{
    AuthenticatedBundleItem, BundleEntry, BundleItem, BundleItemAuthenticator, BundleItemId,
    UnauthenticatedBundleItem,
};
use ario_core::chunking::DefaultChunker;
use ario_core::data::{
    AuthenticatedDataChunk, AuthenticatedTxDataChunk, Authenticator,
    BundleItemDataAuthenticityProof, BundleItemDataKind, DataChunk, DataItem, DataRoot,
    TxDataChunk, TxDataKind, UnauthenticatedBundleItemDataChunk, UnauthenticatedDataChunk,
};
use ario_core::tx::{AuthenticatedTx, Tx, TxId};
use ario_core::{Authenticated, AuthenticationState, Item, MaybeOwned, Unauthenticated};
use bytemuck::TransparentWrapper;
use bytes::Buf;
use futures_concurrency::future::FutureGroup;
use futures_lite::{AsyncRead, AsyncSeek, StreamExt};
use futures_lite::{FutureExt, ready};
use itertools::Itertools;
use rangemap::RangeMap;
use std::cmp::min;
use std::io::{ErrorKind, Seek, SeekFrom};
use std::iter;
use std::marker::PhantomData;
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("tx '{0}' does not have a data item")]
    NoDataItem(TxId),
    #[error("tx '{0}' not found")]
    TxNotFound(TxId),
    #[error("bundle_item '{0}' not found")]
    BundleItemNotFound(BundleItemId),
    #[error("maximum data item nesting depth exceeded: {got} > {max}")]
    MaxNestingDepthExceeded { max: usize, got: usize },
    #[error("unsupported data item")]
    UnsupportedDataItem,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("data authentication failed: {0}")]
    DataAuthenticationFailure(String),
    #[error("chunk not found or out of bounds")]
    ChunkNotFound,
}

#[derive(Clone, Debug, TransparentWrapper)]
#[repr(transparent)]
struct Chunk(Range<u64>);

impl From<Range<u64>> for Chunk {
    fn from(value: Range<u64>) -> Self {
        Self(value)
    }
}

impl Chunk {
    pub fn len(&self) -> u64 {
        self.0.end - self.0.start
    }

    pub fn offset(&self) -> u64 {
        self.0.start
    }

    pub fn contains(&self, pos: u64) -> bool {
        pos >= self.0.start && pos < self.0.end
    }

    pub fn overlaps(&self, range: &Range<u64>) -> bool {
        self.0.start < range.end && range.start < self.0.end
    }

    pub fn range(&self) -> &Range<u64> {
        &self.0
    }
}

#[repr(transparent)]
struct ChunkIterator<'a>(Box<dyn Iterator<Item = &'a Chunk> + 'a>);
impl<'a> Iterator for ChunkIterator<'a> {
    type Item = &'a Chunk;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<'a> ChunkIterator<'a> {
    fn new(iter: impl Iterator<Item = &'a Chunk> + 'a) -> Self {
        Self(Box::new(iter))
    }
}

pub trait DataReader: AsyncRead + AsyncSeek + Send + Unpin {
    fn len(&self) -> u64;

    fn item(&self) -> Item<'static, Authenticated>;
}

impl<'a, D: ChunkSource<Authenticated>> DataReader for ChunkReader<D> {
    fn len(&self) -> u64 {
        self.len
    }

    fn item(&self) -> Item<'static, Authenticated> {
        self.data_source.item()
    }
}

pub type DataItemReader = ChunkReader<DynChunkSource<Authenticated>>;

impl Client {
    pub async fn read_data_item<'a, L: Into<Arl>>(
        &self,
        location: L,
    ) -> Result<DataItemReader, super::Error> {
        let location = location.into();
        let item = self
            .item_by_location(&location)
            .await?
            .ok_or_else(|| location::Error::NotFound)?;

        self.data_item_reader(item, location).await
    }

    pub(crate) async fn data_item_reader(
        &self,
        item: Item<'static, Authenticated>,
        location: Arl,
    ) -> Result<DataItemReader, super::Error> {
        let item_id = item.id();
        if location.item_id() != &item_id {
            Err(location::Error::ItemMismatch {
                expected: item_id,
                actual: location.item_id().clone(),
            })?;
        }

        let locations = iter::successors(location.parent(), |p| p.parent())
            .chain(iter::once(location))
            .collect_vec();

        if locations.len() > 16 {
            Err(Error::MaxNestingDepthExceeded {
                max: 16,
                got: locations.len(),
            })?;
        }

        let mut iter = locations.iter().peekable();

        let mut intermediate_source: Option<DynChunkSource<Unauthenticated>> = None;

        while let Some(location) = iter.next() {
            if iter.peek().is_none() {
                // final item
                return Ok(ChunkReader::new(
                    Authenticated::new_source(&self, location, intermediate_source.take()).await?,
                ));
            } else {
                // intermediate item
                intermediate_source = Some(
                    Unauthenticated::new_source(&self, location, intermediate_source.take())
                        .await?,
                );
            }
        }

        unreachable!("locations must not be empty")
    }
}

trait NewSource: AuthenticationState {
    async fn new_source(
        client: &Client,
        location: &Arl,
        parent: Option<DynChunkSource<Unauthenticated>>,
    ) -> Result<DynChunkSource<Self>, super::Error>;
}

impl NewSource for Authenticated {
    async fn new_source(
        client: &Client,
        location: &Arl,
        parent: Option<DynChunkSource<Unauthenticated>>,
    ) -> Result<DynChunkSource<Authenticated>, super::Error> {
        match location {
            Arl::Tx(tx_arl) => {
                if parent.is_some() {
                    Err(Error::UnsupportedDataItem)?;
                }
                new_tx_source::<Authenticated>(client, tx_arl).await
            }
            Arl::BundleItem(bundle_item_arl) => {
                let parent = parent.ok_or(Error::UnsupportedDataItem)?;
                let (entry, item, authenticator) = client
                    ._bundle_item_authenticated(bundle_item_arl)
                    .await?
                    .ok_or_else(|| {
                        Error::BundleItemNotFound(bundle_item_arl.bundle_item_id().clone())
                    })?;
                Ok(Box::new(BundleItemChunkSource::authenticated(
                    entry,
                    item,
                    authenticator,
                    parent,
                )))
            }
        }
    }
}

impl NewSource for Unauthenticated {
    async fn new_source(
        client: &Client,
        location: &Arl,
        parent: Option<DynChunkSource<Unauthenticated>>,
    ) -> Result<DynChunkSource<Unauthenticated>, super::Error> {
        match location {
            Arl::Tx(tx_arl) => {
                if parent.is_some() {
                    Err(Error::UnsupportedDataItem)?;
                }
                new_tx_source::<Unauthenticated>(client, tx_arl).await
            }
            Arl::BundleItem(bundle_item_arl) => {
                let parent = parent.ok_or(Error::UnsupportedDataItem)?;
                let (entry, item) = client
                    ._bundle_item_unauthenticated(bundle_item_arl)
                    .await?
                    .ok_or_else(|| {
                        Error::BundleItemNotFound(bundle_item_arl.bundle_item_id().clone())
                    })?;
                Ok(Box::new(BundleItemChunkSource::unauthenticated(
                    entry, item, parent,
                )))
            }
        }
    }
}

async fn new_tx_source<Auth: AuthenticationState>(
    client: &Client,
    location: &TxArl,
) -> Result<DynChunkSource<Auth>, super::Error>
where
    for<'a> Tx<'a, Auth>: From<AuthenticatedTx<'a>>,
    for<'a> TxDataChunk<'a, Auth>: From<AuthenticatedTxDataChunk<'a>>,
    for<'b> Auth: DataChunkReader<TxDataKind, (), Authenticated, Auth>,
{
    let tx = client
        .tx_by_id(location.tx_id())
        .await?
        .ok_or_else(|| Error::TxNotFound(location.tx_id().clone()))?;

    Ok(Box::new(TxChunkSource::new(client.clone(), tx).await?))
}

pub struct ChunkReader<D: ChunkSource<Authenticated>> {
    pos: u64,
    len: u64,
    state: State<Authenticated>,
    data_source: D,
}

impl<D: ChunkSource<Authenticated>> ChunkReader<D> {
    fn new(data_source: D) -> Self {
        Self {
            pos: 0,
            len: data_source.len(),
            state: State::default(),
            data_source,
        }
    }
}

type RetrieveFut<V> = Pin<Box<dyn Future<Output = Result<V, super::Error>> + Send>>;

enum State<Auth: AuthenticationState> {
    Ready {
        data: Option<OwnedTypedByteBufferCursor<Auth>>,
    },
    Retrieving {
        chunk: Chunk,
        fut: RetrieveFut<TypedByteBuffer<'static, Auth>>,
    },
}

impl<Auth: AuthenticationState> Default for State<Auth> {
    fn default() -> Self {
        Self::Ready { data: None }
    }
}

type TxChunk<Auth: AuthenticationState> = ItemChunk<TxDataKind, Auth>;
type BundleItemChunk<Auth: AuthenticationState> = ItemChunk<BundleItemDataKind, Auth>;

struct ItemChunk<T, Auth: AuthenticationState> {
    data: DataChunk<'static, T, Auth>,
    chunk_range: Range<u64>,
    data_range: Range<u64>,
}

trait DataChunkReader<T, Authenticator, Input: AuthenticationState, Output: AuthenticationState> {
    fn read<'a>(
        data_chunk: DataChunk<'a, T, Input>,
        authenticator: Option<&Authenticator>,
    ) -> Result<TypedByteBuffer<'a, Output>, Error>;
}

impl<T, Authenticator> DataChunkReader<T, Authenticator, Authenticated, Self> for Authenticated {
    fn read<'a>(
        data_chunk: AuthenticatedDataChunk<'a, T>,
        _: Option<&Authenticator>,
    ) -> Result<TypedByteBuffer<'a, Self>, Error> {
        Ok(data_chunk.authenticated_data_erased())
    }
}

impl<T, Authenticator> DataChunkReader<T, Authenticator, Authenticated, Self> for Unauthenticated {
    fn read<'a>(
        data_chunk: AuthenticatedDataChunk<'a, T>,
        _: Option<&Authenticator>,
    ) -> Result<TypedByteBuffer<'a, Self>, Error> {
        Ok(data_chunk.invalidate().danger_unauthenticated_data_erased())
    }
}

impl<T, Authenticator> DataChunkReader<T, Authenticator, Unauthenticated, Self>
    for Unauthenticated
{
    fn read<'a>(
        data_chunk: UnauthenticatedDataChunk<'a, T>,
        _: Option<&Authenticator>,
    ) -> Result<TypedByteBuffer<'a, Self>, Error> {
        Ok(data_chunk.danger_unauthenticated_data_erased())
    }
}

impl DataChunkReader<BundleItemDataKind, BundleItemDataAuthenticityProof<'_>, Unauthenticated, Self>
    for Authenticated
{
    fn read<'a>(
        data_chunk: DataChunk<'a, BundleItemDataKind, Unauthenticated>,
        authenticator: Option<&BundleItemDataAuthenticityProof>,
    ) -> Result<TypedByteBuffer<'a, Self>, Error> {
        let authenticator = authenticator.ok_or(Error::DataAuthenticationFailure(
            "data authenticator is missing".to_string(),
        ))?;
        data_chunk
            .authenticate(authenticator)
            .map(|d| d.authenticated_data_erased())
            .map_err(|(_, err)| Error::DataAuthenticationFailure(err.to_string()))
    }
}

impl<T, Auth: AuthenticationState> ItemChunk<T, Auth> {
    fn new(
        data: impl Into<DataChunk<'static, T, Auth>>,
        chunk_offset: u64,
        data_range: Range<u64>,
    ) -> Self {
        Self {
            chunk_range: chunk_offset..chunk_offset + (data_range.end - data_range.start) as u64,
            data: data.into(),
            data_range,
        }
    }
}

pub trait ChunkSource<Auth: AuthenticationState>: Send + Sync + Unpin {
    fn len(&self) -> u64;
    fn chunks(&self) -> ChunkIterator<'_>;
    fn chunk(&self, pos: u64) -> Option<&Chunk>;
    fn item(&self) -> Item<'static, Auth>;
    fn retrieve_chunk(&self, chunk: &Chunk) -> RetrieveFut<TypedByteBuffer<'static, Auth>>;
}

type DynChunkSource<Auth: AuthenticationState> = Box<dyn ChunkSource<Auth>>;

impl<Auth: AuthenticationState> ChunkSource<Auth> for DynChunkSource<Auth> {
    #[inline]
    fn len(&self) -> u64 {
        self.as_ref().len()
    }

    #[inline]
    fn chunks(&self) -> ChunkIterator<'_> {
        self.as_ref().chunks()
    }

    #[inline]
    fn chunk(&self, pos: u64) -> Option<&Chunk> {
        self.as_ref().chunk(pos)
    }

    #[inline]
    fn item(&self) -> Item<'static, Auth> {
        self.as_ref().item()
    }

    #[inline]
    fn retrieve_chunk(&self, chunk: &Chunk) -> RetrieveFut<TypedByteBuffer<'static, Auth>> {
        self.as_ref().retrieve_chunk(chunk)
    }
}

struct TxChunkSource<'a, Auth: AuthenticationState> {
    tx: MaybeOwned<'a, AuthenticatedTx<'a>>,
    tx_offset: Offset,
    data_root: Arc<DataRoot>,
    data_size: u64,
    chunk_map: RangeMap<u64, usize>,
    client: Client,
    _phantom: PhantomData<Auth>,
}

impl<'a, Auth: AuthenticationState> TxChunkSource<'a, Auth> {
    async fn new(
        client: Client,
        tx: impl Into<MaybeOwned<'a, AuthenticatedTx<'a>>>,
    ) -> Result<Self, super::Error> {
        let tx = tx.into();
        let (data_root, data_size) = match tx.data_item() {
            Some(DataItem::External(external)) => {
                (Arc::new(external.data_root().clone()), external.data_size())
            }
            Some(_) => Err(Error::UnsupportedDataItem)?,
            None => Err(Error::NoDataItem(tx.id().clone()))?,
        };
        let tx_offset = client.tx_offset(tx.id()).await?;
        let chunk_map = DefaultChunker::chunk_map(data_size)
            .iter()
            .enumerate()
            .map(|(i, r)| (r, i))
            .collect();
        Ok(Self {
            data_root,
            data_size,
            tx,
            tx_offset,
            chunk_map,
            client,
            _phantom: PhantomData,
        })
    }
}

impl<Auth: AuthenticationState> ChunkSource<Auth> for TxChunkSource<'_, Auth>
where
    for<'a> Tx<'a, Auth>: From<AuthenticatedTx<'a>>,
    for<'a> TxDataChunk<'a, Auth>: From<AuthenticatedTxDataChunk<'a>>,
    for<'b> Auth: DataChunkReader<TxDataKind, (), Authenticated, Auth>,
{
    fn len(&self) -> u64 {
        self.data_size
    }

    fn chunks(&self) -> ChunkIterator<'_> {
        ChunkIterator::new(self.chunk_map.iter().map(|(r, _)| Chunk::wrap_ref(r)))
    }

    fn chunk(&self, pos: u64) -> Option<&Chunk> {
        self.chunk_map
            .get_key_value(&pos)
            .map(|(r, _)| Chunk::wrap_ref(r))
    }

    fn item(&self) -> Item<'static, Auth> {
        Item::Tx(self.tx.clone().into_owned().into_owned().into())
    }

    fn retrieve_chunk(&self, chunk: &Chunk) -> RetrieveFut<TypedByteBuffer<'static, Auth>> {
        if !self.chunk_map.contains_key(&chunk.offset()) {
            return Box::pin(async { Err(Error::ChunkNotFound)? });
        }

        let tx_offset = self.tx_offset.clone();
        let client = self.client.clone();
        let data_root = self.data_root.clone();
        let requested_chunk = chunk.clone();

        Box::pin(async move {
            let chunk_abs_pos = tx_offset.absolute(requested_chunk.offset());
            let chunk = client
                .retrieve_chunk(chunk_abs_pos, requested_chunk.offset(), &data_root)
                .await?
                .ok_or(Error::ChunkNotFound)?;
            Ok(<Auth as DataChunkReader<_, _, _, Auth>>::read(
                chunk,
                None::<&()>,
            )?)
        })
    }
}

struct BundleItemChunkSource<
    'a,
    Auth: AuthenticationState,
    ContainerAuth: AuthenticationState,
    Container: ChunkSource<ContainerAuth>,
> {
    entry: MaybeOwned<'a, BundleEntry<'a>>,
    item: MaybeOwned<'a, BundleItem<'a, Auth>>,
    data_authenticator: Option<Arc<BundleItemAuthenticator<'static>>>,
    chunk_map: RangeMap<u64, usize>,
    data_size: u64,
    container: Arc<Container>,
    _phantom: PhantomData<ContainerAuth>,
}

impl<'a, ContainerAuth: AuthenticationState, Container: ChunkSource<ContainerAuth>>
    BundleItemChunkSource<'a, Authenticated, ContainerAuth, Container>
{
    fn authenticated(
        entry: impl Into<MaybeOwned<'a, BundleEntry<'a>>>,
        item: impl Into<MaybeOwned<'a, AuthenticatedBundleItem<'a>>>,
        data_authenticator: impl Into<MaybeOwned<'a, BundleItemAuthenticator<'static>>>,
        container: Container,
    ) -> Self {
        let data_authenticator = data_authenticator.into().into_owned();
        let chunk_map = data_authenticator
            .chunks()
            .into_iter()
            .enumerate()
            .map(|(i, c)| (c.clone(), i))
            .collect();

        let entry = entry.into();
        let item = item.into();
        let data_size = item.data_size();

        Self {
            entry,
            item,
            data_authenticator: Some(Arc::new(data_authenticator)),
            chunk_map,
            data_size,
            container: Arc::new(container),
            _phantom: PhantomData,
        }
    }
}

impl<'a, ContainerAuth: AuthenticationState, Container: ChunkSource<ContainerAuth>>
    BundleItemChunkSource<'a, Unauthenticated, ContainerAuth, Container>
{
    fn unauthenticated(
        entry: impl Into<MaybeOwned<'a, BundleEntry<'a>>>,
        item: impl Into<MaybeOwned<'a, UnauthenticatedBundleItem<'a>>>,
        container: Container,
    ) -> Self {
        let entry = entry.into();
        let item = item.into();
        let data_size = item.data_size();

        // align our chunks to container chunks
        //todo: check the chunk_map below
        let offset = entry.container_location().offset() + item.data_offset();
        let chunk_map = container
            .chunks()
            .enumerate()
            .filter_map(|(i, c)| {
                let start = c.offset();
                let range_end = (c.offset() + c.len()).min(offset + data_size);
                (start < range_end).then(|| (start..range_end, i))
            })
            .collect();

        Self {
            entry,
            item,
            data_authenticator: None,
            chunk_map,
            data_size,
            container: Arc::new(container),
            _phantom: PhantomData,
        }
    }
}

impl<
    'a,
    Auth: AuthenticationState,
    ContainerAuth: AuthenticationState,
    Container: ChunkSource<ContainerAuth>,
> ChunkSource<Auth> for BundleItemChunkSource<'a, Auth, ContainerAuth, Container>
where
    Container: 'static,
    for<'b> Auth: DataChunkReader<
            BundleItemDataKind,
            BundleItemDataAuthenticityProof<'b>,
            Unauthenticated,
            Auth,
        >,
{
    fn len(&self) -> u64 {
        self.data_size
    }

    fn chunks(&self) -> ChunkIterator<'_> {
        ChunkIterator::new(self.chunk_map.iter().map(|(r, _)| Chunk::wrap_ref(r)))
    }

    fn chunk(&self, pos: u64) -> Option<&Chunk> {
        self.chunk_map
            .get_key_value(&pos)
            .map(|(r, _)| Chunk::wrap_ref(r))
    }

    fn item(&self) -> Item<'static, Auth> {
        Item::BundleItem(self.item.clone().into_owned().into_owned().into())
    }

    fn retrieve_chunk(&self, chunk: &Chunk) -> RetrieveFut<TypedByteBuffer<'static, Auth>> {
        if !self.chunk_map.contains_key(&chunk.offset()) {
            return Box::pin(async { Err(Error::ChunkNotFound)? });
        }

        // map chunk to container chunks
        let container_offset = self.entry.container_location().offset() + self.item.data_offset();
        let container_range =
            chunk.range().start + container_offset..chunk.range().end + container_offset;

        let mut container_chunks = self
            .container
            .chunks()
            .filter_map(|c| {
                if c.overlaps(&container_range) {
                    Some(c.clone())
                } else {
                    None
                }
            })
            .collect_vec();

        if container_chunks.is_empty() {
            return Box::pin(async { Err(Error::ChunkNotFound)? });
        }

        container_chunks.sort_by(|a, b| a.offset().cmp(&b.offset()));

        // needs to be skipped from final data
        let leading_padding = container_chunks
            .first()
            .map(|c| container_range.start.saturating_sub(c.range().start))
            .unwrap_or(0);

        // needs to be trimmed from final data
        let trailing_padding = container_chunks
            .last()
            .map(|c| c.range().end.saturating_sub(container_range.end))
            .unwrap_or(0);

        if self.data_authenticator.is_none() && Auth::is_authenticated() {
            // we need authenticated output but don't have an authenticator at hand
            return Box::pin(async {
                Err(Error::DataAuthenticationFailure(
                    "data_authenticator missing, bundle_item data cannot be authenticated"
                        .to_string(),
                ))?
            });
        }

        let data_authenticator = self.data_authenticator.clone();
        let container = self.container.clone();
        let chunk = chunk.clone();

        Box::pin(async move {
            // retrieve container_chunks concurrently
            let pending_futs = container_chunks
                .iter()
                .map(|c| {
                    let container = container.clone();
                    async move { container.retrieve_chunk(c).await.map(|r| (c, r)) }
                })
                .collect::<FutureGroup<_>>();

            let mut container_chunks: Vec<_> = pending_futs.try_collect().await?;
            container_chunks.sort_by(|(a, _), (b, _)| a.offset().cmp(&b.offset()));
            let mut buf = container_chunks
                .into_iter()
                .map(|(_, data)| data)
                .collect::<TypedByteBuffer<_>>();

            // skip leading padding
            (_, buf) = buf.split_at(leading_padding);
            // trim trailing padding
            let len = buf.len();
            (buf, _) = buf.split_at(len - trailing_padding);

            if buf.len() != chunk.len() {
                Err(Error::from(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "returned data length does not match expectation",
                )))?
            }

            let chunk = UnauthenticatedBundleItemDataChunk::from_byte_buffer(
                buf.into_untyped(),
                chunk.offset(),
            );

            // find the correct proof if we have an authenticator
            let proof = data_authenticator.as_ref().and_then(|auth| {
                auth.proof(&chunk.range()).map(|proof| {
                    BundleItemDataAuthenticityProof::new(
                        Arc::unwrap_or_clone(auth.clone()),
                        proof.into_owned(),
                    )
                })
            });

            // authenticate if necessary
            Ok(<Auth as DataChunkReader<_, _, _, Auth>>::read(
                chunk,
                proof.as_ref(),
            )?)
        })
    }
}

impl<D: ChunkSource<Authenticated>> ChunkReader<D> {
    pub fn len(&self) -> u64 {
        self.len
    }

    fn retrieve_chunk(&mut self, pos: u64) -> Result<(), std::io::Error> {
        let chunk = self
            .data_source
            .chunk(pos)
            .ok_or(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                format!("no chunk found for pos {}", pos),
            ))?
            .clone();

        let fut = self.data_source.retrieve_chunk(&chunk);
        self.state = State::Retrieving { chunk, fut };
        self.pos = pos;
        Ok(())
    }

    fn on_chunk(
        &mut self,
        chunk: Chunk,
        mut fut: RetrieveFut<TypedByteBuffer<'static, Authenticated>>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match fut.poll(cx) {
            Poll::Pending => {
                self.state = State::Retrieving { chunk, fut };
                Poll::Pending
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(err))),
            Poll::Ready(Ok(mut data)) => {
                if data.len() != chunk.len() {
                    return Poll::Ready(Err(std::io::Error::other("chunk length incorrect")));
                }
                if !chunk.contains(self.pos) {
                    return Poll::Ready(Err(std::io::Error::other("invalid chunk range")));
                }

                // trim & skip padding if any
                let leading_padding = self.pos - chunk.offset();
                if leading_padding > 0 {
                    (_, data) = data.split_at(leading_padding);
                }
                let max_len = self.len.saturating_sub(self.pos);
                if data.len() > max_len {
                    (data, _) = data.split_at(max_len);
                }

                self.state = State::Ready {
                    data: Some(data.into_cursor()),
                };
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<D: ChunkSource<Authenticated>> AsyncRead for ChunkReader<D> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let pos = self.pos;
        if pos >= self.len {
            // eof
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        loop {
            match std::mem::replace(&mut this.state, State::default()) {
                State::Ready {
                    data: Some(mut data),
                } => {
                    if data.has_remaining() {
                        let n = min(buf.len(), data.remaining());
                        data.copy_to_slice(&mut buf[..n]);
                        this.pos += n as u64;
                        this.state = State::Ready { data: Some(data) };
                        return Poll::Ready(Ok(n));
                    }
                }
                State::Ready { data: None } => {
                    this.retrieve_chunk(pos)?;
                }
                State::Retrieving { chunk, fut } => {
                    ready!(this.on_chunk(chunk, fut, cx))?;
                }
            }
        }
    }
}

impl<D: ChunkSource<Authenticated>> AsyncSeek for ChunkReader<D> {
    fn poll_seek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<std::io::Result<u64>> {
        let pos = match pos {
            SeekFrom::Start(pos) => pos,
            SeekFrom::Current(rel) => self.pos.saturating_add_signed(rel),
            SeekFrom::End(rel) => self.len.saturating_add_signed(rel),
        };

        if pos > self.len {
            return Poll::Ready(Err(std::io::Error::other(
                "seeking beyond eof is not allowed",
            )));
        }

        let this = self.get_mut();

        loop {
            match std::mem::replace(&mut this.state, State::default()) {
                State::Ready {
                    data: Some(mut data),
                } => {
                    // check if `pos` is within current data range
                    if pos >= this.pos && pos < (this.pos + data.remaining() as u64) {
                        let discard = pos - this.pos;
                        data.seek_relative(discard as i64)?;
                        this.pos = pos;
                        if data.has_remaining() {
                            this.state = State::Ready { data: Some(data) };
                            return Poll::Ready(Ok(pos));
                        }
                    }
                }
                State::Ready { data: None } => {
                    // start retrieving chunk
                    this.retrieve_chunk(pos)?;
                }
                State::Retrieving { chunk, fut } => {
                    ready!(this.on_chunk(chunk, fut, cx))?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use crate::data_reader::{ChunkReader, TxChunkSource};
    use crate::location::Arl;
    use ario_core::Gateway;
    use ario_core::bundle::{BundleItemId, BundleItemReader, BundleReader};
    use ario_core::crypto::hash::{Hasher, Sha256};
    use ario_core::data::Authenticator;
    use ario_core::tx::TxId;
    use futures_lite::AsyncReadExt;
    use hex_literal::hex;
    use itertools::Itertools;
    use std::str::FromStr;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[ignore]
    #[tokio::test]
    async fn read_tx() -> anyhow::Result<()> {
        init_tracing();
        let client = Client::builder()
            .enable_netwatch(false)
            .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
            .build()
            .await?;

        let tx_id = TxId::from_str("ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk")?;

        let tx = client.tx_by_id(&tx_id).await?.unwrap();
        let mut data_reader = ChunkReader::new(TxChunkSource::new(client.clone(), &tx).await?);
        let len = data_reader.len();

        assert_eq!(len, 3251342);

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let n = data_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[0..n]);
        }

        let hash = hasher.finalize();
        assert_eq!(
            hash.as_slice(),
            hex!("87a46b9a4720751cfe182b55c75ea49363e4dc55ec7c2d759c9c03ab62a64717")
        );
        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn read_bundle_item() -> anyhow::Result<()> {
        init_tracing();
        let client = Client::builder()
            .enable_netwatch(false)
            .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
            .build()
            .await?;

        let arl = Arl::from_str(
            "ar://ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk/UHVB0gDKDiId6XAeZlCH_9h6h6Tz0we8MuGA0CUYxPE",
        )?;
        assert_eq!(
            arl.tx_id(),
            &TxId::from_str("ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk")?
        );
        assert_eq!(
            arl.as_bundle_item_arl().unwrap().bundle_item_id(),
            &BundleItemId::from_str("UHVB0gDKDiId6XAeZlCH_9h6h6Tz0we8MuGA0CUYxPE")?
        );

        let mut reader = client.read_data_item(arl).await?;

        assert_eq!(reader.len(), 598382);

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[0..n]);
        }

        let hash = hasher.finalize();
        assert_eq!(
            hash.as_slice(),
            hex!("4f76ec77b3476bcb2b37fbdf9f91ea52b407ee7d3c298d18439a1e53ff37aaf8")
        );
        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn read_bundle_item_alignment_local_data() -> anyhow::Result<()> {
        init_tracing();
        let client = Client::builder()
            .enable_netwatch(false)
            .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
            .build()
            .await?;

        let tx_id = TxId::from_str("ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk")?;
        let item_id = BundleItemId::from_str("UHVB0gDKDiId6XAeZlCH_9h6h6Tz0we8MuGA0CUYxPE")?;

        let tx = client.tx_by_id(&tx_id).await?.unwrap().into();

        let mut file =
            tokio::fs::File::open("./testdata/ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk.tx")
                .await?
                .compat();
        let bundle = BundleReader::new(&tx, &mut file).await?;

        let entry = bundle.entries().find(|e| e.id() == &item_id).unwrap();

        let (bundle_item, authenticator) =
            BundleItemReader::read_async(&entry, &mut file, bundle.id().clone()).await?;
        let _bundle_item = bundle_item.authenticate()?;

        let chunks = authenticator.chunks().collect_vec();
        assert_eq!(chunks.len(), 3);
        assert_eq!(**chunks.get(0).unwrap(), 0..204794);
        assert_eq!(**chunks.get(1).unwrap(), 204794..466938);
        assert_eq!(**chunks.get(2).unwrap(), 466938..598382);

        Ok(())
    }
}
