use crate::Client;
use crate::data_reader::{
    ChunkSource, ChunkSourceTagEraser, DataChunkExt, DynChunkSource, DynChunkSourceBuilder, Error,
    ReadableDataItem, UntaggedChunkSource,
};
use crate::location::TypedArl;
use ario_core::buffer::TypedByteBuffer;
use ario_core::bundle::{
    AuthenticatedBundleItem, BundleEntry, BundleItem, BundleItemAuthenticator, BundleItemKind,
    UnauthenticatedBundleItem,
};
use ario_core::chunking::{AlignedChunkMap, AnyChunkMap, ChunkMap, FixedRangeMap};
use ario_core::data::{
    Authenticator, BundleItemDataAuthenticityProof, BundleItemDataChunk, DataChunk,
    UnauthenticatedBundleItemDataChunk,
};
use ario_core::{Authenticated, AuthenticationState, Item, MaybeOwned, Unauthenticated};
use async_trait::async_trait;
use futures_concurrency::future::FutureGroup;
use futures_lite::StreamExt;
use itertools::Itertools;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::ops::Range;
use std::sync::Arc;

pub struct BundleItemChunkSource<
    'a,
    Auth: AuthenticationState,
    ContainerAuth: AuthenticationState,
    ContainerKind: ReadableDataItem,
    Container: ChunkSource<ContainerKind, ContainerAuth>,
> {
    entry: MaybeOwned<'a, BundleEntry<'a>>,
    item: MaybeOwned<'a, BundleItem<'a, Auth>>,
    data_authenticator: Option<Arc<BundleItemAuthenticator<'static>>>,
    chunk_map: AnyChunkMap,
    data_size: u64,
    container: Arc<Container>,
    _phantom: PhantomData<(ContainerKind, ContainerAuth)>,
}

pub(crate) trait Builder<
    Auth: AuthenticationState,
    ContainerKind: ReadableDataItem,
    ContainerAuth: AuthenticationState,
    Container: ChunkSource<ContainerKind, ContainerAuth>,
>
{
    fn new_from_location(
        client: &Client,
        location: &TypedArl<BundleItemKind>,
        container: Container,
    ) -> impl Future<
        Output = Result<
            BundleItemChunkSource<'static, Auth, ContainerAuth, ContainerKind, Container>,
            crate::Error,
        >,
    > + Send;
}

impl<
    ContainerKind: ReadableDataItem,
    ContainerAuth: AuthenticationState,
    Container: ChunkSource<ContainerKind, ContainerAuth> + 'static,
> Builder<Authenticated, ContainerKind, ContainerAuth, Container> for Authenticated
where
    for<'b> DataChunk<'b, ContainerKind, ContainerAuth>:
        DataChunkExt<'b, ContainerKind, (), Unauthenticated>,
    for<'b, 'c> BundleItemDataChunk<'b, Unauthenticated>:
        DataChunkExt<'b, BundleItemKind, BundleItemDataAuthenticityProof<'c>, Authenticated>,
{
    async fn new_from_location(
        client: &Client,
        location: &TypedArl<BundleItemKind>,
        container: Container,
    ) -> Result<
        BundleItemChunkSource<'static, Authenticated, ContainerAuth, ContainerKind, Container>,
        crate::Error,
    > {
        let (entry, item, authenticator) = client
            ._bundle_item_authenticated(location)
            .await?
            .ok_or_else(|| Error::BundleItemNotFound(location.bundle_item_id().clone()))?;

        Ok(BundleItemChunkSource::authenticated(
            entry,
            item,
            authenticator,
            container,
        ))
    }
}

impl<
    ContainerKind: ReadableDataItem,
    ContainerAuth: AuthenticationState,
    Container: ChunkSource<ContainerKind, ContainerAuth> + 'static,
> Builder<Unauthenticated, ContainerKind, ContainerAuth, Container> for Unauthenticated
where
    for<'b> DataChunk<'b, ContainerKind, ContainerAuth>:
        DataChunkExt<'b, ContainerKind, (), Unauthenticated>,
{
    async fn new_from_location(
        client: &Client,
        location: &TypedArl<BundleItemKind>,
        container: Container,
    ) -> Result<
        BundleItemChunkSource<'static, Unauthenticated, ContainerAuth, ContainerKind, Container>,
        crate::Error,
    > {
        let (entry, item) = client
            ._bundle_item_unauthenticated(location)
            .await?
            .ok_or_else(|| Error::BundleItemNotFound(location.bundle_item_id().clone()))?;

        Ok(BundleItemChunkSource::unauthenticated(
            entry, item, container,
        ))
    }
}

impl<
    'a,
    Auth: AuthenticationState,
    ContainerAuth: AuthenticationState,
    ContainerKind: ReadableDataItem,
    Container: ChunkSource<ContainerKind, ContainerAuth>,
> BundleItemChunkSource<'a, Auth, ContainerAuth, ContainerKind, Container>
where
    Auth: Builder<Auth, ContainerKind, ContainerAuth, Container>,
    Self: ChunkSource<BundleItemKind, Auth> + 'static,
{
    pub(super) async fn new_from_location(
        client: &Client,
        location: &TypedArl<BundleItemKind>,
        container: Container,
    ) -> Result<Self, crate::Error> {
        <Auth as Builder<_, _, _, _>>::new_from_location(client, location, container).await
    }
}

#[async_trait]
impl<
    Auth: AuthenticationState,
    ContainerAuth: AuthenticationState,
    ContainerKind: ReadableDataItem,
    Container: ChunkSource<ContainerKind, ContainerAuth> + 'static,
> DynChunkSourceBuilder<BundleItemKind, Auth, ContainerKind, ContainerAuth, Container>
    for (BundleItemKind, Auth, Container)
where
    Auth: Builder<Auth, ContainerKind, ContainerAuth, Container>,
    BundleItemChunkSource<'static, Auth, ContainerAuth, ContainerKind, Container>:
        ChunkSource<BundleItemKind, Auth>,
{
    async fn new_from_location(
        client: &Client,
        location: &TypedArl<BundleItemKind>,
        container: Option<Container>,
    ) -> Result<DynChunkSource<BundleItemKind, Auth>, crate::Error> {
        let container = container.ok_or(Error::UnsupportedDataItem)?;
        Ok(Box::new(
            <Auth as Builder<_, _, _, _>>::new_from_location(client, location, container).await?,
        ))
    }
}

impl<
    'a,
    ContainerAuth: AuthenticationState,
    ContainerKind: ReadableDataItem,
    Container: ChunkSource<ContainerKind, ContainerAuth>,
> BundleItemChunkSource<'a, Authenticated, ContainerAuth, ContainerKind, Container>
{
    fn authenticated(
        entry: impl Into<MaybeOwned<'a, BundleEntry<'a>>>,
        item: impl Into<MaybeOwned<'a, AuthenticatedBundleItem<'a>>>,
        data_authenticator: impl Into<MaybeOwned<'a, BundleItemAuthenticator<'static>>>,
        container: Container,
    ) -> Self
    where
        Self: ChunkSource<BundleItemKind, Authenticated>,
    {
        let data_authenticator = data_authenticator.into().into_owned();
        let chunk_map = AnyChunkMap::new(
            FixedRangeMap::<{ 256 * 1024 }>::try_from_iter(
                data_authenticator.chunks().into_iter().map(|r| r.clone()),
            )
            .expect("range to be valid"), //todo: add error handling
        );

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

impl<
    'a,
    ContainerAuth: AuthenticationState,
    ContainerKind: ReadableDataItem,
    Container: ChunkSource<ContainerKind, ContainerAuth>,
> BundleItemChunkSource<'a, Unauthenticated, ContainerAuth, ContainerKind, Container>
where
    Self: ChunkSource<BundleItemKind, Unauthenticated>,
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
        let offset = entry.container_location().offset() + item.data_offset();
        let chunk_map = AnyChunkMap::new(AlignedChunkMap::<_, 0>::new(
            container.chunks().clone(),
            offset,
            Some(data_size),
        ));

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
    Auth: AuthenticationState,
    ContainerAuth: AuthenticationState,
    ContainerKind: ReadableDataItem,
    Container: ChunkSource<ContainerKind, ContainerAuth> + 'static,
> From<BundleItemChunkSource<'static, Auth, ContainerAuth, ContainerKind, Container>>
    for UntaggedChunkSource<Auth>
where
    for<'b> DataChunk<'b, ContainerKind, ContainerAuth>:
        DataChunkExt<'b, ContainerKind, (), Unauthenticated>,
    for<'b, 'c> BundleItemDataChunk<'b, Unauthenticated>:
        DataChunkExt<'b, BundleItemKind, BundleItemDataAuthenticityProof<'c>, Auth>,
{
    fn from(
        value: BundleItemChunkSource<'static, Auth, ContainerAuth, ContainerKind, Container>,
    ) -> Self {
        Box::new(ChunkSourceTagEraser::new(value))
    }
}

impl<Auth: AuthenticationState> From<DynChunkSource<BundleItemKind, Auth>>
    for UntaggedChunkSource<Auth>
{
    fn from(value: DynChunkSource<BundleItemKind, Auth>) -> Self {
        Box::new(ChunkSourceTagEraser::new(value))
    }
}

#[async_trait]
impl<
    'a,
    Auth: AuthenticationState,
    ContainerAuth: AuthenticationState,
    ContainerKind: ReadableDataItem,
    Container: ChunkSource<ContainerKind, ContainerAuth>,
> ChunkSource<BundleItemKind, Auth>
    for BundleItemChunkSource<'a, Auth, ContainerAuth, ContainerKind, Container>
where
    Container: 'static,
    for<'b> DataChunk<'b, ContainerKind, ContainerAuth>:
        DataChunkExt<'b, ContainerKind, (), Unauthenticated>,
    for<'b, 'c> DataChunk<'b, BundleItemKind, Unauthenticated>:
        DataChunkExt<'b, BundleItemKind, BundleItemDataAuthenticityProof<'c>, Auth>,
{
    fn len(&self) -> u64 {
        self.data_size
    }

    fn chunks(&self) -> &AnyChunkMap {
        &self.chunk_map
    }

    fn item(&self) -> Item<'static, Auth> {
        Item::BundleItem(self.item.clone().into_owned().into_owned().into())
    }

    async fn retrieve_chunk(
        &self,
        range: Range<u64>,
    ) -> Result<DataChunk<'static, BundleItemKind, Auth>, crate::Error>
    where
        BundleItemKind: ReadableDataItem,
        Auth: AuthenticationState,
    {
        use crate::data_reader::DataChunkExt;

        if !self.chunk_map.chunk_at(range.start).is_some() {
            Err(Error::ChunkNotFound)?;
        }

        // map chunk to container chunks
        let container_offset = self.entry.container_location().offset() + self.item.data_offset();
        let container_range = range.start + container_offset..range.end + container_offset;

        let mut container_chunks = self
            .container
            .chunks()
            .iter_range(container_range.clone())
            .collect_vec();

        if container_chunks.is_empty() {
            return Err(Error::ChunkNotFound)?;
        }

        container_chunks.sort_by(|a, b| a.start.cmp(&b.start));

        // needs to be skipped from final data
        let leading_padding = container_chunks
            .first()
            .map(|c| container_range.start.saturating_sub(c.start))
            .unwrap_or(0);

        // needs to be trimmed from final data
        let trailing_padding = container_chunks
            .last()
            .map(|c| c.end.saturating_sub(container_range.end))
            .unwrap_or(0);

        if self.data_authenticator.is_none() && Auth::is_authenticated() {
            // we need authenticated output but don't have an authenticator at hand
            Err(Error::DataAuthenticationFailure(
                "data_authenticator missing, bundle_item data cannot be authenticated".to_string(),
            ))?;
        }

        // retrieve container_chunks concurrently
        let pending_futs = container_chunks
            .iter()
            .map(|c| {
                let container = &self.container;
                async move { container.retrieve_chunk(c.clone()).await.map(|r| (c, r)) }
            })
            .collect::<FutureGroup<_>>();

        let mut container_chunks: Vec<_> = pending_futs.try_collect().await?;
        container_chunks.sort_by(|(a, _), (b, _)| a.start.cmp(&b.start));
        let mut buf = container_chunks
            .into_iter()
            .map(|(_, data)| {
                data.into_buffer(None::<&()>)
                    .expect("conversion to succeed")
            })
            .collect::<TypedByteBuffer<_>>();

        // skip leading padding
        (_, buf) = buf.split_at(leading_padding);
        // trim trailing padding
        let len = buf.len();
        (buf, _) = buf.split_at(len - trailing_padding);

        if buf.len() != (range.end - range.start) {
            Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidData,
                "returned data length does not match expectation",
            )))?
        }

        let chunk =
            UnauthenticatedBundleItemDataChunk::from_byte_buffer(buf.into_untyped(), range.start);

        // find the correct proof if we have an authenticator
        let proof = self.data_authenticator.as_ref().and_then(|auth| {
            auth.proof(&chunk.range()).map(|proof| {
                BundleItemDataAuthenticityProof::new(
                    Arc::unwrap_or_clone(auth.clone()),
                    proof.into_owned(),
                )
            })
        });
        // authenticate if necessary
        Ok(chunk.into_state(proof.as_ref())?)
    }
}
