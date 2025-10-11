use crate::Client;
use crate::data_reader::{
    ChunkSource, ChunkSourceTagEraser, DataChunkExt, DynChunkSource, DynChunkSourceBuilder, Error,
    ReadableDataItem, UntaggedChunkSource,
};
use crate::location::TypedArl;
use crate::tx::Offset;
use ario_core::chunking::{AnyChunkMap, ChunkMap, DefaultChunker};
use ario_core::data::{AuthenticatedTxDataChunk, DataChunk, DataItem, DataRoot, TxDataChunk};
use ario_core::tx::{AuthenticatedTx, Tx, TxKind};
use ario_core::{Authenticated, AuthenticationState, Item};
use std::marker::PhantomData;
use std::ops::Range;
use std::sync::Arc;

pub struct TxChunkSource<Auth: AuthenticationState> {
    tx: AuthenticatedTx<'static>,
    tx_offset: Offset,
    data_root: Arc<DataRoot>,
    data_size: u64,
    chunk_map: AnyChunkMap,
    client: Client,
    _phantom: PhantomData<Auth>,
}

impl<Auth: AuthenticationState> From<TxChunkSource<Auth>> for UntaggedChunkSource<Auth>
where
    for<'a> Tx<'a, Auth>: From<Tx<'a, Authenticated>>,
    for<'a> TxDataChunk<'a, Auth>: From<TxDataChunk<'a, Authenticated>>,
    for<'a> TxDataChunk<'a, Authenticated>: DataChunkExt<'a, TxKind, (), Auth>,
{
    fn from(value: TxChunkSource<Auth>) -> Self {
        super::AnyChunkSource::new_box(ChunkSourceTagEraser::new(value))
    }
}

impl<Auth: AuthenticationState> From<DynChunkSource<TxKind, Auth>> for UntaggedChunkSource<Auth> {
    fn from(value: DynChunkSource<TxKind, Auth>) -> Self {
        super::AnyChunkSource::new_box(ChunkSourceTagEraser::new(value))
    }
}

impl<Auth: AuthenticationState, ContainerKind, ContainerAuth, Container>
    DynChunkSourceBuilder<TxKind, Auth, ContainerKind, ContainerAuth, Container>
    for (TxKind, Auth, Container)
where
    for<'a> Tx<'a, Auth>: From<AuthenticatedTx<'a>>,
    for<'a> TxDataChunk<'a, Auth>: From<AuthenticatedTxDataChunk<'a>>,
    for<'a> AuthenticatedTxDataChunk<'a>: DataChunkExt<'a, TxKind, (), Auth>,
{
    async fn new_from_location(
        client: &Client,
        location: &TypedArl<TxKind>,
        container: Option<Container>,
    ) -> Result<DynChunkSource<TxKind, Auth>, crate::Error> {
        if container.is_some() {
            Err(Error::UnsupportedDataItem)?;
        }

        let tx = client
            .tx_by_id(location.tx_id())
            .await?
            .ok_or_else(|| Error::TxNotFound(location.tx_id().clone()))?;

        Ok(super::AnyChunkSource::new_box(
            TxChunkSource::new(client.clone(), tx).await?,
        ))
    }
}

impl<Auth: AuthenticationState> TxChunkSource<Auth> {
    pub(super) async fn new(
        client: Client,
        tx: AuthenticatedTx<'static>,
    ) -> Result<Self, crate::Error> {
        let (data_root, data_size) = match tx.data_item() {
            Some(DataItem::External(external)) => {
                (Arc::new(external.data_root().clone()), external.data_size())
            }
            Some(_) => Err(Error::UnsupportedDataItem)?,
            None => Err(Error::NoDataItem(tx.id().clone()))?,
        };
        let tx_offset = client.tx_offset(tx.id()).await?;
        let chunk_map = AnyChunkMap::new(DefaultChunker::chunk_map(data_size));

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

    pub(super) async fn new_from_location(
        client: &Client,
        location: &TypedArl<TxKind>,
    ) -> Result<Self, crate::Error> {
        let tx = client
            .tx_by_id(location.tx_id())
            .await?
            .ok_or_else(|| Error::TxNotFound(location.tx_id().clone()))?;

        Ok(Self::new(client.clone(), tx).await?)
    }
}

impl<Auth: AuthenticationState> ChunkSource<TxKind, Auth> for TxChunkSource<Auth>
where
    for<'b> Tx<'b, Auth>: From<AuthenticatedTx<'b>>,
    for<'b> TxDataChunk<'b, Auth>: From<AuthenticatedTxDataChunk<'b>>,
    for<'b> AuthenticatedTxDataChunk<'b>: DataChunkExt<'b, TxKind, (), Auth>,
{
    fn len(&self) -> u64 {
        self.data_size
    }

    fn chunks(&self) -> &AnyChunkMap {
        &self.chunk_map
    }

    fn item(&self) -> Item<'static, Auth> {
        Item::Tx(self.tx.clone().into())
    }

    async fn retrieve_chunk(
        &self,
        range: Range<u64>,
    ) -> Result<DataChunk<'static, TxKind, Auth>, crate::Error>
    where
        TxKind: ReadableDataItem,
        Auth: AuthenticationState,
    {
        self.chunk_map
            .chunk_at(range.start)
            .ok_or(Error::ChunkNotFound)?;

        let chunk_abs_pos = self.tx_offset.absolute(range.start);
        let chunk = self
            .client
            .retrieve_chunk(chunk_abs_pos, range.start, &self.data_root)
            .await?
            .ok_or(Error::ChunkNotFound)?;
        Ok(chunk.into_state(None::<&()>)?)
    }
}
