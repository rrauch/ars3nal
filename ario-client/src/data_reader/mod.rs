mod bundle_item;
mod chunk_reader;
mod tx;

use crate::data_reader::bundle_item::BundleItemChunkSource;
use crate::data_reader::chunk_reader::ChunkReader;
use crate::data_reader::tx::TxChunkSource;
use crate::location::{Arl, ArlType, BundleItemArl, TxArl, TypedArl};
use crate::{Client, location};
use ario_core::buffer::TypedByteBuffer;
use ario_core::bundle::{BundleItemId, BundleItemKind};
use ario_core::chunking::AnyChunkMap;
use ario_core::data::{BundleItemDataAuthenticityProof, DataChunk};
use ario_core::tx::{TxId, TxKind};
use ario_core::{Authenticated, AuthenticationState, Item, Unauthenticated};
use async_trait::async_trait;
use futures_lite::{AsyncRead, AsyncSeek};
use itertools::Itertools;
use send_future::SendFuture as _;
use std::iter;
use std::marker::PhantomData;
use std::ops::Range;
use std::sync::Arc;
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

pub trait DataReader: AsyncRead + AsyncSeek + Send + Sync + Unpin {
    fn len(&self) -> u64;

    fn item(&self) -> Item<'static, Authenticated>;
}

impl<T: DataReader + ?Sized> DataReader for Box<T> {
    fn len(&self) -> u64 {
        self.as_ref().len()
    }

    fn item(&self) -> Item<'static, Authenticated> {
        self.as_ref().item()
    }
}

pub trait ReadableDataItem: Send + Sync + Unpin + 'static {}
impl ReadableDataItem for TxKind {}
impl ReadableDataItem for BundleItemKind {}
impl ReadableDataItem for () {}

//todo: seal trait

pub(crate) type MaybeAuthenticatedDataItemReader<T: ReadableDataItem, Auth: AuthenticationState> =
    ChunkReader<T, Auth, DynChunkSource<T, Auth>>;

pub type DataItemReader<T: ReadableDataItem> = MaybeAuthenticatedDataItemReader<T, Authenticated>;
pub(crate) type UnauthenticatedDataItemReader<T: ReadableDataItem> =
    MaybeAuthenticatedDataItemReader<T, Unauthenticated>;

pub type TxReader = DataItemReader<TxKind>;
pub type BundleItemReader = DataItemReader<BundleItemKind>;

impl Client {
    pub async fn read_any<'a, L: Into<Arl>>(
        &self,
        location: L,
    ) -> Result<impl DataReader + 'static, super::Error> {
        let location = location.into();

        match location {
            Arl::Tx(tx) => Ok(Box::new(self.read_tx(tx).await?) as Box<dyn DataReader>),
            Arl::BundleItem(item) => {
                Ok(Box::new(self.read_bundle_item(item).await?) as Box<dyn DataReader>)
            }
        }
    }

    pub async fn read_tx<L: Into<TxArl>>(&self, location: L) -> Result<TxReader, super::Error> {
        self.data_item_reader(location.into()).await
    }

    pub async fn read_bundle_item<L: Into<BundleItemArl>>(
        &self,
        location: L,
    ) -> Result<BundleItemReader, super::Error> {
        self.data_item_reader(location.into()).await
    }

    pub(crate) async fn any_reader<Auth: AuthenticationState>(
        &self,
        location: impl Into<Arl>,
    ) -> Result<MaybeAuthenticatedDataItemReader<(), Auth>, super::Error>
    where
        (TxKind, Auth, UntaggedChunkSource<Unauthenticated>): DynChunkSourceBuilder<
                TxKind,
                Auth,
                (),
                Unauthenticated,
                UntaggedChunkSource<Unauthenticated>,
            >,
        (BundleItemKind, Auth, UntaggedChunkSource<Unauthenticated>): DynChunkSourceBuilder<
                BundleItemKind,
                Auth,
                (),
                Unauthenticated,
                UntaggedChunkSource<Unauthenticated>,
            >,
    {
        let location = location.into();

        match location {
            Arl::Tx(tx) => Ok(self.data_item_reader(tx).await?.into_untagged()),
            Arl::BundleItem(item) => Ok(self.data_item_reader(item).await?.into_untagged()),
        }
    }

    pub(crate) async fn data_item_reader<T: ReadableDataItem + ArlType, Auth: AuthenticationState>(
        &self,
        location: impl Into<TypedArl<T>>,
    ) -> Result<MaybeAuthenticatedDataItemReader<T, Auth>, super::Error>
    where
        Arl: From<TypedArl<T>>,
        (T, Auth, UntaggedChunkSource<Unauthenticated>): DynChunkSourceBuilder<
                T,
                Auth,
                (),
                Unauthenticated,
                UntaggedChunkSource<Unauthenticated>,
            >,
    {
        let location = location.into();
        let arl = location.clone().into();
        let item = self
            .item_by_location(&arl)
            .await?
            .ok_or(location::Error::NotFound)?;

        let item_id = item.id();
        if location.item_id() != &item_id {
            Err(location::Error::ItemMismatch {
                expected: item_id,
                actual: location.item_id().clone(),
            })?;
        }

        let mut locations = iter::successors(Some(arl.clone()), |p| p.parent()).collect_vec();
        locations.reverse();

        if locations.len() > 16 {
            Err(Error::MaxNestingDepthExceeded {
                max: 16,
                got: locations.len(),
            })?;
        }

        let mut iter = locations.iter().peekable();

        let mut intermediate_source: Option<UntaggedChunkSource<Unauthenticated>> = None;

        while let Some(arl) = iter.next() {
            if iter.peek().is_none() {
                // final item
                return Ok(ChunkReader::new(
                    <(T, Auth, UntaggedChunkSource<Unauthenticated>) as DynChunkSourceBuilder<
                        T,
                        Auth,
                        (),
                        Unauthenticated,
                        UntaggedChunkSource<Unauthenticated>,
                    >>::new_from_location(
                        &self, &location, intermediate_source.take()
                    )
                    .send()
                    .await?,
                ));
            } else {
                intermediate_source = Some(match arl {
                    Arl::Tx(tx_arl) => {
                        if intermediate_source.is_some() {
                            Err(Error::UnsupportedDataItem)?;
                        }
                        UntaggedChunkSource::<Unauthenticated>::from(
                            TxChunkSource::new_from_location(&self, tx_arl).await?,
                        )
                    }
                    Arl::BundleItem(item_arl) => UntaggedChunkSource::<Unauthenticated>::from(
                        BundleItemChunkSource::new_from_location(
                            &self,
                            item_arl,
                            intermediate_source
                                .take()
                                .ok_or(Error::UnsupportedDataItem)?,
                        )
                        .send()
                        .await?,
                    ),
                });
            }
        }

        unreachable!("locations must not be empty")
    }
}

trait DataChunkExt<'a, T: ReadableDataItem, Authenticator, Output: AuthenticationState> {
    fn into_buffer(
        self,
        authenticator: Option<&Authenticator>,
    ) -> Result<TypedByteBuffer<'a, (T, Output)>, Error>;

    fn into_state(
        self,
        authenticator: Option<&Authenticator>,
    ) -> Result<DataChunk<'a, T, Output>, Error>;
}

impl<'a, T: ReadableDataItem, Authenticator> DataChunkExt<'a, T, Authenticator, Authenticated>
    for DataChunk<'a, T, Authenticated>
{
    fn into_buffer(
        self,
        _: Option<&Authenticator>,
    ) -> Result<TypedByteBuffer<'a, (T, Authenticated)>, Error> {
        Ok(self.authenticated_data())
    }

    fn into_state(
        self,
        _: Option<&Authenticator>,
    ) -> Result<DataChunk<'a, T, Authenticated>, Error> {
        Ok(self)
    }
}

impl<'a, T: ReadableDataItem, Authenticator> DataChunkExt<'a, T, Authenticator, Unauthenticated>
    for DataChunk<'a, T, Authenticated>
{
    fn into_buffer(
        self,
        auth: Option<&Authenticator>,
    ) -> Result<TypedByteBuffer<'a, (T, Unauthenticated)>, Error> {
        Ok(self.into_state(auth)?.danger_unauthenticated_data())
    }

    fn into_state(
        self,
        _: Option<&Authenticator>,
    ) -> Result<DataChunk<'a, T, Unauthenticated>, Error> {
        Ok(self.invalidate())
    }
}

impl<'a, T: ReadableDataItem, Authenticator> DataChunkExt<'a, T, Authenticator, Unauthenticated>
    for DataChunk<'a, T, Unauthenticated>
{
    fn into_buffer(
        self,
        _: Option<&Authenticator>,
    ) -> Result<TypedByteBuffer<'a, (T, Unauthenticated)>, Error> {
        Ok(self.danger_unauthenticated_data())
    }

    fn into_state(
        self,
        _: Option<&Authenticator>,
    ) -> Result<DataChunk<'a, T, Unauthenticated>, Error> {
        Ok(self)
    }
}

impl<'a> DataChunkExt<'a, BundleItemKind, BundleItemDataAuthenticityProof<'_>, Authenticated>
    for DataChunk<'a, BundleItemKind, Unauthenticated>
{
    fn into_buffer(
        self,
        authenticator: Option<&BundleItemDataAuthenticityProof<'_>>,
    ) -> Result<TypedByteBuffer<'a, (BundleItemKind, Authenticated)>, Error> {
        Ok(self.into_state(authenticator)?.authenticated_data())
    }

    fn into_state(
        self,
        authenticator: Option<&BundleItemDataAuthenticityProof<'_>>,
    ) -> Result<DataChunk<'a, BundleItemKind, Authenticated>, Error> {
        let authenticator = authenticator.ok_or(Error::DataAuthenticationFailure(
            "data authenticator is missing".to_string(),
        ))?;
        self.authenticate(authenticator)
            .map_err(|(_, err)| Error::DataAuthenticationFailure(err.to_string()))
    }
}

#[async_trait::async_trait]
pub trait ChunkSource<T, Auth>: Send + Sync + Unpin {
    fn len(&self) -> u64;
    fn chunks(&self) -> &AnyChunkMap;
    fn item(&self) -> Item<'static, Auth>
    where
        Auth: AuthenticationState;

    async fn retrieve_chunk(
        &self,
        range: Range<u64>,
    ) -> Result<DataChunk<'static, T, Auth>, crate::Error>
    where
        T: ReadableDataItem,
        Auth: AuthenticationState;
}

#[async_trait]
impl<T, Auth, S: ChunkSource<T, Auth> + ?Sized> ChunkSource<T, Auth> for Arc<S> {
    #[inline]
    fn len(&self) -> u64 {
        self.as_ref().len()
    }

    #[inline]
    fn chunks(&self) -> &AnyChunkMap {
        self.as_ref().chunks()
    }

    #[inline]
    fn item(&self) -> Item<'static, Auth>
    where
        Auth: AuthenticationState,
    {
        self.as_ref().item()
    }

    #[inline]
    async fn retrieve_chunk(
        &self,
        range: Range<u64>,
    ) -> Result<DataChunk<'static, T, Auth>, crate::Error>
    where
        T: ReadableDataItem,
        Auth: AuthenticationState,
    {
        self.as_ref().retrieve_chunk(range).await
    }
}

#[async_trait]
impl<T, Auth, S: ChunkSource<T, Auth> + ?Sized> ChunkSource<T, Auth> for Box<S> {
    #[inline]
    fn len(&self) -> u64 {
        self.as_ref().len()
    }

    #[inline]
    fn chunks(&self) -> &AnyChunkMap {
        self.as_ref().chunks()
    }

    #[inline]
    fn item(&self) -> Item<'static, Auth>
    where
        Auth: AuthenticationState,
    {
        self.as_ref().item()
    }

    #[inline]
    async fn retrieve_chunk(
        &self,
        range: Range<u64>,
    ) -> Result<DataChunk<'static, T, Auth>, crate::Error>
    where
        T: ReadableDataItem,
        Auth: AuthenticationState,
    {
        self.as_ref().retrieve_chunk(range).await
    }
}

type DynChunkSource<T: ReadableDataItem, Auth: AuthenticationState> =
    Box<dyn ChunkSource<T, Auth> + 'static>;
type UntaggedChunkSource<Auth: AuthenticationState> = DynChunkSource<(), Auth>;

#[repr(transparent)]
struct ChunkSourceTagEraser<T: ReadableDataItem, Auth, CS: ChunkSource<T, Auth>>(
    CS,
    PhantomData<(T, Auth)>,
);

impl<T: ReadableDataItem, Auth: AuthenticationState, CS: ChunkSource<T, Auth>>
    ChunkSourceTagEraser<T, Auth, CS>
where
    for<'a> DataChunk<'a, (), Auth>: From<DataChunk<'a, T, Auth>>,
{
    pub(crate) fn new(source: CS) -> Self {
        Self(source, PhantomData)
    }
}

#[async_trait]
impl<T: ReadableDataItem, Auth: AuthenticationState, CS: ChunkSource<T, Auth>> ChunkSource<(), Auth>
    for ChunkSourceTagEraser<T, Auth, CS>
where
    for<'a> DataChunk<'a, (), Auth>: From<DataChunk<'a, T, Auth>>,
{
    #[inline]
    fn len(&self) -> u64 {
        self.0.len()
    }

    #[inline]
    fn chunks(&self) -> &AnyChunkMap {
        self.0.chunks()
    }

    #[inline]
    fn item(&self) -> Item<'static, Auth>
    where
        Auth: AuthenticationState,
    {
        self.0.item()
    }

    async fn retrieve_chunk(
        &self,
        range: Range<u64>,
    ) -> Result<DataChunk<'static, (), Auth>, crate::Error>
    where
        (): ReadableDataItem,
        Auth: AuthenticationState,
    {
        self.0.retrieve_chunk(range).await.map(|chunk| chunk.into())
    }
}

#[async_trait::async_trait]
trait DynChunkSourceBuilder<
    T: ReadableDataItem + ArlType,
    Auth: AuthenticationState,
    ContainerKind,
    ContainerAuth,
    Container,
>
{
    async fn new_from_location(
        client: &Client,
        location: &TypedArl<T>,
        container: Option<Container>,
    ) -> Result<DynChunkSource<T, Auth>, crate::Error>;
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use crate::data_reader::ChunkReader;
    use crate::data_reader::DataReader;
    use crate::data_reader::tx::TxChunkSource;
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
        let mut data_reader = ChunkReader::new(TxChunkSource::new(client.clone(), tx).await?);
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

        let mut reader = client.read_any(arl).await?;

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
    async fn read_nested_bundle_item() -> anyhow::Result<()> {
        init_tracing();
        let client = Client::builder()
            .enable_netwatch(false)
            .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
            .build()
            .await?;

        let arl = Arl::from_str(
            "ar://xczOqUZQb-vjzD21PSJC7qRGZkX4-3KvFu1-DEGFJO4/nYeYq2C89p7soY7R5jusF_OgZbtDXwNGNT9k0L1mPb4/BF0SmGfQPOhH3oKVzifUOoyJlf2nrCroiNTfnEXvy9M",
        )?;
        assert_eq!(
            arl.tx_id(),
            &TxId::from_str("xczOqUZQb-vjzD21PSJC7qRGZkX4-3KvFu1-DEGFJO4")?
        );
        assert_eq!(
            arl.as_bundle_item_arl().unwrap().bundle_item_id(),
            &BundleItemId::from_str("BF0SmGfQPOhH3oKVzifUOoyJlf2nrCroiNTfnEXvy9M")?
        );
        assert_eq!(arl.depth(), 2);

        let mut reader = client.read_any(arl).await?;

        let len = reader.len();
        let mut buf = vec![];
        reader.read_to_end(&mut buf).await?;
        assert_eq!(buf.len(), len as usize);
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
