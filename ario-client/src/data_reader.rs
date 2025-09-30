use crate::Client;
use crate::tx::Offset;
use ario_core::MaybeOwned;
use ario_core::bundle::{AuthenticatedBundleItem, BundleEntry, BundleItemAuthenticator};
use ario_core::chunking::{DefaultChunker, MostlyFixedChunkMap};
use ario_core::data::{AuthenticatedTxDataChunk, Authenticator, DataItem, DataRoot};
use ario_core::tx::{AuthenticatedTx, TxId};
use bytes::Buf;
use futures_lite::{AsyncRead, AsyncSeek};
use futures_lite::{FutureExt, ready};
use itertools::Itertools;
use rangemap::RangeMap;
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::io::{Cursor, ErrorKind, SeekFrom};
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("tx '{0}' does not have a data item")]
    NoDataItem(TxId),
    #[error("unsupported data item")]
    UnsupportedDataItem,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("data validation failed: {0}")]
    DataValidationFailure(String),
}

pub struct AsyncDataReader<D: DataSource> {
    pos: u64,
    len: u64,
    state: State<D::Chunk>,
    data_source: D,
}

type RetrieveFut<C: Chunk> = Pin<Box<dyn Future<Output = Result<Option<C>, super::Error>> + Send>>;

enum State<C: Chunk> {
    Ready(Option<C>),
    Retrieving(u64, RetrieveFut<C>),
}

trait Chunk: Send + Clone + Unpin {
    fn range(&self) -> &Range<u64>;

    fn reader(&self, pos: u64) -> Option<impl Buf>;
}

#[derive(Clone)]
#[repr(transparent)]
struct MultiChunk(Arc<(Vec<TxChunk>, Range<u64>)>);

impl MultiChunk {
    fn new(mut chunks: Vec<TxChunk>) -> Result<Self, Error> {
        if chunks.is_empty() {
            return Err(Error::IoError(std::io::Error::other(
                "multichunk cannot be empty",
            )));
        }
        chunks.sort_unstable_by(|a, b| Ord::cmp(&a.0.chunk_range.start, &b.0.chunk_range.start));
        let range =
            chunks.first().unwrap().0.chunk_range.start..chunks.last().unwrap().0.chunk_range.end;
        Ok(Self(Arc::new((chunks, range))))
    }
}

struct MultiBuf<B: Buf>(VecDeque<B>);

impl<B: Buf> Buf for MultiBuf<B> {
    fn remaining(&self) -> usize {
        self.0.iter().fold(0, |accum, b| accum + b.remaining())
    }

    fn chunk(&self) -> &[u8] {
        self.0.get(0).map(|b| b.chunk()).unwrap_or_else(|| &[])
    }

    fn advance(&mut self, cnt: usize) {
        let mut remaining = cnt;
        while remaining > 0 {
            match self.0.get_mut(0) {
                Some(first) => {
                    let n = min(first.remaining(), remaining);
                    first.advance(n);
                    remaining -= n;
                    if !first.has_remaining() {
                        self.0.pop_front();
                    }
                }
                None => {
                    return;
                }
            }
        }
    }
}

impl Chunk for MultiChunk {
    fn range(&self) -> &Range<u64> {
        &self.0.1
    }

    fn reader(&self, pos: u64) -> Option<impl Buf> {
        if !self.range().contains(&pos) {
            return None;
        }

        let mut found = false;
        let matching_chunks = self
            .0
            .0
            .iter()
            .filter_map(|c| {
                if !found {
                    if c.range().contains(&pos) {
                        // first matching chunk
                        // may be partial
                        found = true;
                        c.reader(pos)
                    } else {
                        None
                    }
                } else {
                    // full chunk
                    c.reader(c.0.chunk_range.start)
                }
            })
            .collect::<VecDeque<_>>();

        if matching_chunks.is_empty() {
            return None;
        }

        Some(MultiBuf(matching_chunks))
    }
}

#[derive(Clone)]
#[repr(transparent)]
struct TxChunk(Arc<Inner>);

impl TxChunk {
    fn new(
        data: AuthenticatedTxDataChunk<'static>,
        chunk_offset: u64,
        data_range: Range<usize>,
    ) -> Self {
        Self(Arc::new(Inner {
            chunk_range: chunk_offset..chunk_offset + (data_range.end - data_range.start) as u64,
            data,
            data_range,
        }))
    }
}

#[derive(Clone)]
struct Inner {
    data: AuthenticatedTxDataChunk<'static>,
    chunk_range: Range<u64>,
    data_range: Range<usize>,
}

impl Chunk for TxChunk {
    fn range(&self) -> &Range<u64> {
        &self.0.chunk_range
    }

    fn reader(&self, pos: u64) -> Option<impl Buf> {
        let range = self.range();
        if !range.contains(&pos) {
            return None;
        }

        let start = self.0.as_ref().data_range.start + (pos - range.start) as usize;

        let range = start..self.0.as_ref().data_range.end;

        if range.is_empty() {
            return None;
        }

        Some(Cursor::new(
            &self.0.as_ref().data.as_ref()[range.start..range.end],
        ))
    }
}

pub struct TxDataSource<'a> {
    tx: MaybeOwned<'a, AuthenticatedTx<'a>>,
    tx_offset: Offset,
    data_root: Arc<DataRoot>,
    chunk_map: MostlyFixedChunkMap<{ 256 * 1024 }>,
    client: Client,
}

impl<'a> TxDataSource<'a> {
    async fn new(
        client: Client,
        tx: impl Into<MaybeOwned<'a, AuthenticatedTx<'a>>>,
    ) -> Result<(Self, u64), super::Error> {
        let tx = tx.into();
        let (data_root, data_size) = match tx.data_item() {
            Some(DataItem::External(external)) => {
                (Arc::new(external.data_root().clone()), external.data_size())
            }
            Some(_) => Err(Error::UnsupportedDataItem)?,
            None => Err(Error::NoDataItem(tx.id().clone()))?,
        };
        let tx_offset = client.tx_offset(tx.id()).await?;
        let chunk_map = DefaultChunker::chunk_map(data_size);
        Ok((
            Self {
                data_root,
                tx,
                tx_offset,
                chunk_map,
                client,
            },
            data_size,
        ))
    }
}

pub type AsyncTxReader<'a> = AsyncDataReader<TxDataSource<'a>>;

impl<'a> AsyncTxReader<'a> {
    pub async fn new(
        client: Client,
        tx: impl Into<MaybeOwned<'a, AuthenticatedTx<'a>>>,
    ) -> Result<Self, super::Error> {
        let (data_source, data_size) = TxDataSource::new(client, tx).await?;
        Ok(Self {
            pos: 0,
            len: data_size,
            state: State::Ready(None),
            data_source,
        })
    }
}

trait DataSource: Send + Unpin {
    type Chunk: Chunk;

    fn chunk_range(&self, pos: u64) -> Option<Range<u64>>;

    fn retrieve_chunk(&self, chunk_range: Range<u64>) -> RetrieveFut<Self::Chunk>;
}

impl DataSource for TxDataSource<'_> {
    type Chunk = TxChunk;

    fn chunk_range(&self, pos: u64) -> Option<Range<u64>> {
        self.chunk_map.get_by_offset(pos)
    }

    fn retrieve_chunk(&self, chunk: Range<u64>) -> RetrieveFut<Self::Chunk> {
        let chunk_abs_pos = self.tx_offset.absolute(chunk.start);
        let client = self.client.clone();
        let data_root = self.data_root.clone();

        Box::pin(async move {
            Ok(client
                .retrieve_chunk(chunk_abs_pos, chunk.start, &data_root)
                .await?
                .map(|validated_chunk| {
                    let len = validated_chunk.len();
                    TxChunk::new(validated_chunk, chunk.start, 0..len)
                }))
        })
    }
}

pub struct BundleItemDataSource<'a> {
    entry: MaybeOwned<'a, BundleEntry<'a>>,
    item: MaybeOwned<'a, AuthenticatedBundleItem<'a>>,
    data_authenticator: Arc<BundleItemAuthenticator<'static>>,
    chunk_map: RangeMap<u64, usize>,
    tx_data_source: Arc<TxDataSource<'static>>,
}

pub type AsyncBundleItemReader<'a> = AsyncDataReader<BundleItemDataSource<'a>>;

impl<'a> AsyncBundleItemReader<'a> {
    pub async fn new(
        client: Client,
        entry: impl Into<MaybeOwned<'a, BundleEntry<'a>>>,
        item: impl Into<MaybeOwned<'a, AuthenticatedBundleItem<'a>>>,
        data_authenticator: impl Into<MaybeOwned<'a, BundleItemAuthenticator<'static>>>,
        tx: impl Into<MaybeOwned<'a, AuthenticatedTx<'static>>>,
    ) -> Result<Self, super::Error> {
        let item = item.into();
        let data_authenticator = data_authenticator.into().into_owned();
        let mut chunk_map = RangeMap::new();
        data_authenticator
            .chunks()
            .into_iter()
            .enumerate()
            .for_each(|(i, c)| chunk_map.insert(c.clone(), i));

        let (tx_data_source, _) = TxDataSource::new(client, tx.into().into_owned()).await?;

        Ok(Self {
            pos: 0,
            len: item.data_size(),
            state: State::Ready(None),
            data_source: BundleItemDataSource {
                entry: entry.into(),
                item,
                data_authenticator: Arc::new(data_authenticator),
                chunk_map,
                tx_data_source: Arc::new(tx_data_source),
            },
        })
    }
}

impl<'a> DataSource for BundleItemDataSource<'a> {
    type Chunk = MultiChunk;

    fn chunk_range(&self, pos: u64) -> Option<Range<u64>> {
        self.chunk_map.get_key_value(&pos).map(|(r, _)| r.clone())
    }

    fn retrieve_chunk(&self, chunk_range: Range<u64>) -> RetrieveFut<Self::Chunk> {
        let offset = self.entry.container_location().offset() + self.item.data_offset();
        let tx_range = chunk_range.start + offset..chunk_range.end + offset;

        // get all underlying chunks
        // could be more than one

        let mut matching_chunks = self
            .tx_data_source
            .chunk_map
            .iter()
            .filter(|chunk| max(tx_range.start, chunk.start) < min(tx_range.end, chunk.end))
            .collect_vec();

        let tx_data_source = self.tx_data_source.clone();
        let data_authenticator = self.data_authenticator.clone();

        Box::pin(async move {
            matching_chunks.sort_unstable_by(|a, b| Ord::cmp(&a.start, &b.start));
            let mut chunks = Vec::with_capacity(matching_chunks.len());
            let mut pos = chunk_range.start;

            for chunk in matching_chunks {
                let remaining = (chunk_range.end - pos) as usize;
                if remaining == 0 {
                    break;
                }

                let mut chunk = tx_data_source
                    .retrieve_chunk(chunk)
                    .await?
                    .ok_or(Error::from(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "chunk not found",
                    )))?;
                let inner = Arc::make_mut(&mut chunk.0);

                let chunk_offset = (tx_range.start - inner.chunk_range.start) as usize;
                inner.chunk_range.start =
                    (inner.chunk_range.start + (chunk_offset as u64)) - offset;
                inner.data_range.start = inner.data_range.start + chunk_offset;
                let len = inner.data_range.end.saturating_sub(inner.data_range.start);
                if len == 0 {
                    continue;
                }
                let len = min(len, remaining);
                inner.data_range.end = inner.data_range.start + len;
                inner.chunk_range.end = inner.chunk_range.start + (len as u64);
                chunks.push(chunk);
                pos += len as u64;
            }

            Ok(if chunks.is_empty() {
                None
            } else {
                let chunk = MultiChunk::new(chunks)?;
                // validate chunk data
                let proof =
                    data_authenticator
                        .proof(chunk.range())
                        .ok_or(Error::DataValidationFailure(
                            "no proof for bundle item chunk available".to_string(),
                        ))?;
                data_authenticator
                    .authenticate(chunk.reader(chunk.range().start).unwrap(), &proof)
                    .map_err(|e| Error::DataValidationFailure(e.to_string()))?;
                Some(chunk)
            })
        })
    }
}

impl<D: DataSource> AsyncDataReader<D> {
    pub fn len(&self) -> u64 {
        self.len
    }

    fn retrieve_chunk(&mut self, pos: u64) -> Result<(), std::io::Error> {
        let chunk_range = self
            .data_source
            .chunk_range(pos)
            .ok_or(std::io::Error::other("seeking beyond eof is not allowed"))?;
        let fut = self.data_source.retrieve_chunk(chunk_range);
        self.state = State::Retrieving(pos, fut);
        Ok(())
    }

    fn on_chunk(
        &mut self,
        retrieving_pos: u64,
        mut fut: RetrieveFut<D::Chunk>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match fut.poll(cx) {
            Poll::Pending => {
                self.state = State::Retrieving(retrieving_pos, fut);
                Poll::Pending
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(err))),
            Poll::Ready(Ok(None)) => Poll::Ready(Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "chunk not found",
            ))),
            Poll::Ready(Ok(Some(chunk))) => {
                self.state = State::Ready(Some(chunk));
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<D: DataSource> AsyncRead for AsyncDataReader<D> {
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
            match std::mem::replace(&mut this.state, State::Ready(None)) {
                State::Ready(Some(chunk)) => {
                    let mut num_bytes = 0;
                    let mut keep_chunk = false;

                    if let Some(reader) = chunk.reader(pos) {
                        let mut remaining = reader.remaining();
                        if remaining > 0 {
                            let n = min(remaining, buf.len());
                            let mut reader = reader.take(n);
                            reader.copy_to_slice(&mut buf[..n]);
                            this.pos += n as u64;
                            num_bytes = n;
                        }
                        remaining -= num_bytes;
                        keep_chunk = remaining > 0 && num_bytes > 0;
                    }

                    if keep_chunk {
                        this.state = State::Ready(Some(chunk));
                    } else {
                        this.state = State::Ready(None);
                    }

                    if num_bytes == 0 {
                        // read more
                        continue;
                    }
                    return Poll::Ready(Ok(num_bytes));
                }
                State::Ready(None) => this.retrieve_chunk(pos)?,
                State::Retrieving(retr_pos, fut) => {
                    ready!(this.on_chunk(retr_pos, fut, cx))?;
                }
            }
        }
    }
}

impl<D: DataSource> AsyncSeek for AsyncDataReader<D> {
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
            match std::mem::replace(&mut this.state, State::Ready(None)) {
                State::Ready(Some(chunk)) => {
                    if chunk.reader(pos).is_some() {
                        this.pos = pos;
                        this.state = State::Ready(Some(chunk));
                        return Poll::Ready(Ok(pos));
                    }
                }
                State::Retrieving(retrieving_pos, fut) => {
                    ready!(this.on_chunk(retrieving_pos, fut, cx))?;
                }
                State::Ready(None) => this.retrieve_chunk(pos)?,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use crate::data_reader::AsyncTxReader;
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

        let mut data_reader = AsyncTxReader::new(client.clone(), &tx).await?;
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
    async fn read_bundle_item_alignment_local_data() -> anyhow::Result<()> {
        init_tracing();
        let client = Client::builder()
            .enable_netwatch(false)
            .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
            .build()
            .await?;

        let tx_id = TxId::from_str("ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk")?;
        let item_id = BundleItemId::from_str("UHVB0gDKDiId6XAeZlCH_9h6h6Tz0we8MuGA0CUYxPE")?;

        let tx = client.tx_by_id(&tx_id).await?.unwrap();

        let mut file =
            tokio::fs::File::open("./testdata/ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk.tx")
                .await?
                .compat();
        let bundle = BundleReader::new(&tx, &mut file).await?;

        let entry = bundle.entries().find(|e| e.id() == &item_id).unwrap();

        let (bundle_item, authenticator) =
            BundleItemReader::read_async(&entry, &mut file, bundle.id().clone()).await?;
        let bundle_item = bundle_item.authenticate()?;

        let chunks = authenticator.chunks().collect_vec();
        assert_eq!(chunks.len(), 3);
        assert_eq!(**chunks.get(0).unwrap(), 0..204794);
        assert_eq!(**chunks.get(1).unwrap(), 204794..466938);
        assert_eq!(**chunks.get(2).unwrap(), 466938..598382);

        Ok(())
    }
}
