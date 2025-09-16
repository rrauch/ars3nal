use crate::Client;
use crate::tx::Offset;
use ario_core::blob::OwnedBlob;
use ario_core::chunking::{Chunker, DefaultChunker, MostlyFixedChunkMap};
use ario_core::data::{DataItem, DataRoot, MaybeOwnedExternalDataItem};
use ario_core::tx::{TxId, ValidatedTx};
use bytes::Buf;
use futures_lite::{AsyncRead, AsyncSeek};
use futures_lite::{FutureExt, ready};
use std::cmp::min;
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
}

pub(crate) struct AsyncDataReader<D: DataSource> {
    pos: u64,
    len: u64,
    client: Client,
    state: State,
    data_source: D,
}

type RetrieveFut =
    Pin<Box<dyn Future<Output = Result<Option<(u64, OwnedBlob)>, super::Error>> + Send>>;

enum State {
    Ready(Option<Chunk>),
    Retrieving(u64, Range<usize>, RetrieveFut),
}

#[derive(Clone)]
struct Chunk {
    inner: Arc<ChunkInner>,
    range: Range<usize>,
}

impl Chunk {
    fn reader(&self, abs_pos: u64) -> Option<Cursor<&[u8]>> {
        if abs_pos < self.inner.offset {
            return None;
        }
        let data_start = self.inner.offset + self.range.start as u64;
        let data_end = self.inner.offset + self.range.end as u64;
        if data_start >= data_end {
            return None;
        }
        if abs_pos >= data_start && abs_pos < data_end {
            let rel_start = (abs_pos - self.inner.offset) as usize;

            // falls within valid range
            let len = (data_end - (data_start + rel_start as u64)) as usize;
            if len == 0 {
                // end of chunk
                return None;
            }
            let rel_end = rel_start + len;
            let bytes = &self.inner.data.bytes()[rel_start..rel_end];
            Some(Cursor::new(bytes))
        } else {
            None
        }
    }
}

struct ChunkInner {
    data: OwnedBlob,
    offset: u64,
}

pub(crate) struct TxDataSource<'a> {
    tx: &'a ValidatedTx<'a>,
    tx_offset: Offset,
    data_item: MaybeOwnedExternalDataItem<'a>,
    chunk_map: MostlyFixedChunkMap<{ 256 * 1024 }>,
}

pub type AsyncTxReader<'a> = AsyncDataReader<TxDataSource<'a>>;

impl<'a> AsyncTxReader<'a> {
    pub async fn new(client: Client, tx: &'a ValidatedTx<'a>) -> Result<Self, super::Error> {
        let data_item = match tx.data_item() {
            Some(DataItem::External(external)) => external,
            Some(_) => Err(Error::UnsupportedDataItem)?,
            None => Err(Error::NoDataItem(tx.id().clone()))?,
        };
        let tx_offset = client.tx_offset(tx.id()).await?;
        let chunk_map = DefaultChunker::chunk_map(data_item.data_size());
        Ok(Self {
            pos: 0,
            len: data_item.data_size(),
            client,
            state: State::Ready(None),
            data_source: TxDataSource {
                data_item,
                tx,
                tx_offset,
                chunk_map,
            },
        })
    }
}

trait DataSource: Send + Unpin {
    fn map_offset(&self, pos: u64) -> Option<(u128, u64, Range<usize>, &DataRoot)>;
}

impl DataSource for TxDataSource<'_> {
    fn map_offset(&self, pos: u64) -> Option<(u128, u64, Range<usize>, &DataRoot)> {
        let chunk_range = self.chunk_map.get_by_offset(pos)?;
        let rel_pos = (pos - chunk_range.start) as usize;
        let len = (chunk_range.end - chunk_range.start) as usize;

        // chunk
        let chunk_abs_pos = self.tx_offset.absolute(chunk_range.start);
        let range = rel_pos..(rel_pos + len);

        Some((
            chunk_abs_pos,
            chunk_range.start,
            range,
            self.data_item.data_root(),
        ))
    }
}

impl<D: DataSource> AsyncDataReader<D> {
    pub fn len(&self) -> u64 {
        self.len
    }

    fn retrieve_chunk(&mut self, pos: u64) -> Result<(), std::io::Error> {
        let (tx_pos, chunk_pos, chunk_range, data_root) = self
            .data_source
            .map_offset(pos)
            .ok_or(std::io::Error::other("seeking beyond eof is not allowed"))?;
        let client = self.client.clone();
        let data_root = data_root.clone();
        let fut = Box::pin(async move {
            client
                .download_chunk(tx_pos, chunk_pos, &data_root)
                .await
                .map(|bytes| bytes.map(|bytes| (chunk_pos, bytes)))
        });
        self.state = State::Retrieving(pos, chunk_range, fut);
        Ok(())
    }

    fn on_chunk(
        &mut self,
        retrieving_pos: u64,
        range: Range<usize>,
        mut fut: RetrieveFut,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match fut.poll(cx) {
            Poll::Pending => {
                self.state = State::Retrieving(retrieving_pos, range, fut);
                Poll::Pending
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(err))),
            Poll::Ready(Ok(None)) => Poll::Ready(Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "chunk not found",
            ))),
            Poll::Ready(Ok(Some((offset, bytes)))) => {
                self.state = State::Ready(Some(Chunk {
                    range,
                    inner: Arc::new(ChunkInner {
                        data: bytes,
                        offset,
                    }),
                }));
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
                    if let Some(cursor) = chunk.reader(pos) {
                        let mut remaining = cursor.remaining();
                        let num_bytes = if remaining > 0 {
                            let num_bytes = min(remaining, buf.len());
                            let start = cursor.position() as usize;
                            let end = start + num_bytes;
                            let input = &cursor.into_inner()[start..end];
                            let output = &mut buf[0..num_bytes];
                            output.copy_from_slice(input);
                            this.pos += num_bytes as u64;
                            num_bytes
                        } else {
                            0
                        };
                        remaining -= num_bytes;
                        if remaining > 0 {
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
                }
                State::Ready(None) => this.retrieve_chunk(pos)?,
                State::Retrieving(retr_pos, range, fut) => {
                    if retr_pos != pos {
                        continue;
                    }
                    ready!(this.on_chunk(retr_pos, range, fut, cx))?;
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
                State::Retrieving(retrieving_pos, range, fut) => {
                    if retrieving_pos != pos {
                        continue;
                    }
                    ready!(this.on_chunk(retrieving_pos, range, fut, cx))?;
                }
                State::Ready(None) => this.retrieve_chunk(pos)?,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use crate::api::Api;
    use crate::data_reader::AsyncDataReader;
    use ario_core::Gateway;
    use ario_core::crypto::hash::{Hasher, Sha256};
    use ario_core::network::Network;
    use ario_core::tx::TxId;
    use futures_lite::AsyncReadExt;
    use hex_literal::hex;
    use std::str::FromStr;

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
        let api = Api::new(reqwest::Client::new(), Network::default(), false);
        let client = Client::builder()
            .enable_netwatch(false)
            .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
            .build();

        let tx_id = TxId::from_str("ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk")?;

        let tx = client
            .tx_by_id(&tx_id)
            .await?
            .unwrap()
            .validate()
            .map_err(|(_, err)| err)?;

        let mut data_reader = AsyncDataReader::new(client.clone(), &tx).await?;
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

        let mut hash = hasher.finalize();
        assert_eq!(
            hash.as_slice(),
            hex!("87a46b9a4720751cfe182b55c75ea49363e4dc55ec7c2d759c9c03ab62a64717")
        );
        Ok(())
    }
}
