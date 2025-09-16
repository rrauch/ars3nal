use crate::Client;
use crate::tx::Offset;
use ario_core::blob::OwnedBlob;
use ario_core::chunking::{DefaultChunker, MostlyFixedChunkMap};
use ario_core::data::{DataItem, MaybeOwnedExternalDataItem};
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
    state: State,
    data_source: D,
}

type RetrieveFut = Pin<Box<dyn Future<Output = Result<Option<Chunk>, super::Error>> + Send>>;

enum State {
    Ready(Option<Chunk>),
    Retrieving(u64, RetrieveFut),
}

#[derive(Clone)]
#[repr(transparent)]
struct Chunk(Arc<(OwnedBlob, Range<u64>)>);

impl Chunk {
    fn range(&self) -> &Range<u64> {
        &self.0.as_ref().1
    }

    fn reader(&self, pos: u64) -> Option<Cursor<&[u8]>> {
        let range = self.range();
        if !range.contains(&pos) {
            return None;
        }

        let range = (pos - range.start) as usize..(range.end - range.start) as usize;

        if range.is_empty() {
            return None;
        }

        Some(Cursor::new(
            &self.0.as_ref().0.bytes()[range.start..range.end],
        ))
    }
}

pub(crate) struct TxDataSource<'a> {
    tx: &'a ValidatedTx<'a>,
    tx_offset: Offset,
    data_item: MaybeOwnedExternalDataItem<'a>,
    chunk_map: MostlyFixedChunkMap<{ 256 * 1024 }>,
    client: Client,
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
            state: State::Ready(None),
            data_source: TxDataSource {
                data_item,
                tx,
                tx_offset,
                chunk_map,
                client,
            },
        })
    }
}

trait DataSource: Send + Unpin {
    fn chunk_range(&self, pos: u64) -> Option<Range<u64>>;

    fn retrieve_chunk(&self, chunk_range: Range<u64>) -> RetrieveFut;
}

impl DataSource for TxDataSource<'_> {
    fn chunk_range(&self, pos: u64) -> Option<Range<u64>> {
        self.chunk_map.get_by_offset(pos)
    }

    fn retrieve_chunk(&self, chunk: Range<u64>) -> RetrieveFut {
        let chunk_abs_pos = self.tx_offset.absolute(chunk.start);
        let client = self.client.clone();
        let data_root = self.data_item.data_root().clone();

        Box::pin(async move {
            Ok(client
                .retrieve_chunk(chunk_abs_pos, chunk.start, &data_root)
                .await?
                .map(|blob| Chunk(Arc::new((blob, chunk)))))
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
        mut fut: RetrieveFut,
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
                State::Retrieving(retr_pos, fut) => {
                    if retr_pos != pos {
                        continue;
                    }
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
                    if retrieving_pos != pos {
                        continue;
                    }
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
    use crate::data_reader::AsyncDataReader;
    use ario_core::Gateway;
    use ario_core::crypto::hash::{Hasher, Sha256};
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

        let hash = hasher.finalize();
        assert_eq!(
            hash.as_slice(),
            hex!("87a46b9a4720751cfe182b55c75ea49363e4dc55ec7c2d759c9c03ab62a64717")
        );
        Ok(())
    }
}
