use crate::db::{Read, Transaction, TxScope};
use crate::wal::WalFileChunks;
use futures_lite::{AsyncRead, AsyncSeek};
use std::io::{Cursor, Read as ReadExt, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_util::bytes::Buf;

struct FileReader<'tx, C: TxScope>
where
    Transaction<C>: Read,
{
    offset: u64,
    len: u64,
    state: State<'tx, C>,
}

impl<'tx, C: TxScope> FileReader<'tx, C>
where
    Transaction<C>: Read,
{
    async fn open(wal_file_id: u64, tx: &'tx mut Transaction<C>) -> Result<Self, crate::Error> {
        let chunks = match tx.wal_file_chunks(wal_file_id).await? {
            None => Err(super::Error::FileNotFound(wal_file_id))?,
            Some(chunks) => WalFileChunks::try_from_iter(chunks.into_iter())?,
        };

        Ok(Self {
            offset: 0,
            len: chunks.len,
            state: State::Ready(Inner::new(wal_file_id, chunks, tx)),
        })
    }

    fn invalid_state_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, "invalid reader state")
    }
}

enum State<'tx, C: TxScope>
where
    Transaction<C>: Read,
{
    Ready(Inner<'tx, C>),
    RetrievingChunk {
        fut: Pin<Box<dyn Future<Output = Result<Inner<'tx, C>, crate::Error>> + Send + 'tx>>,
    },
    Invalid,
}

struct Inner<'tx, C: TxScope> {
    file_id: u64,
    tx: &'tx mut Transaction<C>,
    buf: Option<Cursor<Vec<u8>>>,
    chunks: WalFileChunks,
}

impl<'tx, C: TxScope> Inner<'tx, C>
where
    Transaction<C>: Read,
{
    async fn retrieve_chunk(mut self, offset: u64) -> Result<Self, crate::Error> {
        self.buf = None;
        let (rel_offset, content_hash) = match self.chunks.range_map.get_key_value(&offset) {
            Some((range, hash)) => (offset - range.start, hash),
            None => Err(super::Error::NoChunkForOffset(offset))?,
        };

        let mut buf = Cursor::new(
            self.tx
                .wal_content(content_hash)
                .await?
                .ok_or_else(|| super::Error::ContentNotFound(content_hash.0.to_string()))?,
        );

        buf.set_position(rel_offset);

        self.buf = Some(buf);
        Ok(self)
    }
}

impl<'tx, C: TxScope> Inner<'tx, C>
where
    Transaction<C>: Read,
{
    fn new(file_id: u64, chunks: WalFileChunks, tx: &'tx mut Transaction<C>) -> Self {
        Self {
            file_id,
            tx,
            buf: None,
            chunks,
        }
    }
}

impl<'tx, C: TxScope> AsyncRead for FileReader<'tx, C>
where
    Transaction<C>: Read,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            match std::mem::replace(&mut self.state, State::Invalid) {
                State::Ready(mut inner) => {
                    match inner.buf.take() {
                        Some(mut data) if data.has_remaining() => {
                            // buffer not empty yet
                            let n = data.read(buf)?;
                            self.offset += n as u64;
                            if data.has_remaining() {
                                inner.buf = Some(data);
                            }
                            self.state = State::Ready(inner);
                            return Poll::Ready(Ok(n));
                        }
                        _ => {
                            // buffer empty
                            if self.offset >= self.len {
                                // eof
                                self.state = State::Ready(inner);
                                return Poll::Ready(Ok(0));
                            }

                            // need to retrieve chunk
                            self.state = State::RetrievingChunk {
                                fut: Box::pin(inner.retrieve_chunk(self.offset)),
                            };
                            continue;
                        }
                    }
                }
                State::RetrievingChunk { mut fut } => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(inner)) => {
                        self.state = State::Ready(inner);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
                    Poll::Pending => {
                        self.state = State::RetrievingChunk { fut };
                        return Poll::Pending;
                    }
                },
                State::Invalid => return Poll::Ready(Err(Self::invalid_state_error())),
            }
        }
    }
}

impl<'tx, C: TxScope> AsyncSeek for FileReader<'tx, C>
where
    Transaction<C>: Read,
{
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<std::io::Result<u64>> {
        let pos = match pos {
            SeekFrom::Start(pos) => pos,
            SeekFrom::End(pos) => self.len.saturating_add_signed(pos),
            SeekFrom::Current(pos) => self.offset.saturating_add_signed(pos),
        };

        if pos >= self.len {
            return Poll::Ready(Err(std::io::Error::other(
                "Seeking beyond EOF not supported",
            )));
        }

        loop {
            match std::mem::replace(&mut self.state, State::Invalid) {
                State::Ready(inner) => {
                    if self.offset == pos {
                        // already at correct offset
                        self.state = State::Ready(inner);
                        return Poll::Ready(Ok(pos));
                    } else {
                        // seek
                        self.state = State::RetrievingChunk {
                            fut: Box::pin(inner.retrieve_chunk(pos)),
                        };
                        self.offset = pos;
                        continue;
                    }
                }
                State::RetrievingChunk { mut fut } => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(inner)) => {
                        self.state = State::Ready(inner);
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
                    Poll::Pending => {
                        self.state = State::RetrievingChunk { fut };
                        return Poll::Pending;
                    }
                },
                State::Invalid => return Poll::Ready(Err(Self::invalid_state_error())),
            }
        }
    }
}
