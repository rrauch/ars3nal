use crate::db::{Transaction, TxScope, Write};
use crate::wal::WalFileMetadata;
use ario_core::buffer::HeapCircularBuffer;
use ario_core::crypto::hash::{Blake3, HasherExt};
use futures_lite::AsyncWrite;
use std::cmp::min;
use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_util::bytes::{Buf, BufMut};

pub(crate) struct FileWriter<'tx, C: TxScope>
where
    Transaction<C>: Write,
{
    state: State<'tx, C>,
    file_id: u64,
    bytes_written: u64,
}

impl<'tx, C: TxScope> FileWriter<'tx, C>
where
    Transaction<C>: Write,
{
    pub async fn new(
        chunk_size: u32,
        tx: &'tx mut Transaction<C>,
        metadata: &WalFileMetadata,
    ) -> Result<Self, crate::Error> {
        let buf = HeapCircularBuffer::new(chunk_size as usize);
        let file_id = tx.new_wal_file(metadata).await?;
        let inner = Inner {
            file_id,
            tx,
            buf,
            chunk_no: 0,
        };
        Ok(Self {
            state: State::Buffering(inner),
            file_id,
            bytes_written: 0,
        })
    }

    #[inline]
    pub(crate) fn file_id(&self) -> u64 {
        self.file_id
    }

    #[inline]
    pub(crate) fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    fn invalid_state_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, "invalid writer state")
    }

    fn closing_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, "writer is closing")
    }
}

enum State<'tx, C: TxScope>
where
    Transaction<C>: Write,
{
    Buffering(Inner<'tx, C>),
    Committing {
        fut: Pin<Box<dyn Future<Output = Result<Inner<'tx, C>, crate::Error>> + Send + 'tx>>,
    },
    Closing {
        fut: Pin<Box<dyn Future<Output = Result<(), crate::Error>> + Send + 'tx>>,
    },
    Invalid,
}

struct Inner<'tx, C: TxScope> {
    file_id: u64,
    tx: &'tx mut Transaction<C>,
    buf: HeapCircularBuffer,
    chunk_no: usize,
}

impl<'tx, C: TxScope> Inner<'tx, C>
where
    Transaction<C>: Write,
{
    async fn commit_chunk(&mut self) -> Result<(), crate::Error> {
        if !self.buf.is_empty() {
            let content = self.buf.make_contiguous();
            let len = content.len();
            let content_hash = Blake3::digest(content);
            self.tx
                .insert_wal_content(content_hash.as_slice(), content)
                .await?;

            self.tx
                .insert_wal_chunk(self.file_id, self.chunk_no, content_hash.as_slice())
                .await?;

            self.buf.consume(len);
            self.chunk_no += 1;
        }
        Ok(())
    }

    async fn close(mut self) -> Result<(), crate::Error> {
        self.commit_chunk().await?;
        Ok(())
    }

    fn start_commit(
        mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Inner<'tx, C>, crate::Error>> + Send + 'tx>> {
        Box::pin(async move {
            self.commit_chunk().await?;
            Ok(self)
        })
    }
}

impl<'tx, C: TxScope> AsyncWrite for FileWriter<'tx, C>
where
    Transaction<C>: Write,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            match std::mem::replace(&mut self.state, State::Invalid) {
                State::Buffering(mut inner) => {
                    if inner.buf.is_full() {
                        // time to flush
                        self.state = State::Committing {
                            fut: inner.start_commit(),
                        };
                        continue;
                    }

                    let n = min(buf.len(), inner.buf.remaining_mut());
                    self.bytes_written += copy(&mut inner.buf, &mut Cursor::new(&buf[..n]));
                    self.state = State::Buffering(inner);
                    return Poll::Ready(Ok(n));
                }
                State::Committing { mut fut } => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(inner)) => {
                        self.state = State::Buffering(inner);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
                    Poll::Pending => {
                        self.state = State::Committing { fut };
                        return Poll::Pending;
                    }
                },
                State::Closing { fut } => {
                    self.state = State::Closing { fut };
                    return Poll::Ready(Err(Self::closing_error()));
                }
                State::Invalid => return Poll::Ready(Err(Self::invalid_state_error())),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            match std::mem::replace(&mut self.state, State::Invalid) {
                State::Buffering(inner) => {
                    if inner.buf.is_full() {
                        // time to flush
                        self.state = State::Committing {
                            fut: inner.start_commit(),
                        };
                        continue;
                    }
                    // don't flush yet
                    self.state = State::Buffering(inner);
                    return Poll::Ready(Ok(()));
                }
                State::Committing { mut fut } => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(inner)) => {
                        self.state = State::Buffering(inner);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
                    Poll::Pending => {
                        self.state = State::Committing { fut };
                        return Poll::Pending;
                    }
                },
                State::Closing { fut } => {
                    self.state = State::Closing { fut };
                    return Poll::Ready(Err(Self::closing_error()));
                }
                State::Invalid => return Poll::Ready(Err(Self::invalid_state_error())),
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            match std::mem::replace(&mut self.state, State::Invalid) {
                State::Buffering(inner) => {
                    if !inner.buf.is_empty() {
                        // flush remaining data
                        self.state = State::Committing {
                            fut: inner.start_commit(),
                        };
                        continue;
                    }
                    // ready to close
                    self.state = State::Closing {
                        fut: Box::pin(async move { inner.close().await }),
                    };
                    continue;
                }
                State::Committing { mut fut } => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(inner)) => {
                        self.state = State::Buffering(inner);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
                    Poll::Pending => {
                        self.state = State::Committing { fut };
                        return Poll::Pending;
                    }
                },
                State::Closing { mut fut } => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
                    Poll::Pending => {
                        self.state = State::Closing { fut };
                        return Poll::Pending;
                    }
                },
                State::Invalid => return Poll::Ready(Err(Self::invalid_state_error())),
            }
        }
    }
}

fn copy(buf: &mut impl BufMut, input: &mut impl Buf) -> u64 {
    let mut n = 0;
    loop {
        if !input.has_remaining() {
            break;
        }
        let chunk_len = buf.chunk_mut().len();
        if chunk_len == 0 {
            break;
        }

        let len = min(input.remaining(), chunk_len);

        // SAFETY: used solely for writing initialized bytes
        let out = &mut unsafe { chunk_mut_slice_unsafe(buf) }[..len];

        out.copy_from_slice(&input.chunk()[..len]);
        input.advance(len);
        unsafe { buf.advance_mut(len) }
        n += len as u64;
    }
    n
}

/// The caller **must** ensure that no uninitialized bytes are read from or written to the retured slice.
unsafe fn chunk_mut_slice_unsafe(buf: &mut impl BufMut) -> &mut [u8] {
    unsafe {
        let maybe_uninit = buf.chunk_mut().as_uninit_slice_mut();
        std::slice::from_raw_parts_mut(maybe_uninit.as_mut_ptr() as *mut _, maybe_uninit.len())
    }
}
