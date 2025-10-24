use crate::data_reader::{
    ChunkSource, DataReader, DynChunkSource, MaybeAuthenticatedDataItemReader, ReadableDataItem,
    UntaggedChunkSource,
};
use ario_core::buffer::{OwnedTypedByteBufferCursor, TypedByteBuffer};
use ario_core::chunking::ChunkMap;
use ario_core::data::DataChunk;
use ario_core::{Authenticated, AuthenticationState, Item, Unauthenticated};
use bytes::Buf;
use futures_lite::FutureExt;
use futures_lite::{AsyncRead, AsyncSeek, ready};
use std::cmp::min;
use std::io::{ErrorKind, Seek, SeekFrom};
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

pub(crate) struct ChunkReader<
    T: ReadableDataItem,
    Auth: AuthenticationState,
    D: ChunkSource<T, Auth>,
    const FORCE_READING: bool = false,
> {
    pos: u64,
    len: u64,
    state: State<T, Auth>,
    data_source: Arc<D>,
    _phantom: PhantomData<T>,
}

type RetrieveFut<T, Auth> =
    Pin<Box<dyn Future<Output = Result<DataChunk<'static, T, Auth>, crate::Error>> + Send>>;

impl<T: ReadableDataItem, Auth: AuthenticationState> MaybeAuthenticatedDataItemReader<T, Auth>
where
    UntaggedChunkSource<Auth>: From<DynChunkSource<T, Auth>>,
{
    pub fn into_untagged(mut self) -> MaybeAuthenticatedDataItemReader<(), Auth> {
        {
            // drop the state to free the data_source
            self.state = State::default();
        }
        let data_source = match Arc::try_unwrap(self.data_source) {
            Ok(data_source) => UntaggedChunkSource::from(data_source),
            Err(arc) => UntaggedChunkSource::from(Box::new(arc)),
        };

        MaybeAuthenticatedDataItemReader {
            pos: self.pos,
            len: self.len,
            state: State::default(),
            data_source: Arc::new(data_source),
            _phantom: PhantomData,
        }
    }
}

trait AllowReading<T, Auth: AuthenticationState> {
    fn read_chunk(chunk: DataChunk<T, Auth>) -> TypedByteBuffer<(T, Auth)>;
}

impl<T: ReadableDataItem, D: ChunkSource<T, Authenticated>, const FORCE_READING: bool>
    AllowReading<T, Authenticated> for ChunkReader<T, Authenticated, D, FORCE_READING>
{
    fn read_chunk(chunk: DataChunk<T, Authenticated>) -> TypedByteBuffer<(T, Authenticated)> {
        chunk.authenticated_data()
    }
}

impl<T: ReadableDataItem, D: ChunkSource<T, Unauthenticated>> AllowReading<T, Unauthenticated>
    for ChunkReader<T, Unauthenticated, D, true>
{
    fn read_chunk(chunk: DataChunk<T, Unauthenticated>) -> TypedByteBuffer<(T, Unauthenticated)> {
        chunk.danger_unauthenticated_data()
    }
}

impl<T: ReadableDataItem, Auth: AuthenticationState, D: ChunkSource<T, Auth>>
    ChunkReader<T, Auth, D>
{
    pub(super) fn new(data_source: D) -> Self {
        Self {
            pos: 0,
            len: data_source.len(),
            state: State::default(),
            data_source: Arc::new(data_source),
            _phantom: PhantomData,
        }
    }
}

enum State<T: ReadableDataItem, Auth: AuthenticationState> {
    Ready {
        data: Option<OwnedTypedByteBufferCursor<(T, Auth)>>,
    },
    Retrieving {
        fut: Mutex<RetrieveFut<T, Auth>>,
    },
}

impl<T: ReadableDataItem, Auth: AuthenticationState> Default for State<T, Auth> {
    fn default() -> Self {
        Self::Ready { data: None }
    }
}

impl<'a, T: ReadableDataItem, D: ChunkSource<T, Authenticated> + 'static, const FORCE_READING: bool>
    DataReader for ChunkReader<T, Authenticated, D, FORCE_READING>
where
    Self: AllowReading<T, Authenticated>,
{
    fn len(&self) -> u64 {
        self.len
    }

    fn item(&self) -> Item<'static, Authenticated> {
        self.data_source.item()
    }
}

impl<'a, T: ReadableDataItem, Unauthenticated, D: ChunkSource<T, Unauthenticated> + 'static>
    ChunkReader<T, Unauthenticated, D>
where
    Unauthenticated: AuthenticationState,
{
    /// Danger: exposes unauthenticated data
    pub(crate) fn danger_make_readable(self) -> impl AsyncRead + AsyncSeek + Send + Unpin
    where
        ChunkReader<T, Unauthenticated, D, true>: AllowReading<T, Unauthenticated>,
    {
        self.make_readable()
    }

    fn make_readable(self) -> ChunkReader<T, Unauthenticated, D, true> {
        ChunkReader {
            pos: self.pos,
            len: self.len,
            state: self.state,
            data_source: self.data_source,
            _phantom: PhantomData,
        }
    }
}

impl<
    T: ReadableDataItem,
    Auth: AuthenticationState,
    D: ChunkSource<T, Auth> + 'static,
    const FORCE_READING: bool,
> ChunkReader<T, Auth, D, FORCE_READING>
where
    Self: AllowReading<T, Auth>,
{
    pub fn len(&self) -> u64 {
        self.len
    }

    fn retrieve_chunk(&mut self, pos: u64) -> Result<(), std::io::Error> {
        let chunk = self
            .data_source
            .chunks()
            .chunk_at(pos)
            .ok_or(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                format!("no chunk found for pos {}", pos),
            ))?
            .clone();

        let data_source = self.data_source.clone();
        let fut = Box::pin(async move { data_source.retrieve_chunk(chunk).await });

        self.state = State::Retrieving {
            fut: Mutex::new(fut),
        };
        self.pos = pos;
        Ok(())
    }

    fn on_chunk(
        &mut self,
        mutex: Mutex<RetrieveFut<T, Auth>>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let mut fut = mutex.lock().unwrap();

        match fut.poll(cx) {
            Poll::Pending => {
                drop(fut);
                self.state = State::Retrieving { fut: mutex };
                Poll::Pending
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(err))),
            Poll::Ready(Ok(chunk)) => {
                if !chunk.range().contains(&self.pos) {
                    return Poll::Ready(Err(std::io::Error::other("invalid chunk range")));
                }

                // trim & skip padding if any
                let leading_padding = self.pos - chunk.offset();

                let mut data = <Self as AllowReading<T, Auth>>::read_chunk(chunk);

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

impl<
    T: ReadableDataItem,
    Auth: AuthenticationState,
    D: ChunkSource<T, Auth> + 'static,
    const FORCE_READING: bool,
> AsyncRead for ChunkReader<T, Auth, D, FORCE_READING>
where
    Self: AllowReading<T, Auth>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let pos = self.pos;
        if pos >= self.len {
            // eof
            return Poll::Ready(Ok(0));
        }

        loop {
            match std::mem::replace(&mut self.state, State::default()) {
                State::Ready {
                    data: Some(mut data),
                } => {
                    if data.has_remaining() {
                        let n = min(buf.len(), data.remaining());
                        data.copy_to_slice(&mut buf[..n]);
                        self.pos += n as u64;
                        self.state = State::Ready { data: Some(data) };
                        return Poll::Ready(Ok(n));
                    }
                }
                State::Ready { data: None } => {
                    self.retrieve_chunk(pos)?;
                }
                State::Retrieving { fut } => {
                    ready!(self.on_chunk(fut, cx))?;
                }
            }
        }
    }
}

impl<
    T: ReadableDataItem,
    Auth: AuthenticationState,
    D: ChunkSource<T, Auth> + 'static,
    const FORCE_READING: bool,
> AsyncSeek for ChunkReader<T, Auth, D, FORCE_READING>
where
    Self: AllowReading<T, Auth>,
{
    fn poll_seek(
        mut self: Pin<&mut Self>,
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

        loop {
            match std::mem::replace(&mut self.state, State::default()) {
                State::Ready {
                    data: Some(mut data),
                } => {
                    // check if `pos` is within current data range
                    if pos >= self.pos && pos < (self.pos + data.remaining() as u64) {
                        let discard = pos - self.pos;
                        data.seek_relative(discard as i64)?;
                        self.pos = pos;
                        if data.has_remaining() {
                            self.state = State::Ready { data: Some(data) };
                            return Poll::Ready(Ok(pos));
                        }
                    }
                }
                State::Ready { data: None } => {
                    // start retrieving chunk
                    self.retrieve_chunk(pos)?;
                }
                State::Retrieving { fut } => {
                    ready!(self.on_chunk(fut, cx))?;
                }
            }
        }
    }
}
