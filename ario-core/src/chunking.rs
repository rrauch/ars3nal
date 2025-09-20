use crate::blob::{AsBlob, Blob};
use crate::buffer::{BufMutExt, HeapCircularBuffer};
use crate::crypto::hash::{Digest, Hashable, Hasher, Sha256};
use crate::crypto::{Output, OutputLen};
use crate::data::MaybeOwnedDefaultChunkedData;
use crate::typed::Typed;
use bytes::Buf;
use derive_where::derive_where;
use futures_lite::AsyncRead;
use futures_lite::AsyncReadExt;
use maybe_owned::MaybeOwned;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::fmt::Debug;
use std::hash::Hash;
use std::io::Cursor;
use std::io::Read;
use std::ops::Range;

pub type DefaultChunker = MostlyFixedChunker<Sha256, { 256 * 1024 }, { 32 * 1024 }>;

pub type TypedChunk<T, C: Chunker> = Typed<T, Chunk<C>>;

#[derive_where(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Chunk<C: Chunker> {
    output: C::Output,
    offset: Range<u64>,
}

impl<C: Chunker> Hash for Chunk<C> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.output.as_blob().hash(state);
        self.offset.hash(state)
    }
}

pub type MaybeOwnedChunk<'a, C: Chunker> = MaybeOwned<'a, Chunk<C>>;

pub(crate) trait IntoMaybeOwnedChunk<'a, C: Chunker> {
    fn into(self) -> MaybeOwnedChunk<'a, C>;
}

impl<'a, C: Chunker> IntoMaybeOwnedChunk<'a, C> for Chunk<C> {
    fn into(self) -> MaybeOwnedChunk<'a, C> {
        MaybeOwned::Owned(self)
    }
}

impl<'a, C: Chunker> IntoMaybeOwnedChunk<'a, C> for MaybeOwnedChunk<'a, C> {
    fn into(self) -> MaybeOwnedChunk<'a, C> {
        self
    }
}

impl<'a> IntoMaybeOwnedChunk<'a, DefaultChunker> for MaybeOwnedDefaultChunkedData<'a> {
    fn into(self) -> MaybeOwnedChunk<'a, DefaultChunker> {
        match self {
            MaybeOwned::Owned(owned) => MaybeOwnedChunk::Owned(owned.0),
            MaybeOwned::Borrowed(borrowed) => MaybeOwnedChunk::Borrowed(&borrowed.0),
        }
    }
}

impl<C: Chunker> Chunk<C> {
    pub(crate) fn new(output: C::Output, offset: u64, len: usize) -> Self {
        Self {
            output,
            offset: offset..(offset + len as u64),
        }
    }

    pub fn offset(&self) -> &Range<u64> {
        &self.offset
    }

    pub fn len(&self) -> u64 {
        self.offset.end - self.offset.start
    }

    pub fn is_empty(&self) -> bool {
        self.offset.is_empty()
    }

    pub fn output(&self) -> &C::Output {
        &self.output
    }
}

pub trait ChunkInfo:
    Hashable
    + AsBlob
    + for<'a> TryFrom<Blob<'a>>
    + Send
    + Sync
    + Debug
    + Clone
    + PartialEq
    + Serialize
    + for<'a> Deserialize<'a>
{
    type Len: OutputLen;
}

impl<H: Hasher> ChunkInfo for Digest<H> {
    type Len = <H::Output as Output>::Len;
}

pub trait Chunker: Sized + Send {
    type Output: ChunkInfo;
    fn empty() -> Self::Output;
    fn single_chunk(input: &mut impl Buf, offset: u64) -> Chunk<Self>;
    fn update(&mut self, input: &mut impl Buf) -> impl IntoIterator<Item = Chunk<Self>>;
    fn finalize(self) -> impl IntoIterator<Item = Chunk<Self>>;
    fn max_chunk_size() -> usize;
}

pub(crate) trait ChunkerExt
where
    Self: Chunker,
{
    fn single_input(self, input: &mut impl Buf) -> Vec<Chunk<Self>>;
    fn try_from_reader(self, reader: &mut impl Read) -> std::io::Result<Vec<Chunk<Self>>> {
        self.try_from_reader_with_buf_size::<{ 64 * 1024 }>(reader)
    }

    fn try_from_reader_with_buf_size<const BUF_SIZE: usize>(
        self,
        reader: &mut impl Read,
    ) -> std::io::Result<Vec<Chunk<Self>>>;

    fn try_from_async_reader(
        self,
        reader: &mut (impl AsyncRead + Send + Unpin),
    ) -> impl Future<Output = std::io::Result<Vec<Chunk<Self>>>> + Send {
        self.try_from_async_reader_with_buf_size::<{ 64 * 1024 }>(reader)
    }

    fn try_from_async_reader_with_buf_size<const BUF_SIZE: usize>(
        self,
        reader: &mut (impl AsyncRead + Send + Unpin),
    ) -> impl Future<Output = std::io::Result<Vec<Chunk<Self>>>> + Send;
}

impl<T: Chunker> ChunkerExt for T {
    fn single_input(mut self, input: &mut impl Buf) -> Vec<Chunk<Self>> {
        let mut chunks = vec![];
        chunks.extend(self.update(input));
        chunks.extend(self.finalize());
        chunks
    }

    fn try_from_reader_with_buf_size<const BUF_SIZE: usize>(
        mut self,
        reader: &mut impl Read,
    ) -> std::io::Result<Vec<Chunk<Self>>> {
        let mut chunks = vec![];
        let mut buf = vec![0; BUF_SIZE];
        loop {
            let n = reader.read(&mut buf)?;
            if n > 0 {
                chunks.extend(self.update(&mut Cursor::new(&buf[..n])));
                continue;
            }
            break;
        }
        chunks.extend(self.finalize());
        Ok(chunks)
    }

    async fn try_from_async_reader_with_buf_size<const BUF_SIZE: usize>(
        mut self,
        reader: &mut (impl AsyncRead + Send + Unpin),
    ) -> std::io::Result<Vec<Chunk<Self>>> {
        let mut chunks = vec![];
        let mut buf = vec![0; BUF_SIZE];
        loop {
            let n = reader.read(&mut buf).await?;
            if n > 0 {
                chunks.extend(self.update(&mut Cursor::new(&buf[..n])));
                continue;
            }
            break;
        }
        chunks.extend(self.finalize());
        Ok(chunks)
    }
}

pub struct MostlyFixedChunker<H: Hasher, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize> {
    hasher: H,
    current_chunk_start_offset: u64,
    total_bytes_processed: u64,
    buf: HeapCircularBuffer,
}

impl<H: Hasher, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize> Chunker
    for MostlyFixedChunker<H, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>
{
    type Output = Digest<H>;

    fn empty() -> Self::Output {
        H::new().finalize()
    }

    fn single_chunk(input: &mut impl Buf, offset: u64) -> Chunk<Self> {
        let mut hasher = H::new();
        let len = (input.remaining() as u64) + offset;
        while input.has_remaining() {
            let data = input.chunk();
            hasher.update(data);
            input.advance(data.len());
        }
        Chunk {
            output: hasher.finalize(),
            offset: offset..len,
        }
    }

    fn update(&mut self, input: &mut impl Buf) -> impl IntoIterator<Item = Chunk<Self>> {
        let mut chunks = vec![];
        while input.has_remaining() {
            self.buf.transfer_from_buf(input);

            if self.buf.is_full() {
                chunks.extend(self.process_chunk(false));
            }
        }
        chunks
    }

    fn finalize(mut self) -> impl IntoIterator<Item = Chunk<Self>> {
        let mut chunks = vec![];
        // Process any remaining data
        while self.buf.remaining() > 0 {
            chunks.extend(self.process_chunk(true));
        }
        chunks
    }

    fn max_chunk_size() -> usize {
        MAX_CHUNK_SIZE
    }
}

impl<H: Hasher, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize>
    MostlyFixedChunker<H, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>
{
    pub fn new() -> Self {
        assert!(MAX_CHUNK_SIZE > 0, "MAX_CHUNK_SIZE must be greater than 0.");
        assert!(MIN_CHUNK_SIZE > 0, "MIN_CHUNK_SIZE must be greater than 0.");
        assert!(
            MIN_CHUNK_SIZE <= MAX_CHUNK_SIZE,
            "MIN_CHUNK_SIZE must be <= MAX_CHUNK_SIZE."
        );
        let buf = HeapCircularBuffer::new(MAX_CHUNK_SIZE + MIN_CHUNK_SIZE);
        Self {
            hasher: H::new(),
            current_chunk_start_offset: 0,
            total_bytes_processed: 0,
            buf,
        }
    }

    fn process_chunk(&mut self, is_final: bool) -> Vec<Chunk<Self>> {
        let mut chunks = vec![];
        let buffered_len = self.buf.remaining();

        if buffered_len == 0 {
            return chunks;
        }

        let chunk_len = if is_final {
            if buffered_len > MAX_CHUNK_SIZE {
                // split the remaining data more evenly
                (buffered_len + 1) / 2
            } else {
                buffered_len
            }
        } else {
            min(MAX_CHUNK_SIZE, self.buf.remaining())
        };
        assert!(chunk_len <= MAX_CHUNK_SIZE);

        let buf = &self.buf.make_contiguous()[..chunk_len];
        self.hasher.update(buf);

        let processed = buf.len();
        assert!(processed > 0);

        // finalize the chunk
        let data_hash = std::mem::replace(&mut self.hasher, H::new()).finalize();
        let offset_end = self.current_chunk_start_offset + processed as u64;

        chunks.push(Chunk {
            output: data_hash,
            offset: self.current_chunk_start_offset..offset_end,
        });

        self.buf.advance(processed);
        self.current_chunk_start_offset = offset_end;
        self.total_bytes_processed += processed as u64;

        chunks
    }

    pub fn chunk_map(len: u64) -> MostlyFixedChunkMap<MAX_CHUNK_SIZE> {
        MostlyFixedChunkMap::new::<MIN_CHUNK_SIZE>(len)
    }
}

#[derive(Debug, Clone)]
pub struct MostlyFixedChunkMap<const FULL_CHUNK_SIZE: usize> {
    len: usize,
    size: u64,
    num_full_chunks: usize,
    full_chunk_end: u64,
    penultimate_chunk: Option<Range<u64>>,
    ultimate_chunk: Option<Range<u64>>,
}

impl<const FULL_CHUNK_SIZE: usize> MostlyFixedChunkMap<FULL_CHUNK_SIZE> {
    fn new<const MIN_CHUNK_SIZE: usize>(size: u64) -> Self {
        let max: u64 = FULL_CHUNK_SIZE as u64;
        let min: u64 = MIN_CHUNK_SIZE as u64;

        let mut num_full_chunks = size / max;
        let remainder = size % max;

        // If the remainder is too small, "borrow" the last full chunk to merge with it.
        if remainder > 0 && remainder < min && num_full_chunks > 0 {
            num_full_chunks -= 1;
        }

        let mut pos = num_full_chunks * max;

        let mut penultimate_chunk = None;
        let mut ultimate_chunk = None;

        // Process the rest of the data, which may be one or two chunks.
        let remaining_len = size - pos;
        if remaining_len > 0 {
            if remaining_len > max {
                // This is a merged chunk (MAX + remainder). Split it into two.
                let size1 = remaining_len / 2;
                let size2 = remaining_len - size1; // Handles odd/even correctly.

                penultimate_chunk = Some(pos..(pos + size2));
                pos += size2;
                ultimate_chunk = Some(pos..(pos + size1));
            } else {
                // This is a single final chunk.
                ultimate_chunk = Some(pos..(pos + remaining_len));
            }
        }
        let num_full_chunks = num_full_chunks as usize;

        Self {
            len: num_full_chunks
                + penultimate_chunk.as_ref().map(|_| 1).unwrap_or(0)
                + ultimate_chunk.as_ref().map(|_| 1).unwrap_or(0),
            size,
            full_chunk_end: num_full_chunks as u64 * FULL_CHUNK_SIZE as u64,
            num_full_chunks,
            penultimate_chunk,
            ultimate_chunk,
        }
    }

    pub fn get_by_offset(&self, offset: u64) -> Option<Range<u64>> {
        if offset >= self.size {
            return None;
        }

        if offset < self.full_chunk_end {
            let chunk_size = FULL_CHUNK_SIZE as u64;
            let start = (offset / chunk_size) * chunk_size;
            return Some(start..(start + chunk_size));
        }

        self.penultimate_chunk
            .as_ref()
            .filter(|r| r.contains(&offset))
            .or(self.ultimate_chunk.as_ref())
            .filter(|r| r.contains(&offset))
            .cloned()
    }

    pub fn iter(&self) -> MostlyFixedChunkMapIter<'_, FULL_CHUNK_SIZE> {
        MostlyFixedChunkMapIter {
            map: self,
            current_index: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub struct MostlyFixedChunkMapIter<'a, const FULL_CHUNK_SIZE: usize> {
    map: &'a MostlyFixedChunkMap<FULL_CHUNK_SIZE>,
    current_index: usize,
}

impl<'a, const FULL_CHUNK_SIZE: usize> Iterator for MostlyFixedChunkMapIter<'a, FULL_CHUNK_SIZE> {
    type Item = Range<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.map.len {
            return None;
        }

        let chunk = if self.current_index < self.map.num_full_chunks {
            let chunk_size = FULL_CHUNK_SIZE as u64;
            let start = self.current_index as u64 * chunk_size;
            Some(start..(start + chunk_size))
        } else if self.current_index == self.map.num_full_chunks
            && self.map.penultimate_chunk.is_some()
        {
            self.map.penultimate_chunk.clone()
        } else {
            self.map.ultimate_chunk.clone()
        };

        self.current_index += 1;
        chunk
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.map.len.saturating_sub(self.current_index);
        (remaining, Some(remaining))
    }
}

pub struct AlignedChunker<H: Hasher, const MAX_CHUNK_SIZE: usize> {
    offset: u64,
    pos: u64,
    current_chunk_start: u64,
    current_chunk_remaining: usize,
    hasher: H,
    chunk_map: MostlyFixedChunkMap<MAX_CHUNK_SIZE>,
}

impl<H: Hasher, const MAX_CHUNK_SIZE: usize> AlignedChunker<H, MAX_CHUNK_SIZE> {
    pub fn new(offset: u64, chunk_map: MostlyFixedChunkMap<MAX_CHUNK_SIZE>) -> Self {
        let (current_chunk_start, current_chunk_remaining) = Self::calc_chunk(&chunk_map, offset);
        Self {
            offset,
            pos: offset,
            current_chunk_start,
            current_chunk_remaining,
            hasher: H::new(),
            chunk_map,
        }
    }

    fn calc_chunk(chunk_map: &MostlyFixedChunkMap<MAX_CHUNK_SIZE>, offset: u64) -> (u64, usize) {
        let current_chunk = chunk_map
            .get_by_offset(offset)
            .unwrap_or_else(|| offset..offset + MAX_CHUNK_SIZE as u64);
        let len = (current_chunk.end - offset) as usize;
        (offset, len)
    }

    fn advance(&mut self, len: usize) -> Option<Chunk<Self>> {
        assert!(len <= self.current_chunk_remaining);
        let mut chunk = None;
        self.current_chunk_remaining -= len;
        self.pos += len as u64;
        if self.current_chunk_remaining == 0 {
            // chunk complete
            let hasher = std::mem::replace(&mut self.hasher, H::new());
            chunk = Some(Chunk::new(
                hasher.finalize(),
                self.current_chunk_start - self.offset,
                (self.pos - self.current_chunk_start) as usize,
            ));

            let (next_chunk_start, next_chunk_len) = Self::calc_chunk(&self.chunk_map, self.pos);
            self.current_chunk_remaining = next_chunk_len;
            self.current_chunk_start = next_chunk_start;
        }
        chunk
    }
}

impl<H: Hasher, const MAX_CHUNK_SIZE: usize> Chunker for AlignedChunker<H, MAX_CHUNK_SIZE> {
    type Output = Digest<H>;

    fn empty() -> Self::Output {
        H::new().finalize()
    }

    fn single_chunk(input: &mut impl Buf, offset: u64) -> Chunk<Self> {
        let mut hasher = H::new();
        let len = (input.remaining() as u64) + offset;
        while input.has_remaining() {
            let data = input.chunk();
            hasher.update(data);
            input.advance(data.len());
        }
        Chunk {
            output: hasher.finalize(),
            offset: offset..len,
        }
    }

    fn update(&mut self, input: &mut impl Buf) -> impl IntoIterator<Item = Chunk<Self>> {
        let mut chunks = vec![];
        while input.has_remaining() {
            let data = input.chunk();
            let len = min(data.len(), self.current_chunk_remaining);
            self.hasher.update(&data[..len]);
            if let Some(chunk) = self.advance(len) {
                chunks.push(chunk);
            }
            input.advance(len);
        }
        chunks
    }

    fn finalize(self) -> impl IntoIterator<Item = Chunk<Self>> {
        let mut chunks = vec![];
        let len = (self.pos - self.current_chunk_start) as usize;
        if len > 0 {
            chunks.push(Chunk::new(
                self.hasher.finalize(),
                self.current_chunk_start - self.offset,
                len,
            ))
        }
        chunks
    }

    fn max_chunk_size() -> usize {
        MAX_CHUNK_SIZE
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::chunking::{AlignedChunker, Chunk, Chunker, ChunkerExt};
    use crate::chunking::{DefaultChunker, MostlyFixedChunker};
    use crate::crypto::hash::{Hasher, Sha256};
    use std::fs::File;
    use std::io::Cursor;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    static ONE_MB: &'static [u8] = include_bytes!("../testdata/1mb.bin");
    static ONE_MB_PATH: &'static str = "./testdata/1mb.bin";
    static TX_EVEN_DATA: &'static [u8] =
        include_bytes!("../testdata/OX63odH91fXS4hN506rYC_WUo8mWC5M3xuBymLhSKSw.data");
    static TX_ODD_DATA: &'static [u8] =
        include_bytes!("../testdata/trtu91u1kRVDrZI6WvWVxU3uvEjJRZcls2WSZvYJyBc.data");

    fn verify_chunk_map<H: Hasher, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize>(
        chunks: &Vec<Chunk<MostlyFixedChunker<H, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>>>,
    ) -> anyhow::Result<()> {
        let len = chunks.iter().map(|c| c.len()).sum();
        if len != 0 {
            let map = MostlyFixedChunker::<H, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>::chunk_map(len);
            assert_eq!(map.len(), chunks.len());
            for (c, range) in chunks.iter().zip(map.iter()) {
                assert_eq!(&c.offset, &range);
            }
        }
        Ok(())
    }

    #[test]
    fn test_chunking() -> anyhow::Result<()> {
        let chunks = DefaultChunker::new().single_input(&mut Cursor::new(ONE_MB));
        verify_chunk_map(&chunks)?;

        assert_eq!(chunks.len(), 8);

        assert_eq!(chunks[0].offset.start, 0);
        assert_eq!(chunks[0].len(), 262144);
        assert_eq!(
            chunks[0].output.to_base64(),
            "R9tpW9gwYRmLjsYUCZvGJynV1OCHjfIgjbSUek-qIe4"
        );

        assert_eq!(chunks[7].offset.start, 1835008);
        assert_eq!(chunks[7].len(), 66754);
        assert_eq!(
            chunks[7].output.to_base64(),
            "C_xIgfY5ZGpsNHEpUBiFxSZ-nlnuDhoT1-fCnuLke68"
        );

        Ok(())
    }

    #[test]
    fn test_chunking_even() -> anyhow::Result<()> {
        let chunks = DefaultChunker::new().single_input(&mut Cursor::new(TX_EVEN_DATA));
        verify_chunk_map(&chunks)?;

        assert_eq!(chunks.len(), 2);

        assert_eq!(chunks[0].offset.start, 0);
        assert_eq!(chunks[0].len(), 262144);
        assert_eq!(
            chunks[0].output.to_base64(),
            "BOLZqkj-lt7NKlGkHbo1uZNEPQuaulpfMk_Wyfs9cyI"
        );

        assert_eq!(chunks[1].offset.start, 262144);
        assert_eq!(chunks[1].len(), 68727);
        assert_eq!(
            chunks[1].output.to_base64(),
            "x0Nx2EbydmSLLXkz2ftJw83kmQinPOg57P6P2o4n1ew"
        );

        Ok(())
    }

    #[test]
    fn test_chunking_odd() -> anyhow::Result<()> {
        let chunks = DefaultChunker::new().single_input(&mut Cursor::new(TX_ODD_DATA));
        verify_chunk_map(&chunks)?;

        assert_eq!(chunks.len(), 3);

        assert_eq!(chunks[0].offset.start, 0);
        assert_eq!(chunks[0].len(), 262144);
        assert_eq!(
            chunks[0].output.to_base64(),
            "KeHLQhG8YcahPHQOcTZ3VTnyOvZSCbwEuBx8rMmilEU"
        );

        assert_eq!(chunks[2].offset.start, 524288);
        assert_eq!(chunks[2].len(), 159533);
        assert_eq!(
            chunks[2].output.to_base64(),
            "5fKXk1Squ8hy13_EakA-97Ih5-HFvSPssHZzW4E_EMk"
        );

        Ok(())
    }

    #[test]
    fn small_final_chunk() -> anyhow::Result<()> {
        let data = vec![0; 256 * 1024 + 1];

        let chunks = DefaultChunker::new().single_input(&mut Cursor::new(data.as_slice()));
        verify_chunk_map(&chunks)?;

        assert_eq!(chunks.len(), 2);

        assert_eq!(chunks[0].offset.start, 0);
        assert_eq!(chunks[0].len(), 131073);
        assert_eq!(
            chunks[0].output.to_base64(),
            "0oEgnMctR7CQF1siYhhA2euCZ9CcwF3BIr-qdZqCgw8"
        );

        assert_eq!(chunks[1].offset.start, 131073);
        assert_eq!(chunks[1].len(), 131072);
        assert_eq!(
            chunks[1].output.to_base64(),
            "-kMjm87nuXymLwB8xoSHVgo54Z90893nSG2z-Y345HE"
        );

        Ok(())
    }

    #[test]
    fn tiny_chunk() -> anyhow::Result<()> {
        let data = vec![0; 16 * 1024];

        let chunks = DefaultChunker::new().single_input(&mut Cursor::new(data.as_slice()));
        verify_chunk_map(&chunks)?;

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].offset.start, 0);
        assert_eq!(chunks[0].len(), 16 * 1024);
        assert_eq!(
            chunks[0].output.to_base64(),
            "T-e1mvbeO2ZbZ3iMwvmYkquCfvrjpGc0Kzu047yOW_4"
        );

        Ok(())
    }

    #[test]
    fn empty() -> anyhow::Result<()> {
        let data = vec![];
        let chunks = DefaultChunker::new().single_input(&mut Cursor::new(data.as_slice()));
        verify_chunk_map(&chunks)?;
        assert!(chunks.is_empty());
        Ok(())
    }

    #[test]
    fn reader() -> anyhow::Result<()> {
        let reference = DefaultChunker::new().single_input(&mut Cursor::new(ONE_MB));

        let mut file = File::open(ONE_MB_PATH)?;
        let chunks = DefaultChunker::new().try_from_reader(&mut file)?;
        verify_chunk_map(&chunks)?;

        assert_eq!(&chunks, &reference);

        Ok(())
    }

    #[test]
    fn async_reader() -> anyhow::Result<()> {
        let reference = DefaultChunker::new().single_input(&mut Cursor::new(ONE_MB));

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let file = tokio::fs::File::open(ONE_MB_PATH).await?;
            let chunks = DefaultChunker::new()
                .try_from_async_reader(&mut file.compat())
                .await?;
            verify_chunk_map(&chunks)?;

            assert_eq!(&chunks, &reference);

            Ok(())
        })
    }

    #[test]
    fn aligned_chunker() -> anyhow::Result<()> {
        let chunker = AlignedChunker::<Sha256, _>::new(
            (DefaultChunker::max_chunk_size() - 100) as u64,
            DefaultChunker::chunk_map(ONE_MB.len() as u64),
        );
        let data = vec![0x01u8; 256];
        let chunks = chunker.try_from_reader(&mut Cursor::new(&data))?;
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks.get(0).as_ref().unwrap().offset, 0..100);
        assert_eq!(chunks.get(1).as_ref().unwrap().offset, 100..256);
        Ok(())
    }
}
