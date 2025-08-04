use crate::crypto::hash::{Digest, Hasher, Sha256};
use bytes::Buf;
use derive_where::derive_where;
use ringbuf::LocalRb;
use ringbuf::consumer::Consumer;
use ringbuf::producer::Producer;
use ringbuf::storage::Heap;
use ringbuf::traits::Observer;
use std::cmp::min;
use std::ops::Range;

pub type DefaultChunker = Chunker<Sha256, { 256 * 1024 }, { 32 * 1024 }>;

#[derive_where(Clone, Debug, PartialEq)]
pub struct Chunk<H: Hasher> {
    data_hash: Digest<H>,
    offset: Range<u64>,
}

impl<H: Hasher> Chunk<H> {
    pub(crate) fn new(data_hash: Digest<H>, offset: u64, len: usize) -> Self {
        Self {
            data_hash,
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

    pub fn data_hash(&self) -> &Digest<H> {
        &self.data_hash
    }
}

pub struct Chunker<H: Hasher, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize> {
    hasher: H,
    current_chunk_start_offset: u64,
    total_bytes_processed: u64,
    buf: LocalRb<Heap<u8>>,
    chunks: Vec<Chunk<H>>,
}

impl<H: Hasher, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize>
    Chunker<H, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>
{
    pub fn new() -> Self {
        assert!(MAX_CHUNK_SIZE > 0, "MAX_CHUNK_SIZE must be greater than 0.");
        assert!(MIN_CHUNK_SIZE > 0, "MIN_CHUNK_SIZE must be greater than 0.");
        assert!(
            MIN_CHUNK_SIZE <= MAX_CHUNK_SIZE,
            "MIN_CHUNK_SIZE must be <= MAX_CHUNK_SIZE."
        );
        let buf = LocalRb::new(MAX_CHUNK_SIZE + MIN_CHUNK_SIZE);
        Self {
            hasher: H::new(),
            current_chunk_start_offset: 0,
            total_bytes_processed: 0,
            buf,
            chunks: Vec::new(),
        }
    }

    pub fn update(&mut self, input: &mut impl Buf) {
        while input.has_remaining() {
            if self.buf.is_full() {
                self.process_chunk(false);
                continue;
            }

            let chunk = input.chunk();
            let to_copy = chunk.len().min(self.buf.vacant_len());
            let num_bytes = self.buf.push_slice(&chunk[..to_copy]);
            input.advance(num_bytes);
        }
    }

    fn process_chunk(&mut self, is_final: bool) {
        let buffered_len = self.buf.occupied_len();

        if buffered_len == 0 {
            return;
        }

        let chunk_len = if is_final {
            if buffered_len > MAX_CHUNK_SIZE {
                // split the remaining data more evenly
                (buffered_len + 1) / 2
            } else {
                buffered_len
            }
        } else {
            min(MAX_CHUNK_SIZE, self.buf.occupied_len())
        };
        assert!(chunk_len <= MAX_CHUNK_SIZE);

        let mut remaining = chunk_len;
        let (mut sl1, mut sl2) = self.buf.as_slices();

        while remaining > 0 {
            if !sl1.is_empty() {
                let to_process = sl1.len().min(remaining);
                self.hasher.update(&sl1[..to_process]);
                sl1 = &sl1[to_process..];
                remaining -= to_process;
            } else if !sl2.is_empty() {
                let to_process = sl2.len().min(remaining);
                self.hasher.update(&sl2[..to_process]);
                sl2 = &sl2[to_process..];
                remaining -= to_process;
            } else {
                break;
            }
        }

        let processed = chunk_len - remaining;
        assert!(processed > 0);

        // finalize the chunk
        let data_hash = std::mem::replace(&mut self.hasher, H::new()).finalize();
        let offset_end = self.current_chunk_start_offset + processed as u64;

        self.chunks.push(Chunk {
            data_hash,
            offset: self.current_chunk_start_offset..offset_end,
        });

        // Safety: advance read index by `processed` bytes
        unsafe {
            self.buf.advance_read_index(processed);
        }
        self.current_chunk_start_offset = offset_end;
        self.total_bytes_processed += processed as u64;
    }

    pub fn finalize(mut self) -> Vec<Chunk<H>> {
        // Process any remaining data
        while self.buf.occupied_len() > 0 {
            self.process_chunk(true);
        }
        self.chunks
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::chunking::DefaultChunker;
    use std::io::Cursor;

    static ONE_MB: &'static [u8] = include_bytes!("../testdata/1mb.bin");
    static TX_EVEN_DATA: &'static [u8] =
        include_bytes!("../testdata/OX63odH91fXS4hN506rYC_WUo8mWC5M3xuBymLhSKSw.data");
    static TX_ODD_DATA: &'static [u8] =
        include_bytes!("../testdata/trtu91u1kRVDrZI6WvWVxU3uvEjJRZcls2WSZvYJyBc.data");

    #[test]
    fn test_chunking() -> anyhow::Result<()> {
        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(ONE_MB));
        let chunks = chunker.finalize();
        assert_eq!(chunks.len(), 8);

        assert_eq!(chunks[0].offset.start, 0);
        assert_eq!(chunks[0].len(), 262144);
        assert_eq!(
            chunks[0].data_hash.to_base64(),
            "R9tpW9gwYRmLjsYUCZvGJynV1OCHjfIgjbSUek-qIe4"
        );

        assert_eq!(chunks[7].offset.start, 1835008);
        assert_eq!(chunks[7].len(), 66754);
        assert_eq!(
            chunks[7].data_hash.to_base64(),
            "C_xIgfY5ZGpsNHEpUBiFxSZ-nlnuDhoT1-fCnuLke68"
        );

        Ok(())
    }

    #[test]
    fn test_chunking_even() -> anyhow::Result<()> {
        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(TX_EVEN_DATA));
        let chunks = chunker.finalize();
        assert_eq!(chunks.len(), 2);

        assert_eq!(chunks[0].offset.start, 0);
        assert_eq!(chunks[0].len(), 262144);
        assert_eq!(
            chunks[0].data_hash.to_base64(),
            "BOLZqkj-lt7NKlGkHbo1uZNEPQuaulpfMk_Wyfs9cyI"
        );

        assert_eq!(chunks[1].offset.start, 262144);
        assert_eq!(chunks[1].len(), 68727);
        assert_eq!(
            chunks[1].data_hash.to_base64(),
            "x0Nx2EbydmSLLXkz2ftJw83kmQinPOg57P6P2o4n1ew"
        );

        Ok(())
    }

    #[test]
    fn test_chunking_odd() -> anyhow::Result<()> {
        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(TX_ODD_DATA));
        let chunks = chunker.finalize();
        assert_eq!(chunks.len(), 3);

        assert_eq!(chunks[0].offset.start, 0);
        assert_eq!(chunks[0].len(), 262144);
        assert_eq!(
            chunks[0].data_hash.to_base64(),
            "KeHLQhG8YcahPHQOcTZ3VTnyOvZSCbwEuBx8rMmilEU"
        );

        assert_eq!(chunks[2].offset.start, 524288);
        assert_eq!(chunks[2].len(), 159533);
        assert_eq!(
            chunks[2].data_hash.to_base64(),
            "5fKXk1Squ8hy13_EakA-97Ih5-HFvSPssHZzW4E_EMk"
        );

        Ok(())
    }

    #[test]
    fn small_final_chunk() -> anyhow::Result<()> {
        let data = vec![0; 256 * 1024 + 1];

        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(data.as_slice()));
        let chunks = chunker.finalize();

        assert_eq!(chunks.len(), 2);

        assert_eq!(chunks[0].offset.start, 0);
        assert_eq!(chunks[0].len(), 131073);
        assert_eq!(
            chunks[0].data_hash.to_base64(),
            "0oEgnMctR7CQF1siYhhA2euCZ9CcwF3BIr-qdZqCgw8"
        );

        assert_eq!(chunks[1].offset.start, 131073);
        assert_eq!(chunks[1].len(), 131072);
        assert_eq!(
            chunks[1].data_hash.to_base64(),
            "-kMjm87nuXymLwB8xoSHVgo54Z90893nSG2z-Y345HE"
        );

        Ok(())
    }

    #[test]
    fn tiny_chunk() -> anyhow::Result<()> {
        let data = vec![0; 16 * 1024];

        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(data.as_slice()));
        let chunks = chunker.finalize();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].offset.start, 0);
        assert_eq!(chunks[0].len(), 16 * 1024);
        assert_eq!(
            chunks[0].data_hash.to_base64(),
            "T-e1mvbeO2ZbZ3iMwvmYkquCfvrjpGc0Kzu047yOW_4"
        );

        Ok(())
    }

    #[test]
    fn empty() -> anyhow::Result<()> {
        let data = vec![];
        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(data.as_slice()));
        let chunks = chunker.finalize();
        assert!(chunks.is_empty());
        Ok(())
    }
}
