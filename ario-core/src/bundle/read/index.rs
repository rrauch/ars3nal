use crate::blob::Blob;
use crate::buffer::HeapCircularBuffer;
use crate::bundle::Error as BundleError;
use crate::bundle::read::{
    Context, Flow, IncrementalInputProcessor, PollResult, Result, Step, parse_u16, parse_u64,
};
use crate::bundle::{
    BundleItemId, MAX_BUNDLE_SIZE, MAX_ITEM_COUNT, MAX_ITEM_SIZE, V2Entry, V2Index,
};
use bon::bon;
use bytes::BufMut;
use itertools::Either;

pub enum IndexReader {
    Header(IncrementalInputProcessor<IndexReaderCtx, Header>),
    Entries(IncrementalInputProcessor<IndexReaderCtx, Entries>),
}

impl Flow for IndexReader {
    type Output = V2Index;
    type Buf<'a> = Box<dyn BufMut + 'a>;

    fn required_bytes(&self) -> usize {
        match self {
            Self::Header(s) => s.required_bytes(),
            Self::Entries(s) => s.required_bytes(),
        }
    }

    fn buffer(&mut self) -> Self::Buf<'_> {
        match self {
            Self::Header(s) => Box::new(s.buffer()),
            Self::Entries(s) => Box::new(s.buffer()),
        }
    }

    fn try_process(self) -> crate::bundle::read::Result<Either<Self, Self::Output>> {
        Ok(match self {
            Self::Header(s) => match s.transition()? {
                Either::Left(header) => Either::Left(Self::Header(header)),
                Either::Right(entries) => Either::Left(Self::Entries(entries)),
            },
            Self::Entries(s) => match s.finalize()? {
                Either::Left(entries) => Either::Left(Self::Entries(entries)),
                Either::Right(index) => Either::Right(index),
            },
        })
    }
}

#[bon]
impl IndexReader {
    #[builder]
    pub fn new(#[builder(default = 2048)] buffer_capacity: usize) -> Self {
        let ctx = IndexReaderCtx {
            buf: HeapCircularBuffer::new(buffer_capacity),
        };
        Self::Header(IncrementalInputProcessor::new(ctx, Header))
    }
}

pub struct IndexReaderCtx {
    buf: HeapCircularBuffer,
}

impl Context for IndexReaderCtx {
    type Buf = HeapCircularBuffer;

    fn buffer(&mut self) -> &mut Self::Buf {
        &mut self.buf
    }
}

pub struct Header;

impl Step<IndexReaderCtx> for Header {
    type Next = Entries;
    fn required_bytes(&self, ctx: &IndexReaderCtx) -> usize {
        32usize.saturating_sub(ctx.buf.remaining())
    }

    fn poll(&mut self, ctx: &mut IndexReaderCtx) -> Result<PollResult<Self::Next>> {
        Ok(if self.required_bytes(ctx) > 0 {
            PollResult::NeedMoreData
        } else {
            PollResult::Continue(Entries::new(Self::parse_item_count(ctx)?))
        })
    }
}

impl Header {
    fn parse_item_count(ctx: &mut IndexReaderCtx) -> Result<u16> {
        let item_count =
            parse_u16(&ctx.buf.make_contiguous()[..32]).ok_or(BundleError::InvalidHeader)?;
        if item_count == 0 {
            return Err(BundleError::EmptyBundle)?;
        }
        if item_count > MAX_ITEM_COUNT {
            return Err(BundleError::TooManyItems {
                max: MAX_ITEM_COUNT,
                actual: item_count,
            })?;
        }
        ctx.buf.reset();
        Ok(item_count)
    }
}

pub struct Entries {
    item_count: u16,
    entries: Vec<(BundleItemId, u64)>,
}

impl Step<IndexReaderCtx> for Entries {
    type Next = V2Index;

    fn required_bytes(&self, ctx: &IndexReaderCtx) -> usize {
        if self.is_full() {
            return 0;
        }
        64usize.saturating_sub(ctx.buf.remaining())
    }

    fn poll(&mut self, ctx: &mut IndexReaderCtx) -> Result<PollResult<Self::Next>> {
        loop {
            if !self.is_full() {
                let bytes_required = self.required_bytes(ctx);
                if bytes_required > 0 {
                    return Ok(PollResult::NeedMoreData);
                }
                self.parse_entry(ctx)?;
                ctx.buf.reset();
            } else {
                return Ok(PollResult::Continue(self.finalize()?));
            }
        }
    }
}

impl Entries {
    fn new(item_count: u16) -> Self {
        Self {
            item_count,
            entries: Vec::with_capacity(item_count as usize),
        }
    }

    fn is_full(&self) -> bool {
        self.entries.len() >= self.item_count as usize
    }

    fn finalize(&mut self) -> Result<V2Index> {
        if !self.is_full() {
            return Err(BundleError::InsufficientItems {
                required: self.item_count,
                actual: self.entries.len() as u16,
            })?;
        }

        let mut size = 0u64;
        let mut entries = self
            .entries
            .drain(..)
            .map(|(id, len)| {
                size = size.saturating_add(len);
                V2Entry {
                    id,
                    offset: size.saturating_sub(len),
                    len,
                }
            })
            .collect::<Vec<_>>();

        let header_len = (32 + (entries.len() * 64)) as u64;

        entries
            .iter_mut()
            .for_each(|e| e.offset = e.offset.saturating_add(header_len));

        let index = V2Index { entries };
        let total_size = index.total_size();
        if total_size > MAX_BUNDLE_SIZE {
            return Err(BundleError::BundleExceedsMaxSize {
                max: MAX_BUNDLE_SIZE,
                actual: total_size,
            })?;
        }
        Ok(index)
    }

    fn parse_entry(&mut self, ctx: &mut IndexReaderCtx) -> Result<()> {
        if self.is_full() {
            // all expected entries parsed already
            return Err(BundleError::InvalidHeader)?;
        }

        let content = &ctx.buf.make_contiguous()[..64];
        let (len_bytes, id_bytes) = content.split_at(32);

        let len = parse_u64(len_bytes).ok_or(BundleError::InvalidHeader)?;
        if len == 0 {
            return Err(BundleError::EmptyItem)?;
        }
        if len > MAX_ITEM_SIZE {
            return Err(BundleError::ItemExceedsMaxSize {
                max: MAX_ITEM_SIZE,
                actual: len,
            })?;
        }

        let id = BundleItemId::try_from(Blob::Slice(id_bytes))
            .map_err(|e| BundleError::InvalidItemId(e.to_string()))?;

        self.entries.push((id, len));

        Ok(())
    }
}
