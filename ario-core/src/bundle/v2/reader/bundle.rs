use crate::blob::Blob;
use crate::buffer::HeapCircularBuffer;
use crate::bundle::Error as BundleError;
use crate::bundle::v2::reader::{
    Context, Flow, IncrementalInputProcessor, PollResult, Result, Step, parse_u16, parse_u64,
};
use crate::bundle::v2::{
    Bundle, BundleEntry, ContainerLocation, MAX_BUNDLE_SIZE, MAX_ITEM_COUNT, MAX_ITEM_SIZE,
};
use crate::bundle::{BundleId, BundleItemId};
use bon::bon;
use bytes::BufMut;
use itertools::Either;

pub(crate) enum BundleReader {
    Header(IncrementalInputProcessor<BundleReaderCtx, Header>),
    Entries(IncrementalInputProcessor<BundleReaderCtx, Entries>),
}

impl Flow for BundleReader {
    type Output = Bundle;
    type Buf<'a> = Box<dyn BufMut + 'a + Send>;

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

    fn try_process(self) -> crate::bundle::v2::reader::Result<Either<Self, Self::Output>> {
        Ok(match self {
            Self::Header(s) => match s.transition()? {
                Either::Left(header) => Either::Left(Self::Header(header)),
                Either::Right(entries) => Either::Left(Self::Entries(entries)),
            },
            Self::Entries(s) => match s.finalize()? {
                Either::Left(entries) => Either::Left(Self::Entries(entries)),
                Either::Right(bundle) => Either::Right(bundle),
            },
        })
    }
}

#[bon]
impl BundleReader {
    #[builder]
    pub fn new(id: BundleId, #[builder(default = 2048)] buffer_capacity: usize) -> Self {
        let ctx = BundleReaderCtx {
            id,
            buf: HeapCircularBuffer::new(buffer_capacity),
        };
        Self::Header(IncrementalInputProcessor::new(ctx, Header))
    }
}

pub(super) struct BundleReaderCtx {
    id: BundleId,
    buf: HeapCircularBuffer,
}

impl Context for BundleReaderCtx {
    type Buf = HeapCircularBuffer;

    fn buffer(&mut self) -> &mut Self::Buf {
        &mut self.buf
    }
}

pub struct Header;

impl Step<BundleReaderCtx> for Header {
    type Next = Entries;
    fn required_bytes(&self, ctx: &BundleReaderCtx) -> usize {
        32usize.saturating_sub(ctx.buf.remaining())
    }

    fn poll(&mut self, ctx: &mut BundleReaderCtx) -> Result<PollResult<Self::Next>> {
        Ok(if self.required_bytes(ctx) > 0 {
            PollResult::NeedMoreData
        } else {
            PollResult::Continue(Entries::new(Self::parse_item_count(ctx)?))
        })
    }
}

impl Header {
    fn parse_item_count(ctx: &mut BundleReaderCtx) -> Result<u16> {
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

impl Step<BundleReaderCtx> for Entries {
    type Next = Bundle;

    fn required_bytes(&self, ctx: &BundleReaderCtx) -> usize {
        if self.is_full() {
            return 0;
        }
        64usize.saturating_sub(ctx.buf.remaining())
    }

    fn poll(&mut self, ctx: &mut BundleReaderCtx) -> Result<PollResult<Self::Next>> {
        loop {
            if !self.is_full() {
                let bytes_required = self.required_bytes(ctx);
                if bytes_required > 0 {
                    return Ok(PollResult::NeedMoreData);
                }
                self.parse_entry(ctx)?;
                ctx.buf.reset();
            } else {
                return Ok(PollResult::Continue(self.finalize(&ctx.id)?));
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

    fn finalize(&mut self, id: &BundleId) -> Result<Bundle> {
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
                BundleEntry {
                    id,
                    container_location: ContainerLocation::new(
                        0, // placeholder, updated to actual value below
                        size.saturating_sub(len),
                    ),
                    len,
                }
            })
            .collect::<Vec<_>>();

        let header_len = (32 + (entries.len() * 64)) as u64;

        entries.iter_mut().for_each(|e| {
            e.container_location.offset = e.container_location.offset.saturating_add(header_len)
        });

        let mut bundle = Bundle {
            id: id.clone(),
            entries,
        };
        let total_size = bundle.total_size();
        if total_size > MAX_BUNDLE_SIZE {
            return Err(BundleError::BundleExceedsMaxSize {
                max: MAX_BUNDLE_SIZE,
                actual: total_size,
            })?;
        }

        bundle
            .entries
            .iter_mut()
            .for_each(|e| e.container_location.container_size = total_size);

        Ok(bundle)
    }

    fn parse_entry(&mut self, ctx: &mut BundleReaderCtx) -> Result<()> {
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
