mod data;
mod header;
mod tags;

use super::{Flow, Result, Step};
use crate::buffer::HeapCircularBuffer;
use crate::bundle::v2::reader::item::data::Data;
use crate::bundle::v2::reader::item::header::Header;
use crate::bundle::v2::reader::item::tags::Tags;
use crate::bundle::v2::reader::{Context, IncrementalInputProcessor};
use crate::bundle::v2::{ContainerLocation, RawBundleItem};
use bon::bon;
use bytes::BufMut;
use itertools::Either;

pub(crate) enum ItemReader<const PROCESS_DATA: bool> {
    Header(IncrementalInputProcessor<ItemReaderCtx, Header<PROCESS_DATA>>),
    Tags(IncrementalInputProcessor<ItemReaderCtx, Tags<PROCESS_DATA>>),
    Data(IncrementalInputProcessor<ItemReaderCtx, Data<PROCESS_DATA>>),
}

impl<const PROCESS_DATA: bool> Flow for ItemReader<PROCESS_DATA>
where
    Data<PROCESS_DATA>: Step<ItemReaderCtx, Next = RawBundleItem<'static>>,
{
    type Output = RawBundleItem<'static>;
    type Buf<'a> = Box<dyn BufMut + 'a + Send>;

    fn required_bytes(&self) -> usize {
        match self {
            Self::Header(s) => s.required_bytes(),
            Self::Tags(s) => s.required_bytes(),
            Self::Data(s) => s.required_bytes(),
        }
    }

    fn buffer(&mut self) -> Self::Buf<'_> {
        match self {
            Self::Header(s) => Box::new(s.buffer()),
            Self::Tags(s) => Box::new(s.buffer()),
            Self::Data(s) => Box::new(s.buffer()),
        }
    }
    fn try_process(self) -> Result<Either<Self, Self::Output>> {
        Ok(match self {
            Self::Header(s) => match s.transition()? {
                Either::Left(header) => Either::Left(Self::Header(header)),
                Either::Right(tags) => Either::Left(Self::Tags(tags)),
            },
            Self::Tags(s) => match s.transition()? {
                Either::Left(tags) => Either::Left(Self::Tags(tags)),
                Either::Right(data) => Either::Left(Self::Data(data)),
            },
            Self::Data(s) => match s.finalize()? {
                Either::Left(data) => Either::Left(Self::Data(data)),
                Either::Right(out) => Either::Right(out),
            },
        })
    }
}

#[bon]
impl<const PROCESS_DATA: bool> ItemReader<PROCESS_DATA> {
    #[builder]
    pub fn new(
        len: u64,
        container_location: Option<ContainerLocation>,
        #[builder(default = 64 * 1024)] buffer_capacity: usize,
    ) -> Self {
        let ctx = ItemReaderCtx {
            len,
            pos: 0,
            buf: HeapCircularBuffer::new(buffer_capacity),
            container_location,
        };
        Self::Header(IncrementalInputProcessor::new(ctx, Header::new()))
    }
}

pub(super) struct ItemReaderCtx {
    len: u64,
    pos: u64,
    buf: HeapCircularBuffer,
    container_location: Option<ContainerLocation>,
}

impl ItemReaderCtx {
    pub fn advance(&mut self, bytes: u64) -> std::io::Result<()> {
        self.pos = self.pos.saturating_add(bytes);
        if self.pos > self.len {
            return Err(std::io::Error::other("item reader out of bounds"));
        }
        Ok(())
    }

    pub fn remaining(&self) -> u64 {
        self.len.saturating_sub(self.pos)
    }
}

impl Context for ItemReaderCtx {
    type Buf = HeapCircularBuffer;

    fn buffer(&mut self) -> &mut Self::Buf {
        &mut self.buf
    }
}
