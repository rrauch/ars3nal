mod data;
mod header;
mod tags;

use super::{Flow, Result};
use crate::buffer::HeapCircularBuffer;
use crate::bundle::V2BundleItemData;
use crate::bundle::read::item::data::Data;
use crate::bundle::read::item::header::Header;
use crate::bundle::read::item::tags::Tags;
use crate::bundle::read::{Context, StateMachine, Step};
use bon::bon;
use bytes::BufMut;
use itertools::Either;
use std::time::{Duration, Instant};

pub(crate) enum ItemReader {
    Header(StateMachine<ItemReaderCtx, Header>),
    Tags(StateMachine<ItemReaderCtx, Tags>),
    Data(StateMachine<ItemReaderCtx, Data>),
}

impl Flow for ItemReader {
    type Output = V2BundleItemData<'static>;
    type Buf<'a> = Box<dyn BufMut + 'a>;

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

    fn progress(&mut self, now: Instant) -> Result<()> {
        match self {
            Self::Header(s) => s.progress(now),
            Self::Tags(s) => s.progress(now),
            Self::Data(s) => s.progress(now),
        }
    }

    fn try_process(self, now: Instant) -> Result<Either<Self, Self::Output>> {
        Ok(match self {
            Self::Header(s) => match s.transition(now)? {
                Either::Left(header) => Either::Left(Self::Header(header)),
                Either::Right(tags) => Either::Left(Self::Tags(tags)),
            },
            Self::Tags(s) => match s.transition(now)? {
                Either::Left(tags) => Either::Left(Self::Tags(tags)),
                Either::Right(data) => Either::Left(Self::Data(data)),
            },
            Self::Data(s) => match s.finalize(now)? {
                Either::Left(data) => Either::Left(Self::Data(data)),
                Either::Right(out) => Either::Right(out),
            },
        })
    }
}

#[bon]
impl ItemReader {
    #[builder]
    pub fn new(
        len: u64,
        now: Instant,
        #[builder(default = Duration::from_secs(60))] max_inactivity: Duration,
        #[builder(default = Duration::from_secs(3600))] max_duration: Duration,
    ) -> Self {
        let ctx = ItemReaderCtx {
            len,
            pos: 0,
            buf: HeapCircularBuffer::new(1024 * 64),
        };
        Self::Header(StateMachine::new(
            ctx,
            Header::new(),
            now,
            max_inactivity,
            max_duration,
        ))
    }
}

pub struct ItemReaderCtx {
    len: u64,
    pos: u64,
    buf: HeapCircularBuffer,
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
