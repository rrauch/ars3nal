mod index;
mod item;

use crate::buffer::BufMutExt;
use bytes::{Buf, BufMut};
use futures_lite::AsyncRead;
use itertools::Either;
use std::io::{Cursor, Read};
use std::time::{Duration, Instant};
use thiserror::Error;

type Result<T> = core::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error(
        "timeout reached; maximum: '{} ms', actual: '{} ms'",
        max.as_millis(),
        actual.as_millis()
    )]
    Timeout { max: Duration, actual: Duration },
    #[error(transparent)]
    BundleError(#[from] super::Error),
    #[error(transparent)]
    BundleItemError(#[from] super::BundleItemError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

pub struct StateMachine<Ctx, S> {
    ctx: Ctx,
    state: S,
    started: Instant,
    last_progress: Instant,
    max_inactivity: Duration,
    max_duration: Duration,
}

pub enum PollResult<Next> {
    NeedMoreData,
    Continue(Next),
}

pub trait Flow: Sized {
    type Output;
    type Buf<'a>: BufMut
    where
        Self: 'a;

    fn required_bytes(&self) -> usize;
    fn buffer(&mut self) -> Self::Buf<'_>;

    fn progress(&mut self, now: Instant) -> Result<()>;
    fn try_process(self, now: Instant) -> Result<Either<Self, Self::Output>>;
}

pub trait FlowExt: Sized {
    type Output;
    fn process<R: Read>(self, reader: R) -> Result<Self::Output>;
    fn process_async<R: AsyncRead + Unpin>(
        self,
        reader: R,
    ) -> impl Future<Output = Result<Self::Output>>;
}

impl<T: Flow> FlowExt for T {
    type Output = T::Output;

    fn process<R: Read>(self, mut reader: R) -> Result<Self::Output> {
        let mut this = self;
        loop {
            if this.required_bytes() > 0 {
                let mut buf = this.buffer();
                buf.fill(&mut reader)?;
            }
            match this.try_process(Instant::now())? {
                Either::Left(l) => this = l,
                Either::Right(out) => return Ok(out),
            }
        }
    }

    async fn process_async<R: AsyncRead + Unpin>(self, mut reader: R) -> Result<Self::Output> {
        let mut this = self;
        loop {
            if this.required_bytes() > 0 {
                let mut buf = this.buffer();
                buf.fill_async(&mut reader).await?;
            }
            match this.try_process(Instant::now())? {
                Either::Left(l) => this = l,
                Either::Right(out) => return Ok(out),
            }
        }
    }
}

pub trait Step<Ctx> {
    type Next;

    fn required_bytes(&self, ctx: &Ctx) -> usize;

    fn poll(&mut self, ctx: &mut Ctx) -> Result<PollResult<Self::Next>>;
}

impl<Ctx: Context, S: Step<Ctx>> StateMachine<Ctx, S> {
    fn new(
        ctx: Ctx,
        state: S,
        now: Instant,
        max_inactivity: Duration,
        max_duration: Duration,
    ) -> StateMachine<Ctx, S> {
        Self {
            ctx,
            state,
            started: now,
            last_progress: now,
            max_inactivity,
            max_duration,
        }
    }
}

impl<Ctx: Context, S: Step<Ctx>> StateMachine<Ctx, S> {
    pub fn progress(&mut self, now: Instant) -> Result<()> {
        self.check_timeout(now)?;
        self.last_progress = now;
        Ok(())
    }

    fn check_timeout(&self, now: Instant) -> Result<()> {
        let last_activity = now.saturating_duration_since(self.last_progress);
        if last_activity > self.max_inactivity {
            return Err(Error::Timeout {
                max: self.max_inactivity,
                actual: last_activity,
            });
        }

        let duration = now.saturating_duration_since(self.started);
        if duration > self.max_duration {
            return Err(Error::Timeout {
                max: self.max_duration,
                actual: duration,
            });
        }
        Ok(())
    }

    fn transition_to<NextState: Step<Ctx>>(
        self,
        next_state: NextState,
    ) -> StateMachine<Ctx, NextState> {
        StateMachine {
            ctx: self.ctx,
            state: next_state,
            started: self.started,
            last_progress: self.last_progress,
            max_inactivity: self.max_inactivity,
            max_duration: self.max_duration,
        }
    }

    pub fn buffer(&mut self) -> impl BufMut {
        let bytes_required = self.state.required_bytes(&self.ctx);
        self.ctx.buffer().limit_mut(bytes_required)
    }

    pub fn required_bytes(&self) -> usize {
        self.state.required_bytes(&self.ctx)
    }
}

impl<Ctx: Context, S: Step<Ctx>> StateMachine<Ctx, S>
where
    <S as Step<Ctx>>::Next: Step<Ctx>,
{
    fn transition(
        mut self,
        now: Instant,
    ) -> Result<Either<StateMachine<Ctx, S>, StateMachine<Ctx, S::Next>>> {
        self.progress(now)?;
        if self.state.required_bytes(&self.ctx) > 0 {
            return Ok(Either::Left(self));
        }
        match self.state.poll(&mut self.ctx)? {
            PollResult::NeedMoreData => Ok(Either::Left(self)),
            PollResult::Continue(next) => Ok(Either::Right(self.transition_to(next))),
        }
    }
}

impl<Ctx: Context, S: Step<Ctx>> StateMachine<Ctx, S> {
    fn finalize(mut self, now: Instant) -> Result<Either<StateMachine<Ctx, S>, S::Next>> {
        self.progress(now)?;
        if self.state.required_bytes(&self.ctx) > 0 {
            return Ok(Either::Left(self));
        }
        match self.state.poll(&mut self.ctx)? {
            PollResult::NeedMoreData => Ok(Either::Left(self)),
            PollResult::Continue(next) => Ok(Either::Right(next)),
        }
    }
}

pub trait Context {
    type Buf: BufMut + Send;
    fn buffer(&mut self) -> &mut Self::Buf;
}

#[inline]
fn parse_u16(value: &[u8]) -> Option<u16> {
    if value.len() >= 2 {
        let (value, suffix) = value.split_at(2);
        if !suffix.is_empty() {
            if !all_zeroes(suffix) {
                return None;
            }
        }
        //todo: make more efficient
        return Some(Cursor::new(value).get_u16_le());
    }
    None
}

#[inline]
fn parse_u64(value: &[u8]) -> Option<u64> {
    if value.len() >= 8 {
        let (value, suffix) = value.split_at(8);
        if !suffix.is_empty() {
            if !all_zeroes(suffix) {
                return None;
            }
        }
        //todo: make more efficient
        return Some(Cursor::new(value).get_u64_le());
    }
    None
}

#[inline]
fn all_zeroes(value: &[u8]) -> bool {
    value.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use crate::bundle::read::FlowExt;
    use crate::bundle::read::index::IndexReader;
    use crate::bundle::read::item::ItemReader;
    use futures_lite::AsyncSeekExt;
    use std::io::SeekFrom;
    use std::time::{Duration, Instant};

    static BUNDLE_1: &'static [u8] =
        include_bytes!("../../../testdata/nxoCcgVXf1A3yrMMEXAJpa0YUfgl9EONIKNVR6nr-50.bundle");

    static BUNDLE_2: &'static [u8] =
        include_bytes!("../../../testdata/Gz9dZaqN2I7AWT0vWGZWi5wlMjbImh13SOIomthyB6M.bundle");

    #[tokio::test]
    async fn deserialize_bundle() -> anyhow::Result<()> {
        for bundle in [BUNDLE_1] {
            let mut input = futures_lite::io::Cursor::new(bundle);

            let index = IndexReader::builder()
                .now(Instant::now())
                .max_inactivity(Duration::from_secs(30))
                .build()
                .process_async(&mut input)
                .await?;

            for entry in index.entries {
                input.seek(SeekFrom::Start(entry.offset)).await?;
                let bundle_item_data = ItemReader::builder()
                    .now(Instant::now())
                    .len(entry.len)
                    .build()
                    .process_async(&mut input)
                    .await?;
                println!("");
            }
        }

        Ok(())
    }
}
