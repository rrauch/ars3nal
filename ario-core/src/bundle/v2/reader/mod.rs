pub(super) mod bundle;
pub(super) mod item;

use crate::buffer::BufMutExt;
use bytes::{Buf, BufMut};
use futures_lite::AsyncRead;
use itertools::Either;
use std::io::{Cursor, ErrorKind, Read};
use thiserror::Error;

type Result<T> = core::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    BundleError(#[from] super::super::Error),
    #[error(transparent)]
    BundleItemError(#[from] super::BundleItemError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

impl From<Error> for super::super::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::BundleError(e) => e,
            Error::BundleItemError(e) => Self::BundleItemError(e),
            Error::IoError(e) => Self::IoError(e),
        }
    }
}

pub struct IncrementalInputProcessor<Ctx, S> {
    ctx: Ctx,
    state: S,
}

pub enum PollResult<Next> {
    NeedMoreData,
    Continue(Next),
}

pub trait Flow: Sized {
    type Output;
    type Buf<'a>: BufMut + Send
    where
        Self: 'a;

    fn required_bytes(&self) -> usize;
    fn buffer(&mut self) -> Self::Buf<'_>;

    fn try_process(self) -> Result<Either<Self, Self::Output>>;
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
                if buf.fill(&mut reader)? == 0 {
                    drop(buf);
                    if this.required_bytes() > 0 {
                        // premature eof
                        Err(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            format!(
                                "unexpected eof; {} more bytes expected",
                                this.required_bytes()
                            ),
                        ))?
                    }
                }
            }
            match this.try_process()? {
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
                if buf.fill_async(&mut reader).await? == 0 {
                    drop(buf);
                    if this.required_bytes() > 0 {
                        // premature eof
                        Err(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            format!(
                                "unexpected eof; {} more bytes expected",
                                this.required_bytes()
                            ),
                        ))?
                    }
                }
            }
            match this.try_process()? {
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

impl<Ctx: Context, S: Step<Ctx>> IncrementalInputProcessor<Ctx, S> {
    fn new(ctx: Ctx, state: S) -> IncrementalInputProcessor<Ctx, S> {
        Self { ctx, state }
    }
}

impl<Ctx: Context, S: Step<Ctx>> IncrementalInputProcessor<Ctx, S> {
    fn transition_to<NextState: Step<Ctx>>(
        self,
        next_state: NextState,
    ) -> IncrementalInputProcessor<Ctx, NextState> {
        IncrementalInputProcessor {
            ctx: self.ctx,
            state: next_state,
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

impl<Ctx: Context, S: Step<Ctx>> IncrementalInputProcessor<Ctx, S>
where
    <S as Step<Ctx>>::Next: Step<Ctx>,
{
    fn transition(
        mut self,
    ) -> Result<Either<IncrementalInputProcessor<Ctx, S>, IncrementalInputProcessor<Ctx, S::Next>>>
    {
        if self.state.required_bytes(&self.ctx) > 0 {
            return Ok(Either::Left(self));
        }
        match self.state.poll(&mut self.ctx)? {
            PollResult::NeedMoreData => Ok(Either::Left(self)),
            PollResult::Continue(next) => Ok(Either::Right(self.transition_to(next))),
        }
    }
}

impl<Ctx: Context, S: Step<Ctx>> IncrementalInputProcessor<Ctx, S> {
    fn finalize(mut self) -> Result<Either<IncrementalInputProcessor<Ctx, S>, S::Next>> {
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
