use crate::blob::{Blob, OwnedBlob};
use crate::buffer::{BufMutExt, HeapCircularBuffer};
use crate::bundle::v2::SignatureType;
use crate::bundle::v2::reader::item::ItemReaderCtx;
use crate::bundle::v2::reader::item::data::Data;
use crate::bundle::v2::reader::{PollResult, Result, Step};
use crate::bundle::{BundleItemError, TagError};
use bytes::Buf;
use std::cmp::max;

const MAX_TAG_BUF_SIZE: usize = 1024 * 1024 * 4; // 4 MiB

pub(crate) struct Tags {
    len: usize,
    buf: Option<HeapCircularBuffer>,
    count: usize,
    owner: OwnedBlob,
    signature: OwnedBlob,
    signature_type: SignatureType,
    target: Option<OwnedBlob>,
    anchor: Option<OwnedBlob>,
}

impl Tags {
    pub(super) fn new(
        len: usize,
        buf_capacity: usize,
        count: usize,
        owner: OwnedBlob,
        signature: OwnedBlob,
        signature_type: SignatureType,
        target: Option<OwnedBlob>,
        anchor: Option<OwnedBlob>,
    ) -> Result<Self> {
        // No crate with streaming avro support exists at the time this was written
        // so we have no other choice but to buffer the full tags value!
        //
        // If the total length of the avro data exceeds the normal buffer capacity, we
        // create a separate buffer and transfer chunks into it.
        let buf = if len > buf_capacity {
            if len > MAX_TAG_BUF_SIZE {
                return Err(std::io::Error::other(format!(
                    "{} exceeds max allowed buffer size of {}",
                    len, MAX_TAG_BUF_SIZE
                )))?;
            }
            Some(HeapCircularBuffer::new(len))
        } else {
            None
        };
        Ok(Self {
            len,
            buf,
            count,
            owner,
            signature,
            signature_type,
            target,
            anchor,
        })
    }
}

impl Step<ItemReaderCtx> for Tags {
    type Next = Data;

    fn required_bytes(&self, ctx: &ItemReaderCtx) -> usize {
        self.len.saturating_sub(max(
            ctx.buf.remaining(),
            self.buf.as_ref().map(|b| b.remaining()).unwrap_or(0),
        ))
    }

    fn poll(&mut self, ctx: &mut ItemReaderCtx) -> Result<PollResult<Self::Next>> {
        if let Some(buf) = self.buf.as_mut() {
            buf.transfer_from_buf(&mut ctx.buf);
        }

        let buf = if let Some(buf) = self.buf.as_mut() {
            buf
        } else {
            &mut ctx.buf
        };

        if buf.remaining() < self.len {
            return Ok(PollResult::NeedMoreData);
        }

        // buffer is full
        // proceed with deserialization
        ctx.advance(self.len as u64)?;
        Ok(PollResult::Continue(self.transition(ctx)?))
    }
}

impl Tags {
    fn transition(&mut self, ctx: &mut ItemReaderCtx) -> Result<Data> {
        let tag_data = self.tags(ctx).map_err(|e| BundleItemError::from(e))?;
        let data_size = ctx.remaining();
        Ok(Data::new(
            ctx.pos,
            data_size,
            self.owner.clone(),
            self.signature.clone(),
            self.signature_type,
            self.target.take(),
            self.anchor.take(),
            tag_data,
            self.count,
        )?)
    }

    fn tags(&mut self, ctx: &mut ItemReaderCtx) -> core::result::Result<OwnedBlob, TagError> {
        if self.count == 0 {
            return Ok([].into());
        }

        let avro_data = Blob::from(ctx.buf.make_contiguous()).into_owned();
        ctx.buf.reset();
        Ok(avro_data)
    }
}
