use crate::blob::OwnedBlob;
use crate::bundle::BundleItemError;
use crate::bundle::v2::reader::item::ItemReaderCtx;
use crate::bundle::v2::reader::{PollResult, Result, Step};
use crate::bundle::v2::{BundleItemDataProcessor, ContainerLocation, RawBundleItem, SignatureType};
use bytes::Buf;
use std::cmp::min;
use std::io::Cursor;

pub(crate) struct Data {
    len: u64,
    owner: OwnedBlob,
    signature: OwnedBlob,
    signature_type: SignatureType,
    target: Option<OwnedBlob>,
    anchor: Option<OwnedBlob>,
    tag_data: OwnedBlob,
    tag_count: usize,
    processor: Option<BundleItemDataProcessor>,
    data_offset: u64,
}

impl Data {
    pub(super) fn new(
        pos: u64,
        len: u64,
        container_location: Option<ContainerLocation>,
        owner: OwnedBlob,
        signature: OwnedBlob,
        signature_type: SignatureType,
        target: Option<OwnedBlob>,
        anchor: Option<OwnedBlob>,
        tag_data: OwnedBlob,
        tag_count: usize,
    ) -> Result<Self> {
        if len == 0 {
            //todo: find out if data item payload can be zero-sized
            return Err(BundleItemError::EmptyPayload)?;
        }

        Ok(Self {
            len,
            owner,
            signature,
            signature_type,
            target,
            anchor,
            tag_data,
            tag_count,
            processor: Some(BundleItemDataProcessor::new(container_location)),
            data_offset: pos,
        })
    }

    fn process(&mut self, data: &[u8]) {
        self.processor
            .as_mut()
            .unwrap()
            .update(&mut Cursor::new(data));
    }

    fn remaining(&self) -> u64 {
        self.len
            .saturating_sub(self.processor.as_ref().unwrap().processed)
    }

    fn finalize(&mut self, pos: u64) -> Result<RawBundleItem<'static>> {
        if self.remaining() > 0 {
            return Err(BundleItemError::Other(format!(
                "unexpected end of data; expected '{}' additional bytes",
                self.remaining()
            )))?;
        }
        assert_eq!(self.data_offset + self.len, pos);
        let dr = self.processor.take().unwrap().finalize();
        Ok(RawBundleItem {
            anchor: self.anchor.take(),
            tag_data: self.tag_data.clone(),
            tag_count: self.tag_count,
            target: self.target.take(),
            owner: self.owner.clone(),
            signature: self.signature.clone(),
            signature_type: self.signature_type,
            data_size: self.len,
            data_deep_hash: dr.data_deep_hash,
            data_verifier: dr.data_authenticator,
            data_offset: self.data_offset,
        })
    }
}

impl Step<ItemReaderCtx> for Data {
    type Next = RawBundleItem<'static>;

    fn required_bytes(&self, ctx: &ItemReaderCtx) -> usize {
        min(
            self.remaining().saturating_sub(ctx.buf.remaining() as u64) as usize,
            ctx.buf.remaining_mut(),
        )
    }

    fn poll(&mut self, ctx: &mut ItemReaderCtx) -> Result<PollResult<Self::Next>> {
        if self.required_bytes(ctx) > 0 {
            return Ok(PollResult::NeedMoreData);
        }

        let len = min(self.remaining() as usize, ctx.buf.remaining());
        self.process(&ctx.buf.make_contiguous()[..len]);

        ctx.buf.advance(len);
        ctx.advance(len as u64)?;

        if self.remaining() > 0 {
            return Ok(PollResult::NeedMoreData);
        }
        Ok(PollResult::Continue(self.finalize(ctx.pos)?))
    }
}
