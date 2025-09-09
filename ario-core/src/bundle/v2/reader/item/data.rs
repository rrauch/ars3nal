use crate::blob::OwnedBlob;
use crate::bundle::BundleItemError;
use crate::bundle::v2::reader::item::ItemReaderCtx;
use crate::bundle::v2::reader::{PollResult, Result, Step};
use crate::bundle::v2::{
    BundleItemChunker, BundleItemMerkleTree, DataDeepHash, RawBundleItem, SignatureType,
};
use crate::chunking::{Chunk, Chunker};
use crate::crypto::hash::{Hasher, Sha384, deep_hash};
use bytes::Buf;
use std::cmp::min;
use std::io::Cursor;

pub(crate) struct Data {
    len: u64,
    processed: u64,
    owner: OwnedBlob,
    signature: OwnedBlob,
    signature_type: SignatureType,
    target: Option<OwnedBlob>,
    anchor: Option<OwnedBlob>,
    tag_data: OwnedBlob,
    tag_count: usize,
    hasher: Option<Sha384>,
    chunker: Option<BundleItemChunker>,
    chunks: Vec<Chunk<BundleItemChunker>>,
    data_offset: u64,
}

impl Data {
    pub(super) fn new(
        pos: u64,
        len: u64,
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
            processed: 0,
            owner,
            signature,
            signature_type,
            target,
            anchor,
            tag_data,
            tag_count,
            hasher: Some(Sha384::new()),
            chunker: Some(BundleItemChunker::new()),
            chunks: vec![],
            data_offset: pos,
        })
    }

    fn process(&mut self, data: &[u8]) {
        self.hasher.as_mut().unwrap().update(data);
        self.chunks.extend(
            self.chunker
                .as_mut()
                .unwrap()
                .update(&mut Cursor::new(data)),
        );
        self.processed += data.len() as u64;
    }

    fn remaining(&self) -> u64 {
        self.len.saturating_sub(self.processed)
    }

    fn finalize(&mut self, pos: u64) -> Result<RawBundleItem<'static>> {
        if self.processed != self.len {
            return Err(BundleItemError::Other(format!(
                "wrong number of bytes processed: {} != {}",
                self.processed, self.len
            )))?;
        }
        assert_eq!(self.data_offset + self.len, pos);
        self.chunks.extend(self.chunker.take().unwrap().finalize());
        let hash = self.hasher.take().unwrap().finalize();
        let data_deep_hash =
            DataDeepHash::new_from_inner(deep_hash::from_data_digest(&hash, self.processed));
        Ok(RawBundleItem {
            anchor: self.anchor.take(),
            tag_data: self.tag_data.clone(),
            tag_count: self.tag_count,
            target: self.target.take(),
            owner: self.owner.clone(),
            signature: self.signature.clone(),
            signature_type: self.signature_type,
            data_size: self.len,
            data_deep_hash,
            data_merkle_tree: BundleItemMerkleTree::from_iter(self.chunks.drain(..)),
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
