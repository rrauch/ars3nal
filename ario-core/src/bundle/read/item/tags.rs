use crate::blob::OwnedBlob;
use crate::buffer::{BufMutExt, HeapCircularBuffer};
use crate::bundle::read::item::{Data, ItemReaderCtx};
use crate::bundle::read::{PollResult, Result, Step};
use crate::bundle::{BundleAnchor, BundleItemError, TagError};
use crate::tag::{Tag, TagName, TagValue};
use crate::wallet::WalletAddress;
use bytes::Buf;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_avro_fast::Schema;
use std::cmp::max;
use std::ops::Deref;
use std::sync::LazyLock;

const MAX_TAG_BUF_SIZE: usize = 1024 * 1024 * 4; // 4 MiB

static AVRO_SCHEMA: LazyLock<Schema> = LazyLock::new(|| {
    r#"
{
  "type": "array",
  "items": {
    "type": "record",
    "name": "Tag",
    "fields": [
      { "name": "name", "type": "bytes" },
      { "name": "value", "type": "bytes" }
    ]
  }
}
"#
    .parse()
    .expect("Failed to parse avro schema")
});

pub(crate) struct Tags {
    len: usize,
    buf: Option<HeapCircularBuffer>,
    count: usize,
    target: Option<WalletAddress>,
    anchor: Option<BundleAnchor>,
}

impl Tags {
    pub(super) fn new(
        len: usize,
        buf_capacity: usize,
        count: usize,
        target: Option<WalletAddress>,
        anchor: Option<BundleAnchor>,
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
            target,
            anchor,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct AvroTag {
    name: OwnedBlob,
    value: OwnedBlob,
}

impl From<AvroTag> for Tag<'static> {
    fn from(value: AvroTag) -> Self {
        Tag::new(
            TagName::new_from_inner(value.name),
            TagValue::new_from_inner(value.value),
        )
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
        let tags = self.tags(ctx).map_err(|e| BundleItemError::from(e))?;
        let data_size = ctx.remaining();
        Ok(Data::new(
            data_size,
            self.target.take(),
            self.anchor.take(),
            tags,
        )?)
    }

    fn tags(
        &mut self,
        ctx: &mut ItemReaderCtx,
    ) -> core::result::Result<Vec<Tag<'static>>, TagError> {
        if self.count == 0 {
            return Ok(vec![]);
        }

        let avro_data = ctx.buf.make_contiguous();
        let res = serde_avro_fast::from_datum_slice::<Vec<AvroTag>>(avro_data, AVRO_SCHEMA.deref());
        ctx.buf.reset();
        let tags = res?.into_iter().map(|t| Tag::from(t)).collect_vec();

        if tags.len() != self.count {
            return Err(TagError::IncorrectTagCount {
                expected: self.count,
                actual: tags.len(),
            });
        }
        Ok(tags)
    }
}
