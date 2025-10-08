use crate::blob::{Blob, OwnedBlob};
use crate::bundle::BundleItemError;
use crate::bundle::v2::reader::item::ItemReaderCtx;
use crate::bundle::v2::reader::item::tags::Tags;
use crate::bundle::v2::reader::{PollResult, Result, Step, parse_u16, parse_u64};
use crate::bundle::v2::{MAX_TAG_COUNT, MAX_TAG_KEY_SIZE, MAX_TAG_VALUE_SIZE, SignatureType};

enum Field {
    SignatureType,
    Signature(SignatureType),
    Owner(SignatureType),
    Target,
    MaybeAnchor,
    Anchor,
    TagCount,
    TagSize,
}

pub(crate) struct Header<const PROCESS_DATA: bool> {
    next_field: Field,
    owner: Option<OwnedBlob>,
    signature: Option<OwnedBlob>,
    signature_type: Option<SignatureType>,
    target: Option<OwnedBlob>,
    anchor: Option<OwnedBlob>,
    tag_count: u16,
    tag_size: u64,
}

impl<const PROCESS_DATA: bool> Step<ItemReaderCtx> for Header<PROCESS_DATA> {
    type Next = Tags<PROCESS_DATA>;

    fn required_bytes(&self, ctx: &ItemReaderCtx) -> usize {
        let len = match &self.next_field {
            Field::SignatureType => 2,
            Field::Signature(sig_type) => sig_type.len(),
            Field::Owner(sig_type) => sig_type.verifier_len() + 1, // next field presence byte
            Field::Target => 32 + 1,                               // next field presence byte
            Field::MaybeAnchor => 1,
            Field::Anchor => 32,
            Field::TagCount => 8,
            Field::TagSize => 8,
        };
        len.saturating_sub(ctx.buf.remaining())
    }

    fn poll(&mut self, ctx: &mut ItemReaderCtx) -> Result<PollResult<Self::Next>> {
        if self.required_bytes(ctx) > 0 {
            return Ok(PollResult::NeedMoreData);
        }
        let len = ctx.buf.remaining();
        let res = self.process_fields(ctx.buf.make_contiguous());
        ctx.buf.reset();
        ctx.advance(len as u64)?;
        if res? {
            return Ok(PollResult::Continue(self.transition(ctx)?));
        }
        Ok(PollResult::NeedMoreData)
    }
}

impl<const PROCESS_DATA: bool> Header<PROCESS_DATA> {
    pub(super) fn new() -> Self {
        Self {
            next_field: Field::SignatureType,
            owner: None,
            signature: None,
            signature_type: None,
            target: None,
            anchor: None,
            tag_count: 0,
            tag_size: 0,
        }
    }

    fn transition(&mut self, ctx: &ItemReaderCtx) -> Result<Tags<PROCESS_DATA>> {
        //todo: additional verification
        let (owner, signature, signature_type) = match (
            self.owner.take(),
            self.signature.take(),
            self.signature_type.take(),
        ) {
            (Some(owner), Some(signature), Some(signature_type)) => {
                (owner, signature, signature_type)
            }
            _ => {
                return Err(BundleItemError::Other("signature data missing".to_string()))?;
            }
        };
        if self.tag_size > ctx.remaining() {
            return Err(BundleItemError::TagSizeOutOfBounds(self.tag_size))?;
        }
        Ok(Tags::new(
            self.tag_size as usize,
            ctx.buf.capacity(),
            self.tag_count as usize,
            owner,
            signature,
            signature_type,
            self.target.take(),
            self.anchor.take(),
        )?)
    }

    fn process_fields(&mut self, buf: &[u8]) -> Result<bool> {
        match &mut self.next_field {
            Field::SignatureType => {
                self.next_field = Field::Signature(parse_signature_type(buf)?);
            }
            Field::Signature(sig_type) => {
                let sig_type = *sig_type;
                self.signature_type = Some(sig_type);
                self.signature = Some(Blob::from(buf).into_owned());
                self.next_field = Field::Owner(sig_type);
            }
            Field::Owner(_) => {
                let (content, has_target_field) = buf.split_at(buf.len() - 1);
                self.owner = Some(Blob::from(content).into_owned());
                self.next_field = if parse_presence_byte(has_target_field)? {
                    // target present byte set
                    Field::Target
                } else {
                    // check if anchor preset byte is set
                    Field::MaybeAnchor
                }
            }
            Field::Target => {
                let (content, has_anchor_field) = buf.split_at(buf.len() - 1);
                self.target = Some(Blob::from(content).into_owned());
                self.next_field = if parse_presence_byte(has_anchor_field)? {
                    // anchor present byte set
                    Field::Anchor
                } else {
                    // jump straight to tag_count
                    Field::TagCount
                }
            }
            Field::MaybeAnchor => {
                self.next_field = if parse_presence_byte(buf)? {
                    Field::Anchor
                } else {
                    Field::TagCount
                };
            }
            Field::Anchor => {
                self.anchor = Some(Blob::from(buf).into_owned());
                self.next_field = Field::TagCount;
            }
            Field::TagCount => {
                self.tag_count = parse_tag_count(buf)?;
                self.next_field = Field::TagSize;
            }
            Field::TagSize => {
                self.tag_size = parse_tag_size(buf, self.tag_count as u64)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[inline]
fn parse_signature_type(buf: &[u8]) -> Result<SignatureType> {
    let sig_type: SignatureType = parse_u16(buf)
        .ok_or(BundleItemError::InvalidOrUnsupportedSignatureType(
            "invalid value".to_string(),
        ))?
        .try_into()?;
    Ok(sig_type)
}

#[inline]
fn parse_tag_count(buf: &[u8]) -> Result<u16> {
    let tag_count = parse_u16(buf).ok_or(BundleItemError::Other(
        "invalid tag count value".to_string(),
    ))?;
    if tag_count > MAX_TAG_COUNT {
        return Err(BundleItemError::MaxTagCountExceeded {
            max: MAX_TAG_COUNT,
            actual: tag_count,
        })?;
    }
    Ok(tag_count)
}

#[inline]
fn parse_tag_size(buf: &[u8], tag_count: u64) -> Result<u64> {
    const SINGLE_TAG_MIN_SIZE: u64 = 16; // todo
    const SINGLE_TAG_MAX_SIZE: u64 = (MAX_TAG_KEY_SIZE + MAX_TAG_VALUE_SIZE + 128) as u64; // + overhead

    let tag_size =
        parse_u64(buf).ok_or(BundleItemError::Other("invalid tag size value".to_string()))?;

    let plausible_min_size = SINGLE_TAG_MIN_SIZE * tag_count;
    let plausible_max_size = SINGLE_TAG_MAX_SIZE * tag_count;

    if tag_size < plausible_min_size {
        return Err(BundleItemError::Other(format!(
            "tags byte size '{}' below plausible minimum '{}'",
            tag_size, plausible_min_size
        )))?;
    }

    if tag_size > plausible_max_size {
        return Err(BundleItemError::Other(format!(
            "tags byte size '{}' exceeds plausible maximum '{}'",
            tag_size, plausible_max_size
        )))?;
    }

    Ok(tag_size)
}

#[inline]
fn parse_presence_byte(value: &[u8]) -> Result<bool> {
    Ok(match value {
        &[0x00] => false,
        &[0x01] => true,
        _ => {
            return Err(BundleItemError::Other(
                "invalid presence byte value".to_string(),
            ))?;
        }
    })
}
