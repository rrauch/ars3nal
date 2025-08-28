use crate::blob::{AsBlob, Blob, OwnedBlob};
use crate::bundle::read::item::ItemReaderCtx;
use crate::bundle::read::item::tags::Tags;
use crate::bundle::read::{PollResult, Result, Step, parse_u16, parse_u64};
use crate::bundle::{
    BundleAnchor, BundleItemError, MAX_TAG_COUNT, MAX_TAG_KEY_SIZE, MAX_TAG_VALUE_SIZE,
    SignatureType, V2SignatureData,
};
use crate::wallet::WalletAddress;

enum Field {
    SignatureType,
    Signature(SignatureType),
    Owner(OwnedBlob, SignatureType),
    Target,
    MaybeAnchor,
    Anchor,
    TagCount,
    TagSize,
}

pub(crate) struct Header {
    next_field: Field,
    signature_data: Option<V2SignatureData>,
    target: Option<WalletAddress>,
    anchor: Option<BundleAnchor>,
    tag_count: u16,
    tag_size: u64,
}

impl Step<ItemReaderCtx> for Header {
    type Next = Tags;

    fn required_bytes(&self, ctx: &ItemReaderCtx) -> usize {
        let len = match &self.next_field {
            Field::SignatureType => 2,
            Field::Signature(sig_type) => sig_type.len(),
            Field::Owner(_, sig_type) => sig_type.verifier_len() + 1, // next field presence byte
            Field::Target => 32 + 1,                                  // next field presence byte
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

impl Header {
    pub(super) fn new() -> Self {
        Self {
            next_field: Field::SignatureType,
            signature_data: None,
            target: None,
            anchor: None,
            tag_count: 0,
            tag_size: 0,
        }
    }

    fn transition(&mut self, ctx: &ItemReaderCtx) -> Result<Tags> {
        //todo: additional verification
        if self.tag_size > ctx.remaining() {
            return Err(BundleItemError::TagSizeOutOfBounds(self.tag_size))?;
        }
        Ok(Tags::new(
            self.tag_size as usize,
            ctx.buf.capacity(),
            self.tag_count as usize,
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
                self.next_field = Field::Owner(parse_signature_blob(buf, sig_type)?, sig_type);
            }
            Field::Owner(owner, sig_type) => {
                //todo: V2SignatureData
                let (content, has_target_field) = buf.split_at(buf.len() - 1);
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
                self.target = Some(parse_target(content)?);
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
                self.anchor = Some(parse_anchor(buf)?);
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
fn parse_signature_blob(buf: &[u8], sig_type: SignatureType) -> Result<OwnedBlob> {
    if buf.len() != sig_type.len() {
        return Err(BundleItemError::IncorrectSignatureLength {
            expected: sig_type.len(),
            actual: buf.len(),
        })?;
    }
    Ok(Blob::from(buf).into_owned())
}

#[inline]
fn parse_signature_owner(
    buf: &[u8],
    sig_type: SignatureType,
    sig_blob: OwnedBlob,
) -> Result<V2SignatureData> {
    if buf.len() != sig_type.verifier_len() {
        return Err(BundleItemError::IncorrectOwnerLength {
            expected: sig_type.verifier_len(),
            actual: buf.len(),
        })?;
    }
    todo!()
}

#[inline]
fn parse_target(buf: &[u8]) -> Result<WalletAddress> {
    Ok(WalletAddress::try_from(buf.as_blob())
        .map_err(|e| BundleItemError::InvalidWalletAddress(e.to_string()))?)
}

#[inline]
fn parse_anchor(buf: &[u8]) -> Result<BundleAnchor> {
    Ok(BundleAnchor::try_from(buf.as_blob())
        .map_err(|e| BundleItemError::InvalidAnchor(e.to_string()))?)
}

#[inline]
fn parse_tag_count(buf: &[u8]) -> Result<u16> {
    let tag_count = parse_u16(buf).ok_or(BundleItemError::Other(
        "invalid tag count value".to_string(),
    ))?;
    if tag_count > MAX_TAG_COUNT {
        return Err(BundleItemError::MaxTagCountExceeded(tag_count))?;
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
