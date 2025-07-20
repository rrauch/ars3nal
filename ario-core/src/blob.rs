use crate::base64::UrlSafeNoPadding;
use crate::serde::Base64SerdeStrategy;
use crate::typed::{FromInner, Typed};
use bytes::Bytes;
use std::fmt::{Debug, Formatter};
use thiserror::Error;

pub type TypedBlob<T, const MAX_LEN: usize = { usize::MAX }> =
    Typed<T, Bytes, Base64SerdeStrategy<UrlSafeNoPadding, MAX_LEN>, (), BlobDebug>;

pub trait BlobName {
    const NAME: &'static str = "blob";
}

#[derive(Error, Debug)]
pub enum IntoBlobError {
    #[error("maximum length exceeded; found {found}, max length {max}")]
    MaxLengthExceeded { max: usize, found: usize },
}

impl<T, const MAX_LEN: usize> TypedBlob<T, MAX_LEN> {
    pub fn try_from<I: Into<Bytes>>(value: I) -> Result<Self, IntoBlobError> {
        let bytes = value.into();
        if bytes.len() > MAX_LEN {
            Err(IntoBlobError::MaxLengthExceeded {
                max: MAX_LEN,
                found: bytes.len(),
            })
        } else {
            Ok(Self::from_inner(bytes))
        }
    }
}

pub struct BlobDebug;

impl<T, const MAX_LEN: usize> Debug for TypedBlob<T, MAX_LEN>
where
    T: BlobName,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{};len={}b]", T::NAME, self.0.len()).as_str())
    }
}
