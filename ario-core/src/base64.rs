use crate::serde::{AsBytes, FromBytes};
use crate::stringify::Stringify;
use bytes::BytesMut;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use std::borrow::Cow;
use std::fmt::Display;
use std::marker::PhantomData;
use thiserror::Error;

pub struct Base64Stringify<V, const MAX_LEN: usize = { usize::MAX }>(PhantomData<V>);

impl<T, const MAX_LEN: usize> Stringify<T> for Base64Stringify<UrlSafeNoPadding, MAX_LEN>
where
    T: FromBase64<UrlSafeNoPadding, MAX_LEN> + ToBase64<UrlSafeNoPadding>,
{
    type Error = Base64DeserializationError<<T as FromBase64<UrlSafeNoPadding, MAX_LEN>>::Error>;

    fn to_str(input: &T) -> impl Into<Cow<str>> {
        input.to_base64()
    }

    fn try_from_str<S: AsRef<str>>(input: S) -> Result<T, Self::Error>
    where
        Self: Sized,
    {
        let input = input.as_ref();
        if input.len() > MAX_LEN {
            return Err(Base64DeserializationError::MaxLengthExceeded {
                max: MAX_LEN,
                found: input.len(),
            });
        }
        T::try_from_base64(input).map_err(Into::into)
    }
}

pub struct UrlSafeNoPadding;

pub trait FromBase64<V, const MAX_LEN: usize> {
    type Error: Display;
    fn try_from_base64(input: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

#[derive(Error, Debug)]
pub enum Base64DeserializationError<E> {
    #[error("Input length of '{found}' exceeds maximum of '{max}'")]
    MaxLengthExceeded { max: usize, found: usize },
    #[error(transparent)]
    Base64Error(ct_codecs::Error),
    #[error(transparent)]
    InnerError(#[from] E),
}

impl<T, const MAX_LEN: usize> FromBase64<UrlSafeNoPadding, MAX_LEN> for T
where
    T: FromBytes,
{
    type Error = Base64DeserializationError<<T as FromBytes>::Error>;

    fn try_from_base64(input: &str) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        if input.len() > MAX_LEN {
            return Err(Base64DeserializationError::MaxLengthExceeded {
                max: MAX_LEN,
                found: input.len(),
            });
        }
        let mut buf = BytesMut::zeroed(((input.len() * 3) / 4) + 1);
        let decoded_len = try_base64_dec_urlsafe_nopadding(input, &mut buf)
            .map_err(Base64DeserializationError::Base64Error)?
            .len();
        buf.truncate(decoded_len);
        let bytes = buf.freeze();
        Ok(T::try_from_bytes(bytes)?)
    }
}

pub(crate) trait ToBase64<V> {
    fn to_base64(&self) -> String;
}

impl<T: AsBytes> ToBase64<UrlSafeNoPadding> for T {
    fn to_base64(&self) -> String {
        base64_enc_urlsafe_nopadding(self.as_bytes())
    }
}

fn base64_enc_urlsafe_nopadding(input: impl AsRef<[u8]>) -> String {
    Base64UrlSafeNoPadding::encode_to_string(input)
        .expect("base64 encode_to_string should never fail")
}

fn try_base64_dec_urlsafe_nopadding(
    input: impl AsRef<str>,
    out: &mut [u8],
) -> Result<&[u8], ct_codecs::Error> {
    Base64UrlSafeNoPadding::decode(out, input.as_ref(), None)
}
