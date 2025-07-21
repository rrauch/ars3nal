use crate::serde::{AsBytes, FromBytes};
use crate::stringify::Stringify;
use bytes::BytesMut;
use ct_codecs::{Decoder, Encoder, Hex};
use std::borrow::Cow;
use std::fmt::Display;
use std::marker::PhantomData;
use thiserror::Error;

pub struct HexStringify<V, const MAX_LEN: usize = { usize::MAX }>(PhantomData<V>);

pub struct LowerCase;

impl<T, const MAX_LEN: usize> Stringify<T> for HexStringify<LowerCase, MAX_LEN>
where
    T: FromHex<LowerCase, MAX_LEN> + ToHex<LowerCase>,
{
    type Error = HexDeserializationError<<T as FromHex<LowerCase, MAX_LEN>>::Error>;

    fn to_str(input: &T) -> impl Into<Cow<str>> {
        input.to_hex()
    }

    fn try_from_str<S: AsRef<str>>(input: S) -> Result<T, Self::Error>
    where
        Self: Sized,
    {
        let input = input.as_ref();
        if input.len() > MAX_LEN {
            return Err(HexDeserializationError::MaxLengthExceeded {
                max: MAX_LEN,
                found: input.len(),
            });
        }
        T::try_from_hex(input).map_err(Into::into)
    }
}

pub trait FromHex<V, const MAX_LEN: usize> {
    type Error: Display;
    fn try_from_hex(input: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

#[derive(Error, Debug)]
pub enum HexDeserializationError<E> {
    #[error("Input length of '{found}' exceeds maximum of '{max}'")]
    MaxLengthExceeded { max: usize, found: usize },
    #[error(transparent)]
    HexError(ct_codecs::Error),
    #[error(transparent)]
    InnerError(#[from] E),
}

impl<T, const MAX_LEN: usize> FromHex<LowerCase, MAX_LEN> for T
where
    T: FromBytes,
{
    type Error = HexDeserializationError<<T as FromBytes>::Error>;

    fn try_from_hex(input: &str) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        if input.len() > MAX_LEN {
            return Err(HexDeserializationError::MaxLengthExceeded {
                max: MAX_LEN,
                found: input.len(),
            });
        }
        let mut buf = BytesMut::zeroed((input.len() / 2) + 1);
        let decoded_len = try_hex_dec(input, &mut buf)
            .map_err(HexDeserializationError::HexError)?
            .len();
        buf.truncate(decoded_len);
        let bytes = buf.freeze();
        Ok(T::try_from_bytes(bytes)?)
    }
}

pub(crate) trait ToHex<V> {
    fn to_hex(&self) -> String;
}

impl<T: AsBytes> ToHex<LowerCase> for T {
    fn to_hex(&self) -> String {
        hex_enc_lowercase(self.as_bytes().into())
    }
}

fn hex_enc_lowercase(input: impl AsRef<[u8]>) -> String {
    let mut hex = Hex::encode_to_string(input).expect("hex encode_to_string should never fail");
    hex.make_ascii_lowercase();
    hex
}

fn try_hex_dec(input: impl AsRef<str>, out: &mut [u8]) -> Result<&[u8], ct_codecs::Error> {
    Hex::decode(out, input.as_ref(), None)
}
