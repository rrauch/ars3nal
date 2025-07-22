use crate::base64::{Base64Stringify, UrlSafeNoPadding};
use crate::serde::{AsBytes, FromBytes, StringifySerdeStrategy};
use crate::typed::Typed;
use bytes::Bytes;
use derive_where::derive_where;
use std::array::TryFromSliceError;
use std::borrow::Cow;
use std::marker::PhantomData;
use thiserror::Error;

pub type TypedSignature<T, S: Scheme, const LEN: usize> =
    Typed<T, Signature<S, LEN>, StringifySerdeStrategy, Base64Stringify<UrlSafeNoPadding>>;

#[derive_where(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Signature<S: Scheme, const LEN: usize>([u8; LEN], PhantomData<S>);

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Invalid input length, expected '{expected}' but go '{actual}'")]
    InvalidInputLength { expected: usize, actual: usize },
    #[error(transparent)]
    ConversionError(#[from] TryFromSliceError),
}

impl<S: Scheme, const LEN: usize> Signature<S, LEN> {
    pub(crate) fn empty() -> Self {
        Self([0u8; LEN], PhantomData)
    }

    pub fn try_clone_from_bytes(input: impl AsRef<[u8]>) -> Result<Self, SignatureError> {
        let input = input.as_ref();
        if input.len() != LEN {
            return Err(SignatureError::InvalidInputLength {
                expected: LEN,
                actual: input.len(),
            });
        }
        Ok(Self(input.try_into()?, PhantomData))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; LEN] {
        self.0
    }
}

impl<S: Scheme, const LEN: usize> AsBytes for Signature<S, LEN> {
    fn as_bytes(&self) -> impl Into<Cow<'_, [u8]>> {
        self.as_slice()
    }
}

impl<S: Scheme, const LEN: usize> FromBytes for Signature<S, LEN> {
    type Error = SignatureError;

    fn try_from_bytes(input: Bytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::try_clone_from_bytes(input.as_ref())
    }
}

pub trait Scheme {}

impl Scheme for () {}
