use crate::blob::Blob;
use crate::typed::Typed;
use derive_where::derive_where;
use hybrid_array::typenum::Unsigned;
use hybrid_array::{Array, ArraySize};
use std::array::TryFromSliceError;
use std::fmt::Display;
use thiserror::Error;

pub type TypedSignature<T, SIGNER, S: Scheme> = Typed<(T, SIGNER), Signature<S>>;

#[derive_where(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Signature<S: Scheme>(Array<u8, S::SigLen>);

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid input length, expected '{expected}' but go '{actual}'")]
    InvalidInputLength { expected: usize, actual: usize },
    #[error(transparent)]
    ConversionError(#[from] TryFromSliceError),
}

impl<S: Scheme> Signature<S> {
    pub(crate) fn empty() -> Self {
        Self(Array::default())
    }

    pub fn try_clone_from_bytes(input: impl AsRef<[u8]>) -> Result<Self, Error> {
        let input = input.as_ref();
        let expected = S::SigLen::to_usize();
        if input.len() != expected {
            return Err(Error::InvalidInputLength {
                expected,
                actual: input.len(),
            });
        }
        Ok(Self(Array::try_from(input)?))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Array<u8, S::SigLen> {
        self.0
    }
}

impl<S: Scheme> AsRef<[u8]> for Signature<S> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a, S: Scheme> TryFrom<Blob<'a>> for Signature<S> {
    type Error = <Blob<'a> as TryInto<Array<u8, S::SigLen>>>::Error;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Signature(value.try_into()?))
    }
}

pub trait Scheme {
    #[allow(non_camel_case_types)]
    type SigLen: ArraySize;
    type Signer;
    type Verifier;
    type VerificationError: Display;
    type Message;

    fn sign(signer: &Self::Signer, msg: Self::Message) -> Signature<Self>
    where
        Self: Sized;
    fn verify(
        verifier: &Self::Verifier,
        msg: Self::Message,
        signature: &Signature<Self>,
    ) -> Result<(), Self::VerificationError>
    where
        Self: Sized;
}

pub(crate) trait SupportsSignatures {
    type Signer;
    type Verifier;
    type Scheme: Scheme<Signer = Self::Signer, Verifier = Self::Verifier>;
}

pub(crate) trait VerifySigExt<S: Scheme> {
    type VerificationError: Display;

    fn verify_sig_impl(
        &self,
        msg: S::Message,
        sig: &Signature<S>,
    ) -> Result<(), Self::VerificationError>;
}

pub(crate) trait SignExt<S: Scheme> {
    fn sign_impl(&self, msg: S::Message) -> Signature<S>;
}
