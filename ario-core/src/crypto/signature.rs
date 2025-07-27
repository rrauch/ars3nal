use crate::blob::Blob;
use crate::typed::Typed;
use derive_where::derive_where;
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};

use std::array::TryFromSliceError;
use std::fmt::Display;
use thiserror::Error;

pub type TypedSignature<T, SIGNER, S: Scheme> = Typed<(T, SIGNER), Signature<S>>;

#[derive_where(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Signature<S: Scheme>(GenericArray<u8, S::SigLen>);

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid input length, expected '{expected}' but go '{actual}'")]
    InvalidInputLength { expected: usize, actual: usize },
    #[error(transparent)]
    ConversionError(#[from] TryFromSliceError),
}

impl<S: Scheme> Signature<S> {
    pub(crate) fn empty() -> Self {
        Self(GenericArray::default())
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
        Ok(Self(GenericArray::from_slice(input).clone()))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> GenericArray<u8, S::SigLen> {
        self.0
    }
}

impl<S: Scheme> AsRef<[u8]> for Signature<S> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a, S: Scheme> TryFrom<Blob<'a>> for Signature<S> {
    type Error = <Blob<'a> as TryInto<GenericArray<u8, S::SigLen>>>::Error;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Signature(value.try_into()?))
    }
}

pub trait Scheme {
    #[allow(non_camel_case_types)]
    type SigLen: ArrayLength;
    type Signer;
    type Verifier;
    type VerificationError: Display;

    fn sign(signer: &Self::Signer, data: impl AsRef<[u8]>) -> Signature<Self>
    where
        Self: Sized;
    fn verify(
        verifier: &Self::Verifier,
        data: impl AsRef<[u8]>,
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
        data: impl AsRef<[u8]>,
        sig: &Signature<S>,
    ) -> Result<(), Self::VerificationError>;
}

pub(crate) trait SignExt<S: Scheme> {
    fn sign_impl(&self, data: impl AsRef<[u8]>) -> Signature<S>;
}
