use crate::base64::ToBase64;
use crate::blob::{AsBlob, Blob};
use crate::crypto::Output;
use crate::typed::Typed;
use derive_where::derive_where;
use std::fmt::{Debug, Display, Formatter};

pub type TypedSignature<T, SIGNER, S: Scheme> = Typed<(T, SIGNER), Signature<S>>;

#[derive_where(Clone, PartialEq)]
#[repr(transparent)]
pub struct Signature<S: Scheme>(S::Output);

impl<S: Scheme> Display for Signature<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_base64().as_str())
    }
}

impl<S: Scheme> Debug for Signature<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.to_base64().as_str())
    }
}

impl<S: Scheme> AsBlob for Signature<S> {
    fn as_blob(&self) -> Blob<'_> {
        self.0.as_blob()
    }
}

impl<S: Scheme> Signature<S> {
    pub(crate) fn from_inner(inner: S::Output) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> S::Output {
        self.0
    }
}

impl<'a, S: Scheme> TryFrom<Blob<'a>> for Signature<S> {
    type Error = <Blob<'a> as TryInto<S::Output>>::Error;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Signature(value.try_into()?))
    }
}

pub trait Scheme {
    type Output: Output + PartialEq;
    type Signer;
    type SigningError: Display;
    type Verifier;
    type VerificationError: Display;
    type Message<'a>;

    fn sign(
        signer: &Self::Signer,
        msg: Self::Message<'_>,
    ) -> Result<Signature<Self>, Self::SigningError>
    where
        Self: Sized;
    fn verify(
        verifier: &Self::Verifier,
        msg: Self::Message<'_>,
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
        msg: S::Message<'_>,
        sig: &Signature<S>,
    ) -> Result<(), Self::VerificationError>;
}

pub(crate) trait SignExt<S: Scheme> {
    type SigningError: Display;
    fn sign_impl(&self, msg: S::Message<'_>) -> Result<Signature<S>, Self::SigningError>;
}
