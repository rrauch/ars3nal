use crate::base64::ToBase64;
use crate::blob::{AsBlob, Blob};
use crate::crypto::Output;
use crate::crypto::keys::{PublicKey, SecretKey};
use crate::typed::Typed;
use bytemuck::TransparentWrapper;
use derive_where::derive_where;
use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

pub type TypedSignature<T, SIGNER, S: Scheme> = Typed<(T, SIGNER), Signature<S>>;

#[derive_where(Clone, PartialEq)]
#[derive(TransparentWrapper)]
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

    pub(crate) fn into_inner(self) -> S::Output {
        self.0
    }

    pub(crate) fn as_inner(&self) -> &S::Output {
        &self.0
    }

    #[inline]
    pub(crate) fn as_variant<O: Scheme<Output = S::Output>>(&self) -> &Signature<O> {
        Signature::<O>::wrap_ref(&self.0)
    }
}

impl<'a, S: Scheme> TryFrom<Blob<'a>> for Signature<S> {
    type Error = <Blob<'a> as TryInto<S::Output>>::Error;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Signature(value.try_into()?))
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    SigningError(#[from] SigningError),
    #[error(transparent)]
    VerificationError(#[from] VerificationError),
}

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("signing error: {0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("verification error: {0}")]
    Other(String),
}

pub trait SchemeVariant {
    type Scheme: Scheme;
    type Error: Display + Send;
    type Message: ?Sized;

    fn process(msg: &Self::Message) -> Result<Cow<<Self::Scheme as Scheme>::Message>, Self::Error>
    where
        <Self::Scheme as Scheme>::Message: Clone;
}

impl<T> Scheme for T
where
    T: SchemeVariant,
    <<T as SchemeVariant>::Scheme as Scheme>::Message: Clone,
{
    type Output = <T::Scheme as Scheme>::Output;
    type Signer = <T::Scheme as Scheme>::Signer;
    type SigningError = SigningError;
    type Verifier = <T::Scheme as Scheme>::Verifier;
    type VerificationError = VerificationError;
    type Message = T::Message;

    #[inline]
    fn sign(
        signer: &Self::Signer,
        msg: &Self::Message,
    ) -> Result<Signature<Self>, Self::SigningError>
    where
        Self: Sized,
    {
        let msg = T::process(msg).map_err(|e| SigningError::Other(e.to_string()))?;
        Ok(Signature::from_inner(
            <T::Scheme as Scheme>::sign(signer, &msg)
                .map_err(|e| e.into())?
                .into_inner(),
        ))
    }

    #[inline]
    fn verify(
        verifier: &Self::Verifier,
        msg: &Self::Message,
        signature: &Signature<Self>,
    ) -> Result<(), Self::VerificationError>
    where
        Self: Sized,
    {
        let msg = T::process(msg).map_err(|e| VerificationError::Other(e.to_string()))?;
        <T::Scheme as Scheme>::verify(verifier, &msg, signature.as_variant()).map_err(|e| e.into())
    }
}

pub trait Scheme {
    type Output: Output + PartialEq;
    type Signer;
    type SigningError: Into<SigningError>;
    type Verifier: for<'a> TryFrom<Blob<'a>> + Debug + Clone + PartialEq;
    type VerificationError: Into<VerificationError>;
    type Message: ?Sized;

    fn sign(
        signer: &Self::Signer,
        msg: &Self::Message,
    ) -> Result<Signature<Self>, Self::SigningError>
    where
        Self: Sized;
    fn verify(
        verifier: &Self::Verifier,
        msg: &Self::Message,
        signature: &Signature<Self>,
    ) -> Result<(), Self::VerificationError>
    where
        Self: Sized;
}

pub(crate) trait VerifySigExt<S: Scheme> {
    type VerificationError: Into<VerificationError>;

    fn verify_sig(
        &self,
        msg: &S::Message,
        sig: &Signature<S>,
    ) -> Result<(), Self::VerificationError>;
}

impl<T, S> VerifySigExt<S> for T
where
    T: PublicKey,
    S: Scheme<Verifier = T>,
{
    type VerificationError = <S as Scheme>::VerificationError;

    fn verify_sig(
        &self,
        msg: &S::Message,
        sig: &Signature<S>,
    ) -> Result<(), Self::VerificationError> {
        S::verify(self, msg, sig)
    }
}

pub(crate) trait SignSigExt<S: Scheme> {
    type SigningError: Into<SigningError>;
    fn sign_sig(&self, msg: &S::Message) -> Result<Signature<S>, Self::SigningError>;
}

impl<T, S> SignSigExt<S> for T
where
    T: SecretKey,
    S: Scheme<Signer = T>,
{
    type SigningError = <S as Scheme>::SigningError;

    fn sign_sig(&self, msg: &S::Message) -> Result<Signature<S>, Self::SigningError> {
        S::sign(self, msg)
    }
}
