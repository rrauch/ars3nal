use crate::base64::{Base64Stringify, UrlSafeNoPadding};
use crate::serde::{AsBytes, FromBytes, StringifySerdeStrategy};
use crate::typed::Typed;
use bytes::Bytes;
use derive_where::derive_where;
use generic_array::typenum::{U512, Unsigned};
use generic_array::{ArrayLength, GenericArray};
use rsa::pss::{BlindedSigningKey, VerifyingKey as PssVerifyingKey};
use rsa::signature::{RandomizedSignerMut, SignatureEncoding, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey, signature};
use std::array::TryFromSliceError;
use std::borrow::Cow;
use std::ops::Deref;
use thiserror::Error;

pub type TypedSignature<T, SIGNER, S: Scheme> =
    Typed<(T, SIGNER), Signature<S>, StringifySerdeStrategy, Base64Stringify<UrlSafeNoPadding>>;

#[derive_where(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Signature<S: Scheme>(GenericArray<u8, S::SIG_LEN>);

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
        let expected = S::SIG_LEN::to_usize();
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

    pub fn into_inner(self) -> GenericArray<u8, S::SIG_LEN> {
        self.0
    }
}

impl<S: Scheme> AsBytes for Signature<S> {
    fn as_bytes(&self) -> impl Into<Cow<'_, [u8]>> {
        self.as_slice()
    }
}

impl<S: Scheme> FromBytes for Signature<S> {
    type Error = Error;

    fn try_from_bytes(input: Bytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::try_clone_from_bytes(input.as_ref())
    }
}

pub trait Scheme {
    #[allow(non_camel_case_types)]
    type SIG_LEN: ArrayLength;
    type Signer;
    type Verifier;
    type VerificationError;

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

pub struct RsaPss;

impl Scheme for RsaPss {
    type SIG_LEN = U512;

    type Signer = RsaPrivateKey;
    type Verifier = RsaPublicKey;
    type VerificationError = signature::Error;

    fn sign(signer: &Self::Signer, data: impl AsRef<[u8]>) -> Signature<Self>
    where
        Self: Sized,
    {
        let mut signing_key = BlindedSigningKey::<rsa::sha2::Sha256>::new_with_salt_len(
            signer.clone(),
            calculate_rsa_pss_max_salt_len::<sha2::Sha256>(signer.size()),
        );

        let mut rng = rand::rng();

        let sig = signing_key.sign_with_rng(&mut rng, data.as_ref());
        Signature::try_clone_from_bytes(sig.to_bytes().deref())
            .expect("signature to be of correct length")
    }

    fn verify(
        verifier: &Self::Verifier,
        data: impl AsRef<[u8]>,
        signature: &Signature<Self>,
    ) -> Result<(), Self::VerificationError>
    where
        Self: Sized,
    {
        let verifying_key: PssVerifyingKey<rsa::sha2::Sha256> = PssVerifyingKey::new_with_salt_len(
            verifier.clone(),
            calculate_rsa_pss_max_salt_len::<sha2::Sha256>(verifier.size()),
        );

        verifying_key.verify(
            data.as_ref(),
            &rsa::pss::Signature::try_from(signature.as_slice())?,
        )
    }
}

/// Calculate the maximum salt length for the given key & digest
fn calculate_rsa_pss_max_salt_len<D: digest::Digest>(key_size_bytes: usize) -> usize {
    let hash_size_bytes = <D as digest::Digest>::output_size();
    key_size_bytes - hash_size_bytes - 2
}

#[cfg(test)]
mod tests {
    use crate::signature::{RsaPss, Scheme};
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    const SECRET_KEY_4096_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
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
tlG6br5CMjD4OawH/YTbcmNt1N2h
-----END PRIVATE KEY-----"#;

    #[test]
    fn rsa_pss_sign_verify() {
        let secret_key = RsaPrivateKey::from_pkcs8_pem(SECRET_KEY_4096_PEM).unwrap();
        let public_key = secret_key.to_public_key();

        let message = "HEllO wOrlD";
        let signature = RsaPss::sign(&secret_key, message);
        RsaPss::verify(&public_key, message, &signature).unwrap()
    }
}
