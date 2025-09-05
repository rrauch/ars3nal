use crate::blob::{AsBlob, Blob};
use crate::confidential::RevealExt;
use crate::crypto::Output;
use crate::crypto::ec::{Curve, EcPublicKey, EcSecretKey};
use crate::crypto::signature::{Scheme, Signature, SigningError, VerificationError};
use derive_where::derive_where;
use ecdsa::RecoveryId;
use ecdsa::Signature as ExternalSignature;
use hybrid_array::typenum::Unsigned;
use signature::Verifier;
use std::marker::PhantomData;
use std::ops::{Add, Range};
use thiserror::Error;

pub struct Ecdsa<C: Curve>(PhantomData<C>);

#[derive_where(Clone, Debug, PartialEq)]
pub struct EcdsaSignature<C: Curve> {
    inner: ExternalSignature<C>,
    rec_id: Option<RecoveryId>,
}

impl<C: Curve> EcdsaSignature<C> {
    pub(crate) fn recover_verifier(
        &self,
        msg: &<Ecdsa<C> as Scheme>::Message,
    ) -> Result<<Ecdsa<C> as Scheme>::Verifier, EcdsaError> {
        if let Some(rec_id) = self.rec_id {
            Ok(EcPublicKey(elliptic_curve::PublicKey::<C>::from(
                ecdsa::VerifyingKey::recover_from_msg(msg, &self.inner, rec_id)?,
            )))
        } else {
            Err(EcdsaError::NonRecoverableSignature)
        }
    }
}

impl<C: Curve> AsBlob for EcdsaSignature<C> {
    fn as_blob(&self) -> Blob<'_> {
        let mut bytes = self.inner.to_vec();
        if let Some(rec_id) = self.rec_id {
            bytes.push(rec_id.to_byte()); // rec_id is stored at the end
        }
        Blob::from(bytes)
    }
}

impl<C: Curve> TryFrom<Blob<'_>> for EcdsaSignature<C> {
    type Error = EcdsaError;

    fn try_from(value: Blob<'_>) -> Result<Self, Self::Error> {
        let expected = <<C as elliptic_curve::Curve>::FieldBytesSize as Add>::Output::to_usize();
        let with_recovery = expected + 1;

        let bytes = value.bytes();

        if ![expected, with_recovery].contains(&bytes.len()) || expected < 2 {
            return Err(EcdsaError::UnexpectedInputLength {
                expected: expected..with_recovery + 1,
                actual: value.len(),
            });
        }

        let (sig_bytes, rec_id) = if bytes.len() == with_recovery {
            let (sig_bytes, rec_id) = bytes.split_at(bytes.len() - 1);
            let rec_id = match RecoveryId::from_byte(rec_id[0]) {
                Some(r) => r,
                None => return Err(EcdsaError::InvalidRecoveryId),
            };
            (sig_bytes, Some(rec_id))
        } else {
            (bytes, None)
        };

        let sig = ExternalSignature::<C>::from_slice(sig_bytes)?;

        Ok(Self { inner: sig, rec_id })
    }
}

impl<C: Curve> Output for EcdsaSignature<C> {
    type Len = <<C as elliptic_curve::Curve>::FieldBytesSize as Add>::Output;
}

#[derive(Error, Debug)]
pub enum EcdsaError {
    #[error(transparent)]
    ExternalError(#[from] ecdsa::Error),
    #[error(transparent)]
    EcError(#[from] elliptic_curve::Error),
    #[error(
        "unexpected input length: expected: '{}-{}', actual: '{actual}'",
        expected.start,
        expected.end
    )]
    UnexpectedInputLength {
        expected: Range<usize>,
        actual: usize,
    },
    #[error("invalid recovery id")]
    InvalidRecoveryId,
    #[error("signature does not support key recovery")]
    NonRecoverableSignature,
    #[error("recovered key does not match expected public key")]
    PublicKeyMismatch,
}

impl Into<SigningError> for EcdsaError {
    fn into(self) -> SigningError {
        SigningError::Other(self.to_string())
    }
}

impl Into<VerificationError> for EcdsaError {
    fn into(self) -> VerificationError {
        VerificationError::Other(self.to_string())
    }
}

impl<C: Curve> Scheme for Ecdsa<C> {
    type Output = EcdsaSignature<C>;
    type Signer = EcSecretKey<C>;
    type SigningError = EcdsaError;
    type Verifier = EcPublicKey<C>;
    type VerificationError = EcdsaError;
    type Message = [u8];

    fn sign(
        signer: &Self::Signer,
        msg: &Self::Message,
    ) -> Result<Signature<Self>, Self::SigningError>
    where
        Self: Sized,
    {
        let (sig, rec_id) = ecdsa::SigningKey::from(signer.inner.reveal()).sign_recoverable(msg)?;

        Ok(Signature::from_inner(EcdsaSignature {
            inner: sig,
            rec_id: Some(rec_id),
        }))
    }

    fn verify(
        verifier: &Self::Verifier,
        msg: &Self::Message,
        signature: &Signature<Self>,
    ) -> Result<(), Self::VerificationError>
    where
        Self: Sized,
    {
        let verifying_key = ecdsa::VerifyingKey::from(&verifier.0);
        verifying_key.verify(msg, &signature.as_inner().inner)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::ec::SupportedSecretKey;
    use crate::crypto::ec::ecdsa::Ecdsa;
    use crate::crypto::keys::SecretKey;
    use crate::crypto::signature::{SignSigExt, Signature, VerifySigExt};
    use crate::jwk::Jwk;
    use k256::Secp256k1;

    static JWK_WALLET: &'static [u8] =
        include_bytes!("../../../testdata/ar_wallet_tests_ES256K_fixture.json");

    #[test]
    fn jwk_sign_verify() -> Result<(), anyhow::Error> {
        let jwk = Jwk::from_json(JWK_WALLET)?;
        let sk = match SupportedSecretKey::try_from(&jwk) {
            Ok(SupportedSecretKey::Secp256k1(sk)) => sk,
            Err(err) => Err(err)?,
        };
        let pk = sk.public_key_impl();
        //let _addr = pk.digest::<Sha256>().to_base64();
        let message = "HEllO wOrlD".as_bytes();

        let signature: Signature<Ecdsa<Secp256k1>> = sk.sign_sig(message)?;
        pk.verify_sig(message, &signature)?;
        Ok(())
    }
}
