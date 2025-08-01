use crate::JsonError;
use crate::blob::{AsBlob, Blob};
use crate::crypto::Output;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher, Sha256Hash};
use crate::crypto::keys::{AsymmetricScheme, PublicKey, SecretKey};
use crate::crypto::signature::{Scheme, Signature, SigningError, VerificationError};
use crate::jwk::{Jwk, KeyType};
use derive_where::derive_where;
use ecdsa::Signature as ExternalSignature;
use ecdsa::hazmat::DigestAlgorithm;
use ecdsa::{EcdsaCurve, RecoveryId};
use elliptic_curve::SecretKey as ExternalSecretKey;
use elliptic_curve::point::DecompressPoint;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, PublicKey as ExternalPublicKey};
use hybrid_array::ArraySize;
use hybrid_array::typenum::Unsigned;
use k256::Secp256k1;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Add;
use thiserror::Error;
use zeroize::Zeroize;

pub trait Curve: EcdsaCurve + CurveArithmetic {}

impl<C> Curve for C where C: EcdsaCurve + CurveArithmetic {}

pub struct Ecdsa<C: Curve>(PhantomData<C>);

pub trait SupportedEcdsaScheme {
    type Curve: Curve;
}

impl SupportedEcdsaScheme for Ecdsa<Secp256k1> {
    type Curve = Secp256k1;
}

pub enum SupportedSecretKey {
    Secp256k1(EcdsaSecretKey<Secp256k1>),
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error(transparent)]
    JwkError(#[from] JwkError),
    #[error(transparent)]
    EcdsaError(#[from] EcdsaError),
}

#[derive(Error, Debug)]
pub enum JwkError {
    #[error("expected kty 'EC' but found '{0}'")]
    NonEcdsaKeyType(String),
    #[error("curve '{0}' not supported")]
    UnsupportedCurve(String),
    #[error("no 'crv' field in jwk found")]
    MissingCurve,
    #[error(transparent)]
    JsonError(#[from] JsonError),
}

impl TryFrom<&Jwk> for SupportedSecretKey {
    type Error = KeyError;

    fn try_from(jwk: &Jwk) -> Result<Self, Self::Error> {
        if jwk.kty != KeyType::Ec {
            Err(JwkError::NonEcdsaKeyType(jwk.kty.to_string()))?
        }
        match jwk.fields.get("crv").map(|s| s.as_str()) {
            Some("secp256k1") => {
                let mut jwk_str = jwk.to_json_str().map_err(JwkError::from)?;
                let res = ExternalSecretKey::<Secp256k1>::from_jwk_str(&jwk_str);
                jwk_str.zeroize();
                let sk = res.map_err(EcdsaError::from)?;
                let pk = sk.public_key();
                Ok(Self::Secp256k1(EcdsaSecretKey {
                    inner: sk,
                    pk: EcdsaPublicKey(pk),
                }))
            }
            Some(unsupported) => Err(JwkError::UnsupportedCurve(unsupported.to_string()).into()),
            None => Err(JwkError::MissingCurve.into()),
        }
    }
}

#[derive_where(Clone)]
pub struct EcdsaSecretKey<C: Curve> {
    inner: ExternalSecretKey<C>,
    pk: EcdsaPublicKey<C>,
}

impl<C: Curve> SecretKey for EcdsaSecretKey<C>
where
    Ecdsa<C>: SupportedEcdsaScheme,
    EcdsaPublicKey<C>: AsBlob,
{
    type Scheme = Ecdsa<C>;

    fn public_key_impl(&self) -> &<Self::Scheme as AsymmetricScheme>::PublicKey {
        &self.pk
    }
}

#[derive_where(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub struct EcdsaPublicKey<C: Curve>(ExternalPublicKey<C>);

impl<C: Curve> PublicKey for EcdsaPublicKey<C>
where
    Ecdsa<C>: SupportedEcdsaScheme,
    Self: AsBlob,
{
    type Scheme = Ecdsa<C>;
}

impl<C: Curve> Hashable for EcdsaPublicKey<C>
where
    Self: AsBlob,
{
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(self.as_blob())
    }
}

impl<C: Curve> DeepHashable for EcdsaPublicKey<C>
where
    Self: AsBlob,
{
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::blob(self.as_blob().bytes())
    }
}

impl AsBlob for EcdsaPublicKey<Secp256k1> {
    fn as_blob(&self) -> Blob<'_> {
        self.0.to_sec1_bytes().into()
    }
}

impl<C: Curve> AsymmetricScheme for Ecdsa<C>
where
    Self: SupportedEcdsaScheme,
    EcdsaPublicKey<C>: AsBlob,
{
    type SecretKey = EcdsaSecretKey<C>;
    type PublicKey = EcdsaPublicKey<C>;
}

#[derive_where(Clone, Debug, PartialEq)]
pub struct EcdsaSignature<C: Curve>
where
    <<C as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArraySize + Send + Sync,
{
    inner: ExternalSignature<C>,
    rec_id: RecoveryId,
}

impl<C: Curve> AsBlob for EcdsaSignature<C>
where
    <<C as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArraySize + Send + Sync,
{
    fn as_blob(&self) -> Blob<'_> {
        let mut bytes = self.inner.to_vec();
        bytes.push(self.rec_id.to_byte()); // rec_id is stored at the end
        Blob::from(bytes)
    }
}

impl<C: Curve> TryFrom<Blob<'_>> for EcdsaSignature<C>
where
    <<C as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArraySize + Send + Sync,
{
    type Error = EcdsaError;

    fn try_from(value: Blob<'_>) -> Result<Self, Self::Error> {
        let expected =
            <<C as elliptic_curve::Curve>::FieldBytesSize as Add>::Output::to_usize() + 1;
        let bytes = value.bytes();

        if bytes.len() != expected || expected < 2 {
            return Err(EcdsaError::UnexpectedInputLength {
                expected,
                actual: value.len(),
            });
        }

        let (sig_bytes, rec_id) = bytes.split_at(bytes.len() - 1);
        let rec_id = match RecoveryId::from_byte(rec_id[0]) {
            Some(r) => r,
            None => return Err(EcdsaError::InvalidRecoveryId),
        };

        let sig = ExternalSignature::<C>::from_slice(sig_bytes)?;

        Ok(Self { inner: sig, rec_id })
    }
}

impl<C: Curve> Output for EcdsaSignature<C>
where
    <<C as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArraySize + Send + Sync,
{
    type Len = <<C as elliptic_curve::Curve>::FieldBytesSize as Add>::Output;
}

#[derive(Error, Debug)]
pub enum EcdsaError {
    #[error(transparent)]
    ExternalError(#[from] ecdsa::Error),
    #[error(transparent)]
    EcError(#[from] elliptic_curve::Error),
    #[error("unexpected input length: expected: '{expected}', actual: '{actual}'")]
    UnexpectedInputLength { expected: usize, actual: usize },
    #[error("invalid recovery id")]
    InvalidRecoveryId,
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

impl<C: Curve> Scheme for Ecdsa<C>
where
    <<C as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArraySize + Send + Sync,
    <C as elliptic_curve::Curve>::FieldBytesSize: Debug + ModulusSize,
    <C as CurveArithmetic>::AffinePoint:
        DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
    for<'a> EcdsaSignature<C>: TryFrom<Blob<'a>>,
    for<'a> EcdsaPublicKey<C>: From<Blob<'a>>,
    C: DigestAlgorithm,
{
    type Output = EcdsaSignature<C>;
    type Signer = EcdsaSecretKey<C>;
    type SigningError = EcdsaError;
    type Verifier = EcdsaPublicKey<C>;
    type VerificationError = EcdsaError;
    type Message<'a> = &'a Sha256Hash;

    fn sign(
        signer: &Self::Signer,
        msg: Self::Message<'_>,
    ) -> Result<Signature<Self>, Self::SigningError>
    where
        Self: Sized,
    {
        let (sig, rec_id) =
            ecdsa::SigningKey::from(&signer.inner).sign_prehash_recoverable(msg.as_slice())?;

        Ok(Signature::from_inner(EcdsaSignature { inner: sig, rec_id }))
    }

    fn verify(
        verifier: &Self::Verifier,
        msg: Self::Message<'_>,
        signature: &Signature<Self>,
    ) -> Result<(), Self::VerificationError>
    where
        Self: Sized,
    {
        let sig = &signature.as_inner().inner;
        let rec_id = signature.as_inner().rec_id;

        let recovered: elliptic_curve::PublicKey<C> =
            ecdsa::VerifyingKey::recover_from_prehash(msg.as_slice(), sig, rec_id)?.into();

        if &recovered != &verifier.0 {
            return Err(EcdsaError::PublicKeyMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::crypto::ecdsa::SupportedSecretKey;
    use crate::crypto::hash::{HashableExt, Sha256};
    use crate::crypto::keys::SecretKey;
    use crate::jwk::Jwk;

    static JWK_WALLET: &'static [u8] =
        include_bytes!("../../testdata/ar_wallet_tests_ES256K_fixture.json");

    #[test]
    fn jwk() -> Result<(), anyhow::Error> {
        let jwk = Jwk::from_json(JWK_WALLET)?;
        let sk = match SupportedSecretKey::try_from(&jwk) {
            Ok(SupportedSecretKey::Secp256k1(sk)) => sk,
            Err(err) => Err(err)?
        };
        let pk = sk.public_key_impl();
        let _addr = pk.digest::<Sha256>().to_base64();
        Ok(())
    }
}
