use crate::JsonError;
use crate::base64::{Base64Error, FromBase64};
use crate::blob::{AsBlob, Blob};
use crate::confidential::{NewSecretExt, OptionRevealExt, RevealExt, Sensitive};
use crate::crypto::Output;
use crate::crypto::edwards::{Curve, Curve25519};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher, Sha512Hash};
use crate::crypto::keys::{AsymmetricScheme, PublicKey, SecretKey};
use crate::crypto::signature::{Scheme, Signature, SigningError, VerificationError};
use crate::jwk::{Jwk, KeyType};
use derive_where::derive_where;
use ed25519::Signature as Ed25519Signature;
use hybrid_array::typenum::U64;
use std::fmt::Debug;
use std::marker::PhantomData;
use thiserror::Error;

pub struct Eddsa<C: SupportedCurves>(PhantomData<C>);

#[derive(Error, Debug)]
pub enum EddsaError {
    #[error(transparent)]
    KeyError(#[from] KeyError),
    #[error("signature error")]
    SignatureError,
}

impl Into<SigningError> for EddsaError {
    fn into(self) -> SigningError {
        SigningError::Other(self.to_string())
    }
}

impl Into<VerificationError> for EddsaError {
    fn into(self) -> VerificationError {
        VerificationError::Other(self.to_string())
    }
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error(transparent)]
    JwkError(#[from] JwkError),
    #[error(transparent)]
    Base64Error(#[from] Base64Error),
    #[error(transparent)]
    Ed25519Error(#[from] ed25519::Error),
    #[error("invalid key length: expected '{expected}', actual: '{actual}'")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("key error: {0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum JwkError {
    #[error("expected kty 'OKP' but found '{0}'")]
    NonEdwardsKeyType(String),
    #[error("curve '{0}' not supported")]
    UnsupportedCurve(String),
    #[error("no 'crv' field in jwk found")]
    MissingCurve,
    #[error("one or more mandatory fields not found")]
    MissingMandatoryFields,
    #[error("provided signing key and verifying key do not match")]
    KeyMismatch,
    #[error(transparent)]
    JsonError(#[from] JsonError),
}

pub enum SupportedSigningKey {
    Ed25519(EddsaSigningKey<Curve25519>),
}

impl TryFrom<&Jwk> for SupportedSigningKey {
    type Error = KeyError;

    fn try_from(jwk: &Jwk) -> Result<Self, Self::Error> {
        if jwk.key_type() != KeyType::Okp {
            Err(JwkError::NonEdwardsKeyType(jwk.key_type().to_string()))?
        }
        match jwk.get("crv").reveal().map(|s| s.as_str()) {
            Some("Ed25519") | Some("ed25519") => {
                let (d, x) = match (jwk.get("d"), jwk.get("x")) {
                    (Some(d), Some(x)) => (d, x),
                    _ => return Err(JwkError::MissingMandatoryFields)?,
                };
                let x = x.reveal().try_from_base64()?;
                let slice: &[u8; 32] = match x.as_ref().try_into() {
                    Ok(slice) => slice,
                    Err(_) => {
                        return Err(KeyError::InvalidKeyLength {
                            expected: 32,
                            actual: x.len(),
                        });
                    }
                };
                let vk = ed25519_dalek::VerifyingKey::from_bytes(slice)?;

                let d = d.reveal().try_from_base64()?.sensitive();
                let slice: &[u8; 32] = match d.reveal().bytes().try_into() {
                    Ok(slice) => slice,
                    Err(_) => {
                        return Err(KeyError::InvalidKeyLength {
                            expected: 32,
                            actual: x.len(),
                        });
                    }
                };
                let sk = ed25519_dalek::SigningKey::from_bytes(slice).sensitive();
                if sk.reveal().verifying_key() != vk {
                    return Err(JwkError::KeyMismatch)?;
                }
                Ok(Self::Ed25519(EddsaSigningKey::<Curve25519> {
                    inner: sk,
                    pk: EddsaVerifyingKey(vk),
                }))
            }
            Some(unsupported) => Err(JwkError::UnsupportedCurve(unsupported.to_string()).into()),
            None => Err(JwkError::MissingCurve.into()),
        }
    }
}

impl<C: SupportedCurves> AsymmetricScheme for Eddsa<C>
where
    EddsaVerifyingKey<C>: PublicKey,
{
    type SecretKey = EddsaSigningKey<C>;
    type PublicKey = EddsaVerifyingKey<C>;
}

pub trait SupportedCurves: Curve {
    type VerifyingKey: for<'a> CanVerify<Self::Message<'a>, Self::Signature>
        + Clone
        + Send
        + Sync
        + Debug
        + PartialEq;
    type SigningKey: for<'a> CanSign<Self::Message<'a>, Self::Signature> + Clone + Send + Sync;
    type Signature: Clone + Send + Sync + Debug + PartialEq + Output;
    type Message<'a>;
}

#[derive_where(Clone)]
pub struct EddsaSigningKey<C: SupportedCurves>
where
    EddsaVerifyingKey<C>: PublicKey,
{
    inner: Sensitive<C::SigningKey>,
    pk: EddsaVerifyingKey<C>,
}

trait CanSign<M, S> {
    fn sign(&self, msg: M) -> Result<S, SigningError>;
}

impl<'a> CanSign<&'a Sha512Hash, Ed25519Signature> for ed25519_dalek::SigningKey {
    #[inline]
    fn sign(&self, msg: &'a Sha512Hash) -> Result<Ed25519Signature, SigningError> {
        self.sign_prehashed(msg.as_wrapped_digest(), None)
            .map_err(|e| SigningError::Other(e.to_string()))
    }
}

trait CanVerify<M, S> {
    fn verify(&self, msg: M, signature: &S) -> Result<(), VerificationError>;
}

impl<'a> CanVerify<&'a Sha512Hash, Ed25519Signature> for ed25519_dalek::VerifyingKey {
    #[inline]
    fn verify(
        &self,
        msg: &'a Sha512Hash,
        signature: &Ed25519Signature,
    ) -> Result<(), VerificationError> {
        self.verify_prehashed(msg.as_wrapped_digest(), None, signature)
            .map_err(|e| VerificationError::Other(e.to_string()))
    }
}

impl<C: SupportedCurves> EddsaSigningKey<C>
where
    EddsaVerifyingKey<C>: AsBlob,
    EddsaVerifyingKey<C>: for<'a> TryFrom<Blob<'a>>,
{
    #[inline]
    fn sign(&self, msg: C::Message<'_>) -> Result<C::Signature, SigningError> {
        self.inner.reveal().sign(msg)
    }
}

impl<C: SupportedCurves> SecretKey for EddsaSigningKey<C>
where
    EddsaVerifyingKey<C>: PublicKey,
{
    type Scheme = Eddsa<C>;

    fn public_key_impl(&self) -> &<Self::Scheme as AsymmetricScheme>::PublicKey {
        &self.pk
    }
}

#[derive_where(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub struct EddsaVerifyingKey<C: SupportedCurves>(C::VerifyingKey);

impl<C: SupportedCurves> PublicKey for EddsaVerifyingKey<C>
where
    Self: AsBlob,
    Self: for<'a> TryFrom<Blob<'a>>,
{
    type Scheme = Eddsa<C>;
}

impl<C: SupportedCurves> EddsaVerifyingKey<C>
where
    Self: AsBlob,
    Self: for<'a> TryFrom<Blob<'a>>,
{
    #[inline]
    fn verify(
        &self,
        msg: C::Message<'_>,
        signature: &C::Signature,
    ) -> Result<(), VerificationError> {
        self.0.verify(msg, signature)
    }
}

impl<C: SupportedCurves> Hashable for EddsaVerifyingKey<C>
where
    Self: AsBlob,
{
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(self.as_blob())
    }
}

impl<C: SupportedCurves> DeepHashable for EddsaVerifyingKey<C>
where
    Self: AsBlob,
{
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::blob(self.as_blob().bytes())
    }
}

impl AsBlob for EddsaVerifyingKey<Curve25519> {
    fn as_blob(&self) -> Blob<'_> {
        self.0.as_bytes().as_slice().into()
    }
}

impl<'a> TryFrom<Blob<'a>> for EddsaVerifyingKey<Curve25519> {
    type Error = KeyError;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Self(ed25519_dalek::VerifyingKey::try_from(value.bytes())?))
    }
}

impl SupportedCurves for Curve25519 {
    type VerifyingKey = ed25519_dalek::VerifyingKey;
    type SigningKey = ed25519_dalek::SigningKey;
    type Signature = Ed25519Signature;
    type Message<'a> = &'a Sha512Hash;
}

impl AsBlob for Ed25519Signature {
    fn as_blob(&self) -> Blob<'_> {
        self.to_bytes().into()
    }
}

impl<'a> TryFrom<Blob<'a>> for Ed25519Signature {
    type Error = EddsaError;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Self::from_slice(value.bytes()).map_err(|_| EddsaError::SignatureError)?)
    }
}

impl Output for Ed25519Signature {
    type Len = U64;
}

impl<C> Output for EddsaSignature<C>
where
    C: Curve + SupportedCurves,
{
    type Len = <C::Signature as Output>::Len;
}

impl<C> AsBlob for EddsaSignature<C>
where
    C: Curve + SupportedCurves,
{
    fn as_blob(&self) -> Blob<'_> {
        <C::Signature as AsBlob>::as_blob(&self.0)
    }
}

impl<'a, C> TryFrom<Blob<'a>> for EddsaSignature<C>
where
    C: Curve + SupportedCurves,
{
    type Error = EddsaError;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Self(
            <C::Signature as TryFrom<Blob<'a>>>::try_from(value)
                .map_err(|_| EddsaError::SignatureError)?,
        ))
    }
}

#[derive_where(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub struct EddsaSignature<C: Curve + SupportedCurves>(<C as SupportedCurves>::Signature);

impl<C: Curve> Scheme for Eddsa<C>
where
    C: SupportedCurves,
    EddsaVerifyingKey<C>: PublicKey,
    EddsaVerifyingKey<C>: for<'a> TryFrom<Blob<'a>>,
{
    type Output = EddsaSignature<C>;
    type Signer = EddsaSigningKey<C>;
    type SigningError = SigningError;
    type Verifier = EddsaVerifyingKey<C>;
    type VerificationError = VerificationError;
    type Message<'a> = C::Message<'a>;

    fn sign(
        signer: &Self::Signer,
        msg: Self::Message<'_>,
    ) -> Result<Signature<Self>, Self::SigningError>
    where
        Self: Sized,
    {
        Ok(Signature::from_inner(EddsaSignature(signer.sign(msg)?)))
    }

    fn verify(
        verifier: &Self::Verifier,
        msg: Self::Message<'_>,
        signature: &Signature<Self>,
    ) -> Result<(), Self::VerificationError>
    where
        Self: Sized,
    {
        Ok(verifier.verify(msg, &signature.as_inner().0)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::edwards::Ed25519;
    use crate::crypto::edwards::eddsa::SupportedSigningKey;
    use crate::crypto::hash::HashableExt;
    use crate::crypto::keys::SecretKey;
    use crate::crypto::signature::{SignSigExt, Signature, VerifySigExt};
    use crate::jwk::Jwk;

    static JWK_WALLET: &'static [u8] =
        include_bytes!("../../../testdata/ar_wallet_tests_Ed25519_fixture.json");

    #[test]
    fn jwk_sign_verify() -> Result<(), anyhow::Error> {
        let jwk = Jwk::from_json(JWK_WALLET)?;
        let sk = match SupportedSigningKey::try_from(&jwk) {
            Ok(SupportedSigningKey::Ed25519(sk)) => sk,
            Err(err) => Err(err)?,
        };
        let vk = sk.public_key_impl();
        let message = "HEllO wOrlD".as_bytes().digest();

        let signature: Signature<Ed25519> = sk.sign_sig(&message)?;
        vk.verify_sig(&message, &signature)?;
        Ok(())
    }
}
