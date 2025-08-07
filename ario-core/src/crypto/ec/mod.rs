pub mod ecdsa;

use crate::JsonError;
use crate::blob::{AsBlob, Blob};
use crate::confidential::{Confidential, NewSecretExt, OptionRevealExt, RevealExt, Sensitive};
use crate::crypto::ec::ecdsa::{Ecdsa, EcdsaError};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher};
use crate::crypto::keys::{AsymmetricScheme, PublicKey, SecretKey};
use crate::crypto::signature::SupportsSignatures;
use crate::jwk::{Jwk, KeyType};
use ::ecdsa::EcdsaCurve;
use ::ecdsa::hazmat::DigestAlgorithm;
use derive_where::derive_where;
use elliptic_curve::SecretKey as ExternalSecretKey;
use elliptic_curve::point::{DecompressPoint, PointCompression};
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, PublicKey as ExternalPublicKey};
use hybrid_array::ArraySize;
use k256::Secp256k1;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Add;
use thiserror::Error;

pub trait Curve:
    EcdsaCurve
    + CurveArithmetic<
        AffinePoint: DecompressPoint<Self> + FromEncodedPoint<Self> + ToEncodedPoint<Self>,
        FieldBytesSize: Debug + ModulusSize,
    > + PointCompression
    + elliptic_curve::Curve<FieldBytesSize: Add<Output: ArraySize + Send + Sync>>
    + DigestAlgorithm
{
}

impl Curve for Secp256k1 {}

pub struct Ec<C: Curve>(PhantomData<C>);

impl<C: Curve> AsymmetricScheme for Ec<C> {
    type SecretKey = EcSecretKey<C>;
    type PublicKey = EcPublicKey<C>;
}

impl<C: Curve> SupportsSignatures for Ec<C> {
    type Signer = EcSecretKey<C>;
    type Verifier = EcPublicKey<C>;
    type Scheme = Ecdsa<C>;
}

pub enum SupportedSecretKey {
    Secp256k1(EcSecretKey<Secp256k1>),
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error(transparent)]
    JwkError(#[from] JwkError),
    #[error(transparent)]
    EcdsaError(#[from] EcdsaError),
    #[error("key error: {0}")]
    Other(String),
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
        if jwk.key_type() != KeyType::Ec {
            Err(JwkError::NonEcdsaKeyType(jwk.key_type().to_string()))?
        }
        match jwk.get("crv").reveal().map(|s| s.as_str()) {
            Some("secp256k1") => {
                // there doesn't seem to be a better way than turning the jwk struct back into a json string
                // and passing it to `from_jwk_str`. Might warrant a PR.
                let sk = ExternalSecretKey::<Secp256k1>::from_jwk_str(
                    &jwk.to_json_str().map_err(JwkError::from)?.reveal(),
                )
                .map_err(EcdsaError::from)?;
                let pk = sk.public_key();
                Ok(Self::Secp256k1(EcSecretKey {
                    inner: sk.sensitive(),
                    pk: EcPublicKey(pk),
                }))
            }
            Some(unsupported) => Err(JwkError::UnsupportedCurve(unsupported.to_string()).into()),
            None => Err(JwkError::MissingCurve.into()),
        }
    }
}

#[derive_where(Clone)]
pub struct EcSecretKey<C: Curve> {
    inner: Sensitive<ExternalSecretKey<C>>,
    pk: EcPublicKey<C>,
}

impl<C: Curve> SecretKey for EcSecretKey<C> {
    type Scheme = Ec<C>;

    fn public_key_impl(&self) -> &<Self::Scheme as AsymmetricScheme>::PublicKey {
        &self.pk
    }
}

impl EcSecretKey<Secp256k1> {
    pub(crate) fn derive_key_from_seed(seed: &Confidential<[u8; 64]>) -> Result<Self, KeyError> {
        let path = "m/44'/60'/0'/0/0"
            .parse::<bip32::DerivationPath>()
            .map_err(|e| KeyError::Other(e.to_string()))?;

        let xprv: bip32::ExtendedPrivateKey<bip32::secp256k1::SecretKey> =
            bip32::ExtendedPrivateKey::derive_from_path(seed.reveal(), &path)
                .map_err(|e| KeyError::Other(e.to_string()))?;

        let sk_bytes = xprv.private_key().to_bytes().to_vec().confidential();
        let sk = ExternalSecretKey::<Secp256k1>::from_slice(sk_bytes.reveal().as_slice())
            .map_err(EcdsaError::from)?;
        let pk = sk.public_key();

        Ok(Self::from(EcSecretKey {
            inner: sk.sensitive(),
            pk: EcPublicKey(pk),
        }))
    }
}

#[derive_where(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub struct EcPublicKey<C: Curve>(ExternalPublicKey<C>);

impl<C: Curve> PublicKey for EcPublicKey<C> {
    type Scheme = Ec<C>;
}

impl<C: Curve> Hashable for EcPublicKey<C> {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(self.as_blob())
    }
}

impl<C: Curve> DeepHashable for EcPublicKey<C> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::blob(self.as_blob().bytes())
    }
}

impl<C: Curve> AsBlob for EcPublicKey<C> {
    fn as_blob(&self) -> Blob<'_> {
        self.0.to_sec1_bytes().into()
    }
}

impl<'a, C: Curve> TryFrom<Blob<'a>> for EcPublicKey<C> {
    type Error = KeyError;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Self(
            elliptic_curve::PublicKey::from_sec1_bytes(value.as_ref()).map_err(EcdsaError::from)?,
        ))
    }
}
