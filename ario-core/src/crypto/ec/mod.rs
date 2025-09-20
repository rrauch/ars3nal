pub mod ecdsa;
pub mod ethereum;

use crate::JsonError;
use crate::base64::{Base64Error, FromBase64};
use crate::blob::{AsBlob, Blob};
use crate::confidential::{Confidential, NewSecretExt, OptionRevealExt, RevealExt, Sensitive};
use crate::crypto::ec::ecdsa::EcdsaError;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher};
use crate::crypto::keys::{AsymmetricScheme, PublicKey, SecretKey};
use crate::jwk::{Jwk, KeyType};
use ::ecdsa::EcdsaCurve;
use ::ecdsa::hazmat::DigestAlgorithm;
use derive_where::derive_where;
use elliptic_curve::SecretKey as ExternalSecretKey;
use elliptic_curve::pkcs8::AssociatedOid;
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
    + AssociatedOid
{
}

impl Curve for Secp256k1 {}

pub struct Ec<C: Curve>(PhantomData<C>);

impl<C: Curve> AsymmetricScheme for Ec<C> {
    type SecretKey = EcSecretKey<C>;
    type PublicKey = EcPublicKey<C>;
}

pub enum SupportedSecretKey {
    Secp256k1(EcSecretKey<Secp256k1>),
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error(transparent)]
    JwkError(#[from] JwkError),
    #[error(transparent)]
    Base64Error(#[from] Base64Error),
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
    #[error("one or more mandatory fields not found")]
    MissingMandatoryFields,
    #[error("provided private key and public key do not match")]
    KeyMismatch,
    #[error("invalid field length: expected '{expected}' but got '{actual}'")]
    InvalidLength { expected: usize, actual: usize },
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
                let (d, x, y) = match (jwk.get("d"), jwk.get("x"), jwk.get("y")) {
                    (Some(d), Some(x), Some(y)) => (d, x, y),
                    _ => return Err(JwkError::MissingMandatoryFields)?,
                };

                let x = x.reveal().try_from_base64()?;
                if x.len() != 32 {
                    return Err(JwkError::InvalidLength {
                        expected: 32,
                        actual: x.len(),
                    })?;
                }
                let y = y.reveal().try_from_base64()?;
                if y.len() != 32 {
                    return Err(JwkError::InvalidLength {
                        expected: 32,
                        actual: y.len(),
                    })?;
                }

                let mut sec1 = [0u8; 65];
                sec1[0] = 0x04;
                sec1[1..=32].copy_from_slice(x.bytes());
                sec1[33..].copy_from_slice(y.bytes());

                let d = d.reveal().try_from_base64()?.sensitive();

                let pk = ExternalPublicKey::<Secp256k1>::from_sec1_bytes(&sec1)
                    .map_err(EcdsaError::EcError)?;
                let sk = ExternalSecretKey::<Secp256k1>::from_slice(d.reveal().bytes())
                    .map_err(EcdsaError::EcError)?
                    .sensitive();

                if sk.reveal().public_key() != pk {
                    return Err(JwkError::KeyMismatch)?;
                }

                Ok(Self::Secp256k1(EcSecretKey {
                    inner: sk,
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
    pub(super) fn from_raw(raw: &[u8]) -> Result<Self, KeyError> {
        let sk = ExternalSecretKey::<Secp256k1>::from_slice(raw)
            .map_err(EcdsaError::EcError)?
            .sensitive();
        let pk = sk.reveal().public_key();

        Ok(Self {
            inner: sk,
            pk: EcPublicKey(pk),
        })
    }

    pub(crate) fn derive_key_from_seed(seed: &Confidential<[u8; 64]>) -> Result<Self, KeyError> {
        let path = "m/44'/60'/0'/0/0"
            .parse::<bip32::DerivationPath>()
            .map_err(|e| KeyError::Other(e.to_string()))?;

        let xprv: bip32::ExtendedPrivateKey<bip32::secp256k1::SecretKey> =
            bip32::ExtendedPrivateKey::derive_from_path(seed.reveal(), &path)
                .map_err(|e| KeyError::Other(e.to_string()))?;

        let sk_bytes = xprv.private_key().to_bytes().to_vec().confidential();
        Self::from_raw(sk_bytes.reveal().as_slice())
    }
}

#[derive_where(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
