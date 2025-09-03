pub mod pss;

use crate::base64::{Base64Error, FromBase64};
use crate::blob::{AsBlob, Blob};
use crate::confidential::{Confidential, NewSecretExt, OptionRevealExt, RevealExt, RevealMutExt};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher, Sha256};
use crate::crypto::keys::{AsymmetricScheme, KeySize, PublicKey, SecretKey};
use crate::jwk::{Jwk, KeyType};
use crate::{BigUint, RsaError};
use bytemuck::TransparentWrapper;
use digest::consts::{U256, U512};
use hkdf::Hkdf;
use rand_chacha::ChaCha20Rng;
use rsa::rand_core::SeedableRng;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey as ExternalRsaPrivateKey, RsaPublicKey as ExternalRsaPublicKey};
use std::ops::Deref;
use std::sync::LazyLock;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

static RSA_EXPONENT: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_be_slice_vartime(&[0x01, 0x00, 0x01])); // 65537

pub struct Rsa<const BIT: usize>;

pub trait SupportedRsaKeySize {
    type KeySize: KeySize;
}

impl SupportedRsaKeySize for Rsa<4096> {
    type KeySize = U512;
}

impl SupportedRsaKeySize for Rsa<2048> {
    type KeySize = U256;
}

impl<const BIT: usize> AsymmetricScheme for Rsa<BIT>
where
    Self: SupportedRsaKeySize,
{
    type SecretKey = RsaPrivateKey<BIT>;
    type PublicKey = RsaPublicKey<BIT>;
}

pub enum SupportedPrivateKey {
    Rsa4096(RsaPrivateKey<4096>),
    Rsa2048(RsaPrivateKey<2048>),
}

#[derive(Clone, TransparentWrapper)]
#[repr(transparent)]
pub struct RsaPrivateKey<const BIT: usize>(ExternalRsaPrivateKey);

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("the key does not use the expected Arweave RSA exponent")]
    IncorrectExponent,
    #[error("expected key size: '{expected}' but found '{actual}'")]
    UnexpectedKeySize { expected: usize, actual: usize },
    #[error("unsupported key size: '{0}'")]
    UnsupportedKeySize(usize),
    #[error(transparent)]
    RsaError(#[from] RsaError),
    #[error(transparent)]
    JwkError(#[from] JwkError),
    #[error("key error: {0}")]
    Other(String),
}

impl<const BIT: usize> RsaPrivateKey<BIT>
where
    Rsa<BIT>: SupportedRsaKeySize,
{
    pub(crate) fn derive_key_from_seed(seed: &Confidential<[u8; 64]>) -> Result<Self, KeyError> {
        let hk = Hkdf::<Sha256>::new(None, seed.reveal());
        let mut rng_seed = [0u8; 32];
        hk.expand(b"arweave-rsa-private-key-v1", &mut rng_seed)
            .map_err(|e| KeyError::Other(e.to_string()))?;

        // Create seeded RNG
        let mut rng = ChaCha20Rng::from_seed(rng_seed).sensitive();

        Self::try_from_inner(ExternalRsaPrivateKey::new_with_exp(
            rng.reveal_mut(),
            BIT,
            RSA_EXPONENT.clone(),
        )?)
    }
}

impl<const BIT: usize> RsaPrivateKey<BIT> {
    const EXPECTED_BYTES: usize = (BIT + 7) / 8;

    pub(crate) fn try_from_inner(inner: ExternalRsaPrivateKey) -> Result<Self, KeyError> {
        if inner.size() != Self::EXPECTED_BYTES {
            return Err(KeyError::UnexpectedKeySize {
                expected: Self::EXPECTED_BYTES,
                actual: inner.size(),
            });
        }
        if inner.e() != RSA_EXPONENT.deref() {
            return Err(KeyError::IncorrectExponent);
        }
        Ok(Self(inner))
    }
    pub(crate) fn as_inner(&self) -> &ExternalRsaPrivateKey {
        &self.0
    }
}

impl<const BIT: usize> SecretKey for RsaPrivateKey<BIT>
where
    Rsa<BIT>: SupportedRsaKeySize,
{
    type Scheme = Rsa<BIT>;

    fn public_key_impl(&self) -> &<Self::Scheme as AsymmetricScheme>::PublicKey {
        RsaPublicKey::wrap_ref(self.0.as_ref())
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct RsaPrivateKeyComponents(Confidential<RsaPrivateKeyComponentsInner>);

#[derive(Zeroize)]
struct RsaPrivateKeyComponentsInner {
    n: BigUint,
    e: BigUint,
    d: BigUint,
    primes: Vec<BigUint>,
}

impl TryFrom<&Jwk> for SupportedPrivateKey {
    type Error = KeyError;

    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        Ok(RsaPrivateKeyComponents::from_jwk(value)?.try_into()?)
    }
}

impl TryFrom<RsaPrivateKeyComponents> for SupportedPrivateKey {
    type Error = KeyError;

    fn try_from(value: RsaPrivateKeyComponents) -> Result<Self, Self::Error> {
        let value = value.0.reveal();
        // Note: ExternalRsaPrivateKey::from_components does NOT zeroize the provided key material on error
        // a PR might be warranted
        // might be related to https://github.com/RustCrypto/RSA/issues/507
        ExternalRsaPrivateKey::from_components(
            value.n.clone(),
            value.e.clone(),
            value.d.clone(),
            value.primes.clone(),
        )?
        .try_into()
    }
}

impl TryFrom<ExternalRsaPrivateKey> for SupportedPrivateKey {
    type Error = KeyError;

    fn try_from(sk: ExternalRsaPrivateKey) -> Result<Self, Self::Error> {
        Ok(match sk.size() {
            512 => SupportedPrivateKey::Rsa4096(RsaPrivateKey::try_from_inner(sk)?),
            256 => SupportedPrivateKey::Rsa2048(RsaPrivateKey::try_from_inner(sk)?),
            unsupported => return Err(KeyError::UnsupportedKeySize(unsupported)),
        })
    }
}

#[derive(Error, Debug)]
pub enum JwkError {
    #[error(transparent)]
    InvalidFieldValue(#[from] JwkFieldValueError),
    #[error("expected kty 'RSA' but found '{0}'")]
    NonRsaKeyType(String),
    #[error("one or more mandatory fields not found")]
    MissingMandatoryFields,
}

#[derive(Error, Debug)]
pub enum JwkFieldValueError {
    #[error("field value length '{found}' exceeds allowed maximum of '{max}'")]
    MaxLengthExceeded { max: usize, found: usize },
    #[error(transparent)]
    Base64Error(#[from] Base64Error),
}

impl RsaPrivateKeyComponents {
    pub fn new(n: BigUint, e: BigUint, d: BigUint, p_q: Option<(BigUint, BigUint)>) -> Self {
        Self(
            RsaPrivateKeyComponentsInner {
                n,
                e,
                d,
                primes: p_q.map(|(p, q)| vec![p, q]).unwrap_or_default(),
            }
            .confidential(),
        )
    }

    pub(crate) fn from_jwk(jwk: &Jwk) -> Result<Self, JwkError> {
        if jwk.key_type() != KeyType::Rsa {
            return Err(JwkError::NonRsaKeyType(jwk.key_type().to_string()));
        }

        fn try_to_big_uint<S: AsRef<str>>(value: S) -> Result<BigUint, JwkError> {
            Ok(BigUint::from_be_slice_vartime(
                value
                    .as_ref()
                    .try_from_base64()
                    .map_err(JwkFieldValueError::from)?
                    .sensitive()
                    .reveal()
                    .bytes(),
            ))
        }

        let p_q = match (jwk.get("p").reveal(), jwk.get("q").reveal()) {
            (Some(p), Some(q)) => Some((try_to_big_uint(p)?, try_to_big_uint(q)?)),
            _ => None,
        };

        match (
            jwk.get("n").reveal(),
            jwk.get("e").reveal(),
            jwk.get("d").reveal(),
        ) {
            (Some(n), Some(e), Some(d)) => Ok(Self::new(
                try_to_big_uint(n)?,
                try_to_big_uint(e)?,
                try_to_big_uint(d)?,
                p_q,
            )),
            _ => Err(JwkError::MissingMandatoryFields),
        }
    }
}

#[derive(Clone, Debug, PartialEq, TransparentWrapper)]
#[transparent(ExternalRsaPublicKey)]
#[repr(transparent)]
pub struct RsaPublicKey<const BIT: usize>(ExternalRsaPublicKey);

impl<const BIT: usize> RsaPublicKey<BIT> {
    const EXPECTED_BYTES: usize = (BIT + 7) / 8;

    pub(crate) fn try_from_inner(inner: ExternalRsaPublicKey) -> Result<Self, KeyError> {
        if inner.size() != Self::EXPECTED_BYTES {
            return Err(KeyError::UnexpectedKeySize {
                expected: Self::EXPECTED_BYTES,
                actual: inner.size(),
            });
        }
        Ok(Self(inner))
    }

    pub(crate) fn from_modulus(n: impl Into<BigUint>) -> Result<Self, KeyError> {
        let n = n.into();
        let inner = ExternalRsaPublicKey::new(n, RSA_EXPONENT.clone())?;
        Self::try_from_inner(inner)
    }

    pub(crate) fn as_inner(&self) -> &ExternalRsaPublicKey {
        &self.0
    }
}

impl<const BIT: usize> PublicKey for RsaPublicKey<BIT>
where
    Rsa<BIT>: SupportedRsaKeySize,
{
    type Scheme = Rsa<BIT>;
}

impl<const BIT: usize> Hashable for RsaPublicKey<BIT> {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(self.0.n_bytes().as_ref());
    }
}

impl<const BIT: usize> DeepHashable for RsaPublicKey<BIT> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::blob(self.0.n_bytes().as_ref())
    }
}

impl<const BIT: usize> AsBlob for RsaPublicKey<BIT> {
    fn as_blob(&self) -> Blob<'_> {
        Blob::from(self.0.n_bytes())
    }
}

impl<'a, const BIT: usize> TryFrom<Blob<'a>> for RsaPublicKey<BIT> {
    type Error = KeyError;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        let expected: usize = (BIT + 7) / 8;
        let size = value.len();

        if size != expected {
            return Err(Self::Error::UnexpectedKeySize {
                expected,
                actual: size,
            });
        }
        Ok(RsaPublicKey::from_modulus(BigUint::from_be_slice_vartime(
            value.as_ref(),
        ))?)
    }
}
