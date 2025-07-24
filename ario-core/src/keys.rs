use crate::base64::{Base64Stringify, UrlSafeNoPadding};
use crate::hash::{DeepHashable, Digest, Hasher, HasherExt, Sha256Hasher};
use crate::serde::{AsBytes, Base64SerdeStrategy, FromBytes, StringifySerdeStrategy};
use crate::signature::{Scheme, Signature};
use crate::typed::{FromInner, Typed};
use crate::{Address, BigUint, RsaError};
use bytes::Bytes;
use derive_where::derive_where;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::LazyLock;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

static ARWEAVE_RSA_EXPONENT: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_be_slice_vartime(&[0x01, 0x00, 0x01]));

pub type TypedSecretKey<T> = Typed<T, SecretKey<T>, (), ()>;

#[derive_where(Debug, Clone)]
pub struct SecretKey<T> {
    inner: RsaPrivateKey,
    pkey: TypedPublicKey<T>,
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("the key does not use the expected Arweave RSA exponent 'AQAB'")]
    IncorrectExponent,
    #[error(transparent)]
    RsaError(#[from] RsaError),
}

impl<T> TypedSecretKey<T> {
    pub(crate) fn try_from_components(
        components: RsaPrivateKeyComponents,
    ) -> Result<Self, KeyError> {
        let inner = RsaPrivateKey::from_components(
            components.n,
            components.e,
            components.d,
            components.primes,
        )?;

        // Note: RsaPrivateKey::from_components does NOT zeroize the provided key material on error
        // a PR might be warranted
        // might be related to https://github.com/RustCrypto/RSA/issues/507

        if inner.e() != ARWEAVE_RSA_EXPONENT.deref() {
            return Err(KeyError::IncorrectExponent);
        }

        let pkey = inner.to_public_key();

        Ok(Self::from_inner(SecretKey {
            inner,
            pkey: TypedPublicKey::from_inner(PublicKey::new(pkey).into()),
        }))
    }

    pub(crate) fn public_key_impl(&self) -> &TypedPublicKey<T> {
        &self.pkey
    }
}

#[derive(Zeroize)]
pub struct RsaPrivateKeyComponents {
    n: BigUint,
    e: BigUint,
    d: BigUint,
    primes: Vec<BigUint>,
}

impl RsaPrivateKeyComponents {
    pub fn new(n: BigUint, e: BigUint, d: BigUint, p_q: Option<(BigUint, BigUint)>) -> Self {
        Self {
            n,
            e,
            d,
            primes: p_q.map(|(p, q)| vec![p, q]).unwrap_or_default(),
        }
    }

    pub(crate) fn try_from_jwk(jwk: &[u8]) -> Result<Self, JwkError> {
        let mut jwk: RsaJwk = serde_json::from_slice(jwk)?;
        if !jwk.kty.eq_ignore_ascii_case("RSA") {
            return Err(JwkError::NonRsaKeyType(jwk.kty.to_string()));
        }

        let p_q = if jwk.p.is_some() && jwk.q.is_some() {
            Some((
                jwk.p.take().unwrap().into_inner(),
                jwk.q.take().unwrap().into_inner(),
            ))
        } else {
            None
        };

        Ok(Self::new(
            jwk.n.clone().into_inner(),
            jwk.e.clone().into_inner(),
            jwk.d.clone().into_inner(),
            p_q,
        ))
    }
}

#[derive(Error, Debug)]
pub enum JwkError {
    #[error(transparent)]
    InvalidFieldValue(#[from] JwkFieldValueError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error("expected kty 'RSA' but found '{0}'")]
    NonRsaKeyType(String),
}

#[derive(Error, Debug)]
pub enum JwkFieldValueError {
    #[error("field value length '{found}' exceeds allowed maximum of '{max}'")]
    MaxLengthExceeded { max: usize, found: usize },
    #[error("failed to decode Base64: {0}")]
    Base64DecodingError(String),
}

type RsaJwkValue = Typed<(), BigUint, Base64SerdeStrategy<UrlSafeNoPadding, { 1024 * 10 }>>;

#[derive(Zeroize, ZeroizeOnDrop, Deserialize)]
struct RsaJwk<'a> {
    #[zeroize(skip)]
    kty: &'a str,
    n: RsaJwkValue,
    e: RsaJwkValue,
    d: RsaJwkValue,
    #[serde(default)]
    p: Option<RsaJwkValue>,
    #[serde(default)]
    q: Option<RsaJwkValue>,
}

pub type TypedPublicKey<T> =
    Typed<T, PublicKey<T>, StringifySerdeStrategy, Base64Stringify<UrlSafeNoPadding, { 1024 * 2 }>>;

#[derive_where(Debug, Clone)]
pub struct PublicKey<T> {
    inner: RsaPublicKey,
    address: Address<T>,
    ph: PhantomData<T>,
}

impl<T> PublicKey<T> {
    fn new(inner: RsaPublicKey) -> Self {
        let address = rsa_public_key_to_address(&inner);
        Self {
            inner,
            address,
            ph: PhantomData,
        }
    }

    pub(crate) fn from_modulus(n: impl Into<BigUint>) -> Result<Self, KeyError> {
        let n = n.into();
        let inner = RsaPublicKey::new(n, ARWEAVE_RSA_EXPONENT.clone())?;
        Ok(Self::new(inner))
    }

    pub(crate) fn address_impl(&self) -> &Address<T> {
        &self.address
    }

    pub(crate) fn verify_signature<S: Scheme<Verifier = RsaPublicKey>>(
        &self,
        data: impl AsRef<[u8]>,
        sig: &Signature<S>,
    ) -> Result<(), S::VerificationError> {
        S::verify(&self.inner, data, sig)
    }
}

impl<T> DeepHashable for PublicKey<T> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_bytes().into().deref().deep_hash()
    }
}

impl<T> AsBytes for PublicKey<T> {
    fn as_bytes(&self) -> impl Into<Cow<'_, [u8]>> {
        self.inner.n_bytes().to_vec()
    }
}

impl<T> FromBytes for PublicKey<T> {
    type Error = KeyError;

    fn try_from_bytes(input: Bytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::from_modulus(BigUint::from_be_slice_vartime(input.as_ref()))
    }
}

fn rsa_public_key_to_address<T>(pk: &RsaPublicKey) -> Address<T> {
    // sha256 hash from bytes representing a big-endian encoded modulus
    Address::from_inner(Sha256Hasher::digest(pk.n_bytes()))
}
