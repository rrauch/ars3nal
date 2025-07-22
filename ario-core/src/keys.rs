use crate::base64::UrlSafeNoPadding;
use crate::hash::{HasherExt, Sha256Hasher};
use crate::serde::Base64SerdeStrategy;
use crate::typed::{FromInner, Typed};
use crate::{Address, BigUint, RsaError};
use derive_where::derive_where;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use std::marker::PhantomData;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type TypedSecretKey<T> = Typed<T, SecretKeyInner<T>, (), ()>;

#[derive_where(Debug, Clone)]
pub struct SecretKeyInner<T> {
    inner: RsaPrivateKey,
    pkey: TypedPublicKey<T>,
}

impl<T> TypedSecretKey<T> {
    pub(crate) fn try_from_components(
        components: RsaPrivateKeyComponents,
    ) -> Result<Self, RsaError> {
        let inner = RsaPrivateKey::from_components(
            components.n,
            components.e,
            components.d,
            components.primes,
        )?;

        // todo: RsaPrivateKey::from_components does NOT zeroize the provided key material on error
        // a PR might be warranted

        let pkey = inner.to_public_key();

        Ok(Self::from_inner(SecretKeyInner {
            inner,
            pkey: TypedPublicKey::new(pkey),
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

pub type TypedPublicKey<T> = Typed<T, PublicKeyInner<T>>;

#[derive_where(Debug, Clone)]
pub struct PublicKeyInner<T> {
    inner: RsaPublicKey,
    address: Address<T>,
    ph: PhantomData<T>,
}

impl<T> TypedPublicKey<T> {
    fn new(inner: RsaPublicKey) -> Self {
        let address = rsa_public_key_to_address(&inner);
        Self::from_inner(PublicKeyInner {
            inner,
            address,
            ph: PhantomData,
        })
    }

    pub(crate) fn address_impl(&self) -> &Address<T> {
        &self.address
    }
}

fn rsa_public_key_to_address<T>(pk: &RsaPublicKey) -> Address<T> {
    // sha256 hash from bytes representing a big-endian encoded modulus
    Address::from_inner(Sha256Hasher::digest(pk.n_bytes()))
}
