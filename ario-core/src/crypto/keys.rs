use crate::blob::AsBlob;
use crate::crypto::signature;
use crate::crypto::signature::{SignExt, Signature, SupportsSignatures, VerifySigExt};
use crate::hash::{DeepHashable, Hashable};
use crate::typed::Typed;
use generic_array::ArrayLength;
use thiserror::Error;
use crate::RsaError;

pub type TypedSecretKey<T, SK: SecretKey> = Typed<T, SK>;

pub(crate) trait SecretKey {
    type Scheme;
    type KeyLen: ArrayLength;
    type PublicKey: PublicKey<Scheme = Self::Scheme, SecretKey = Self>;

    fn public_key_impl(&self) -> &Self::PublicKey;
}

pub type TypedPublicKey<T, PK: PublicKey> = Typed<T, PK>;

pub(crate) trait PublicKey: Hashable + DeepHashable + AsBlob + PartialEq {
    type Scheme;
    type KeyLen: ArrayLength;
    type SecretKey: SecretKey<Scheme = Self::Scheme, PublicKey = Self>;
}

impl<PK: PublicKey> VerifySigExt<<PK::Scheme as SupportsSignatures>::Scheme> for PK
where
    PK::Scheme: SupportsSignatures<Verifier = PK>,
{
    type VerificationError =
        <<PK::Scheme as SupportsSignatures>::Scheme as signature::Scheme>::VerificationError;

    fn verify_sig_impl(
        &self,
        data: impl AsRef<[u8]>,
        sig: &Signature<<PK::Scheme as SupportsSignatures>::Scheme>,
    ) -> Result<(), Self::VerificationError> {
        <<PK::Scheme as SupportsSignatures>::Scheme as signature::Scheme>::verify(self, data, sig)
    }
}

impl<SK: SecretKey> SignExt<<SK::Scheme as SupportsSignatures>::Scheme> for SK
where
    SK::Scheme: SupportsSignatures<Signer = SK>,
{
    fn sign_impl(
        &self,
        data: impl AsRef<[u8]>,
    ) -> Signature<<SK::Scheme as SupportsSignatures>::Scheme> {
        <<SK::Scheme as SupportsSignatures>::Scheme as signature::Scheme>::sign(self, data)
    }
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("the key does not use the expected Arweave RSA exponent 'AQAB'")]
    IncorrectExponent,
    #[error("expected key length: '{expected}' but found '{actual}'")]
    UnexpectedKeyLength { expected: usize, actual: usize },
    #[error(transparent)]
    RsaError(#[from] RsaError),
}

/*impl<T> TypedSecretKey<T> {
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

type RsaJwkValue = Typed<(), BigUint>;

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
*/

/*
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

impl<T> Display for PublicKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}
*/

/*fn rsa_public_key_to_address<T>(pk: &ExternalRsaPublicKey) -> Address<T> {
    // sha256 hash from bytes representing a big-endian encoded modulus
    Address::from_inner(Sha256Hasher::digest(pk.n_bytes()))
}*/
