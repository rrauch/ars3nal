use crate::blob::AsBlob;
use crate::crypto::hash::Hashable;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::rsa::KeyError as RsaKeyError;
use crate::crypto::rsa::SupportedPrivateKey as SupportedRsaPrivateKey;
use crate::crypto::signature;
use crate::crypto::signature::{SignExt, Signature, SupportsSignatures, VerifySigExt};
use crate::jwk::{Jwk, KeyType};
use crate::typed::Typed;
use hybrid_array::ArraySize;
use std::fmt::Debug;
use thiserror::Error;

pub type TypedSecretKey<T, SK: SecretKey> = Typed<T, SK>;

pub enum SupportedSecretKey {
    Rsa(SupportedRsaPrivateKey),
}

impl TryFrom<&Jwk> for SupportedSecretKey {
    type Error = KeyError;

    fn try_from(jwk: &Jwk) -> Result<Self, Self::Error> {
        match jwk.kty {
            KeyType::Rsa => Ok(Self::Rsa(SupportedRsaPrivateKey::try_from(jwk)?)),
            unsupported => Err(KeyError::UnsupportedKeyType(unsupported)),
        }
    }
}

impl From<SupportedRsaPrivateKey> for SupportedSecretKey {
    fn from(value: SupportedRsaPrivateKey) -> Self {
        Self::Rsa(value)
    }
}

pub trait KeyLen: ArraySize + Send + Sync {}
impl<T> KeyLen for T where T: ArraySize + Send + Sync {}

pub(crate) trait SecretKey {
    type Scheme;
    type KeyLen: KeyLen;
    type PublicKey: PublicKey<Scheme = Self::Scheme, SecretKey = Self>;

    fn public_key_impl(&self) -> &Self::PublicKey;
}

pub type TypedPublicKey<T, PK: PublicKey> = Typed<T, PK>;

pub(crate) trait PublicKey:
    Hashable + DeepHashable + AsBlob + PartialEq + Clone + Debug
{
    type Scheme;
    type KeyLen: ArraySize;
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
        data: <<PK::Scheme as SupportsSignatures>::Scheme as signature::Scheme>::Message<'_>,
        sig: &Signature<<PK::Scheme as SupportsSignatures>::Scheme>,
    ) -> Result<(), Self::VerificationError> {
        <<PK::Scheme as SupportsSignatures>::Scheme as signature::Scheme>::verify(self, data, sig)
    }
}

impl<SK: SecretKey> SignExt<<SK::Scheme as SupportsSignatures>::Scheme> for SK
where
    SK::Scheme: SupportsSignatures<Signer = SK>,
{
    type SigningError =
        <<SK::Scheme as SupportsSignatures>::Scheme as signature::Scheme>::SigningError;

    fn sign_impl(
        &self,
        data: <<SK::Scheme as SupportsSignatures>::Scheme as signature::Scheme>::Message<'_>,
    ) -> Result<Signature<<SK::Scheme as SupportsSignatures>::Scheme>, Self::SigningError> {
        <<SK::Scheme as SupportsSignatures>::Scheme as signature::Scheme>::sign(self, data)
    }
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("unsupported key type: '{0}'")]
    UnsupportedKeyType(KeyType),
    #[error(transparent)]
    RsaError(#[from] RsaKeyError),
    #[error(transparent)]
    Other(anyhow::Error),
}

#[cfg(test)]
mod tests {
    use crate::crypto::keys::SupportedSecretKey;
    use crate::crypto::rsa::SupportedPrivateKey as SupportedRsaPrivateKey;
    use crate::jwk::Jwk;

    static JWK_RSA_SK: &'static [u8] =
        include_bytes!("../../testdata/ar_wallet_tests_PS256_65537_fixture.json");

    #[test]
    fn jwk_rsa_sk() -> anyhow::Result<()> {
        match SupportedSecretKey::try_from(&(Jwk::from_json(JWK_RSA_SK)?))? {
            SupportedSecretKey::Rsa(SupportedRsaPrivateKey::Rsa4096(_)) => {}
            _ => unreachable!(),
        }
        Ok(())
    }
}
