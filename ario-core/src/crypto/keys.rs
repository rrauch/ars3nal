use crate::blob::AsBlob;
use crate::crypto::ec::KeyError as EcKeyError;
use crate::crypto::ec::SupportedSecretKey as SupportedEcSecretKey;
use crate::crypto::edwards::eddsa;
use crate::crypto::edwards::eddsa::KeyError as EddsaKeyError;
use crate::crypto::hash::Hashable;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::rsa::KeyError as RsaKeyError;
use crate::crypto::rsa::SupportedPrivateKey as SupportedRsaPrivateKey;
use crate::jwk::{Jwk, KeyType as JwkKeyType};
use crate::typed::Typed;
use hybrid_array::ArraySize;
use hybrid_array::typenum::Unsigned;
use serde::Serialize;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

pub type TypedSecretKey<T, SK: SecretKey> = Typed<T, SK>;

pub enum SupportedSecretKey {
    Rsa(SupportedRsaPrivateKey),
    Ec(SupportedEcSecretKey),
    Eddsa(eddsa::SupportedSigningKey),
}

impl TryFrom<&Jwk> for SupportedSecretKey {
    type Error = KeyError;

    fn try_from(jwk: &Jwk) -> Result<Self, Self::Error> {
        match jwk.key_type() {
            JwkKeyType::Rsa => Ok(Self::from(SupportedRsaPrivateKey::try_from(jwk)?)),
            JwkKeyType::Ec => Ok(Self::from(SupportedEcSecretKey::try_from(jwk)?)),
            JwkKeyType::Okp => Ok(Self::from(eddsa::SupportedSigningKey::try_from(jwk)?)),
            //unsupported => Err(KeyError::UnsupportedKeyType(unsupported)),
        }
    }
}

impl From<SupportedRsaPrivateKey> for SupportedSecretKey {
    fn from(value: SupportedRsaPrivateKey) -> Self {
        Self::Rsa(value)
    }
}

impl From<SupportedEcSecretKey> for SupportedSecretKey {
    fn from(value: SupportedEcSecretKey) -> Self {
        Self::Ec(value)
    }
}

impl From<eddsa::SupportedSigningKey> for SupportedSecretKey {
    fn from(value: eddsa::SupportedSigningKey) -> Self {
        Self::Eddsa(value)
    }
}

pub trait AsymmetricScheme {
    type SecretKey: SecretKey;
    type PublicKey: PublicKey;
}

pub trait SymmetricScheme {
    type SecretKey: SymmetricKey;
}

pub trait KeySize: ArraySize + Send + Sync {
    const SIZE: usize;
}
impl<T> KeySize for T
where
    T: ArraySize + Send + Sync,
{
    const SIZE: usize = <T as Unsigned>::USIZE;
}

pub(crate) trait SymmetricKey {
    type Scheme: SymmetricScheme;
}

pub type TypedSymmetricKey<T, K: SymmetricKey> = Typed<T, K>;

pub(crate) trait SecretKey {
    type Scheme: AsymmetricScheme;

    fn public_key_impl(&self) -> &<Self::Scheme as AsymmetricScheme>::PublicKey;
}

pub type TypedPublicKey<T, PK: PublicKey> = Typed<T, PK>;

pub(crate) trait PublicKey:
    Hashable + DeepHashable + AsBlob + PartialEq + Clone + Debug + Serialize
{
    type Scheme: AsymmetricScheme;
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("unsupported key type: '{0}'")]
    UnsupportedKeyType(KeyType),
    #[error(transparent)]
    RsaError(#[from] RsaKeyError),
    #[error(transparent)]
    EcError(#[from] EcKeyError),
    #[error(transparent)]
    EddsaError(#[from] EddsaKeyError),
    #[error(transparent)]
    Other(anyhow::Error),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Secp256k1,
    Ed25519,
    MultiAptos,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rsa => "RSA",
            Self::Secp256k1 => "Secp256k1",
            Self::Ed25519 => "Ed25519",
            Self::MultiAptos => "MultiAptos",
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::ec::SupportedSecretKey as SupportedEcSecretKey;
    use crate::crypto::edwards::eddsa;
    use crate::crypto::keys::SupportedSecretKey;
    use crate::crypto::rsa::SupportedPrivateKey as SupportedRsaPrivateKey;
    use crate::jwk::Jwk;

    static JWK_RSA_SK: &'static [u8] =
        include_bytes!("../../testdata/ar_wallet_tests_PS256_65537_fixture.json");

    static JWK_EC_SK: &'static [u8] =
        include_bytes!("../../testdata/ar_wallet_tests_ES256K_fixture.json");

    static JWK_ED25519_SK: &'static [u8] =
        include_bytes!("../../testdata/ar_wallet_tests_Ed25519_fixture.json");

    #[test]
    fn jwk_rsa_sk() -> anyhow::Result<()> {
        match SupportedSecretKey::try_from(&(Jwk::from_json(JWK_RSA_SK)?))? {
            SupportedSecretKey::Rsa(SupportedRsaPrivateKey::Rsa4096(_)) => {}
            _ => unreachable!(),
        }
        Ok(())
    }

    #[test]
    fn jwk_ec_sk() -> anyhow::Result<()> {
        match SupportedSecretKey::try_from(&(Jwk::from_json(JWK_EC_SK)?))? {
            SupportedSecretKey::Ec(SupportedEcSecretKey::Secp256k1(_)) => {}
            _ => unreachable!(),
        }
        Ok(())
    }

    #[test]
    fn jwk_ed25519_sk() -> anyhow::Result<()> {
        match SupportedSecretKey::try_from(&(Jwk::from_json(JWK_ED25519_SK)?))? {
            SupportedSecretKey::Eddsa(eddsa::SupportedSigningKey::Ed25519(_)) => {}
            _ => unreachable!(),
        }
        Ok(())
    }
}
