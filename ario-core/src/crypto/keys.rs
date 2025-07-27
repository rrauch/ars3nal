use crate::blob::AsBlob;
use crate::crypto::hash::Hashable;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::rsa::KeyError as RsaKeyError;
use crate::crypto::signature;
use crate::crypto::signature::{SignExt, Signature, SupportsSignatures, VerifySigExt};
use crate::typed::Typed;
use hybrid_array::ArraySize;
use thiserror::Error;

pub type TypedSecretKey<T, SK: SecretKey> = Typed<T, SK>;

pub trait KeyLen: ArraySize {}
impl<T> KeyLen for T where T: ArraySize {}

pub(crate) trait SecretKey {
    type Scheme;
    type KeyLen: KeyLen;
    type PublicKey: PublicKey<Scheme = Self::Scheme, SecretKey = Self>;

    fn public_key_impl(&self) -> &Self::PublicKey;
}

pub type TypedPublicKey<T, PK: PublicKey> = Typed<T, PK>;

pub(crate) trait PublicKey: Hashable + DeepHashable + AsBlob + PartialEq {
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
    #[error("unsupported key type")]
    UnsupportedKeyType,
    #[error(transparent)]
    RsaError(#[from] RsaKeyError),
}
