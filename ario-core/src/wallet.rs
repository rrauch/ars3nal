use crate::id::Typed256B64Id;
use crate::keys::{JwkError, RsaPrivateKeyComponents, TypedPublicKey, TypedSecretKey};
use crate::{Address, RsaError};
use thiserror::Error;
use zeroize::Zeroize;

pub struct WalletKind;
pub type WalletKeyPair = TypedSecretKey<WalletKind>;

#[derive(Error, Debug)]
pub enum WalletKeyPairError {
    #[error(transparent)]
    RsaError(#[from] RsaError),
    #[error(transparent)]
    JwkError(#[from] JwkError),
}

impl WalletKeyPair {
    pub fn try_from_jwk<'a>(input: impl Into<&'a mut [u8]>) -> Result<Self, WalletKeyPairError> {
        let bytes = input.into();
        let res = RsaPrivateKeyComponents::try_from_jwk(bytes);
        bytes.zeroize();
        Ok(Self::try_from_components(res?)?)
    }
}

pub type WalletPublicKey = TypedPublicKey<WalletKind>;
pub type WalletAddress = Address<WalletKind>;
pub type WalletId = Typed256B64Id<WalletKind>;
