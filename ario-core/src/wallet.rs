use crate::keys::{JwkError, RsaPrivateKeyComponents, TypedSecretKey};
use crate::tx::{SignedTx, SigningError, UnsignedTx};
use crate::{Address, RsaError};
use thiserror::Error;
use zeroize::Zeroize;

pub struct WalletKind;
pub type Wallet = TypedSecretKey<WalletKind>;

#[derive(Error, Debug)]
pub enum WalletKeyPairError {
    #[error(transparent)]
    RsaError(#[from] RsaError),
    #[error(transparent)]
    JwkError(#[from] JwkError),
}

impl Wallet {
    pub fn address(&self) -> &WalletAddress {
        self.public_key_impl().address_impl()
    }

    pub fn try_from_jwk<'a>(input: impl Into<&'a mut [u8]>) -> Result<Self, WalletKeyPairError> {
        let bytes = input.into();
        let res = RsaPrivateKeyComponents::try_from_jwk(bytes);
        bytes.zeroize();
        Ok(Self::try_from_components(res?)?)
    }

    pub fn sign_tx(&self, tx: UnsignedTx) -> Result<SignedTx, (UnsignedTx, SigningError)> {
        tx.sign(&self)
    }
}

pub type WalletAddress = Address<WalletKind>;

#[cfg(test)]
mod tests {
    use crate::wallet::Wallet;
    use bytes::{Bytes, BytesMut};

    #[test]
    fn wallet_from_jwk() -> anyhow::Result<()> {
        let bytes = Bytes::from_static(include_bytes!("../testdata/wallet.jwk"));
        let wallet = Wallet::try_from_jwk(BytesMut::from(bytes).as_mut())?;

        let addr = wallet.address();

        assert_eq!(
            "GRQ7swQO1AMyFgnuAPI7AvGQlW3lzuQuwlJbIpWV7xk",
            format!("{}", addr)
        );

        Ok(())
    }
}
