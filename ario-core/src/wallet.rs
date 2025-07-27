use crate::Address;
use crate::crypto::keys::{KeyError, PublicKey, SecretKey, TypedPublicKey, TypedSecretKey};
use crate::crypto::rsa::{Rsa2048, Rsa4096, RsaParams, RsaPrivateKey, RsaPss, RsaPublicKey};
use crate::crypto::signature::{Scheme, VerifySigExt};
use crate::hash::HashableExt;
use crate::tx::{SignedTx, SigningError, TxSignature, UnsignedTx};
use crate::typed::FromInner;
use bytemuck::TransparentWrapper;
use thiserror::Error;
use zeroize::Zeroize;

pub struct WalletKind;
pub type Wallet<SK: WalletSecretKey> = TypedSecretKey<WalletKind, SK>;
pub type WalletPKey<PK: WalletPublicKey> = TypedPublicKey<WalletKind, PK>;

pub trait WalletSecretKey: SecretKey {}
impl WalletSecretKey for RsaPrivateKey<Rsa4096> {}
impl WalletSecretKey for RsaPrivateKey<Rsa2048> {}

pub trait WalletPublicKey: PublicKey + VerifySigExt<RsaPss<Self::P>> {
    type P: RsaParams;
}
impl WalletPublicKey for RsaPublicKey<Rsa4096> {
    type P = Rsa4096;
}
impl WalletPublicKey for RsaPublicKey<Rsa2048> {
    type P = Rsa2048;
}

#[derive(Error, Debug)]
pub enum WalletKeyPairError {
    #[error(transparent)]
    KeyError(#[from] KeyError),
    //#[error(transparent)]
    // JwkError(#[from] JwkError),
}

impl<SK: WalletSecretKey> Wallet<SK> {
    //pub fn address(&self) -> &WalletAddress {
    //self.public_key_impl().address_impl()
    //    todo!()
    // }

    pub fn public_key(&self) -> &WalletPKey<SK::PublicKey> {
        WalletPKey::wrap_ref(self.public_key_impl())
    }

    pub fn try_from_jwk<'a>(input: impl Into<&'a mut [u8]>) -> Result<Self, WalletKeyPairError> {
        /*let bytes = input.into();
        let res = RsaPrivateKeyComponents::try_from_jwk(bytes);
        bytes.zeroize();
        Ok(Self::try_from_components(res?)?)*/
        todo!()
    }

    pub fn sign_tx<'a>(
        &'a self,
        tx: UnsignedTx<'a>,
    ) -> Result<SignedTx<'a>, (UnsignedTx<'a>, SigningError)> {
        tx.sign(&self)
    }
}

pub type WalletAddress = Address<WalletKind>;

impl<PK: WalletPublicKey> WalletPKey<PK> {
    pub fn derive_address(&self) -> WalletAddress {
        WalletAddress::from_inner(self.0.digest())
    }

    /*pub fn verify_tx(&self, data: impl AsRef<[u8]>, sig: &TxSignature) -> Result<(), ()> {
        self.verify_sig_impl(data, &sig.0)
    }*/

    /*pub fn verify_tx<S: Scheme<Verifier = PK>>(
        &self,
        data: impl AsRef<[u8]>,
        sig: &TxSignature,
    ) -> Result<(), ()> {
        S::verify(self, data, &sig.0)
    }*/
}

impl<PK: WalletPublicKey<P = Rsa4096>> WalletPKey<PK> {
    pub fn verify_tx(&self, data: impl AsRef<[u8]>, sig: &TxSignature) -> Result<(), String> {
        self.verify_sig_impl(data, &sig.0)
            .map_err(|e| e.to_string())
    }
}

/*impl WalletPKey<RsaPublicKey<Rsa4096>> {
    pub fn verify_tx(
        &self,
        data: impl AsRef<[u8]>,
        sig: &TxSignature,
    ) -> Result<(), rsa::signature::Error> {
        //<Rsa<Rsa4096> as SupportSignatures>::Scheme::verify(&self.0, data, sig)
        self.verify_sig_impl(data, sig)
    }
}*/

#[cfg(test)]
mod tests {
    use crate::wallet::Wallet;
    use bytes::{Bytes, BytesMut};

    #[test]
    fn wallet_from_jwk() -> anyhow::Result<()> {
        let bytes = Bytes::from_static(include_bytes!("../testdata/wallet.jwk"));
        /*let wallet = Wallet::try_from_jwk(BytesMut::from(bytes).as_mut())?;

        let addr = wallet.address();

        assert_eq!(
            "GRQ7swQO1AMyFgnuAPI7AvGQlW3lzuQuwlJbIpWV7xk",
            format!("{}", addr)
        );*/
        todo!();

        Ok(())
    }
}
