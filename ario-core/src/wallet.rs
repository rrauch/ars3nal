use crate::Address;
use crate::blob::{AsBlob, Blob};
use crate::crypto::hash::{Digest, HashableExt, Sha256, Sha256Hash, Sha384Hash};
use crate::crypto::keys;
use crate::crypto::keys::{
    AsymmetricScheme, KeyError, PublicKey, SecretKey, SupportedSecretKey, TypedPublicKey,
    TypedSecretKey,
};
use crate::crypto::rsa::RsaPss;
use crate::crypto::signature::SignExt;
use crate::crypto::signature::VerifySigExt;
use crate::crypto::signature::{Scheme as SignatureScheme, SupportsSignatures};
use crate::json::JsonSource;
use crate::jwk::{Jwk, KeyType};
use crate::tx::{SignedTx, SigningError, TxHash, TxSignature, UnsignedTx};
use crate::typed::FromInner;
use bytemuck::TransparentWrapper;
use thiserror::Error;

pub struct WalletKind;
pub type Wallet<SK: WalletSecretKey> = TypedSecretKey<WalletKind, SK>;
pub type WalletPk<PK: WalletPublicKey> = TypedPublicKey<WalletKind, PK>;

pub trait SupportedSignatureScheme: SignatureScheme {}

impl<const BIT: usize> SupportedSignatureScheme for RsaPss<BIT> where RsaPss<BIT>: SignatureScheme {}

pub(crate) trait WalletSecretKey: SecretKey + SignExt<Self::SigScheme> {
    type SigScheme: SupportedSignatureScheme;
}

impl<SK> WalletSecretKey for SK
where
    SK: SecretKey,
    SK::Scheme: SupportsSignatures<Signer = SK>,
    <SK::Scheme as SupportsSignatures>::Scheme: SupportedSignatureScheme,
{
    type SigScheme = <SK::Scheme as SupportsSignatures>::Scheme;
}

pub(crate) trait WalletPublicKey: PublicKey + VerifySigExt<Self::SigScheme> {
    type SigScheme: SignatureScheme;
}

impl<PK> WalletPublicKey for PK
where
    PK: PublicKey,
    PK::Scheme: SupportsSignatures<Verifier = PK>,
    <PK::Scheme as SupportsSignatures>::Scheme: SupportedSignatureScheme,
{
    type SigScheme = <PK::Scheme as SupportsSignatures>::Scheme;
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

    pub fn public_key(&self) -> &WalletPk<<SK::Scheme as keys::AsymmetricScheme>::PublicKey> {
        WalletPk::wrap_ref(self.public_key_impl())
    }

    pub fn try_from_jwk(jwk: &Jwk) -> Result<Self, WalletKeyPairError> {
        match SupportedSecretKey::try_from(jwk)? {
            SupportedSecretKey::Rsa(rsa_sk) => {
                todo!()
            }
        }
    }
}

impl<S: SignatureScheme + crate::tx::SignatureScheme, SK: WalletSecretKey<SigScheme = S>>
    Wallet<SK>
{
    pub fn sign_tx<'a>(
        &'a self,
        tx: UnsignedTx<'a, S>,
    ) -> Result<SignedTx<'a, S>, (UnsignedTx<'a, S>, SigningError)> {
        todo!()
    }
}

pub type WalletAddress = Address<WalletKind>;

impl<PK: WalletPublicKey> WalletPk<PK> {
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

impl<S: SignatureScheme, PK: WalletPublicKey<SigScheme = S>> WalletPk<PK>
where
    for<'a> S: SignatureScheme<Message<'a> = &'a Digest<Sha256>>,
{
    pub(crate) fn verify_tx(&self, tx_hash: &TxHash, sig: &TxSignature<S>) -> Result<(), String> {
        match tx_hash {
            TxHash::DeepHash(deep_hash) => {
                let tx_hash = deep_hash.digest();
                self.verify_sig_impl(&tx_hash, sig)
            }
            TxHash::Shallow(shallow) => self.verify_sig_impl(shallow, sig),
        }
        .map_err(|e| e.into().to_string())
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
    use crate::crypto::rsa::{Rsa, RsaPrivateKey};
    use crate::jwk::Jwk;
    use crate::wallet::Wallet;

    static AR_WALLET_RSA: &'static [u8] =
        include_bytes!("../testdata/ar_wallet_tests_PS256_65537_fixture.json");

    #[test]
    fn wallet_from_jwk() -> anyhow::Result<()> {
        let wallet = Wallet::<RsaPrivateKey<4096>>::try_from_jwk(&Jwk::from_json(AR_WALLET_RSA)?)?;
        todo!()
    }
}
