use crate::base64::{TryFromBase64, TryFromBase64Error};
use crate::blob::Blob;
use crate::crypto::ec::SupportedSecretKey as SupportedEcSecretKey;
use crate::crypto::ec::ecdsa::Ecdsa;
use crate::crypto::ec::{Curve as EcdsaCurve, EcSecretKey};
use crate::crypto::hash::{Digest, HashableExt, Sha256, Sha256Hash};
use crate::crypto::keys;
use crate::crypto::keys::{
    KeyError, PublicKey, SecretKey, SupportedSecretKey, TypedPublicKey, TypedSecretKey,
};
use crate::crypto::rsa::RsaPrivateKey;
use crate::crypto::rsa::SupportedPrivateKey as SupportedRsaPrivateKey;
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::signature::SignSigExt;
use crate::crypto::signature::VerifySigExt;
use crate::crypto::signature::{Scheme as SignatureScheme, SupportsSignatures};
use crate::jwk::Jwk;
use crate::tx::v2::TxDraft;
use crate::tx::{TxError, TxHash, TxSignature, ValidatedTx};
use crate::typed::FromInner;
use crate::{Address, blob};
use bytemuck::TransparentWrapper;
use k256::Secp256k1;
use std::convert::Infallible;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Clone)]
#[repr(transparent)]
pub struct Wallet(Arc<WalletInner>);
impl Wallet {
    pub fn from_jwk(jwk: &Jwk) -> Result<Self, WalletError> {
        let inner = match SupportedSecretKey::try_from(jwk)? {
            SupportedSecretKey::Rsa(SupportedRsaPrivateKey::Rsa4096(rsa)) => {
                WalletInner::Rsa4096(WalletSk::from_inner(rsa.into()))
            }
            SupportedSecretKey::Rsa(SupportedRsaPrivateKey::Rsa2048(rsa)) => {
                WalletInner::Rsa2048(WalletSk::from_inner(rsa.into()))
            }
            SupportedSecretKey::Ec(SupportedEcSecretKey::Secp256k1(k256)) => {
                WalletInner::Secp256k1(WalletSk::from_inner(k256.into()))
            }
        };
        Ok(Self(Arc::new(inner)))
    }

    pub fn address(&self) -> WalletAddress {
        match &self.0.deref() {
            WalletInner::Rsa4096(rsa) => rsa.public_key().derive_address(),
            WalletInner::Rsa2048(rsa) => rsa.public_key().derive_address(),
            WalletInner::Secp256k1(k256) => k256.public_key().derive_address(),
        }
    }

    pub fn sign_tx_draft<'a>(&self, tx_draft: TxDraft<'a>) -> Result<ValidatedTx<'a>, TxError> {
        // v2 only for now
        Ok(match &self.0.deref() {
            WalletInner::Rsa4096(rsa) => tx_draft.sign(rsa)?.into(),
            WalletInner::Rsa2048(rsa) => tx_draft.sign(rsa)?.into(),
            WalletInner::Secp256k1(k256) => tx_draft.sign(k256)?.into(),
        })
    }
}

#[derive(Error, Debug)]
pub enum WalletError {
    #[error(transparent)]
    KeyError(#[from] KeyError),
    #[error("key type cannot be used as a wallet key")]
    UnsupportedKey,
}

enum WalletInner {
    Rsa4096(WalletSk<RsaPrivateKey<4096>>),
    Rsa2048(WalletSk<RsaPrivateKey<2048>>),
    Secp256k1(WalletSk<EcSecretKey<Secp256k1>>),
}

pub struct WalletKind;
pub type WalletSk<SK: WalletSecretKey> = TypedSecretKey<WalletKind, SK>;
pub type WalletPk<PK: WalletPublicKey> = TypedPublicKey<WalletKind, PK>;

pub trait SupportedSignatureScheme: SignatureScheme {}

impl<const BIT: usize> SupportedSignatureScheme for RsaPss<BIT> where Self: SignatureScheme {}
impl<C: EcdsaCurve> SupportedSignatureScheme for Ecdsa<C> where Self: SignatureScheme {}

pub(crate) trait WalletSecretKey: SecretKey + SignSigExt<Self::SigScheme> {
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

impl<S: SignatureScheme, SK: WalletSecretKey<SigScheme = S>> WalletSk<SK>
where
    for<'a> S: SignatureScheme<Message<'a> = &'a Digest<Sha256>>,
{
    pub(crate) fn sign_tx_hash(&self, tx_hash: &TxHash) -> Result<TxSignature<S>, String> {
        let prehash = tx_hash.to_sign_prehash();
        let sig = self.sign_sig(&prehash).map_err(|e| e.into().to_string())?;
        Ok(TxSignature::from_inner(sig))
    }
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

impl<SK: WalletSecretKey> WalletSk<SK> {
    pub fn public_key(&self) -> &WalletPk<<SK::Scheme as keys::AsymmetricScheme>::PublicKey> {
        WalletPk::wrap_ref(self.public_key_impl())
    }
}

pub type WalletAddress = Address<WalletKind>;

#[derive(Error, Debug)]
pub enum WalletAddressError {
    #[error(transparent)]
    Base64Error(#[from] TryFromBase64Error<Infallible>),
    #[error(transparent)]
    BlobError(#[from] blob::Error),
}

impl FromStr for WalletAddress {
    type Err = WalletAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Blob::try_from_base64(s.as_bytes())?;
        Ok(WalletAddress::try_from(bytes)?)
    }
}

impl<PK: WalletPublicKey> WalletPk<PK> {
    pub fn derive_address(&self) -> WalletAddress {
        WalletAddress::from_inner(self.0.digest())
    }
}

impl<S: SignatureScheme, PK: WalletPublicKey<SigScheme = S>> WalletPk<PK>
where
    for<'a> S: SignatureScheme<Message<'a> = &'a Sha256Hash>,
{
    pub(crate) fn verify_tx_hash(
        &self,
        tx_hash: &TxHash,
        sig: &TxSignature<S>,
    ) -> Result<(), String> {
        let prehash = tx_hash.to_sign_prehash();
        self.verify_sig(&prehash, sig)
            .map_err(|e| e.into().to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::jwk::Jwk;
    use crate::tx::{Format, Quantity, Reward, SignatureType, Transfer, TxAnchor, TxBuilder};
    use crate::typed::FromInner;
    use crate::wallet::{Wallet, WalletAddress};
    use std::str::FromStr;

    static WALLET_RSA_JWK: &'static [u8] =
        include_bytes!("../testdata/ar_wallet_tests_PS256_65537_fixture.json");
    static WALLET_EC_JWK: &'static [u8] =
        include_bytes!("../testdata/ar_wallet_tests_ES256K_fixture.json");

    #[test]
    fn wallet_rsa_sign() -> anyhow::Result<()> {
        let wallet = Wallet::from_jwk(&Jwk::from_json(WALLET_RSA_JWK)?)?;

        let target_str = "OK_m2Tk41N94KZLl5WQSx_-iNWbvcp8EMfrYsel_QeQ";

        let draft = TxBuilder::v2()
            .reward(12345)?
            .last_tx(TxAnchor::from_inner([0u8; 48]))
            .transfer(Transfer::new(WalletAddress::from_str(target_str)?, 999999)?)
            .draft();

        let tx = wallet.sign_tx_draft(draft)?;

        assert_eq!(tx.format(), Format::V2);
        assert_eq!(tx.signature().signature_type(), SignatureType::RsaPss);
        assert_eq!(tx.reward(), &Reward::try_from("12345")?);
        assert_eq!(tx.quantity(), Some(&Quantity::try_from("999999")?));
        assert_eq!(tx.target().unwrap().to_base64(), target_str);

        Ok(())
    }

    #[test]
    fn wallet_ec_sign() -> anyhow::Result<()> {
        let wallet = Wallet::from_jwk(&Jwk::from_json(WALLET_EC_JWK)?)?;

        let target_str = "OK_m2Tk41N94KZLl5WQSx_-iNWbvcp8EMfrYsel_QeQ";

        let draft = TxBuilder::v2()
            .reward(22345)?
            .last_tx(TxAnchor::from_inner([0u8; 48]))
            .transfer(Transfer::new(WalletAddress::from_str(target_str)?, 99999)?)
            .draft();

        let tx = wallet.sign_tx_draft(draft)?;

        assert_eq!(tx.format(), Format::V2);
        assert_eq!(tx.signature().signature_type(), SignatureType::EcdsaSecp256k1);
        assert_eq!(tx.reward(), &Reward::try_from("22345")?);
        assert_eq!(tx.quantity(), Some(&Quantity::try_from("099999")?));
        assert_eq!(tx.target().unwrap().to_base64(), target_str);

        Ok(())
    }
}
