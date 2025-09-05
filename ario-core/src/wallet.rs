use crate::base64::{TryFromBase64, TryFromBase64Error};
use crate::blob::Blob;
use crate::confidential::{Confidential, NewSecretExt, OptionRevealExt, RevealExt};
use crate::crypto::ec::EcSecretKey;
use crate::crypto::ec::SupportedSecretKey as SupportedEcSecretKey;
use crate::crypto::edwards::{Ed25519SigningKey, eddsa};
use crate::crypto::hash::{Digest, HashableExt, Hasher};
use crate::crypto::keys;
use crate::crypto::keys::{
    KeyError, PublicKey, SecretKey, SupportedSecretKey, TypedPublicKey, TypedSecretKey,
};
use crate::crypto::rsa::RsaPrivateKey;
use crate::crypto::rsa::SupportedPrivateKey as SupportedRsaPrivateKey;
use crate::crypto::signature::Scheme as SignatureScheme;
use crate::crypto::signature::SignSigExt;
use crate::crypto::signature::VerifySigExt;
use crate::entity::{ArEntityHash, ArEntitySignature, PrehashFor};
use crate::jwk::Jwk;
use crate::tx::v2::TxDraft;
use crate::tx::{TxError, ValidatedTx};
use crate::typed::{FromInner, WithDisplay};
use crate::{Address, blob};
use bip39::Mnemonic;
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
            SupportedSecretKey::Eddsa(eddsa::SupportedSigningKey::Ed25519(ed25519)) => {
                WalletInner::Ed25519(WalletSk::from_inner(ed25519.into()))
            }
        };
        Ok(Self(Arc::new(inner)))
    }

    pub fn from_mnemonic(
        m: &Confidential<String>,
        passphrase: Option<&Confidential<String>>,
        key_type: KeyType,
    ) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::parse_normalized(m.reveal().as_str())
            .map_err(MnemonicError::Bip39Error)?
            .confidential();

        let word_count = mnemonic.reveal().word_count();
        if ![12, 18, 24].contains(&word_count) {
            return Err(MnemonicError::UnsupportedWordCount(word_count))?;
        }

        let seed = mnemonic
            .reveal()
            .to_seed_normalized(passphrase.reveal().map(|s| s.as_str()).unwrap_or(""))
            .confidential();

        let inner = match key_type {
            KeyType::Rsa => WalletInner::Rsa4096(WalletSk::from_inner(
                RsaPrivateKey::derive_key_from_seed(&seed).map_err(KeyError::RsaError)?,
            )),
            KeyType::Secp256k1 => WalletInner::Secp256k1(WalletSk::from_inner(
                EcSecretKey::derive_key_from_seed(&seed).map_err(KeyError::EcError)?,
            )),
            KeyType::Ed25519 => {
                todo!()
            }
        };

        Ok(Self(Arc::new(inner)))
    }

    pub fn address(&self) -> WalletAddress {
        match &self.0.deref() {
            WalletInner::Rsa4096(rsa) => rsa.public_key().derive_address(),
            WalletInner::Rsa2048(rsa) => rsa.public_key().derive_address(),
            WalletInner::Secp256k1(k256) => k256.public_key().derive_address(),
            WalletInner::Ed25519(ed25519) => ed25519.public_key().derive_address(),
        }
    }

    pub fn sign_tx_draft<'a>(&self, tx_draft: TxDraft<'a>) -> Result<ValidatedTx<'a>, TxError> {
        // v2 only for now
        Ok(match &self.0.deref() {
            WalletInner::Rsa4096(rsa) => tx_draft.sign(rsa)?.into(),
            WalletInner::Rsa2048(_) => {
                return Err(TxError::UnsupportedKeyType("Rsa2048".to_string()));
            }
            WalletInner::Secp256k1(k256) => tx_draft.sign(k256)?.into(),
            WalletInner::Ed25519(_) => {
                return Err(TxError::UnsupportedKeyType("Ed25519".to_string()));
            }
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Secp256k1,
    Ed25519,
}

#[derive(Error, Debug)]
pub enum WalletError {
    #[error(transparent)]
    KeyError(#[from] KeyError),
    #[error("key type cannot be used as a wallet key")]
    UnsupportedKey,
    #[error(transparent)]
    MnemonicError(#[from] MnemonicError),
}

#[derive(Error, Debug)]
pub enum MnemonicError {
    #[error(transparent)]
    Bip39Error(#[from] bip39::Error),
    #[error("mnemonic word count '{0}' not supported")]
    UnsupportedWordCount(usize),
}

enum WalletInner {
    Rsa4096(WalletSk<RsaPrivateKey<4096>>),
    Rsa2048(WalletSk<RsaPrivateKey<2048>>),
    Secp256k1(WalletSk<EcSecretKey<Secp256k1>>),
    Ed25519(WalletSk<Ed25519SigningKey>),
}

pub struct WalletKind;
pub type WalletSk<SK: SecretKey> = TypedSecretKey<WalletKind, SK>;
pub type WalletPk<PK: PublicKey> = TypedPublicKey<WalletKind, PK>;

impl<SK: SecretKey> WalletSk<SK> {
    pub(crate) fn sign_entity_hash<S: SignatureScheme, T: ArEntityHash, H: Hasher>(
        &self,
        entity_hash: &T,
    ) -> Result<ArEntitySignature<T, S>, String>
    where
        SK: SignSigExt<S>,
        T: PrehashFor<H>,
        S: SignatureScheme<Message = Digest<H>>,
    {
        let prehash = entity_hash.to_sign_prehash();
        let sig = self.sign_sig(&prehash).map_err(|e| e.into().to_string())?;
        Ok(ArEntitySignature::from_inner(sig))
    }
}

impl<SK: SecretKey> WalletSk<SK> {
    pub fn public_key(&self) -> &WalletPk<<SK::Scheme as keys::AsymmetricScheme>::PublicKey> {
        WalletPk::wrap_ref(self.public_key_impl())
    }
}

pub type WalletAddress = Address<WalletKind>;

impl WithDisplay for WalletAddress {}

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

impl<PK: PublicKey> WalletPk<PK> {
    pub fn derive_address(&self) -> WalletAddress {
        WalletAddress::from_inner(self.0.digest())
    }
}

impl<PK: PublicKey> WalletPk<PK> {
    pub(crate) fn verify_entity_hash<S: SignatureScheme, T: ArEntityHash, H: Hasher>(
        &self,
        hash: &T,
        sig: &ArEntitySignature<T, S>,
    ) -> Result<(), String>
    where
        PK: VerifySigExt<S>,
        T: PrehashFor<H>,
        S: SignatureScheme<Message = Digest<H>>,
    {
        let prehash = hash.to_sign_prehash();
        self.verify_sig(&prehash, sig)
            .map_err(|e| e.into().to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::confidential::NewSecretExt;
    use crate::jwk::Jwk;
    use crate::tx::{Format, Quantity, Reward, SignatureType, Transfer, TxAnchor, TxBuilder};
    use crate::typed::FromInner;
    use crate::wallet::{KeyType, Wallet, WalletAddress};
    use std::str::FromStr;

    static WALLET_RSA_JWK: &'static [u8] =
        include_bytes!("../testdata/ar_wallet_tests_PS256_65537_fixture.json");
    static WALLET_EC_JWK: &'static [u8] =
        include_bytes!("../testdata/ar_wallet_tests_ES256K_fixture.json");

    static SEED_PHRASE_1: &'static str =
        "struggle swim faith addict eternal pass word shock trim west vanish together";
    static SEED_PHRASE_2: &'static str = "never marriage knife silver space kite voice phrase castle embody always lens quantum pulp great title girl cloth honey gauge very before ice walnut";

    #[test]
    fn wallet_rsa_sign() -> anyhow::Result<()> {
        let wallet = Wallet::from_jwk(&Jwk::from_json(WALLET_RSA_JWK)?)?;

        let target_str = "OK_m2Tk41N94KZLl5WQSx_-iNWbvcp8EMfrYsel_QeQ";

        let draft = TxBuilder::v2()
            .reward(12345)?
            .tx_anchor(TxAnchor::from_inner([0u8; 48]))
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
            .tx_anchor(TxAnchor::from_inner([0u8; 48]))
            .transfer(Transfer::new(WalletAddress::from_str(target_str)?, 99999)?)
            .draft();

        let tx = wallet.sign_tx_draft(draft)?;

        assert_eq!(tx.format(), Format::V2);
        assert_eq!(
            tx.signature().signature_type(),
            SignatureType::EcdsaSecp256k1
        );
        assert_eq!(tx.reward(), &Reward::try_from("22345")?);
        assert_eq!(tx.quantity(), Some(&Quantity::try_from("099999")?));
        assert_eq!(tx.target().unwrap().to_base64(), target_str);

        Ok(())
    }

    // RSA key generation is VERY slow. Only activate if you need to test this.
    #[ignore]
    #[test]
    fn mnemonic_rsa_deterministic() -> anyhow::Result<()> {
        for mnemonic in [
            SEED_PHRASE_1.to_string().confidential(),
            SEED_PHRASE_2.to_string().confidential(),
        ] {
            let mut previous: Option<Wallet> = None;
            for _ in 0..3 {
                let wallet = Wallet::from_mnemonic(&mnemonic, None, KeyType::Rsa)?;
                if let Some(prev) = previous {
                    assert_eq!(wallet.address().to_base64(), prev.address().to_string());
                }
                previous = Some(wallet);
            }
        }
        Ok(())
    }

    #[test]
    fn mnemonic_k256_deterministic() -> anyhow::Result<()> {
        for mnemonic in [
            SEED_PHRASE_1.to_string().confidential(),
            SEED_PHRASE_2.to_string().confidential(),
        ] {
            let mut previous: Option<Wallet> = None;
            for _ in 0..3 {
                let wallet = Wallet::from_mnemonic(&mnemonic, None, KeyType::Secp256k1)?;
                if let Some(prev) = previous {
                    assert_eq!(wallet.address().to_base64(), prev.address().to_string());
                }
                previous = Some(wallet);
            }
        }
        Ok(())
    }
}
