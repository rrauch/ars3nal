use crate::base64::{TryFromBase64, TryFromBase64Error};
use crate::blob::Blob;
use crate::crypto::ec::Curve as EcdsaCurve;
use crate::crypto::ec::ecdsa::Ecdsa;
use crate::crypto::hash::{Digest, HashableExt, Sha256, Sha256Hash};
use crate::crypto::keys;
use crate::crypto::keys::{KeyError, PublicKey, SecretKey, TypedPublicKey, TypedSecretKey};
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::signature::SignSigExt;
use crate::crypto::signature::VerifySigExt;
use crate::crypto::signature::{Scheme as SignatureScheme, SupportsSignatures};
use crate::tx::{TxHash, TxSignature};
use crate::typed::FromInner;
use crate::{Address, blob};
use bytemuck::TransparentWrapper;
use std::convert::Infallible;
use std::str::FromStr;
use thiserror::Error;

pub struct WalletKind;
pub type Wallet<SK: WalletSecretKey> = TypedSecretKey<WalletKind, SK>;
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

impl<S: SignatureScheme, SK: WalletSecretKey<SigScheme = S>> Wallet<SK>
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

#[derive(Error, Debug)]
pub enum WalletKeyPairError {
    #[error(transparent)]
    KeyError(#[from] KeyError),
}

impl<SK: WalletSecretKey> Wallet<SK> {
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
