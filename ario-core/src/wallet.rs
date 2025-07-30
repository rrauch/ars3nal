use crate::Address;
use crate::crypto::hash::{Digest, HashableExt, Sha256};
use crate::crypto::keys;
use crate::crypto::keys::{KeyError, PublicKey, SecretKey, TypedPublicKey, TypedSecretKey};
use crate::crypto::rsa::RsaPss;
use crate::crypto::signature::SignExt;
use crate::crypto::signature::VerifySigExt;
use crate::crypto::signature::{Scheme as SignatureScheme, SupportsSignatures};
use crate::tx::{TxHash, TxSignature};
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
}

impl<SK: WalletSecretKey> Wallet<SK> {
    pub fn public_key(&self) -> &WalletPk<<SK::Scheme as keys::AsymmetricScheme>::PublicKey> {
        WalletPk::wrap_ref(self.public_key_impl())
    }
}

pub type WalletAddress = Address<WalletKind>;

impl<PK: WalletPublicKey> WalletPk<PK> {
    pub fn derive_address(&self) -> WalletAddress {
        WalletAddress::from_inner(self.0.digest())
    }
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
