use crate::blob::Blob;
use crate::crypto::edwards::eddsa::EddsaVerifyingKey;
use crate::crypto::edwards::variants::Ed25519HexStr;
use crate::crypto::edwards::{Ed25519, Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use crate::crypto::hash::{Digest, Hasher, Sha512, Sha512HexStr};
use crate::crypto::signature::{Scheme, Signature};
use crate::entity::Error::{InvalidKey, InvalidSignature};
use crate::entity::{ArEntityHash, ArEntitySignature, Error, Owner, PrehashFor};
use crate::typed::FromInner;
use crate::wallet::WalletPk;
use derive_where::derive_where;

pub type Ed25519RegularSignatureData<T: ArEntityHash> = Ed25519SignatureData<T, Ed25519>;
pub type Ed25519HexStrSignatureData<T: ArEntityHash> = Ed25519SignatureData<T, Ed25519HexStr>;

trait SupportedScheme:
    for<'a> Scheme<
        Signer = Ed25519SigningKey,
        Verifier = Ed25519VerifyingKey,
        Output = Ed25519Signature,
        Message<'a> = &'a Digest<Self::Hasher>,
    > + Sized
{
    type Hasher: Hasher;

    fn signature<T: ArEntityHash>(sig: &ArEntitySignature<T, Self>) -> super::Signature<'_, T>;
}
impl SupportedScheme for Ed25519 {
    type Hasher = Sha512;

    fn signature<T: ArEntityHash>(
        sig: &ArEntitySignature<T, Self>,
    ) -> crate::entity::Signature<'_, T> {
        super::Signature::Ed25519(sig.into())
    }
}
impl SupportedScheme for Ed25519HexStr {
    type Hasher = Sha512HexStr;
    fn signature<T: ArEntityHash>(
        sig: &ArEntitySignature<T, Self>,
    ) -> crate::entity::Signature<'_, T> {
        super::Signature::Ed25519HexStr(sig.into())
    }
}

#[derive_where(Clone, Debug, PartialEq)]
pub(crate) struct Ed25519SignatureData<T: ArEntityHash, S: SupportedScheme> {
    owner: WalletPk<S::Verifier>,
    signature: ArEntitySignature<T, S>,
}

impl<T: ArEntityHash, S: SupportedScheme> Ed25519SignatureData<T, S>
where
    T: PrehashFor<S::Hasher>,
{
    pub fn new(owner: WalletPk<S::Verifier>, signature: ArEntitySignature<T, S>) -> Self {
        Self { owner, signature }
    }

    pub fn from_raw(raw_signature: Blob, raw_public_key: Blob) -> Result<Self, Error> {
        let signature = Ed25519Signature::try_from(raw_signature)
            .map_err(|e| InvalidSignature(e.to_string()))?;

        let owner =
            EddsaVerifyingKey::try_from(raw_public_key).map_err(|e| InvalidKey(e.into()))?;

        Ok(Self::new(
            WalletPk::from_inner(owner),
            ArEntitySignature::<T, _>::from_inner(Signature::from_inner(signature)),
        ))
    }

    pub fn owner(&self) -> Owner<'_> {
        Owner::Ed25519((&self.owner).into())
    }

    pub fn signature(&self) -> super::Signature<'_, T> {
        S::signature(&self.signature)
    }

    pub fn verify_sig(&self, hash: &T) -> Result<(), Error> {
        self.owner
            .verify_entity_hash(hash, &self.signature)
            .map_err(|e| InvalidSignature(e.to_string()))
    }
}
