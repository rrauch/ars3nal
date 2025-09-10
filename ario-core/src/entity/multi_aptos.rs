use crate::blob::Blob;
use crate::crypto::edwards::multi_aptos::{
    MultiAptosEd25519, MultiAptosSignature, MultiAptosVerifyingKey,
};
use crate::crypto::signature::{Scheme, Signature};
use crate::entity::Error::{InvalidKey, InvalidSignature};
use crate::entity::{ArEntityHash, ArEntitySignature, Error, MessageFor, Owner};
use crate::typed::FromInner;
use crate::wallet::{WalletPk, WalletSk};
use derive_where::derive_where;

#[derive_where(Clone, Debug, PartialEq)]
pub(crate) struct MultiAptosSignatureData<T: ArEntityHash> {
    owner: WalletPk<<MultiAptosEd25519 as Scheme>::Verifier>,
    signature: ArEntitySignature<T, MultiAptosEd25519>,
}

impl<T: ArEntityHash> MultiAptosSignatureData<T>
where
    T: MessageFor<MultiAptosEd25519>,
{
    pub fn new(
        owner: WalletPk<<MultiAptosEd25519 as Scheme>::Verifier>,
        signature: ArEntitySignature<T, MultiAptosEd25519>,
    ) -> Self {
        Self { owner, signature }
    }

    pub fn from_raw(raw_signature: Blob, raw_public_key: Blob) -> Result<Self, Error> {
        let signature = MultiAptosSignature::try_from(raw_signature)
            .map_err(|e| InvalidSignature(e.to_string()))?;

        let owner =
            MultiAptosVerifyingKey::try_from(raw_public_key).map_err(|e| InvalidKey(e.into()))?;

        Ok(Self::new(
            WalletPk::from_inner(owner),
            ArEntitySignature::<T, _>::from_inner(Signature::from_inner(signature)),
        ))
    }

    pub fn owner(&self) -> Owner<'_> {
        Owner::MultiAptos((&self.owner).into())
    }

    pub fn signature(&self) -> super::Signature<'_, T> {
        super::Signature::MultiAptos((&self.signature).into())
    }

    pub fn verify_sig(&self, hash: &T) -> Result<(), Error> {
        self.owner
            .verify_entity_hash(hash, &self.signature)
            .map_err(|e| InvalidSignature(e.to_string()))
    }

    pub(crate) fn sign(
        hash: &T,
        signer: &WalletSk<<MultiAptosEd25519 as Scheme>::Signer>,
    ) -> Result<Self, Error> {
        Ok(Self {
            owner: signer.public_key().clone(),
            signature: signer.sign_entity_hash(hash).map_err(Error::SigningError)?,
        })
    }
}
