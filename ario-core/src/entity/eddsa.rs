use crate::blob::{AsBlob, Blob};
use crate::crypto::edwards::eddsa::{
    Eddsa, EddsaSignature, EddsaVerifyingKey, KeyError, SupportedCurves,
};
use crate::crypto::edwards::{Ed25519, Ed25519SigningKey, Ed25519VerifyingKey};
use crate::crypto::hash::Sha512;
use crate::crypto::signature::Signature;
use crate::entity::Error::{InvalidKey, InvalidSignature};
use crate::entity::{ArEntityHash, ArEntitySignature, Error, Owner, PrehashFor, SignatureScheme};
use crate::typed::FromInner;
use crate::wallet::WalletPk;

impl SignatureScheme for Ed25519 {
    type Signer = Ed25519SigningKey;
    type Verifier = Ed25519VerifyingKey;
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EddsaSignatureData<T: ArEntityHash> {
    Ed25519 {
        owner: WalletPk<Ed25519VerifyingKey>,
        signature: ArEntitySignature<T, Ed25519>,
    },
}

impl<T: ArEntityHash> Into<EddsaSignatureData<T>>
    for (WalletPk<Ed25519VerifyingKey>, ArEntitySignature<T, Ed25519>)
{
    fn into(self) -> EddsaSignatureData<T> {
        EddsaSignatureData::Ed25519 {
            owner: self.0,
            signature: self.1,
        }
    }
}

impl<T: ArEntityHash> EddsaSignatureData<T>
where
    T: PrehashFor<Sha512>,
{
    pub(crate) fn from_eddsa<C: SupportedCurves>(
        owner: WalletPk<EddsaVerifyingKey<C>>,
        signature: ArEntitySignature<T, Eddsa<C>>,
    ) -> Self
    where
        EddsaVerifyingKey<C>: AsBlob,
        EddsaVerifyingKey<C>: for<'a> TryFrom<Blob<'a>>,
        (
            WalletPk<EddsaVerifyingKey<C>>,
            ArEntitySignature<T, Eddsa<C>>,
        ): Into<EddsaSignatureData<T>>,
    {
        (owner, signature).into()
    }

    pub(crate) fn owner(&self) -> Owner<'_> {
        match self {
            Self::Ed25519 { owner, .. } => Owner::Ed25519(owner.into()),
        }
    }

    pub(crate) fn signature(&self) -> super::Signature<'_, T> {
        match self {
            Self::Ed25519 { signature, .. } => super::Signature::Ed25519(signature.into()),
        }
    }

    pub(crate) fn verify_sig(&self, hash: &T) -> Result<(), Error> {
        match self {
            Self::Ed25519 { owner, signature } => owner
                .verify_entity_hash::<T, Sha512>(hash, signature)
                .map_err(|e| InvalidSignature(e.to_string())),
        }
    }
}

impl<T: ArEntityHash> EddsaSignatureData<T>
where
    T: PrehashFor<Sha512>,
{
    pub(crate) fn from_raw<C: SupportedCurves>(
        raw_signature: Blob,
        raw_public_key: Blob,
    ) -> Result<Self, Error>
    where
        EddsaVerifyingKey<C>: AsBlob,
        EddsaVerifyingKey<C>: for<'a> TryFrom<Blob<'a>, Error = KeyError>,
        (
            WalletPk<EddsaVerifyingKey<C>>,
            ArEntitySignature<T, Eddsa<C>>,
        ): Into<EddsaSignatureData<T>>,
    {
        let signature = EddsaSignature::<C>::try_from(raw_signature)
            .map_err(|e| InvalidSignature(e.to_string()))?;

        let owner =
            EddsaVerifyingKey::try_from(raw_public_key).map_err(|e| InvalidKey(e.into()))?;

        Ok((
            WalletPk::from_inner(owner),
            ArEntitySignature::<T, _>::from_inner(Signature::from_inner(signature)),
        )
            .into())
    }
}
