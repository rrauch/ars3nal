use crate::blob::Blob;
use crate::crypto::ec::ecdsa::{Ecdsa, EcdsaSignature};
use crate::crypto::ec::{Curve, EcPublicKey, EcSecretKey};
use crate::crypto::hash::Sha256;
use crate::crypto::signature::Signature;
use crate::entity::Error::InvalidSignature;
use crate::entity::{
    ArEntityHash, ArEntitySignature, Error, Owner, SignatureScheme, ToSignPrehash,
};
use crate::typed::FromInner;
use crate::wallet::WalletPk;
use k256::Secp256k1;

impl SignatureScheme for Ecdsa<Secp256k1> {
    type Signer = EcSecretKey<Secp256k1>;
    type Verifier = EcPublicKey<Secp256k1>;
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EcdsaSignatureData<T: ArEntityHash> {
    Secp256k1 {
        owner: WalletPk<EcPublicKey<Secp256k1>>,
        signature: ArEntitySignature<T, Ecdsa<Secp256k1>>,
    },
}

impl<T: ArEntityHash> Into<EcdsaSignatureData<T>>
    for (
        WalletPk<EcPublicKey<Secp256k1>>,
        ArEntitySignature<T, Ecdsa<Secp256k1>>,
    )
{
    fn into(self) -> EcdsaSignatureData<T> {
        EcdsaSignatureData::Secp256k1 {
            owner: self.0,
            signature: self.1,
        }
    }
}

impl<T: ArEntityHash> EcdsaSignatureData<T>
where
    T: ToSignPrehash<Hasher = Sha256>,
{
    pub(crate) fn from_ecdsa<C: Curve>(
        owner: WalletPk<EcPublicKey<C>>,
        signature: ArEntitySignature<T, Ecdsa<C>>,
    ) -> Self
    where
        (WalletPk<EcPublicKey<C>>, ArEntitySignature<T, Ecdsa<C>>): Into<EcdsaSignatureData<T>>,
    {
        (owner, signature).into()
    }

    pub(crate) fn owner(&self) -> Owner<'_> {
        match self {
            Self::Secp256k1 { owner, .. } => Owner::Secp256k1(owner.into()),
        }
    }

    pub(crate) fn signature(&self) -> super::Signature<'_, T> {
        match self {
            Self::Secp256k1 { signature, .. } => super::Signature::Secp256k1(signature.into()),
        }
    }

    pub(crate) fn verify_sig(&self, hash: &T) -> Result<(), Error> {
        match self {
            Self::Secp256k1 { owner, signature } => owner
                .verify_entity_hash::<T>(hash, signature)
                .map_err(|e| InvalidSignature(e.to_string())),
        }
    }
}

impl<T: ArEntityHash> EcdsaSignatureData<T>
where
    T: ToSignPrehash<Hasher = Sha256>,
{
    pub(crate) fn from_raw(raw_signature: Blob, hash: &T) -> Result<Self, Error> {
        let signature = EcdsaSignature::<Secp256k1>::try_from(raw_signature)
            .map_err(|e| InvalidSignature(e.to_string()))?;
        let prehash = hash.to_sign_prehash();
        let owner = signature
            .recover_verifier(&prehash)
            .map_err(|e| InvalidSignature(e.to_string()))?;
        Ok((
            WalletPk::from_inner(owner),
            ArEntitySignature::<T, _>::from_inner(Signature::from_inner(signature)),
        )
            .into())
    }
}
