use crate::blob::Blob;
use crate::crypto::ec::ecdsa::{Ecdsa, EcdsaSignature};
use crate::crypto::ec::{Curve, EcPublicKey, EcSecretKey};
use crate::crypto::signature::{Scheme, Signature};
use crate::entity::Error::{InvalidKey, InvalidSignature};
use crate::entity::{ArEntityHash, ArEntitySignature, Error, MessageFor, Owner};
use crate::typed::FromInner;
use crate::wallet::WalletPk;
use derive_where::derive_where;
use k256::Secp256k1;

pub type Secp256k1SignatureData<T: ArEntityHash> = EcdsaSignatureData<T, Secp256k1>;

trait SupportedCurve: Curve {}
impl SupportedCurve for Secp256k1 {}

#[derive_where(Clone, Debug, PartialEq)]
pub(crate) struct EcdsaSignatureData<T: ArEntityHash, C: SupportedCurve>
where
    Ecdsa<C>: Scheme<
            Signer = EcSecretKey<C>,
            Verifier = EcPublicKey<C>,
            Output = EcdsaSignature<C>,
            Message = [u8],
        >,
{
    owner: WalletPk<<Ecdsa<C> as Scheme>::Verifier>,
    signature: ArEntitySignature<T, Ecdsa<C>>,
}

impl<T: ArEntityHash, C: SupportedCurve> EcdsaSignatureData<T, C>
where
    Ecdsa<C>: Scheme<
            Signer = EcSecretKey<C>,
            Verifier = EcPublicKey<C>,
            Output = EcdsaSignature<C>,
            Message = [u8],
        >,
    T: MessageFor<Ecdsa<C>>,
{
    pub fn new(
        owner: WalletPk<<Ecdsa<C> as Scheme>::Verifier>,
        signature: ArEntitySignature<T, Ecdsa<C>>,
    ) -> Self {
        Self { owner, signature }
    }

    pub(crate) fn recover_from_raw(raw_signature: Blob, hash: &T) -> Result<Self, Error> {
        let signature = EcdsaSignature::<C>::try_from(raw_signature)
            .map_err(|e| InvalidSignature(e.to_string()))?;
        let msg = hash.to_signable_message();
        let owner = signature
            .recover_verifier(&msg)
            .map_err(|e| InvalidSignature(e.to_string()))?;
        Ok(Self::new(
            WalletPk::from_inner(owner),
            ArEntitySignature::<T, _>::from_inner(Signature::from_inner(signature)),
        ))
    }

    pub(crate) fn from_raw(raw_signature: Blob, raw_public_key: Blob) -> Result<Self, Error> {
        let signature = EcdsaSignature::<C>::try_from(raw_signature)
            .map_err(|e| InvalidSignature(e.to_string()))?;

        let owner = EcPublicKey::try_from(raw_public_key).map_err(|e| InvalidKey(e.into()))?;

        Ok(Self::new(
            WalletPk::from_inner(owner),
            ArEntitySignature::<T, _>::from_inner(Signature::from_inner(signature)),
        ))
    }

    pub(crate) fn verify_sig(&self, hash: &T) -> Result<(), Error> {
        self.owner
            .verify_entity_hash(hash, &self.signature)
            .map_err(|e| InvalidSignature(e.to_string()))
    }
}

impl<T: ArEntityHash> EcdsaSignatureData<T, Secp256k1> {
    pub fn owner(&self) -> Owner<'_> {
        Owner::Secp256k1((&self.owner).into())
    }

    pub(crate) fn signature(&self) -> super::Signature<'_, T> {
        super::Signature::Secp256k1((&self.signature).into())
    }
}
