use crate::blob::{AsBlob, Blob};
use crate::crypto::ec::ecdsa::{Ecdsa, EcdsaSignature, Variant};
use crate::crypto::ec::ethereum::{Eip191Format, Eip712Format, EthereumVariant};
use crate::crypto::ec::{Curve, EcPublicKey, EcSecretKey};
use crate::crypto::signature::{Scheme, Signature};
use crate::entity::Error::{InvalidKey, InvalidSignature};
use crate::entity::{ArEntityHash, ArEntitySignature, Error, MessageFor, Owner};
use crate::typed::FromInner;
use crate::wallet::{WalletPk, WalletSk};
use derive_where::derive_where;
use k256::Secp256k1;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

pub type Secp256k1SignatureData<T: ArEntityHash> = EcdsaSignatureData<T, Secp256k1>;

type EthereumSignatureData<T: ArEntityHash, F, Ctx = ()> =
    EcdsaSignatureData<T, Secp256k1, EthereumVariant<F>, Ctx>;

pub type Eip191SignatureData<T: ArEntityHash, Ctx = ()> =
    EthereumSignatureData<T, Eip191Format, Ctx>;

pub type Eip712SignatureData<T: ArEntityHash, Ctx = ()> =
    EthereumSignatureData<T, Eip712Format, Ctx>;

trait SupportedCurve: Curve {}
impl SupportedCurve for Secp256k1 {}

#[derive_where(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct EcdsaSignatureData<T: ArEntityHash, C: SupportedCurve, V: Variant = (), Ctx = ()>
where
    for<'a> Ecdsa<C, V>: Scheme<
            Signer = EcSecretKey<C>,
            Verifier = EcPublicKey<C>,
            Output = EcdsaSignature<C, V>,
            Message<'a> = [u8],
        >,
{
    owner: WalletPk<<Ecdsa<C, V> as Scheme>::Verifier>,
    signature: ArEntitySignature<T, Ecdsa<C, V>>,
    _phantom: PhantomData<Ctx>,
}

impl<T: ArEntityHash, C: SupportedCurve, V: Variant, Ctx> Hash for EcdsaSignatureData<T, C, V, Ctx>
where
    for<'a> Ecdsa<C, V>: Scheme<
            Signer = EcSecretKey<C>,
            Verifier = EcPublicKey<C>,
            Output = EcdsaSignature<C, V>,
            Message<'a> = [u8],
        >,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.owner.as_blob().hash(state);
        self.signature.hash(state);
    }
}

impl<T: ArEntityHash, C: SupportedCurve, V: Variant, Ctx> EcdsaSignatureData<T, C, V, Ctx>
where
    for<'a> Ecdsa<C, V>: Scheme<
            Signer = EcSecretKey<C>,
            Verifier = EcPublicKey<C>,
            Output = EcdsaSignature<C, V>,
            Message<'a> = [u8],
        >,
    T: MessageFor<Ecdsa<C, V>>,
{
    pub fn new(
        owner: WalletPk<<Ecdsa<C, V> as Scheme>::Verifier>,
        signature: ArEntitySignature<T, Ecdsa<C, V>>,
    ) -> Self {
        Self {
            owner,
            signature,
            _phantom: PhantomData,
        }
    }

    pub(crate) fn recover_from_raw(raw_signature: Blob, hash: &T) -> Result<Self, Error> {
        let signature = EcdsaSignature::<C, V>::try_from(raw_signature)
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
        let signature = EcdsaSignature::<C, V>::try_from(raw_signature)
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

    pub(crate) fn sign(hash: &T, signer: &WalletSk<EcSecretKey<C>>) -> Result<Self, Error> {
        Ok(Self {
            owner: signer.public_key().clone(),
            signature: signer.sign_entity_hash(hash).map_err(Error::SigningError)?,
            _phantom: PhantomData,
        })
    }
}

impl<T: ArEntityHash, Ctx> EcdsaSignatureData<T, Secp256k1, (), Ctx> {
    pub fn owner(&self) -> Owner<'_> {
        Owner::Secp256k1((&self.owner).into())
    }

    pub(crate) fn signature(&self) -> super::Signature<'_, T> {
        super::Signature::Secp256k1((&self.signature).into())
    }
}

impl<T: ArEntityHash, Ctx> EthereumSignatureData<T, Eip191Format, Ctx> {
    pub fn owner(&self) -> Owner<'_> {
        Owner::Secp256k1((&self.owner).into())
    }

    pub(crate) fn signature(&self) -> super::Signature<'_, T> {
        super::Signature::Eip191((&self.signature).into())
    }
}

impl<T: ArEntityHash, Ctx> EthereumSignatureData<T, Eip712Format, Ctx> {
    pub fn owner(&self) -> Owner<'_> {
        Owner::Secp256k1((&self.owner).into())
    }

    pub(crate) fn signature(&self) -> super::Signature<'_, T> {
        super::Signature::Eip712((&self.signature).into())
    }
}
