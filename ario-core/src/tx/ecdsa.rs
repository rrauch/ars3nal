use crate::blob::Blob;
use crate::crypto::ec::ecdsa::{Ecdsa, EcdsaSignature};
use crate::crypto::ec::{Curve, EcPublicKey, EcSecretKey};
use crate::crypto::signature::Signature;
use crate::tx;
use crate::tx::CommonTxDataError::InvalidSignature;
use crate::tx::{CommonTxDataError, Owner, TxHash, TxSignature, TxSignatureScheme};
use crate::typed::FromInner;
use crate::wallet::WalletPk;
use k256::Secp256k1;

impl TxSignatureScheme for Ecdsa<Secp256k1> {
    type Signer = EcSecretKey<Secp256k1>;
    type Verifier = EcPublicKey<Secp256k1>;
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EcdsaSignatureData {
    Secp256k1 {
        owner: WalletPk<EcPublicKey<Secp256k1>>,
        signature: TxSignature<Ecdsa<Secp256k1>>,
    },
}

impl Into<EcdsaSignatureData>
    for (
        WalletPk<EcPublicKey<Secp256k1>>,
        TxSignature<Ecdsa<Secp256k1>>,
    )
{
    fn into(self) -> EcdsaSignatureData {
        EcdsaSignatureData::Secp256k1 {
            owner: self.0,
            signature: self.1,
        }
    }
}

impl EcdsaSignatureData {
    pub(super) fn from_ecdsa<C: Curve>(
        owner: WalletPk<EcPublicKey<C>>,
        signature: TxSignature<Ecdsa<C>>,
    ) -> Self
    where
        (WalletPk<EcPublicKey<C>>, TxSignature<Ecdsa<C>>): Into<EcdsaSignatureData>,
    {
        (owner, signature).into()
    }

    pub(super) fn owner(&self) -> Owner {
        match self {
            Self::Secp256k1 { owner, .. } => Owner::Secp256k1(owner.into()),
        }
    }

    pub(super) fn signature(&self) -> tx::Signature {
        match self {
            Self::Secp256k1 { signature, .. } => tx::Signature::Secp256k1(signature.into()),
        }
    }

    pub(super) fn verify_sig(&self, tx_hash: &TxHash) -> Result<(), CommonTxDataError> {
        match self {
            Self::Secp256k1 { owner, signature } => owner
                .verify_tx_hash(tx_hash, signature)
                .map_err(|e| InvalidSignature(e.to_string())),
        }
    }
}

impl EcdsaSignatureData {
    pub(super) fn from_raw(
        raw_signature: Blob,
        tx_hash: &TxHash,
    ) -> Result<Self, CommonTxDataError> {
        let signature = EcdsaSignature::<Secp256k1>::try_from(raw_signature)
            .map_err(|e| InvalidSignature(e.to_string()))?;
        let prehash = tx_hash.to_sign_prehash();
        let owner = signature
            .recover_verifier(&prehash)
            .map_err(|e| InvalidSignature(e.to_string()))?;
        Ok((
            WalletPk::from_inner(owner),
            TxSignature::from_inner(Signature::from_inner(signature)),
        )
            .into())
    }
}
