use crate::blob::Blob;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher};
use crate::crypto::rsa::{RsaPss, RsaPublicKey};
use crate::crypto::{keys, signature};
use crate::tx::{CommonTxDataError, Owner, Signature, TxSignatureScheme, TxHash, TxSignature};
use crate::typed::FromInner;
use crate::wallet::WalletPk;

impl TxSignatureScheme for RsaPss<4096> {
    type Signer = <Self as signature::Scheme>::Signer;
    type Verifier = <Self as signature::Scheme>::Verifier;
}

impl TxSignatureScheme for RsaPss<2048> {
    type Signer = <Self as signature::Scheme>::Signer;
    type Verifier = <Self as signature::Scheme>::Verifier;
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RsaSignatureData {
    Rsa4096 {
        owner: WalletPk<RsaPublicKey<4096>>,
        signature: TxSignature<RsaPss<4096>>,
    },
    Rsa2048 {
        owner: WalletPk<RsaPublicKey<2048>>,
        signature: TxSignature<RsaPss<2048>>,
    },
}

impl RsaSignatureData {
    pub(super) fn from_raw<'a>(
        raw_owner: Blob<'a>,
        raw_signature: Blob<'a>,
    ) -> Result<Self, CommonTxDataError> {
        use crate::crypto::rsa::SupportedPublicKey;
        use crate::crypto::signature::Scheme as SignatureScheme;
        use crate::crypto::signature::Signature;
        use crate::tx::CommonTxDataError::*;

        Ok(
            match SupportedPublicKey::try_from(raw_owner)
                .map_err(|e| CommonTxDataError::from(keys::KeyError::RsaError(e)))?
            {
                SupportedPublicKey::Rsa4096(pk) => Self::Rsa4096 {
                    owner: WalletPk::from_inner(pk),
                    signature: TxSignature::from_inner(Signature::from_inner(
                        <<RsaPss<4096> as SignatureScheme>::Output>::try_from(raw_signature)
                            .map_err(|e| InvalidSignature(e.to_string()))?,
                    )),
                },
                SupportedPublicKey::Rsa2048(pk) => Self::Rsa2048 {
                    owner: WalletPk::from_inner(pk),
                    signature: TxSignature::from_inner(Signature::from_inner(
                        <<RsaPss<2048> as SignatureScheme>::Output>::try_from(raw_signature)
                            .map_err(|e| InvalidSignature(e.to_string()))?,
                    )),
                },
            },
        )
    }

    pub(super) fn verify_sig(&self, tx_hash: &TxHash) -> Result<(), CommonTxDataError> {
        use crate::tx::CommonTxDataError::*;

        match self {
            Self::Rsa4096 { owner, signature } => owner
                .verify_tx(tx_hash, signature)
                .map_err(|e| InvalidSignature(e)),
            Self::Rsa2048 { owner, signature } => owner
                .verify_tx(tx_hash, signature)
                .map_err(|e| InvalidSignature(e)),
        }
    }

    fn owner(&self) -> Owner {
        match self {
            Self::Rsa4096 { owner, .. } => Owner::Rsa4096(owner.into()),
            Self::Rsa2048 { owner, .. } => Owner::Rsa2048(owner.into()),
        }
    }

    fn signature(&self) -> Signature {
        match self {
            Self::Rsa4096 { signature, .. } => Signature::Rsa4096(signature.into()),
            Self::Rsa2048 { signature, .. } => Signature::Rsa2048(signature.into()),
        }
    }
}

impl DeepHashable for RsaSignatureData {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        match self {
            Self::Rsa4096 { owner, .. } => owner.deep_hash(),
            Self::Rsa2048 { owner, .. } => owner.deep_hash(),
        }
    }
}

impl Hashable for RsaSignatureData {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        match self {
            Self::Rsa4096 { owner, .. } => owner.feed(hasher),
            Self::Rsa2048 { owner, .. } => owner.feed(hasher),
        }
    }
}
