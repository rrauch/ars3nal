use crate::blob::Blob;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher, Sha256};
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::rsa::{Rsa, RsaPublicKey, SupportedRsaKeySize};
use crate::crypto::{keys, signature};
use crate::entity::Error::InvalidSignature;
use crate::entity::{
    ArEntityHash, ArEntitySignature, Error, Owner, PrehashFor, Signature, SignatureScheme,
};
use crate::typed::FromInner;
use crate::wallet::WalletPk;

impl SignatureScheme for RsaPss<4096> {
    type Signer = <Self as signature::Scheme>::Signer;
    type Verifier = <Self as signature::Scheme>::Verifier;
}

impl SignatureScheme for RsaPss<2048> {
    type Signer = <Self as signature::Scheme>::Signer;
    type Verifier = <Self as signature::Scheme>::Verifier;
}

#[derive(Error, Debug)]
pub(crate) enum PssSignatureError {
    #[error("unsupported rsa key size: '{0}'")]
    UnsupportedKeySize(usize),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PssSignatureData<T: ArEntityHash> {
    Rsa4096 {
        owner: WalletPk<RsaPublicKey<4096>>,
        signature: ArEntitySignature<T, RsaPss<4096>>,
    },
    Rsa2048 {
        owner: WalletPk<RsaPublicKey<2048>>,
        signature: ArEntitySignature<T, RsaPss<2048>>,
    },
}

impl<T: ArEntityHash> PssSignatureData<T>
where
    T: PrehashFor<Sha256>,
{
    pub(crate) fn from_rsa<const BIT: usize>(
        owner: WalletPk<RsaPublicKey<BIT>>,
        signature: ArEntitySignature<T, RsaPss<BIT>>,
    ) -> Result<Self, PssSignatureError>
    where
        Rsa<BIT>: SupportedRsaKeySize,
    {
        match BIT {
            4096 => {
                // SAFETY: BIT is 4096, so types are identical
                unsafe {
                    Ok(Self::Rsa4096 {
                        owner: std::mem::transmute(owner),
                        signature: std::mem::transmute(signature),
                    })
                }
            }
            2048 => {
                // SAFETY: BIT is 2048, so types are identical
                unsafe {
                    Ok(Self::Rsa2048 {
                        owner: std::mem::transmute(owner),
                        signature: std::mem::transmute(signature),
                    })
                }
            }
            unsupported => Err(PssSignatureError::UnsupportedKeySize(unsupported)),
        }
    }

    pub(crate) fn from_raw<'a>(
        raw_owner: Blob<'a>,
        raw_signature: Blob<'a>,
    ) -> Result<Self, Error> {
        use crate::crypto::rsa::SupportedPublicKey;
        use crate::crypto::signature::Scheme as SignatureScheme;
        use crate::crypto::signature::Signature;

        Ok(
            match SupportedPublicKey::try_from(raw_owner)
                .map_err(|e| Error::from(keys::KeyError::RsaError(e)))?
            {
                SupportedPublicKey::Rsa4096(pk) => Self::Rsa4096 {
                    owner: WalletPk::from_inner(pk),
                    signature: ArEntitySignature::<T, _>::from_inner(Signature::from_inner(
                        <<RsaPss<4096> as SignatureScheme>::Output>::try_from(raw_signature)
                            .map_err(|e| InvalidSignature(e.to_string()))?,
                    )),
                },
                SupportedPublicKey::Rsa2048(pk) => Self::Rsa2048 {
                    owner: WalletPk::from_inner(pk),
                    signature: ArEntitySignature::<T, _>::from_inner(Signature::from_inner(
                        <<RsaPss<2048> as SignatureScheme>::Output>::try_from(raw_signature)
                            .map_err(|e| InvalidSignature(e.to_string()))?,
                    )),
                },
            },
        )
    }

    pub(crate) fn verify_sig(&self, hash: &T) -> Result<(), Error> {
        match self {
            Self::Rsa4096 { owner, signature } => owner
                .verify_entity_hash::<T, Sha256>(hash, signature)
                .map_err(|e| InvalidSignature(e)),
            Self::Rsa2048 { owner, signature } => owner
                .verify_entity_hash::<T, Sha256>(hash, signature)
                .map_err(|e| InvalidSignature(e)),
        }
    }

    pub(crate) fn owner(&self) -> Owner<'_> {
        match self {
            Self::Rsa4096 { owner, .. } => Owner::Rsa4096(owner.into()),
            Self::Rsa2048 { owner, .. } => Owner::Rsa2048(owner.into()),
        }
    }

    pub(crate) fn signature(&self) -> Signature<'_, T> {
        match self {
            Self::Rsa4096 { signature, .. } => Signature::Rsa4096(signature.into()),
            Self::Rsa2048 { signature, .. } => Signature::Rsa2048(signature.into()),
        }
    }
}

impl<T: ArEntityHash> DeepHashable for PssSignatureData<T> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        match self {
            Self::Rsa4096 { owner, .. } => owner.deep_hash(),
            Self::Rsa2048 { owner, .. } => owner.deep_hash(),
        }
    }
}

impl<T: ArEntityHash> Hashable for PssSignatureData<T> {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        match self {
            Self::Rsa4096 { owner, .. } => owner.feed(hasher),
            Self::Rsa2048 { owner, .. } => owner.feed(hasher),
        }
    }
}
