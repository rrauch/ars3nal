use crate::blob::Blob;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher, Sha256};
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::rsa::{Rsa, RsaPrivateKey, RsaPublicKey, SupportedRsaKeySize};
use crate::crypto::signature::Scheme;
use crate::crypto::{keys, signature};
use crate::entity::Error::InvalidSignature;
use crate::entity::{ArEntityHash, ArEntitySignature, Error, Owner, PrehashFor, Signature};
use crate::typed::FromInner;
use crate::wallet::WalletPk;
use itertools::Either;

pub type Rsa4096SignatureData<T: ArEntityHash> = PssSignatureData<T, 4096>;
pub type Rsa2048SignatureData<T: ArEntityHash> = PssSignatureData<T, 2048>;

pub fn from_raw_autodetect<'a, T: ArEntityHash>(
    raw_owner: Blob<'a>,
    raw_signature: Blob<'a>,
) -> Result<Either<Rsa4096SignatureData<T>, Rsa2048SignatureData<T>>, Error>
where
    T: PrehashFor<Sha256>,
{
    Ok(match raw_owner.len() {
        256 => Either::Right(Rsa2048SignatureData::from_raw(raw_owner, raw_signature)?),
        512 => Either::Left(Rsa4096SignatureData::from_raw(raw_owner, raw_signature)?),
        unsupported => {
            return Err(Error::InvalidKey(
                crate::crypto::rsa::KeyError::UnsupportedKeySize(unsupported).into(),
            ))?;
        }
    })
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PssSignatureData<T: ArEntityHash, const BIT: usize>
where
    RsaPss<BIT>: Scheme,
{
    owner: WalletPk<RsaPublicKey<BIT>>,
    signature: ArEntitySignature<T, RsaPss<BIT>>,
}

impl<T: ArEntityHash, const BIT: usize> PssSignatureData<T, BIT>
where
    RsaPss<BIT>:
        Scheme<Signer = RsaPrivateKey<BIT>, Verifier = RsaPublicKey<BIT>, Message = Digest<Sha256>>,
    Rsa<BIT>: SupportedRsaKeySize,
    T: PrehashFor<Sha256>,
{
    pub(crate) fn new(
        owner: WalletPk<RsaPublicKey<BIT>>,
        signature: ArEntitySignature<T, RsaPss<BIT>>,
    ) -> Self {
        Self { owner, signature }
    }

    pub(crate) fn from_raw<'a>(
        raw_owner: Blob<'a>,
        raw_signature: Blob<'a>,
    ) -> Result<Self, Error> {
        let owner = RsaPublicKey::try_from(raw_owner)
            .map_err(|e| Error::from(keys::KeyError::RsaError(e)))?;
        let signature = <<RsaPss<BIT> as Scheme>::Output>::try_from(raw_signature)
            .map_err(|_| InvalidSignature("failed to deserialize from raw blob".to_string()))?;

        Ok(Self::new(
            WalletPk::from_inner(owner),
            ArEntitySignature::<T, _>::from_inner(signature::Signature::from_inner(signature)),
        ))
    }

    pub(crate) fn verify_sig(&self, hash: &T) -> Result<(), Error> {
        self.owner
            .verify_entity_hash(hash, &self.signature)
            .map_err(|e| InvalidSignature(e))
    }
}

impl<T: ArEntityHash> PssSignatureData<T, 4096> {
    pub fn owner(&self) -> Owner<'_> {
        Owner::Rsa4096((&self.owner).into())
    }

    pub(crate) fn signature(&self) -> Signature<'_, T> {
        Signature::Rsa4096((&self.signature).into())
    }
}

impl<T: ArEntityHash> PssSignatureData<T, 2048> {
    pub fn owner(&self) -> Owner<'_> {
        Owner::Rsa2048((&self.owner).into())
    }

    pub(crate) fn signature(&self) -> Signature<'_, T> {
        Signature::Rsa2048((&self.signature).into())
    }
}

impl<T: ArEntityHash, const BIT: usize> DeepHashable for PssSignatureData<T, BIT>
where
    RsaPss<BIT>: Scheme,
{
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.owner.deep_hash()
    }
}

impl<T: ArEntityHash, const BIT: usize> Hashable for PssSignatureData<T, BIT>
where
    RsaPss<BIT>: Scheme,
{
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        self.owner.feed(hasher)
    }
}
