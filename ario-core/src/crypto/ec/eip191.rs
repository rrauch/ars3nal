use crate::confidential::RevealExt;
use crate::crypto::ec::ecdsa::{Ecdsa, EcdsaError, EcdsaSignature, Variant};
use crate::crypto::ec::{EcPublicKey, EcSecretKey};
use crate::crypto::hash::{Digest, Hasher};
use crate::crypto::signature::{Scheme, Signature, SigningError, VerificationError};
use ecdsa::RecoveryId;
use k256::Secp256k1;
use sha3::Keccak256;
use signature::hazmat::PrehashVerifier;
use thiserror::Error;

pub struct Eip191Variant;

impl Variant for Eip191Variant {
    fn serialize_rec_id(rec_id: RecoveryId) -> u8 {
        rec_id.to_byte() + 27
    }

    fn deserialize_rec_id(value: u8) -> Option<RecoveryId> {
        if value < 27 {
            return None;
        }
        RecoveryId::from_byte(value - 27)
    }
}

pub type Eip191 = Ecdsa<Secp256k1, Eip191Variant>;
pub type Eip191SecretKey = EcSecretKey<Secp256k1>;
pub type Eip191PublicKey = EcPublicKey<Secp256k1>;
pub type Eip191Signature = EcdsaSignature<Secp256k1, Eip191Variant>;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    EcdsaError(#[from] EcdsaError),
}

impl Into<SigningError> for Error {
    fn into(self) -> SigningError {
        SigningError::Other(self.to_string())
    }
}

impl Into<VerificationError> for Error {
    fn into(self) -> VerificationError {
        VerificationError::Other(self.to_string())
    }
}

fn to_eip191_hash(input: &[u8]) -> Digest<Keccak256> {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", input.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(input);
    hasher.finalize()
}

impl Scheme for Eip191 {
    type Output = Eip191Signature;
    type Signer = <Ecdsa<Secp256k1> as Scheme>::Signer;
    type SigningError = Error;
    type Verifier = <Ecdsa<Secp256k1> as Scheme>::Verifier;
    type VerificationError = Error;
    type Message<'a> = <Ecdsa<Secp256k1> as Scheme>::Message<'a>;

    fn sign(
        signer: &Self::Signer,
        msg: &Self::Message<'_>,
    ) -> Result<Signature<Self>, Self::SigningError>
    where
        Self: Sized,
    {
        let hash = to_eip191_hash(msg);
        let (sig, rec_id) = ecdsa::SigningKey::from(signer.inner.reveal())
            .sign_prehash_recoverable(hash.as_slice())
            .map_err(EcdsaError::from)?;

        Ok(Signature::from_inner(EcdsaSignature::new(
            sig,
            Some(rec_id),
        )))
    }

    fn verify(
        verifier: &Self::Verifier,
        msg: &Self::Message<'_>,
        signature: &Signature<Self>,
    ) -> Result<(), Self::VerificationError>
    where
        Self: Sized,
    {
        let hash = to_eip191_hash(msg);
        let verifying_key = ecdsa::VerifyingKey::from(&verifier.0);
        verifying_key
            .verify_prehash(hash.as_slice(), signature.as_inner().inner())
            .map_err(EcdsaError::from)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::blob::Blob;
    use crate::crypto::ec::eip191::{Eip191, Eip191SecretKey};
    use crate::crypto::keys::SecretKey;
    use crate::crypto::signature::{SignSigExt, Signature, VerifySigExt};
    use hex_literal::hex;

    #[test]
    fn sig_verify() -> Result<(), anyhow::Error> {
        let raw_msg = Blob::Slice(b"Hello World");
        let raw_sk = Blob::Slice(&hex!(
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
        ));

        let sk = Eip191SecretKey::from_raw(raw_sk.bytes())?;

        let sig: Signature<Eip191> = sk.sign_sig(raw_msg.bytes())?;

        sk.public_key_impl().verify_sig(raw_msg.bytes(), &sig)?;

        Ok(())
    }
}
