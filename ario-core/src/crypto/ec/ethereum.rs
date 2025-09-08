use crate::confidential::RevealExt;
use crate::crypto::ec::ecdsa::{Ecdsa, EcdsaError, EcdsaSignature, Variant};
use crate::crypto::ec::{EcPublicKey, EcSecretKey};
use crate::crypto::hash::{Digest, HashableExt, Hasher};
use crate::crypto::keys::SecretKey;
use crate::crypto::signature::{Scheme, Signature, SigningError, VerificationError};
use crate::typed::{FromInner, Typed};
use crate::wallet::WalletPk;
use core::fmt;
use ct_codecs::{Decoder, Encoder};
use ecdsa::RecoveryId;
use elliptic_curve::sec1::ToEncodedPoint;
use hybrid_array::Array;
use hybrid_array::sizes::U20;
use k256::Secp256k1;
use sha3::Keccak256;
use signature::hazmat::PrehashVerifier;
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::LazyLock;
use thiserror::Error;

static EIP_712_DOMAIN_SEPARATOR: LazyLock<Digest<Keccak256>> = LazyLock::new(|| {
    let mut hasher = Keccak256::new();
    hasher.update(
        b"EIP712Domain(string name,string version)"
            .digest::<Keccak256>()
            .as_slice(),
    );
    hasher.update(b"Bundlr".digest::<Keccak256>().as_slice());
    hasher.update(b"1".digest::<Keccak256>().as_slice());
    hasher.finalize()
});

static EIP_712_MESSAGE_TYPE: LazyLock<Digest<Keccak256>> =
    LazyLock::new(|| b"Bundlr(bytes Transaction hash,address address)".digest::<Keccak256>());

pub struct EthereumVariant<Format>(PhantomData<Format>);

impl<Format: EthereumFormat> Variant for EthereumVariant<Format> {
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

trait EthereumFormat: Send + Sync {
    fn format(input: &[u8], public_key: &EthereumPublicKey) -> Digest<Keccak256>;
}

pub type Ethereum<Format> = Ecdsa<Secp256k1, EthereumVariant<Format>>;
pub type EthereumSecretKey = EcSecretKey<Secp256k1>;
pub type EthereumPublicKey = EcPublicKey<Secp256k1>;

pub struct EthereumAddressKind;
pub type EthereumAddress = Typed<EthereumAddressKind, Array<u8, U20>>;

/// Implements EIP-55 mixed-case checksum address encoding.
impl fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 1. Get the lowercase hex representation (without "0x" prefix).
        let lowercase_addr = ct_codecs::Hex::encode_to_string(self.0.as_slice())
            .expect("hex encoding to never fail");

        // 2. Compute the Keccak-256 hash of the lowercase ASCII hex string.
        let hash = lowercase_addr.digest::<Keccak256>();
        let hash = hash.as_slice();

        // 3. Build the checksummed address string.
        let checksummed_addr: String = lowercase_addr
            .char_indices()
            .map(|(i, c)| {
                // Characters '0'-'9' are not changed.
                if c.is_ascii_digit() {
                    return c;
                }

                // Check the corresponding nibble of the hash.
                // If the nibble is 8 or greater, uppercase the character.
                let hash_nibble = if i % 2 == 0 {
                    hash[i / 2] >> 4
                } else {
                    hash[i / 2] & 0x0F
                };

                if hash_nibble >= 8 {
                    c.to_ascii_uppercase()
                } else {
                    c // Keep it lowercase
                }
            })
            .collect();

        // 4. Write the final prefixed string to the formatter.
        write!(f, "0x{}", checksummed_addr)
    }
}

#[derive(Error, Debug)]
pub enum EthereumAddressError {
    #[error("Ethereum address is missing the '0x' prefix.")]
    InvalidPrefix,
    #[error("Ethereum address has an invalid number of hex characters (must be 40).")]
    InvalidLength,
    #[error("Ethereum address contains non-hexadecimal characters.")]
    InvalidHexCharacter,
    #[error("Ethereum address is mixed-case but has an invalid EIP-55 checksum.")]
    InvalidChecksum,
}

impl FromStr for EthereumAddress {
    type Err = EthereumAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 1. Validate prefix and length.
        if !s.starts_with("0x") {
            return Err(EthereumAddressError::InvalidPrefix);
        }
        let hex_part = &s[2..];
        if hex_part.len() != 40 {
            return Err(EthereumAddressError::InvalidLength);
        }

        // 2. Check for mixed-case to determine if checksum validation is needed.
        let is_lowercase = hex_part.chars().all(|c| !c.is_ascii_uppercase());
        let is_uppercase = hex_part.chars().all(|c| !c.is_ascii_lowercase());

        if !is_lowercase && !is_uppercase {
            // It's mixed-case, so validate the EIP-55 checksum.
            let lowercase_addr = hex_part.to_ascii_lowercase();
            let hash = lowercase_addr.as_bytes().digest::<Keccak256>();
            let hash = hash.as_slice();

            for (i, c) in hex_part.char_indices() {
                if c.is_ascii_digit() {
                    continue;
                }

                let hash_nibble = if i % 2 == 0 {
                    hash[i / 2] >> 4
                } else {
                    hash[i / 2] & 0x0F
                };

                // Check for checksum mismatch.
                if (hash_nibble >= 8 && c.is_ascii_lowercase())
                    || (hash_nibble < 8 && c.is_ascii_uppercase())
                {
                    return Err(EthereumAddressError::InvalidChecksum);
                }
            }
        }

        // 3. Decode the hex string into bytes.
        let bytes = Array::try_from(
            ct_codecs::Hex::decode_to_vec(hex_part, None)
                .map_err(|_| EthereumAddressError::InvalidHexCharacter)?,
        )
        .expect("hex string to be 40 bytes long");

        Ok(EthereumAddress::new_from_inner(bytes))
    }
}

pub trait EthereumPublicKeyExt {
    fn to_ethereum_address(&self) -> EthereumAddress;
}

impl EthereumPublicKeyExt for WalletPk<EthereumPublicKey> {
    fn to_ethereum_address(&self) -> EthereumAddress {
        self.0.to_ethereum_address()
    }
}

impl EthereumPublicKeyExt for EthereumPublicKey {
    fn to_ethereum_address(&self) -> EthereumAddress {
        let encoded_point = self.0.to_encoded_point(false);
        assert_eq!(encoded_point.as_bytes()[0], 4);
        let hash = (&encoded_point.as_bytes()[1..]).digest::<Keccak256>();
        let address = Array::try_from(&hash.as_slice()[12..]).expect("hash to be 32 bytes long");
        EthereumAddress::from_inner(address)
    }
}

pub type EthereumSignature<Format> = EcdsaSignature<Secp256k1, EthereumVariant<Format>>;

pub struct Eip191Format;

impl EthereumFormat for Eip191Format {
    fn format(input: &[u8], _: &EthereumPublicKey) -> Digest<Keccak256> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", input.len());
        let mut hasher = Keccak256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(input);
        hasher.finalize()
    }
}

pub type Eip191 = Ethereum<Eip191Format>;
pub type Eip191Signature = EthereumSignature<Eip191Format>;

pub struct Eip712Format;

impl EthereumFormat for Eip712Format {
    fn format(input: &[u8], public_key: &EthereumPublicKey) -> Digest<Keccak256> {
        let message_hash = {
            let encoded_tx_hash = input.digest::<Keccak256>();

            let address = public_key.to_ethereum_address();
            let mut encoded_address = [0u8; 32];
            encoded_address[12..].copy_from_slice(address.as_slice());

            let mut hasher = Keccak256::new();
            hasher.update(EIP_712_MESSAGE_TYPE.as_slice());
            hasher.update(encoded_tx_hash.as_slice());
            hasher.update(encoded_address.as_slice());
            hasher.finalize()
        };

        let mut hasher = Keccak256::new();
        hasher.update(b"\x19\x01");
        hasher.update(EIP_712_DOMAIN_SEPARATOR.as_slice());
        hasher.update(message_hash.as_slice());
        hasher.finalize()
    }
}

pub type Eip712 = Ethereum<Eip712Format>;
pub type Eip712ignature = EthereumSignature<Eip712Format>;

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

impl<Format: EthereumFormat> Scheme for Ethereum<Format> {
    type Output = EthereumSignature<Format>;
    type Signer = EthereumSecretKey;
    type SigningError = Error;
    type Verifier = EthereumPublicKey;
    type VerificationError = Error;
    type Message<'a> = [u8];

    fn sign(
        signer: &Self::Signer,
        msg: &Self::Message<'_>,
    ) -> Result<Signature<Self>, Self::SigningError>
    where
        Self: Sized,
    {
        let hash = Format::format(msg, signer.public_key_impl());
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
        let hash = Format::format(msg, verifier);
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
    use crate::crypto::ec::ethereum::{Eip191, Eip712, EthereumAddress, EthereumSecretKey};
    use crate::crypto::keys::SecretKey;
    use crate::crypto::signature::{SignSigExt, Signature, VerifySigExt};
    use crate::typed::FromInner;
    use hex_literal::hex;
    use std::str::FromStr;

    #[test]
    fn ethereum_addr() -> Result<(), anyhow::Error> {
        let address_bytes: [u8; 20] = [
            0xfb, 0x69, 0x16, 0x09, 0x5c, 0xa1, 0xdf, 0x60, 0xbb, 0x79, 0xce, 0x92, 0xce, 0x3e,
            0xa7, 0x4c, 0x37, 0xc5, 0xd3, 0x59,
        ];

        let eth_address = EthereumAddress::from_inner(address_bytes.into());
        assert_eq!(
            eth_address.to_string(),
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );

        let eth2 = EthereumAddress::from_str(eth_address.to_string().as_str())?;
        assert_eq!(eth_address, eth2);

        let eth3 =
            EthereumAddress::from_str(eth_address.to_string().to_ascii_lowercase().as_str())?;
        assert_eq!(eth_address, eth3);

        Ok(())
    }

    #[test]
    fn sig_verify() -> Result<(), anyhow::Error> {
        let raw_msg = Blob::Slice(b"Hello World");
        let raw_sk = Blob::Slice(&hex!(
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
        ));

        let sk = EthereumSecretKey::from_raw(raw_sk.bytes())?;

        let sig: Signature<Eip191> = sk.sign_sig(raw_msg.bytes())?;
        sk.public_key_impl().verify_sig(raw_msg.bytes(), &sig)?;

        let sig: Signature<Eip712> = sk.sign_sig(raw_msg.bytes())?;
        sk.public_key_impl().verify_sig(raw_msg.bytes(), &sig)?;

        Ok(())
    }
}
