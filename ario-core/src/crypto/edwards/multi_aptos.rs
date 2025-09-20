// Loosely based on https://github.com/aptos-labs/aptos-core/blob/main/crates/aptos-crypto/src/multi_ed25519.rs

use crate::blob::{AsBlob, Blob};
use crate::confidential::{NewSecretExt, RevealExt, Sensitive};
use crate::crypto::edwards::variants::Aptos;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher};
use crate::crypto::keys::{AsymmetricScheme, PublicKey, SecretKey};
use crate::crypto::signature::{Scheme, SchemeVariant, Signature, SigningError, VerificationError};
use crate::crypto::{Output, OutputLen, keys};
use bytes::{BufMut, Bytes, BytesMut};
use core::fmt;
use ct_codecs::Encoder;
use ed25519_dalek::ed25519;
use hybrid_array::typenum::{Sum, U4, U2048};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use signature::Signer;
use std::ops::Deref;
use thiserror::Error;

pub type U2052 = Sum<U2048, U4>;

pub const MAX_NUM_OF_KEYS: usize = 32;
const BITMAP_NUM_OF_BYTES: usize = 4;
const BITMAP_MAX_BITS: u8 = (BITMAP_NUM_OF_BYTES * 8) as u8;

pub const SERIALIZED_SIGS_SIZE: usize = U2052::USIZE;
pub const SERIALIZED_OWNERS_SIZE: usize = (ed25519_dalek::PUBLIC_KEY_LENGTH * MAX_NUM_OF_KEYS) + 1;

pub struct MultiAptosEd25519;

impl Scheme for MultiAptosEd25519 {
    type Output = MultiAptosSignature;
    type Signer = MultiAptosSigningKey;
    type SigningError = MultiAptosError;
    type Verifier = MultiAptosVerifyingKey;
    type VerificationError = MultiAptosError;
    type Message<'a> = [u8];

    fn sign(
        signer: &Self::Signer,
        msg: &Self::Message<'_>,
    ) -> Result<Signature<Self>, Self::SigningError>
    where
        Self: Sized,
    {
        let msg = Aptos::process(msg).map_err(|e| MultiAptosError::Other(e.to_string()))?;
        Ok(Signature::from_inner(MultiAptosSignature::new(
            signer.keys.reveal().iter().map(|sk| sk.sign(&msg)),
        )?))
    }

    fn verify(
        verifier: &Self::Verifier,
        msg: &Self::Message<'_>,
        signature: &Signature<Self>,
    ) -> Result<(), Self::VerificationError>
    where
        Self: Sized,
    {
        let msg = Aptos::process(msg).map_err(|e| MultiAptosError::Other(e.to_string()))?;
        let sig = signature.as_inner();
        let bitmap = sig.bitmap;
        match bitmap.last_set_bit() {
            Some(last_bit) if (last_bit as usize) < verifier.keys.len() => (),
            _ => {
                return Err(MultiAptosError::SignatureError);
            }
        };
        let num_ones_in_bitmap = bitmap.count_ones() as usize;
        if num_ones_in_bitmap < *verifier.threshold {
            return Err(MultiAptosError::SignatureError);
        }
        if num_ones_in_bitmap != sig.sigs.len() {
            return Err(MultiAptosError::SignatureError);
        }

        // accumulating failure flag
        let mut failure = 0u8;

        let mut sig_idx = 0;

        // aim for constant(ish)-time evaluation
        verifier.keys.iter().enumerate().for_each(|(i, vk)| {
            let is_set = bitmap.is_set(i as u8) as u8;
            let current_sig = &sig.sigs[sig_idx];
            let is_ok = vk.verify_strict(&msg, current_sig).is_ok() as u8;

            // If the bit for this index was set, we check the result.
            // If the bit was not set, this expression results in 0 (no failure).
            // If the bit was set but verification failed (is_ok=0), this results in 1 (failure).
            // We OR this with our accumulated failure flag.
            failure |= is_set & (1 - is_ok);

            // Only advance the signature index if the bit was set.
            // This avoids data-dependent branching.
            sig_idx += is_set as usize;
        });

        if failure != 0 {
            return Err(MultiAptosError::SignatureError);
        }
        Ok(())
    }
}

/// A 32-bit bitmap for tracking which participants have signed in a multisig scheme.
///
/// Bits are indexed from left to right (MSB-first), from 0 to 31.
#[derive(Copy, Clone, PartialEq, Default, Serialize, Deserialize)]
#[repr(transparent)]
struct Bitmap([u8; BITMAP_NUM_OF_BYTES]);

impl Bitmap {
    fn new() -> Self {
        Self::default()
    }

    /// Sets the bit at the given index to 1.
    ///
    /// Indices are 0-based, from left-to-right.
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds (>= 32).
    fn set(&mut self, index: u8) -> Result<(), MultiAptosError> {
        if index >= BITMAP_MAX_BITS {
            return Err(MultiAptosError::Other(format!(
                "Bitmap index {} is out of bounds.",
                index
            )));
        }
        let byte_index = (index / 8) as usize;
        let bit_in_byte = index % 8;
        self.0[byte_index] |= 128 >> bit_in_byte;
        Ok(())
    }

    /// Checks if the bit at the given index is set to 1.
    ///
    /// Returns `false` if the index is out of bounds.
    fn is_set(&self, index: u8) -> bool {
        if index >= BITMAP_MAX_BITS {
            return false;
        }
        let byte_index = (index / 8) as usize;
        let bit_in_byte = index % 8;
        (self.0[byte_index] & (128 >> bit_in_byte)) != 0
    }

    /// Returns the total number of bits set to 1.
    fn count_ones(&self) -> u32 {
        self.0.iter().map(|byte| byte.count_ones()).sum()
    }

    /// Finds the index of the highest (last) bit that is set to 1.
    ///
    /// Returns `None` if the bitmap is empty.
    fn last_set_bit(&self) -> Option<u8> {
        self.0
            .iter()
            .rev()
            .enumerate()
            .find(|(_, byte)| byte != &&0u8)
            .map(|(i, byte)| {
                (8 * (BITMAP_NUM_OF_BYTES - i) - byte.trailing_zeros() as usize - 1) as u8
            })
    }
}

impl From<[u8; BITMAP_NUM_OF_BYTES]> for Bitmap {
    /// Creates a `Bitmap` directly from a 4-byte array.
    fn from(bytes: [u8; BITMAP_NUM_OF_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Bitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Bitmap(0b_{:08b}_{:08b}_{:08b}_{:08b})",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

impl fmt::Display for Bitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{}",
            ct_codecs::Hex::encode_to_string(self.0).expect("hex encoding to never fail")
        )
    }
}

impl AsBlob for Bitmap {
    fn as_blob(&self) -> Blob<'_> {
        Blob::Bytes(Bytes::copy_from_slice(self.0.as_slice()))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiAptosSignature {
    sigs: Vec<ed25519_dalek::Signature>,
    bitmap: Bitmap,
}

impl MultiAptosSignature {
    fn new(
        sigs: impl IntoIterator<Item = ed25519_dalek::Signature>,
    ) -> Result<Self, MultiAptosError> {
        let mut bitmap = Bitmap::new();
        let sigs = sigs
            .into_iter()
            .enumerate()
            .map(|(idx, sig)| {
                if idx > MAX_NUM_OF_KEYS {
                    Err(MultiAptosError::SignatureError)
                } else {
                    let idx = idx as u8;
                    if bitmap.is_set(idx) {
                        Err(MultiAptosError::SignatureError)
                    } else {
                        bitmap.set(idx)?;
                        Ok(sig)
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        if sigs.len() == 0 {
            return Err(MultiAptosError::SignatureError);
        }
        Ok(Self { sigs, bitmap })
    }
}

impl Output for MultiAptosSignature {
    type Len = U2052;
}

impl AsBlob for MultiAptosSignature {
    fn as_blob(&self) -> Blob<'_> {
        // make sure the full buffer is properly zero-initialized
        let mut bytes = BytesMut::zeroed(SERIALIZED_SIGS_SIZE);
        bytes.clear();

        self.sigs
            .iter()
            .for_each(|sig| bytes.extend_from_slice(sig.as_blob().bytes()));

        let bitmap = self.bitmap.as_blob();
        assert!(bytes.chunk_mut().len() >= bitmap.len());

        let bitmap_pos = bytes.capacity() - bitmap.len();
        let advance_by = bitmap_pos - bytes.len();
        unsafe {
            // SAFETY: `advance_by` is guaranteed to be within the initialized buffer
            bytes.advance_mut(advance_by);
        }
        bytes.extend_from_slice(bitmap.bytes());

        Blob::Bytes(bytes.freeze())
    }
}

impl<'a> TryFrom<Blob<'a>> for MultiAptosSignature {
    type Error = MultiAptosError;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        if value.len() != SERIALIZED_SIGS_SIZE {
            return Err(MultiAptosError::SignatureError);
        }

        let (suffix, sig_count) = check_and_get_suffix::<
            { ed25519_dalek::SIGNATURE_LENGTH },
            BITMAP_NUM_OF_BYTES,
        >(value.bytes())
        .map_err(|_| MultiAptosError::SignatureError)?;

        let bitmap = Bitmap::from(*suffix);

        if bitmap.count_ones() != sig_count as u32 {
            return Err(MultiAptosError::SignatureError);
        }

        Ok(Self {
            sigs: (&value.bytes()[..ed25519_dalek::SIGNATURE_LENGTH * sig_count])
                .chunks_exact(ed25519_dalek::SIGNATURE_LENGTH)
                .map(|bytes| {
                    ed25519_dalek::Signature::from_slice(bytes)
                        .map_err(|_| MultiAptosError::SignatureError)
                })
                .collect::<Result<_, _>>()?,
            bitmap,
        })
    }
}

impl AsymmetricScheme for MultiAptosEd25519 {
    type SecretKey = MultiAptosSigningKey;
    type PublicKey = MultiAptosVerifyingKey;
}

#[derive(Error, Debug)]
pub enum MultiAptosError {
    #[error(transparent)]
    KeyError(#[from] KeyError),
    #[error("signature error")]
    SignatureError,
    #[error("other error: {0}")]
    Other(String),
}

impl Into<SigningError> for MultiAptosError {
    fn into(self) -> SigningError {
        SigningError::Other(self.to_string())
    }
}

impl Into<VerificationError> for MultiAptosError {
    fn into(self) -> VerificationError {
        VerificationError::Other(self.to_string())
    }
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error(transparent)]
    EntryError(#[from] EntryError),
    #[error(transparent)]
    ThresholdError(#[from] ThresholdError),
    #[error(transparent)]
    Ed25519Error(#[from] ed25519::Error),
    #[error("invalid entry length: expected '{expected}', actual: '{actual}'")]
    InvalidLength { expected: usize, actual: usize },
    #[error("key error: {0}")]
    Other(String),
}

impl From<KeyError> for keys::KeyError {
    fn from(value: KeyError) -> Self {
        match value {
            KeyError::Ed25519Error(e) => keys::KeyError::EddsaError(e.into()),
            KeyError::InvalidLength { expected, actual } => {
                keys::KeyError::EddsaError(super::eddsa::KeyError::InvalidKeyLength {
                    expected,
                    actual,
                })
            }
            other => keys::KeyError::Other(other.into()),
        }
    }
}

#[derive(Error, Debug)]
pub enum ThresholdError {
    #[error("threshold cannot be zero")]
    ZeroThreshold,
    #[error("threshold '{0}' exceeds maximum")]
    ThresholdExceedsMax(usize),
    #[error("threshold '{threshold}' exceeds number of keys '{key_count}'")]
    ThresholdExceedsKeys { threshold: usize, key_count: usize },
}

#[derive(Error, Debug)]
pub enum EntryError {
    #[error("invalid entry length: expected '{expected}', actual: '{actual}'")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid number of entries: '{0}'")]
    InvalidNumberOfEntries(usize),
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub(crate) struct Threshold(usize);

impl Deref for Threshold {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<usize> for Threshold {
    type Error = ThresholdError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > MAX_NUM_OF_KEYS {
            return Err(ThresholdError::ThresholdExceedsMax(value));
        }
        if value == 0 {
            return Err(ThresholdError::ZeroThreshold);
        }
        Ok(Self(value))
    }
}

#[derive(Clone)]
pub struct MultiAptosSigningKey {
    keys: Sensitive<Vec<ed25519_dalek::SigningKey>>,
    pk: MultiAptosVerifyingKey,
    threshold: Threshold,
}

impl MultiAptosSigningKey {
    fn new(
        keys: impl IntoIterator<Item = ed25519_dalek::SigningKey>,
        threshold: Threshold,
    ) -> Result<Self, KeyError> {
        let keys = keys.into_iter().collect_vec();
        if *threshold > keys.len() {
            return Err(ThresholdError::ThresholdExceedsKeys {
                threshold: *threshold,
                key_count: keys.len(),
            })?;
        }
        if keys.len() > MAX_NUM_OF_KEYS {
            return Err(EntryError::InvalidNumberOfEntries(keys.len()))?;
        }
        let pk = MultiAptosVerifyingKey::new(keys.iter().map(|sk| sk.verifying_key()), threshold)?;

        Ok(Self {
            keys: keys.sensitive(),
            pk,
            threshold,
        })
    }

    fn from_raw(raw: &[u8]) -> Result<Self, KeyError> {
        let (suffix, num_keys) =
            check_and_get_suffix::<{ ed25519_dalek::SECRET_KEY_LENGTH }, 1>(raw)?;
        let threshold = Threshold::try_from(u8::from_be_bytes(*suffix) as usize)?;

        Ok(Self::new(
            raw[..ed25519_dalek::SECRET_KEY_LENGTH * num_keys]
                .chunks_exact(ed25519_dalek::SECRET_KEY_LENGTH)
                .map(|bytes| {
                    ed25519_dalek::SigningKey::try_from(bytes).map_err(KeyError::Ed25519Error)
                })
                .collect::<Result<Vec<_>, KeyError>>()?,
            threshold,
        )?)
    }
}

impl SecretKey for MultiAptosSigningKey {
    type Scheme = MultiAptosEd25519;

    fn public_key_impl(&self) -> &<Self::Scheme as AsymmetricScheme>::PublicKey {
        &self.pk
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
pub struct MultiAptosVerifyingKey {
    keys: Vec<ed25519_dalek::VerifyingKey>,
    threshold: Threshold,
}

impl MultiAptosVerifyingKey {
    fn new(
        keys: impl IntoIterator<Item = ed25519_dalek::VerifyingKey>,
        threshold: Threshold,
    ) -> Result<Self, KeyError> {
        let keys = keys.into_iter().collect_vec();
        if *threshold > keys.len() {
            return Err(ThresholdError::ThresholdExceedsKeys {
                threshold: *threshold,
                key_count: keys.len(),
            })?;
        }
        if keys.len() > MAX_NUM_OF_KEYS {
            return Err(EntryError::InvalidNumberOfEntries(keys.len()))?;
        };

        Ok(Self { keys, threshold })
    }
}

impl AsBlob for MultiAptosVerifyingKey {
    fn as_blob(&self) -> Blob<'_> {
        let mut bytes =
            BytesMut::with_capacity((ed25519_dalek::PUBLIC_KEY_LENGTH * self.keys.len()) + 1);

        self.keys
            .iter()
            .for_each(|k| bytes.extend_from_slice(k.as_bytes()));

        bytes.put_u8(self.threshold.0 as u8);

        Blob::Bytes(bytes.freeze())
    }
}

impl<'a> TryFrom<Blob<'a>> for MultiAptosVerifyingKey {
    type Error = KeyError;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        if value.len() != SERIALIZED_OWNERS_SIZE {
            return Err(KeyError::InvalidLength {
                expected: SERIALIZED_OWNERS_SIZE,
                actual: value.len(),
            });
        }

        let (suffix, num_keys) =
            check_and_get_suffix::<{ ed25519_dalek::PUBLIC_KEY_LENGTH }, 1>(value.bytes())?;
        let threshold = Threshold::try_from(u8::from_le_bytes(*suffix) as usize)?;

        Ok(Self {
            keys: value.bytes()[..num_keys * ed25519_dalek::PUBLIC_KEY_LENGTH]
                .chunks_exact(ed25519_dalek::PUBLIC_KEY_LENGTH)
                .map(|bytes| {
                    ed25519_dalek::VerifyingKey::try_from(bytes).map_err(KeyError::Ed25519Error)
                })
                .collect::<Result<Vec<_>, KeyError>>()?,
            threshold,
        })
    }
}

impl Hashable for MultiAptosVerifyingKey {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        self.as_blob().feed(hasher)
    }
}

impl DeepHashable for MultiAptosVerifyingKey {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_blob().deep_hash()
    }
}

impl PublicKey for MultiAptosVerifyingKey {
    type Scheme = MultiAptosEd25519;
}

fn check_and_get_suffix<const ENTRY_SIZE: usize, const SUFFIX_LEN: usize>(
    bytes: &[u8],
) -> Result<(&[u8; SUFFIX_LEN], usize), EntryError> {
    let min_len = ENTRY_SIZE + SUFFIX_LEN;
    let payload_len = bytes.len();
    if payload_len < min_len {
        return Err(EntryError::InvalidLength {
            expected: min_len,
            actual: payload_len,
        });
    }

    let (payload, suffix) = bytes.split_at(payload_len - SUFFIX_LEN);
    let suffix_bytes = suffix.try_into().expect("suffix_len bytes to be correct");

    // count number of entries
    // an all-zeroed entry means we reached the end
    let num_entries = payload
        .chunks_exact(ENTRY_SIZE)
        .take_while(|b| !is_all_zero(*b))
        .count();

    if num_entries == 0 || num_entries > MAX_NUM_OF_KEYS {
        Err(EntryError::InvalidNumberOfEntries(num_entries))
    } else {
        Ok((suffix_bytes, num_entries))
    }
}

fn is_all_zero(slice: &[u8]) -> bool {
    let (prefix, chunks, suffix) = bytemuck::pod_align_to::<u8, usize>(slice);

    prefix.iter().all(|&b| b == 0)
        && chunks.iter().all(|&word| word == 0)
        && suffix.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use crate::blob::{AsBlob, Blob, OwnedBlob};
    use crate::crypto::edwards::multi_aptos::{
        Bitmap, MultiAptosEd25519, MultiAptosError, MultiAptosSignature, MultiAptosSigningKey,
        MultiAptosVerifyingKey, SERIALIZED_OWNERS_SIZE,
    };
    use crate::crypto::signature::{SignSigExt, Signature, VerifySigExt};
    use bytes::{BufMut, BytesMut};
    use hex_literal::hex;

    fn build_blob<const LEN: usize, B: AsRef<[u8]>>(
        input: impl IntoIterator<Item = B>,
        suffix: impl AsRef<[u8]>,
    ) -> OwnedBlob {
        let mut bytes = BytesMut::zeroed(LEN);
        bytes.clear();
        input
            .into_iter()
            .for_each(|b| bytes.extend_from_slice(b.as_ref()));

        let suffix = suffix.as_ref();

        let suffix_pos = bytes.capacity() - suffix.len();
        let advance_by = suffix_pos - bytes.len();
        unsafe {
            // SAFETY: `advance_by` is guaranteed to be within the initialized buffer
            bytes.advance_mut(advance_by);
        }
        bytes.extend_from_slice(suffix);

        Blob::Bytes(bytes.freeze())
    }

    #[test]
    fn bitmap_tests() -> Result<(), anyhow::Error> {
        let mut bitmap = Bitmap::from([0b0100_0000u8, 0b1111_1111u8, 0u8, 0b1000_0000u8]);
        assert!(!bitmap.is_set(0));
        assert!(bitmap.is_set(1));
        for i in 8..16 {
            assert!(bitmap.is_set(i));
        }
        for i in 16..24 {
            assert!(!bitmap.is_set(i));
        }
        assert!(bitmap.is_set(24));
        assert!(!bitmap.is_set(31));
        assert_eq!(bitmap.last_set_bit(), Some(24));

        bitmap.set(30)?;
        assert!(bitmap.is_set(30));
        assert_eq!(bitmap.last_set_bit(), Some(30));

        Ok(())
    }

    #[test]
    fn rountrip() -> Result<(), anyhow::Error> {
        let raw_sks = build_blob::<1, _>(
            [
                &hex!("9DA90B2E9A011A042EC8F391DD669C712036B3BDB868CFD5F56BD9EECCB9A006"),
                &hex!("309A2C532CAB824CCB06521289387ECFBA30C0D2A1BFFCBA135A81D4EE03B54F"),
                &hex!("31A3C2B28ED39ECDD6645A393092504AB98D7E7605928E41016AAEF75F351890"),
            ],
            &[0x03],
        );

        let raw_pks = build_blob::<{ SERIALIZED_OWNERS_SIZE }, _>(
            [
                &hex!("D6C1252B6F04A3FA645C723182D5738A3CF6D7C9864D13E9A83E42AA09ABC742"),
                &hex!("0FB7A09A7364E6210B2A0BFB0A9D3066C2452AE28A3494E4E28989A0D14037A9"),
                &hex!("BC771E90A3C0AAA2053C2C4FD8A8C751BA74D97C8581C9AD6DFDDB1A11BDF380"),
            ],
            &[0x03],
        );

        let sk = MultiAptosSigningKey::from_raw(raw_sks.bytes())?;
        let pk = MultiAptosVerifyingKey::try_from(raw_pks)?;

        assert_eq!(sk.threshold, pk.threshold);
        assert_eq!(sk.pk, pk);

        let msg = b"Hello World";

        let multi_sig: Signature<MultiAptosEd25519> = sk.sign_sig(msg.as_slice())?;
        let serialized = multi_sig.as_blob();

        let multi_sig2: Signature<MultiAptosEd25519> =
            Signature::from_inner(MultiAptosSignature::try_from(serialized)?);

        assert_eq!(multi_sig, multi_sig2);

        pk.verify_sig(msg.as_slice(), &multi_sig)?;

        Ok(())
    }

    #[test]
    fn invalid_sig() -> Result<(), anyhow::Error> {
        let raw_sks = build_blob::<1, _>(
            [
                &hex!("9DA90B2E9A011A042EC8F391DD669C712036B3BDB868CFD5F56BD9EECCB9A006"),
                &hex!("309A2C532CAB824CCB06521289387ECFBA30C0D2A1BFFCBA135A81D4EE03B54F"),
                &hex!("31A3C2B28ED39ECDD6645A393092504AB98D7E7605928E41016AAEF75F351890"),
            ],
            &[0x03],
        );

        let raw_pks = build_blob::<{ SERIALIZED_OWNERS_SIZE }, _>(
            [
                &hex!("D6C1252B6F04A3FA645C723182D5738A3CF6D7C9864D13E9A83E42AA09ABC742"),
                &hex!("BC771E90A3C0AAA2053C2C4FD8A8C751BA74D97C8581C9AD6DFDDB1A11BDF380"),
                &hex!("BC771E90A3C0AAA2053C2C4FD8A8C751BA74D97C8581C9AD6DFDDB1A11BDF380"),
            ],
            &[0x03],
        );

        let sk = MultiAptosSigningKey::from_raw(raw_sks.bytes())?;
        let msg = b"Hello World";
        let multi_sig: Signature<MultiAptosEd25519> = sk.sign_sig(msg.as_slice())?;

        let pk = MultiAptosVerifyingKey::try_from(raw_pks)?;
        match pk.verify_sig(msg.as_slice(), &multi_sig) {
            Err(MultiAptosError::SignatureError) => {}
            _ => panic!("verification should have failed with SignatureError"),
        }

        Ok(())
    }
}
