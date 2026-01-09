use crate::types::{AuthMode, Cipher, SignatureFormat};
use crate::{DriveId, Password};
use ario_core::bundle::{
    BundleItem, BundleItemBuilder, BundleItemError, Ed25519Scheme, V2BundleItemDataProcessor,
};
use ario_core::confidential::{NewSecretExt, RevealExt, RevealMutExt};
use ario_core::crypto::aes::gcm::{AesGcm, AesGcmParams, Tag as AesGcmTag};
use ario_core::crypto::aes::{AesKey, Nonce};
use ario_core::crypto::encryption;
use ario_core::crypto::encryption::DecryptionExt;
use ario_core::crypto::hash::{Digest, Hasher, Sha256};
use ario_core::tag::Tag;
use ario_core::wallet::hazmat::SigningKey;
use ario_core::wallet::{Wallet, WalletAddress};
use hkdf::Hkdf;
use hkdf::hmac::digest::consts::U16;
use rsa::pss::SigningKey as PssSigningKey;
use rsa::rand_core::{CryptoRng, RngCore};
use rsa::signature::digest::typenum::U12;
use rsa::signature::hazmat::RandomizedPrehashSigner;
use std::fmt::Display;
use std::io::Cursor;
use thiserror::Error;
use tokio_util::bytes::BytesMut;

#[derive(Debug, Clone)]
pub struct DriveKey {
    v1: AesKey<256>,
    v2: AesKey<256>,
}

#[derive(Error, Debug)]
pub enum DriveKeyError {
    #[error("only RSA keys can be used with drive keys")]
    UnsupportedKey,
    #[error(transparent)]
    SignatureError(#[from] rsa::signature::Error),
    #[error(transparent)]
    HkdfError(#[from] hkdf::InvalidLength),
    #[error("derived key cannot be used with aes-256")]
    AesKeyError,
    #[error(transparent)]
    DecryptionError(#[from] encryption::Error),
    #[error(transparent)]
    BundleItemError(#[from] BundleItemError),
}

fn v1_message(drive_id: &DriveId) -> Digest<Sha256> {
    let mut hasher = Sha256::new();
    hasher.update("drive".as_bytes());
    hasher.update(drive_id.as_ref());
    hasher.finalize()
}

fn v2_message(drive_id: &DriveId, owner: &WalletAddress) -> Result<Digest<Sha256>, DriveKeyError> {
    let mut payload = Vec::with_capacity(drive_id.as_ref().len() + 5);
    payload.extend_from_slice("drive".as_bytes());
    payload.extend_from_slice(drive_id.as_ref());

    // We cannot use the normal bundle item processing / signing pipeline here
    // due to the fact that the output has to be 100% byte-for-byte identical to whatever
    // the `arbundles` TS/JS library produces.
    //
    // So we are *manually* building the data item here.

    let data = V2BundleItemDataProcessor::from_single_value(payload);

    let draft = BundleItemBuilder::v2()
        .tags(vec![("Action", "Drive-Signature-V2").into()])
        .data_upload(&data)
        .draft()?;

    todo!()
}

fn hkdf_derive(sig: &[u8], password: &Password) -> Result<AesKey<256>, DriveKeyError> {
    let mut buf = vec![0u8; 32].into_boxed_slice().confidential();
    let hkdf = Hkdf::<Sha256>::new(None, sig.as_ref());
    hkdf.expand(password.reveal().as_bytes(), buf.reveal_mut())?;
    Ok(AesKey::try_from_bytes(buf.reveal()).ok_or_else(|| DriveKeyError::AesKeyError)?)
}

impl DriveKey {
    pub fn derive_from(
        drive_id: &DriveId,
        wallet: &Wallet,
        password: impl Into<Password>,
    ) -> Result<Self, DriveKeyError> {
        let password = password.into();

        // We need to get the raw rsa private key as this scheme is not compatible with the usual
        // Arweave RSA-PSS signatures
        let rsa_sk = match wallet.danger_expose_signing_key() {
            SigningKey::Rsa4096(sk) => sk.danger_expose_raw_key(),
            _ => Err(DriveKeyError::UnsupportedKey)?,
        };

        let signing_key = PssSigningKey::<Sha256>::new_with_salt_len(rsa_sk.clone(), 0);

        // RSA-PSS with salt_len=0 is deterministic, consuming no random bytes.
        // Determinism is required here: the signature output feeds into key derivation,
        // so identical inputs must always produce identical derived keys.
        // DummyRng enforces this invariant - any call indicates a misconfiguration.
        let mut rng = DummyRng;

        let sig_v1: Box<[u8]> = signing_key
            .sign_prehash_with_rng(&mut rng, v1_message(drive_id).as_slice())?
            .into();

        let sig_v2: Box<[u8]> = signing_key
            .sign_prehash_with_rng(
                &mut rng,
                v2_message(drive_id, &wallet.address())?.as_slice(),
            )?
            .into();

        Ok(Self {
            v1: hkdf_derive(sig_v1.as_ref(), &password)?,
            v2: hkdf_derive(sig_v2.as_ref(), &password)?,
        })
    }

    pub fn decrypt_metadata(
        &self,
        ciphertext: &[u8],
        nonce: &Nonce<U12>,
        tag: &AesGcmTag<U16>,
        signature_format: SignatureFormat,
    ) -> Result<Vec<u8>, DriveKeyError> {
        let params = AesGcmParams::new(self.key(signature_format), nonce, "".as_bytes());
        let mut plaintext = BytesMut::with_capacity(ciphertext.len());

        let mut ciphertext = Cursor::new(ciphertext);
        AesGcm::decrypt(params, &mut ciphertext, &mut plaintext, &tag)?;
        Ok(plaintext.to_vec())
    }

    pub fn auth_mode(&self) -> AuthMode {
        AuthMode::Password
    }

    fn key(&self, signature_format: SignatureFormat) -> &AesKey<256> {
        match signature_format {
            SignatureFormat::V1 => &self.v1,
            SignatureFormat::V2 => &self.v2,
        }
    }
}

struct DummyRng;

impl RngCore for DummyRng {
    fn next_u32(&mut self) -> u32 {
        unreachable!("dummy rng should not be called during drive key derivation");
    }

    fn next_u64(&mut self) -> u64 {
        unreachable!("dummy rng should not be called during drive key derivation");
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        unreachable!("dummy rng should not be called during drive key derivation");
    }
}

impl CryptoRng for DummyRng {}

pub(crate) trait MetadataCryptor<'a> {
    type EncryptionError: Display + Send + 'static;
    type DecryptionError: Display + Send + 'static;
    fn encrypt(
        &self,
        plaintext_metadata: &[u8],
        drive_key: &DriveKey,
    ) -> Result<Vec<u8>, Self::EncryptionError>;
    fn decrypt(
        &self,
        encrypted_metadata: &[u8],
        drive_key: &DriveKey,
    ) -> Result<Vec<u8>, Self::DecryptionError>;
}

#[derive(Error, Debug)]
pub(crate) enum DefaultMetadataCryptorError {
    #[error("Unimplemented")]
    Unimplemented,
    #[error("Cipher '{0}' is unsupported")]
    UnsupportedCipher(Cipher),
    #[error("IV is missing")]
    IvMissing,
    #[error("ciphertext is too short")]
    CiphertextTooShort,
    #[error(transparent)]
    DriveKeyError(#[from] DriveKeyError),
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("invalid tag")]
    InvalidTag,
}

impl<'a> MetadataCryptor<'a> for () {
    type EncryptionError = DefaultMetadataCryptorError;
    type DecryptionError = DefaultMetadataCryptorError;

    fn encrypt(&self, _: &[u8], _: &DriveKey) -> Result<Vec<u8>, Self::EncryptionError> {
        Err(DefaultMetadataCryptorError::Unimplemented)
    }

    fn decrypt(&self, _: &[u8], _: &DriveKey) -> Result<Vec<u8>, Self::DecryptionError> {
        Err(DefaultMetadataCryptorError::Unimplemented)
    }
}

pub(crate) struct DefaultMetadataCryptor {
    cipher: Cipher,
    nonce: Nonce<U12>,
    signature_format: SignatureFormat,
}

impl DefaultMetadataCryptor {
    pub(crate) fn new(
        cipher: Cipher,
        iv: Option<&[u8]>,
        signature_format: SignatureFormat,
    ) -> Result<Self, DefaultMetadataCryptorError> {
        match cipher {
            Cipher::Aes256Gcm => {}
            other => return Err(DefaultMetadataCryptorError::UnsupportedCipher(other)),
        }

        let iv = iv.ok_or_else(|| DefaultMetadataCryptorError::IvMissing)?;
        let nonce = Nonce::try_from(iv).map_err(|_| DefaultMetadataCryptorError::InvalidNonce)?;
        Ok(Self {
            cipher,
            nonce,
            signature_format,
        })
    }
}

impl MetadataCryptor<'_> for DefaultMetadataCryptor {
    type EncryptionError = DefaultMetadataCryptorError;
    type DecryptionError = DefaultMetadataCryptorError;

    fn encrypt(
        &self,
        plaintext_metadata: &[u8],
        drive_key: &DriveKey,
    ) -> Result<Vec<u8>, Self::EncryptionError> {
        todo!()
    }

    fn decrypt(
        &self,
        encrypted_metadata: &[u8],
        drive_key: &DriveKey,
    ) -> Result<Vec<u8>, Self::DecryptionError> {
        let len = encrypted_metadata.len();
        if len < 16 {
            return Err(DefaultMetadataCryptorError::CiphertextTooShort)?;
        }

        let ciphertext = &encrypted_metadata[..len - 16];
        let tag = AesGcmTag::try_from_bytes(&encrypted_metadata[len - 16..])
            .ok_or_else(|| DefaultMetadataCryptorError::InvalidTag)?;

        Ok(drive_key.decrypt_metadata(ciphertext, &self.nonce, &tag, self.signature_format)?)
    }
}
