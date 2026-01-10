use crate::key_ring::KeyRing;
use crate::types::file::FileId;
use crate::types::{Cipher, SignatureFormat};
use crate::{DriveId, Password};
use ario_core::blob::AsBlob;
use ario_core::bundle::{
    ArweaveScheme, BundleItem, BundleItemBuilder, BundleItemError, V2BundleItemDataProcessor,
};
use ario_core::confidential::{NewSecretExt, RevealExt, RevealMutExt};
use ario_core::crypto::aes::gcm::{AesGcm, AesGcmParams, Tag as AesGcmTag};
use ario_core::crypto::aes::{AesKey, Nonce};
use ario_core::crypto::encryption;
use ario_core::crypto::encryption::DecryptionExt;
use ario_core::crypto::hash::{Hasher, HasherExt, Sha256};
use ario_core::crypto::rsa::RsaPrivateKey;
use ario_core::crypto::rsa::pss::DeterministicRsaPss;
use ario_core::crypto::signature::Signature;
use ario_core::wallet::hazmat::SigningKey;
use ario_core::wallet::{Wallet, WalletSk};
use hkdf::Hkdf;
use hkdf::hmac::digest::array::Array;
use hkdf::hmac::digest::consts::U16;
use rsa::signature::digest::typenum::U12;
use std::fmt::Display;
use std::io::Cursor;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct DriveKey(Arc<AesKey<256>>);

#[derive(Error, Debug)]
pub enum DriveKeyError {
    #[error("only RSA keys can be used with drive keys")]
    UnsupportedKey,
    #[error("error signing message: '{0}'")]
    SignatureError(String),
    #[error(transparent)]
    DecryptionError(#[from] encryption::Error),
    #[error(transparent)]
    BundleItemError(#[from] BundleItemError),
}

fn v1_wallet_sig(
    drive_id: &DriveId,
    sk: &WalletSk<RsaPrivateKey<4096>>,
) -> Result<WalletSignature, DriveKeyError> {
    let mut hasher = Sha256::new();
    hasher.update("drive".as_bytes());
    hasher.update(drive_id.as_ref());
    let hash = hasher.finalize();
    sk.danger_sign_arbitrary_message::<DeterministicRsaPss<4096>>(&(&hash).into())
        .map_err(DriveKeyError::SignatureError)
}

fn v2_wallet_sig(
    drive_id: &DriveId,
    wallet: &Wallet,
    sk: &WalletSk<RsaPrivateKey<4096>>,
) -> Result<WalletSignature, DriveKeyError> {
    let mut payload = Vec::with_capacity(drive_id.as_ref().len() + 5);
    payload.extend_from_slice("drive".as_bytes());
    payload.extend_from_slice(drive_id.as_ref());

    let data = V2BundleItemDataProcessor::from_single_value(payload);

    let draft = BundleItemBuilder::v2()
        .tags(vec![("Action", "Drive-Signature-V2").into()])
        .data_upload(&data)
        .draft()?;

    // hack
    // first, we sign the bundle normally with the regular ArweaveScheme
    let item = match wallet.sign_bundle_item_draft::<ArweaveScheme>(draft)? {
        BundleItem::V2(v2_item) => v2_item,
    };

    // then we extract the raw bundle item hash and sign it with the deterministic scheme
    let hash = Sha256::digest(item.danger_bundle_item_hash().as_slice());
    sk.danger_sign_arbitrary_message::<DeterministicRsaPss<4096>>(&(&hash).into())
        .map_err(DriveKeyError::SignatureError)
}

type WalletSignature = Signature<DeterministicRsaPss<4096>>;

fn hkdf_derive(sig: &WalletSignature, password: &Password) -> AesKey<256> {
    let sig = sig.as_blob();
    let mut buf = vec![0u8; 32].into_boxed_slice().confidential();
    let hkdf = Hkdf::<Sha256>::new(None, sig.as_ref());
    hkdf.expand(password.reveal().as_bytes(), buf.reveal_mut())
        .expect("hkdf expansion to never fail");
    let bytes = Array::try_from(buf.reveal()).expect("length to always be 32 bytes");
    AesKey::from_byte_array(bytes)
}

fn rsa_sk_from_wallet(wallet: &Wallet) -> Result<&WalletSk<RsaPrivateKey<4096>>, DriveKeyError> {
    match wallet.danger_expose_signing_key() {
        SigningKey::Rsa4096(sk) => Ok(sk),
        _ => Err(DriveKeyError::UnsupportedKey)?,
    }
}

impl DriveKey {
    pub(crate) fn derive_v1(
        drive_id: &DriveId,
        wallet: &Wallet,
        password: &Password,
    ) -> Result<Self, DriveKeyError> {
        Ok(Self(Arc::new(hkdf_derive(
            &v1_wallet_sig(drive_id, rsa_sk_from_wallet(wallet)?)?,
            &password,
        ))))
    }

    pub(crate) fn derive_v2(
        drive_id: &DriveId,
        wallet: &Wallet,
        password: &Password,
    ) -> Result<Self, DriveKeyError> {
        Ok(Self(Arc::new(hkdf_derive(
            &v2_wallet_sig(drive_id, wallet, rsa_sk_from_wallet(wallet)?)?,
            &password,
        ))))
    }

    pub fn decrypt_metadata(
        &self,
        ciphertext: &[u8],
        nonce: &Nonce<U12>,
        tag: &AesGcmTag<U16>,
    ) -> Result<Vec<u8>, DriveKeyError> {
        Ok(decrypt_metadata(ciphertext, nonce, tag, &self.0)?)
    }
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct FileKey(Arc<AesKey<256>>);

fn derive_file_key(file_id: &FileId, aes_drive_key: &AesKey<256>) -> AesKey<256> {
    let mut buf = vec![0u8; 32].into_boxed_slice().confidential();
    let hkdf = Hkdf::<Sha256>::new(None, aes_drive_key.danger_reveal_raw_key().as_slice());
    hkdf.expand(file_id.as_ref(), buf.reveal_mut())
        .expect("hkdf expansion to never fail");
    let bytes = Array::try_from(buf.reveal()).expect("length to always be 32 bytes");
    AesKey::from_byte_array(bytes)
}

fn decrypt_metadata(
    ciphertext: &[u8],
    nonce: &Nonce<U12>,
    tag: &AesGcmTag<U16>,
    key: &AesKey<256>,
) -> Result<Vec<u8>, encryption::Error> {
    let params = AesGcmParams::new(key, nonce, "".as_bytes());
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut ciphertext = Cursor::new(ciphertext);
    AesGcm::decrypt(params, &mut ciphertext, &mut plaintext, &tag)?;
    Ok(plaintext)
}

impl FileKey {
    pub fn derive_from(file_id: &FileId, drive_key: &DriveKey) -> Self {
        Self(Arc::new(derive_file_key(file_id, drive_key.0.as_ref())))
    }

    pub fn decrypt_metadata(
        &self,
        ciphertext: &[u8],
        nonce: &Nonce<U12>,
        tag: &AesGcmTag<U16>,
    ) -> Result<Vec<u8>, DriveKeyError> {
        Ok(decrypt_metadata(ciphertext, nonce, tag, &self.0)?)
    }
}

pub(crate) trait MetadataCryptor<'a> {
    type EncryptionError: Display + Send + 'static;
    type DecryptionError: Display + Send + 'static;
    fn encrypt(
        &self,
        plaintext_metadata: &[u8],
        key_ring: &KeyRing,
    ) -> Result<Vec<u8>, Self::EncryptionError>;
    fn decrypt(
        &self,
        encrypted_metadata: &[u8],
        key_ring: &KeyRing,
    ) -> Result<Vec<u8>, Self::DecryptionError>;
}

#[derive(Error, Debug)]
pub(crate) enum MetadataCryptorError {
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
    #[error("no default key is set in key ring")]
    NoDefaultKeyInKeyRing,
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("invalid tag")]
    InvalidTag,
    #[error("decryption failed")]
    DecryptionFailed,
}

impl<'a> MetadataCryptor<'a> for () {
    type EncryptionError = MetadataCryptorError;
    type DecryptionError = MetadataCryptorError;

    fn encrypt(&self, _: &[u8], _: &KeyRing) -> Result<Vec<u8>, Self::EncryptionError> {
        Err(MetadataCryptorError::Unimplemented)
    }

    fn decrypt(&self, _: &[u8], _: &KeyRing) -> Result<Vec<u8>, Self::DecryptionError> {
        Err(MetadataCryptorError::Unimplemented)
    }
}

pub(crate) struct DriveKeyMetadataCryptor {
    nonce: Nonce<U12>,
    signature_format: Option<SignatureFormat>,
}

impl DriveKeyMetadataCryptor {
    pub(crate) fn new(
        cipher: Cipher,
        iv: Option<&[u8]>,
        signature_format: Option<SignatureFormat>,
    ) -> Result<Self, MetadataCryptorError> {
        match cipher {
            Cipher::Aes256Gcm => {}
            other => return Err(MetadataCryptorError::UnsupportedCipher(other)),
        }

        let iv = iv.ok_or_else(|| MetadataCryptorError::IvMissing)?;
        let nonce = Nonce::try_from(iv).map_err(|_| MetadataCryptorError::InvalidNonce)?;
        Ok(Self {
            nonce,
            signature_format,
        })
    }
}

impl MetadataCryptor<'_> for DriveKeyMetadataCryptor {
    type EncryptionError = MetadataCryptorError;
    type DecryptionError = MetadataCryptorError;

    fn encrypt(
        &self,
        plaintext_metadata: &[u8],
        key_ring: &KeyRing,
    ) -> Result<Vec<u8>, Self::EncryptionError> {
        todo!()
    }

    fn decrypt(
        &self,
        encrypted_metadata: &[u8],
        key_ring: &KeyRing,
    ) -> Result<Vec<u8>, Self::DecryptionError> {
        let (ciphertext, tag) = prepare_encrypted_metadata(encrypted_metadata)?;

        let drive_key = match self.signature_format {
            Some(SignatureFormat::V1) => key_ring.v1_drive_key(),
            Some(SignatureFormat::V2) => key_ring.v2_drive_key(),
            None => key_ring
                .drive_key()
                .ok_or_else(|| MetadataCryptorError::NoDefaultKeyInKeyRing)?,
        };

        Ok(drive_key.decrypt_metadata(ciphertext, &self.nonce, &tag)?)
    }
}

pub(crate) struct FileMetadataCryptor<'a> {
    file_id: &'a FileId,
    nonce: Nonce<U12>,
    signature_format: Option<SignatureFormat>,
}

impl<'a> FileMetadataCryptor<'a> {
    pub(crate) fn new(
        cipher: Cipher,
        iv: Option<&[u8]>,
        file_id: &'a FileId,
        signature_format: Option<SignatureFormat>,
    ) -> Result<Self, MetadataCryptorError> {
        match cipher {
            Cipher::Aes256Gcm => {} // todo: this might not be correct for file metadata
            other => return Err(MetadataCryptorError::UnsupportedCipher(other)),
        }

        let iv = iv.ok_or_else(|| MetadataCryptorError::IvMissing)?;
        let nonce = Nonce::try_from(iv).map_err(|_| MetadataCryptorError::InvalidNonce)?;
        Ok(Self {
            file_id,
            nonce,
            signature_format,
        })
    }
}

impl<'a> MetadataCryptor<'a> for FileMetadataCryptor<'a> {
    type EncryptionError = MetadataCryptorError;
    type DecryptionError = MetadataCryptorError;

    fn encrypt(
        &self,
        plaintext_metadata: &[u8],
        key_ring: &KeyRing,
    ) -> Result<Vec<u8>, Self::EncryptionError> {
        todo!()
    }

    fn decrypt(
        &self,
        encrypted_metadata: &[u8],
        key_ring: &KeyRing,
    ) -> Result<Vec<u8>, Self::DecryptionError> {
        let (ciphertext, tag) = prepare_encrypted_metadata(encrypted_metadata)?;

        let file_key = match self.signature_format {
            Some(SignatureFormat::V1) => key_ring.v1_file_key(self.file_id),
            Some(SignatureFormat::V2) => key_ring.v2_file_key(self.file_id),
            None => key_ring
                .file_key(self.file_id)
                .ok_or_else(|| MetadataCryptorError::NoDefaultKeyInKeyRing)?,
        };

        Ok(file_key.decrypt_metadata(ciphertext, &self.nonce, &tag)?)
    }
}

fn prepare_encrypted_metadata(
    encrypted_metadata: &[u8],
) -> Result<(&[u8], AesGcmTag<U16>), MetadataCryptorError> {
    let len = encrypted_metadata.len();
    if len < 16 {
        return Err(MetadataCryptorError::CiphertextTooShort)?;
    }

    let ciphertext = &encrypted_metadata[..len - 16];
    let tag = AesGcmTag::try_from_bytes(&encrypted_metadata[len - 16..])
        .ok_or_else(|| MetadataCryptorError::InvalidTag)?;

    Ok((ciphertext, tag))
}
