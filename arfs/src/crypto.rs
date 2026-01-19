use crate::key_ring::KeyRing;
use crate::types::file::FileId;
use crate::types::{Cipher, SignatureFormat};
use crate::vfs::FileReader;
use crate::{DriveId, Password};
use ario_core::blob::{AsBlob, OwnedBlob};
use ario_core::bundle::{
    ArweaveScheme, BundleItem, BundleItemBuilder, BundleItemError, V2BundleItemDataProcessor,
};
use ario_core::confidential::{NewSecretExt, RevealExt, RevealMutExt};
use ario_core::crypto::aes::ctr::{AesCtr, AesCtrParams};
use ario_core::crypto::aes::gcm::{AesGcmParams, DefaultAesGcm, Tag as AesGcmTag, Tag};
use ario_core::crypto::aes::{AesKey, Nonce};
use ario_core::crypto::encryption::encryption::EncryptingWriter as CoreEncryptingWriter;
use ario_core::crypto::encryption::{DecryptionExt, EncryptionExt, Encryptor};
use ario_core::crypto::hash::{Hasher, HasherExt, Sha256};
use ario_core::crypto::rsa::RsaPrivateKey;
use ario_core::crypto::rsa::pss::DeterministicRsaPss;
use ario_core::crypto::signature::Signature;
use ario_core::crypto::{OutputLen, encryption};
use ario_core::wallet::hazmat::SigningKey;
use ario_core::wallet::{Wallet, WalletSk};
use async_trait::async_trait;
use futures_lite::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite};
use hkdf::Hkdf;
use hkdf::hmac::digest::array::Array;
use hkdf::hmac::digest::consts::U16;
use rsa::signature::digest::typenum::U12;
use std::fmt::Display;
use std::io::{Cursor, SeekFrom};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
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
        tag: AesGcmTag<U16>,
    ) -> Result<Vec<u8>, DriveKeyError> {
        Ok(decrypt_metadata(ciphertext, nonce, tag, &self.0)?)
    }

    pub fn encrypt_metadata(
        &self,
        plaintext: &[u8],
        nonce: &Nonce<U12>,
    ) -> Result<Vec<u8>, DriveKeyError> {
        Ok(encrypt_metadata(plaintext, nonce, &self.0)?)
    }
}

#[derive(Error, Debug)]
pub enum FileKeyError {
    #[error(transparent)]
    DecryptionError(#[from] encryption::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("Cipher '{0}' not supported")]
    UnsupportedCipher(Cipher),
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("invalid tag")]
    InvalidTag,
    #[error("IV is missing")]
    IvMissing,
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
    tag: AesGcmTag<U16>,
    key: &AesKey<256>,
) -> Result<Vec<u8>, encryption::Error> {
    let params = AesGcmParams::new(key, nonce, "".as_bytes());
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut ciphertext = Cursor::new(ciphertext);
    DefaultAesGcm::decrypt(params, &mut ciphertext, &mut plaintext, tag)?;
    Ok(plaintext)
}

fn encrypt_metadata(
    plaintext: &[u8],
    nonce: &Nonce<U12>,
    key: &AesKey<256>,
) -> Result<Vec<u8>, encryption::Error> {
    let params = AesGcmParams::new(key, nonce, "".as_bytes());
    let len = plaintext.len();
    let mut plaintext = Cursor::new(plaintext);
    let mut ciphertext = Vec::with_capacity(len + U16::to_usize());
    let tag = DefaultAesGcm::encrypt(params, &mut plaintext, &mut ciphertext)?.into_bytes();
    // append the tag
    ciphertext.extend_from_slice(tag.as_slice());
    Ok(ciphertext)
}

impl FileKey {
    pub fn derive_from(file_id: &FileId, drive_key: &DriveKey) -> Self {
        Self(Arc::new(derive_file_key(file_id, drive_key.0.as_ref())))
    }

    pub fn decrypt_metadata(
        &self,
        ciphertext: &[u8],
        nonce: &Nonce<U12>,
        tag: AesGcmTag<U16>,
    ) -> Result<Vec<u8>, FileKeyError> {
        Ok(decrypt_metadata(ciphertext, nonce, tag, &self.0)?)
    }

    pub async fn decrypt_content<'a, T: AsyncRead + AsyncSeek + Send + Sync + Unpin + 'a>(
        &self,
        mut ciphertext: T,
        plaintext_len: u64,
        cipher: Cipher,
        iv: Option<OwnedBlob>,
    ) -> Result<Box<dyn FileReader + 'a>, FileKeyError> {
        let iv = iv.ok_or_else(|| FileKeyError::IvMissing)?;
        let nonce = Nonce::try_from(iv).map_err(|_| FileKeyError::InvalidNonce)?;

        match cipher {
            Cipher::Aes256Gcm => {
                // read tag first
                ciphertext.seek(SeekFrom::Start(plaintext_len)).await?;
                let mut buf = vec![0u8; 16];
                ciphertext.read_exact(&mut buf).await?;
                ciphertext.seek(SeekFrom::Start(0)).await?;
                let tag = Tag::try_from_bytes(buf.as_slice()).ok_or(FileKeyError::InvalidTag)?;

                let ciphertext = Take::new(ciphertext, 0, plaintext_len); // trim the tag as we have to ignore it
                let params = AesGcmParams::new(self.0.as_ref().clone(), nonce, b"");
                Ok(Box::new(DefaultAesGcm::decrypting_async_reader(
                    params, ciphertext, tag,
                )?))
            }
            Cipher::Aes256Ctr => {
                let params = AesCtrParams::new(self.0.as_ref().clone(), nonce);
                Ok(Box::new(AesCtr::decrypting_async_reader(
                    params,
                    ciphertext,
                    (),
                )?))
            }
        }
    }

    pub fn encrypt_metadata(
        &self,
        plaintext: &[u8],
        nonce: &Nonce<U12>,
    ) -> Result<Vec<u8>, DriveKeyError> {
        Ok(encrypt_metadata(plaintext, nonce, &self.0)?)
    }

    pub async fn encrypt_content<'a, T: AsyncWrite + Send + Sync + Unpin + 'a>(
        &self,
        ciphertext: T,
        cipher: Cipher,
        iv: Option<OwnedBlob>,
    ) -> Result<Box<dyn EncryptingWriter + 'a>, FileKeyError> {
        let iv = iv.ok_or_else(|| FileKeyError::IvMissing)?;
        let nonce = Nonce::try_from(iv).map_err(|_| FileKeyError::InvalidNonce)?;
        match cipher {
            Cipher::Aes256Gcm => {
                let params = AesGcmParams::new(self.0.as_ref().clone(), nonce, b"");
                Ok(Box::new(DefaultAesGcm::encrypting_async_writer(
                    params, ciphertext,
                )?))
            }
            Cipher::Aes256Ctr => {
                let params = AesCtrParams::new(self.0.as_ref().clone(), nonce);
                Ok(Box::new(AesCtr::encrypting_async_writer(
                    params, ciphertext,
                )?))
            }
        }
    }
}

pub trait EncryptingWriter: AsyncWrite + FinalizeWithTag + Send + Sync + Unpin {}
impl<T> EncryptingWriter for T where T: AsyncWrite + FinalizeWithTag + Send + Sync + Unpin {}

#[async_trait]
pub trait FinalizeWithTag {
    async fn finalize(self: Box<Self>) -> std::io::Result<OwnedBlob>;
}

#[async_trait]
impl<'a, E: Encryptor<'a>, W: AsyncWrite> FinalizeWithTag for CoreEncryptingWriter<'a, E, W>
where
    W: Unpin + Send,
    E: Unpin + Send,
{
    async fn finalize(self: Box<Self>) -> std::io::Result<OwnedBlob> {
        let maybe_tag = CoreEncryptingWriter::finalize_async_boxed(self).await?;
        Ok(maybe_tag.into())
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
    #[error(transparent)]
    FileKeyError(#[from] FileKeyError),
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

    fn drive_key(&self, key_ring: &KeyRing) -> Result<DriveKey, MetadataCryptorError> {
        Ok(match self.signature_format {
            Some(SignatureFormat::V1) => key_ring.v1_drive_key(),
            Some(SignatureFormat::V2) => key_ring.v2_drive_key(),
            None => key_ring
                .drive_key()
                .ok_or_else(|| MetadataCryptorError::NoDefaultKeyInKeyRing)?,
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
        let drive_key = self.drive_key(key_ring)?;
        Ok(drive_key.encrypt_metadata(plaintext_metadata, &self.nonce)?)
    }

    fn decrypt(
        &self,
        encrypted_metadata: &[u8],
        key_ring: &KeyRing,
    ) -> Result<Vec<u8>, Self::DecryptionError> {
        let (ciphertext, tag) = prepare_encrypted_metadata(encrypted_metadata)?;
        let drive_key = self.drive_key(key_ring)?;
        Ok(drive_key.decrypt_metadata(ciphertext, &self.nonce, tag)?)
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
            Cipher::Aes256Gcm => {}
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

    fn file_key(&self, key_ring: &KeyRing) -> Result<FileKey, MetadataCryptorError> {
        Ok(match self.signature_format {
            Some(SignatureFormat::V1) => key_ring.v1_file_key(self.file_id),
            Some(SignatureFormat::V2) => key_ring.v2_file_key(self.file_id),
            None => key_ring
                .file_key(self.file_id)
                .ok_or_else(|| MetadataCryptorError::NoDefaultKeyInKeyRing)?,
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
        let file_key = self.file_key(key_ring)?;
        Ok(file_key.encrypt_metadata(plaintext_metadata, &self.nonce)?)
    }

    fn decrypt(
        &self,
        encrypted_metadata: &[u8],
        key_ring: &KeyRing,
    ) -> Result<Vec<u8>, Self::DecryptionError> {
        let (ciphertext, tag) = prepare_encrypted_metadata(encrypted_metadata)?;
        let file_key = self.file_key(key_ring)?;
        Ok(file_key.decrypt_metadata(ciphertext, &self.nonce, tag)?)
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

pub struct Take<T> {
    inner: T,
    limit: u64,
    pos: u64,
}

impl<T> Take<T> {
    pub fn new(inner: T, current_pos: u64, limit: u64) -> Self {
        Self {
            inner,
            limit,
            pos: current_pos,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Take<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let remaining = self.limit.saturating_sub(self.pos) as usize;
        if remaining == 0 {
            return Poll::Ready(Ok(0));
        }
        let max = buf.len().min(remaining);
        let result = Pin::new(&mut self.inner).poll_read(cx, &mut buf[..max]);
        if let Poll::Ready(Ok(n)) = result {
            self.pos = self.pos.saturating_add(n as u64);
        }
        result
    }
}

impl<T: AsyncSeek + Unpin> AsyncSeek for Take<T> {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<std::io::Result<u64>> {
        let oob = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek out of bounds");

        let target = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(n) => self.pos.checked_add_signed(n).ok_or_else(oob)?,
            SeekFrom::End(n) if n <= 0 => self.limit.checked_add_signed(n).ok_or_else(oob)?,
            SeekFrom::End(_) => return Poll::Ready(Err(oob())),
        };

        if target > self.limit {
            return Poll::Ready(Err(oob()));
        }

        if target == self.pos {
            return Poll::Ready(Ok(target));
        }

        let result = Pin::new(&mut self.inner).poll_seek(cx, SeekFrom::Start(target));
        if let Poll::Ready(Ok(pos)) = result {
            self.pos = pos;
            Poll::Ready(Ok(pos))
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{AesGcmTag, FileKey};
    use crate::types::Cipher;
    use crate::types::file::FileId;
    use crate::{DriveId, KeyRing};
    use ario_core::blob::OwnedBlob;
    use ario_core::crypto::aes::Nonce;
    use ario_core::jwk::Jwk;
    use ario_core::wallet::Wallet;
    use futures_lite::io::Cursor;
    use futures_lite::{AsyncReadExt, AsyncWriteExt};
    use hkdf::hmac::digest::consts::U12;
    use rsa::signature::digest::crypto_common::Generate;
    use std::str::FromStr;

    static WALLET_RSA_JWK: &'static [u8] =
        include_bytes!("../../ario-core/testdata/ar_wallet_tests_PS256_65537_fixture.json");

    static TEST_FILE: &'static [u8] = include_bytes!("../../ario-core/testdata/1mb.bin");

    fn init() -> anyhow::Result<KeyRing> {
        let wallet = Wallet::from_jwk(&Jwk::from_json(WALLET_RSA_JWK)?)?;
        Ok(KeyRing::builder()
            .drive_id(&DriveId::from_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8")?)
            .password("test-password".to_string())
            .wallet(&wallet)
            .build()?)
    }

    #[test]
    fn metadata_encryption_roundtrip() -> anyhow::Result<()> {
        let key_ring = init()?;
        let reference_pt = "This is a short metadata test. Data is held in memory.".as_bytes();
        let len = reference_pt.len();
        let nonce = Nonce::<U12>::generate();

        let v1_drive_key = key_ring.v1_drive_key();
        let encrypted_metadata = v1_drive_key.encrypt_metadata(reference_pt, &nonce)?;
        let ciphertext = &encrypted_metadata[..len];
        let tag = AesGcmTag::try_from_bytes(&encrypted_metadata[len..]).unwrap();
        let plaintext = v1_drive_key.decrypt_metadata(ciphertext, &nonce, tag)?;
        assert_eq!(plaintext.as_slice(), reference_pt);

        let v2_drive_key = key_ring.v2_drive_key();
        let encrypted_metadata = v2_drive_key.encrypt_metadata(reference_pt, &nonce)?;
        let ciphertext = &encrypted_metadata[..len];
        let tag = AesGcmTag::try_from_bytes(&encrypted_metadata[len..]).unwrap();
        let plaintext = v2_drive_key.decrypt_metadata(ciphertext, &nonce, tag)?;
        assert_eq!(plaintext.as_slice(), reference_pt);

        let file_id = FileId::from_str("b1a2a3a4-a1b2-c1c2-c1d2-f3d4d5a1d7d8")?;

        let v1_file_key = key_ring.v1_file_key(&file_id);
        let encrypted_metadata = v1_file_key.encrypt_metadata(reference_pt, &nonce)?;
        let ciphertext = &encrypted_metadata[..len];
        let tag = AesGcmTag::try_from_bytes(&encrypted_metadata[len..]).unwrap();
        let plaintext = v1_file_key.decrypt_metadata(ciphertext, &nonce, tag)?;
        assert_eq!(plaintext.as_slice(), reference_pt);

        let v2_file_key = key_ring.v2_file_key(&file_id);
        let encrypted_metadata = v2_file_key.encrypt_metadata(reference_pt, &nonce)?;
        let ciphertext = &encrypted_metadata[..len];
        let tag = AesGcmTag::try_from_bytes(&encrypted_metadata[len..]).unwrap();
        let plaintext = v2_file_key.decrypt_metadata(ciphertext, &nonce, tag)?;
        assert_eq!(plaintext.as_slice(), reference_pt);

        Ok(())
    }

    #[tokio::test]
    async fn file_encryption_roundtrip() -> anyhow::Result<()> {
        let key_ring = init()?;
        let file_id = FileId::from_str("c2a2a3a4-61b2-c1c2-c1d2-f3d4d5a1d7d8")?;
        let ciphers = [Cipher::Aes256Gcm, Cipher::Aes256Ctr];
        for cipher in ciphers {
            let nonce = cipher.generate_nonce();

            let v1_file_key = key_ring.v1_file_key(&file_id);
            test_file_encryption(&v1_file_key, cipher, nonce.clone(), TEST_FILE).await?;

            let v2_file_key = key_ring.v2_file_key(&file_id);
            test_file_encryption(&v2_file_key, cipher, nonce.clone(), TEST_FILE).await?;
        }
        Ok(())
    }

    async fn test_file_encryption(
        file_key: &FileKey,
        cipher: Cipher,
        nonce: OwnedBlob,
        plaintext: &[u8],
    ) -> anyhow::Result<()> {
        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);
        let mut encryptor = file_key
            .encrypt_content(&mut cursor, cipher, Some(nonce.clone()))
            .await?;
        let n = futures_lite::io::copy(Cursor::new(plaintext), &mut encryptor).await?;
        assert_eq!(n, plaintext.len() as u64);
        let tag = encryptor.finalize().await?;
        cursor.write_all(tag.bytes()).await?;
        cursor.close().await?;

        let cursor = Cursor::new(&buffer);
        let mut decryptor = file_key
            .decrypt_content(cursor, plaintext.len() as u64, cipher, Some(nonce))
            .await?;
        let mut buffer = Vec::with_capacity(plaintext.len());
        decryptor.read_to_end(&mut buffer).await?;
        assert_eq!(buffer.as_slice(), plaintext);
        Ok(())
    }
}
