use crate::buffer::BufError;
use crate::confidential::RevealExt;
use crate::crypto::aes::ctr::AesCtrCore;
use crate::crypto::aes::{Aes, AesCipher, AesKey, Block, BlockFragment, Nonce, Op};
use crate::crypto::encryption::hazmat::SeekableDecryptor;
use crate::crypto::encryption::{Decryptor, Encryptor, Scheme};
use aes::cipher::typenum::U16;
use aes::cipher::{BlockCipherEncrypt, InnerIvInit, KeyInit, StreamCipherCore, crypto_common};
use bytes::{Buf, BufMut};
use crypto_common::BlockSizeUser;
use ghash::GHash;
use ghash::universal_hash::UniversalHash;
use hybrid_array::typenum::U12;
use hybrid_array::{Array, ArraySize};
use maybe_owned::MaybeOwned;
use std::borrow::Cow;
use std::marker::PhantomData;
use thiserror::Error;
use zeroize::Zeroize;

/// Maximum length of associated data.
const A_MAX: u64 = 1 << 36;

/// Maximum length of plaintext.
const P_MAX: u64 = 1 << 36;

/// Maximum length of ciphertext.
const C_MAX: u64 = (1 << 36) + 16;

type CtrFlavour = ctr::flavors::Ctr32BE;
type Ctr<const BIT: usize> = super::ctr::CoreCtr<BIT, CtrFlavour>;

pub type DefaultAesGcm<const BIT: usize> = AesGcm<BIT, U16, U12>;

pub struct AesGcm<const BIT: usize, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    core: AesCtrCore<BIT, CtrFlavour, NonceSize, P_MAX, C_MAX, 1>,
    ghash: GHash,
    mask: Block<BIT>,
    aad_len: u64,
    _marker: PhantomData<TagSize>,
}

pub trait SupportedAesCiphers<const BIT: usize> {}

impl SupportedAesCiphers<256> for aes::Aes256 {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Tag<TagSize>(Array<u8, TagSize>)
where
    TagSize: ValidTagSize;

impl<TagSize> Tag<TagSize>
where
    TagSize: ValidTagSize,
{
    pub fn try_from_bytes<T: AsRef<[u8]>>(input: T) -> Option<Self> {
        let len = TagSize::to_usize();
        let input = input.as_ref();
        if input.len() != len {
            //todo
            return None;
        }
        Some(Self(Array::try_from(input).unwrap()))
    }
}

impl<const BIT: usize, TagSize, NonceSize> AesGcm<BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    fn new(key: &AesKey<BIT>, nonce: &Nonce<NonceSize>, aad: &[u8]) -> Result<Self, Error> {
        if aad.len() as u64 > A_MAX {
            return Err(Error::AssociatedDataTooLong);
        }

        let cipher = <Aes<BIT> as AesCipher>::Cipher::new(key.0.reveal());
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);

        let mut ghash = GHash::new(&ghash_key);
        ghash_key.zeroize();

        let (ctr, mask) = Self::init_ctr(cipher, &ghash, nonce);

        ghash.update_padded(aad);

        let core = AesCtrCore::new(ctr, 0);

        Ok(Self {
            core,
            mask,
            ghash,
            aad_len: aad.len() as u64,
            _marker: PhantomData,
        })
    }

    #[inline]
    fn position(&self) -> u64 {
        self.core.position()
    }

    #[inline]
    fn seek(&mut self, pos: u64) -> Result<(), Error> {
        Ok(self.core.seek(pos)?)
    }

    /// Taken from https://github.com/RustCrypto/AEADs/blob/master/aes-gcm/src/lib.rs
    ///
    /// Initialize counter mode.
    ///
    /// See algorithm described in Section 7.2 of NIST SP800-38D:
    /// <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>
    ///
    /// > Define a block, J0, as follows:
    /// > If len(IV)=96, then J0 = IV || 0{31} || 1.
    /// > If len(IV) ≠ 96, then let s = 128 ⎡len(IV)/128⎤-len(IV), and
    /// >     J0=GHASH(IV||0s+64||[len(IV)]64).
    fn init_ctr(
        cipher: <Aes<BIT> as AesCipher>::Cipher,
        ghash: &GHash,
        nonce: &Nonce<NonceSize>,
    ) -> (Ctr<BIT>, Block<BIT>) {
        let j0 = if NonceSize::to_usize() == 12 {
            let mut block = Block::default();
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            block
        } else {
            let mut ghash = ghash.clone();
            ghash.update_padded(nonce);

            let mut block = Block::default();
            let nonce_bits = (NonceSize::to_usize() as u64) * 8;
            block[8..].copy_from_slice(&nonce_bits.to_be_bytes());
            ghash.update(&[block]);
            ghash.finalize()
        };

        let mut ctr = Ctr::inner_iv_init(cipher, &j0);
        let mut tag_mask = Block::default();
        ctr.write_keystream_block(&mut tag_mask);
        (ctr, tag_mask)
    }

    #[inline]
    fn update(&mut self, input: &[u8], output: &mut [u8], op: Op) -> Result<u64, Error> {
        Ok(self.core.update(
            input,
            output,
            |blocks| {
                self.ghash.update(blocks);
            },
            op,
        )?)
    }

    #[inline]
    fn finalize(mut self, input: &[u8], output: &mut [u8], op: Op) -> Result<Tag<TagSize>, Error> {
        let pos = self.core.finalize(
            input,
            output,
            |buf| {
                self.ghash.update_padded(buf);
            },
            op,
        )?;

        // generate tag

        let aad_len_bits = self.aad_len * 8;
        let input_len_bits = pos * 8;

        let mut block = Block::default();
        block[..8].copy_from_slice(&aad_len_bits.to_be_bytes());
        block[8..].copy_from_slice(&input_len_bits.to_be_bytes());
        self.ghash.update(&[block]);

        let mut full_tag = self.ghash.finalize();
        for (a, b) in full_tag.as_mut_slice().iter_mut().zip(self.mask.as_slice()) {
            *a ^= *b;
        }

        // trim to TagSize
        let tag_len = TagSize::to_usize();
        assert!(full_tag.len() >= tag_len);
        let tag_value = &full_tag.0.as_slice()[..tag_len];

        Ok(Tag(Array::try_from(tag_value).unwrap()))
    }
}

pub trait ValidTagSize: private::SealedTagSize {}

impl<T: private::SealedTagSize> ValidTagSize for T {}

mod private {
    use hybrid_array::ArraySize;
    use hybrid_array::typenum::{Unsigned, consts};

    pub trait SealedTagSize: ArraySize + Unsigned {}

    impl SealedTagSize for consts::U12 {}
    impl SealedTagSize for consts::U13 {}
    impl SealedTagSize for consts::U14 {}
    impl SealedTagSize for consts::U15 {}
    impl SealedTagSize for consts::U16 {}
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    BufError(#[from] BufError),
    #[error(transparent)]
    CtrError(#[from] super::ctr::Error),
    #[error("associated data exceeds maximum length")]
    AssociatedDataTooLong,
    #[error("ciphertext exceeds maximum allowed length")]
    CiphertextTooLong,
    #[error("plaintext exceeds maximum allowed length")]
    PlaintextTooLong,
    #[error("invalid seek position: '{0}' - must be aligned with block size")]
    InvalidSeekPosition(u64),
    #[error("decryption error")]
    DecryptionError,
}

impl From<Error> for super::ctr::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::CtrError(e) => e,
            other => super::ctr::Error::Other(other.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct AesGcmParams<'a, const BIT: usize, NonceSize>
where
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    key: MaybeOwned<'a, AesKey<BIT>>,
    nonce: MaybeOwned<'a, Nonce<NonceSize>>,
    aad: Cow<'a, [u8]>,
}

impl<'a, const BIT: usize, NonceSize> AesGcmParams<'a, BIT, NonceSize>
where
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    pub fn new(
        key: impl Into<MaybeOwned<'a, AesKey<BIT>>>,
        nonce: impl Into<MaybeOwned<'a, Nonce<NonceSize>>>,
        aad: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        Self {
            key: key.into(),
            nonce: nonce.into(),
            aad: aad.into(),
        }
    }
}

impl<const BIT: usize, TagSize, NonceSize> Scheme for AesGcm<BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
    Tag<TagSize>: Unpin,
{
    type Encryptor<'a> = AesGcmEncryptor<'a, BIT, TagSize, NonceSize>;
    type EncryptionParams<'a> = AesGcmParams<'a, BIT, NonceSize>;
    type Decryptor<'a> = AesGcmDecryptor<'a, BIT, TagSize, NonceSize>;
    type DecryptionParams<'a> = AesGcmParams<'a, BIT, NonceSize>;
    type Error = super::ctr::Error;

    fn new_encryptor<'a>(
        params: Self::EncryptionParams<'a>,
    ) -> Result<Self::Encryptor<'a>, Self::Error> {
        let aes_gcm = AesGcm::new(
            params.key.as_ref(),
            params.nonce.as_ref(),
            params.aad.as_ref(),
        )?;
        Ok(AesGcmEncryptor {
            aes_gcm,
            params,
            block_fragment: BlockFragment::new(),
        })
    }

    fn new_decryptor<'a>(
        params: Self::DecryptionParams<'a>,
    ) -> Result<Self::Decryptor<'a>, Self::Error> {
        let aes_gcm = AesGcm::new(
            params.key.as_ref(),
            params.nonce.as_ref(),
            params.aad.as_ref(),
        )?;
        Ok(AesGcmDecryptor {
            aes_gcm,
            params,
            block_fragment: BlockFragment::new(),
        })
    }
}

pub struct AesGcmEncryptor<'a, const BIT: usize, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    aes_gcm: AesGcm<BIT, TagSize, NonceSize>,
    params: AesGcmParams<'a, BIT, NonceSize>,
    block_fragment: BlockFragment<BIT>,
}

impl<'a, const BIT: usize, TagSize, NonceSize> Encryptor<'a>
    for AesGcmEncryptor<'a, BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    type Error = super::ctr::Error;
    type AuthenticationTag = Tag<TagSize>;
    type Alignment = <<Aes<BIT> as AesCipher>::Cipher as BlockSizeUser>::BlockSize;

    fn position(&self) -> u64 {
        self.aes_gcm.position()
    }

    fn update<I: Buf, O: BufMut>(
        &mut self,
        plaintext: &mut I,
        ciphertext: &mut O,
    ) -> Result<(), Self::Error> {
        process(
            plaintext,
            ciphertext,
            &mut self.block_fragment,
            &mut self.aes_gcm,
            Op::Enc,
        )?;
        Ok(())
    }

    fn finalize(self) -> Result<(Self::AuthenticationTag, Option<Vec<u8>>), Self::Error> {
        let (auth_res, residual) =
            process_finalize(self.block_fragment, |plaintext, ciphertext| {
                let tag = self.aes_gcm.finalize(plaintext, ciphertext, Op::Enc)?;
                Ok(tag)
            });
        let tag = auth_res?;
        Ok((tag, residual))
    }
}

pub struct AesGcmDecryptor<'a, const BIT: usize, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    aes_gcm: AesGcm<BIT, TagSize, NonceSize>,
    params: AesGcmParams<'a, BIT, NonceSize>,
    block_fragment: BlockFragment<BIT>,
}

impl<'a, const BIT: usize, TagSize, NonceSize> AesGcmDecryptor<'a, BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    fn finalize_authenticated(self, tag: &Tag<TagSize>) -> (Result<(), Error>, Option<Vec<u8>>) {
        use subtle::ConstantTimeEq;

        process_finalize(self.block_fragment, |ciphertext, plaintext| {
            let generated_tag = self.aes_gcm.finalize(ciphertext, plaintext, Op::Dec)?;
            if tag.0.ct_eq(&generated_tag.0).into() {
                Ok(())
            } else {
                Err(Error::DecryptionError)
            }
        })
    }
}

impl<'a, const BIT: usize, TagSize, NonceSize> Decryptor<'a>
    for AesGcmDecryptor<'a, BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
    Tag<TagSize>: Unpin,
{
    type Error = super::ctr::Error;
    type AuthenticationTag = Tag<TagSize>;
    type Alignment = <<Aes<BIT> as AesCipher>::Cipher as BlockSizeUser>::BlockSize;

    fn position(&self) -> u64 {
        self.aes_gcm.position()
    }

    fn update<I: Buf, O: BufMut>(
        &mut self,
        ciphertext: &mut I,
        plaintext: &mut O,
    ) -> Result<(), Self::Error> {
        process(
            ciphertext,
            plaintext,
            &mut self.block_fragment,
            &mut self.aes_gcm,
            Op::Dec,
        )?;
        Ok(())
    }

    fn finalize(self, tag: &Self::AuthenticationTag) -> (Result<(), Self::Error>, Option<Vec<u8>>) {
        let (auth_res, residual) = self.finalize_authenticated(tag);
        (auth_res.map_err(|e| e.into()), residual)
    }
}

impl<'a, const BIT: usize, TagSize, NonceSize> SeekableDecryptor<'a>
    for AesGcmDecryptor<'a, BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
    Tag<TagSize>: Unpin,
{
    fn seek(&mut self, position: u64) -> Result<(), Self::Error> {
        let current_pos = self.aes_gcm.position();
        if position == current_pos {
            return Ok(());
        }

        self.aes_gcm.seek(position)?;
        self.block_fragment.clear();
        Ok(())
    }
}

fn process<I: Buf, O: BufMut, const BIT: usize, TagSize, NonceSize>(
    input: &mut I,
    output: &mut O,
    block_fragment: &mut BlockFragment<BIT>,
    aes_gcm: &mut AesGcm<BIT, TagSize, NonceSize>,
    op: Op,
) -> Result<(), Error>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    Ok(super::process(
        input,
        output,
        block_fragment,
        |input, output| aes_gcm.update(input, output, op).map(|n| n as usize),
    )?)
}

fn process_finalize<T, const BIT: usize>(
    block_fragment: BlockFragment<BIT>,
    handler: impl FnOnce(&[u8], &mut [u8]) -> Result<T, Error>,
) -> (Result<T, Error>, Option<Vec<u8>>)
where
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    let (auth_res, residual) = super::process_finalize(block_fragment, handler);
    (auth_res.map_err(|e| e.into()), residual)
}

#[cfg(test)]
mod tests {
    use crate::crypto::aes::AesKey;
    use crate::crypto::aes::gcm::{AesGcmParams, DefaultAesGcm, Nonce, Tag};
    use crate::crypto::encryption::DecryptionExt;
    use crate::crypto::encryption::EncryptionExt;
    use aes::cipher::consts::U12;
    use bytes::BytesMut;
    use futures_lite::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
    use hex_literal::hex;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    static ONE_MB: &'static [u8] = include_bytes!("../../../testdata/1mb.bin");

    // taken from https://github.com/RustCrypto/AEADs/blob/master/aes-gcm/tests/common/mod.rs
    #[derive(Debug)]
    pub struct TestVector<K: 'static, N: 'static> {
        pub key: &'static K,
        pub nonce: &'static N,
        pub aad: &'static [u8],
        pub plaintext: &'static [u8],
        pub ciphertext: &'static [u8],
        pub tag: &'static [u8; 16],
    }

    include!("../../../testdata/aes_gcm_256_nist.tests");

    /*const TEST_VECTORS: &[TestVector<[u8; 32], [u8; 12]>] = &[TestVector {
        key: &hex!("82c4f12eeec3b2d3d157b0f992d292b237478d2cecc1d5f161389b97f999057a"),
        nonce: &hex!("7b40b20f5f397177990ef2d1"),
        plaintext: &hex!("982a296ee1cd7086afad976945"),
        aad: b"",
        ciphertext: &hex!("ec8e05a0471d6b43a59ca5335f"),
        tag: &hex!("113ddeafc62373cac2f5951bb9165249"),
    }];*/

    fn to_params(test: &TestVector<[u8; 32], [u8; 12]>) -> AesGcmParams<'_, 256, U12> {
        let key = AesKey::try_from_bytes(test.key.as_slice()).unwrap();
        let nonce: Nonce<U12> = test.nonce.as_slice().try_into().unwrap();
        AesGcmParams::new(key, nonce, test.aad)
    }

    #[test]
    fn simple_enc() -> anyhow::Result<()> {
        for test in TEST_VECTORS {
            let params = to_params(test);
            let mut plaintext = Cursor::new(test.plaintext);

            let mut output = BytesMut::with_capacity(test.ciphertext.len());
            let tag = DefaultAesGcm::encrypt(params, &mut plaintext, &mut output)?;
            let ciphertext = output.freeze();
            assert_eq!(ciphertext.to_vec().as_slice(), test.ciphertext);
            assert_eq!(tag.0.as_slice(), test.tag.as_slice());
            //println!("{}", hex::encode(test.key.as_slice()));
        }
        Ok(())
    }

    #[test]
    fn simple_dec() -> anyhow::Result<()> {
        for test in TEST_VECTORS {
            let params = to_params(test);
            let mut ciphertext = Cursor::new(test.ciphertext);
            let tag = Tag::try_from_bytes(test.tag.as_slice()).unwrap();

            let mut output = BytesMut::with_capacity(test.plaintext.len());
            DefaultAesGcm::decrypt(params, &mut ciphertext, &mut output, tag)?;
            let plaintext = output.freeze();
            assert_eq!(plaintext.to_vec().as_slice(), test.plaintext);
        }
        Ok(())
    }

    #[test]
    fn readwrite_roundtrip() -> anyhow::Result<()> {
        let mut plaintext_reader = Cursor::new(ONE_MB);
        let mut ciphertext = Vec::with_capacity(ONE_MB.len());
        let key = AesKey::try_from_bytes(hex!(
            "1fded32d5999de4a76e0f8082108823aef60417e1896cf4218a2fa90f632ec8a"
        ))
        .unwrap();
        let nonce: Nonce<U12> = hex!("1f3afa4711e9474f32e70462").try_into()?;
        let expected_tag = Tag::try_from_bytes(hex!("67acceefeca1304b26a248dbead3ac36")).unwrap();
        let params = AesGcmParams::new(key, nonce, b"");
        let mut output = Cursor::new(&mut ciphertext);

        let tag =
            DefaultAesGcm::encrypt_readwrite(params.clone(), &mut plaintext_reader, &mut output)?;

        assert_eq!(&tag, &expected_tag);

        let mut ciphertext_reader = Cursor::new(ciphertext);

        let mut plaintext = Vec::with_capacity(ONE_MB.len());
        let mut output = Cursor::new(&mut plaintext);

        DefaultAesGcm::decrypt_readwrite(params, &mut ciphertext_reader, &mut output, tag)?;

        assert_eq!(&plaintext, ONE_MB);

        Ok(())
    }

    #[tokio::test]
    async fn readwrite_async_roundtrip() -> anyhow::Result<()> {
        let mut plaintext_reader = futures_lite::io::Cursor::new(ONE_MB);
        let mut ciphertext = Vec::with_capacity(ONE_MB.len());
        let key = AesKey::try_from_bytes(hex!(
            "1fded32d5999de4a76e0f8082108823aef60417e1896cf4218a2fa90f632ec8a"
        ))
        .unwrap();
        let nonce: Nonce<U12> = hex!("1f3afa4711e9474f32e70462").try_into()?;
        let expected_tag = Tag::try_from_bytes(hex!("67acceefeca1304b26a248dbead3ac36")).unwrap();
        let params = AesGcmParams::new(key, nonce, b"");
        let mut output = futures_lite::io::Cursor::new(&mut ciphertext);

        let tag = DefaultAesGcm::encrypt_async_readwrite(
            params.clone(),
            &mut plaintext_reader,
            &mut output,
        )
        .await?;

        assert_eq!(&tag, &expected_tag);

        let mut ciphertext_reader = futures_lite::io::Cursor::new(ciphertext);

        let mut plaintext = Vec::with_capacity(ONE_MB.len());
        let mut output = futures_lite::io::Cursor::new(&mut plaintext);

        DefaultAesGcm::decrypt_async_readwrite(params, &mut ciphertext_reader, &mut output, tag)
            .await?;

        assert_eq!(&plaintext, ONE_MB);

        Ok(())
    }

    #[test]
    fn seek() -> anyhow::Result<()> {
        let mut plaintext_reader = Cursor::new(ONE_MB);
        let mut ciphertext = Vec::with_capacity(ONE_MB.len());
        let key = AesKey::try_from_bytes(hex!(
            "1fded32d5999de4a76e0f8082108823aef60417e1896cf4218a2fa90f632ec8a"
        ))
        .unwrap();
        let nonce: Nonce<U12> = hex!("1f3afa4711e9474f32e70462").try_into()?;
        let params = AesGcmParams::new(key, nonce, b"");
        let mut output = Cursor::new(&mut ciphertext);

        let tag =
            DefaultAesGcm::encrypt_readwrite(params.clone(), &mut plaintext_reader, &mut output)?;

        let mut ciphertext_reader = Cursor::new(ciphertext);

        let mut decrypting_reader =
            DefaultAesGcm::decrypting_reader(params, &mut ciphertext_reader, tag)?;

        fn seek_test<R: Read + Seek>(
            reader: &mut R,
            buffer: &mut [u8],
            pos: usize,
        ) -> anyhow::Result<()> {
            reader.seek(SeekFrom::Start(pos as u64))?;
            reader.read_exact(buffer)?;
            assert_eq!(buffer, &ONE_MB[pos..pos + buffer.len()]);
            Ok(())
        }

        let len = 4096;
        let mut buffer = vec![0u8; len];

        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 0)?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 4096)?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 25631)?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 8192)?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 55112)?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 256256)?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 1000000)?;

        // we did not read the full ciphertext sequentially, therefore authentication should fail
        assert!(decrypting_reader.finalize().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn seek_async() -> anyhow::Result<()> {
        let mut plaintext_reader = futures_lite::io::Cursor::new(ONE_MB);
        let mut ciphertext = Vec::with_capacity(ONE_MB.len());
        let key = AesKey::try_from_bytes(hex!(
            "1fded32d5999de4a76e0f8082108823aef60417e1896cf4218a2fa90f632ec8a"
        ))
        .unwrap();
        let nonce: Nonce<U12> = hex!("1f3afa4711e9474f32e70462").try_into()?;
        let params = AesGcmParams::new(key, nonce, b"");
        let mut output = futures_lite::io::Cursor::new(&mut ciphertext);

        let tag = DefaultAesGcm::encrypt_async_readwrite(
            params.clone(),
            &mut plaintext_reader,
            &mut output,
        )
        .await?;

        let mut ciphertext_reader = futures_lite::io::Cursor::new(ciphertext);

        let mut decrypting_reader =
            DefaultAesGcm::decrypting_async_reader(params, &mut ciphertext_reader, tag)?;

        async fn seek_test<R: AsyncRead + AsyncSeek + Unpin>(
            reader: &mut R,
            buffer: &mut [u8],
            pos: usize,
        ) -> anyhow::Result<()> {
            reader.seek(SeekFrom::Start(pos as u64)).await?;
            reader.read_exact(buffer).await?;
            assert_eq!(buffer, &ONE_MB[pos..pos + buffer.len()]);
            Ok(())
        }

        let len = 4096;
        let mut buffer = vec![0u8; len];

        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 0).await?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 4096).await?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 25631).await?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 8192).await?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 55112).await?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 256256).await?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 1000000).await?;

        // we did not read the full ciphertext sequentially, therefore authentication should fail
        assert!(decrypting_reader.finalize().is_err());
        Ok(())
    }
}
