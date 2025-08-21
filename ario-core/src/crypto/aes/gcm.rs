use crate::confidential::RevealExt;
use crate::crypto::aes::{Aes, AesCipher, AesKey};
use crate::crypto::encryption;
use crate::crypto::encryption::{BufExt, BufMutExt, Decryptor, Encryptor, Scheme};
use aes::cipher::typenum::U16;
use aes::cipher::{
    BlockCipherEncrypt, InOutBuf, InnerIvInit, KeyInit, StreamCipherCore, crypto_common,
};
use bytes::{Buf, BufMut};
use crypto_common::BlockSizeUser;
use ctr::cipher::StreamCipherSeekCore;
use ghash::GHash;
use ghash::universal_hash::UniversalHash;
use hybrid_array::typenum::U12;
use hybrid_array::{Array, ArraySize};
use maybe_owned::MaybeOwned;
use std::borrow::Cow;
use std::cmp::min;
use std::io::Cursor;
use std::marker::PhantomData;
use thiserror::Error;
use zeroize::Zeroize;

/// Maximum length of associated data.
const A_MAX: u64 = 1 << 36;

/// Maximum length of plaintext.
const P_MAX: u64 = 1 << 36;

/// Maximum length of ciphertext.
const C_MAX: u64 = (1 << 36) + 16;

pub type DefaultAesGcm<const BIT: usize> = AesGcm<BIT, U16, U12>;

pub struct AesGcm<const BIT: usize, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    ctr: Ctr<BIT>,
    ghash: GHash,
    mask: Block<BIT>,
    aad_len: u64,
    pos: u64,
    _marker: PhantomData<(TagSize, NonceSize)>,
}

pub trait SupportedAesCiphers<const BIT: usize> {}

impl SupportedAesCiphers<256> for aes::Aes256 {}

type Ctr<const BIT: usize> = ctr::CtrCore<<Aes<BIT> as AesCipher>::Cipher, ctr::flavors::Ctr32BE>;
type Block<const BIT: usize> =
    Array<u8, <<Aes<BIT> as AesCipher>::Cipher as BlockSizeUser>::BlockSize>;

pub type Nonce<NonceSize> = Array<u8, NonceSize>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Tag<TagSize>(Array<u8, TagSize>)
where
    TagSize: ValidTagSize;

impl<TagSize> Tag<TagSize>
where
    TagSize: ValidTagSize,
{
    fn try_from_bytes<T: AsRef<[u8]>>(input: T) -> Option<Self> {
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

        Ok(Self {
            ctr,
            mask,
            ghash,
            aad_len: aad.len() as u64,
            pos: 0,
            _marker: PhantomData,
        })
    }

    fn seek(&mut self, pos: u64) -> Result<(), Error> {
        let block_size = <Aes<BIT> as AesCipher>::Cipher::block_size() as u64;

        if pos % block_size != 0 {
            return Err(Error::InvalidSeekPosition(pos));
        }

        self.ctr.set_block_pos(
            <Ctr<BIT> as StreamCipherSeekCore>::Counter::try_from(pos / block_size)
                .map_err(|_| Error::InvalidSeekPosition(pos))?,
        );

        self.pos = pos;

        Ok(())
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

    fn process_incremental(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        op: Op,
    ) -> Result<u64, Error> {
        assert_eq!(input.len(), output.len());

        let len = input.len() as u64;
        assert!(len > 0);

        if self.pos + len > C_MAX {
            return Err(Error::CiphertextTooLong);
        }

        if self.pos + len > P_MAX {
            return Err(Error::PlaintextTooLong);
        }

        let (mut blocks, tail) = InOutBuf::new(input, output).unwrap().into_chunks();

        if !tail.is_empty() {
            panic!("input must be multiple of block size");
        }

        self.ctr.apply_keystream_blocks_inout(blocks.reborrow());
        let buf = match op {
            Op::Enc => blocks.get_out(),
            Op::Dec => blocks.get_in(),
        };
        self.ghash.update(buf);

        self.pos += len;

        Ok(len)
    }

    fn process_finalize(
        mut self,
        input: &[u8],
        output: &mut [u8],
        op: Op,
    ) -> Result<Tag<TagSize>, Error> {
        assert_eq!(input.len(), output.len());

        if !input.is_empty() {
            let len = input.len();
            if self.pos + len as u64 > C_MAX {
                return Err(Error::CiphertextTooLong);
            }

            if self.pos + len as u64 > P_MAX {
                return Err(Error::PlaintextTooLong);
            }

            if input.len() > output.len() {
                // we couldn't process the final input
                // due to insufficient output buffer capacity
                return Err(Error::InsufficientOutputBufferCapacity {
                    additional_required: input.len() - output.len(),
                });
            }

            let len = input.len();
            let mut buf = InOutBuf::new(input, output).unwrap();
            self.ctr.apply_keystream_partial(buf.reborrow());
            let buf = match op {
                Op::Enc => buf.get_out(),
                Op::Dec => buf.get_in(),
            };
            self.ghash.update_padded(&buf[..len]);

            self.pos += len as u64;
        }

        let aad_len_bits = self.aad_len * 8;
        let input_len_bits = self.pos * 8;

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

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
enum Op {
    Enc,
    Dec,
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
    BufError(#[from] encryption::BufError),
    #[error(
        "insufficient output buffer capacity, additional bytes required: '{additional_required}'"
    )]
    InsufficientOutputBufferCapacity { additional_required: usize },
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

impl Into<encryption::Error> for Error {
    fn into(self) -> encryption::Error {
        encryption::Error::Other(self.to_string())
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
{
    type Encryptor<'a> = AesGcmEncryptor<'a, BIT, TagSize, NonceSize>;
    type EncryptionParams<'a> = AesGcmParams<'a, BIT, NonceSize>;
    type Decryptor<'a> = AesGcmDecryptor<'a, BIT, TagSize, NonceSize>;
    type DecryptionParams<'a> = AesGcmParams<'a, BIT, NonceSize>;
    type Error = Error;

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

impl<'a, const BIT: usize, TagSize, NonceSize> AesGcmEncryptor<'a, BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    fn block_size() -> usize {
        <Aes<BIT> as AesCipher>::Cipher::block_size()
    }
}

impl<'a, const BIT: usize, TagSize, NonceSize> Encryptor<'a>
    for AesGcmEncryptor<'a, BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    type Error = Error;
    type AuthenticationTag = Tag<TagSize>;
    type Alignment = <<Aes<BIT> as AesCipher>::Cipher as BlockSizeUser>::BlockSize;

    fn position(&self) -> u64 {
        self.aes_gcm.pos
    }

    fn update<I: Buf, O: BufMut>(
        &mut self,
        plaintext: &mut I,
        ciphertext: &mut O,
    ) -> Result<(), Self::Error> {
        process(
            plaintext,
            ciphertext,
            Self::block_size(),
            &mut self.block_fragment,
            &mut self.aes_gcm,
            Op::Enc,
        )?;
        Ok(())
    }

    fn finalize(self) -> Result<(Self::AuthenticationTag, Option<Vec<u8>>), Self::Error> {
        Ok(self
            .block_fragment
            .process_finalize(|plaintext, ciphertext| {
                let tag = self
                    .aes_gcm
                    .process_finalize(plaintext, ciphertext, Op::Enc)?;
                Ok(tag)
            })?)
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
    fn block_size() -> usize {
        <Aes<BIT> as AesCipher>::Cipher::block_size()
    }
}

impl<'a, const BIT: usize, TagSize, NonceSize> Decryptor<'a>
    for AesGcmDecryptor<'a, BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    type Error = Error;
    type AuthenticationTag = Tag<TagSize>;
    type Alignment = <<Aes<BIT> as AesCipher>::Cipher as BlockSizeUser>::BlockSize;

    fn position(&self) -> u64 {
        self.aes_gcm.pos
    }

    fn update<I: Buf, O: BufMut>(
        &mut self,
        ciphertext: &mut I,
        plaintext: &mut O,
    ) -> Result<(), Self::Error> {
        process(
            ciphertext,
            plaintext,
            Self::block_size(),
            &mut self.block_fragment,
            &mut self.aes_gcm,
            Op::Dec,
        )?;
        Ok(())
    }

    fn finalize(self, tag: &Self::AuthenticationTag) -> Result<Option<Vec<u8>>, Self::Error> {
        use subtle::ConstantTimeEq;

        self.block_fragment
            .process_finalize(|ciphertext, plaintext| {
                let generated_tag =
                    self.aes_gcm
                        .process_finalize(ciphertext, plaintext, Op::Dec)?;

                if tag.0.ct_eq(&generated_tag.0).into() {
                    Ok(())
                } else {
                    Err(Error::DecryptionError)
                }
            })
            .map(|(_, residual)| residual)
    }
}

struct BlockFragment<const BIT: usize>
where
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    buf: Cursor<Block<BIT>>,
    out_buf: Block<BIT>,
}

impl<const BIT: usize> BlockFragment<BIT>
where
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    fn new() -> Self {
        Self {
            buf: Cursor::new(Block::default()),
            out_buf: Block::default(),
        }
    }

    fn block_size() -> usize {
        <Aes<BIT> as AesCipher>::Cipher::block_size()
    }

    /// Handles buffering of incomplete blocks
    ///
    /// Returns `true` if a full block is ready for further processing
    fn maybe_buffer<I: Buf>(&mut self, input: &mut I) -> Result<bool, Error> {
        loop {
            // max number of bytes we can process in this iteration
            let pos = self.buf.position();
            if pos > 0 {
                if !self.buf.has_remaining() {
                    // block is full
                    return Ok(true);
                }

                // incomplete block data found
                // try to fill
                if self.fill_buf(input) == 0 {
                    // input eof
                    return Ok(false);
                }
                continue;
            }

            let input_len = input.chunk().len();

            if input_len > 0 && input_len < Self::block_size() {
                // less than full block in current input chunk
                let len = min(input_len, self.buf.remaining());
                if len == 0 {
                    // should not happen
                    unreachable!("input and buffer should have capacity")
                }
                // fill the buffer and advance input
                self.fill_buf(input);
                continue;
            }

            return Ok(false);
        }
    }

    /// Processes the buffered block with the provided Fn.
    ///
    /// Marks current buffered block as handled on success.
    fn process<O: BufMut>(
        &mut self,
        output: &mut O,
        handler: impl FnOnce(&[u8], &mut [u8]) -> Result<(), Error>,
    ) -> Result<usize, Error>
    where
        Aes<BIT>: AesCipher,
    {
        assert!(!self.buf.has_remaining());
        let block_size = Self::block_size();
        let output_capacity = output.remaining_mut();
        if output_capacity < block_size {
            return Err(Error::InsufficientOutputBufferCapacity {
                additional_required: block_size - output_capacity,
            });
        }

        let block = self.buf.get_ref();

        if output.chunk_mut().len() >= block_size {
            // enough space remaining in output chunk
            let out = output.chunk_mut_slice(block_size)?;
            handler(block, out)?;
        } else {
            // use temporary buffer
            let out = self.out_buf.as_mut_slice();
            handler(block, out)?;
            output.copy_from_slice(&out)?;
        }

        // mark processed
        self.buf.set_position(0);
        Ok(block_size)
    }

    fn process_finalize<T>(
        self,
        handler: impl FnOnce(&[u8], &mut [u8]) -> Result<T, Error>,
    ) -> Result<(T, Option<Vec<u8>>), Error> {
        let block_fragment = self.filled_buf_as_slice();

        let input = if block_fragment.has_remaining() {
            Cow::Borrowed(block_fragment)
        } else {
            Cow::Owned(vec![])
        };

        let mut out = vec![0u8; input.len()];
        let t = handler(input.as_ref(), &mut out)?;
        let out = if out.is_empty() { None } else { Some(out) };

        Ok((t, out))
    }

    fn filled_buf_as_slice(&self) -> &[u8] {
        &self.buf.get_ref().as_slice()[..(self.buf.position() as usize)]
    }

    fn fill_buf<I: Buf>(&mut self, input: &mut I) -> usize {
        let remaining = self.buf.remaining();
        let pos = self.buf.position();
        let len = min(remaining, input.chunk().len());
        if len == 0 {
            // insufficient input
            return 0;
        }
        let start = pos as usize;
        let end = start + len;
        let out = &mut self.buf.get_mut()[start..end];
        input.copy_to_slice(out);
        self.buf.advance(len);
        len
    }
}

fn process<I: Buf, O: BufMut, const BIT: usize, TagSize, NonceSize>(
    input: &mut I,
    output: &mut O,
    block_size: usize,
    block_fragment: &mut BlockFragment<BIT>,
    aes_gcm: &mut AesGcm<BIT, TagSize, NonceSize>,
    op: Op,
) -> Result<u64, Error>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    let mut bytes_processed = 0;
    loop {
        if block_fragment.maybe_buffer(input)? {
            // buffered block ready to be processed
            bytes_processed += block_fragment.process(output, |input, output| {
                aes_gcm.process_incremental(input, output, op)?;
                Ok(())
            })? as u64;
        }

        // max number of bytes we can process in this iteration
        let input_len = input.chunk().len();
        let output_len = output.chunk_mut().len();

        let num_bytes_processable = min(input_len, output_len);
        if num_bytes_processable == 0 {
            return Ok(bytes_processed);
        }

        if num_bytes_processable < block_size {
            // should never happen
            unreachable!("num_bytes_processable < block_size");
        }

        // align to block size
        let num_bytes_processable = num_bytes_processable / block_size * block_size;

        let input_slice = input.chunk_slice(num_bytes_processable)?;
        let output_slice = output.chunk_mut_slice(num_bytes_processable)?;

        bytes_processed += aes_gcm.process_incremental(input_slice, output_slice, op)?;

        input.advance(num_bytes_processable);
        unsafe {
            output.advance_mut(num_bytes_processable);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::aes::AesKey;
    use crate::crypto::aes::gcm::{AesGcmParams, DefaultAesGcm, Nonce, Tag};
    use crate::crypto::encryption::DecryptionExt;
    use crate::crypto::encryption::EncryptionExt;
    use aes::cipher::consts::U12;
    use bytes::BytesMut;
    use hex_literal::hex;
    use std::io::Cursor;

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
        key: &hex!("1fded32d5999de4a76e0f8082108823aef60417e1896cf4218a2fa90f632ec8a"),
        nonce: &hex!("1f3afa4711e9474f32e70462"),
        plaintext: &hex!(
            "06b2c75853df9aeb17befd33cea81c630b0fc53667ff45199c629c8e15dce41e530aa792f796b8138eeab2e86c7b7bee1d40b0"
        ),
        aad: b"",
        ciphertext: &hex!(
            "91fbd061ddc5a7fcc9513fcdfdc9c3a7c5d4d64cedf6a9c24ab8a77c36eefbf1c5dc00bc50121b96456c8cd8b6ff1f8b3e480f"
        ),
        tag: &hex!("30096d340f3d5c42d82a6f475def23eb"),
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
            DefaultAesGcm::decrypt(params, &mut ciphertext, &mut output, &tag)?;
            let plaintext = output.freeze();
            assert_eq!(plaintext.to_vec().as_slice(), test.plaintext);
        }
        Ok(())
    }

    #[test]
    fn readwrite_roundtrip() -> anyhow::Result<()> {
        let mut plaintext_reader = Cursor::new(ONE_MB);
        let mut ciphertext = vec![0u8; ONE_MB.len()];
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

        let mut plaintext = vec![0u8; ONE_MB.len()];
        let mut output = Cursor::new(&mut plaintext);

        DefaultAesGcm::decrypt_readwrite(params, &mut ciphertext_reader, &mut output, &tag)?;

        assert_eq!(&plaintext, ONE_MB);

        Ok(())
    }
}
