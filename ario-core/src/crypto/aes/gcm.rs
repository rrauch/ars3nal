use crate::buffer::{BufError, BufExt, BufMutExt, CircularBuffer, StackCircularBuffer};
use crate::confidential::RevealExt;
use crate::crypto::aes::{Aes, AesCipher, AesKey};
use crate::crypto::encryption;
use crate::crypto::encryption::hazmat::{
    FinalizeDecryptionWithoutAuthentication, SeekableDecryptor,
};
use crate::crypto::encryption::{Decryptor, Encryptor, Scheme};
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
            <Ctr<BIT> as StreamCipherSeekCore>::Counter::try_from((pos / block_size) + 1) // payload starts at counter 1
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
    BufError(#[from] BufError),
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
        Ok(process_finalize(
            self.block_fragment,
            |plaintext, ciphertext| {
                let tag = self
                    .aes_gcm
                    .process_finalize(plaintext, ciphertext, Op::Enc)?;
                Ok(tag)
            },
        )?)
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

    fn finalize_maybe_authenticated(
        self,
        tag: Option<&Tag<TagSize>>,
    ) -> Result<Option<Vec<u8>>, Error> {
        use subtle::ConstantTimeEq;

        process_finalize(self.block_fragment, |ciphertext, plaintext| {
            let generated_tag = self
                .aes_gcm
                .process_finalize(ciphertext, plaintext, Op::Dec)?;
            if let Some(tag) = tag {
                if tag.0.ct_eq(&generated_tag.0).into() {
                    Ok(())
                } else {
                    Err(Error::DecryptionError)
                }
            } else {
                Ok(())
            }
        })
        .map(|(_, residual)| residual)
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
        self.finalize_maybe_authenticated(Some(tag))
    }
}

impl<'a, const BIT: usize, TagSize, NonceSize> FinalizeDecryptionWithoutAuthentication<'a>
    for AesGcmDecryptor<'a, BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    fn finalize_unauthenticated(self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.finalize_maybe_authenticated(None)
    }
}

impl<'a, const BIT: usize, TagSize, NonceSize> SeekableDecryptor<'a>
    for AesGcmDecryptor<'a, BIT, TagSize, NonceSize>
where
    TagSize: ValidTagSize,
    NonceSize: ArraySize,
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    fn seek(&mut self, position: u64) -> Result<(), Self::Error> {
        let current_pos = self.aes_gcm.pos;
        if position == current_pos {
            return Ok(());
        }

        self.aes_gcm.seek(position)?;
        self.block_fragment.clear();
        Ok(())
    }
}

struct BlockFragment<const BIT: usize>
where
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    in_buf: CircularBuffer<Block<BIT>>,
    out_buf: CircularBuffer<Block<BIT>>,
}

impl<const BIT: usize> BlockFragment<BIT>
where
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    fn new() -> Self {
        Self {
            in_buf: StackCircularBuffer::new(),
            out_buf: StackCircularBuffer::new(),
        }
    }

    fn clear(&mut self) {
        self.in_buf.reset();
        self.out_buf.reset();
    }

    fn block_size() -> usize {
        <Aes<BIT> as AesCipher>::Cipher::block_size()
    }

    /*
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
    }*/

    /*
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
        assert!(!self.in_buf.has_remaining());
        let block_size = Self::block_size();
        let output_capacity = output.remaining_mut();
        if output_capacity < block_size {
            return Err(Error::InsufficientOutputBufferCapacity {
                additional_required: block_size - output_capacity,
            });
        }

        let block = self.in_buf.get_ref();

        if output.chunk_mut().len() >= block_size {
            // enough space remaining in output chunk

            // SAFETY: used solely for writing initialized bytes
            let out = unsafe { output.chunk_mut_slice_unsafe() };

            handler(block, out)?;
        } else {
            // use temporary buffer
            let out = self.out_buf.as_mut_slice();
            handler(block, out)?;
            output.copy_all_from_slice(&out)?;
        }

        // mark processed
        self.in_buf.set_position(0);
        Ok(block_size)
    }*/

    /*fn process_finalize<T>(
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
    }*/

    /*fn filled_buf_as_slice(&self) -> &[u8] {
        &self.in_buf.get_ref().as_slice()[..(self.in_buf.position() as usize)]
    }

    fn fill_buf<I: Buf>(&mut self, input: &mut I) -> usize {
        let remaining = self.in_buf.remaining();
        let pos = self.in_buf.position();
        let len = min(remaining, input.chunk().len());
        if len == 0 {
            // insufficient input
            return 0;
        }
        let start = pos as usize;
        let end = start + len;
        let out = &mut self.in_buf.get_mut()[start..end];
        input.copy_to_slice(out);
        self.in_buf.advance(len);
        len
    }*/
}

fn process<I: Buf, O: BufMut, const BIT: usize, TagSize, NonceSize>(
    input: &mut I,
    output: &mut O,
    block_size: usize,
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
    assert!(input.has_remaining() || output.has_remaining_mut());

    loop {
        // make sure we don't get stuck
        if !input.has_remaining() && !output.has_remaining_mut() {
            return Ok(());
        }

        // deal with partials & unflushed buffers first

        // 1. return any remaining bytes in the output buffer first
        if !block_fragment.out_buf.is_empty() {
            output.transfer_from_buf(&mut block_fragment.out_buf);
            return Ok(());
        }

        // 2. fill partial block if there is one
        if !block_fragment.in_buf.is_empty() {
            block_fragment.in_buf.transfer_from_buf(input);
        }

        // 3. if partial block is full, process now
        if block_fragment.in_buf.is_full() {
            debug_assert!(block_fragment.out_buf.is_empty());
            // buffered block ready to be processed
            let n = aes_gcm.process_incremental(
                block_fragment.in_buf.chunk(),
                unsafe { block_fragment.out_buf.chunk_mut_slice_unsafe() },
                op,
            )? as usize;

            block_fragment.in_buf.advance(n);
            unsafe { block_fragment.out_buf.advance_mut(n) };
            continue;
        }

        // 4. handle input chunk that is < block_size
        let chunk = input.chunk();
        if chunk.has_remaining() && chunk.remaining() < block_size {
            block_fragment
                .in_buf
                .transfer_exact_from_buf(input, chunk.len())
                .map_err(|_| BufError::Other)?;
            continue;
        }

        // 5. handle output that is < block_size
        if output.chunk_mut().len() < block_size {
            // attempt to fill in_buf
            let len = min(block_fragment.in_buf.remaining_mut(), input.remaining());
            block_fragment
                .in_buf
                .transfer_from_buf(&mut input.limit_buf(len));
            if block_fragment.in_buf.is_full() {
                // managed to fill a block
                continue;
            }
            // unable to fill a full block
            // cannot produce any output at this time
            return Ok(());
        }

        // main processing section

        let input_chunk = input.chunk();
        // SAFETY: used solely for writing initialized bytes
        let output_chunk = unsafe { output.chunk_mut_slice_unsafe() };

        let num_bytes_processable = min(input_chunk.len(), output_chunk.len());
        if num_bytes_processable == 0 {
            // processed everything we can
            return Ok(());
        }
        assert!(num_bytes_processable >= block_size);

        // align to block size
        let num_bytes_processable = num_bytes_processable / block_size * block_size;

        let n = aes_gcm.process_incremental(
            &input_chunk[..num_bytes_processable],
            &mut output_chunk[..num_bytes_processable],
            op,
        )? as usize;

        input.advance(n);
        unsafe { output.advance_mut(n) };
    }
    /*
    // main processing
    let num_bytes_processable = min(input.remaining(), output.remaining_mut());
    if num_bytes_processable == 0 {
        return Ok(());
    }
    assert!(num_bytes_processable >= block_size);

    // align to block size
    let num_bytes_processable = num_bytes_processable / block_size * block_size;

    //Ok(self.buf.is_full())

    loop {
        if block_fragment.maybe_buffer(input)? {
            // buffered block ready to be processed
            block_fragment.process(output, |input, output| {
                aes_gcm.process_incremental(input, output, op)?;
                Ok(())
            })?;
        }

        // max number of bytes we can process in this iteration
        let input_len = input.chunk().len();
        let output_len = output.chunk_mut().len();

        let num_bytes_processable = min(input_len, output_len);
        if num_bytes_processable == 0 {
            return Ok(());
        }

        if num_bytes_processable < block_size {
            // should never happen
            unreachable!("num_bytes_processable < block_size");
        }

        // align to block size
        let num_bytes_processable = num_bytes_processable / block_size * block_size;

        let input_slice = input.chunk_slice(num_bytes_processable)?;

        // SAFETY: used solely for writing initialized bytes
        let output_slice = unsafe { &mut output.chunk_mut_slice_unsafe()[..num_bytes_processable] };

        aes_gcm.process_incremental(input_slice, output_slice, op)?;

        input.advance(num_bytes_processable);
        unsafe {
            output.advance_mut(num_bytes_processable);
        }
    }*/
}

fn process_finalize<T, const BIT: usize>(
    mut block_fragment: BlockFragment<BIT>,
    handler: impl FnOnce(&[u8], &mut [u8]) -> Result<T, Error>,
) -> Result<(T, Option<Vec<u8>>), Error>
where
    Aes<BIT>: AesCipher,
    <Aes<BIT> as AesCipher>::Cipher: SupportedAesCiphers<BIT>,
{
    let residual_len = block_fragment.in_buf.remaining() + block_fragment.out_buf.remaining();
    let mut out = Vec::with_capacity(residual_len);

    out.transfer_from_buf(&mut block_fragment.out_buf);

    let input = if block_fragment.in_buf.has_remaining() {
        Cow::Borrowed(block_fragment.in_buf.make_contiguous())
    } else {
        Cow::Owned(vec![])
    };

    let out_buf = if out.capacity() != out.len() {
        // SAFETY: used solely for writing initialized bytes
        unsafe { out.chunk_mut_slice_unsafe() }
    } else {
        &mut []
    };

    let t = handler(input.as_ref(), out_buf)?;

    let len = out_buf.len();
    unsafe { out.advance_mut(len) }

    let out = if out.is_empty() { None } else { Some(out) };

    Ok((t, out))
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
            println!("{}", hex::encode(test.key.as_slice()));
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

        DefaultAesGcm::decrypt_readwrite(params, &mut ciphertext_reader, &mut output, &tag)?;

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

        DefaultAesGcm::decrypt_async_readwrite(params, &mut ciphertext_reader, &mut output, &tag)
            .await?;

        assert_eq!(&plaintext, ONE_MB);

        Ok(())
    }

    #[test]
    #[ignore]
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
            DefaultAesGcm::decrypting_reader(params, &mut ciphertext_reader)?;

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

        //seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 0)?;
        //seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 4096)?;
        seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 25631)?;
        //seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 8192)?;
        //seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 55112)?;
        //seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 256256)?;
        //seek_test(&mut decrypting_reader, buffer.as_mut_slice(), 1000000)?;

        decrypting_reader.finalize_unauthenticated()?;
        Ok(())
    }
}
