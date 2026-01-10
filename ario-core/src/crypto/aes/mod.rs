pub mod ctr;
pub mod gcm;

use crate::buffer::{BufError, BufExt, BufMutExt, CircularBuffer, StackCircularBuffer};
use crate::confidential::{NewSecretExt, Protected};
use crate::crypto::aes::ctr::Error;
use crate::crypto::keys::{SymmetricKey, SymmetricScheme};
use aes::cipher::consts::U16;
use aes::cipher::typenum::Unsigned;
use aes::cipher::{BlockCipherEncrypt, BlockSizeUser, KeyInit};
use bytes::{Buf, BufMut};
use hybrid_array::Array;
use std::borrow::Cow;
use std::cmp::min;

pub struct Aes<const BIT: usize>;

pub trait AesCipher {
    type Cipher: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit;
}

impl AesCipher for Aes<256> {
    type Cipher = aes::Aes256;
}

impl<const BIT: usize> SymmetricScheme for Aes<BIT>
where
    Self: AesCipher,
{
    type SecretKey = AesKey<BIT>;
}

pub type KeySize<const BIT: usize> =
    <<Aes<BIT> as AesCipher>::Cipher as aes::cipher::KeySizeUser>::KeySize;

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct AesKey<const BIT: usize>(Protected<Array<u8, KeySize<BIT>>>)
where
    Aes<BIT>: AesCipher;

impl<const BIT: usize> AesKey<BIT>
where
    Aes<BIT>: AesCipher,
{
    pub fn try_from_bytes<T: AsRef<[u8]>>(input: T) -> Option<Self> {
        let key_size = KeySize::<BIT>::to_usize();
        let input = input.as_ref();
        if key_size != input.len() {
            //todo
            return None;
        }
        Some(Self(Array::try_from(input).unwrap().protected()))
    }

    pub fn from_byte_array(bytes: Array<u8, KeySize<BIT>>) -> Self {
        Self(bytes.protected())
    }
}

impl<const BIT: usize> SymmetricKey for AesKey<BIT>
where
    Aes<BIT>: AesCipher,
{
    type Scheme = Aes<BIT>;
}

pub type Cipher<const BIT: usize>
where
    Aes<BIT>: AesCipher,
= <Aes<BIT> as AesCipher>::Cipher;

pub type Block<const BIT: usize> =
    Array<u8, <<Aes<BIT> as AesCipher>::Cipher as BlockSizeUser>::BlockSize>;

pub type Nonce<NonceSize> = Array<u8, NonceSize>;

pub struct BlockFragment<const BIT: usize>
where
    Aes<BIT>: AesCipher,
{
    in_buf: CircularBuffer<Block<BIT>>,
    out_buf: CircularBuffer<Block<BIT>>,
}

impl<const BIT: usize> BlockFragment<BIT>
where
    Aes<BIT>: AesCipher,
{
    pub fn new() -> Self {
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
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub enum Op {
    Enc,
    Dec,
}

fn process<I: Buf, O: BufMut, const BIT: usize, E: Into<Error>>(
    input: &mut I,
    output: &mut O,
    block_fragment: &mut BlockFragment<BIT>,
    mut handler: impl FnMut(&[u8], &mut [u8]) -> Result<usize, E>,
) -> Result<(), Error>
where
    Aes<BIT>: AesCipher,
{
    assert!(input.has_remaining() || output.has_remaining_mut());
    let block_size = BlockFragment::<BIT>::block_size();

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
            let n = handler(block_fragment.in_buf.chunk(), unsafe {
                block_fragment.out_buf.chunk_mut_slice_unsafe()
            })
            .map_err(|e| e.into())?;
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

        let n = handler(
            &input_chunk[..num_bytes_processable],
            &mut output_chunk[..num_bytes_processable],
        )
        .map_err(|e| e.into())?;
        input.advance(n);
        unsafe { output.advance_mut(n) };
    }
}

fn process_finalize<T, const BIT: usize, E: Into<Error>>(
    mut block_fragment: BlockFragment<BIT>,
    handler: impl FnOnce(&[u8], &mut [u8]) -> Result<T, E>,
) -> Result<(T, Option<Vec<u8>>), Error>
where
    Aes<BIT>: AesCipher,
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

    let t = handler(input.as_ref(), out_buf).map_err(|e| e.into())?;

    let len = out_buf.len();
    unsafe { out.advance_mut(len) }

    let out = if out.is_empty() { None } else { Some(out) };

    Ok((t, out))
}

#[cfg(feature = "hazmat")]
pub mod hazmat {
    use crate::confidential::RevealExt;
    use crate::crypto::aes::{Aes, AesCipher, AesKey, KeySize};
    use hybrid_array::Array;

    impl<const BIT: usize> AesKey<BIT>
    where
        Aes<BIT>: AesCipher,
    {
        pub fn danger_reveal_raw_key(&self) -> &Array<u8, KeySize<BIT>> {
            self.0.reveal()
        }
    }
}
