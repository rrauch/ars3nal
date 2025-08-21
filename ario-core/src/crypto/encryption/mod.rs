mod read_write;

use crate::crypto::encryption::read_write::{DecryptingReader, EncryptingWriter};
use bytes::{Buf, BufMut};
use hybrid_array::ArraySize;
use hybrid_array::typenum::Unsigned;
use std::cmp::min;
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use std::{io, ptr};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BufError {
    #[error("chunk too small: required: '{required}', actual: '{actual}'")]
    ChunkTooSmall { required: usize, actual: usize },
    #[error("buffer too small: required: '{required}', actual: '{actual}'")]
    BufferTooSmall { required: usize, actual: usize },
    #[error("buffer overflow")]
    BufferOverflow,
}

pub(crate) trait BufExt {
    fn chunk_slice(&self, len: usize) -> Result<&[u8], BufError>;
    fn write_all<W: Write>(&mut self, output: W) -> io::Result<usize>;
}

impl<T: Buf> BufExt for T {
    fn chunk_slice(&self, len: usize) -> Result<&[u8], BufError> {
        assert!(len > 0);

        if self.chunk().len() < len {
            return Err(BufError::ChunkTooSmall {
                required: len,
                actual: self.chunk().len(),
            });
        }

        Ok(&self.chunk()[..len])
    }

    fn write_all<W: Write>(&mut self, mut writer: W) -> io::Result<usize> {
        let mut written = 0;
        while self.has_remaining() {
            let chunk = self.chunk();
            let len = chunk.len();
            writer.write_all(chunk)?;
            self.advance(len);
            written += len;
        }
        Ok(written)
    }
}

pub(crate) trait BufMutExt {
    fn chunk_mut_slice(&mut self, len: usize) -> Result<&mut [u8], BufError>;
    fn copy_from_slice(&mut self, input: &[u8]) -> Result<(), BufError> {
        self.copy_from_buf(&mut Cursor::new(input))
    }

    fn copy_from_buf(&mut self, input: &mut impl Buf) -> Result<(), BufError>;
}

impl<T: BufMut> BufMutExt for T {
    fn chunk_mut_slice(&mut self, len: usize) -> Result<&mut [u8], BufError> {
        if self.chunk_mut().len() < len {
            return Err(BufError::ChunkTooSmall {
                required: len,
                actual: self.chunk_mut().len(),
            });
        }

        // SAFETY: We're zero-initializing possibly uninitialized memory.
        // The slice bounds are guaranteed valid and writing to MaybeUninit<u8> as u8 is safe.
        let output = unsafe {
            let maybe_uninit = self.chunk_mut()[..len].as_uninit_slice_mut();
            ptr::write_bytes(
                maybe_uninit.as_mut_ptr() as *mut u8,
                0x00,
                maybe_uninit.len(),
            );
            std::slice::from_raw_parts_mut(maybe_uninit.as_mut_ptr() as *mut _, maybe_uninit.len())
        };

        Ok(output)
    }

    fn copy_from_buf(&mut self, input: &mut impl Buf) -> Result<(), BufError> {
        if self.remaining_mut() < input.remaining() {
            return Err(BufError::BufferTooSmall {
                required: input.remaining(),
                actual: self.remaining_mut(),
            });
        }

        loop {
            if !input.has_remaining() {
                break;
            }
            let chunk_len = self.chunk_mut().len();
            assert!(chunk_len > 0);

            let len = min(input.remaining(), chunk_len);
            let out = self.chunk_mut_slice(len)?;
            out.copy_from_slice(&input.chunk()[..len]);
            input.advance(len);
            unsafe { self.advance_mut(len) }
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    BufError(#[from] BufError),
    #[error("encryption / decryption error: {0}")]
    Other(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

//#[derive_where(Clone, PartialEq)]
/*#[repr(transparent)]
pub struct Ciphertext<'a, S: Scheme>(S::EncryptedData<'a>);

impl<'a, S: Scheme> Ciphertext<'a, S> {
    pub(crate) fn new(data: S::EncryptedData<'a>) -> Self {
        Self(data)
    }
}

impl<'a, S: Scheme> AsBlob for Ciphertext<'a, S> {
    fn as_blob(&self) -> Blob<'_> {
        self.0.as_blob()
    }
}*/

/// A stateful, incremental encryptor that processes data in chunks.
///
/// This trait allows for encryption of data streams without requiring the entire input to be
/// available at once. It internally handles buffering for partial blocks and may return residual
/// data during finalization.
pub trait Encryptor<'a> {
    type Error: Into<Error>;
    /// The type returned after finalization (e.g., an authentication tag for AEAD, or `()` if not applicable).
    type AuthenticationTag;

    /// Required alignment for certain operations such as buffering and seeking.
    /// Typically, the cipher's block size.
    type Alignment: ArraySize;

    /// Returns the current position within the plaintext
    fn position(&self) -> u64;

    /// Encrypts data from the input buffer to the output buffer incrementally.
    ///
    /// This method processes as much data as possible from `plaintext` into `ciphertext`,
    /// advancing both buffers. It may buffer partial blocks internally if the input is not
    /// block-aligned.
    fn update<I: Buf, O: BufMut>(
        &mut self,
        plaintext: &mut I,
        ciphertext: &mut O,
    ) -> Result<(), Self::Error>;

    /// Finalizes the encryption process, ensuring all data is processed.
    ///
    /// This consumes the encryptor and returns any final output (e.g., an authentication tag)
    /// and residual ciphertext from internal buffering.
    ///
    /// # Returns
    /// A tuple containing:
    /// - `Self::AuthenticationTag`: The final output value (e.g., authentication tag).
    /// - `Option<Vec<u8>>`: Any residual ciphertext that was buffered.
    fn finalize(self) -> Result<(Self::AuthenticationTag, Option<Vec<u8>>), Self::Error>;
}

/// A stateful, incremental decryptor that processes data in chunks.
///
/// This trait allows for decryption of data streams incrementally, with internal buffering
/// for partial blocks. It may return residual plaintext during finalization.
pub trait Decryptor<'a> {
    type Error: Into<Error>;
    /// The type required for finalization (e.g., an authentication tag for AEAD, or `()` if not applicable).
    type AuthenticationTag;

    /// Required alignment for certain operations such as buffering and seeking.
    /// Typically, the cipher's block size.
    type Alignment: ArraySize;

    /// Returns the current position within the ciphertext
    fn position(&self) -> u64;

    /// Decrypts data from the input buffer to the output buffer incrementally.
    ///
    /// This method processes as much data as possible from `ciphertext` into `plaintext`,
    /// advancing both buffers. It may buffer partial blocks internally if the input is not
    /// block-aligned.
    fn update<I: Buf, O: BufMut>(
        &mut self,
        ciphertext: &mut I,
        plaintext: &mut O,
    ) -> Result<(), Self::Error>;

    /// Finalizes the decryption process, ensuring all data is processed and verified if applicable.
    ///
    /// This consumes the decryptor, accepts a final input value (e.g., for tag verification),
    /// and returns any residual plaintext from internal buffering.
    fn finalize(self, tag: &Self::AuthenticationTag) -> Result<Option<Vec<u8>>, Self::Error>;
}

/*
pub mod hazmat {
    use crate::crypto::encryption::Decryptor;
    use bytes::{Buf, BufMut};

    pub trait FinalizeDecryptionWithoutVerification<'a>: Decryptor<'a> {
        /// Allows finalizing while skipping verification.
        /// Intended to be used together with `SeekableDecryptor::seek`.
        ///
        /// **WARNING**: Only use if ciphertext has already been pre-verified!
        fn finalize_unverified<I: Buf, O: BufMut>(
            self,
            ciphertext: &mut I,
            plaintext: &mut O,
        ) -> Result<(), Self::Error>;
    }

    pub trait SeekableDecryptor<'a>: Decryptor<'a> {
        /// Sets the current position within the ciphertext.
        ///
        /// **WARNING**: May make verification impossible!
        fn seek(&mut self, position: u64) -> Result<(), Self::Error>;
    }
}*/

/// A trait representing a cryptographic scheme capable of incremental encryption and decryption.
///
/// Implementations of this trait provide stateful encryptors and decryptors that process data
/// in chunks, handling internal buffering and finalization (e.g., tag generation/verification for AEAD).
pub trait Scheme {
    /// A stateful encryptor for this scheme.
    type Encryptor<'a>: Encryptor<'a>;
    /// The parameters required to initialize an encryptor (e.g., key, nonce, associated data).
    type EncryptionParams<'a>;

    /// A stateful decryptor for this scheme.
    type Decryptor<'a>: Decryptor<'a>;
    /// The parameters required to initialize a decryptor (e.g., key, nonce, associated data).
    type DecryptionParams<'a>;

    type Error: Into<Error>;

    /// Creates a new incremental encryptor from the given parameters.
    fn new_encryptor<'a>(
        params: Self::EncryptionParams<'a>,
    ) -> Result<Self::Encryptor<'a>, Self::Error>;

    /// Creates a new incremental decryptor from the given parameters.
    fn new_decryptor<'a>(
        params: Self::DecryptionParams<'a>,
    ) -> Result<Self::Decryptor<'a>, Self::Error>;
}

pub trait EncryptionExt {
    type EncryptionParams<'a>
    where
        Self: 'a;
    type Encryptor<'a>: Encryptor<'a>
    where
        Self: 'a;

    fn encrypt<'a, I: Buf, O: BufMut>(
        params: Self::EncryptionParams<'a>,
        plaintext: &mut I,
        ciphertext: &mut O,
    ) -> Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>;

    fn encrypt_readwrite<'a, I: Read, O: Write>(
        params: Self::EncryptionParams<'a>,
        plaintext_reader: &'a mut I,
        ciphertext_writer: &'a mut O,
    ) -> Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>
    where
        Self: 'a,
    {
        Self::encrypt_readwrite_with_buf_size::<I, O, { 64 * 1024 }>(
            params,
            plaintext_reader,
            ciphertext_writer,
        )
    }

    fn encrypt_readwrite_with_buf_size<'a, I: Read, O: Write, const BUF_SIZE: usize>(
        params: Self::EncryptionParams<'a>,
        plaintext_reader: &'a mut I,
        ciphertext_writer: &'a mut O,
    ) -> Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>
    where
        Self: 'a;

    fn encrypting_writer<'a, O: Write>(
        params: Self::EncryptionParams<'a>,
        ciphertext_writer: &'a mut O,
    ) -> Result<EncryptingWriter<'a, Self::Encryptor<'a>, O>, Error>
    where
        Self: 'a,
    {
        Self::encrypting_writer_with_buf_size::<O, { 64 * 1024 }>(params, ciphertext_writer)
    }

    fn encrypting_writer_with_buf_size<'a, O: Write, const BUF_SIZE: usize>(
        params: Self::EncryptionParams<'a>,
        ciphertext_writer: &'a mut O,
    ) -> Result<EncryptingWriter<'a, Self::Encryptor<'a>, O>, Error>
    where
        Self: 'a;
}

impl<T> EncryptionExt for T
where
    T: Scheme,
{
    type EncryptionParams<'a>
        = <Self as Scheme>::EncryptionParams<'a>
    where
        T: 'a;
    type Encryptor<'a>
        = <Self as Scheme>::Encryptor<'a>
    where
        T: 'a;

    fn encrypt<'a, I: Buf, O: BufMut>(
        params: Self::EncryptionParams<'a>,
        plaintext: &mut I,
        ciphertext: &mut O,
    ) -> Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>
    where
        T: 'a,
    {
        let mut encryptor = <Self as Scheme>::new_encryptor(params).map_err(|e| e.into())?;
        while plaintext.has_remaining() {
            encryptor
                .update(plaintext, ciphertext)
                .map_err(|e| e.into())?;
        }
        let (tag, residual) = encryptor.finalize().map_err(|e| e.into())?;
        if let Some(residual) = residual {
            ciphertext.copy_from_slice(residual.as_slice())?;
        }
        Ok(tag)
    }

    fn encrypt_readwrite_with_buf_size<'a, I: Read, O: Write, const BUF_SIZE: usize>(
        params: Self::EncryptionParams<'a>,
        plaintext_reader: &'a mut I,
        ciphertext_writer: &'a mut O,
    ) -> Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>
    where
        T: 'a,
    {
        // todo: can this be made const?
        let buf_size = align(
            BUF_SIZE,
            <Self::Encryptor<'a> as Encryptor>::Alignment::to_usize(),
        );

        let mut writer =
            encrypting_writer_with_buf_size::<O, Self>(params, ciphertext_writer, buf_size)?;
        io::copy(
            &mut BufReader::with_capacity(buf_size, plaintext_reader),
            &mut writer,
        )?;
        Ok(writer.close()?)
    }

    fn encrypting_writer_with_buf_size<'a, O: Write, const BUF_SIZE: usize>(
        params: Self::EncryptionParams<'a>,
        ciphertext_writer: &'a mut O,
    ) -> Result<EncryptingWriter<'a, Self::Encryptor<'a>, O>, Error>
    where
        Self: 'a,
    {
        encrypting_writer_with_buf_size::<O, Self>(params, ciphertext_writer, BUF_SIZE)
    }
}

fn encrypting_writer_with_buf_size<'a, O: Write, T>(
    params: <T as Scheme>::EncryptionParams<'a>,
    ciphertext_writer: &'a mut O,
    buf_size: usize,
) -> Result<EncryptingWriter<'a, <T as Scheme>::Encryptor<'a>, O>, Error>
where
    T: 'a,
    T: Scheme,
{
    let encryptor = <T as Scheme>::new_encryptor(params).map_err(|e| e.into())?;
    Ok(EncryptingWriter::new(
        encryptor,
        ciphertext_writer,
        buf_size,
    ))
}

pub trait DecryptionExt {
    type DecryptionParams<'a>
    where
        Self: 'a;

    type Decryptor<'a>: Decryptor<'a>
    where
        Self: 'a;

    fn decrypt<'a, I: Buf, O: BufMut>(
        params: Self::DecryptionParams<'a>,
        ciphertext: &mut I,
        plaintext: &mut O,
        tag: &<Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<(), Error>
    where
        Self: 'a;

    fn decrypt_readwrite<'a, I: Read, O: Write>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: &'a mut I,
        plaintext_writer: &'a mut O,
        tag: &<Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<(), Error>
    where
        Self: 'a,
    {
        Self::decrypt_readwrite_with_buf_size::<I, O, { 64 * 1024 }>(
            params,
            ciphertext_reader,
            plaintext_writer,
            tag,
        )
    }

    fn decrypt_readwrite_with_buf_size<'a, I: Read, O: Write, const BUF_SIZE: usize>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: &'a mut I,
        plaintext_writer: &'a mut O,
        tag: &<Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<(), Error>
    where
        Self: 'a;
}

impl<T> DecryptionExt for T
where
    T: Scheme,
{
    type DecryptionParams<'a>
        = <Self as Scheme>::DecryptionParams<'a>
    where
        T: 'a;
    type Decryptor<'a>
        = <Self as Scheme>::Decryptor<'a>
    where
        T: 'a;

    fn decrypt<'a, I: Buf, O: BufMut>(
        params: Self::DecryptionParams<'a>,
        ciphertext: &mut I,
        plaintext: &mut O,
        tag: &<Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<(), Error>
    where
        T: 'a,
    {
        let mut decryptor = <Self as Scheme>::new_decryptor(params).map_err(|e| e.into())?;
        while ciphertext.has_remaining() {
            decryptor
                .update(ciphertext, plaintext)
                .map_err(|e| e.into())?;
        }
        let residual = decryptor.finalize(tag).map_err(|e| e.into())?;
        if let Some(residual) = residual {
            plaintext.copy_from_slice(residual.as_slice())?;
        }
        Ok(())
    }

    fn decrypt_readwrite_with_buf_size<'a, I: Read, O: Write, const BUF_SIZE: usize>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: &'a mut I,
        plaintext_writer: &'a mut O,
        tag: &<Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<(), Error>
    where
        T: 'a,
    {
        let buf_size = align(
            BUF_SIZE,
            <Self::Decryptor<'a> as Decryptor>::Alignment::to_usize(),
        );

        let decryptor = <Self as Scheme>::new_decryptor(params).map_err(|e| e.into())?;

        let mut reader = DecryptingReader::new(decryptor, ciphertext_reader, buf_size);
        let mut writer = &mut BufWriter::with_capacity(buf_size, plaintext_writer);
        io::copy(&mut reader, &mut writer)?;
        if let Some(residual) = reader.close(tag)? {
            writer.write_all(&residual)?;
        }
        Ok(())
    }
}

fn align(n: usize, align: usize) -> usize {
    if n < align {
        align
    } else {
        let remainder = n % align;
        if remainder == 0 {
            n
        } else {
            n + align - remainder
        }
    }
}
