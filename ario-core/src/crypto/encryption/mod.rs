pub mod decryption;
pub mod encryption;

use crate::blob::OwnedBlob;
use crate::buffer::{BufError, BufMutExt};
use crate::crypto::encryption::decryption::DecryptingReader;
use crate::crypto::encryption::encryption::EncryptingWriter;
use bytes::{Buf, BufMut};
use futures_lite::{AsyncRead, AsyncWrite};
use hybrid_array::ArraySize;
use std::io;
use std::io::{Read, Write};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    BufError(#[from] BufError),
    #[error("encryption / decryption error: {0}")]
    Other(String),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

/// A stateful, incremental encryptor that processes data in chunks.
///
/// This trait allows for encryption of data streams without requiring the entire input to be
/// available at once. It internally handles buffering for partial blocks and may return residual
/// data during finalization.
pub trait Encryptor<'a> {
    type Error: Into<Error>;
    /// The type returned after finalization (e.g., an authentication tag for AEAD, or `()` if not applicable).
    type AuthenticationTag: Send + Sync + Into<OwnedBlob>;

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
    type Error: Into<Error> + Send + Sync + Unpin;
    /// The type required for finalization (e.g., an authentication tag for AEAD, or `()` if not applicable).
    type AuthenticationTag: Send + Sync + Unpin;

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
    /// and returns the authentication result & any residual plaintext from internal buffering.
    fn finalize(self, tag: &Self::AuthenticationTag) -> (Result<(), Self::Error>, Option<Vec<u8>>);
}

pub mod hazmat {
    use crate::crypto::encryption::Decryptor;
    pub trait SeekableDecryptor<'a>: Decryptor<'a> {
        /// Sets the current position within the ciphertext.
        ///
        /// **WARNING**: May make verification impossible!
        fn seek(&mut self, position: u64) -> Result<(), Self::Error>;
    }
}

/// A trait representing a cryptographic scheme capable of incremental encryption and decryption.
///
/// Implementations of this trait provide stateful encryptors and decryptors that process data
/// in chunks, handling internal buffering and finalization (e.g., tag generation/verification for AEAD).
pub trait Scheme {
    /// A stateful encryptor for this scheme.
    type Encryptor<'a>: Encryptor<'a>;
    /// The parameters required to initialize an encryptor (e.g., key, nonce, associated data).
    type EncryptionParams<'a>: Send;

    /// A stateful decryptor for this scheme.
    type Decryptor<'a>: Decryptor<'a>;
    /// The parameters required to initialize a decryptor (e.g., key, nonce, associated data).
    type DecryptionParams<'a>: Send;

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
    type EncryptionParams<'a>: Send
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

    fn encrypt_readwrite<'a, I: Read + 'a, O: Write + 'a>(
        params: Self::EncryptionParams<'a>,
        plaintext_reader: I,
        ciphertext_writer: O,
    ) -> Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>
    where
        Self: Unpin + 'a,
    {
        Self::encrypt_readwrite_with_buf_size::<I, O, { 64 * 1024 }>(
            params,
            plaintext_reader,
            ciphertext_writer,
        )
    }

    fn encrypt_readwrite_with_buf_size<'a, I: Read + 'a, O: Write + 'a, const BUF_SIZE: usize>(
        params: Self::EncryptionParams<'a>,
        plaintext_reader: I,
        ciphertext_writer: O,
    ) -> Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>
    where
        Self: Unpin + 'a;

    fn encrypting_writer<'a, O: Write + 'a>(
        params: Self::EncryptionParams<'a>,
        ciphertext_writer: O,
    ) -> Result<EncryptingWriter<'a, Self::Encryptor<'a>, O>, Error>
    where
        Self: Unpin + 'a,
    {
        Self::encrypting_writer_with_buf_size::<O, { 64 * 1024 }>(params, ciphertext_writer)
    }

    fn encrypting_writer_with_buf_size<'a, O: Write + 'a, const BUF_SIZE: usize>(
        params: Self::EncryptionParams<'a>,
        ciphertext_writer: O,
    ) -> Result<EncryptingWriter<'a, Self::Encryptor<'a>, O>, Error>
    where
        Self: Unpin + 'a;

    fn encrypt_async_readwrite<
        'a,
        I: AsyncRead + Unpin + Send + 'a,
        O: AsyncWrite + Unpin + Send + 'a,
    >(
        params: Self::EncryptionParams<'a>,
        plaintext_reader: I,
        ciphertext_writer: O,
    ) -> impl Future<
        Output = Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>,
    > + Send
    where
        Self: Unpin + 'a,
        for<'b> Self: 'b,
        for<'b> Self::Encryptor<'b>: Send + Unpin,
    {
        Self::encrypt_async_readwrite_with_buf_size::<I, O, { 64 * 1024 }>(
            params,
            plaintext_reader,
            ciphertext_writer,
        )
    }

    fn encrypt_async_readwrite_with_buf_size<
        'a,
        I: AsyncRead + Unpin + Send + 'a,
        O: AsyncWrite + Unpin + Send + 'a,
        const BUF_SIZE: usize,
    >(
        params: Self::EncryptionParams<'a>,
        plaintext_reader: I,
        ciphertext_writer: O,
    ) -> impl Future<
        Output = Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>,
    > + Send
    where
        Self: Unpin + 'a,
        for<'b> Self: 'b,
        for<'b> Self::Encryptor<'b>: Send + Unpin;

    fn encrypting_async_writer<'a, O: AsyncWrite + Unpin>(
        params: Self::EncryptionParams<'a>,
        ciphertext_writer: O,
    ) -> Result<EncryptingWriter<'a, Self::Encryptor<'a>, O>, Error>
    where
        Self: Unpin + 'a,
        for<'b> Self: 'b,
        for<'b> Self::Encryptor<'b>: Send + Unpin,
    {
        Self::encrypting_async_writer_with_buf_size::<O, { 64 * 1024 }>(params, ciphertext_writer)
    }

    fn encrypting_async_writer_with_buf_size<'a, O: AsyncWrite + Unpin, const BUF_SIZE: usize>(
        params: Self::EncryptionParams<'a>,
        ciphertext_writer: O,
    ) -> Result<EncryptingWriter<'a, Self::Encryptor<'a>, O>, Error>
    where
        Self: Unpin + 'a,
        for<'b> Self: 'b,
        for<'b> Self::Encryptor<'b>: Send + Unpin;
}

impl<T> EncryptionExt for T
where
    T: Scheme,
{
    type EncryptionParams<'a>
        = <Self as Scheme>::EncryptionParams<'a>
    where
        Self: 'a;
    type Encryptor<'a>
        = <Self as Scheme>::Encryptor<'a>
    where
        Self: 'a;

    fn encrypt<'a, I: Buf, O: BufMut>(
        params: Self::EncryptionParams<'a>,
        plaintext: &mut I,
        ciphertext: &mut O,
    ) -> Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>
    where
        Self: 'a,
    {
        let mut encryptor = <Self as Scheme>::new_encryptor(params).map_err(|e| e.into())?;
        while plaintext.has_remaining() {
            encryptor
                .update(plaintext, ciphertext)
                .map_err(|e| e.into())?;
        }
        let (tag, residual) = encryptor.finalize().map_err(|e| e.into())?;
        if let Some(residual) = residual {
            ciphertext.copy_all_from_slice(residual.as_slice())?;
        }
        Ok(tag)
    }

    fn encrypt_readwrite_with_buf_size<'a, I: Read + 'a, O: Write + 'a, const BUF_SIZE: usize>(
        params: Self::EncryptionParams<'a>,
        mut plaintext_reader: I,
        ciphertext_writer: O,
    ) -> Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>
    where
        Self: Unpin + 'a,
    {
        let mut writer =
            encrypting_writer_with_buf_size::<O, Self>(params, ciphertext_writer, BUF_SIZE)?;
        io::copy(&mut plaintext_reader, &mut writer)?;
        Ok(writer.finalize()?)
    }

    fn encrypting_writer_with_buf_size<'a, O: Write + 'a, const BUF_SIZE: usize>(
        params: Self::EncryptionParams<'a>,
        ciphertext_writer: O,
    ) -> Result<EncryptingWriter<'a, Self::Encryptor<'a>, O>, Error>
    where
        Self: Unpin + 'a,
    {
        encrypting_writer_with_buf_size::<O, Self>(params, ciphertext_writer, BUF_SIZE)
    }

    fn encrypt_async_readwrite_with_buf_size<
        'a,
        I: AsyncRead + Unpin + Send + 'a,
        O: AsyncWrite + Unpin + Send + 'a,
        const BUF_SIZE: usize,
    >(
        params: Self::EncryptionParams<'a>,
        plaintext_reader: I,
        ciphertext_writer: O,
    ) -> impl Future<
        Output = Result<<Self::Encryptor<'a> as Encryptor<'a>>::AuthenticationTag, Error>,
    > + Send
    where
        Self: Unpin + 'a,
        for<'b> Self: 'b,
        for<'b> Self::Encryptor<'b>: Send + Unpin,
    {
        async {
            let mut writer = encrypting_async_writer_with_buf_size::<O, Self>(
                params,
                ciphertext_writer,
                BUF_SIZE,
            )?;
            futures_lite::io::copy(plaintext_reader, &mut writer).await?;
            Ok(writer.finalize_async().await?)
        }
    }

    fn encrypting_async_writer_with_buf_size<'a, O: AsyncWrite + Unpin, const BUF_SIZE: usize>(
        params: Self::EncryptionParams<'a>,
        ciphertext_writer: O,
    ) -> Result<EncryptingWriter<'a, Self::Encryptor<'a>, O>, Error>
    where
        Self: Unpin + 'a,
        for<'b> Self: 'b,
        for<'b> Self::Encryptor<'b>: Send + Unpin,
    {
        encrypting_async_writer_with_buf_size::<O, Self>(params, ciphertext_writer, BUF_SIZE)
    }
}

fn encrypting_writer_with_buf_size<'a, O: Write + 'a, T>(
    params: <T as Scheme>::EncryptionParams<'a>,
    ciphertext_writer: O,
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

fn encrypting_async_writer_with_buf_size<'a, O: AsyncWrite + Unpin, T>(
    params: <T as Scheme>::EncryptionParams<'a>,
    ciphertext_writer: O,
    buf_size: usize,
) -> Result<EncryptingWriter<'a, <T as Scheme>::Encryptor<'a>, O>, Error>
where
    T: 'a,
    T: Scheme,
    T: Unpin,
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
        ciphertext: I,
        plaintext: O,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<(), Error>
    where
        Self: 'a;

    fn decrypt_readwrite<'a, I: Read, O: Write>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        plaintext_writer: O,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
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
        ciphertext_reader: I,
        plaintext_writer: O,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<(), Error>
    where
        Self: 'a;

    fn decrypting_reader<'a, I: Read>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<DecryptingReader<'a, Self::Decryptor<'a>, I>, Error>
    where
        Self: 'a,
    {
        Self::decrypting_reader_with_buf_size::<I, { 64 * 1024 }>(params, ciphertext_reader, tag)
    }

    fn decrypting_reader_with_buf_size<'a, I: Read, const BUF_SIZE: usize>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<DecryptingReader<'a, Self::Decryptor<'a>, I>, Error>
    where
        Self: 'a;

    fn decrypt_async_readwrite<
        'a,
        I: AsyncRead + Send + Unpin + 'a,
        O: AsyncWrite + Send + Unpin + 'a,
    >(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        plaintext_writer: O,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> impl Future<Output = Result<(), Error>> + Send
    where
        Self: Unpin + 'a,
        for<'b> Self: 'b,
        for<'b> Self::Decryptor<'b>: Send + Unpin,
    {
        Self::decrypt_async_readwrite_with_buf_size::<I, O, { 64 * 1024 }>(
            params,
            ciphertext_reader,
            plaintext_writer,
            tag,
        )
    }

    fn decrypt_async_readwrite_with_buf_size<
        'a,
        I: AsyncRead + Send + Unpin + 'a,
        O: AsyncWrite + Send + Unpin + 'a,
        const BUF_SIZE: usize,
    >(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        plaintext_writer: O,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> impl Future<Output = Result<(), Error>> + Send
    where
        Self: Unpin + 'a,
        for<'b> Self: 'b,
        for<'b> Self::Decryptor<'b>: Send + Unpin;
    fn decrypting_async_reader<'a, I: AsyncRead + Unpin>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<DecryptingReader<'a, Self::Decryptor<'a>, I>, Error>
    where
        Self: 'a,
        Self: Unpin,
        Self::Decryptor<'a>: Unpin,
    {
        Self::decrypting_async_reader_with_buf_size::<I, { 64 * 1024 }>(
            params,
            ciphertext_reader,
            tag,
        )
    }

    fn decrypting_async_reader_with_buf_size<'a, I: AsyncRead + Unpin, const BUF_SIZE: usize>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<DecryptingReader<'a, Self::Decryptor<'a>, I>, Error>
    where
        Self: 'a,
        Self: Unpin,
        Self::Decryptor<'a>: Unpin;
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
        mut ciphertext: I,
        mut plaintext: O,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<(), Error>
    where
        T: 'a,
    {
        let mut decryptor = <Self as Scheme>::new_decryptor(params).map_err(|e| e.into())?;
        while ciphertext.has_remaining() {
            decryptor
                .update(&mut ciphertext, &mut plaintext)
                .map_err(|e| e.into())?;
        }
        let (auth_res, residual) = decryptor.finalize(&tag);
        auth_res.map_err(|e| e.into())?;
        if let Some(residual) = residual {
            plaintext.copy_all_from_slice(residual.as_slice())?;
        }
        Ok(())
    }

    fn decrypt_readwrite_with_buf_size<'a, I: Read, O: Write, const BUF_SIZE: usize>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        plaintext_writer: O,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<(), Error>
    where
        T: 'a,
    {
        let mut reader =
            Self::decrypting_reader_with_buf_size::<I, BUF_SIZE>(params, ciphertext_reader, tag)?;
        let mut writer = plaintext_writer;
        io::copy(&mut reader, &mut writer)?;
        reader.finalize()?;
        Ok(())
    }

    fn decrypting_reader_with_buf_size<'a, I: Read, const BUF_SIZE: usize>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<DecryptingReader<'a, Self::Decryptor<'a>, I>, Error>
    where
        Self: 'a,
    {
        let decryptor = <Self as Scheme>::new_decryptor(params).map_err(|e| e.into())?;

        Ok(DecryptingReader::new(
            decryptor,
            ciphertext_reader,
            tag,
            BUF_SIZE,
        ))
    }

    async fn decrypt_async_readwrite_with_buf_size<
        'a,
        I: AsyncRead + Unpin + 'a,
        O: AsyncWrite + Unpin + 'a,
        const BUF_SIZE: usize,
    >(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        plaintext_writer: O,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<(), Error>
    where
        Self: Unpin + 'a,
        for<'b> Self: 'b,
        for<'b> Self::Decryptor<'b>: Send + Unpin,
    {
        let mut reader = Self::decrypting_async_reader_with_buf_size::<I, BUF_SIZE>(
            params,
            ciphertext_reader,
            tag,
        )?;
        let mut writer = plaintext_writer;
        futures_lite::io::copy(&mut reader, &mut writer).await?;
        reader.finalize()?;
        Ok(())
    }

    fn decrypting_async_reader_with_buf_size<'a, I: AsyncRead + Unpin, const BUF_SIZE: usize>(
        params: Self::DecryptionParams<'a>,
        ciphertext_reader: I,
        tag: <Self::Decryptor<'a> as Decryptor<'a>>::AuthenticationTag,
    ) -> Result<DecryptingReader<'a, Self::Decryptor<'a>, I>, Error>
    where
        Self: 'a,
        Self: Unpin,
        Self::Decryptor<'a>: Unpin,
    {
        let decryptor = <Self as Scheme>::new_decryptor(params).map_err(|e| e.into())?;

        Ok(DecryptingReader::new(
            decryptor,
            ciphertext_reader,
            tag,
            BUF_SIZE,
        ))
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
