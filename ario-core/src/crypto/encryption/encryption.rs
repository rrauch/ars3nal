use crate::buffer::{BufExt, HeapCircularBuffer};
use crate::crypto::encryption::{Encryptor, align};
use bytes::Buf;
use futures_lite::AsyncWriteExt;
use futures_lite::FutureExt;
use futures_lite::{AsyncWrite, ready};
use hybrid_array::typenum::Unsigned;
use std::cmp::min;
use std::io::{Cursor, Error, ErrorKind, Write};
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

struct EncryptingCore<'a, E: Encryptor<'a>> {
    encryptor: Option<E>,
    buf: HeapCircularBuffer,
    closed: bool,
    _marker: PhantomData<&'a ()>,
}

impl<'a, E: Encryptor<'a>> EncryptingCore<'a, E> {
    fn new(encryptor: E, buf_size: usize) -> Self {
        Self {
            encryptor: Some(encryptor),
            buf: HeapCircularBuffer::new(align(buf_size, E::Alignment::to_usize())),
            closed: false,
            _marker: PhantomData,
        }
    }

    fn is_closed(&self) -> bool {
        self.encryptor.is_none() || self.closed
    }

    fn set_closed(&mut self) {
        self.closed = true;
    }

    fn close(&mut self) -> Result<(E::AuthenticationTag, Option<Vec<u8>>), Error> {
        let encryptor = self
            .encryptor
            .take()
            .ok_or(Error::new(ErrorKind::Other, "writer already closed"))?;

        let (tag, residual) = encryptor.finalize().map_err(|e| Error::other(e.into()))?;
        self.set_closed();
        Ok((tag, residual))
    }

    fn encrypt_data(&mut self, input: &[u8]) -> Result<usize, Error> {
        if self.buf.is_full() {
            return Ok(0);
        }

        let encryptor = self
            .encryptor
            .as_mut()
            .ok_or(Error::new(ErrorKind::Other, "writer already closed"))?;

        let len = min(input.len(), self.buf.remaining_mut());
        let mut input = Cursor::new(&input[..len]);

        encryptor
            .update(&mut input, &mut self.buf)
            .map_err(|e| Error::other(e.into()))?;

        let bytes_consumed = input.position() as usize;

        Ok(bytes_consumed)
    }

    fn take_output(&mut self) -> &mut impl Buf {
        &mut self.buf
    }

    fn remaining_input_capacity(&self) -> usize {
        self.buf.remaining_mut()
    }

    fn has_output(&self) -> bool {
        !self.buf.is_empty()
    }
}

impl<'a, E: Encryptor<'a>> Drop for EncryptingCore<'a, E> {
    fn drop(&mut self) {
        debug_assert!(
            self.encryptor.is_none(),
            "encryptor was not finalized properly. 'finalize' needs to be called manually prior to dropping!"
        );
        if self.encryptor.is_some() {
            // encryptor wasn't properly closed
            // output might be corrupted
            // todo: issue warning
        }
    }
}

pub struct EncryptingWriter<'a, E: Encryptor<'a>, W> {
    core: EncryptingCore<'a, E>,
    writer: &'a mut W,
}

impl<'a, E: Encryptor<'a>, W> EncryptingWriter<'a, E, W> {
    pub fn new(encryptor: E, writer: &'a mut W, buf_size: usize) -> Self {
        Self {
            core: EncryptingCore::new(encryptor, buf_size),
            writer,
        }
    }
}

impl<'a, E: Encryptor<'a>, W: Write> EncryptingWriter<'a, E, W> {
    pub fn finalize(mut self) -> std::io::Result<E::AuthenticationTag> {
        self.flush()?;

        let (tag, residual) = self.core.close()?;

        if let Some(residual) = residual {
            self.writer.write_all(&residual)?;
            self.writer.flush()?;
        }

        Ok(tag)
    }
}

impl<'a, E: Encryptor<'a>, W: Write> Write for EncryptingWriter<'a, E, W> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if self.core.is_closed() {
            return Err(Error::new(ErrorKind::Other, "writer already closed"));
        }

        if self.core.remaining_input_capacity() == 0 {
            self.flush()?;
        }
        self.core.encrypt_data(input)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.core.has_output() {
            let buf = self.core.take_output();
            buf.write_all(&mut self.writer)?;
        }
        self.writer.flush()?;
        Ok(())
    }
}

impl<'a, E: Encryptor<'a>, W: AsyncWrite> EncryptingWriter<'a, E, W>
where
    W: Unpin,
    E: Unpin,
{
    pub async fn finalize_async(mut self) -> std::io::Result<E::AuthenticationTag> {
        self.flush().await?;

        let (tag, residual) = self.core.close()?;

        if let Some(residual) = residual {
            self.writer.write_all(&residual).await?;
            self.writer.flush().await?;
        }

        self.writer.close().await?;

        Ok(tag)
    }
}

impl<'a, E: Encryptor<'a>, W: AsyncWrite> AsyncWrite for EncryptingWriter<'a, E, W>
where
    W: Unpin,
    E: Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.core.is_closed() {
            return Poll::Ready(Err(Error::new(ErrorKind::Other, "writer already closed")));
        }

        if self.core.remaining_input_capacity() == 0 {
            ready!(self.as_mut().poll_flush(cx))?;
        }

        Poll::Ready(self.as_mut().get_mut().core.encrypt_data(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();

        // Write all available encrypted data
        while this.core.has_output() {
            let buf = this.core.take_output();
            let bytes_written = ready!(buf.write_fut(&mut this.writer).poll(cx))?;
            if bytes_written == 0 {
                return Poll::Ready(Err(Error::new(ErrorKind::WriteZero, "write zero")));
            }
        }

        // Flush underlying writer
        ready!(Pin::new(&mut this.writer).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // `finalize_async` needs to be called to properly close the writer
        ready!(self.as_mut().poll_flush(cx))?;
        self.as_mut().get_mut().core.set_closed();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use bytes::BufMut;
    use hybrid_array::typenum::U1;
    use std::io::Read;
    use thiserror::Error;

    // Mock encryptor for testing
    struct MockEncryptor {
        data: Vec<u8>,
    }

    impl MockEncryptor {
        fn new() -> Self {
            Self { data: Vec::new() }
        }
    }

    #[derive(Error, Debug)]
    enum Error {
        #[error(transparent)]
        Any(#[from] anyhow::Error),
    }

    impl Into<crate::crypto::encryption::Error> for Error {
        fn into(self) -> crate::crypto::encryption::Error {
            crate::crypto::encryption::Error::Other(self.to_string())
        }
    }

    impl<'a> Encryptor<'a> for MockEncryptor {
        type Alignment = U1;
        type AuthenticationTag = Vec<u8>;

        fn update<R: Buf, W: BufMut>(
            &mut self,
            reader: &mut R,
            writer: &mut W,
        ) -> Result<(), Error> {
            let mut buf = vec![0u8; writer.remaining_mut()];
            let bytes_read = reader.reader().read(&mut buf).map_err(|e| anyhow!(e))?;
            writer.put_slice(&buf[..bytes_read]);
            Ok(())
        }

        fn finalize(self) -> Result<(Self::AuthenticationTag, Option<Vec<u8>>), Error> {
            Ok((vec![0xAA, 0xBB], None))
        }

        type Error = Error;

        fn position(&self) -> u64 {
            todo!()
        }
    }

    #[test]
    fn test_encrypting_writer_data_integrity() -> anyhow::Result<()> {
        let input_data = b"Hello, World! This is a test message for the encrypting writer.";
        let mut output = Vec::new();

        {
            let encryptor = MockEncryptor::new();
            let mut writer = EncryptingWriter::new(encryptor, &mut output, 64);

            // Write data in chunks to simulate real usage
            let mut pos = 0;
            while pos < input_data.len() {
                let chunk_size = min(16, input_data.len() - pos);
                let written =
                    std::io::Write::write(&mut writer, &input_data[pos..pos + chunk_size])?;
                pos += written;
                if written == 0 {
                    break;
                }
            }

            writer.finalize()?;
        }

        assert_eq!(
            input_data.as_slice(),
            output.as_slice(),
            "Data corruption in EncryptingWriter!"
        );

        Ok(())
    }
}
