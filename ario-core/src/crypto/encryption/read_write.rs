use crate::crypto::encryption::{Decryptor, Encryptor, align};
use buffer::Buffer;
use bytes::Buf;
use futures_lite::AsyncWrite;
use hybrid_array::typenum::Unsigned;
use std::cmp::min;
use std::io::{Cursor, Error, ErrorKind, Read, Result, Write};
use zeroize::Zeroize;

pub struct EncryptingWriter<'a, E: Encryptor<'a>, W> {
    encryptor: Option<E>,
    writer: &'a mut W,
    buf: Cursor<Vec<u8>>,
}

impl<'a, E: Encryptor<'a>, W> EncryptingWriter<'a, E, W> {
    pub fn new(encryptor: E, writer: &'a mut W, buf_size: usize) -> Self {
        Self {
            encryptor: Some(encryptor),
            writer,
            buf: Cursor::new(vec![0u8; align(buf_size, E::Alignment::to_usize())]),
        }
    }
}

impl<'a, E: Encryptor<'a>, W> Drop for EncryptingWriter<'a, E, W> {
    fn drop(&mut self) {
        self.buf.get_mut().zeroize();
        debug_assert!(
            self.encryptor.is_none(),
            "encryptor was not closed properly. 'close' needs to be called manually prior to dropping!"
        );
        if self.encryptor.is_some() {
            // encryptor wasn't properly closed
            // output might be corrupted
            // todo: issue warning
        }
    }
}

impl<'a, E: Encryptor<'a>, W: Write> EncryptingWriter<'a, E, W> {
    pub fn close(mut self) -> Result<E::AuthenticationTag> {
        let encryptor = self
            .encryptor
            .take()
            .ok_or(Error::new(ErrorKind::Other, "writer already closed"))?;

        self.flush()?;

        let (tag, residual) = encryptor.finalize().map_err(|e| Error::other(e.into()))?;

        if let Some(residual) = residual {
            self.writer.write_all(&residual)?;
            self.writer.flush()?;
        }

        Ok(tag)
    }
}

impl<'a, E: Encryptor<'a>, W: AsyncWrite> EncryptingWriter<'a, E, W> {
    pub async fn close_async(self) -> Result<()> {
        todo!()
    }
}

impl<'a, E: Encryptor<'a>, W: Write> Write for EncryptingWriter<'a, E, W> {
    fn write(&mut self, input: &[u8]) -> Result<usize> {
        if !self.buf.has_remaining() {
            // output buffer full, flush first
            self.flush()?;
        }

        let encryptor = self
            .encryptor
            .as_mut()
            .ok_or(Error::new(ErrorKind::Other, "writer already closed"))?;

        let len = min(input.len(), self.buf.remaining());

        let mut input = Cursor::new(&input[..len]);

        let start = self.buf.position() as usize;
        let end = start + len;
        let mut output = &mut self.buf.get_mut().as_mut_slice()[start..end];
        let out_len_start = output.len();

        encryptor
            .update(&mut input, &mut output)
            .map_err(|e| Error::other(e.into()))?;
        let bytes_consumed = input.position() as usize;
        let bytes_produced = out_len_start - output.len();

        self.buf.advance(bytes_produced);

        Ok(bytes_consumed)
    }

    fn flush(&mut self) -> Result<()> {
        let len = self.buf.position() as usize;
        if len > 0 {
            let data = &self.buf.get_ref().as_slice()[..len];
            self.writer.write_all(data)?;
            self.buf.set_position(0);
        }
        self.writer.flush()?;
        Ok(())
    }
}

pub struct DecryptingReader<'a, D: Decryptor<'a>, R> {
    decryptor: Option<D>,
    reader: &'a mut R,
    buf: Buffer,
    eof: bool,
}

impl<'a, D: Decryptor<'a>, R> DecryptingReader<'a, D, R> {
    pub fn new(decryptor: D, reader: &'a mut R, buf_size: usize) -> Self {
        Self {
            decryptor: Some(decryptor),
            reader,
            buf: Buffer::new(align(buf_size, D::Alignment::to_usize())),
            eof: false,
        }
    }
}

impl<'a, D: Decryptor<'a>, R> Drop for DecryptingReader<'a, D, R> {
    fn drop(&mut self) {
        debug_assert!(
            self.decryptor.is_none(),
            "decryptor was not closed properly. 'close' needs to be called manually prior to dropping!"
        );
        if self.decryptor.is_some() {
            // decryptor wasn't properly closed
            // output is not authenticated!
            // todo: issue warning
        }
    }
}

impl<'a, D: Decryptor<'a>, R: Read> DecryptingReader<'a, D, R> {
    pub fn close(mut self, tag: &D::AuthenticationTag) -> Result<Option<Vec<u8>>> {
        let mut decryptor = self
            .decryptor
            .take()
            .ok_or(Error::new(ErrorKind::Other, "reader already closed"))?;

        let mut residual = if self.buf.remaining() > 0 {
            // unprocessed input found
            let mut residual = vec![0u8; self.buf.remaining()];
            let mut input = Cursor::new(self.buf.as_ref());
            let mut output = residual.as_mut_slice();
            let out_len_start = output.len();
            decryptor
                .update(&mut input, &mut output)
                .map_err(|e| Error::other(e.into()))?;
            if input.has_remaining() {
                // not all input could be processed
                return Err(Error::new(ErrorKind::Other, "unprocessed input remains"));
            }
            let bytes_produced = out_len_start - output.len();
            residual.truncate(bytes_produced);
            residual
        } else {
            vec![]
        };

        if let Some(mut r2) = decryptor
            .finalize(tag)
            .map_err(|e| Error::other(e.into()))?
        {
            residual.append(&mut r2);
        }
        Ok(if residual.len() > 0 {
            Some(residual)
        } else {
            None
        })
    }
}

impl<'a, D: Decryptor<'a>, R: Read> Read for DecryptingReader<'a, D, R> {
    fn read(&mut self, output: &mut [u8]) -> Result<usize> {
        let mut need_input = self.buf.remaining() == 0;

        loop {
            if need_input && !self.eof && self.buf.remaining_mut() > 0 {
                // more input needed, fill buffer
                let output = self.buf.as_mut();
                let n = self.reader.read(output)?;
                if n == 0 {
                    self.eof = true;
                } else {
                    self.buf.advance_mut(n);
                }
                need_input = false;
            }

            if need_input {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "unexpected eof or buffer too small",
                ));
            }

            if self.buf.remaining() == 0 {
                return Ok(0);
            }

            let decryptor = self
                .decryptor
                .as_mut()
                .ok_or(Error::new(ErrorKind::Other, "reader already closed"))?;

            let len = min(output.len(), self.buf.as_ref().len());
            let mut input = Cursor::new(&self.buf.as_ref()[..len]);

            let mut output = &mut output[..len];
            let out_len_start = output.len();

            decryptor
                .update(&mut input, &mut output)
                .map_err(|e| Error::other(e.into()))?;

            let bytes_consumed = input.position() as usize;
            let bytes_produced = out_len_start - output.len();
            self.buf.advance(bytes_consumed);
            if bytes_produced > 0 {
                return Ok(bytes_produced);
            }
            // not enough input yet to produce any output
            need_input = true;
        }
    }
}

mod buffer {
    use zeroize::Zeroize;

    pub struct Buffer {
        bytes: Vec<u8>,
        head: usize,
        tail: usize,
        len: usize,
    }

    impl Buffer {
        pub fn new(capacity: usize) -> Self {
            Self {
                bytes: vec![0u8; capacity],
                head: 0,
                tail: 0,
                len: 0,
            }
        }

        /// Number of bytes available to read
        pub fn remaining(&self) -> usize {
            self.len
        }

        /// Advances the read position by consuming `read` bytes
        /// # Panics
        /// Panics if `read` exceeds available bytes
        pub fn advance(&mut self, read: usize) {
            assert!(read <= self.len, "attempt to advance beyond available data");
            self.head = (self.head + read) % self.bytes.len();
            self.len -= read;
        }

        /// Resets the buffer to empty state
        pub fn reset(&mut self) {
            self.head = 0;
            self.tail = 0;
            self.len = 0;
        }

        /// Number of bytes available for writing
        pub fn remaining_mut(&self) -> usize {
            self.bytes.len() - self.len
        }

        /// Advances the write position by committing `written` bytes
        /// # Panics
        /// Panics if `written` exceeds available space
        pub fn advance_mut(&mut self, written: usize) {
            assert!(
                written <= self.remaining_mut(),
                "attempt to advance beyond available space"
            );
            self.tail = (self.tail + written) % self.bytes.len();
            self.len += written;
        }
    }

    impl AsRef<[u8]> for Buffer {
        /// Returns slice of the readable data
        fn as_ref(&self) -> &[u8] {
            if self.head <= self.tail {
                &self.bytes[self.head..self.head + self.len]
            } else {
                let wrap_len = self.bytes.len() - self.head;
                if self.len <= wrap_len {
                    &self.bytes[self.head..self.head + self.len]
                } else {
                    &self.bytes[self.head..]
                }
            }
        }
    }

    impl AsMut<[u8]> for Buffer {
        /// Returns mutable slice of the writable space
        fn as_mut(&mut self) -> &mut [u8] {
            if self.tail < self.head {
                &mut self.bytes[self.tail..self.head]
            } else {
                &mut self.bytes[self.tail..]
            }
        }
    }

    impl Drop for Buffer {
        fn drop(&mut self) {
            self.bytes.zeroize();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_basic_operations() {
            let mut buf = Buffer::new(4);

            // Initial state
            assert_eq!(buf.remaining(), 0);
            assert_eq!(buf.remaining_mut(), 4);

            // Write data
            let write_slice = buf.as_mut();
            write_slice[..2].copy_from_slice(&[1, 2]);
            buf.advance_mut(2);

            assert_eq!(buf.remaining(), 2);
            assert_eq!(buf.remaining_mut(), 2);
            assert_eq!(buf.as_ref(), &[1, 2]);

            // Read data
            buf.advance(1);
            assert_eq!(buf.remaining(), 1);
            assert_eq!(buf.as_ref(), &[2]);

            // Write more data
            let write_slice = buf.as_mut();
            write_slice[..2].copy_from_slice(&[3, 4]);
            buf.advance_mut(2);

            assert_eq!(buf.remaining(), 3);
            assert_eq!(buf.as_ref(), &[2, 3, 4]);

            // Test circular behavior
            buf.advance(3); // Read all
            assert_eq!(buf.remaining(), 0);

            // Write past end (should wrap)
            let write_slice = buf.as_mut();
            write_slice[..3].copy_from_slice(&[5, 6, 7]);
            buf.advance_mut(3);

            assert_eq!(buf.remaining(), 3);
            assert_eq!(buf.as_ref(), &[5, 6, 7]);
        }

        #[test]
        fn test_full_buffer() {
            let mut buf = Buffer::new(3);

            // Fill buffer
            let write_slice = buf.as_mut();
            write_slice.copy_from_slice(&[1, 2, 3]);
            buf.advance_mut(3);

            assert_eq!(buf.remaining(), 3);
            assert_eq!(buf.remaining_mut(), 0);
            assert_eq!(buf.as_ref(), &[1, 2, 3]);

            // Read partially
            buf.advance(2);
            assert_eq!(buf.remaining(), 1);
            assert_eq!(buf.as_ref(), &[3]);

            // Write should now be available
            assert_eq!(buf.remaining_mut(), 2);
        }

        #[test]
        fn test_reset() {
            let mut buf = Buffer::new(4);

            // Write some data
            let write_slice = buf.as_mut();
            write_slice[..2].copy_from_slice(&[1, 2]);
            buf.advance_mut(2);

            assert_eq!(buf.remaining(), 2);

            // Reset
            buf.reset();

            assert_eq!(buf.remaining(), 0);
            assert_eq!(buf.remaining_mut(), 4);
        }

        #[test]
        #[cfg(not(debug_assertions))]
        #[should_panic(expected = "attempt to advance beyond available data")]
        fn test_advance_beyond_data() {
            let mut buf = Buffer::new(2);
            buf.advance(1);
        }

        #[test]
        #[cfg(not(debug_assertions))]
        #[should_panic(expected = "attempt to advance beyond available space")]
        fn test_advance_mut_beyond_capacity() {
            let mut buf = Buffer::new(2);
            let write_slice = buf.as_mut();
            write_slice[..2].copy_from_slice(&[1, 2]);
            buf.advance_mut(2);
            buf.advance_mut(1); // Should panic
        }
    }
}
