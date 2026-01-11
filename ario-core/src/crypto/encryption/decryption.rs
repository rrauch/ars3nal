use crate::buffer::{BufExt, HeapCircularBuffer};
use crate::crypto::encryption::hazmat::SeekableDecryptor;
use crate::crypto::encryption::{BufMutExt, Decryptor, align};
use bytes::{Buf, BufMut};
use futures_lite::{AsyncRead, AsyncSeek, AsyncSeekExt, FutureExt};
use hybrid_array::typenum::Unsigned;
use std::cmp::min;
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            core::task::Poll::Ready(t) => t,
            core::task::Poll::Pending => return core::task::Poll::Pending,
        }
    };
    ($e:expr, $pending_expr:expr $(,)?) => {
        match $e {
            core::task::Poll::Ready(t) => t,
            core::task::Poll::Pending => {
                $pending_expr;
                return core::task::Poll::Pending;
            }
        }
    };
}

struct DecryptingCore<'a, D: Decryptor<'a>> {
    decryptor: Option<D>,
    buf: HeapCircularBuffer,
    eof: bool,
    _marker: PhantomData<&'a ()>,
}

impl<'a, D: Decryptor<'a>> DecryptingCore<'a, D> {
    fn new(decryptor: D, buf_size: usize) -> Self {
        Self {
            decryptor: Some(decryptor),
            buf: HeapCircularBuffer::new(align(buf_size, D::Alignment::to_usize())),
            eof: false,
            _marker: PhantomData,
        }
    }

    fn is_closed(&self) -> bool {
        self.decryptor.is_none()
    }

    fn mark_eof(&mut self) {
        self.eof = true;
    }

    fn drain_buffer(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let decryptor = self
            .decryptor
            .as_mut()
            .ok_or(Error::new(ErrorKind::Other, "reader already closed"))?;

        if self.buf.remaining() > 0 {
            let mut content = Vec::with_capacity(self.buf.remaining());

            loop {
                let len_start = content.len();
                decryptor
                    .update(&mut self.buf, &mut content)
                    .map_err(|e| Error::other(e.into()))?;
                let bytes_produced = content.len() - len_start;
                if bytes_produced == 0 {
                    break;
                }
            }

            if self.buf.has_remaining() {
                return Err(Error::new(ErrorKind::Other, "unprocessed input remains"));
            }

            Ok(Some(content))
        } else {
            Ok(None)
        }
    }

    fn seek_within_buffer(&mut self, current_pos: u64, seek_pos: u64) -> bool {
        if current_pos == seek_pos {
            return true;
        }
        if seek_pos > current_pos {
            let seek_distance = seek_pos - current_pos;
            let buf_remaining = self.buf.remaining() as u64;

            if seek_distance < buf_remaining {
                // the seek falls within the available buffer
                // no "real" seek is needed
                // advance buffer and return
                self.buf.consume(seek_distance as usize);
                return true;
            }
        }
        // seek falls outside buffer
        self.buf.reset();
        false
    }

    fn borrow_decryptor(&mut self) -> Result<&mut D, Error> {
        let decryptor = self
            .decryptor
            .as_mut()
            .ok_or(Error::new(ErrorKind::Other, "reader already closed"))?;
        Ok(decryptor)
    }

    fn take_decryptor(&mut self) -> Result<D, Error> {
        self.decryptor
            .take()
            .ok_or(Error::new(ErrorKind::Other, "reader already closed"))
    }

    fn decrypt_data(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        if self.buf.remaining() == 0 {
            return Ok(0);
        }

        let decryptor = self
            .decryptor
            .as_mut()
            .ok_or(Error::new(ErrorKind::Other, "reader already closed"))?;

        let len = min(output.len(), self.buf.remaining());
        let mut output_slice = &mut output[..len];
        let out_len_start = output_slice.len();

        decryptor
            .update(&mut self.buf.limit_buf(len), &mut output_slice)
            .map_err(|e| Error::other(e.into()))?;

        let bytes_produced = out_len_start - output_slice.len();

        Ok(bytes_produced)
    }

    fn accepts_input(&self) -> bool {
        !self.eof && !self.buf.is_full()
    }

    fn has_input(&self) -> bool {
        !self.buf.is_empty()
    }

    fn is_eof(&self) -> bool {
        self.eof
    }

    fn input_buffer(&mut self) -> &mut impl BufMut {
        &mut self.buf
    }

    fn commit_input(&mut self, bytes_read: usize) {
        self.buf.commit(bytes_read);
    }
}

impl<'a, D: Decryptor<'a>> Drop for DecryptingCore<'a, D> {
    fn drop(&mut self) {
        /*if !cfg!(test) {
            debug_assert!(
                self.decryptor.is_none(),
                "decryptor was not closed properly. 'close' needs to be called manually prior to dropping!"
            );
        }*/
        if self.decryptor.is_some() {
            // decryptor wasn't properly closed
            // output is not authenticated!
            // todo: issue warning
        }
    }
}

pub struct DecryptingReader<'a, D: Decryptor<'a>, R> {
    core: DecryptingCore<'a, D>,
    reader: R,
    len: Option<u64>,
    async_state: AsyncState,
    tag: <D as Decryptor<'a>>::AuthenticationTag,
    residual: Option<std::io::Cursor<Vec<u8>>>,
    finalization: Option<Result<(), <D as Decryptor<'a>>::Error>>,
}

enum AsyncState {
    None,
    Invalid,
    Seeking(SeekState),
}

impl<'a, D: Decryptor<'a>, R> DecryptingReader<'a, D, R> {
    pub fn new(
        decryptor: D,
        reader: R,
        tag: <D as Decryptor<'a>>::AuthenticationTag,
        buf_size: usize,
    ) -> Self {
        Self {
            core: DecryptingCore::new(decryptor, buf_size),
            reader,
            len: None,
            async_state: AsyncState::None,
            tag,
            residual: None,
            finalization: None,
        }
    }

    pub fn finalize(mut self) -> Result<(), Error> {
        if let Some(auth_res) = self.finalization {
            // already finalized
            auth_res
        } else {
            let (auth_res, _) = self.core.take_decryptor()?.finalize(&self.tag);
            auth_res
        }
        .map_err(|e| Error::other(e.into()))
    }

    fn align(pos: u64) -> (u64, usize) {
        let block_size = D::Alignment::to_usize() as u64;
        let block_no = pos / block_size;
        let offset = pos % block_size;
        (block_no * block_size, offset as usize)
    }
}

impl<'a, D: Decryptor<'a>, R: Read> DecryptingReader<'a, D, R>
where
    R: Seek,
{
    fn absolute_seek_pos(&mut self, seek_from: SeekFrom, current_pos: u64) -> Result<u64, Error> {
        if let SeekFrom::Start(pos) = seek_from {
            return Ok(pos);
        }

        if let SeekFrom::Current(pos) = seek_from {
            return Ok(current_pos.saturating_add_signed(pos));
        }

        let len = match self.len {
            Some(len) => len,
            None => {
                let len = self.reader.seek(SeekFrom::End(0))?;
                self.len = Some(len);
                self.reader.seek(SeekFrom::Start(current_pos))?;
                len
            }
        };

        if let SeekFrom::End(pos) = seek_from {
            return Ok(len.saturating_add_signed(pos));
        }
        unreachable!("seek_from")
    }
}

impl<'a, D: Decryptor<'a>, R: Read> Read for DecryptingReader<'a, D, R> {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        if let Some(residual) = self.residual.as_mut() {
            let n = min(residual.remaining(), output.len());
            residual.copy_to_slice(&mut output[..n]);
            return Ok(n);
        }

        let mut need_input =
            !self.core.has_input() && !(self.core.is_eof() || self.core.is_closed());

        loop {
            if need_input && self.core.accepts_input() {
                let input_buf = self.core.input_buffer();
                let n = input_buf.fill(&mut self.reader)?;
                if n == 0 {
                    self.core.mark_eof();
                }
                need_input = false;
            }

            if need_input {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "unexpected eof or buffer too small",
                ));
            }

            if !self.core.has_input() {
                // we keep the authentication result on purpose here
                let (auth_res, residual) = self.core.take_decryptor()?.finalize(&self.tag);
                self.finalization = Some(auth_res);

                if let Some(residual) = residual {
                    let mut residual = std::io::Cursor::new(residual);
                    let n = min(residual.remaining(), output.len());
                    residual.copy_to_slice(&mut output[..n]);
                    self.residual = Some(residual);
                    return Ok(n);
                }
                return Ok(0);
            }

            let bytes_produced = self.core.decrypt_data(output)?;
            if bytes_produced > 0 {
                return Ok(bytes_produced);
            }

            need_input = true;
        }
    }
}

impl<'a, D: Decryptor<'a>, R: AsyncRead> AsyncRead for DecryptingReader<'a, D, R>
where
    R: Unpin,
    D: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(residual) = self.residual.as_mut() {
            let n = min(residual.remaining(), output.len());
            residual.copy_to_slice(&mut output[..n]);
            return Poll::Ready(Ok(n));
        }

        let mut need_input =
            !self.core.has_input() && !(self.core.is_eof() || self.core.is_closed());
        let this = self.as_mut().get_mut();

        loop {
            if need_input && this.core.accepts_input() {
                let input_buf = this.core.input_buffer();
                let n = ready!(input_buf.read_fut(&mut this.reader).poll(cx))?;
                if n == 0 {
                    this.core.mark_eof();
                }
                need_input = false;
            }

            if need_input {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "unexpected eof or buffer too small",
                ))?;
            }

            if !this.core.has_input() {
                // we keep the authentication result on purpose here
                let (auth_res, residual) = this.core.take_decryptor()?.finalize(&this.tag);
                this.finalization = Some(auth_res);

                if let Some(residual) = residual {
                    let mut residual = std::io::Cursor::new(residual);
                    let n = min(residual.remaining(), output.len());
                    residual.copy_to_slice(&mut output[..n]);
                    this.residual = Some(residual);
                    return Poll::Ready(Ok(n));
                }
                return Poll::Ready(Ok(0));
            }

            let bytes_produced = this.core.decrypt_data(output)?;
            if bytes_produced > 0 {
                return Poll::Ready(Ok(bytes_produced));
            }

            need_input = true;
        }
    }
}

impl<'a, D: Decryptor<'a>, R: Read + Seek> Seek for DecryptingReader<'a, D, R>
where
    D: SeekableDecryptor<'a>,
{
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        if self.core.is_closed() {
            return Err(Error::other("reader already closed"));
        }
        let current_pos = self.reader.seek(SeekFrom::Current(0))?;
        let seek_pos = self.absolute_seek_pos(pos, current_pos)?;
        if self.core.seek_within_buffer(current_pos, seek_pos) {
            return Ok(seek_pos);
        }

        let (block_pos, offset) = Self::align(seek_pos);

        self.reader.seek(SeekFrom::Start(block_pos))?;
        self.core
            .borrow_decryptor()?
            .seek(block_pos)
            .map_err(|e| Error::other(e.into()))?;

        if offset > 0 {
            // read and discard `offset` bytes
            let mut discard = vec![0u8; offset];
            self.read_exact(&mut discard)?;
        }

        Ok(seek_pos)
    }
}

impl<'a, D: Decryptor<'a>, R: AsyncRead + AsyncSeek> AsyncSeek for DecryptingReader<'a, D, R>
where
    D: SeekableDecryptor<'a>,
    R: Unpin,
    D: Unpin,
{
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<std::io::Result<u64>> {
        if self.core.is_closed() {
            return Err(Error::other("reader already closed"))?;
        }
        let this = self.as_mut().get_mut();

        loop {
            match std::mem::replace(&mut this.async_state, AsyncState::Invalid) {
                AsyncState::Seeking(SeekState::AbsoluteSeekPosition(mut abs)) => {
                    let (seek_pos, current_pos, len) = ready!(
                        abs.drive(&mut this.reader, cx),
                        this.async_state = abs.into()
                    )?;
                    if let Some(len) = len {
                        this.len = Some(len);
                    }
                    if this.core.seek_within_buffer(current_pos, seek_pos) {
                        this.async_state = AsyncState::None;
                        return Poll::Ready(Ok(seek_pos));
                    }
                    let (block_pos, offset) = Self::align(seek_pos);
                    this.async_state = AsyncState::Seeking(SeekState::Seeking(block_pos, offset));
                    continue;
                }
                AsyncState::Seeking(SeekState::Seeking(block_pos, offset)) => {
                    ready!(
                        this.reader.seek(SeekFrom::Start(block_pos)).poll(cx),
                        this.async_state = SeekState::Seeking(block_pos, offset).into()
                    )?;
                    let pos = block_pos + offset as u64;

                    this.core
                        .borrow_decryptor()?
                        .seek(block_pos)
                        .map_err(|e| Error::other(e.into()))?;

                    if offset == 0 {
                        // all done
                        this.async_state = AsyncState::None;
                        return Poll::Ready(Ok(pos));
                    }

                    this.async_state = AsyncState::Seeking(SeekState::Discard(
                        HeapCircularBuffer::new(offset),
                        pos,
                    ));
                    continue;
                }
                AsyncState::Seeking(SeekState::Discard(mut discard, pos)) => {
                    while !discard.is_full() {
                        assert!(
                            ready!(
                                discard.read_fut(&mut *this).poll(cx),
                                this.async_state = SeekState::Discard(discard, pos).into()
                            )? > 0
                        );
                    }
                    // all done
                    this.async_state = AsyncState::None;
                    return Poll::Ready(Ok(pos));
                }
                AsyncState::Invalid => {
                    return Poll::Ready(Err(Error::other("invalid seek state")));
                }
                _ => {
                    this.async_state = AsyncState::Seeking(SeekState::AbsoluteSeekPosition(
                        AbsoluteSeekState::new(pos, this.len),
                    ));
                    continue;
                }
            };
        }
    }
}

enum SeekState {
    AbsoluteSeekPosition(AbsoluteSeekState),
    Seeking(u64, usize),
    Discard(HeapCircularBuffer, u64),
}

impl Into<AsyncState> for SeekState {
    fn into(self) -> AsyncState {
        AsyncState::Seeking(self)
    }
}

impl SeekState {
    fn new(seek_from: SeekFrom, len: Option<u64>) -> Self {
        Self::AbsoluteSeekPosition(AbsoluteSeekState::new(seek_from, len))
    }
}

struct AbsoluteSeekState {
    seek_from: SeekFrom,
    len: Option<u64>,
    stage: AbsoluteSeekStage,
}

impl Into<AsyncState> for AbsoluteSeekState {
    fn into(self) -> AsyncState {
        AsyncState::Seeking(SeekState::AbsoluteSeekPosition(self))
    }
}

enum AbsoluteSeekStage {
    Start,
    GetCurrentPos,
    GotCurrentPos(u64),
    GetLen(u64),
    SeekBack(u64, u64),
    GotLen(u64, u64),
    Done(u64, u64),
}

impl AbsoluteSeekState {
    fn new(seek_from: SeekFrom, len: Option<u64>) -> Self {
        Self {
            seek_from,
            len,
            stage: AbsoluteSeekStage::Start,
        }
    }

    fn drive<R: AsyncRead + AsyncSeek + Unpin>(
        &mut self,
        reader: &mut R,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(u64, u64, Option<u64>), Error>> {
        use AbsoluteSeekStage::*;

        loop {
            match self.stage {
                Start => {
                    self.stage = GetCurrentPos;
                    continue;
                }
                GetCurrentPos => {
                    self.stage = GotCurrentPos(ready!(reader.seek(SeekFrom::Current(0)).poll(cx))?);
                    continue;
                }
                GotCurrentPos(current_pos) => {
                    match self.seek_from {
                        SeekFrom::Start(pos) => {
                            self.stage = Done(pos, current_pos);
                            continue;
                        }
                        SeekFrom::Current(pos) => {
                            self.stage = Done(current_pos.saturating_add_signed(pos), current_pos);
                            continue;
                        }
                        _ => {}
                    }

                    if let Some(len) = self.len {
                        self.stage = GotLen(len, current_pos);
                        continue;
                    }
                    self.stage = GetLen(current_pos);
                    continue;
                }
                GetLen(current_pos) => {
                    self.stage =
                        SeekBack(current_pos, ready!(reader.seek(SeekFrom::End(0)).poll(cx))?);
                    continue;
                }
                SeekBack(previous_pos, len) => {
                    ready!(reader.seek(SeekFrom::Start(previous_pos)).poll(cx))?;
                    self.stage = GotLen(len, previous_pos);
                    continue;
                }
                GotLen(len, current_pos) => {
                    self.len = Some(len);
                    if let SeekFrom::End(pos) = self.seek_from {
                        self.stage = Done(len.saturating_add_signed(pos), current_pos);
                        continue;
                    }
                    unreachable!();
                }
                Done(pos, current_pos) => {
                    return Poll::Ready(Ok((pos, current_pos, self.len)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aes::gcm::{AesGcmParams, DefaultAesGcm};
    use crate::crypto::aes::{AesKey, Nonce};
    use crate::crypto::encryption::{DecryptionExt, EncryptionExt};
    use anyhow::anyhow;
    use hybrid_array::typenum::U1;
    use thiserror::Error;

    struct MockDecryptor {
        data: Vec<u8>,
    }

    impl MockDecryptor {
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

    impl<'a> Decryptor<'a> for MockDecryptor {
        type Alignment = U1;
        type AuthenticationTag = Vec<u8>;
        type Error = Error;

        fn update<I: Buf, O: BufMut>(
            &mut self,
            reader: &mut I,
            writer: &mut O,
        ) -> Result<(), Self::Error> {
            let mut buf = vec![0u8; writer.remaining_mut()];
            let bytes_read = reader.reader().read(&mut buf).map_err(|e| anyhow!(e))?;
            writer.put_slice(&buf[..bytes_read]);
            Ok(())
        }

        fn finalize(
            self,
            tag: &Self::AuthenticationTag,
        ) -> (Result<(), Self::Error>, Option<Vec<u8>>) {
            // Verify mock tag
            if tag != &vec![0xAA, 0xBB] {
                return (Err(anyhow!("Invalid authentication tag").into()), None);
            }
            (Ok(()), None)
        }

        fn position(&self) -> u64 {
            todo!()
        }
    }

    #[test]
    fn test_decrypting_reader_data_integrity() -> anyhow::Result<()> {
        let original_data = b"Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.";

        // Simulate encrypted input (in this mock case, it's just the original data)
        let encrypted_input = original_data.to_vec();
        let mut decrypted_data = Vec::new();
        let tag = vec![0xAA, 0xBB]; // Mock tag

        {
            let mut encrypted_cursor = std::io::Cursor::new(&encrypted_input);
            let decryptor = MockDecryptor::new();
            let mut reader = DecryptingReader::new(decryptor, &mut encrypted_cursor, tag, 64);

            // Read data in chunks to simulate real usage
            let mut buffer = [0u8; 16];
            loop {
                let bytes_read = std::io::Read::read(&mut reader, &mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                decrypted_data.extend_from_slice(&buffer[..bytes_read]);
            }

            reader.finalize()?;
        }

        assert_eq!(
            original_data.as_slice(),
            decrypted_data.as_slice(),
            "Data corruption in DecryptingReader!"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_decrypting_reader_async() -> anyhow::Result<()> {
        let original_data = b"Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.";

        let key = AesKey::try_from_bytes(b"gdenj3490gfso43SDdf3249fdeuuuuuu").unwrap();
        let nonce = Nonce::try_from(b"5391jvke011X".as_slice())?;
        let params = AesGcmParams::new(&key, &nonce, b"");
        let mut ciphertext = Vec::with_capacity(original_data.len());
        let tag = DefaultAesGcm::encrypt(
            params.clone(),
            &mut std::io::Cursor::new(original_data),
            &mut ciphertext,
        )?;
        let mut decrypted_data = Vec::new();

        {
            let mut reader = DefaultAesGcm::decrypting_async_reader_with_buf_size::<_, 15>(
                params,
                ciphertext.as_slice(),
                tag,
            )?;

            // Read data in chunks to simulate real usage
            let mut buffer = [0u8; 16];
            loop {
                let bytes_read = futures_lite::AsyncReadExt::read(&mut reader, &mut buffer).await?;
                if bytes_read == 0 {
                    break;
                }
                decrypted_data.extend_from_slice(&buffer[..bytes_read]);
            }

            reader.finalize()?;
        }

        assert_eq!(
            original_data.as_slice(),
            decrypted_data.as_slice(),
            "Data corruption in DecryptingReader!"
        );

        Ok(())
    }

    #[test]
    fn test_decrypting_reader() -> anyhow::Result<()> {
        let original_data = b"Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.\
        Hello, World! This is a test message for the decrypting reader.";

        let key = AesKey::try_from_bytes(b"gdenj3490gfso43SDdf3249fdeuuuuuu").unwrap();
        let nonce = Nonce::try_from(b"5391jvke011X".as_slice())?;
        let params = AesGcmParams::new(&key, &nonce, b"");
        let mut ciphertext = Vec::with_capacity(original_data.len());
        let tag = DefaultAesGcm::encrypt(
            params.clone(),
            &mut std::io::Cursor::new(original_data),
            &mut ciphertext,
        )?;
        let mut decrypted_data = Vec::new();

        {
            let mut reader = DefaultAesGcm::decrypting_reader_with_buf_size::<_, 15>(
                params,
                ciphertext.as_slice(),
                tag,
            )?;

            // Read data in chunks to simulate real usage
            let mut buffer = [0u8; 16];
            loop {
                let bytes_read = std::io::Read::read(&mut reader, &mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                decrypted_data.extend_from_slice(&buffer[..bytes_read]);
            }

            reader.finalize()?;
        }

        assert_eq!(
            original_data.as_slice(),
            decrypted_data.as_slice(),
            "Data corruption in DecryptingReader!"
        );

        Ok(())
    }
}
