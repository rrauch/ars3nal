use bytes::buf::UninitSlice;
use bytes::{Buf, BufMut};
use futures_lite::{AsyncRead, AsyncWrite, ready};
use hybrid_array::ArraySize;
use std::cmp::min;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, ptr};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum BufError {
    #[error("chunk too small: required: '{required}', actual: '{actual}'")]
    ChunkTooSmall { required: usize, actual: usize },
    #[error("buffer too small: required: '{required}', actual: '{actual}'")]
    BufferTooSmall { required: usize, actual: usize },
    #[error("buffer overflow")]
    BufferOverflow,
    #[error("buffer error")]
    Other,
}

pub(crate) trait BufExt<B: Buf + ?Sized> {
    fn chunk_slice(&self, len: usize) -> Result<&[u8], BufError>;
    fn write_all<W: Write>(&mut self, output: W) -> io::Result<usize>;

    fn limit_buf(&mut self, limit: usize) -> LimitedBuf<'_, B>;
    fn write_fut<'a, W: AsyncWrite + 'a>(&'a mut self, writer: W) -> WriteBufFut<'a, W, B>
    where
        B: Sized;
}

pub struct WriteBufFut<'a, W: AsyncWrite + 'a, B: Buf> {
    writer: W,
    buf: &'a mut B,
}

impl<'a, W: AsyncWrite + 'a, B: Buf> WriteBufFut<'a, W, B> {
    fn new(writer: W, buf: &'a mut B) -> Self {
        Self { writer, buf }
    }
}

impl<'a, W: AsyncWrite + 'a + Unpin, B: Buf + Unpin> Future for WriteBufFut<'a, W, B> {
    type Output = Result<usize, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();

        if !this.buf.has_remaining() {
            return Poll::Ready(Ok(0));
        }

        let chunk = this.buf.chunk();

        match ready!(Pin::new(&mut this.writer).poll_write(cx, chunk)) {
            Ok(n) => {
                this.buf.advance(n);
                Poll::Ready(Ok(n))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

pub struct LimitedBuf<'a, B: Buf + ?Sized> {
    buf: &'a mut B,
    remaining: usize,
}

impl<'a, B: Buf + ?Sized> LimitedBuf<'a, B> {
    fn new(buf: &'a mut B, limit: usize) -> Self {
        Self {
            remaining: min(buf.remaining(), limit),
            buf,
        }
    }
}

impl<'a, B: Buf> Buf for LimitedBuf<'a, B> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        if self.remaining == 0 {
            return &[];
        };

        let chunk = self.buf.chunk();
        let len = min(chunk.len(), self.remaining);
        &chunk[..len]
    }

    fn advance(&mut self, cnt: usize) {
        self.remaining = self.remaining.saturating_sub(cnt);
        self.buf.advance(cnt);
    }
}

impl<T: Buf + ?Sized> BufExt<T> for T {
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

    fn limit_buf(&mut self, limit: usize) -> LimitedBuf<'_, T> {
        LimitedBuf::new(self, limit)
    }

    fn write_fut<'a, W: AsyncWrite + 'a>(&'a mut self, writer: W) -> WriteBufFut<'a, W, T>
    where
        T: Sized,
    {
        WriteBufFut::new(writer, self)
    }
}

pub(crate) trait BufMutExt<B: BufMut> {
    fn chunk_mut_slice(&mut self) -> &mut [u8];
    fn copy_all_from_slice(&mut self, input: &[u8]) -> Result<(), BufError>
    where
        Self: BufMut,
    {
        if self.remaining_mut() < input.remaining() {
            return Err(BufError::BufferTooSmall {
                required: input.remaining(),
                actual: self.remaining_mut(),
            });
        }

        let mut len = input.len() as u64;
        len -= self.transfer_from_buf(&mut Cursor::new(input));
        if len != 0 {
            //todo
            panic!("copying failed: {} bytes remaining", len);
        }
        Ok(())
    }

    fn transfer_from_buf(&mut self, input: &mut impl Buf) -> u64;

    fn fill<R: Read>(&mut self, reader: R) -> io::Result<usize>;
    //unsafe fn chunk_mut_slice_unsafe(&mut self) -> &mut [u8];

    fn read_fut<'a, R: AsyncRead + 'a>(&'a mut self, reader: R) -> ReadBufFut<'a, R, B>;
    unsafe fn chunk_mut_slice_unsafe(&mut self) -> &mut [u8];
    fn transfer_exact_from_buf(
        &mut self,
        input: &mut impl Buf,
        bytes: usize,
    ) -> Result<(), io::Error>;
}

impl<T: BufMut> BufMutExt<T> for T {
    fn chunk_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: We're zero-initializing possibly uninitialized memory.
        // The slice bounds are guaranteed valid and writing to MaybeUninit<u8> as u8 is safe.
        unsafe {
            let maybe_uninit = self.chunk_mut().as_uninit_slice_mut();
            ptr::write_bytes(
                maybe_uninit.as_mut_ptr() as *mut u8,
                0x00,
                maybe_uninit.len(),
            );
            std::slice::from_raw_parts_mut(maybe_uninit.as_mut_ptr() as *mut _, maybe_uninit.len())
        }
    }

    /// The caller **must** ensure that no uninitialized bytes are read from or written to the retured slice.
    unsafe fn chunk_mut_slice_unsafe(&mut self) -> &mut [u8] {
        unsafe {
            let maybe_uninit = self.chunk_mut().as_uninit_slice_mut();
            std::slice::from_raw_parts_mut(maybe_uninit.as_mut_ptr() as *mut _, maybe_uninit.len())
        }
    }

    fn transfer_from_buf(&mut self, input: &mut impl Buf) -> u64 {
        let mut n = 0;
        loop {
            if !input.has_remaining() {
                break;
            }
            let chunk_len = self.chunk_mut().len();
            if chunk_len == 0 {
                break;
            }

            let len = min(input.remaining(), chunk_len);

            // SAFETY: used solely for writing initialized bytes
            let out = &mut unsafe { self.chunk_mut_slice_unsafe() }[..len];

            out.copy_from_slice(&input.chunk()[..len]);
            input.advance(len);
            unsafe { self.advance_mut(len) }
            n += len as u64;
        }
        n
    }

    fn transfer_exact_from_buf(
        &mut self,
        input: &mut impl Buf,
        bytes: usize,
    ) -> Result<(), io::Error> {
        let mut input = input.limit_buf(bytes);
        let n = self.transfer_from_buf(&mut input) as usize;
        if n != bytes {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                format!("read {} bytes but expected {}", n, bytes),
            ));
        }
        Ok(())
    }

    fn fill<R: Read>(&mut self, mut reader: R) -> io::Result<usize> {
        let mut read = 0;
        while self.has_remaining_mut() {
            let chunk = unsafe {
                let maybe_uninit = self.chunk_mut().as_uninit_slice_mut();
                std::slice::from_raw_parts_mut(
                    maybe_uninit.as_mut_ptr() as *mut _,
                    maybe_uninit.len(),
                )
            };
            let n = reader.read(chunk)?;
            if n > 0 {
                read += n;
                unsafe {
                    self.advance_mut(n);
                }
                continue;
            }
            return Ok(read);
        }
        Ok(read)
    }

    fn read_fut<'a, R: AsyncRead + 'a>(&'a mut self, reader: R) -> ReadBufFut<'a, R, T> {
        ReadBufFut::new(reader, self)
    }
}

pub struct ReadBufFut<'a, R: AsyncRead + 'a, B: BufMut> {
    reader: R,
    buf: &'a mut B,
}

impl<'a, R: AsyncRead + 'a + Unpin, B: BufMut + Unpin> Future for ReadBufFut<'a, R, B> {
    type Output = Result<usize, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();

        if !this.buf.has_remaining_mut() {
            return Poll::Ready(Err(io::Error::other("buffer overflow")));
        }
        let chunk = unsafe {
            let maybe_uninit = this.buf.chunk_mut().as_uninit_slice_mut();
            std::slice::from_raw_parts_mut(maybe_uninit.as_mut_ptr() as *mut _, maybe_uninit.len())
        };
        match ready!(Pin::new(&mut this.reader).poll_read(cx, chunk)) {
            Ok(n) => {
                unsafe {
                    this.buf.advance_mut(n);
                }
                Poll::Ready(Ok(n))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl<'a, R: AsyncRead + 'a, B: BufMut> ReadBufFut<'a, R, B> {
    fn new(reader: R, buf: &'a mut B) -> Self {
        Self { reader, buf }
    }
}

trait CBStorage: Zeroize + Send {
    fn len(&self) -> usize;
    fn as_slice(&self) -> &[u8];
    fn as_mut_slice(&mut self) -> &mut [u8];
    fn split_at(&self, offset: usize) -> (&[u8], &[u8]);
    fn split_at_mut(&mut self, offset: usize) -> (&mut [u8], &mut [u8]);
}

impl CBStorage for Vec<u8> {
    fn len(&self) -> usize {
        self.len()
    }

    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }

    fn split_at(&self, offset: usize) -> (&[u8], &[u8]) {
        self.as_slice().split_at(offset)
    }

    fn split_at_mut(&mut self, offset: usize) -> (&mut [u8], &mut [u8]) {
        self.as_mut_slice().split_at_mut(offset)
    }
}

impl<N: ArraySize> CBStorage for hybrid_array::Array<u8, N> {
    fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }

    fn split_at(&self, offset: usize) -> (&[u8], &[u8]) {
        self.as_slice().split_at(offset)
    }

    fn split_at_mut(&mut self, offset: usize) -> (&mut [u8], &mut [u8]) {
        self.as_mut_slice().split_at_mut(offset)
    }
}

pub struct CircularBuffer<S: CBStorage> {
    bytes: S,
    size: usize,
    start: usize,
}

pub type HeapCircularBuffer = CircularBuffer<Vec<u8>>;

impl HeapCircularBuffer {
    pub fn new(capacity: usize) -> Self {
        Self::_new(vec![0u8; capacity])
    }
}

pub type StackCircularBuffer<N: ArraySize> = CircularBuffer<hybrid_array::Array<u8, N>>;

impl<N: ArraySize> StackCircularBuffer<N> {
    pub fn new() -> Self {
        Self::_new(hybrid_array::Array::default())
    }
}

impl<S: CBStorage> CircularBuffer<S> {
    fn _new(bytes: S) -> Self {
        Self {
            bytes,
            size: 0,
            start: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Number of bytes available to read
    pub fn remaining(&self) -> usize {
        self.size
    }

    /// Advances the read position by consuming `read` bytes
    /// # Panics
    /// Panics if `read` exceeds available bytes
    pub fn consume(&mut self, read: usize) {
        assert!(
            read <= self.size,
            "attempt to consume beyond available data"
        );
        if read == 0 {
            return;
        }
        let capacity = self.bytes.len();
        debug_assert!(self.start < capacity, "start out-of-bounds");
        self.start = add_mod(self.start, read, capacity);
        self.size -= read;
    }

    /// Resets the buffer to empty state
    pub fn reset(&mut self) {
        self.size = 0;
        self.start = 0;
    }

    pub fn is_full(&self) -> bool {
        self.size == self.bytes.len()
    }

    /// Number of bytes available for writing
    pub fn remaining_mut(&self) -> usize {
        self.bytes.len() - self.size
    }

    /// Advances the write position by committing `written` bytes
    /// # Panics
    /// Panics if `written` exceeds available space
    pub fn commit(&mut self, written: usize) {
        assert!(
            written <= self.remaining_mut(),
            "attempt to advance beyond available space"
        );
        if written == 0 {
            return;
        }
        self.size += written;
    }

    pub fn as_slices(&self) -> (&[u8], &[u8]) {
        let capacity = self.bytes.len();

        if capacity == 0 || self.is_empty() {
            return (&[], &[]);
        }

        debug_assert!(self.start < capacity, "start out-of-bounds");
        debug_assert!(self.size <= capacity, "size out-of-bounds");

        let start = self.start;
        let end = add_mod(self.start, self.size, capacity);

        if start < end {
            (&self.bytes.as_slice()[start..end], &[][..])
        } else {
            let (back, front) = self.bytes.split_at(start);
            (front, &back[..end])
        }
    }

    pub fn as_mut_slices(&mut self) -> (&mut [u8], &mut [u8]) {
        let capacity = self.bytes.len();

        if capacity == 0 || self.size == capacity {
            return (&mut [][..], &mut [][..]);
        }

        debug_assert!(self.start < capacity, "start out-of-bounds");
        debug_assert!(self.size <= capacity, "size out-of-bounds");

        let write_start = add_mod(self.start, self.size, capacity);
        let available = capacity - self.size;
        let write_end = add_mod(write_start, available, capacity);

        if write_start < write_end {
            (
                &mut self.bytes.as_mut_slice()[write_start..write_end],
                &mut [][..],
            )
        } else {
            let (back, front) = self.bytes.split_at_mut(write_start);
            (front, &mut back[..write_end])
        }
    }

    pub fn make_contiguous(&mut self) -> &[u8] {
        let capacity = self.bytes.len();

        if capacity == 0 || self.size == 0 {
            return &[];
        }

        debug_assert!(self.start < capacity, "start out-of-bounds");
        debug_assert!(self.size <= capacity, "size out-of-bounds");

        let start = self.start;
        let end = add_mod(self.start, self.size, capacity);

        if start < end {
            // Already contiguous; nothing to do
            &self.bytes.as_slice()[start..end]
        } else {
            // Not contiguous; need to rotate
            self.start = 0;
            self.bytes.as_mut_slice().rotate_left(start);
            &self.bytes.as_slice()[..self.size]
        }
    }
}

/// Returns `(x + y) % m` without risk of overflows if `x + y` cannot fit in `usize`.
///
/// `x` and `y` are expected to be less than, or equal to `m`.
#[inline]
const fn add_mod(x: usize, y: usize, m: usize) -> usize {
    debug_assert!(m > 0);
    debug_assert!(x <= m);
    debug_assert!(y <= m);
    let (z, overflow) = x.overflowing_add(y);
    (z + (overflow as usize) * (usize::MAX % m + 1)) % m
}

impl<S: CBStorage> Drop for CircularBuffer<S> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<S: CBStorage> Buf for CircularBuffer<S> {
    fn remaining(&self) -> usize {
        self.remaining()
    }

    fn chunk(&self) -> &[u8] {
        let (first, second) = self.as_slices();
        if !first.is_empty() { first } else { second }
    }

    fn advance(&mut self, cnt: usize) {
        self.consume(cnt);
    }
}

unsafe impl<S: CBStorage> BufMut for CircularBuffer<S> {
    fn remaining_mut(&self) -> usize {
        self.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.commit(cnt)
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let (first, second) = self.as_mut_slices();
        let slice = if !first.is_empty() { first } else { second };

        UninitSlice::new(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybrid_array::sizes::*;

    static ONE_MB: &'static [u8] = include_bytes!("../testdata/1mb.bin");

    macro_rules! test_all_impls {
        ($test_name:ident, $test_body:expr) => {
            #[test]
            fn $test_name() {
                // Test heap implementation
                {
                    let buf: HeapCircularBuffer = HeapCircularBuffer::new(10);
                    $test_body(buf);
                }

                // Test stack implementation
                {
                    let buf: StackCircularBuffer<U10> = StackCircularBuffer::new();
                    $test_body(buf);
                }
            }
        };
    }

    macro_rules! test_all_impls_custom_size {
        ($test_name:ident, $size:expr, $stack_size:ty, $test_body:expr) => {
            #[test]
            fn $test_name() {
                // Test heap implementation
                {
                    let buf: HeapCircularBuffer = HeapCircularBuffer::new($size);
                    $test_body(buf);
                }

                // Test stack implementation
                {
                    let buf: StackCircularBuffer<$stack_size> = StackCircularBuffer::new();
                    $test_body(buf);
                }
            }
        };
    }

    test_all_impls!(test_empty_buffer, |buf: CircularBuffer<_>| {
        assert!(buf.is_empty());
        assert_eq!(buf.remaining(), 0);
        assert_eq!(buf.remaining_mut(), buf.capacity());
        assert!(!buf.is_full());
    });

    test_all_impls_custom_size!(test_full_buffer, 5, U5, |mut buf: CircularBuffer<_>| {
        buf.commit(5);
        assert!(buf.is_full());
        assert_eq!(buf.remaining(), 5);
        assert_eq!(buf.remaining_mut(), 0);
    });

    test_all_impls_custom_size!(test_consume_partial, 5, U5, |mut buf: CircularBuffer<_>| {
        buf.commit(3);
        buf.consume(2);
        assert_eq!(buf.remaining(), 1);
        assert_eq!(buf.remaining_mut(), 4);
    });

    #[test]
    #[cfg(not(debug_assertions))]
    #[should_panic]
    fn test_consume_too_much() {
        let mut buf = HeapCircularBuffer::new(5);
        buf.commit(3);
        buf.consume(4);
    }

    test_all_impls_custom_size!(test_wrap_around_read, 3, U3, |mut buf: CircularBuffer<
        _,
    >| {
        buf.commit(3);
        buf.consume(2);
        buf.commit(2);

        let (slice1, slice2) = buf.as_slices();
        assert_eq!(slice1.len() + slice2.len(), 3);
        assert!(!slice1.is_empty());
        assert!(!slice2.is_empty());
    });

    test_all_impls_custom_size!(test_wrap_around_write, 3, U3, |mut buf: CircularBuffer<
        _,
    >| {
        buf.commit(2);
        buf.consume(2);
        buf.commit(2);

        let (slice1, slice2) = buf.as_slices();
        assert_eq!(slice1.len() + slice2.len(), 2);
    });

    test_all_impls_custom_size!(test_zero_capacity, 0, U0, |mut buf: CircularBuffer<_>| {
        assert!(buf.is_empty());
        assert!(buf.is_full());
        assert_eq!(buf.remaining(), 0);
        assert_eq!(buf.remaining_mut(), 0);

        buf.consume(0);
        buf.commit(0);
        buf.reset();
    });

    test_all_impls_custom_size!(test_reset, 5, U5, |mut buf: CircularBuffer<_>| {
        buf.commit(3);
        buf.consume(1);
        buf.reset();

        assert!(buf.is_empty());
        assert_eq!(buf.start, 0);
        assert_eq!(buf.remaining_mut(), buf.capacity());
    });

    test_all_impls_custom_size!(test_mut_slices_wrap, 4, U4, |mut buf: CircularBuffer<_>| {
        buf.commit(4);
        buf.consume(3);
        buf.commit(2);

        let (slice1, slice2) = buf.as_mut_slices();
        assert_eq!(slice1.len() + slice2.len(), 1);
    });

    test_all_impls_custom_size!(
        test_exact_capacity_usage,
        2,
        U2,
        |mut buf: CircularBuffer<_>| {
            buf.commit(2);
            buf.consume(2);
            buf.commit(2);

            assert!(buf.is_full());
            assert_eq!(buf.remaining(), 2);
        }
    );

    #[test]
    fn test_data_integrity_through_circular_buffer() {
        let input_data: &[u8] = ONE_MB;
        let mut circular_buffer = HeapCircularBuffer::new(64 * 1024);
        let mut output = Vec::new();
        let mut input_pos = 0;

        while input_pos < input_data.len() {
            let (first_mut, second_mut) = circular_buffer.as_mut_slices();
            let mut written = 0;

            if !first_mut.is_empty() {
                let to_copy = std::cmp::min(first_mut.len(), input_data.len() - input_pos);
                first_mut[..to_copy].copy_from_slice(&input_data[input_pos..input_pos + to_copy]);
                written += to_copy;
                input_pos += to_copy;
            }

            if !second_mut.is_empty() && input_pos < input_data.len() {
                let to_copy = std::cmp::min(second_mut.len(), input_data.len() - input_pos);
                second_mut[..to_copy].copy_from_slice(&input_data[input_pos..input_pos + to_copy]);
                written += to_copy;
                input_pos += to_copy;
            }

            circular_buffer.commit(written);

            let (first, second) = circular_buffer.as_slices();
            if !first.is_empty() {
                output.extend_from_slice(first);
            }
            if !second.is_empty() {
                output.extend_from_slice(second);
            }

            circular_buffer.consume(circular_buffer.remaining());
        }

        assert_eq!(input_data, output.as_slice(), "Data corruption detected!");
    }

    test_all_impls_custom_size!(
        test_data_integrity_through_circular_buffer_buf_traits,
        64,
        U64,
        |mut buf: CircularBuffer<_>| {
            let input_data: &[u8] =
                b"your_test_data_here_with_some_longer_content_to_test_wrapping";
            let mut output = Vec::new();
            let mut input_pos = 0;

            while input_pos < input_data.len() {
                while buf.remaining_mut() > 0 && input_pos < input_data.len() {
                    let chunk = buf.chunk_mut();
                    let to_copy = min(chunk.len(), input_data.len() - input_pos);

                    unsafe {
                        ptr::copy_nonoverlapping(
                            input_data[input_pos..].as_ptr(),
                            chunk.as_mut_ptr(),
                            to_copy,
                        );
                        buf.advance_mut(to_copy);
                    }
                    input_pos += to_copy;
                }

                while buf.remaining() > 0 {
                    let chunk = buf.chunk();
                    output.extend_from_slice(chunk);
                    let chunk_len = chunk.len();
                    buf.advance(chunk_len);
                }
            }

            assert_eq!(input_data, output.as_slice(), "Data corruption detected!");
        }
    );

    test_all_impls_custom_size!(
        test_as_mut_slices_returns_writable_space,
        8,
        U8,
        |mut buf: CircularBuffer<_>| {
            let (first, second) = buf.as_mut_slices();
            assert_eq!(
                first.len() + second.len(),
                8,
                "Empty buffer should have full capacity writable"
            );

            first[0..3].copy_from_slice(b"abc");
            buf.commit(3);

            let (first, second) = buf.as_mut_slices();
            assert_eq!(
                first.len() + second.len(),
                5,
                "After writing 3 bytes, should have 5 writable"
            );

            let total_writable = first.len() + second.len();
            if !first.is_empty() {
                first.fill(b'x');
            }
            if !second.is_empty() {
                second.fill(b'y');
            }
            buf.commit(total_writable);

            let (first, second) = buf.as_mut_slices();
            assert_eq!(
                first.len() + second.len(),
                0,
                "Full buffer should have no writable space"
            );

            buf.consume(2);

            let (first, second) = buf.as_mut_slices();
            assert_eq!(
                first.len() + second.len(),
                2,
                "After consuming 2 bytes, should have 2 writable"
            );
        }
    );
}
