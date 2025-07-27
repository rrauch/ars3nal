use digest::{
    Digest, ExtendableOutput, ExtendableOutputReset, FixedOutput, FixedOutputReset, HashMarker,
    InvalidBufferSize, InvalidOutputSize, Output, OutputSizeUser, Reset, Update, VariableOutput,
    XofReader,
};
use std::io::Write;
use std::ops::{Deref, DerefMut};

#[derive(Debug)]
#[repr(transparent)]
pub struct WrappedDigest<I>(I);

impl<I: Digest> WrappedDigest<I> {
    pub(crate) fn from_inner(inner: I) -> Self {
        Self(inner)
    }
}

impl<I: Digest> AsRef<I> for WrappedDigest<I> {
    fn as_ref(&self) -> &I {
        &self.0
    }
}

impl<I> Default for WrappedDigest<I>
where
    I: Default,
{
    fn default() -> Self {
        Self(I::default())
    }
}

impl<I> Clone for WrappedDigest<I>
where
    I: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<I> Write for WrappedDigest<I>
where
    I: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl<I: Digest> AsMut<I> for WrappedDigest<I> {
    fn as_mut(&mut self) -> &mut I {
        &mut self.0
    }
}

impl<I: Digest> Deref for WrappedDigest<I> {
    type Target = I;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<I: Digest> DerefMut for WrappedDigest<I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<I> OutputSizeUser for WrappedDigest<I>
where
    I: OutputSizeUser,
{
    type OutputSize = I::OutputSize;
}

impl<I> FixedOutput for WrappedDigest<I>
where
    I: FixedOutput,
{
    fn finalize_into(self, out: &mut Output<Self>) {
        FixedOutput::finalize_into(self.0, out)
    }
}

impl<I> Update for WrappedDigest<I>
where
    I: Update,
{
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data)
    }
}

impl<I> Reset for WrappedDigest<I>
where
    I: Reset,
{
    fn reset(&mut self) {
        Reset::reset(&mut self.0)
    }
}

impl<I> FixedOutputReset for WrappedDigest<I>
where
    I: FixedOutputReset,
{
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        FixedOutputReset::finalize_into_reset(&mut self.0, out)
    }
}

impl<I> ExtendableOutput for WrappedDigest<I>
where
    I: ExtendableOutput,
{
    type Reader = I::Reader;

    fn finalize_xof(self) -> Self::Reader {
        ExtendableOutput::finalize_xof(self.0)
    }
}

impl<I> ExtendableOutputReset for WrappedDigest<I>
where
    I: ExtendableOutputReset,
{
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        ExtendableOutputReset::finalize_xof_reset(&mut self.0)
    }
}

impl<I> VariableOutput for WrappedDigest<I>
where
    I: VariableOutput,
{
    const MAX_OUTPUT_SIZE: usize = I::MAX_OUTPUT_SIZE;

    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        Ok(Self(<I as VariableOutput>::new(output_size)?))
    }

    fn output_size(&self) -> usize {
        VariableOutput::output_size(&self.0)
    }

    fn finalize_variable(self, out: &mut [u8]) -> Result<(), InvalidBufferSize> {
        VariableOutput::finalize_variable(self.0, out)
    }
}

impl<I> XofReader for WrappedDigest<I>
where
    I: XofReader,
{
    fn read(&mut self, buffer: &mut [u8]) {
        XofReader::read(&mut self.0, buffer)
    }
}

impl<I> HashMarker for WrappedDigest<I> where I: HashMarker {}

/*impl<I: Digest> Digest for WrappedDigest<I> {
    fn new() -> Self {
        Self::from_inner(I::new())
    }

    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        Self::from_inner(I::new_with_prefix(data))
    }

    #[inline]
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data)
    }

    #[inline]
    fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
        Self::from_inner(self.0.chain_update(data))
    }

    #[inline]
    fn finalize(self) -> Output<Self> {
        self.0.finalize()
    }

    fn finalize_into(self, out: &mut Output<Self>) {
        self.0.finalize_into(out)
    }

    fn finalize_reset(&mut self) -> Output<Self>
    where
        Self: FixedOutputReset,
    {
        <Self as FixedOutputReset>::finalize_fixed_reset(self)
    }

    fn finalize_into_reset(&mut self, out: &mut Output<Self>)
    where
        Self: FixedOutputReset,
    {
        <Self as FixedOutputReset>::finalize_into_reset(self, out)
    }

    fn reset(&mut self)
    where
        Self: Reset,
    {
        <Self as Reset>::reset(self)
    }

    #[inline]
    fn output_size() -> usize {
        <I as Digest>::output_size()
    }

    #[inline]
    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        I::digest(data)
    }
}*/

/*impl<I: Digest + HashMarker + Send + Sync> Hasher for WrappedDigest<I>
where
    <I as OutputSizeUser>::OutputSize: ArrayLength,
{
    type DigestLen = I::OutputSize;

    fn new() -> Self {
        WrappedDigest::from_inner(I::new())
    }

    #[inline]
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data)
    }

    fn finalize(self) -> crate::crypto::hash::Digest<Self>
    where
        Self: Sized,
    {
        // due to a crate version conflict the generic array is first turned into a vec
        // before converted back to a generic array
        super::Digest::from_bytes(
            self.0
                .finalize()
                .to_vec()
                .try_into()
                .expect("generic array conversion should never fail"),
        )
    }
}*/
