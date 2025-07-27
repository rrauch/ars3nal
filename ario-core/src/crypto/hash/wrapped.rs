use crate::crypto::hash::Hasher;
use digest::{
    Digest, ExtendableOutput, ExtendableOutputReset, FixedOutput, FixedOutputReset, HashMarker,
    InvalidBufferSize, InvalidOutputSize, Output, OutputSizeUser, Reset, Update, VariableOutput,
    XofReader,
};
use generic_array::ArrayLength;
use std::ops::{Deref, DerefMut};


#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct WrappedDigest<I: Digest>(I);

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

impl<I: Digest> OutputSizeUser for WrappedDigest<I> {
    type OutputSize = I::OutputSize;
}

impl<I: Digest> FixedOutput for WrappedDigest<I>
where
    I: FixedOutput,
{
    fn finalize_into(self, out: &mut Output<Self>) {
        FixedOutput::finalize_into(self.0, out)
    }
}

impl<I: Digest> Update for WrappedDigest<I>
where
    I: Update,
{
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data)
    }
}

impl<I: Digest> Reset for WrappedDigest<I>
where
    I: Reset,
{
    fn reset(&mut self) {
        Reset::reset(&mut self.0)
    }
}

impl<I: Digest> FixedOutputReset for WrappedDigest<I>
where
    I: FixedOutputReset,
{
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        FixedOutputReset::finalize_into_reset(&mut self.0, out)
    }
}

impl<I: Digest> ExtendableOutput for WrappedDigest<I>
where
    I: ExtendableOutput,
{
    type Reader = I::Reader;

    fn finalize_xof(self) -> Self::Reader {
        ExtendableOutput::finalize_xof(self.0)
    }
}

impl<I: Digest> ExtendableOutputReset for WrappedDigest<I>
where
    I: ExtendableOutputReset,
{
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        ExtendableOutputReset::finalize_xof_reset(&mut self.0)
    }
}

impl<I: Digest> VariableOutput for WrappedDigest<I>
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

impl<I: Digest> XofReader for WrappedDigest<I>
where
    I: XofReader,
{
    fn read(&mut self, buffer: &mut [u8]) {
        XofReader::read(&mut self.0, buffer)
    }
}

impl<I: Digest> HashMarker for WrappedDigest<I> where I: HashMarker {}

impl<I: Digest + HashMarker + Send + Sync> Hasher for WrappedDigest<I>
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
}