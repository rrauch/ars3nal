use crate::blob::{AsBlob, Blob};
use hybrid_array::{Array, ArraySize};

pub mod ec;
pub mod encryption;
pub mod hash;
pub mod keys;
pub mod merkle;
pub mod rsa;
pub mod signature;
mod aes;

pub trait OutputLen: ArraySize + Send + Sync {}
impl<T> OutputLen for T where T: ArraySize + Send + Sync {}

pub trait Output: Clone + AsBlob + for<'a> TryFrom<Blob<'a>> + Send + Sync {
    type Len: OutputLen;
}

impl<L: OutputLen> AsBlob for Array<u8, L> {
    fn as_blob(&self) -> Blob<'_> {
        Blob::Slice(self.0.as_ref())
    }
}

impl<L: OutputLen> Output for Array<u8, L> {
    type Len = L;
}
