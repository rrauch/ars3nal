use crate::blob::{AsBlob, Blob};
use ::aes::cipher::typenum::Unsigned;
use hybrid_array::{Array, ArraySize};

mod aes;
pub mod ec;
pub mod edwards;
pub mod encryption;
pub mod hash;
pub mod keys;
pub mod merkle;
pub mod rsa;
pub mod signature;

pub trait OutputLen: Send + Sync {
    const USIZE: usize;
    fn to_usize() -> usize;
}
impl<T> OutputLen for T
where
    T: Unsigned + Send + Sync,
{
    const USIZE: usize = <T as Unsigned>::USIZE;

    fn to_usize() -> usize {
        <T as Unsigned>::to_usize()
    }
}

pub trait Output: Clone + AsBlob + for<'a> TryFrom<Blob<'a>> + Send + Sync {
    type Len: OutputLen;
}

impl<L: OutputLen + ArraySize> AsBlob for Array<u8, L> {
    fn as_blob(&self) -> Blob<'_> {
        Blob::Slice(self.0.as_ref())
    }
}

impl<L: OutputLen + ArraySize> Output for Array<u8, L> {
    type Len = L;
}
