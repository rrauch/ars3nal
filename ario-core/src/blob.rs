use crate::typed::Typed;
use bytes::Bytes;
use hybrid_array::{Array, ArraySize};
use std::array::TryFromSliceError;
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use thiserror::Error;

pub type TypedBlob<'a, T> = Typed<T, Blob<'a>>;

#[derive(Clone, PartialEq)]
pub enum Blob<'a> {
    Bytes(Bytes),
    Slice(&'a [u8]),
}

pub type OwnedBlob = Blob<'static>;

impl From<Bytes> for OwnedBlob {
    fn from(value: Bytes) -> Self {
        Self::Bytes(value)
    }
}

impl From<Box<[u8]>> for OwnedBlob {
    fn from(value: Box<[u8]>) -> Self {
        Self::Bytes(Bytes::from(value))
    }
}

impl From<Vec<u8>> for OwnedBlob {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(Bytes::from(value))
    }
}

impl<const N: usize> From<[u8; N]> for OwnedBlob {
    fn from(value: [u8; N]) -> Self {
        Self::Bytes(Bytes::from(Box::<[u8]>::from(value)))
    }
}

impl<'a> From<&'a [u8]> for Blob<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Slice(value)
    }
}

impl<'a> From<&'a Vec<u8>> for Blob<'a> {
    fn from(value: &'a Vec<u8>) -> Self {
        Self::Slice(value.as_slice())
    }
}

impl<'a> Blob<'a> {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Bytes(b) => b.deref(),
            Self::Slice(b) => *b,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Bytes(b) => b.len(),
            Self::Slice(b) => b.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Bytes(b) => b.is_empty(),
            Self::Slice(b) => b.is_empty(),
        }
    }

    pub fn into_owned(self) -> OwnedBlob {
        let bytes = match self {
            Self::Bytes(b) => b,
            Self::Slice(s) => Bytes::copy_from_slice(s),
        };
        Blob::from(bytes)
    }
}

impl<'a> AsRef<[u8]> for Blob<'a> {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

impl<'a> Deref for Blob<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}

impl<'a> Debug for Blob<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[blob;len={}b]", self.len()).as_str())
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid length, expected '{expected}' but go '{actual}'")]
    InvalidLength { expected: usize, actual: usize },
    #[error(transparent)]
    ConversionError(#[from] TryFromSliceError),
}

impl<'a, N: ArraySize> TryFrom<Blob<'a>> for Array<u8, N> {
    type Error = Error;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        if value.len() != N::to_usize() {
            return Err(Error::InvalidLength {
                expected: N::to_usize(),
                actual: value.len(),
            });
        }
        // note: this will always make of copy of the data
        // because `Array` is stack allocated while the blob
        // data is most likely on the heap.
        Ok(value.bytes().try_into()?)
    }
}

impl<'a, const N: usize> TryFrom<Blob<'a>> for [u8; N] {
    type Error = Error;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        if value.len() != N {
            return Err(Error::InvalidLength {
                expected: N,
                actual: value.len(),
            });
        }
        let vec = match value {
            Blob::Bytes(bytes) => {
                let vec: Vec<u8> = bytes.into();
                vec
            }
            Blob::Slice(slice) => slice.to_vec().into(),
        };
        Ok(vec.try_into().expect("conversion to array to succeed"))
    }
}

pub(crate) trait AsBlob {
    fn as_blob(&self) -> Blob<'_>;
}
