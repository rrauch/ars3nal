use crate::typed::Typed;
use bytes::Bytes;
use generic_array::{ArrayLength, GenericArray};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;

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

impl<'a, N: ArrayLength> TryFrom<Blob<'a>> for GenericArray<u8, N> {
    type Error = generic_array::LengthError;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        if value.len() != N::to_usize() {
            return Err(generic_array::LengthError);
        }
        match value {
            Blob::Bytes(bytes) => {
                let vec: Vec<u8> = bytes.into();
                GenericArray::try_from(vec)
            }
            Blob::Slice(slice) => GenericArray::try_from(slice.to_vec()),
        }
    }
}

impl<'a, const N: usize> TryFrom<Blob<'a>> for [u8; N] {
    type Error = generic_array::LengthError;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        if value.len() != N {
            return Err(generic_array::LengthError);
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
