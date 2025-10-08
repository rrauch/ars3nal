use crate::typed::{FromInner, Typed};
use bytes::{Buf, Bytes, BytesMut};
use hybrid_array::{Array, ArraySize};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::array::TryFromSliceError;
use std::borrow::Cow;
use std::fmt::{Debug, Formatter};
use std::io::Cursor;
use std::marker::PhantomData;
use std::ops::{Deref, Range};
use thiserror::Error;

pub type TypedBlob<'a, T> = Typed<T, Blob<'a>>;

impl<'a, T> TypedBlob<'a, T> {
    pub fn into_owned(self) -> TypedBlob<'static, T> {
        TypedBlob::from_inner(self.into_inner().into_owned())
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Blob<'a> {
    Bytes(Bytes),
    Slice(&'a [u8]),
}

impl<'a, T: Into<Blob<'a>>> FromIterator<T> for OwnedBlob {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::from_iter(iter.into_iter().map(|b| b.into()))
    }
}

impl OwnedBlob {
    fn from_iter<'a>(iter: impl Iterator<Item = Blob<'a>>) -> Self {
        let mut this = BytesMut::new();
        iter.for_each(|b| Blob::_append(&mut this, b));
        Self::Bytes(this.freeze())
    }

    fn append(&mut self, other: OwnedBlob) {
        match self {
            Self::Bytes(this) => {
                let mut b1 = BytesMut::from(std::mem::take(this));
                Blob::_append(&mut b1, other);
                *this = b1.freeze();
            }
            Self::Slice(slice) => {
                let mut b1 = BytesMut::from(&slice[..]);
                Blob::_append(&mut b1, other);
                *self = Self::Bytes(b1.freeze());
            }
        }
    }

    fn _append(this: &mut BytesMut, other: Blob<'_>) {
        match other {
            Blob::Bytes(other) => match other.try_into_mut() {
                Ok(other) => {
                    this.unsplit(other);
                }
                Err(other) => {
                    this.extend_from_slice(other.as_ref());
                }
            },
            Blob::Slice(slice) => {
                this.extend_from_slice(slice);
            }
        }
    }
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

impl<'a> From<Cow<'a, [u8]>> for Blob<'a> {
    fn from(value: Cow<'a, [u8]>) -> Self {
        match value {
            Cow::Borrowed(slice) => Blob::from(slice),
            Cow::Owned(vec) => Blob::from(vec),
        }
    }
}

impl<'a> Blob<'a> {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Bytes(b) => b.deref(),
            Self::Slice(b) => *b,
        }
    }

    pub fn buf(&self) -> impl Buf {
        match self {
            Self::Bytes(b) => Cursor::new(b.deref()),
            Self::Slice(b) => Cursor::new(*b),
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

    pub fn borrow(&'a self) -> Blob<'a> {
        Blob::from(self.bytes())
    }

    pub fn slice(&self, range: Range<usize>) -> Self {
        match self {
            Blob::Bytes(b) => Blob::Bytes(b.slice(range)),
            Blob::Slice(s) => Blob::Slice(&s[range]),
        }
    }
}

impl<'a> Serialize for Blob<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.bytes())
    }
}

impl<'de, 'a> Deserialize<'de> for Blob<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor<'a>(PhantomData<&'a ()>);

        impl<'de, 'a> Visitor<'de> for BytesVisitor<'a> {
            type Value = Blob<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("bytes")
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = if let Some(size) = seq.size_hint() {
                    Vec::with_capacity(size)
                } else {
                    Vec::new()
                };
                let mut seq = seq;
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(Blob::from(bytes))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Blob::from(v.to_vec()))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Blob::from(v))
            }
        }

        let bytes = deserializer.deserialize_byte_buf(BytesVisitor(PhantomData))?;
        Ok(Blob::from(bytes))
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

pub trait AsBlob {
    fn as_blob(&self) -> Blob<'_>;
}

impl AsBlob for Blob<'_> {
    fn as_blob(&self) -> Blob<'_> {
        Blob::Slice(self.bytes())
    }
}

impl<const N: usize> AsBlob for [u8; N] {
    fn as_blob(&self) -> Blob<'_> {
        Blob::Slice(self.as_slice())
    }
}

impl AsBlob for Vec<u8> {
    fn as_blob(&self) -> Blob<'_> {
        Blob::Slice(self.as_slice())
    }
}

impl<'a> AsBlob for &'a [u8] {
    fn as_blob(&self) -> Blob<'a> {
        Blob::Slice(self)
    }
}

impl AsBlob for String {
    fn as_blob(&self) -> Blob<'_> {
        self.as_bytes().into()
    }
}
