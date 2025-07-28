pub mod deep_hash;

use crate::base64::ToBase64;
use crate::blob::{AsBlob, Blob};
use crate::typed::Typed;
use bytes::Bytes;
use derive_where::derive_where;
use hybrid_array::{Array, ArraySize};
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use uuid::Uuid;

pub type Sha256 = sha2::Sha256;
pub type Sha256Hash = Digest<Sha256>;

pub type Sha384 = sha2::Sha384;
pub type Sha384Hash = Digest<Sha384>;

pub type TypedDigest<T, H: Hasher> = Typed<T, Digest<H>>;

#[derive_where(Clone)]
#[repr(transparent)]
pub struct Digest<H: Hasher>(H::Output);

impl<H: Hasher> Digest<H> {
    pub(crate) fn from_bytes<'a>(
        blob: impl Into<Blob<'a>>,
    ) -> Result<Self, <<H as Hasher>::Output as TryFrom<Blob<'a>>>::Error> {
        Ok(Self(H::Output::try_from(blob.into())?))
    }
}

impl<H: Hasher> Display for Digest<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.to_base64().as_str())
    }
}

impl<H: Hasher> Debug for Digest<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.to_base64().as_str())
    }
}

impl<H: Hasher> PartialEq for Digest<H> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl<H: Hasher> Hash for Digest<H> {
    fn hash<H2: std::hash::Hasher>(&self, state: &mut H2) {
        self.0.as_ref().hash(state)
    }
}

impl<H: Hasher> Digest<H> {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn into_inner(self) -> H::Output {
        self.0
    }
}

impl<'a, H: Hasher> TryFrom<Blob<'a>> for Digest<H> {
    type Error = <Blob<'a> as TryInto<H::Output>>::Error;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Digest(value.try_into()?))
    }
}

impl<H: Hasher> AsRef<[u8]> for Digest<H> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

pub trait OutputLen: ArraySize {}
impl<T> OutputLen for T where T: ArraySize {}

pub trait Output: Clone + AsRef<[u8]> + AsBlob + for<'a> TryFrom<Blob<'a>> + Send + Sync {
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

pub trait Hasher: Send + Sync {
    type Output: Output;

    fn new() -> Self;
    fn update(&mut self, data: impl AsRef<[u8]>);
    fn finalize(self) -> Digest<Self>
    where
        Self: Sized;
}

impl<H> Hasher for H
where
    H: digest::Digest + Send + Sync,
{
    type Output = digest::Output<Self>;

    fn new() -> Self {
        <Self as digest::Digest>::new()
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        digest::Digest::update(self, data)
    }

    fn finalize(self) -> Digest<Self>
    where
        Self: Sized,
    {
        Digest(digest::Digest::finalize(self))
    }
}

pub trait HasherExt<H: Hasher> {
    fn digest(input: impl AsRef<[u8]>) -> Digest<H>;
    fn digest_from_iter<T: AsRef<[u8]>, I: Iterator<Item = T>>(iter: I) -> Digest<H>;
}

impl<H: Hasher> HasherExt<H> for H {
    fn digest(input: impl AsRef<[u8]>) -> Digest<H> {
        let mut hasher = H::new();
        hasher.update(input);
        hasher.finalize()
    }

    fn digest_from_iter<T: AsRef<[u8]>, I: IntoIterator<Item = T>>(iter: I) -> Digest<H> {
        let mut hasher = H::new();
        iter.into_iter().for_each(|t| hasher.update(t.as_ref()));
        hasher.finalize()
    }
}

pub(crate) trait Hashable {
    fn feed<H: Hasher>(&self, hasher: &mut H);
}

pub(crate) trait HashableExt {
    fn digest<H: Hasher>(&self) -> Digest<H>;
    fn hasher<H: Hasher>(&self) -> H;
}

impl<T> HashableExt for T
where
    T: Hashable,
{
    fn digest<H: Hasher>(&self) -> Digest<H> {
        HashableExt::hasher::<H>(self).finalize()
    }

    fn hasher<H: Hasher>(&self) -> H {
        let mut hasher = H::new();
        self.feed(&mut hasher);
        hasher
    }
}

impl<'a> Hashable for Blob<'a> {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(self.bytes())
    }
}

impl Hashable for Uuid {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(self.as_bytes())
    }
}

impl<const N: usize> Hashable for [u8; N] {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(self.as_slice())
    }
}

impl<'a> Hashable for &'a [u8] {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(self);
    }
}

impl Hashable for String {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(self.as_bytes())
    }
}

impl<'a> Hashable for &'a str {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        hasher.update(self.as_bytes())
    }
}

impl<T> Hashable for Option<T>
where
    T: Hashable,
{
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        if let Some(this) = &self {
            this.feed(hasher);
        }
    }
}

impl<T> Hashable for Vec<T>
where
    T: Hashable,
{
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        self.iter().for_each(|t| t.feed(hasher))
    }
}

impl<H: Hasher> Hashable for Digest<H> {
    fn feed<H2: Hasher>(&self, hasher: &mut H2) {
        self.as_slice().feed(hasher)
    }
}

impl Hashable for Bytes {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        self.as_ref().feed(hasher)
    }
}
