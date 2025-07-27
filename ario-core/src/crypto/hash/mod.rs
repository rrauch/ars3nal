pub mod deep_hash;
pub mod wrapped;

use crate::base64::ToBase64;
use crate::blob::Blob;
use crate::crypto::hash::wrapped::WrappedDigest;
use crate::typed::Typed;
use bytes::Bytes;
use derive_where::derive_where;
use hybrid_array::{Array, ArraySize};
use std::fmt::{Display, Formatter};
use uuid::Uuid;

//pub type Sha256Hasher =
//    WrappedDigest<CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U32, OidSha256>>>;
//pub type Sha256 = WrappedDigest<sha2::Sha256>;
pub type Sha256 = sha2::Sha256;
pub type Sha256Hash = Digest<Sha256>;

//pub type Sha384Hasher =
//    WrappedDigest<CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U48, OidSha384>>>;
pub type Sha384 = WrappedDigest<sha2::Sha384>;
pub type Sha384Hash = Digest<Sha384>;

pub type TypedDigest<T, H: Hasher> = Typed<T, Digest<H>>;

#[derive_where(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Digest<H: Hasher>(Array<u8, H::DigestLen>);

impl<H: Hasher> Digest<H> {
    pub(crate) fn from_bytes(bytes: Array<u8, H::DigestLen>) -> Self {
        Self(bytes)
    }
}

impl<H: Hasher> Display for Digest<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.to_base64().as_str())
    }
}

impl<H: Hasher> Digest<H> {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Array<u8, H::DigestLen> {
        self.0
    }
}

impl<'a, H: Hasher> TryFrom<Blob<'a>> for Digest<H> {
    type Error = <Blob<'a> as TryInto<Array<u8, H::DigestLen>>>::Error;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Digest(value.try_into()?))
    }
}

impl<H: Hasher> AsRef<[u8]> for Digest<H> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

pub trait Hasher: Send + Sync {
    type DigestLen: ArraySize;

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
    type DigestLen = <H as digest::OutputSizeUser>::OutputSize;

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
        Digest::from_bytes(digest::Digest::finalize(self))
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
