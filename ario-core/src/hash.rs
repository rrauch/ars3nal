use crate::base64::{Base64Stringify, UrlSafeNoPadding};
use crate::serde::{AsBytes, FromBytes, StringifySerdeStrategy};
use crate::typed::Typed;
use bytes::Bytes;
use derive_where::derive_where;
use digest::consts::{U32, U48};
use digest::core_api::{CoreWrapper, CtVariableCoreWrapper};
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use sha2::{Digest as ShaDigest, OidSha256, OidSha384, Sha256VarCore, Sha512VarCore};
use std::array::TryFromSliceError;
use std::borrow::Cow;
use thiserror::Error;
use uuid::Uuid;

pub type TypedDigest<T, H: Hasher> =
    Typed<T, Digest<H>, StringifySerdeStrategy, Base64Stringify<UrlSafeNoPadding>>;

#[derive_where(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Digest<H: Hasher>(GenericArray<u8, H::DIGEST_LEN>);

impl<H: Hasher> Digest<H> {
    pub(crate) fn from_bytes(bytes: GenericArray<u8, H::DIGEST_LEN>) -> Self {
        Self(bytes)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid input length, expected '{expected}' but go '{actual}'")]
    InvalidInputLength { expected: usize, actual: usize },
    #[error(transparent)]
    ConversionError(#[from] TryFromSliceError),
}

impl<H: Hasher> Digest<H> {
    pub fn try_clone_from_bytes(input: impl AsRef<[u8]>) -> Result<Self, Error> {
        let input = input.as_ref();
        let expected = H::DIGEST_LEN::to_usize();
        if input.len() != expected {
            return Err(Error::InvalidInputLength {
                expected,
                actual: input.len(),
            });
        }
        Ok(Self(GenericArray::from_slice(input).clone()))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> GenericArray<u8, H::DIGEST_LEN> {
        self.0
    }
}

impl<H: Hasher> AsBytes for Digest<H> {
    fn as_bytes(&self) -> impl Into<Cow<'_, [u8]>> {
        self.as_slice()
    }
}

impl<H: Hasher> FromBytes for Digest<H> {
    type Error = Error;

    fn try_from_bytes(input: Bytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::try_clone_from_bytes(input.as_ref())
    }
}

pub trait Hasher: Send + Sync {
    #[allow(non_camel_case_types)]
    type DIGEST_LEN: ArrayLength;

    fn new() -> Self;
    fn update(&mut self, data: impl AsRef<[u8]>);
    fn finalize(self) -> Digest<Self>
    where
        Self: Sized;
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

pub type Sha256Hash = Digest<Sha256Hasher>;
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Sha256Hasher(CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U32, OidSha256>>);

impl Hasher for Sha256Hasher {
    type DIGEST_LEN = U32;

    fn new() -> Self {
        Self(sha2::Sha256::new())
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        sha2::Digest::update(&mut self.0, data.as_ref());
    }

    fn finalize(self) -> Digest<Self>
    where
        Self: Sized,
    {
        // due to a crate version conflict the generic array is first turned into a vec
        // before converted back to a generic array
        Digest::from_bytes(
            self.0
                .finalize()
                .to_vec()
                .try_into()
                .expect("generic array conversion should never fail"),
        )
    }
}

pub type Sha384Hash = Digest<Sha384Hasher>;
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Sha384Hasher(CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U48, OidSha384>>);

impl Hasher for Sha384Hasher {
    type DIGEST_LEN = U48;

    fn new() -> Self {
        Self(sha2::Sha384::new())
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        sha2::Digest::update(&mut self.0, data.as_ref());
    }

    fn finalize(self) -> Digest<Self>
    where
        Self: Sized,
    {
        Digest::from_bytes(
            // due to a crate version conflict the generic array is first turned into a vec
            // before converted back to a generic array
            self.0
                .finalize()
                .to_vec()
                .try_into()
                .expect("generic array conversion should never fail"),
        )
    }
}

pub(crate) trait DeepHashable {
    fn deep_hash<H: Hasher>(&self) -> Digest<H>;
    fn blob<H: Hasher, B: AsRef<[u8]>>(buf: &B) -> Digest<H> {
        let buf = buf.as_ref();
        let tag_digest = H::digest(format!("blob{}", buf.len()).as_bytes());
        let data_digest = H::digest(buf);
        H::digest_from_iter(vec![tag_digest.as_slice(), data_digest.as_slice()].into_iter())
    }
    fn list<H: Hasher, C: Into<Vec<Digest<H>>>>(children: C) -> Digest<H> {
        let children = children.into();
        let mut acc_digest = H::digest(format!("list{}", children.len()).as_bytes());
        for c in children {
            acc_digest = H::digest_from_iter(vec![acc_digest.as_slice(), c.as_slice()].into_iter());
        }
        acc_digest
    }
}

impl DeepHashable for Uuid {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_bytes().as_slice().deep_hash()
    }
}

impl<'a> DeepHashable for &'a [u8] {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::blob(self)
    }
}

impl<const N: usize> DeepHashable for [u8; N] {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_slice().deep_hash()
    }
}

impl DeepHashable for String {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_bytes().deep_hash()
    }
}

impl<'a> DeepHashable for &'a str {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_bytes().deep_hash()
    }
}

impl<T> DeepHashable for Option<T>
where
    T: DeepHashable,
{
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        if let Some(this) = &self {
            this.deep_hash()
        } else {
            Self::blob(&[])
        }
    }
}

impl<T> DeepHashable for Vec<T>
where
    T: DeepHashable,
{
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::list(self.iter().map(|t| t.deep_hash()).collect::<Vec<_>>())
    }
}

impl<H: Hasher> DeepHashable for Digest<H> {
    fn deep_hash<H2: Hasher>(&self) -> Digest<H2> {
        self.as_slice().deep_hash()
    }
}

impl DeepHashable for Bytes {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::blob(self)
    }
}

pub(crate) trait Hashable {
    fn feed<H: Hasher>(&self, hasher: &mut H);
}

pub(crate) trait HashableExt {
    fn digest<H: Hasher>(&self) -> Digest<H>;
}

impl<T> HashableExt for T
where
    T: Hashable,
{
    fn digest<H: Hasher>(&self) -> Digest<H> {
        let mut hasher = H::new();
        self.feed(&mut hasher);
        hasher.finalize()
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