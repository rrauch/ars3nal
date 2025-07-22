use crate::base64::{Base64Stringify, UrlSafeNoPadding};
use crate::serde::{AsBytes, FromBytes, StringifySerdeStrategy};
use crate::typed::Typed;
use bytes::Bytes;
use derive_where::derive_where;
use digest::consts::{U32, U48};
use digest::core_api::{CoreWrapper, CtVariableCoreWrapper};
use sha2::{Digest as ShaDigest, OidSha256, OidSha384, Sha256VarCore, Sha512VarCore};
use std::array::TryFromSliceError;
use std::borrow::Cow;
use std::marker::PhantomData;
use thiserror::Error;

pub type TypedDigest<T, H: Hasher<LEN>, const LEN: usize> =
    Typed<T, Digest<H, LEN>, StringifySerdeStrategy, Base64Stringify<UrlSafeNoPadding>>;

#[derive_where(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Digest<H: Hasher<LEN>, const LEN: usize>([u8; LEN], PhantomData<H>);

impl<H: Hasher<LEN>, const LEN: usize> Digest<H, LEN> {
    pub(crate) fn from_bytes(bytes: [u8; LEN]) -> Self {
        Self(bytes, PhantomData)
    }
}

#[derive(Error, Debug)]
pub enum HashError {
    #[error("Invalid input length, expected '{expected}' but go '{actual}'")]
    InvalidInputLength { expected: usize, actual: usize },
    #[error(transparent)]
    ConversionError(#[from] TryFromSliceError),
}

impl<H: Hasher<LEN>, const LEN: usize> Digest<H, LEN> {
    pub fn try_clone_from_bytes(input: impl AsRef<[u8]>) -> Result<Self, HashError> {
        let input = input.as_ref();
        if input.len() != LEN {
            return Err(HashError::InvalidInputLength {
                expected: LEN,
                actual: input.len(),
            });
        }
        Ok(Self(input.try_into()?, PhantomData))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; LEN] {
        self.0
    }
}

impl<H: Hasher<LEN>, const LEN: usize> AsBytes for Digest<H, LEN> {
    fn as_bytes(&self) -> impl Into<Cow<'_, [u8]>> {
        self.as_slice()
    }
}

impl<H: Hasher<LEN>, const LEN: usize> FromBytes for Digest<H, LEN> {
    type Error = HashError;

    fn try_from_bytes(input: Bytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::try_clone_from_bytes(input.as_ref())
    }
}

pub trait Hasher<const DIGEST_LEN: usize>: Send + Sync {
    fn new() -> Self;
    fn update(&mut self, data: impl AsRef<[u8]>);
    fn finalize(self) -> Digest<Self, DIGEST_LEN>
    where
        Self: Sized;
}

pub trait HasherExt<const DIGEST_LEN: usize, H: Hasher<DIGEST_LEN>> {
    fn digest(input: impl AsRef<[u8]>) -> Digest<H, DIGEST_LEN>;
}

impl<const DIGEST_LEN: usize, H: Hasher<DIGEST_LEN>> HasherExt<DIGEST_LEN, H> for H {
    fn digest(input: impl AsRef<[u8]>) -> Digest<H, DIGEST_LEN> {
        let mut hasher = H::new();
        hasher.update(input);
        hasher.finalize()
    }
}

pub type Sha256Hash = Digest<Sha256Hasher, 32>;
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Sha256Hasher(CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U32, OidSha256>>);

impl Hasher<32> for Sha256Hasher {
    fn new() -> Self {
        Self(sha2::Sha256::new())
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        sha2::Digest::update(&mut self.0, data.as_ref());
    }

    fn finalize(self) -> Digest<Self, 32>
    where
        Self: Sized,
    {
        Digest::from_bytes(self.0.finalize().into())
    }
}

pub type Sha384Hash = Digest<Sha384Hasher, 48>;
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Sha384Hasher(CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U48, OidSha384>>);

impl Hasher<48> for Sha384Hasher {
    fn new() -> Self {
        Self(sha2::Sha384::new())
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        sha2::Digest::update(&mut self.0, data.as_ref());
    }

    fn finalize(self) -> Digest<Self, 48>
    where
        Self: Sized,
    {
        Digest::from_bytes(self.0.finalize().into())
    }
}
