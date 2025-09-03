pub mod deep_hash;

use crate::base64::ToBase64;
use crate::blob::{AsBlob, Blob};
use crate::crypto::{Output, OutputLen};
use crate::typed::Typed;
use bytemuck::TransparentWrapper;
use bytes::Bytes;
use ct_codecs::Encoder;
use derive_where::derive_where;
use digest::FixedOutputReset;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use uuid::Uuid;

pub type Sha256 = sha2::Sha256;
pub type Sha256Hash = Digest<Sha256>;

pub type Sha384 = sha2::Sha384;
pub type Sha384Hash = Digest<Sha384>;

pub type Sha512 = sha2::Sha512;
pub type Sha512Hash = Digest<Sha512>;

pub type Sha512HexStr = TransformingHasher<Sha512, HexTransformer>;
pub type Sha512HexStrHash = Digest<Sha512HexStr>;

pub type TypedDigest<T, H: Hasher> = Typed<T, Digest<H>>;

#[derive_where(Clone, PartialEq, Hash)]
#[derive(TransparentWrapper)]
#[repr(transparent)]
pub struct Digest<H: Hasher>(H::Output);

impl<H: Hasher> Digest<H> {
    pub(crate) fn from_inner(inner: H::Output) -> Self {
        Self(inner)
    }
    pub(crate) fn as_wrapped_digest(&self) -> DigestWrapper<H> {
        DigestWrapper(&self)
    }

    #[inline]
    pub(crate) fn as_variant<O: Hasher<Output = H::Output>>(&self) -> &Digest<O> {
        Digest::<O>::wrap_ref(&self.0)
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

impl<H: Hasher> AsBlob for Digest<H> {
    fn as_blob(&self) -> Blob<'_> {
        self.0.as_blob()
    }
}

impl<H: Hasher> Digest<H> {
    #[inline]
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

pub(crate) struct DigestWrapper<'a, H: Hasher>(&'a Digest<H>);

impl<H: Hasher<Output = digest::Output<H>> + digest::OutputSizeUser> digest::OutputSizeUser
    for DigestWrapper<'_, H>
where
    <H as digest::OutputSizeUser>::OutputSize: OutputLen,
{
    type OutputSize = <H as digest::OutputSizeUser>::OutputSize;
}

impl<H: Hasher<Output = digest::Output<H>> + digest::OutputSizeUser> digest::Digest
    for DigestWrapper<'_, H>
where
    <H as digest::OutputSizeUser>::OutputSize: OutputLen,
{
    fn new() -> Self {
        unimplemented!("do not use!")
    }

    fn new_with_prefix(_: impl AsRef<[u8]>) -> Self {
        unimplemented!("do not use!")
    }

    fn update(&mut self, _: impl AsRef<[u8]>) {
        unimplemented!("do not use!")
    }

    fn chain_update(self, _: impl AsRef<[u8]>) -> Self {
        unimplemented!("do not use!")
    }

    fn finalize(self) -> digest::Output<Self> {
        self.0.0.clone()
    }

    fn finalize_into(self, out: &mut digest::Output<Self>) {
        out.copy_from_slice(self.0.as_slice())
    }

    fn finalize_reset(&mut self) -> digest::Output<Self>
    where
        Self: FixedOutputReset,
    {
        self.0
            .0
            .as_slice()
            .try_into()
            .expect("slice len to be correct")
    }

    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>)
    where
        Self: FixedOutputReset,
    {
        out.copy_from_slice(self.0.as_slice())
    }

    fn reset(&mut self)
    where
        Self: digest::Reset,
    {
        // do nothing
    }

    fn output_size() -> usize {
        <Self as digest::OutputSizeUser>::output_size()
    }

    fn digest(_: impl AsRef<[u8]>) -> digest::Output<Self> {
        unimplemented!("do not use!")
    }
}

pub struct HexTransformer;

impl Transformer for HexTransformer {
    fn new() -> Self {
        Self
    }

    fn transform_and_update<H: Hasher>(&mut self, data: impl AsRef<[u8]>, hasher: &mut H) {
        let hex_encoded =
            ct_codecs::Hex::encode_to_string(data).expect("hex encoding to never fail");
        hasher.update(hex_encoded.as_bytes());
    }

    fn finalize<H: Hasher>(self, _: &mut H) {
        // do nothing
    }
}

pub(crate) trait Transformer: Send + Sync {
    fn new() -> Self;
    fn transform_and_update<H: Hasher>(&mut self, data: impl AsRef<[u8]>, hasher: &mut H);

    fn finalize<H: Hasher>(self, hasher: &mut H);
}

pub struct TransformingHasher<H: Hasher, T: Transformer> {
    hasher: H,
    transformer: T,
}

impl<H: Hasher, T: Transformer> Hasher for TransformingHasher<H, T> {
    type Output = H::Output;

    fn new() -> Self {
        TransformingHasher {
            hasher: H::new(),
            transformer: Transformer::new(),
        }
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.transformer
            .transform_and_update(data, &mut self.hasher);
    }

    fn finalize(mut self) -> Digest<Self>
    where
        Self: Sized,
    {
        self.transformer.finalize(&mut self.hasher);
        Digest::from_inner(self.hasher.finalize().0)
    }
}

pub trait Hasher: Send + Sync {
    type Output: Output + PartialEq + Hash + AsRef<[u8]>;

    fn new() -> Self;
    fn update(&mut self, data: impl AsRef<[u8]>);
    fn finalize(self) -> Digest<Self>
    where
        Self: Sized;
}

impl<H> Hasher for H
where
    H: digest::Digest + Send + Sync,
    <H as digest::OutputSizeUser>::OutputSize: Send + Sync,
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
        Digest::from_inner(digest::Digest::finalize(self))
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

impl Hashable for u64 {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        // numbers have to be serialized to strings!
        self.to_string().feed(hasher)
    }
}

impl Hashable for u32 {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        // numbers have to be serialized to strings!
        self.to_string().feed(hasher)
    }
}
