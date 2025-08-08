use crate::blob::{AsBlob, Blob};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher};
use bytemuck::TransparentWrapper;
use derive_where::derive_where;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

#[derive_where(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize; I)]
#[derive(TransparentWrapper)]
#[transparent(I)]
#[repr(transparent)]
pub struct Typed<T, I>(pub(crate) I, PhantomData<T>);

impl<T, I> Typed<T, I> {
    pub(crate) const fn new_from_inner(inner: I) -> Self {
        Self(inner, PhantomData)
    }

    pub(crate) fn into_inner(self) -> I {
        self.0
    }
}

impl<T, I> Deref for Typed<T, I> {
    type Target = I;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, I> DerefMut for Typed<T, I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T, I> AsRef<I> for Typed<T, I> {
    fn as_ref(&self) -> &I {
        &self.0
    }
}

impl<T, I> AsMut<I> for Typed<T, I> {
    fn as_mut(&mut self) -> &mut I {
        &mut self.0
    }
}

impl<T, I> AsBlob for Typed<T, I>
where
    I: AsBlob,
{
    fn as_blob(&self) -> Blob<'_> {
        self.0.as_blob()
    }
}

pub trait WithFromStr {}

impl<T, I> FromStr for Typed<T, I>
where
    I: FromStr,
    Self: WithFromStr,
{
    type Err = <I as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        I::from_str(s).map(Self::from_inner)
    }
}

impl<T, I> DeepHashable for Typed<T, I>
where
    I: DeepHashable,
{
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.0.deep_hash()
    }
}

impl<T, I> Hashable for Typed<T, I>
where
    I: Hashable,
{
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        self.0.feed(hasher)
    }
}

pub(crate) trait FromInner<I> {
    fn from_inner(inner: I) -> Self
    where
        Self: Sized;
}

impl<T, I> FromInner<I> for Typed<T, I> {
    fn from_inner(inner: I) -> Self
    where
        Self: Sized,
    {
        Self::new_from_inner(inner)
    }
}

impl<'a, T, I> TryFrom<Blob<'a>> for Typed<T, I>
where
    I: TryFrom<Blob<'a>>,
{
    type Error = <I as TryFrom<Blob<'a>>>::Error;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        Ok(Self::from_inner(I::try_from(value)?))
    }
}

pub trait WithSerde {}

impl<'de, I: Deserialize<'de>, T> Deserialize<'de> for Typed<T, I>
where
    Self: WithSerde,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        I::deserialize(deserializer).map(|d| Self::from_inner(d))
    }
}

impl<I: Serialize, T> Serialize for Typed<T, I>
where
    Self: WithSerde,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Serialize::serialize(&self.0, serializer)
    }
}

pub trait WithDisplay {}

impl<T, I: Display> Display for Typed<T, I>
where
    Self: WithDisplay,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

pub trait WithDefault {}

impl<T, I: Default> Default for Typed<T, I>
where
    Self: WithDefault,
{
    fn default() -> Self {
        Self::from_inner(I::default())
    }
}
