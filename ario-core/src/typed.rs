use crate::hash::{DeepHashable, Digest, Hashable, Hasher};
use crate::serde::DefaultSerdeStrategy;
use crate::stringify::{DefaultStringify, Stringify};
use derive_where::derive_where;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive_where(Clone, PartialEq, PartialOrd, Hash; I)]
pub struct Typed<
    T,
    I,
    SER = DefaultSerdeStrategy,
    STR = DefaultStringify<I>,
    DBG = DefaultDebugStrategy,
>(pub(crate) I, PhantomData<(T, SER, STR, DBG)>);

pub struct DefaultDebugStrategy;

impl<T, I, SER, STR> Debug for Typed<T, I, SER, STR, DefaultDebugStrategy>
where
    I: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

pub struct StringifyDebugStrategy;

impl<T, I, SER, STR> Debug for Typed<T, I, SER, STR, StringifyDebugStrategy>
where
    STR: Stringify<I>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(STR::to_str(&self.0).into().as_ref())
    }
}

impl<T, I, SER, STR, DBG> Deref for Typed<T, I, SER, STR, DBG> {
    type Target = I;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, I, SER, STR, DBG> DerefMut for Typed<T, I, SER, STR, DBG> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T, I, SER, STR, DBG> AsRef<I> for Typed<T, I, SER, STR, DBG> {
    fn as_ref(&self) -> &I {
        &self.0
    }
}

impl<T, I, SER, STR, DBG> AsMut<I> for Typed<T, I, SER, STR, DBG> {
    fn as_mut(&mut self) -> &mut I {
        &mut self.0
    }
}

impl<T, I, SER, STR, DBG> Typed<T, I, SER, STR, DBG> {
    pub fn into_inner(self) -> I {
        self.0
    }
}

impl<T, I, SER, STR, DBG> FromStr for Typed<T, I, SER, STR, DBG>
where
    STR: Stringify<I>,
{
    type Err = <STR as Stringify<I>>::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        STR::try_from_str(s).map(Self::from_inner)
    }
}

impl<T, I, SER, STR, DBG> Display for Typed<T, I, SER, STR, DBG>
where
    STR: Stringify<I>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(STR::to_str(&self.0).into().as_ref())
    }
}

impl<T, I, SER, STR, DBG> Zeroize for Typed<T, I, SER, STR, DBG>
where
    I: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<T, I, SER, STR, DBG> DeepHashable for Typed<T, I, SER, STR, DBG>
where
    I: DeepHashable,
{
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.0.deep_hash()
    }
}

impl<T, I, SER, STR, DBG> Hashable for Typed<T, I, SER, STR, DBG>
where
    I: Hashable,
{
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        self.0.feed(hasher)
    }
}

impl<T, I, SER, STR, DBG> ZeroizeOnDrop for Typed<T, I, SER, STR, DBG> where I: ZeroizeOnDrop {}

pub(crate) trait FromInner<I> {
    fn from_inner(inner: I) -> Self
    where
        Self: Sized;
}

impl<T, I, SER, STR, DBG> FromInner<I> for Typed<T, I, SER, STR, DBG> {
    fn from_inner(inner: I) -> Self
    where
        Self: Sized,
    {
        Self(inner, PhantomData)
    }
}
