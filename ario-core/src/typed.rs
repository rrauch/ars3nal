use crate::serde::DefaultSerdeStrategy;
use crate::stringify::{DefaultStringify, Stringify};
use derive_where::derive_where;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive_where(Clone, PartialEq, PartialOrd, Hash; I)]
pub struct Typed<T, I, SER = DefaultSerdeStrategy, STR = DefaultStringify<I>>(
    pub(crate) I,
    PhantomData<(T, SER, STR)>,
);

impl<T, I, SER, STR> Deref for Typed<T, I, SER, STR> {
    type Target = I;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, I, SER, STR> DerefMut for Typed<T, I, SER, STR> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T, I, SER, STR> AsRef<I> for Typed<T, I, SER, STR> {
    fn as_ref(&self) -> &I {
        &self.0
    }
}

impl<T, I, SER, STR> AsMut<I> for Typed<T, I, SER, STR> {
    fn as_mut(&mut self) -> &mut I {
        &mut self.0
    }
}

impl<T, I, SER, STR> From<I> for Typed<T, I, SER, STR> {
    fn from(value: I) -> Self {
        Self(value, PhantomData)
    }
}

impl<T, I, SER, STR> Typed<T, I, SER, STR> {
    pub fn into_inner(self) -> I {
        self.0
    }
}

impl<T, I, SER, STR> FromStr for Typed<T, I, SER, STR>
where
    STR: Stringify<I>,
{
    type Err = <STR as Stringify<I>>::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        STR::try_from_str(s).map(Into::into)
    }
}

impl<T, I, SER, STR> Display for Typed<T, I, SER, STR>
where
    STR: Stringify<I>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(STR::to_str(&self.0).into().as_ref())
    }
}

impl<T, I, SER, STR> Zeroize for Typed<T, I, SER, STR>
where
    I: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<T, I, SER, STR> ZeroizeOnDrop for Typed<T, I, SER, STR> where I: ZeroizeOnDrop {}
