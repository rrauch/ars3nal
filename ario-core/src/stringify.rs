use crate::typed::Typed;
use std::borrow::Cow;
use std::fmt::Display;
use std::marker::PhantomData;
use uuid::Uuid;

pub trait Stringify<T> {
    type Error: Display;

    fn to_str(input: &T) -> impl Into<Cow<str>>;
    fn try_from_str<S: AsRef<str>>(input: S) -> Result<T, Self::Error>
    where
        Self: Sized;
}

pub struct DefaultStringify<T>(PhantomData<T>);

impl<T> Stringify<T> for DefaultStringify<T>
where
    T: Stringify<T>,
{
    type Error = <T as Stringify<T>>::Error;

    fn to_str(input: &T) -> impl Into<Cow<str>> {
        T::to_str(input)
    }

    fn try_from_str<S: AsRef<str>>(input: S) -> Result<T, Self::Error>
    where
        Self: Sized,
    {
        T::try_from_str(input)
    }
}

impl<T, I, S> Stringify<Self> for Typed<T, I, S>
where
    S: Stringify<I>,
{
    type Error = <S as Stringify<I>>::Error;

    fn to_str(input: &Self) -> impl Into<Cow<str>> {
        <S as Stringify<I>>::to_str(&input.0)
    }

    fn try_from_str<IN: AsRef<str>>(input: IN) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let inner: I = <S as Stringify<I>>::try_from_str(input.as_ref()).map(Into::into)?;
        Ok(inner.into())
    }
}

impl Stringify<Self> for Uuid {
    type Error = uuid::Error;

    fn to_str(input: &Self) -> impl Into<Cow<str>> {
        input.to_string()
    }

    fn try_from_str<S: AsRef<str>>(input: S) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::try_parse(input.as_ref())
    }
}
