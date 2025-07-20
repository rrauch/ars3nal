use crate::typed::{FromInner, Typed};
use std::borrow::Cow;
use std::fmt::Display;
use std::marker::PhantomData;
use std::str::FromStr;
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

pub struct DisplayFromStrStringify<T>(PhantomData<T>);

impl<T> Stringify<T> for DisplayFromStrStringify<T>
where
    T: Display + FromStr,
    <T as FromStr>::Err: Display,
{
    type Error = <T as FromStr>::Err;

    fn to_str(input: &T) -> impl Into<Cow<str>> {
        input.to_string()
    }

    fn try_from_str<S: AsRef<str>>(input: S) -> Result<T, Self::Error>
    where
        Self: Sized,
    {
        let inner = <T as FromStr>::from_str(input.as_ref())?;
        Ok(inner.into())
    }
}

impl<T, I, SER, STR, DBG> Stringify<Self> for Typed<T, I, SER, STR, DBG>
where
    STR: Stringify<I>,
{
    type Error = <STR as Stringify<I>>::Error;

    fn to_str(input: &Self) -> impl Into<Cow<str>> {
        <STR as Stringify<I>>::to_str(&input.0)
    }

    #[allow(private_bounds)]
    fn try_from_str<IN: AsRef<str>>(input: IN) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self: FromInner<I>,
    {
        let inner: I = <STR as Stringify<I>>::try_from_str(input.as_ref()).map(Into::into)?;
        Ok(Self::from_inner(inner))
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
