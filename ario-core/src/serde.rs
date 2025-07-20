use crate::BigUint;
use crate::base64::{FromBase64, ToBase64};
use crate::stringify::Stringify;
use crate::typed::{FromInner, Typed};
use bytes::Bytes;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::borrow::Cow;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use thiserror::Error;

pub(crate) fn de_empty_string_as_none<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: for<'a> Deserialize<'a>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        Ok(None)
    } else {
        T::deserialize(de::value::StringDeserializer::<D::Error>::new(s))
            .map(Some)
            .map_err(de::Error::custom)
    }
}

pub(crate) fn ser_none_as_empty_string<S, T>(
    value: &Option<T>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    match value {
        Some(val) => val.serialize(serializer),
        None => serializer.serialize_str(""),
    }
}

pub trait FromBytes {
    type Error: Display;
    fn try_from_bytes(input: Bytes) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

impl FromBytes for Bytes {
    type Error = Infallible;

    fn try_from_bytes(input: Bytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(input)
    }
}

impl AsBytes for Bytes {
    fn as_bytes(&self) -> impl Into<Cow<'_, [u8]>> {
        self.as_ref()
    }
}

impl FromBytes for BigUint {
    type Error = Infallible;

    fn try_from_bytes(input: Bytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(BigUint::from_be_slice_vartime(input.as_ref()))
    }
}

impl AsBytes for BigUint {
    fn as_bytes(&self) -> impl Into<Cow<'_, [u8]>> {
        self.to_be_bytes_trimmed_vartime().into_vec()
    }
}

#[derive(Error, Debug)]
pub enum FixedBytesError {
    #[error("Invalid length: expected '{expected}' but found '{found}'")]
    InvalidLength { expected: usize, found: usize },
}

impl<const N: usize> FromBytes for [u8; N] {
    type Error = FixedBytesError;

    fn try_from_bytes(input: Bytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        if input.len() != N {
            return Err(FixedBytesError::InvalidLength {
                expected: N,
                found: input.len(),
            });
        }
        Ok(input.as_ref().try_into().unwrap())
    }
}

impl<const N: usize> AsBytes for [u8; N] {
    fn as_bytes(&self) -> impl Into<Cow<'_, [u8]>> {
        self.as_slice()
    }
}

pub(crate) trait AsBytes {
    fn as_bytes(&self) -> impl Into<Cow<'_, [u8]>>;
}

pub struct DefaultSerdeStrategy;

impl<T, I, STR, DBG> Serialize for Typed<T, I, DefaultSerdeStrategy, STR, DBG>
where
    I: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        <I as Serialize>::serialize(self, serializer)
    }
}

impl<'de, T, I, STR, DBG> Deserialize<'de> for Typed<T, I, DefaultSerdeStrategy, STR, DBG>
where
    I: Deserialize<'de>,
    Self: FromInner<I>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from_inner(I::deserialize(deserializer)?))
    }
}

pub struct StringifySerdeStrategy;

impl<T, I, STR, DBG> Serialize for Typed<T, I, StringifySerdeStrategy, STR, DBG>
where
    STR: Stringify<I>,
{
    fn serialize<S2>(&self, serializer: S2) -> Result<S2::Ok, S2::Error>
    where
        S2: Serializer,
    {
        serializer.serialize_str(STR::to_str(&self.0).into().as_ref())
    }
}

struct StringifyVisitor<T, I, STR>(PhantomData<(T, I, STR)>);

impl<'de, T, I, STR> Visitor<'de> for StringifyVisitor<T, I, STR>
where
    STR: Stringify<I>,
{
    type Value = I;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        STR::try_from_str(value)
            .map(Into::into)
            .map_err(de::Error::custom)
    }
}

impl<'de, T, I, STR, DBG> Deserialize<'de> for Typed<T, I, StringifySerdeStrategy, STR, DBG>
where
    STR: Stringify<I>,
    Self: FromInner<I>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner: I =
            deserializer.deserialize_str(StringifyVisitor::<T, I, STR>(PhantomData::default()))?;
        Ok(Self::from_inner(inner))
    }
}

pub struct Base64SerdeStrategy<V, const MAX_LEN: usize = { usize::MAX }>(PhantomData<V>);

impl<T, I, V, const MAX_LEN: usize, STR, DBG> Serialize
    for Typed<T, I, Base64SerdeStrategy<V, MAX_LEN>, STR, DBG>
where
    I: ToBase64<V>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(I::to_base64(&self.0).as_ref())
    }
}

struct Base64Visitor<T, I, V>(PhantomData<(T, I, V)>);

impl<'de, T, I, V, const MAX_LEN: usize> Visitor<'de>
    for Base64Visitor<T, I, Base64SerdeStrategy<V, MAX_LEN>>
where
    I: FromBase64<V, MAX_LEN>,
{
    type Value = I;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > MAX_LEN {
            return Err(de::Error::invalid_length(value.len(), &"MAX_LEN exceeded"));
        }
        I::try_from_base64(value)
            .map(Into::into)
            .map_err(de::Error::custom)
    }
}

impl<'de, T, I, V, const MAX_LEN: usize, STR, DBG> Deserialize<'de>
    for Typed<T, I, Base64SerdeStrategy<V, MAX_LEN>, STR, DBG>
where
    I: FromBase64<V, MAX_LEN>,
    Self: FromInner<I>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner: I =
            deserializer.deserialize_str(
                Base64Visitor::<T, I, Base64SerdeStrategy<V, MAX_LEN>>(PhantomData::default()),
            )?;
        Ok(Self::from_inner(inner))
    }
}
