use crate::blob::{AsBlob, OwnedBlob};
use core::fmt;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::de::Visitor;
use serde::{Deserializer, Serializer};
use serde_with::{DeserializeAs, SerializeAs};
use std::fmt::Display;
use std::marker::PhantomData;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Base64Error {
    #[error("decoding base64 failed: {0}")]
    DecodingError(String),
}

pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

/*impl<T: AsRef<[u8]>> ToBase64 for T {
    fn to_base64(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(self.as_ref())
            .expect("base64 encoding should not fail")
    }
}*/

impl<T: AsBlob> ToBase64 for T {
    fn to_base64(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(self.as_blob().bytes())
            .expect("base64 encoding should not fail")
    }
}

pub trait FromBase64 {
    fn try_from_base64(&self) -> Result<OwnedBlob, Base64Error>;
}

impl<T: AsRef<str>> FromBase64 for T {
    fn try_from_base64(&self) -> Result<OwnedBlob, Base64Error> {
        Ok(Base64UrlSafeNoPadding::decode_to_vec(self.as_ref(), None)
            .map_err(|e| Base64Error::DecodingError(e.to_string()))?
            .into())
    }
}

pub trait TryFromBase64 {
    type Error: Display;

    fn try_from_base64(base64: impl AsRef<[u8]>) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

#[derive(Error, Debug)]
pub enum TryFromBase64Error<E: Display> {
    #[error(transparent)]
    Base64DecodingError(Base64Error),
    #[error(transparent)]
    OtherError(#[from] E),
}

impl<T> TryFromBase64 for T
where
    T: TryFrom<Vec<u8>>,
    <T as TryFrom<Vec<u8>>>::Error: Display,
{
    type Error = TryFromBase64Error<<T as TryFrom<Vec<u8>>>::Error>;

    fn try_from_base64(base64: impl AsRef<[u8]>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let bytes = Base64UrlSafeNoPadding::decode_to_vec(base64, None).map_err(|e| {
            TryFromBase64Error::Base64DecodingError(Base64Error::DecodingError(e.to_string()))
        })?;

        Ok(T::try_from(bytes)?)
    }
}

pub struct OptionalBase64As;

impl<T> SerializeAs<Option<T>> for OptionalBase64As
where
    T: AsBlob,
{
    fn serialize_as<S>(source: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match source {
            None => serializer.serialize_str(""),
            Some(source) => serializer.serialize_str(source.to_base64().as_str()),
        }
    }
}

impl<'de, T> DeserializeAs<'de, Option<T>> for OptionalBase64As
where
    T: TryFromBase64,
{
    fn deserialize_as<D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Helper<T>(PhantomData<T>);

        impl<T> Visitor<'_> for Helper<T>
        where
            T: TryFromBase64,
        {
            type Value = Option<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "either a string representing a base64 encoded value or an empty string",
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.is_empty() {
                    return Ok(None);
                }
                Ok(Some(
                    T::try_from_base64(v.as_bytes()).map_err(serde::de::Error::custom)?,
                ))
            }
        }

        deserializer.deserialize_str(Helper::<T>(PhantomData))
    }
}
