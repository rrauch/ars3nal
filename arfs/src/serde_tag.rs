use ario_core::blob::Blob;
use ario_core::tag::{Tag, TagName, TagValue};
use serde::de::{Error as DeError, IntoDeserializer};
use serde::ser::Error as SerError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};
use std::borrow::Cow;
use std::fmt::Display;
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error;

pub trait Transformer<'a, 'de>: Sized {
    type Output: Into<serde_content::Value<'a>>;

    fn transform_from<D>(deserializer: D) -> Result<Self::Output, D::Error>
    where
        D: Deserializer<'de>;

    fn transform_into<S>(serializer: S, value: serde_content::Value<'a>) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

pub struct Chain<T>(PhantomData<T>);

impl<'a, 'de, T, TR, SAs> SerializeAs<T> for Chain<(TR, SAs)>
where
    SAs: SerializeAs<T>,
    TR: Transformer<'a, 'de>,
{
    fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        TR::transform_into(
            serializer,
            SAs::serialize_as(source, serde_content::Serializer::new())
                .map_err(S::Error::custom)?,
        )
    }
}

impl<'a, 'b, 'de, T, TR1, TR2, SAs> SerializeAs<T> for Chain<(TR1, TR2, SAs)>
where
    SAs: SerializeAs<T>,
    TR2: Transformer<'b, 'a>,
    TR1: Transformer<'a, 'de>,
{
    fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        TR1::transform_into(
            serializer,
            TR2::transform_into(
                serde_content::Serializer::new(),
                SAs::serialize_as(source, serde_content::Serializer::new())
                    .map_err(S::Error::custom)?,
            )
            .map_err(S::Error::custom)?,
        )
    }
}

impl<'a, 'b, 'c, 'de, T, TR1, TR2, TR3, SAs> SerializeAs<T> for Chain<(TR1, TR2, TR3, SAs)>
where
    SAs: SerializeAs<T>,
    TR3: Transformer<'c, 'b>,
    TR2: Transformer<'b, 'a>,
    TR1: Transformer<'a, 'de>,
{
    fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        TR1::transform_into(
            serializer,
            TR2::transform_into(
                serde_content::Serializer::new(),
                TR3::transform_into(
                    serde_content::Serializer::new(),
                    SAs::serialize_as(source, serde_content::Serializer::new())
                        .map_err(S::Error::custom)?,
                )
                .map_err(S::Error::custom)?,
            )
            .map_err(S::Error::custom)?,
        )
    }
}

impl<'a, 'de, T, TR, DAs> DeserializeAs<'de, T> for Chain<(TR, DAs)>
where
    TR: Transformer<'a, 'de>,
    DAs: DeserializeAs<'a, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        D::Error: Display,
    {
        Ok(
            DAs::deserialize_as(TR::transform_from(deserializer)?.into().into_deserializer())
                .map_err(|e| D::Error::custom(e.to_string()))?,
        )
    }
}

impl<'a, 'b, 'de, T, TR1, TR2, DAs> DeserializeAs<'de, T> for Chain<(TR1, TR2, DAs)>
where
    TR1: Transformer<'a, 'de>,
    TR2: Transformer<'b, 'a>,
    DAs: DeserializeAs<'b, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        D::Error: Display,
    {
        Ok(DAs::deserialize_as(
            TR2::transform_from(
                TR1::transform_from(deserializer)?
                    .into()
                    .into_deserializer(),
            )
            .map_err(|e| D::Error::custom(e.to_string()))?
            .into()
            .into_deserializer(),
        )
        .map_err(|e| D::Error::custom(e.to_string()))?)
    }
}

impl<'a, 'b, 'c, 'de, T, TR1, TR2, TR3, DAs> DeserializeAs<'de, T> for Chain<(TR1, TR2, TR3, DAs)>
where
    TR1: Transformer<'a, 'de>,
    TR2: Transformer<'b, 'a>,
    TR3: Transformer<'c, 'b>,
    DAs: DeserializeAs<'c, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        D::Error: Display,
    {
        Ok(DAs::deserialize_as(
            TR3::transform_from(
                TR2::transform_from(
                    TR1::transform_from(deserializer)?
                        .into()
                        .into_deserializer(),
                )
                .map_err(|e| D::Error::custom(e.to_string()))?
                .into()
                .into_deserializer(),
            )
            .map_err(|e| D::Error::custom(e.to_string()))?
            .into()
            .into_deserializer(),
        )
        .map_err(|e| D::Error::custom(e.to_string()))?)
    }
}

pub struct ToFromStr<T: Display + FromStr>(PhantomData<T>);

impl<'a, 'de, T: Display + FromStr> Transformer<'a, 'de> for ToFromStr<T>
where
    T: Into<serde_content::Value<'a>>,
    T: Deserialize<'a>,
    <T as FromStr>::Err: Display,
{
    type Output = T;

    fn transform_from<D>(deserializer: D) -> Result<Self::Output, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = <Cow<'a, str>>::deserialize(deserializer)?;
        T::from_str(value.as_ref()).map_err(D::Error::custom)
    }

    fn transform_into<S>(serializer: S, value: serde_content::Value<'a>) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let des = value.into_deserializer();
        let value: T = Deserialize::deserialize(des).map_err(S::Error::custom)?;
        serializer.serialize_str(value.to_string().as_str())
    }
}

pub struct BytesToStr;

impl<'a, 'de> Transformer<'a, 'de> for BytesToStr
where
    'de: 'a,
{
    type Output = Cow<'a, str>;

    fn transform_from<D>(deserializer: D) -> Result<Self::Output, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match serde_bytes::deserialize::<Cow<'a, [u8]>, _>(deserializer)? {
                Cow::Borrowed(slice) => {
                    Cow::Borrowed(std::str::from_utf8(slice).map_err(D::Error::custom)?)
                }
                Cow::Owned(vec) => Cow::Owned(String::from_utf8(vec).map_err(D::Error::custom)?),
            },
        )
    }

    fn transform_into<S>(serializer: S, value: serde_content::Value<'_>) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str = match value {
            serde_content::Value::String(str) => str,
            _ => return Err(S::Error::custom("string input expected")),
        };
        serializer.serialize_bytes(str.as_bytes())
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    DeserializationError(serde_content::Error),
    #[error(transparent)]
    SerializationError(serde_content::Error),
}

pub fn from_tags<'a, T>(tags: impl IntoIterator<Item = &'a Tag<'a>>) -> Result<T, Error>
where
    T: Deserialize<'a>,
{
    let value = serde_content::Value::Map(
        tags.into_iter()
            .filter_map(|t| {
                t.name.as_str().map(|s| {
                    (
                        serde_content::Value::String(s.into()),
                        serde_content::Value::Bytes(t.value.bytes().into()),
                    )
                })
            })
            .collect(),
    );
    Ok(serde_content::Deserializer::new(value)
        .deserialize()
        .map_err(Error::DeserializationError)?)
}

pub fn to_tags<T>(value: &T) -> Result<Vec<Tag<'static>>, Error>
where
    T: Serialize,
{
    Ok(match serde_content::Serializer::new()
        .serialize(value)
        .map_err(Error::SerializationError)?
    {
        serde_content::Value::Map(entries) => entries
            .into_iter()
            .filter_map(|(k, v)| try_into_tag(k, v).transpose()),
        _ => {
            return Err(Error::SerializationError(
                <serde_content::Error as SerError>::custom("expected a Map"),
            ));
        }
    }
    .collect::<Result<Vec<Tag<'static>>, Error>>()?)
}

fn try_into_tag<'a>(
    name: serde_content::Value<'a>,
    mut value: serde_content::Value<'a>,
) -> Result<Option<Tag<'a>>, Error> {
    let name = match name {
        serde_content::Value::String(str) => TagName::try_from(match str {
            Cow::Owned(owned) => Blob::from(owned.into_bytes()),
            Cow::Borrowed(borrowed) => Blob::from(borrowed.as_bytes()),
        })
        .map_err(|_| {
            Error::SerializationError(<serde_content::Error as SerError>::custom(
                "expected a valid tag name",
            ))
        })?,
        _ => {
            return Err(Error::SerializationError(
                <serde_content::Error as SerError>::custom("expected a String"),
            ));
        }
    };

    loop {
        let value = match value {
            serde_content::Value::Bytes(bytes) => {
                TagValue::try_from(Blob::from(bytes)).map_err(|_| {
                    Error::SerializationError(<serde_content::Error as SerError>::custom(
                        "expected a valid tag value",
                    ))
                })?
            }
            serde_content::Value::Option(None) => return Ok(None),
            serde_content::Value::Option(Some(optional_value)) => {
                value = *optional_value;
                continue;
            }
            _ => {
                return Err(Error::SerializationError(
                    <serde_content::Error as SerError>::custom("expected Bytes"),
                ));
            }
        };

        return Ok(Some(Tag::new(name, value)));
    }
}
