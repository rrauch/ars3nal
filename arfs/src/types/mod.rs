pub mod drive;
pub mod drive_signature;
pub mod file;
pub mod folder;
pub mod snapshot;

use crate::serde_tag::{BytesToStr, Chain, ToFromStr};
use crate::types::drive::DriveId;
use crate::{Timestamp, serde_tag};
use ario_client::location::ItemArl;
use ario_core::base64::Base64Error;
use ario_core::blob::{Blob, OwnedBlob};
use ario_core::tag::Tag;
use ario_core::{BlockNumber, JsonValue};
use derive_where::derive_where;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::{DisplayFromStr, TimestampMilliSeconds, TimestampSeconds};
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;
use strum::EnumString;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArFsVersion {
    pub major: usize,
    pub minor: usize,
}

impl Display for ArFsVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl FromStr for ArFsVersion {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('.');

        let major = parse_version_part(parts.next(), s)?;
        let minor = parse_version_part(parts.next(), s)?;

        if parts.next().is_some() {
            return Err(ParseError::InvalidVersion(s.to_string()));
        }

        Ok(ArFsVersion { major, minor })
    }
}

fn parse_version_part(part: Option<&str>, s: &str) -> Result<usize, ParseError> {
    Ok(part
        .ok_or_else(|| ParseError::InvalidVersion(s.to_string()))?
        .parse()
        .map_err(|_| ParseError::InvalidVersion(s.to_string()))?)
}

pub trait Id: Debug + Display + FromStr + Clone + PartialEq + Eq + Send + Sync {}
impl<ID: Debug + Display + FromStr + Clone + PartialEq + Eq + Send + Sync> Id for ID {}

#[derive_where(Debug, Clone, PartialEq; ID)]
#[repr(transparent)]
pub struct TaggedId<ID: Id, TAG>(ID, PhantomData<TAG>);

impl<ID: Id, TAG> Display for TaggedId<ID, TAG> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<ID: Id, TAG> FromStr for TaggedId<ID, TAG> {
    type Err = <ID as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(ID::from_str(s)?, PhantomData))
    }
}

impl<ID: Id, TAG> TryFrom<Vec<u8>> for TaggedId<ID, TAG>
where
    ID: TryFrom<Vec<u8>>,
{
    type Error = <ID as TryFrom<Vec<u8>>>::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(ID::try_from(value)?, PhantomData))
    }
}

impl<ID: Id, TAG> AsRef<[u8]> for TaggedId<ID, TAG>
where
    ID: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug)]
pub(crate) struct Model<E: Entity> {
    header: Header<E::Header, E>,
    metadata: Metadata<E::Metadata, E>,
    block_height: BlockNumber,
    location: ItemArl,
    _marker: PhantomData<E>,
}

pub(crate) trait Entity {
    const TYPE: &'static str;

    type Header;
    type Metadata;
}

pub(crate) trait HasId {
    type Id;

    fn id(entity: &Model<Self>) -> &Self::Id
    where
        Self: Entity + Sized;
}

pub(crate) trait HasTimestamp {
    fn timestamp(entity: &Model<Self>) -> &Timestamp
    where
        Self: Entity + Sized;
}

pub(crate) trait HasContentType {
    fn content_type(entity: &Model<Self>) -> &ContentType
    where
        Self: Entity + Sized;
}

pub(crate) enum Visibility {
    Visible,
    Hidden,
}

pub(crate) trait HasVisibility {
    fn visibility(entity: &Model<Self>) -> Visibility
    where
        Self: Entity + Sized;
}

pub(crate) trait HasName {
    fn name(entity: &Model<Self>) -> &str
    where
        Self: Entity + Sized;
}

pub(crate) trait MaybeHasCipher {
    fn cipher(entity: &Model<Self>) -> Option<(Cipher, Option<Blob<'_>>)>
    where
        Self: Entity + Sized;
}

pub(crate) trait HasDriveId {
    fn drive_id(entity: &Model<Self>) -> &DriveId
    where
        Self: Entity + Sized;
}

impl<E: Entity> Model<E> {
    pub(crate) fn new(
        header: Header<E::Header, E>,
        metadata: Metadata<E::Metadata, E>,
        block_height: BlockNumber,
        location: ItemArl,
    ) -> Self {
        Self {
            header,
            metadata,
            block_height,
            location,
            _marker: PhantomData,
        }
    }

    pub(crate) fn header(&self) -> &Header<E::Header, E> {
        &self.header
    }

    pub(crate) fn metadata(&self) -> &Metadata<E::Metadata, E> {
        &self.metadata
    }

    pub(crate) fn into_inner(self) -> (Header<E::Header, E>, Metadata<E::Metadata, E>) {
        (self.header, self.metadata)
    }

    pub(crate) fn extra_attribute_names(&self) -> impl Iterator<Item = &str> {
        self.header.extra.keys().map(|k| k.as_str())
    }

    pub(crate) fn extra_attribute<'a>(&'a self, name: &str) -> Option<Blob<'a>> {
        self.header.extra.get(name).map(|v| v.borrow())
    }

    pub fn block_height(&self) -> BlockNumber {
        self.block_height
    }

    pub fn location(&self) -> &ItemArl {
        &self.location
    }
}

impl<E: Entity> Model<E>
where
    E: HasId,
{
    pub fn id(&self) -> &E::Id {
        E::id(self)
    }
}

impl<E: Entity> Model<E>
where
    E: HasTimestamp,
{
    pub fn timestamp(&self) -> &Timestamp {
        E::timestamp(self)
    }
}

impl<E: Entity> Model<E>
where
    E: HasVisibility,
{
    pub fn is_hidden(&self) -> bool {
        match E::visibility(self) {
            Visibility::Hidden => true,
            Visibility::Visible => false,
        }
    }
}

impl<E: Entity> Model<E>
where
    E: HasContentType,
{
    pub fn content_type(&self) -> &ContentType {
        E::content_type(self)
    }
}

impl<E: Entity> Model<E>
where
    E: HasName,
{
    pub fn name(&self) -> &str {
        E::name(self)
    }
}

impl<E: Entity> Model<E>
where
    E: MaybeHasCipher,
{
    pub fn cipher(&self) -> Option<(Cipher, Option<Blob<'_>>)> {
        E::cipher(self)
    }
}

impl<E: Entity> Model<E>
where
    E: HasDriveId,
{
    pub fn drive_id(&self) -> &DriveId {
        E::drive_id(self)
    }
}

#[serde_as]
#[derive_where(Debug, Clone, PartialEq; H)]
#[derive(Serialize, Deserialize)]
pub(crate) struct Header<H, T> {
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "ArFS")]
    version: ArFsVersion,
    #[serde(flatten)]
    inner: H,
    #[serde(flatten)]
    extra: HashMap<String, OwnedBlob>,
    #[serde(skip)]
    _marker: PhantomData<(T, H)>,
}

impl<H, T> Header<H, T> {
    pub fn version(&self) -> &ArFsVersion {
        &self.version
    }
    pub(crate) fn as_inner(&self) -> &H {
        &self.inner
    }

    pub(crate) fn into_inner(self) -> H {
        self.inner
    }

    pub(crate) fn to_tags(&self) -> Result<Vec<Tag<'_>>, serde_tag::Error>
    where
        H: Serialize + Sized,
    {
        self.try_into()
    }
}

impl<'a, H, T> TryInto<Vec<Tag<'static>>> for &'a Header<H, T>
where
    H: Serialize + Sized,
{
    type Error = serde_tag::Error;

    fn try_into(self) -> Result<Vec<Tag<'static>>, Self::Error> {
        Ok(serde_tag::to_tags(self)?)
    }
}

impl<'a, H, T> TryFrom<&'a Vec<Tag<'a>>> for Header<H, T>
where
    H: Deserialize<'a> + Sized,
{
    type Error = ParseError;

    fn try_from(value: &'a Vec<Tag>) -> Result<Self, Self::Error> {
        Ok(serde_tag::from_tags(value)?)
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("invalid or unsupported version: '{0}'")]
    InvalidVersion(String),
    #[error("incorrect entity; expected: '{expected}' but got '{actual}'")]
    IncorrectEntity { expected: String, actual: String },
    #[error("invalid or unsupported cipher: '{0}'")]
    UnsupportedCipher(String),
    #[error("invalid or unsupported auth mode: '{0}'")]
    UnsupportedAuthMode(String),
    #[error("invalid or unsupported privacy: '{0}'")]
    UnsupportedPrivacy(String),
    #[error("invalid or unsupported signature format: '{0}'")]
    UnsupportedSignatureFormat(String),
    #[error("ArFS version tag not found")]
    NoVersionTag,
    #[error("invalid unix timestamp: '{0}'")]
    InvalidUnixTime(String),
    #[error("invalid uuid")]
    InvalidUuid,
    #[error("invalid content type: '{0}'")]
    InvalidContentType(String),
    #[error("content type is missing")]
    MissingContentType,
    #[error("id is missing")]
    MissingId,
    #[error("privacy is missing")]
    MissingPrivacy,
    #[error("unix time is missing")]
    MissingUnixTime,
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    TagError(#[from] serde_tag::Error),
    #[error(transparent)]
    Base64Error(#[from] Base64Error),
    #[error(transparent)]
    UuidError(#[from] uuid::Error),
    #[error("parse error: {0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Metadata<M, Tag> {
    #[serde(flatten)]
    inner: M,
    #[serde(flatten)]
    extra: HashMap<String, JsonValue>,
    #[serde(skip)]
    _marker: PhantomData<Tag>,
}

impl<M, Tag> Metadata<M, Tag> {
    pub(crate) fn into_inner(self) -> (M, HashMap<String, JsonValue>) {
        (self.inner, self.extra)
    }
}

impl<Tag> Metadata<(), Tag> {
    pub(crate) fn none() -> Self {
        Self {
            inner: (),
            extra: HashMap::default(),
            _marker: PhantomData,
        }
    }
}

impl<M, Tag> TryFrom<JsonValue> for Metadata<M, Tag>
where
    M: DeserializeOwned + Sized,
{
    type Error = ParseError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value)?)
    }
}

impl<M, Tag> TryInto<JsonValue> for Metadata<M, Tag>
where
    M: Serialize + Sized,
{
    type Error = ParseError;

    fn try_into(self) -> Result<JsonValue, Self::Error> {
        Ok(serde_json::to_value(self)?)
    }
}

/*
enum Entity {
    Drive(DriveEntity),
    DriveSignature(DriveSignatureEntity),
    Folder(FolderEntity),
    File(FileEntity),
    Snapshot(SnapshotEntity),
}
*/

fn unsupported_signature_format_err(s: &str) -> ParseError {
    ParseError::UnsupportedSignatureFormat(s.to_string())
}

#[derive(Debug, Copy, Clone, PartialEq, EnumString, strum::Display)]
#[strum(
    parse_err_fn = unsupported_signature_format_err,
    parse_err_ty = ParseError,
    serialize_all = "snake_case"
)]
enum SignatureFormat {
    #[strum(serialize = "1")]
    V1,
}

fn unsupported_privacy_err(s: &str) -> ParseError {
    ParseError::UnsupportedPrivacy(s.to_string())
}

#[derive(Debug, Copy, Clone, PartialEq, EnumString, strum::Display)]
#[strum(
    parse_err_fn = unsupported_privacy_err,
    parse_err_ty = ParseError,
    serialize_all = "snake_case"
)]
pub enum Privacy {
    Public,
    Private,
}

impl Default for Privacy {
    fn default() -> Self {
        Self::Public
    }
}

fn unsupported_auth_mode_err(s: &str) -> ParseError {
    ParseError::UnsupportedAuthMode(s.to_string())
}

#[derive(Debug, Copy, Clone, PartialEq, EnumString, strum::Display)]
#[strum(
    parse_err_fn = unsupported_auth_mode_err,
    parse_err_ty = ParseError,
    serialize_all = "snake_case"
)]
pub(crate) enum AuthMode {
    Password,
}

#[derive(Debug, Clone, PartialEq, EnumString, strum::Display)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum ContentType {
    #[strum(serialize = "application/json")]
    Json,
    #[strum(serialize = "application/octet-stream")]
    Binary,
    #[strum(default)]
    Other(String),
}

impl AsRef<str> for ContentType {
    fn as_ref(&self) -> &str {
        match self {
            Self::Json => "application/json",
            Self::Binary => "application/octet-stream",
            Self::Other(other) => other.as_str(),
        }
    }
}

fn unsupported_cipher_err(s: &str) -> ParseError {
    ParseError::UnsupportedCipher(s.to_string())
}

#[derive(Debug, Copy, Clone, PartialEq, EnumString, strum::Display)]
#[strum(
    parse_err_fn = unsupported_cipher_err,
    parse_err_ty = ParseError
)]
enum Cipher {
    #[strum(serialize = "AES256-GCM")]
    Aes256Gcm,
    #[strum(serialize = "AES256-CTR")]
    Aes256Ctr,
}

fn bool_false() -> bool {
    false
}
