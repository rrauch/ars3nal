pub mod drive;
pub mod drive_signature;
pub mod file;
pub mod folder;
pub mod snapshot;

use crate::crypto::MetadataCryptor;
use crate::serde_tag::{BytesToStr, Chain, ToFromStr};
use crate::types::drive::{DriveEntity, DriveId};
use crate::types::drive_signature::DriveSignatureEntity;
use crate::types::file::{FileEntity, FileId};
use crate::types::folder::{FolderEntity, FolderId};
use crate::types::snapshot::{SnapshotEntity, SnapshotId};
use crate::{KeyRing, Timestamp, Visibility, serde_tag};
use ario_client::location::Arl;
use ario_core::base64::Base64Error;
use ario_core::blob::{AsBlob, Blob, OwnedBlob};
use ario_core::crypto::aes::ctr::AesCtr;
use ario_core::crypto::aes::gcm::DefaultAesGcm;
use ario_core::tag::Tag;
use ario_core::{BlockNumber, JsonValue};
use derive_where::derive_where;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
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

impl Default for ArFsVersion {
    fn default() -> Self {
        Self {
            major: 0,
            minor: 15,
        }
    }
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

#[derive_where(Debug, Clone, PartialEq, Eq, Hash; ID)]
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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Model<E: Entity> {
    header: Header<E::Header, E>,
    metadata: Metadata<E::Metadata, E>,
    extra: E::Extra,
    block_height: BlockNumber,
    location: Arl,
    _marker: PhantomData<E>,
}

pub(crate) trait Entity {
    const TYPE: &'static str;

    type Header: Debug + Clone + PartialEq;
    type Metadata: Debug + Clone + PartialEq;
    type Extra: Default + Debug + Clone + PartialEq;
    type MetadataCryptor<'a>: MetadataCryptor<'a>;

    fn maybe_metadata_cryptor(
        header: &Self::Header,
    ) -> Option<
        Result<
            Self::MetadataCryptor<'_>,
            <Self::MetadataCryptor<'_> as MetadataCryptor<'_>>::DecryptionError,
        >,
    > {
        None
    }
}

pub(crate) trait HasId {
    const NAME: &'static str;
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
    fn cipher(&self) -> Option<(Cipher, Option<Blob<'_>>)>;
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
        location: Arl,
    ) -> Self {
        Self {
            header,
            metadata,
            extra: <E::Extra as Default>::default(),
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
        self.header.extra.keys().filter_map(|k| {
            if k != "Entity-Type" {
                Some(k.as_str())
            } else {
                None
            }
        })
    }

    pub(crate) fn extra_attribute<'a>(&'a self, name: &str) -> Option<Blob<'a>> {
        self.header.extra.get(name).map(|v| v.borrow())
    }

    pub fn block_height(&self) -> BlockNumber {
        self.block_height
    }

    pub fn location(&self) -> &Arl {
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
    E::Header: MaybeHasCipher,
{
    pub fn cipher(&self) -> Option<(Cipher, Option<Blob<'_>>)> {
        self.header.inner.cipher()
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
pub(crate) struct Header<H, T: Entity> {
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "ArFS")]
    version: ArFsVersion,
    #[serde(flatten)]
    inner: H,
    #[serde(flatten)]
    extra: HashMap<String, OwnedBlob>,
    #[serde(
        rename = "Entity-Type",
        skip_deserializing,
        serialize_with = "serialize_entity_type",
        bound = "T: Entity"
    )]
    _marker: PhantomData<(T, H)>,
}

fn serialize_entity_type<T: Entity, H, S: Serializer>(
    _: &PhantomData<(T, H)>,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(T::TYPE.as_bytes())
}

impl<H, T: Entity> Header<H, T> {
    pub(crate) fn from_inner(
        version: Option<ArFsVersion>,
        inner: H,
        extra: Option<HashMap<String, OwnedBlob>>,
    ) -> Self {
        Self {
            version: version.unwrap_or_default(),
            inner,
            extra: extra.unwrap_or_default(),
            _marker: PhantomData::default(),
        }
    }
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

impl<'a, H, T: Entity> TryInto<Vec<Tag<'static>>> for &'a Header<H, T>
where
    H: Serialize + Sized,
{
    type Error = serde_tag::Error;

    fn try_into(self) -> Result<Vec<Tag<'static>>, Self::Error> {
        Ok(serde_tag::to_tags(self)?)
    }
}

impl<'a, H, T: Entity> TryFrom<&'a Vec<Tag<'a>>> for Header<H, T>
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
    #[error("operation requires access to key ring")]
    KeyRingRequired,
    #[error("metadata encryption error: {0}")]
    MetadataEncryptionError(String),
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
    pub(crate) fn from_inner(inner: M, extra: Option<HashMap<String, JsonValue>>) -> Self {
        Self {
            inner,
            extra: extra.unwrap_or_default(),
            _marker: PhantomData::default(),
        }
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

pub(crate) enum ArfsEntity {
    Drive(DriveEntity),
    DriveSignature(DriveSignatureEntity),
    Folder(FolderEntity),
    File(FileEntity),
    Snapshot(SnapshotEntity),
}

impl ArfsEntity {
    pub(crate) fn to_header_tags(&self) -> Result<Vec<Tag<'static>>, serde_tag::Error> {
        Ok(match self {
            Self::Drive(entity) => (&entity.header).try_into()?,
            Self::DriveSignature(entity) => (&entity.header).try_into()?,
            Self::Folder(entity) => (&entity.header).try_into()?,
            Self::File(entity) => (&entity.header).try_into()?,
            Self::Snapshot(entity) => (&entity.header).try_into()?,
        })
    }

    pub(crate) fn to_metadata_bytes(
        &self,
        key_ring: Option<&KeyRing>,
    ) -> Result<OwnedBlob, ParseError> {
        match self {
            Self::Drive(entity) => to_maybe_encrypted_metadata(entity, key_ring),
            Self::DriveSignature(entity) => to_maybe_encrypted_metadata(entity, key_ring),
            Self::Folder(entity) => to_maybe_encrypted_metadata(entity, key_ring),
            Self::File(entity) => to_maybe_encrypted_metadata(entity, key_ring),
            Self::Snapshot(entity) => to_maybe_encrypted_metadata(entity, key_ring),
        }
    }
}

fn to_maybe_encrypted_metadata<E: Entity>(
    entity: &Model<E>,
    key_ring: Option<&KeyRing>,
) -> Result<OwnedBlob, ParseError>
where
    <E as Entity>::Metadata: Serialize,
{
    let plaintext = serde_json::to_vec(&entity.metadata)?;
    Ok(E::maybe_metadata_cryptor(entity.header.as_inner())
        .transpose()
        .map_err(|e| ParseError::MetadataEncryptionError(e.to_string()))?
        .map(|mc| -> Result<_, ParseError> {
            mc.encrypt(
                plaintext.as_slice(),
                key_ring.ok_or_else(|| ParseError::KeyRingRequired)?,
            )
            .map_err(|e| ParseError::MetadataEncryptionError(e.to_string()))
        })
        .transpose()?
        .unwrap_or(plaintext)
        .into())
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ArfsEntityId {
    Drive(DriveId),
    Folder(FolderId),
    File(FileId),
    Snapshot(SnapshotId),
}

fn unsupported_signature_format_err(s: &str) -> ParseError {
    ParseError::UnsupportedSignatureFormat(s.to_string())
}

#[derive(Debug, Copy, Clone, PartialEq, EnumString, strum::Display)]
#[strum(
    parse_err_fn = unsupported_signature_format_err,
    parse_err_ty = ParseError,
    serialize_all = "snake_case"
)]
pub enum SignatureFormat {
    #[strum(serialize = "1")]
    V1,
    #[strum(serialize = "2")]
    V2,
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
pub(crate) enum Cipher {
    #[strum(serialize = "AES256-GCM")]
    Aes256Gcm,
    #[strum(serialize = "AES256-CTR")]
    Aes256Ctr,
}

impl Cipher {
    pub fn generate_nonce(&self) -> OwnedBlob {
        match self {
            Self::Aes256Gcm => DefaultAesGcm::<256>::generate_nonce(),
            Self::Aes256Ctr => AesCtr::<256>::generate_nonce(),
        }
        .as_blob()
        .into_owned()
    }
}

fn bool_false() -> bool {
    false
}
