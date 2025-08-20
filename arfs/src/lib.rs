pub(crate) mod serde_tag;

use crate::serde_tag::BytesToStr;
use crate::serde_tag::Chain;
use crate::serde_tag::ToFromStr;
use ario_core::base64::Base64Error;
use ario_core::blob::{Blob, OwnedBlob};
use ario_core::tx::{Tag, TagValue, TxId};
use ario_core::wallet::WalletAddress;
use ario_core::{BlockNumber, JsonValue};
use chrono::{DateTime, Utc};
use derive_where::derive_where;
use serde::de::{DeserializeOwned, Error};
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::DisplayFromStr;
use serde_with::TimestampSeconds;
use serde_with::serde_as;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;
use strum::EnumString;
use thiserror::Error;
use uuid::Uuid;

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

struct Model<H, M, T> {
    header: Header<H, T>,
    metadata: Metadata<M, T>,
}

impl<H, M, T> Model<H, M, T> {
    fn new(header: Header<H, T>, metadata: Metadata<M, T>) -> Self {
        Self { header, metadata }
    }

    pub(crate) fn header(&self) -> &Header<H, T> {
        &self.header
    }

    pub(crate) fn metadata(&self) -> &Metadata<M, T> {
        &self.metadata
    }
}

#[serde_as]
#[derive_where(Debug, Clone, PartialEq; H)]
#[derive(Serialize, Deserialize)]
struct Header<H, T> {
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
struct Metadata<M, Tag> {
    #[serde(flatten)]
    inner: M,
    #[serde(flatten)]
    extra: HashMap<String, JsonValue>,
    #[serde(skip)]
    _marker: PhantomData<Tag>,
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

pub struct DriveKind;
pub type DriveId = TaggedId<Uuid, DriveKind>;
type DriveEntity = Model<DriveHeader, DriveMetadata, DriveKind>;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DriveHeader {
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Cipher?")]
    cipher: Option<Cipher>,
    #[serde(rename = "Cipher-IV?")]
    cipher_iv: Option<OwnedBlob>,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Content-Type")]
    content_type: ContentType,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Drive-Id")]
    drive_id: DriveId,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Drive-Privacy")]
    privacy: Privacy,
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Drive-Auth-Mode?")]
    auth_mode: Option<AuthMode>,
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Signature-Type?")]
    signature_type: Option<SignatureFormat>,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<i64>, TimestampSeconds)>")]
    #[serde(rename = "Unix-Time")]
    time: DateTime<Utc>,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DriveMetadata {
    name: String,
    #[serde_as(as = "DisplayFromStr")]
    #[serde(rename = "rootFolderId")]
    root_folder_id: FolderId,
}

/*
pub struct DriveSignatureKind;
type DriveSignatureEntity<'a> = Model<'a, DriveSignatureHeader<'a>, (), DriveSignatureKind>;

#[derive(Debug, Clone, PartialEq)]
struct DriveSignatureHeader<'a> {
    signature_format: SignatureFormat,
    cipher: Option<Cipher>,
    cipher_iv: Option<Blob<'a>>,
    data: Blob<'a>,
}

enum Entity<'a> {
    Drive(DriveEntity<'a>),
    /*DriveSignature(DriveSignatureEntity<'a>),
    Folder(FolderEntity<'a>),
    File(FileEntity<'a>),
    Snapshot(SnapshotEntity<'a>),*/
}*/

fn unsupported_signature_format_err(s: &str) -> ParseError {
    ParseError::UnsupportedSignatureFormat(s.to_string())
}

#[derive(Debug, Clone, PartialEq, EnumString, strum::Display)]
#[strum(
    parse_err_fn = unsupported_signature_format_err,
    parse_err_ty = ParseError,
    serialize_all = "snake_case"
)]
enum SignatureFormat {
    #[strum(serialize = "1")]
    V1,
}

pub struct FolderKind;
pub type FolderId = TaggedId<Uuid, FolderKind>;
/*type FolderEntity<'a> = Model<'a, FolderHeader<'a>, FolderMetadata, FolderKind>;

#[derive(Debug, Clone, PartialEq)]
struct FolderHeader<'a> {
    cipher: Option<Cipher>,
    cipher_iv: Option<Blob<'a>>,
    content_type: ContentType,
    drive_id: DriveId,
    folder_id: FolderId,
    parent_folder_id: Option<FolderId>,
    time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
struct FolderMetadata {
    name: String,
}

pub struct FileKind;
pub type FileId = TaggedId<Uuid, FileKind>;
type FileEntity<'a> = Model<'a, FileHeader<'a>, FileMetadata, FileKind>;

#[derive(Debug, Clone, PartialEq)]
struct FileHeader<'a> {
    cipher: Option<Cipher>,
    cipher_iv: Option<Blob<'a>>,
    content_type: ContentType,
    drive_id: DriveId,
    file_id: FileId,
    parent_folder_id: FolderId,
    time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
struct FileMetadata {
    name: String,
    size: u64,
    last_modified: DateTime<Utc>,
    data_tx_id: TxId,
    data_content_type: ContentType,
    pinned_data_owner: Option<WalletAddress>,
}

pub struct SnapshotKind;
pub type SnapshotId = TaggedId<Uuid, SnapshotKind>;
type SnapshotEntity<'a> = Model<'a, SnapshotHeader, (), SnapshotKind>;

#[derive(Debug, Clone, PartialEq)]
struct SnapshotHeader {
    drive_id: DriveId,
    snapshot_id: SnapshotId,
    content_type: ContentType,
    block_start: BlockNumber,
    block_end: BlockNumber,
    data_start: BlockNumber,
    data_end: BlockNumber,
    time: DateTime<Utc>,
}*/

fn unsupported_privacy_err(s: &str) -> ParseError {
    ParseError::UnsupportedPrivacy(s.to_string())
}

#[derive(Debug, Clone, PartialEq, EnumString, strum::Display)]
#[strum(
    parse_err_fn = unsupported_privacy_err,
    parse_err_ty = ParseError,
    serialize_all = "snake_case"
)]
enum Privacy {
    Public,
    Private,
}

fn unsupported_auth_mode_err(s: &str) -> ParseError {
    ParseError::UnsupportedAuthMode(s.to_string())
}

#[derive(Debug, Clone, PartialEq, EnumString, strum::Display)]
#[strum(
    parse_err_fn = unsupported_auth_mode_err,
    parse_err_ty = ParseError,
    serialize_all = "snake_case"
)]
enum AuthMode {
    Password,
}

#[derive(Debug, Clone, PartialEq, EnumString, strum::Display)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
enum ContentType {
    #[strum(serialize = "application/json")]
    Json,
    #[strum(serialize = "application/octet-stream")]
    Binary,
    #[strum(default)]
    Other(String),
}

fn unsupported_cipher_err(s: &str) -> ParseError {
    ParseError::UnsupportedCipher(s.to_string())
}

#[derive(Debug, Clone, PartialEq, EnumString, strum::Display)]
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

#[cfg(test)]
mod tests {
    use crate::{
        ArFsVersion, ContentType, DriveEntity, DriveHeader, DriveId, DriveKind, DriveMetadata,
        FolderId, Header, Metadata, Privacy,
    };
    use ario_client::Client;
    use ario_client::graphql::cynic;
    use ario_client::graphql::schema;
    use ario_core::blob::Blob;
    use ario_core::tx::Tag;
    use ario_core::{Gateway, JsonValue};
    use chrono::DateTime;
    use std::str::FromStr;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[test]
    fn drive_entity_roundtrip() -> anyhow::Result<()> {
        let metadata: JsonValue = serde_json::from_str(
            r#"{"name":"testdrive1","rootFolderId":"da655f38-98a3-434c-ae27-d995fba3bac3", "some_custom": "value"}"#,
        )?;

        let tags = vec![
            Tag::from((Blob::from("ArFS".as_bytes()), Blob::from("0.15".as_bytes()))),
            Tag::from((
                Blob::from("App-Version".as_bytes()),
                Blob::from("3.0.2".as_bytes()),
            )),
            Tag::from((
                Blob::from("App-Name".as_bytes()),
                Blob::from("ArDrive-CLI".as_bytes()),
            )),
            Tag::from((
                Blob::from("Drive-Privacy".as_bytes()),
                Blob::from("public".as_bytes()),
            )),
            Tag::from((
                Blob::from("Drive-Id".as_bytes()),
                Blob::from("29253cd0-7b5e-4788-bb3b-1786601c8ee0".as_bytes()),
            )),
            Tag::from((
                Blob::from("Unix-Time".as_bytes()),
                Blob::from("1755436510".as_bytes()),
            )),
            Tag::from((
                Blob::from("Entity-Type".as_bytes()),
                Blob::from("drive".as_bytes()),
            )),
            Tag::from((
                Blob::from("Content-Type".as_bytes()),
                Blob::from("application/json".as_bytes()),
            )),
        ];

        let header = Header::<DriveHeader, DriveKind>::try_from(&tags)?;
        let metadata = Metadata::<DriveMetadata, DriveKind>::try_from(metadata)?;
        let drive_entity = DriveEntity::new(header, metadata);

        assert_eq!(
            drive_entity.header().version(),
            &ArFsVersion::from_str("0.15")?
        );

        assert_eq!(drive_entity.header().inner.privacy, Privacy::Public);

        assert_eq!(
            &drive_entity.header().inner.drive_id,
            &DriveId::from_str("29253cd0-7b5e-4788-bb3b-1786601c8ee0")?
        );

        assert_eq!(drive_entity.header().inner.content_type, ContentType::Json);

        assert_eq!(
            &drive_entity.header().inner.time,
            &(DateTime::from_timestamp("1755436510".parse()?, 0).unwrap())
        );

        assert!(drive_entity.header().extra.contains_key("App-Name"));
        assert!(drive_entity.header().extra.contains_key("App-Version"));

        assert_eq!(drive_entity.metadata().inner.name, "testdrive1");
        assert_eq!(
            &drive_entity.metadata().inner.root_folder_id,
            &FolderId::from_str("da655f38-98a3-434c-ae27-d995fba3bac3")?
        );

        assert!(drive_entity.metadata().extra.contains_key("some_custom"));

        // roundtrip testing

        let tags2: Vec<Tag<'_>> = drive_entity.header().try_into()?;

        let header2 = Header::<DriveHeader, DriveKind>::try_from(&tags2)?;
        let tags3: Vec<Tag<'_>> = (&header2).try_into()?;

        assert_eq!(drive_entity.header(), &header2);

        Ok(())
    }

    #[derive(cynic::QueryVariables, Debug)]
    pub struct TxByIdQueryVariables<'a> {
        pub tx_id: &'a cynic::Id,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(graphql_type = "Query", variables = "TxByIdQueryVariables")]
    pub struct TxByIdQuery {
        #[arguments(id: $tx_id)]
        pub transaction: Option<Transaction>,
    }

    #[derive(cynic::QueryFragment, Debug)]
    pub struct Transaction {
        pub id: cynic::Id,
    }

    #[tokio::test]
    async fn foo() -> anyhow::Result<()> {
        init_tracing();

        let client = Client::builder()
            .gateways([Gateway::default()])
            .enable_netwatch(false)
            .build();

        let resp: Option<TxByIdQuery> = client
            .graphql_query(TxByIdQueryVariables {
                tx_id: (&"G-1t0Lqysin897HC3IV8xu_Mr884B-Mo5YEnlhUH54k".to_string()).into(),
            })
            .await?;

        let x = resp.unwrap().transaction.unwrap().id;
        println!("");
        Ok(())
    }
}
