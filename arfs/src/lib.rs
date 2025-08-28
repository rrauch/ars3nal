pub(crate) mod serde_tag;

use crate::serde_tag::BytesToStr;
use crate::serde_tag::Chain;
use crate::serde_tag::ToFromStr;
use ario_core::base64::Base64Error;
use ario_core::blob::OwnedBlob;
use ario_core::tag::Tag;
use ario_core::tx::TxId;
use ario_core::wallet::WalletAddress;
use ario_core::{BlockNumber, JsonValue};
use chrono::{DateTime, Utc};
use derive_where::derive_where;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_with::TimestampMilliSeconds;
use serde_with::TimestampSeconds;
use serde_with::serde_as;
use serde_with::{DisplayFromStr, skip_serializing_none};
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

struct Model<E: Entity> {
    header: Header<E::Header, E>,
    metadata: Metadata<E::Metadata, E>,
    _marker: PhantomData<E>,
}

trait Entity {
    const TYPE: &'static str;

    type Header;
    type Metadata;
}

trait Encryptable {
    type EncryptionKey;
    type DecryptionKey;
    type Error: Display + Send;

    type Ciphertext;
    type Plaintext;
}

trait EncryptExt<E: Encryptable> {
    fn encrypt(&self, key: &E::EncryptionKey) -> Result<E::Ciphertext, E::Error>;
}

impl<E: Encryptable> EncryptExt<E> for E::Plaintext {
    fn encrypt(&self, key: &E::EncryptionKey) -> Result<E::Ciphertext, E::Error> {
        todo!()
    }
}

trait DecryptExt<K, P, E> {
    fn decrypt(&self, key: &K) -> Result<P, E>;
}

impl<E: Entity> Model<E> {
    fn new(header: Header<E::Header, E>, metadata: Metadata<E::Metadata, E>) -> Self {
        Self {
            header,
            metadata,
            _marker: PhantomData,
        }
    }

    pub(crate) fn header(&self) -> &Header<E::Header, E> {
        &self.header
    }

    pub(crate) fn metadata(&self) -> &Metadata<E::Metadata, E> {
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

impl<Tag> Metadata<(), Tag> {
    fn none() -> Self {
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

pub struct DriveKind;
pub type DriveId = TaggedId<Uuid, DriveKind>;

impl Entity for DriveKind {
    const TYPE: &'static str = "drive";
    type Header = DriveHeader;
    type Metadata = DriveMetadata;
}

type DriveEntity = Model<DriveKind>;

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DriveHeader {
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Cipher")]
    cipher: Option<Cipher>,
    #[serde(rename = "Cipher-IV")]
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
    #[serde(default, rename = "Drive-Auth-Mode")]
    auth_mode: Option<AuthMode>,
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Signature-Type")]
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

pub struct DriveSignatureKind;

impl Entity for DriveSignatureKind {
    const TYPE: &'static str = "drive-signature";
    type Header = DriveSignatureHeader;
    type Metadata = ();
}

type DriveSignatureEntity = Model<DriveSignatureKind>;

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DriveSignatureHeader {
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Signature-Format")]
    signature_format: SignatureFormat,
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Cipher")]
    cipher: Option<Cipher>,
    #[serde(rename = "Cipher-IV")]
    cipher_iv: OwnedBlob,
    //data: Blob<'a>,
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

impl Entity for FolderKind {
    const TYPE: &'static str = "folder";
    type Header = FolderHeader;
    //type Metadata = Encryptable<OwnedBlob, FolderMetadata>;
    type Metadata = FolderMetadata;
}

type FolderEntity = Model<FolderKind>;

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FolderHeader {
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Cipher")]
    cipher: Option<Cipher>,
    #[serde(rename = "Cipher-IV")]
    cipher_iv: Option<OwnedBlob>,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Content-Type")]
    content_type: ContentType,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Drive-Id")]
    drive_id: DriveId,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Folder-Id")]
    folder_id: FolderId,
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(rename = "Parent-Folder-Id")]
    parent_folder_id: Option<FolderId>,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<i64>, TimestampSeconds)>")]
    #[serde(rename = "Unix-Time")]
    time: DateTime<Utc>,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FolderMetadata {
    name: String,
    #[serde(rename = "isHidden", default = "bool_false")]
    hidden: bool,
}

fn bool_false() -> bool {
    false
}

pub struct FileKind;
pub type FileId = TaggedId<Uuid, FileKind>;

impl Entity for FileKind {
    const TYPE: &'static str = "file";
    type Header = FileHeader;
    //type Metadata = Encryptable<OwnedBlob, FileMetadata>;
    type Metadata = FileMetadata;
}

type FileEntity = Model<FileKind>;

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FileHeader {
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Cipher")]
    cipher: Option<Cipher>,
    #[serde(rename = "Cipher-IV")]
    cipher_iv: Option<OwnedBlob>,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Content-Type")]
    content_type: ContentType,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Drive-Id")]
    drive_id: DriveId,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "File-Id")]
    file_id: FileId,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Parent-Folder-Id")]
    parent_folder_id: FolderId,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<i64>, TimestampSeconds)>")]
    #[serde(rename = "Unix-Time")]
    time: DateTime<Utc>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FileMetadata {
    name: String,
    size: u64,
    #[serde_as(as = "TimestampMilliSeconds")]
    #[serde(rename = "lastModifiedDate")]
    last_modified: DateTime<Utc>,
    #[serde_as(as = "DisplayFromStr")]
    #[serde(rename = "dataTxId")]
    data_tx_id: TxId,
    #[serde_as(as = "DisplayFromStr")]
    #[serde(rename = "dataContentType")]
    content_type: ContentType,
    #[serde(rename = "isHidden", default = "bool_false")]
    hidden: bool,
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(rename = "pinnedDataOwner")]
    pinned_data_owner: Option<WalletAddress>,
}

pub struct SnapshotKind;
pub type SnapshotId = TaggedId<Uuid, SnapshotKind>;

impl Entity for SnapshotKind {
    const TYPE: &'static str = "snapshot";
    type Header = SnapshotHeader;
    type Metadata = ();
}

type SnapshotEntity = Model<SnapshotKind>;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SnapshotHeader {
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Drive-Id")]
    drive_id: DriveId,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Snapshot-Id")]
    snapshot_id: SnapshotId,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Content-Type")]
    content_type: ContentType,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<u64>, _)>")]
    #[serde(rename = "Block-Start")]
    block_start: BlockNumber,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<u64>, _)>")]
    #[serde(rename = "Block-End")]
    block_end: BlockNumber,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<u64>, _)>")]
    #[serde(rename = "Data-Start")]
    data_start: BlockNumber,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<u64>, _)>")]
    #[serde(rename = "Data-End")]
    data_end: BlockNumber,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<i64>, TimestampSeconds)>")]
    #[serde(rename = "Unix-Time")]
    time: DateTime<Utc>,
}

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
        ArFsVersion, Cipher, ContentType, DriveEntity, DriveHeader, DriveId, DriveKind,
        DriveMetadata, DriveSignatureEntity, DriveSignatureHeader, DriveSignatureKind, FileEntity,
        FileHeader, FileId, FileKind, FileMetadata, FolderEntity, FolderHeader, FolderId,
        FolderKind, FolderMetadata, Header, Metadata, Privacy, SignatureFormat, SnapshotEntity,
        SnapshotHeader, SnapshotId, SnapshotKind,
    };
    use ario_client::Client;
    use ario_client::graphql::cynic;
    use ario_client::graphql::schema;
    use ario_core::blob::Blob;
    use ario_core::tag::Tag;
    use ario_core::tx::TxId;
    use ario_core::wallet::WalletAddress;
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
        let _tags3: Vec<Tag<'_>> = (&header2).try_into()?;

        assert_eq!(drive_entity.header(), &header2);

        Ok(())
    }

    #[test]
    fn drive_signature_entity_roundtrip() -> anyhow::Result<()> {
        let tags = vec![
            Tag::from((Blob::from("ArFS".as_bytes()), Blob::from("0.15".as_bytes()))),
            Tag::from((
                Blob::from("Signature-Format".as_bytes()),
                Blob::from("1".as_bytes()),
            )),
            Tag::from((
                Blob::from("Cipher".as_bytes()),
                Blob::from("AES256-GCM".as_bytes()),
            )),
            Tag::from((
                Blob::from("Cipher-IV".as_bytes()),
                Blob::from("todo".as_bytes()),
            )),
            Tag::from((
                Blob::from("Entity-Type".as_bytes()),
                Blob::from("drive-signature".as_bytes()),
            )),
        ];

        let header = Header::<DriveSignatureHeader, DriveSignatureKind>::try_from(&tags)?;
        let sig_entity = DriveSignatureEntity::new(header, Metadata::none());

        assert_eq!(
            sig_entity.header().version(),
            &ArFsVersion::from_str("0.15")?
        );

        assert_eq!(
            sig_entity.header().inner.signature_format,
            SignatureFormat::V1
        );
        assert_eq!(sig_entity.header().inner.cipher, Some(Cipher::Aes256Gcm));
        //todo: check iv && data

        // roundtrip testing

        let tags2: Vec<Tag<'_>> = sig_entity.header().try_into()?;

        let header2 = Header::<DriveSignatureHeader, DriveSignatureKind>::try_from(&tags2)?;
        let _tags3: Vec<Tag<'_>> = (&header2).try_into()?;

        assert_eq!(sig_entity.header(), &header2);

        Ok(())
    }

    #[test]
    fn folder_entity_roundtrip() -> anyhow::Result<()> {
        let metadata: JsonValue =
            serde_json::from_str(r#"{"name":"folder1","isHidden": false, "some": "extra"}"#)?;

        let tags = vec![
            Tag::from((Blob::from("ArFS".as_bytes()), Blob::from("0.15".as_bytes()))),
            Tag::from((
                Blob::from("Drive-Id".as_bytes()),
                Blob::from("29253cd0-7b5e-4788-bb3b-1786601c8ee0".as_bytes()),
            )),
            Tag::from((
                Blob::from("Folder-Id".as_bytes()),
                Blob::from("19253cd0-7b5e-4788-bb3b-1786601c8ee0".as_bytes()),
            )),
            Tag::from((
                Blob::from("Unix-Time".as_bytes()),
                Blob::from("1755436511".as_bytes()),
            )),
            Tag::from((
                Blob::from("Entity-Type".as_bytes()),
                Blob::from("folder".as_bytes()),
            )),
            Tag::from((
                Blob::from("Content-Type".as_bytes()),
                Blob::from("application/json".as_bytes()),
            )),
        ];

        let header = Header::<FolderHeader, FolderKind>::try_from(&tags)?;
        let metadata = Metadata::<FolderMetadata, FolderKind>::try_from(metadata)?;
        let folder_entity = FolderEntity::new(header, metadata);

        assert_eq!(
            folder_entity.header().version(),
            &ArFsVersion::from_str("0.15")?
        );

        assert_eq!(
            &folder_entity.header().inner.drive_id,
            &DriveId::from_str("29253cd0-7b5e-4788-bb3b-1786601c8ee0")?
        );

        assert_eq!(
            &folder_entity.header().inner.folder_id,
            &FolderId::from_str("19253cd0-7b5e-4788-bb3b-1786601c8ee0")?
        );

        assert_eq!(folder_entity.header().inner.content_type, ContentType::Json);

        assert_eq!(
            &folder_entity.header().inner.time,
            &(DateTime::from_timestamp("1755436511".parse()?, 0).unwrap())
        );

        assert_eq!(folder_entity.metadata().inner.name, "folder1");
        assert_eq!(folder_entity.metadata().inner.hidden, false);

        assert!(folder_entity.metadata().extra.contains_key("some"));

        // roundtrip testing

        let tags2: Vec<Tag<'_>> = folder_entity.header().try_into()?;

        let header2 = Header::<FolderHeader, FolderKind>::try_from(&tags2)?;
        let _tags3: Vec<Tag<'_>> = (&header2).try_into()?;

        assert_eq!(folder_entity.header(), &header2);

        Ok(())
    }

    #[test]
    fn file_entity_roundtrip() -> anyhow::Result<()> {
        let metadata: JsonValue = serde_json::from_str(
            r#"{
    "name": "filename.jpg",
    "size": 12345,
    "lastModifiedDate": 1755685342863,
    "dataTxId": "0AYIaLLvU794EoxFsJzAGZ5l_24JvdHfmECvQHgKqok",
    "dataContentType": "image/jpeg",
    "isHidden": false,
    "pinnedDataOwner": "JNC6vBhjHY1EPwV3pEeNmrsgFMxH5d38_LHsZ7jful8"
}"#,
        )?;

        let tags = vec![
            Tag::from((Blob::from("ArFS".as_bytes()), Blob::from("0.15".as_bytes()))),
            Tag::from((
                Blob::from("Drive-Id".as_bytes()),
                Blob::from("29253cd0-7b5e-4788-bb3b-1786601c8ee0".as_bytes()),
            )),
            Tag::from((
                Blob::from("Parent-Folder-Id".as_bytes()),
                Blob::from("19253cd0-7b5e-4788-bb3b-1786601c8ee0".as_bytes()),
            )),
            Tag::from((
                Blob::from("Unix-Time".as_bytes()),
                Blob::from("1755436511".as_bytes()),
            )),
            Tag::from((
                Blob::from("File-Id".as_bytes()),
                Blob::from("39253cd0-7b5e-4788-bb3b-1786601c8ee0".as_bytes()),
            )),
            Tag::from((
                Blob::from("Entity-Type".as_bytes()),
                Blob::from("file".as_bytes()),
            )),
            Tag::from((
                Blob::from("Content-Type".as_bytes()),
                Blob::from("application/json".as_bytes()),
            )),
        ];

        let header = Header::<FileHeader, FileKind>::try_from(&tags)?;
        let metadata = Metadata::<FileMetadata, FileKind>::try_from(metadata)?;
        let file_entity = FileEntity::new(header, metadata);

        assert_eq!(
            file_entity.header().version(),
            &ArFsVersion::from_str("0.15")?
        );

        assert_eq!(
            &file_entity.header().inner.drive_id,
            &DriveId::from_str("29253cd0-7b5e-4788-bb3b-1786601c8ee0")?
        );

        assert_eq!(
            &file_entity.header().inner.parent_folder_id,
            &FolderId::from_str("19253cd0-7b5e-4788-bb3b-1786601c8ee0")?
        );

        assert_eq!(
            &file_entity.header().inner.file_id,
            &FileId::from_str("39253cd0-7b5e-4788-bb3b-1786601c8ee0")?
        );

        assert_eq!(file_entity.header().inner.content_type, ContentType::Json);

        assert_eq!(
            &file_entity.header().inner.time,
            &(DateTime::from_timestamp("1755436511".parse()?, 0).unwrap())
        );

        assert_eq!(file_entity.metadata().inner.name, "filename.jpg");
        assert_eq!(file_entity.metadata().inner.hidden, false);
        assert_eq!(file_entity.metadata().inner.size, 12345);
        assert_eq!(
            &file_entity.metadata().inner.last_modified,
            &(DateTime::from_timestamp_millis(1755685342863).unwrap())
        );
        assert_eq!(
            &file_entity.metadata.inner.data_tx_id,
            &TxId::from_str("0AYIaLLvU794EoxFsJzAGZ5l_24JvdHfmECvQHgKqok")?
        );
        assert_eq!(
            &file_entity.metadata.inner.content_type,
            &ContentType::Other("image/jpeg".to_string())
        );
        assert_eq!(
            file_entity.metadata.inner.pinned_data_owner.as_ref(),
            Some(&WalletAddress::from_str(
                "JNC6vBhjHY1EPwV3pEeNmrsgFMxH5d38_LHsZ7jful8"
            )?)
        );

        // roundtrip testing

        let tags2: Vec<Tag<'_>> = file_entity.header().try_into()?;

        let header2 = Header::<FileHeader, FileKind>::try_from(&tags2)?;
        let _tags3: Vec<Tag<'_>> = (&header2).try_into()?;

        assert_eq!(file_entity.header(), &header2);

        Ok(())
    }

    #[test]
    fn snapshot_entity_roundtrip() -> anyhow::Result<()> {
        let tags = vec![
            Tag::from((Blob::from("ArFS".as_bytes()), Blob::from("0.15".as_bytes()))),
            Tag::from((
                Blob::from("Drive-Id".as_bytes()),
                Blob::from("29253cd0-7b5e-4788-bb3b-1786601c8ee0".as_bytes()),
            )),
            Tag::from((
                Blob::from("Unix-Time".as_bytes()),
                Blob::from("1755436511".as_bytes()),
            )),
            Tag::from((
                Blob::from("Snapshot-Id".as_bytes()),
                Blob::from("49253cd0-7b5e-4788-bb3b-1786601c8ee0".as_bytes()),
            )),
            Tag::from((
                Blob::from("Entity-Type".as_bytes()),
                Blob::from("snapshot".as_bytes()),
            )),
            Tag::from((
                Blob::from("Content-Type".as_bytes()),
                Blob::from("application/json".as_bytes()),
            )),
            Tag::from((
                Blob::from("Block-Start".as_bytes()),
                Blob::from("1111".as_bytes()),
            )),
            Tag::from((
                Blob::from("Block-End".as_bytes()),
                Blob::from("111123".as_bytes()),
            )),
            Tag::from((
                Blob::from("Data-Start".as_bytes()),
                Blob::from("21111".as_bytes()),
            )),
            Tag::from((
                Blob::from("Data-End".as_bytes()),
                Blob::from("2111123".as_bytes()),
            )),
        ];

        let header = Header::<SnapshotHeader, SnapshotKind>::try_from(&tags)?;
        let snapshot_entity = SnapshotEntity::new(header, Metadata::none());

        assert_eq!(
            snapshot_entity.header().version(),
            &ArFsVersion::from_str("0.15")?
        );

        assert_eq!(
            &snapshot_entity.header().inner.drive_id,
            &DriveId::from_str("29253cd0-7b5e-4788-bb3b-1786601c8ee0")?
        );

        assert_eq!(
            &snapshot_entity.header().inner.snapshot_id,
            &SnapshotId::from_str("49253cd0-7b5e-4788-bb3b-1786601c8ee0")?
        );

        assert_eq!(
            snapshot_entity.header().inner.content_type,
            ContentType::Json
        );

        assert_eq!(
            &snapshot_entity.header().inner.time,
            &(DateTime::from_timestamp("1755436511".parse()?, 0).unwrap())
        );

        assert_eq!(*snapshot_entity.header().inner.block_start, 1111);
        assert_eq!(*snapshot_entity.header().inner.block_end, 111123);
        assert_eq!(*snapshot_entity.header().inner.data_start, 21111);
        assert_eq!(*snapshot_entity.header().inner.data_end, 2111123);

        // roundtrip testing

        let tags2: Vec<Tag<'_>> = snapshot_entity.header().try_into()?;

        let header2 = Header::<SnapshotHeader, SnapshotKind>::try_from(&tags2)?;
        let _tags3: Vec<Tag<'_>> = (&header2).try_into()?;

        assert_eq!(snapshot_entity.header(), &header2);

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

    #[ignore]
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
