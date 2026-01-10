use crate::crypto::DefaultMetadataCryptor;
use crate::types::folder::FolderId;
use crate::types::{
    ArfsEntity, ArfsEntityId, AuthMode, BytesToStr, Chain, Cipher, DisplayFromStr, Entity,
    HasContentType, HasId, HasName, HasTimestamp, MaybeHasCipher, MetadataCryptor, Model,
    SignatureFormat, TaggedId, TimestampSeconds, ToFromStr,
};
use crate::{ContentType, Privacy, Timestamp};
use ario_core::blob::{Blob, OwnedBlob};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{serde_as, skip_serializing_none};
use uuid::Uuid;

#[derive(Debug)]
pub struct DriveKind;
pub type DriveId = TaggedId<Uuid, DriveKind>;

impl Entity for DriveKind {
    const TYPE: &'static str = "drive";
    type Header = DriveHeader;
    type Metadata = DriveMetadata;
    type Extra = ();
    type MetadataCryptor<'a> = DefaultMetadataCryptor;

    fn maybe_metadata_cryptor(
        header: &Self::Header,
    ) -> Option<
        Result<
            Self::MetadataCryptor<'_>,
            <Self::MetadataCryptor<'_> as MetadataCryptor<'_>>::DecryptionError,
        >,
    > {
        header.cipher().map(move |(cipher, iv)| {
            DefaultMetadataCryptor::new(
                cipher,
                iv.as_ref().map(|iv| iv.as_ref()),
                header.signature_type,
            )
        })
    }
}

impl HasId for DriveKind {
    const NAME: &'static str = "Drive-Id";

    type Id = DriveId;

    fn id(entity: &Model<Self>) -> &Self::Id
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.drive_id
    }
}

impl From<DriveId> for ArfsEntityId {
    fn from(value: DriveId) -> Self {
        Self::Drive(value)
    }
}

impl HasTimestamp for DriveKind {
    fn timestamp(entity: &Model<Self>) -> &Timestamp
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.time
    }
}

impl HasContentType for DriveKind {
    fn content_type(entity: &Model<Self>) -> &ContentType
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.content_type
    }
}

impl HasName for DriveKind {
    fn name(entity: &Model<Self>) -> &str
    where
        Self: Entity + Sized,
    {
        &entity.metadata.inner.name
    }
}

pub(crate) type DriveEntity = Model<DriveKind>;

impl DriveEntity {
    pub fn privacy(&self) -> Privacy {
        self.header().as_inner().privacy
    }

    pub fn auth_mode(&self) -> Option<AuthMode> {
        self.header().as_inner().auth_mode
    }

    pub fn root_folder(&self) -> &FolderId {
        &self.metadata().inner.root_folder_id
    }
}

impl From<DriveEntity> for ArfsEntity {
    fn from(value: DriveEntity) -> Self {
        Self::Drive(value)
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct DriveHeader {
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Cipher")]
    pub cipher: Option<Cipher>,
    #[serde_as(as = "Option<Chain<(BytesToStr, Base64<UrlSafe, Unpadded>)>>")]
    #[serde(rename = "Cipher-IV")]
    pub cipher_iv: Option<OwnedBlob>,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Content-Type")]
    pub content_type: ContentType,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Drive-Id")]
    pub drive_id: DriveId,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Drive-Privacy")]
    pub privacy: Privacy,
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Drive-Auth-Mode")]
    pub auth_mode: Option<AuthMode>,
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Signature-Type")]
    pub signature_type: Option<SignatureFormat>,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<i64>, TimestampSeconds)>")]
    #[serde(rename = "Unix-Time")]
    pub time: DateTime<Utc>,
}

impl MaybeHasCipher for DriveHeader {
    fn cipher(&self) -> Option<(Cipher, Option<Blob<'_>>)> {
        self.cipher
            .as_ref()
            .map(|c| (*c, self.cipher_iv.as_ref().map(|b| b.borrow())))
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct DriveMetadata {
    pub name: String,
    #[serde_as(as = "DisplayFromStr")]
    #[serde(rename = "rootFolderId")]
    pub root_folder_id: FolderId,
}

#[cfg(test)]
mod tests {
    use crate::types::drive::{DriveEntity, DriveHeader, DriveId, DriveKind, DriveMetadata};
    use crate::types::folder::FolderId;
    use crate::types::{Header, Metadata};
    use crate::{ArFsVersion, ContentType, Privacy};
    use ario_client::location::Arl;
    use ario_core::blob::Blob;
    use ario_core::tag::Tag;
    use ario_core::{BlockNumber, JsonValue};
    use chrono::DateTime;
    use std::str::FromStr;

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
        let drive_entity = DriveEntity::new(
            header,
            metadata,
            BlockNumber::from_inner(1),
            Arl::from_str("ar://Y0wJvUkHFhcJZAduC8wfaiaDMHkrCoqHMSkenHD75VU").unwrap(),
        );

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
}
