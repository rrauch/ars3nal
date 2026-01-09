use crate::types::drive::DriveId;
use crate::types::{
    ArfsEntity, ArfsEntityId, BytesToStr, Chain, Cipher, DisplayFromStr, Entity, HasContentType,
    HasDriveId, HasId, HasName, HasTimestamp, HasVisibility, MaybeHasCipher, Model, TaggedId,
    TimestampSeconds, ToFromStr, Visibility, bool_false,
};
use crate::{ContentType, Timestamp};
use ario_core::blob::{Blob, OwnedBlob};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{serde_as, skip_serializing_none};
use uuid::Uuid;

#[derive(Debug, PartialEq, Clone)]
pub struct FolderKind;
pub type FolderId = TaggedId<Uuid, FolderKind>;

impl Entity for FolderKind {
    const TYPE: &'static str = "folder";
    type Header = FolderHeader;
    type Metadata = FolderMetadata;
    type Extra = ();
    type MetadataCryptor<'a> = ();
}

impl HasId for FolderKind {
    const NAME: &'static str = "Folder-Id";
    type Id = FolderId;

    fn id(entity: &Model<Self>) -> &Self::Id
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.folder_id
    }
}

impl From<FolderId> for ArfsEntityId {
    fn from(value: FolderId) -> Self {
        Self::Folder(value)
    }
}

impl HasTimestamp for FolderKind {
    fn timestamp(entity: &Model<Self>) -> &Timestamp
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.time
    }
}

impl HasVisibility for FolderKind {
    fn visibility(entity: &Model<Self>) -> Visibility
    where
        Self: Entity + Sized,
    {
        if entity.metadata.inner.hidden {
            Visibility::Hidden
        } else {
            Visibility::Visible
        }
    }
}

impl HasContentType for FolderKind {
    fn content_type(entity: &Model<Self>) -> &ContentType
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.content_type
    }
}

impl HasName for FolderKind {
    fn name(entity: &Model<Self>) -> &str
    where
        Self: Entity + Sized,
    {
        &entity.metadata.inner.name
    }
}

impl HasDriveId for FolderKind {
    fn drive_id(entity: &Model<Self>) -> &DriveId
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.drive_id
    }
}

pub(crate) type FolderEntity = Model<FolderKind>;

impl FolderEntity {
    pub fn parent_folder(&self) -> Option<&FolderId> {
        self.header().as_inner().parent_folder_id.as_ref()
    }
}

impl From<FolderEntity> for ArfsEntity {
    fn from(value: FolderEntity) -> Self {
        Self::Folder(value)
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FolderHeader {
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
    #[serde(rename = "Folder-Id")]
    pub folder_id: FolderId,
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(rename = "Parent-Folder-Id")]
    pub parent_folder_id: Option<FolderId>,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<i64>, TimestampSeconds)>")]
    #[serde(rename = "Unix-Time")]
    pub time: DateTime<Utc>,
}

impl MaybeHasCipher for FolderHeader {
    fn cipher(&self) -> Option<(Cipher, Option<Blob<'_>>)> {
        self.cipher
            .as_ref()
            .map(|c| (*c, self.cipher_iv.as_ref().map(|b| b.borrow())))
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FolderMetadata {
    pub name: String,
    #[serde(rename = "isHidden", default = "bool_false")]
    pub hidden: bool,
}

#[cfg(test)]
mod tests {
    use crate::types::drive::DriveId;
    use crate::types::folder::{FolderEntity, FolderHeader, FolderId, FolderKind, FolderMetadata};
    use crate::types::{Header, Metadata};
    use crate::{ArFsVersion, ContentType};
    use ario_client::location::Arl;
    use ario_core::blob::Blob;
    use ario_core::tag::Tag;
    use ario_core::{BlockNumber, JsonValue};
    use chrono::DateTime;
    use std::str::FromStr;

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
        let folder_entity = FolderEntity::new(
            header,
            metadata,
            BlockNumber::from_inner(1),
            Arl::from_str("ar://Y0wJvUkHFhcJZAduC8wfaiaDMHkrCoqHMSkenHD75VU").unwrap(),
        );

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
}
