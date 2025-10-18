use crate::types::drive::DriveId;
use crate::types::folder::FolderId;
use crate::types::{
    ArfsEntity, ArfsEntityId, BytesToStr, Chain, Cipher, DisplayFromStr, Entity, HasContentType,
    HasDriveId, HasId, HasName, HasTimestamp, HasVisibility, MaybeHasCipher, Model, TaggedId,
    TimestampMilliSeconds, TimestampSeconds, ToFromStr, Visibility, bool_false,
};
use crate::{ContentType, Timestamp};
use ario_client::RawItemId;
use ario_client::location::Arl;
use ario_core::blob::{Blob, OwnedBlob};
use ario_core::wallet::WalletAddress;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{serde_as, skip_serializing_none};
use uuid::Uuid;

pub struct FileKind;
pub type FileId = TaggedId<Uuid, FileKind>;

impl Entity for FileKind {
    const TYPE: &'static str = "file";
    type Header = FileHeader;
    type Metadata = FileMetadata;
    type Extra = FileExtra;
}

impl HasId for FileKind {
    const NAME: &'static str = "File-Id";

    type Id = FileId;

    fn id(entity: &Model<Self>) -> &Self::Id
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.file_id
    }
}

impl From<FileId> for ArfsEntityId {
    fn from(value: FileId) -> Self {
        Self::File(value)
    }
}

impl HasTimestamp for FileKind {
    fn timestamp(entity: &Model<Self>) -> &Timestamp
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.time
    }
}

pub(crate) type FileEntity = Model<FileKind>;

impl HasVisibility for FileKind {
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

impl HasContentType for FileKind {
    fn content_type(entity: &Model<Self>) -> &ContentType
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.content_type
    }
}

impl HasName for FileKind {
    fn name(entity: &Model<Self>) -> &str
    where
        Self: Entity + Sized,
    {
        &entity.metadata.inner.name
    }
}

impl MaybeHasCipher for FileKind {
    fn cipher(entity: &Model<Self>) -> Option<(Cipher, Option<Blob<'_>>)>
    where
        Self: Entity + Sized,
    {
        entity.header.inner.cipher.as_ref().map(|c| {
            (
                *c,
                entity.header.inner.cipher_iv.as_ref().map(|iv| iv.borrow()),
            )
        })
    }
}

impl HasDriveId for FileKind {
    fn drive_id(entity: &Model<Self>) -> &DriveId
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.drive_id
    }
}

impl FileEntity {
    pub fn size(&self) -> u64 {
        self.metadata.inner.size
    }

    pub fn last_modified(&self) -> &Timestamp {
        &self.metadata.inner.last_modified
    }

    pub fn parent_folder(&self) -> &FolderId {
        &self.header.inner.parent_folder_id
    }

    pub(crate) fn raw_data(&self) -> &RawItemId {
        &self.metadata.inner.data_tx_id
    }

    pub fn data_location(&self) -> Option<&Arl> {
        self.extra.data_location.as_ref()
    }

    pub(crate) fn set_data_location(&mut self, arl: Arl) {
        self.extra.data_location = Some(arl);
    }

    pub fn data_content_type(&self) -> &ContentType {
        &self.metadata.inner.content_type
    }

    pub fn pinned_data_owner(&self) -> Option<&WalletAddress> {
        self.metadata.inner.pinned_data_owner.as_ref()
    }
}

impl From<FileEntity> for ArfsEntity {
    fn from(value: FileEntity) -> Self {
        Self::File(value)
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FileHeader {
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Cipher")]
    pub cipher: Option<Cipher>,
    #[serde(rename = "Cipher-IV")]
    pub cipher_iv: Option<OwnedBlob>,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Content-Type")]
    pub content_type: ContentType,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Drive-Id")]
    pub drive_id: DriveId,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "File-Id")]
    pub file_id: FileId,
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Parent-Folder-Id")]
    pub parent_folder_id: FolderId,
    #[serde_as(as = "Chain<(BytesToStr, ToFromStr<i64>, TimestampSeconds)>")]
    #[serde(rename = "Unix-Time")]
    pub time: DateTime<Utc>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FileMetadata {
    pub name: String,
    pub size: u64,
    #[serde_as(as = "TimestampMilliSeconds")]
    #[serde(rename = "lastModifiedDate")]
    pub last_modified: DateTime<Utc>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    #[serde(rename = "dataTxId")]
    pub data_tx_id: RawItemId,
    #[serde_as(as = "DisplayFromStr")]
    #[serde(rename = "dataContentType")]
    pub content_type: ContentType,
    #[serde(rename = "isHidden", default = "bool_false")]
    pub hidden: bool,
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(rename = "pinnedDataOwner")]
    pub pinned_data_owner: Option<WalletAddress>,
}

pub(crate) struct FileExtra {
    data_location: Option<Arl>,
}

impl Default for FileExtra {
    fn default() -> Self {
        Self {
            data_location: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::types::drive::DriveId;
    use crate::types::file::{FileEntity, FileHeader, FileId, FileKind, FileMetadata};
    use crate::types::folder::FolderId;
    use crate::types::{Header, Metadata};
    use crate::{ArFsVersion, ContentType};
    use ario_client::location::Arl;
    use ario_core::blob::Blob;
    use ario_core::tag::Tag;
    use ario_core::tx::TxId;
    use ario_core::wallet::WalletAddress;
    use ario_core::{BlockNumber, JsonValue};
    use chrono::DateTime;
    use std::str::FromStr;

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
        let file_entity = FileEntity::new(
            header,
            metadata,
            BlockNumber::from_inner(1),
            Arl::from_str("ar://Y0wJvUkHFhcJZAduC8wfaiaDMHkrCoqHMSkenHD75VU").unwrap(),
        );

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
            file_entity.metadata.inner.data_tx_id.as_slice(),
            TxId::from_str("0AYIaLLvU794EoxFsJzAGZ5l_24JvdHfmECvQHgKqok")?.as_slice()
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
}
