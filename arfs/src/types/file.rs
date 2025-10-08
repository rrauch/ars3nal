use crate::types::drive::DriveId;
use crate::types::folder::FolderId;
use crate::types::{
    BytesToStr, Chain, Cipher, DisplayFromStr, Entity, HasContentType, HasDriveId, HasId, HasName,
    HasTimestamp, HasVisibility, MaybeHasCipher, Model, TaggedId, TimestampMilliSeconds,
    TimestampSeconds, ToFromStr, Visibility, bool_false,
};
use crate::{ContentType, Timestamp};
use ario_core::blob::{Blob, OwnedBlob};
use ario_core::tx::TxId;
use ario_core::wallet::WalletAddress;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use uuid::Uuid;

pub struct FileKind;
pub type FileId = TaggedId<Uuid, FileKind>;

impl Entity for FileKind {
    const TYPE: &'static str = "file";
    type Header = FileHeader;
    type Metadata = FileMetadata;
}

impl HasId for FileKind {
    type Id = FileId;

    fn id(entity: &Model<Self>) -> &Self::Id
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.file_id
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

    pub fn data(&self) -> &TxId {
        &self.metadata.inner.data_tx_id
    }

    pub fn data_content_type(&self) -> &ContentType {
        &self.metadata.inner.content_type
    }

    pub fn pinned_data_owner(&self) -> Option<&WalletAddress> {
        self.metadata.inner.pinned_data_owner.as_ref()
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FileHeader {
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
pub(crate) struct FileMetadata {
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

#[cfg(test)]
mod tests {
    use crate::types::drive::DriveId;
    use crate::types::file::{FileEntity, FileHeader, FileId, FileKind, FileMetadata};
    use crate::types::folder::FolderId;
    use crate::types::{Header, Metadata};
    use crate::{ArFsVersion, ContentType};
    use ario_core::blob::Blob;
    use ario_core::tag::Tag;
    use ario_core::tx::TxId;
    use ario_core::wallet::WalletAddress;
    use ario_core::{BlockNumber, JsonValue};
    use chrono::DateTime;
    use std::str::FromStr;
    use ario_client::location::Arl;

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
}
