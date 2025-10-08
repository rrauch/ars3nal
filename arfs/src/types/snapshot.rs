use crate::types::drive::DriveId;
use crate::types::{
    BytesToStr, Chain, DisplayFromStr, Entity, HasContentType, HasDriveId, HasId, HasTimestamp,
    Model, TaggedId, TimestampSeconds, ToFromStr,
};
use crate::{ContentType, Timestamp};
use ario_core::BlockNumber;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use uuid::Uuid;

pub struct SnapshotKind;
pub type SnapshotId = TaggedId<Uuid, SnapshotKind>;

impl Entity for SnapshotKind {
    const TYPE: &'static str = "snapshot";
    type Header = SnapshotHeader;
    type Metadata = ();
}

impl HasId for SnapshotKind {
    type Id = SnapshotId;

    fn id(entity: &Model<Self>) -> &Self::Id
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.snapshot_id
    }
}

impl HasTimestamp for SnapshotKind {
    fn timestamp(entity: &Model<Self>) -> &Timestamp
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.time
    }
}

impl HasContentType for SnapshotKind {
    fn content_type(entity: &Model<Self>) -> &ContentType
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.content_type
    }
}

impl HasDriveId for SnapshotKind {
    fn drive_id(entity: &Model<Self>) -> &DriveId
    where
        Self: Entity + Sized,
    {
        &entity.header.inner.drive_id
    }
}

pub(crate) type SnapshotEntity = Model<SnapshotKind>;

impl SnapshotEntity {
    pub fn block_start(&self) -> BlockNumber {
        self.header.inner.block_start
    }

    pub fn block_end(&self) -> BlockNumber {
        self.header.inner.block_end
    }

    pub fn data_start(&self) -> BlockNumber {
        self.header.inner.data_start
    }

    pub fn data_end(&self) -> BlockNumber {
        self.header.inner.data_end
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SnapshotHeader {
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

#[cfg(test)]
mod tests {
    use crate::types::drive::DriveId;
    use crate::types::snapshot::{SnapshotEntity, SnapshotHeader, SnapshotId, SnapshotKind};
    use crate::types::{Header, Metadata};
    use crate::{ArFsVersion, ContentType};
    use ario_core::BlockNumber;
    use ario_core::blob::Blob;
    use ario_core::tag::Tag;
    use chrono::DateTime;
    use std::str::FromStr;
    use ario_client::location::Arl;

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
        let snapshot_entity = SnapshotEntity::new(
            header,
            Metadata::none(),
            BlockNumber::from_inner(1),
            Arl::from_str("ar://Y0wJvUkHFhcJZAduC8wfaiaDMHkrCoqHMSkenHD75VU").unwrap(),
        );

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
}
