use crate::types::drive::{DriveEntity, DriveHeader, DriveId, DriveKind};
use crate::types::folder::{FolderEntity, FolderId, FolderKind};
use crate::types::{AuthMode, Entity, HasId, Header, Metadata, Model, ParseError};
use crate::{EntityError, Error, MetadataError, Privacy, Private};

use ario_client::Client;
use ario_client::data_reader::DataReader;
use ario_client::graphql::{
    SortOrder, TagFilter, TxQuery, TxQueryFilterCriteria, TxQueryItem, WithTxResponseFields,
};
use ario_client::location::Arl;
use ario_client::tx::Status as TxStatus;
use ario_core::JsonValue;
use ario_core::tag::Tag;
use ario_core::wallet::WalletAddress;

use futures_lite::{AsyncReadExt, Stream, StreamExt};
use std::fmt::Display;
use std::num::NonZeroUsize;

type TagsOnly = WithTxResponseFields<false, false, false, false, false, false, true, false>;

pub fn find_drive_ids_by_owner<'a>(
    client: &'a Client,
    owner: &'a WalletAddress,
) -> impl Stream<Item = Result<(DriveId, TxQueryItem), Error>> + Unpin + 'a {
    client
        .query_transactions_with_fields::<TagsOnly>(
            TxQuery::builder()
                .filter_criteria(
                    TxQueryFilterCriteria::builder()
                        .owners([owner])
                        .tags([TagFilter::builder()
                            .name("Entity-Type")
                            .values(["drive"])
                            .build()])
                        .build(),
                )
                .sort_order(SortOrder::HeightDescending)
                .build(),
        )
        .map(|r| match r {
            Ok(item) => Ok((to_drive_id(&item)?, item)),
            Err(e) => Err(e.into()),
        })
}

fn to_drive_id(item: &TxQueryItem) -> Result<DriveId, Error> {
    let drive_header =
        Header::<DriveHeader, DriveKind>::try_from(item.tags()).map_err(EntityError::ParseError)?;
    Ok(drive_header.into_inner().drive_id)
}

pub async fn find_drive_by_id_owner<'a>(
    client: &'a Client,
    drive_id: &'a DriveId,
    owner: &'a WalletAddress,
) -> Result<(DriveId, TxQueryItem), Error> {
    client
        .query_transactions_with_fields::<TagsOnly>(
            TxQuery::builder()
                .filter_criteria(
                    TxQueryFilterCriteria::builder()
                        .owners([owner])
                        .tags([
                            TagFilter::builder()
                                .name("Entity-Type")
                                .values(["drive"])
                                .build(),
                            TagFilter::builder()
                                .name("Drive-Id")
                                .values([drive_id.to_string()])
                                .build(),
                        ])
                        .build(),
                )
                .sort_order(SortOrder::HeightDescending)
                .max_results(NonZeroUsize::try_from(1).unwrap())
                .build(),
        )
        .map(|r| match r {
            Ok(item) => Ok((to_drive_id(&item)?, item)),
            Err(e) => Err(Error::from(e)),
        })
        .try_next()
        .await?
        .ok_or(
            EntityError::NotFound {
                entity_type: "drive",
                details: drive_id.to_string(),
            }
            .into(),
        )
}

pub async fn find_entity_location_by_id_drive<'a, E: Entity + HasId>(
    client: &'a Client,
    id: &E::Id,
    drive_id: &'a DriveId,
) -> Result<Arl, Error>
where
    <E as HasId>::Id: Display,
{
    let item = client
        .query_transactions_with_fields::<TagsOnly>(
            TxQuery::builder()
                .filter_criteria(
                    TxQueryFilterCriteria::builder()
                        .tags([
                            TagFilter::builder()
                                .name("Entity-Type")
                                .values([E::TYPE])
                                .build(),
                            TagFilter::builder()
                                .name("Folder-Id")
                                .values([id.to_string()])
                                .build(),
                            TagFilter::builder()
                                .name("Drive-Id")
                                .values([drive_id.to_string()])
                                .build(),
                        ])
                        .build(),
                )
                .sort_order(SortOrder::HeightDescending)
                .max_results(NonZeroUsize::try_from(1).unwrap())
                .build(),
        )
        .try_next()
        .await?
        .ok_or(EntityError::NotFound {
            entity_type: E::TYPE,
            details: id.to_string(),
        })?;
    client
        .location_by_item_id(&item.id())
        .await
        .map_err(|e| e.into())
}

pub async fn folder_entity(
    folder_id: &FolderId,
    client: &Client,
    location: &Arl,
    drive_id: &DriveId,
    owner: &WalletAddress,
    private: Option<&Private>,
) -> Result<FolderEntity, Error> {
    let folder_entity =
        read_entity::<FolderKind, 1024>(client, location, drive_id, owner, private).await?;
    if folder_entity.id() != folder_id {
        Err(EntityError::FolderMismatch {
            expected: folder_id.clone(),
            actual: folder_entity.id().clone(),
        })?;
    }
    if folder_entity.drive_id() != drive_id {
        Err(EntityError::DriveMismatch {
            expected: drive_id.clone(),
            actual: folder_entity.drive_id().clone(),
        })?;
    }
    Ok(folder_entity)
}

async fn read_entity<E: Entity, const MAX_METADATA_LEN: usize>(
    client: &Client,
    location: &Arl,
    drive_id: &DriveId,
    owner: &WalletAddress,
    private: Option<&Private>,
) -> Result<Model<E>, Error>
where
    Header<<E as Entity>::Header, E>: for<'a> TryFrom<&'a Vec<Tag<'a>>, Error = ParseError>,
    Metadata<<E as Entity>::Metadata, E>: TryFrom<JsonValue, Error = ParseError>,
{
    if let Some(address) = private.map(|p| p.wallet.address()) {
        if &address != owner {
            Err(EntityError::OwnerMismatch {
                expected: address,
                actual: owner.clone(),
            })?;
        }
    }

    let block_height = match client.tx_status(location.tx_id()).await? {
        Some(TxStatus::Accepted(accepted)) => accepted.block_height,
        _ => Err(EntityError::InvalidTxStatus(location.tx_id().clone()))?,
    };

    let mut reader = client.read_any(location.clone()).await?;
    let item = reader.item();

    if &item.owner() != owner {
        Err(EntityError::OwnerMismatch {
            expected: owner.clone(),
            actual: item.owner(),
        })?;
    }

    if reader.len() > MAX_METADATA_LEN as u64 {
        Err(EntityError::from(MetadataError::MaxLengthExceeded {
            max: MAX_METADATA_LEN,
            actual: reader.len() as usize,
        }))?;
    }

    let mut buf = vec![0u8; reader.len() as usize];
    reader.read_exact(&mut buf).await?;
    drop(reader);
    let metadata: JsonValue =
        serde_json::from_slice(buf.as_slice()).map_err(|e| EntityError::MetadataError(e.into()))?;

    let header = Header::<E::Header, E>::try_from(item.tags()).map_err(EntityError::from)?;

    let metadata = Metadata::<E::Metadata, E>::try_from(metadata).map_err(EntityError::from)?;

    Ok(Model::new(header, metadata, block_height, location.clone()))
}

pub async fn drive_entity(
    client: &Client,
    drive_id: &DriveId,
    location: &Arl,
    owner: &WalletAddress,
    private: Option<&Private>,
) -> Result<DriveEntity, Error> {
    let drive_entity =
        read_entity::<DriveKind, { 1024 * 1024 }>(client, location, drive_id, owner, private)
            .await?;

    let privacy = private.map(|_| Privacy::Private).unwrap_or(Privacy::Public);
    if drive_entity.header().as_inner().privacy != privacy {
        Err(EntityError::PrivacyMismatch {
            expected: privacy,
            actual: drive_entity.header().as_inner().privacy,
        })?;
    }

    let auth_mode = private.map(|p| AuthMode::from(&p.auth));
    if drive_entity.header().as_inner().auth_mode != auth_mode {
        Err(EntityError::AuthModeMismatch {
            expected: auth_mode
                .map(|a| a.to_string())
                .unwrap_or("None".to_string()),
            actual: drive_entity
                .header()
                .as_inner()
                .auth_mode
                .map(|a| a.to_string())
                .unwrap_or("None".to_string()),
        })?;
    }

    Ok(drive_entity)
}
