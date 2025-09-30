extern crate core;

pub(crate) mod serde_tag;
mod types;

pub use ario_core::bundle::Owner as BundleOwner;
pub use ario_core::tx::Owner as TxOwner;
use chrono::{DateTime, Utc};
use core::fmt;
use std::fmt::{Display, Formatter};
pub use types::{ArFsVersion, DriveId};

use crate::types::{
    AuthMode, DriveEntity, DriveHeader, DriveKind, DriveMetadata, Entity, Header, Metadata, Privacy,
};
use ario_client::Client;
use ario_client::Error as ClientError;
use ario_client::data_reader::{AsyncBundleItemReader, AsyncTxReader};
use ario_client::graphql::{
    ItemId, SortOrder, TagFilter, TxQuery, TxQueryFilterCriteria, WithTxResponseFields,
};
use ario_core::wallet::{Wallet, WalletAddress};
use ario_core::{JsonValue, MaybeOwned};
use futures_lite::{AsyncRead, AsyncReadExt, AsyncSeek, Stream, StreamExt};
use serde_json::Error as JsonError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    EntityError(#[from] EntityError),
    #[error(transparent)]
    ClientError(#[from] ClientError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum EntityError {
    #[error(transparent)]
    ParseError(#[from] types::ParseError),
    #[error(transparent)]
    MetadataError(#[from] MetadataError),
    #[error("entity of type '{entity_type}' with details '{details}' not found")]
    NotFound {
        entity_type: &'static str,
        details: String,
    },
    #[error("owner mismatch, expected '{expected}' but found '{actual}'")]
    OwnerMismatch {
        expected: WalletAddress,
        actual: WalletAddress,
    },
    #[error("privacy mode mismatch, expected '{expected}' but found '{actual}'")]
    PrivacyMismatch { expected: Privacy, actual: Privacy },
    #[error("auth mode mismatch, expected '{expected}' but found '{actual}'")]
    AuthModeMismatch { expected: String, actual: String },
}

#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("data length '{actual}' exceeds max '{max}'")]
    MaxLengthExceeded { max: usize, actual: usize },
    #[error(transparent)]
    JsonError(#[from] JsonError),
}

impl ArFs<Public, ReadOnly> {
    pub async fn new(client: Client, drive_ref: &DriveRef<'_>) -> Result<Self, Error> {
        let drive = drive_entity(&client, drive_ref, None).await?;
        Ok(Self {
            client,
            drive,
            privacy: Public {
                owner: drive_ref.owner.clone().into_owned(),
            },
            mode: ReadOnly,
        })
    }
}

impl ArFs<Public, ReadWrite> {
    pub async fn new(
        client: Client,
        drive_ref: &DriveRef<'_>,
        wallet: Wallet,
    ) -> Result<Self, Error> {
        let owner_address = wallet.address();
        if drive_ref.owner.as_ref() != &owner_address {
            Err(EntityError::OwnerMismatch {
                expected: owner_address,
                actual: drive_ref.owner.clone().into_owned(),
            })?;
        }
        let drive = drive_entity(&client, drive_ref, None).await?;

        Ok(Self {
            client,
            drive,
            privacy: Public {
                owner: drive_ref.owner.clone().into_owned(),
            },
            mode: ReadWrite { wallet },
        })
    }
}

impl<PRIVACY, MODE> ArFs<PRIVACY, MODE> {
    pub fn version(&self) -> &ArFsVersion {
        self.drive.header().version()
    }

    pub fn drive_id(&self) -> &DriveId {
        &self.drive.header().as_inner().drive_id
    }

    pub fn created_at(&self) -> &DateTime<Utc> {
        &self.drive.header().as_inner().time
    }

    fn display(
        &self,
        f: &mut fmt::Formatter<'_>,
        privacy: &'static str,
        mode: &'static str,
        owner: &WalletAddress,
    ) -> fmt::Result {
        writeln!(f, "ArFS Version: {}", self.version())?;
        writeln!(f, "Drive ID: {}", self.drive_id())?;
        writeln!(f, "Owner: {}", &owner)?;
        writeln!(f, "Privacy: {}", privacy)?;
        writeln!(f, "Access Mode: {}", mode)?;
        write!(f, "Created at: {}", self.created_at())
    }
}

pub struct ReadWrite {
    wallet: Wallet,
}

pub struct ReadOnly;

pub struct ArFs<PRIVACY, MODE> {
    client: Client,
    drive: DriveEntity,
    privacy: PRIVACY,
    mode: MODE,
}

pub struct Public {
    owner: WalletAddress,
}

impl<Mode> ArFs<Public, Mode> {
    pub fn owner(&self) -> &WalletAddress {
        &self.privacy.owner
    }

    fn display_public(&self, f: &mut fmt::Formatter<'_>, mode: &'static str) -> fmt::Result {
        self.display(f, "Public", mode, self.owner())
    }
}

impl Display for ArFs<Public, ReadOnly> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_public(f, "Read Only")
    }
}

impl Display for ArFs<Public, ReadWrite> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_public(f, "Read/Write")
    }
}

pub struct Private {
    wallet: Wallet,
    wallet_address: WalletAddress,
    auth: AuthMode,
}

impl Private {
    fn new(wallet: Wallet, auth: AuthMode) -> Self {
        let wallet_address = wallet.address();
        Self {
            wallet,
            wallet_address,
            auth,
        }
    }
}

impl<Mode> ArFs<Private, Mode> {
    pub fn owner(&self) -> &WalletAddress {
        &self.privacy.wallet_address
    }

    fn display_private(&self, f: &mut fmt::Formatter<'_>, mode: &'static str) -> fmt::Result {
        match self.privacy.auth {
            AuthMode::Password => self.display(f, "Private (Password)", mode, self.owner()),
        }
    }
}

impl Display for ArFs<Private, ReadOnly> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_private(f, "Read Only")
    }
}

impl Display for ArFs<Private, ReadWrite> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_private(f, "Read/Write")
    }
}

pub struct DriveRef<'a> {
    drive_id: DriveId,
    container_id: ItemId<'a>,
    owner: MaybeOwned<'a, WalletAddress>,
}

type TagsOnly = WithTxResponseFields<false, false, false, false, false, false, true, false>;

fn find_drive_ids_by_owner<'a>(
    client: &'a Client,
    owner: &'a WalletAddress,
) -> impl Stream<Item = Result<DriveRef<'a>, Error>> + Unpin + 'a {
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
            Ok(item) => {
                let drive_header = Header::<DriveHeader, DriveKind>::try_from(item.tags())
                    .map_err(EntityError::ParseError)?;

                Ok(DriveRef {
                    drive_id: drive_header.as_inner().drive_id.clone(),
                    container_id: item.id().clone().into_owned(),
                    owner: MaybeOwned::Borrowed(owner),
                })
            }
            Err(e) => Err(e.into()),
        })
}

trait MetadataReader: AsyncRead + AsyncSeek + Send + Unpin {
    fn len(&self) -> u64;
}

impl MetadataReader for AsyncTxReader<'_> {
    fn len(&self) -> u64 {
        AsyncTxReader::len(self)
    }
}

impl MetadataReader for AsyncBundleItemReader<'_> {
    fn len(&self) -> u64 {
        AsyncBundleItemReader::len(self)
    }
}

async fn drive_entity(
    client: &Client,
    drive_ref: &DriveRef<'_>,
    private: Option<&Private>,
) -> Result<DriveEntity, Error> {
    const MAX_METADATA_LEN: usize = 1024 * 1024;

    if let Some(address) = private.map(|p| p.wallet.address()) {
        if &address != drive_ref.owner.as_ref() {
            Err(EntityError::OwnerMismatch {
                expected: address,
                actual: drive_ref.owner.clone().into_owned(),
            })?;
        }
    }

    let tx_e;
    let bundle_item;
    let mut reader: Box<dyn MetadataReader>;
    let owner_address;

    let authenticated_tags = match &drive_ref.container_id {
        ItemId::Tx(tx) => {
            if let Some(tx) = client.tx_by_id(&tx).await? {
                tx_e = tx;
                let tags = tx_e.tags();
                owner_address = tx_e.owner().address();

                reader = Box::new(AsyncTxReader::new(client.clone(), &tx_e).await?);
                tags
            } else {
                return Err(EntityError::NotFound {
                    entity_type: DriveKind::TYPE,
                    details: drive_ref.drive_id.to_string(),
                })?;
            }
        }
        ItemId::BundleItem { item_id, bundle_id } => {
            if let Some(item) = client.bundle_item(item_id, bundle_id).await? {
                bundle_item = item;
                let tags = bundle_item.tags();
                owner_address = bundle_item.owner().address();
                reader = Box::new(client.read_bundle_item(&bundle_item).await?);
                tags
            } else {
                return Err(EntityError::NotFound {
                    entity_type: DriveKind::TYPE,
                    details: drive_ref.drive_id.to_string(),
                })?;
            }
        }
    };

    if &owner_address != drive_ref.owner.as_ref() {
        Err(EntityError::OwnerMismatch {
            expected: drive_ref.owner.clone().into_owned(),
            actual: owner_address,
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

    let drive_header = Header::<DriveHeader, DriveKind>::try_from(authenticated_tags)
        .map_err(EntityError::from)?;

    let drive_metadata =
        Metadata::<DriveMetadata, DriveKind>::try_from(metadata).map_err(EntityError::from)?;

    let drive_entity = DriveEntity::new(drive_header, drive_metadata);

    let privacy = private.map(|_| Privacy::Private).unwrap_or(Privacy::Public);
    if drive_entity.header().as_inner().privacy != privacy {
        Err(EntityError::PrivacyMismatch {
            expected: privacy,
            actual: drive_entity.header().as_inner().privacy,
        })?;
    }

    let auth_mode = private.map(|p| p.auth);
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

#[cfg(test)]
mod tests {
    use crate::{ArFs, Public, ReadOnly};
    use ario_client::Client;
    use ario_core::Gateway;
    use ario_core::jwk::Jwk;
    use ario_core::network::Network;
    use ario_core::wallet::Wallet;
    use futures_lite::stream::StreamExt;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[ignore]
    #[tokio::test]
    async fn foo() -> anyhow::Result<()> {
        dotenv::dotenv().ok();
        init_tracing();

        let arlocal = std::env::var("ARLOCAL_URL").unwrap();
        let network_id = std::env::var("ARLOCAL_ID").unwrap_or("arlocal".to_string());
        let wallet_jwk = std::env::var("ARLOCAL_WALLET_JWK").unwrap();

        let client = Client::builder()
            .network(Network::Local(network_id.try_into()?))
            .gateways([Gateway::from_str(arlocal.as_str())?])
            .enable_netwatch(false)
            .build()
            .await?;

        let json =
            tokio::fs::read_to_string(<PathBuf as AsRef<Path>>::as_ref(&PathBuf::from(wallet_jwk)))
                .await?;

        let jwk = Jwk::from_json(json.as_str())?;
        let wallet = Wallet::from_jwk(&jwk)?;
        let drive_owner = wallet.address();

        let mut stream = super::find_drive_ids_by_owner(&client, &drive_owner);

        while let Some(drive_ref) = stream.try_next().await? {
            let arfs = ArFs::<Public, ReadOnly>::new(client.clone(), &drive_ref).await?;
            println!("{}", arfs);
        }
        Ok(())
    }
}
