use crate::db::{ReadWrite, Transaction};
use crate::types::file::{FileEntity, FileHeader, FileId, FileKind, FileMetadata};
use crate::types::folder::{FolderEntity, FolderHeader, FolderKind, FolderMetadata};
use crate::types::{ArfsEntity, Cipher, Header, Metadata, ParseError};
use crate::vfs::MaybeEncryptedDataItem;
use crate::wal::{WalDirMetadata, WalFileMetadata};
use crate::{
    ContentType, DriveId, FxService, KeyRing, Price, PriceAdjustment, PriceLimit, db, serde_tag,
    wal,
};
use ario_client::bundle::bundler;
use ario_client::bundle::bundler::{AcceptingItems, AsyncBundler};
use ario_client::graphql::{TxQuery, TxQueryFilterCriteria};
use ario_client::location::{Arl, TxArl};
use ario_client::tx::Status as TxStatus;
use ario_client::{ByteSize, Client, RawItemId};
use ario_core::blob::OwnedBlob;
use ario_core::bundle::{
    ArweaveScheme, AuthenticatedBundleItem, BundleItemAuthenticator, BundleItemBuilder,
    BundleItemError, V2BundleItemDataProcessor,
};
use ario_core::money::{Money, Winston};
use ario_core::tag::Tag;
use ario_core::tx::TxId;
use ario_core::wallet::{Wallet, WalletAddress};
use ario_core::{BlockNumber, ItemId, JsonValue};
use async_trait::async_trait;
use blocking::unblock;
use bon::bon;
use chrono::{DateTime, Utc};
use futures_lite::{AsyncRead, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt, StreamExt};
use maybe_owned::MaybeOwnedMut;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::{IoSlice, IoSliceMut, SeekFrom};
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};
use tempfile::{NamedTempFile, TempDir};
use thiserror::Error;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};
use tracing::instrument;

static PLACEHOLDER_ARL: LazyLock<Arl> = LazyLock::new(|| {
    Arl::Tx(TxArl::from(
        TxId::from_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .expect("placeholder TxId to be valid"),
    ))
});

pub struct Uploader {
    temp_dir: Arc<TempDir>,
    client: Client,
    min_confirmations: usize,
    mode: Box<dyn UploadMode + Send + Sync + 'static>,
    price_limit: Option<PriceLimit>,
    fx_service: Option<Arc<FxService>>,
    settled_checks: HashMap<DriveId, HashMap<u64, SettledCheck>>,
    settlement_timeout: Duration,
    dry_run: bool,
}

struct SettledCheck {
    last_check: SystemTime,
    num_checks: usize,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("fx_service is required due to fiat price limit")]
    FxServiceRequired,
    #[error(transparent)]
    DatabaseError(#[from] db::Error),
    #[error(transparent)]
    UploadModeError(#[from] UploadModeError),
    #[error("current market price [{current_price}] exceeds price limit [{price_limit}]")]
    PriceLimitExceeded {
        current_price: Money<Winston>,
        price_limit: Money<Winston>,
    },
    #[error("required [{required}] exceeds available wallet balance of [{available}]")]
    InsufficientBalance {
        required: Money<Winston>,
        available: Money<Winston>,
    },
    #[error(transparent)]
    BundleItemError(#[from] BundleItemError),
    #[error("bundle item not found for file '{0}'")]
    MissingBundleItem(FileId),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    ParseError(#[from] crate::types::ParseError),
    #[error(transparent)]
    BundlerError(#[from] bundler::Error),
    #[error(transparent)]
    ArcBundlerError(#[from] Arc<bundler::Error>),
    #[error(transparent)]
    TagError(#[from] serde_tag::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    ClientError(#[from] ario_client::Error),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("dry-run / operation not permitted")]
    DryRun,
}

#[bon]
impl Uploader {
    #[builder]
    pub async fn new(
        client: Client,
        mode: Box<dyn UploadMode + Send + Sync + 'static>,
        price_limit: Option<PriceLimit>,
        fx_service: Option<Arc<FxService>>,
        temp_dir: Option<PathBuf>,
        #[builder(default = Duration::from_secs(86400))] settlement_timeout: Duration,
        #[builder(default = 3)] min_confirmations: usize,
        #[builder(default = false)] dry_run: bool,
    ) -> Result<Self, Error> {
        if let Some(price_limit) = price_limit.as_ref() {
            if !price_limit.is_native() && fx_service.is_none() {
                Err(Error::FxServiceRequired)?
            }
        }

        let temp_dir = unblock(move || match temp_dir {
            Some(temp_dir) => TempDir::with_prefix_in("ars3nal_upload", &temp_dir),
            None => TempDir::with_prefix("ars3nal_upload"),
        })
        .await?;

        Ok(Self {
            client,
            mode,
            price_limit,
            fx_service,
            temp_dir: Arc::new(temp_dir),
            settled_checks: HashMap::default(),
            min_confirmations,
            settlement_timeout,
            dry_run,
        })
    }

    fn cleanup_checks(&mut self) {
        let cutoff = SystemTime::now() - Duration::from_secs(86400);
        // remove old entries
        self.settled_checks
            .values_mut()
            .for_each(|map| map.retain(|_, v| v.last_check > cutoff));

        self.settled_checks.retain(|_, v| !v.is_empty())
    }
}

async fn graphql_test(
    client: &Client,
    item_id: &ItemId,
    block: BlockNumber,
) -> Result<bool, Error> {
    // this does a test graphql query and expects at least 1 bundle_item
    // for the above item_id + block to succeed.
    // the goal here is to ensure the bundle we are interested in has been
    // indexed by the graphql endpoint and can be found during syncing
    if client.any_gateway_info().await?.height < block {
        // gw not ready yet
        return Ok(false);
    }
    let count = client
        .query_transactions(
            TxQuery::builder()
                .filter_criteria(
                    TxQueryFilterCriteria::builder()
                        .block_range(block.into())
                        .bundled_in([item_id])
                        .build(),
                )
                .max_results(NonZeroUsize::new(1).unwrap())
                .build(),
        )
        .try_fold(0usize, |count, _| Ok(count + 1))
        .await?;
    Ok(count > 0)
}

impl Uploader {
    pub async fn process_pending(
        &mut self,
        tx: &mut Transaction<ReadWrite>,
        drive_id: &DriveId,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        self.cleanup_checks();

        if !self.settled_checks.contains_key(drive_id) {
            self.settled_checks
                .insert(drive_id.clone(), Default::default());
        }
        let settled_checks = self.settled_checks.get_mut(drive_id).unwrap();
        let mut next_check = None;

        for (upload_id, upload_time, item_id) in tx.pending_uploads().await? {
            if let Some(location) = self.client.location_by_item_id(&item_id).await.ok() {
                if let Some(TxStatus::Accepted(accepted)) =
                    self.client.tx_status(location.tx_id()).await?
                {
                    if accepted.number_of_confirmations >= self.min_confirmations as u64 {
                        // found on blockchain
                        // make sure it can be queried via graphql
                        if graphql_test(&self.client, &item_id, accepted.block_height).await? {
                            tx.mark_upload_success(upload_id, accepted.block_height)
                                .await?;
                            settled_checks.remove(&upload_id);
                            continue;
                        }
                    }
                }
            }

            match (next_check, Utc::now() + Duration::from_secs(300)) {
                (None, next) => next_check = Some(next),
                (Some(existing), candidate) if candidate < existing => next_check = Some(candidate),
                _ => {} // do nothing
            }
            if let Some(check) = settled_checks.get_mut(&upload_id) {
                check.num_checks += 1;
                check.last_check = SystemTime::now();
            } else {
                settled_checks.insert(
                    upload_id,
                    SettledCheck {
                        num_checks: 1,
                        last_check: SystemTime::now(),
                    },
                );
            }

            let cutoff = upload_time + self.settlement_timeout;
            if cutoff < Utc::now() {
                // upload timed out
                // we treat it as failed at this point
                tx.mark_upload_failed(upload_id).await?;
                settled_checks.remove(&upload_id);
            }
        }

        Ok(next_check)
    }

    async fn price_check(&self) -> Result<(), Error> {
        if let Some(price_limit) = self.price_limit.as_ref() {
            let current_price = self.mode.current_price(price_limit.unit).await?;

            let price_limit = price_limit
                .price
                .to_winston(self.fx_service.as_ref().map(|fx| fx.as_ref()))
                .ok_or_else(|| Error::FxServiceRequired)?;

            if current_price > price_limit {
                tracing::warn!(current_price = %current_price, price_limit = %price_limit, "current market price exceeds price limit, cannot upload right now");
                return Err(Error::PriceLimitExceeded {
                    current_price,
                    price_limit,
                });
            }
        }
        Ok(())
    }

    async fn balance_check(&self, data_size: ByteSize) -> Result<(), Error> {
        let estimated_cost = self.mode.current_price(data_size).await?;
        let current_balance = self.mode.balance().await?;

        if estimated_cost > current_balance {
            tracing::warn!(estimated_cost = %estimated_cost, current_balance = %current_balance, "estimated cost exceeds current balance, cannot proceed with upload");
            return Err(Error::InsufficientBalance {
                available: current_balance,
                required: estimated_cost,
            });
        }
        Ok(())
    }

    #[instrument(fields(drive_id = %drive_id), skip(self, data_wallet, tx))]
    pub async fn process_new(
        &mut self,
        tx: &mut Transaction<ReadWrite>,
        drive_id: &DriveId,
        data_wallet: &Wallet,
        key_ring: Option<&KeyRing>,
        batch_settle_time: Duration,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        let batch_deadline = Utc::now() - batch_settle_time;
        let (has_entries, latest_ts) = tx.has_uploadable_wal_entries(&batch_deadline).await?;
        if !has_entries {
            return Ok(latest_ts.map(|ts| ts + batch_settle_time));
        }

        self.price_check().await?;

        let wal_entries = tx.uploadable_wal_entries(&batch_deadline).await?;
        if wal_entries.is_empty() {
            return Ok(None);
        }

        let estimated_total_size = ByteSize::b(
            wal_entries
                .iter()
                .map(|e| e.estimate_stored_size().as_u64())
                .sum::<u64>()
                + 1200,
        );

        self.balance_check(estimated_total_size).await?;

        let wal_ids = wal_entries.iter().map(|e| e.id()).collect::<Vec<_>>();
        let upload_id = self
            .upload(wal_entries, drive_id, tx, data_wallet, key_ring)
            .await?;

        tx.set_upload_id(upload_id, wal_ids.iter().map(|id| *id))
            .await?;
        Ok(None)
    }

    #[instrument(skip_all)]
    async fn upload(
        &mut self,
        wal_entries: Vec<WalEntry>,
        drive_id: &DriveId,
        tx: &mut Transaction<ReadWrite>,
        data_wallet: &Wallet,
        key_ring: Option<&KeyRing>,
    ) -> Result<u64, Error> {
        let path = self.temp_dir.clone();
        let prefix = drive_id.to_string();
        let work_dir =
            Arc::new(unblock(move || TempDir::with_prefix_in(&prefix, path.path())).await?);

        let bundler = self
            .build_bundle(
                work_dir.clone(),
                wal_entries,
                drive_id,
                tx,
                data_wallet,
                key_ring,
            )
            .await?;

        self.price_check().await?; // second price check in case prices changed

        if self.dry_run {
            Err(Error::DryRun)?
        }

        let mode = self.mode.mode();
        let address = data_wallet.address();
        tracing::debug!(mode = %mode, signing_wallet = %address, "initiating new upload");
        let details = self.mode.submit(drive_id, bundler).await?;
        let upload_id = tx.new_upload(&details, mode).await?;
        let duration = details.uploaded - details.created;
        tracing::info!(mode = %mode, drsigning_wallet = %address, data_size = %details.data_size, cost = %details.cost, duration = %duration, "new upload submitted");

        Ok(upload_id)
    }

    async fn build_bundle(
        &self,
        work_dir: Arc<TempDir>,
        wal_entries: Vec<WalEntry>,
        drive_id: &DriveId,
        tx: &mut Transaction<ReadWrite>,
        data_wallet: &Wallet,
        key_ring: Option<&KeyRing>,
    ) -> Result<AsyncBundler<AcceptingItems>, Error> {
        let mut file_contents = HashMap::new();
        // file data first
        for entry in &wal_entries {
            match entry {
                WalEntry::CreateFile(_, wal_entity_id, metadata)
                | WalEntry::UpdateFile(_, wal_entity_id, metadata) => {
                    let file_id = &metadata.id;
                    if file_contents.contains_key(file_id) {
                        continue;
                    }
                    let mut reader = wal::file_reader::FileReader::open(
                        *wal_entity_id,
                        MaybeOwnedMut::Borrowed(tx),
                    )
                    .await
                    .map_err(|e| std::io::Error::other(e))?;
                    if reader.len() != metadata.size {
                        Err(std::io::Error::other("unexpected file size"))?;
                    }

                    let (temp_file, tags) =
                        temp_data_file(&mut reader, &work_dir, file_id, metadata.size, key_ring)
                            .await?;

                    let mut file = AsyncTempFile::open_ro(temp_file, work_dir.clone()).await?;

                    let data = V2BundleItemDataProcessor::try_from_async_reader(&mut file).await?;
                    let authenticator = data.authenticator();
                    let bundle_item_draft = BundleItemBuilder::v2()
                        .data_upload(data)
                        .tags(tags)
                        .draft()?;
                    let bundle_item =
                        data_wallet.sign_bundle_item_draft::<ArweaveScheme>(bundle_item_draft)?;

                    file_contents.insert(file_id.clone(), (bundle_item, authenticator, file));
                }
                _ => {}
            }
        }

        let mut bundler = AsyncBundler::new(None);

        for entry in wal_entries {
            let entity = entry.into_entity(drive_id, &file_contents, key_ring)?;
            let metadata = entity.to_metadata_bytes(key_ring)?;
            let data = V2BundleItemDataProcessor::from_single_value(metadata.bytes());
            let authenticator = data.authenticator();
            let tags = entity.to_header_tags()?;
            let bundle_item_draft = BundleItemBuilder::v2()
                .tags(tags)
                .data_upload(data)
                .draft()?;
            let bundle_item =
                data_wallet.sign_bundle_item_draft::<ArweaveScheme>(bundle_item_draft)?;
            bundler
                .submit(
                    bundle_item,
                    authenticator,
                    futures_lite::io::Cursor::new(metadata),
                )
                .await?;
        }

        // add file contents to bundle
        for (_, (item, authenticator, mut file)) in file_contents {
            file.seek(SeekFrom::Start(0)).await?;
            bundler.submit(item, authenticator, file).await?;
        }

        Ok(bundler)
    }
}

async fn temp_data_file<R: AsyncRead>(
    reader: R,
    work_dir: &Arc<TempDir>,
    file_id: &FileId,
    data_size: u64,
    key_ring: Option<&KeyRing>,
) -> Result<(Arc<NamedTempFile>, Vec<Tag<'static>>), Error> {
    let mut writer = AsyncTempFile::create_rw(work_dir.clone()).await?;
    Ok(if let Some(key_ring) = key_ring {
        // encrypted mode
        let file_key = key_ring.file_key(file_id).unwrap();
        let cipher = if data_size > 1024 * 1024 * 100 {
            // to maintain compatibility with other ArFS implementations
            // files over 100MiB will use AES-CTR instead of AES-GCM
            Cipher::Aes256Ctr
        } else {
            Cipher::Aes256Gcm
        };
        let nonce = cipher.generate_nonce();
        let mut encryptor = file_key
            .encrypt_content(&mut writer, cipher, Some(nonce.clone()))
            .await
            .map_err(|e| Error::EncryptionError(e.to_string()))?;
        futures_lite::io::copy(reader, &mut encryptor).await?;
        let maybe_tag = encryptor.finalize().await?;
        writer.write_all(maybe_tag.bytes()).await?;
        writer.close().await?;
        let (_, temp_file, _) = writer.into_parts();
        let enc_data_item = MaybeEncryptedDataItem {
            cipher: Some(cipher),
            cipher_iv: Some(nonce),
        };
        let tags = serde_tag::to_tags(&enc_data_item)?;
        (temp_file, tags)
    } else {
        // plaintext mode
        futures_lite::io::copy(reader, &mut writer).await?;
        writer.close().await?;
        let (_, temp_file, _) = writer.into_parts();
        (temp_file, Vec::new())
    })
}

pub(crate) enum WalEntry {
    CreateFile(u64, u64, WalFileMetadata),
    UpdateFile(u64, u64, WalFileMetadata),
    DeleteFile(u64, WalFileMetadata),
    CreateDir(u64, WalDirMetadata),
    UpdateDir(u64, WalDirMetadata),
    DeleteDir(u64, WalDirMetadata),
}
impl WalEntry {
    pub fn create_file(id: u64, wal_entity_id: u64, metadata: &[u8]) -> Result<Self, db::Error> {
        Ok(Self::CreateFile(
            id,
            wal_entity_id,
            serde_sqlite_jsonb::from_slice::<WalFileMetadata>(metadata)
                .map_err(|e| db::Error::DataError(e.into()))?,
        ))
    }

    pub fn update_file(id: u64, wal_entity_id: u64, metadata: &[u8]) -> Result<Self, db::Error> {
        Ok(Self::UpdateFile(
            id,
            wal_entity_id,
            serde_sqlite_jsonb::from_slice::<WalFileMetadata>(metadata)
                .map_err(|e| db::Error::DataError(e.into()))?,
        ))
    }

    pub fn delete_file(id: u64, metadata: &[u8]) -> Result<Self, db::Error> {
        Ok(Self::DeleteFile(
            id,
            serde_sqlite_jsonb::from_slice::<WalFileMetadata>(metadata)
                .map_err(|e| db::Error::DataError(e.into()))?,
        ))
    }

    pub fn create_dir(id: u64, metadata: &[u8]) -> Result<Self, db::Error> {
        Ok(Self::CreateDir(
            id,
            serde_sqlite_jsonb::from_slice::<WalDirMetadata>(metadata)
                .map_err(|e| db::Error::DataError(e.into()))?,
        ))
    }

    pub fn update_dir(id: u64, metadata: &[u8]) -> Result<Self, db::Error> {
        Ok(Self::UpdateDir(
            id,
            serde_sqlite_jsonb::from_slice::<WalDirMetadata>(metadata)
                .map_err(|e| db::Error::DataError(e.into()))?,
        ))
    }

    pub fn delete_dir(id: u64, metadata: &[u8]) -> Result<Self, db::Error> {
        Ok(Self::DeleteDir(
            id,
            serde_sqlite_jsonb::from_slice::<WalDirMetadata>(metadata)
                .map_err(|e| db::Error::DataError(e.into()))?,
        ))
    }

    pub fn id(&self) -> u64 {
        match self {
            Self::CreateFile(id, ..)
            | Self::UpdateFile(id, ..)
            | Self::DeleteFile(id, ..)
            | Self::CreateDir(id, ..)
            | Self::UpdateDir(id, ..)
            | Self::DeleteDir(id, ..) => *id,
        }
    }

    pub fn into_entity(
        self,
        drive_id: &DriveId,
        file_contents: &HashMap<
            FileId,
            (
                AuthenticatedBundleItem,
                BundleItemAuthenticator,
                AsyncTempFile<Compat<tokio::fs::File>>,
            ),
        >,
        key_ring: Option<&KeyRing>,
    ) -> Result<ArfsEntity, Error> {
        match self {
            Self::CreateFile(_, _, metadata) | Self::UpdateFile(_, _, metadata) => {
                let file_id = &metadata.id;
                let data_tx_id = file_contents
                    .get(file_id)
                    .map(|(item, _, _)| item.id().as_ref().clone().into_inner())
                    .ok_or_else(|| Error::MissingBundleItem(file_id.clone()))?;

                Ok(
                    into_file_entity(metadata, drive_id.clone(), data_tx_id, false, key_ring)?
                        .into(),
                )
            }
            Self::DeleteFile(_, metadata) => {
                let data_tx_id = metadata
                    .existing_data_item_id
                    .as_ref()
                    .map(|id| id.clone())
                    .ok_or_else(|| {
                        ParseError::Other(
                            "delete operations require an existing data item id".to_string(),
                        )
                    })?;

                Ok(
                    into_file_entity(metadata, drive_id.clone(), data_tx_id, true, key_ring)?
                        .into(),
                )
            }
            Self::CreateDir(_, metadata) | Self::UpdateDir(_, metadata) => {
                Ok(into_folder_entity(metadata, drive_id.clone(), false, key_ring)?.into())
            }
            Self::DeleteDir(_, metadata) => {
                Ok(into_folder_entity(metadata, drive_id.clone(), true, key_ring)?.into())
            }
        }
    }
}

fn maybe_metadata_enc(
    key_ring: Option<&KeyRing>,
) -> (Option<Cipher>, Option<OwnedBlob>, ContentType) {
    if let Some(_) = key_ring {
        let cipher = Cipher::Aes256Gcm; // metadata encryption always uses GCM mode
        let nonce = cipher.generate_nonce();
        (Some(cipher), Some(nonce), ContentType::Binary)
    } else {
        (None, None, ContentType::Json)
    }
}

fn into_file_entity(
    metadata: WalFileMetadata,
    drive_id: DriveId,
    data_tx_id: RawItemId,
    hidden: bool,
    key_ring: Option<&KeyRing>,
) -> Result<FileEntity, Error> {
    let (cipher, cipher_iv, content_type) = maybe_metadata_enc(key_ring);

    let header = Header::<FileHeader, FileKind>::from_inner(
        None,
        FileHeader {
            drive_id: drive_id,
            file_id: metadata.id,
            cipher,
            cipher_iv,
            content_type,
            parent_folder_id: metadata.parent,
            time: Utc::now(),
        },
        None,
    );

    let extra = metadata
        .extra
        .into_iter()
        .filter_map(|(k, v)| {
            String::from_utf8(v.to_vec())
                .ok()
                .map(|s| (k, JsonValue::String(s))) // only string values supported here
        })
        .collect::<HashMap<_, _>>();

    let extra = if extra.is_empty() { None } else { Some(extra) };

    let metadata = FileMetadata {
        name: metadata.name,
        size: metadata.size,
        data_tx_id,
        last_modified: metadata.last_modified,
        content_type: metadata.content_type.unwrap_or_else(|| ContentType::Binary),
        hidden,
        pinned_data_owner: None,
    };

    let metadata = Metadata::<FileMetadata, FileKind>::from_inner(metadata, extra);

    Ok(FileEntity::new(
        header,
        metadata,
        BlockNumber::from_inner(0),
        PLACEHOLDER_ARL.deref().clone(),
    ))
}

fn into_folder_entity(
    metadata: WalDirMetadata,
    drive_id: DriveId,
    hidden: bool,
    key_ring: Option<&KeyRing>,
) -> Result<FolderEntity, Error> {
    let (cipher, cipher_iv, content_type) = maybe_metadata_enc(key_ring);

    let header = Header::<FolderHeader, FolderKind>::from_inner(
        None,
        FolderHeader {
            drive_id,
            folder_id: metadata.id,
            cipher,
            cipher_iv,
            content_type,
            parent_folder_id: Some(metadata.parent),
            time: Utc::now(),
        },
        None,
    );

    let metadata = FolderMetadata {
        name: metadata.name,
        hidden,
    };

    let metadata = Metadata::<FolderMetadata, FolderKind>::from_inner(metadata, None);

    Ok(FolderEntity::new(
        header,
        metadata,
        BlockNumber::from_inner(0),
        PLACEHOLDER_ARL.deref().clone(),
    ))
}

impl WalEntry {
    fn estimate_stored_size(&self) -> ByteSize {
        let base = match &self {
            Self::CreateFile(_, _, metadata) | Self::UpdateFile(_, _, metadata) => {
                let mut size = metadata.size;
                size = size.saturating_add(metadata.name.as_bytes().len() as u64 + 16);
                size = size.saturating_add(24); // last modified
                size = size.saturating_add(
                    metadata
                        .content_type
                        .as_ref()
                        .map(|ct| ct.as_ref().as_bytes().len() as u64 + 16)
                        .unwrap_or_else(|| 0),
                );
                size = size.saturating_add(
                    metadata
                        .extra
                        .iter()
                        .map(|(k, v)| k.as_bytes().len() as u64 + v.len() as u64)
                        .sum(),
                );
                size
            }
            Self::CreateDir(_, metadata) | Self::UpdateDir(_, metadata) => {
                let mut size = metadata.name.as_bytes().len() as u64;
                size = size.saturating_add(24); // last modified
                size
            }
            Self::DeleteFile(_, _) | Self::DeleteDir(_, _) => 0,
        };
        let with_tags = base.saturating_add(2000);
        ByteSize::b(with_tags.saturating_add(with_tags.div_ceil(10))) // 10% extra as safety margin
    }
}

pub struct Direct {
    client: Client,
    wallet: Wallet,
    address: WalletAddress,
    price_adjustment: PriceAdjustment,
}

impl Direct {
    pub fn new(client: Client, wallet: Wallet, price_adjustment: PriceAdjustment) -> Self {
        Self {
            client,
            address: wallet.address(),
            wallet,
            price_adjustment,
        }
    }
}

#[derive(Error, Debug)]
pub enum UploadModeError {
    #[error("backend error: {0}")]
    BackendError(String),
    #[error("pricing error: {0}")]
    PricingError(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("preparation error: {0}")]
    PreparationError(String),
    #[error("upload error: {0}")]
    UploadError(String),
}

#[async_trait]
impl UploadMode for Direct {
    fn mode(&self) -> Mode {
        Mode::Direct
    }

    async fn current_price(&self, data_size: ByteSize) -> Result<Money<Winston>, UploadModeError> {
        Ok(self
            .client
            .price(data_size.as_u64(), Some(&self.address))
            .await
            .map(|p| {
                if let Price::Winston(winston) = Price::Winston(p)
                    .adjust(&self.price_adjustment)
                    .map_err(|e| UploadModeError::PricingError(e.to_string()))?
                {
                    Ok(winston)
                } else {
                    Err(UploadModeError::PricingError(
                        "expected adjusted price to be in winston".to_string(),
                    ))
                }
            })
            .map_err(|e| UploadModeError::BackendError(e.to_string()))??)
    }

    async fn balance(&self) -> Result<Money<Winston>, UploadModeError> {
        let address = self.wallet.address();
        self.client
            .wallet_balance(&address)
            .await
            .map_err(|e| UploadModeError::BackendError(e.to_string()))
    }

    async fn submit(
        &mut self,
        _drive_id: &DriveId,
        bundler: AsyncBundler<AcceptingItems>,
    ) -> Result<UploadDetails, UploadModeError> {
        let bundler = bundler
            .transition(self.client.clone())
            .await
            .map_err(|e| UploadModeError::PreparationError(e.to_string()))?;
        let estimated_tx_size = ByteSize::b(bundler.data_size() + 1200);
        let reward = self.current_price(estimated_tx_size).await?;
        let current_balance = self.balance().await?;
        if current_balance < reward {
            Err(UploadModeError::PreparationError(format!(
                "insufficient balance: available '{}' < required '{}'",
                current_balance, reward
            )))?;
        }
        let mut tx_draft = bundler.tx_draft();
        tx_draft
            .set_reward(reward)
            .map_err(|e| UploadModeError::PreparationError(e.to_string()))?;

        // submit tx to gw
        let bundler = bundler
            .transition(
                self.wallet
                    .sign_tx_draft(tx_draft)
                    .map_err(|e| UploadModeError::PreparationError(e.to_string()))?,
            )
            .await
            .map_err(|e| UploadModeError::PreparationError(e.to_string()))?;

        let created = DateTime::<Utc>::from(bundler.started());
        let data_size = ByteSize::b(bundler.data_size());
        let item_id = ItemId::Tx(bundler.tx_id().clone());
        let cost = bundler.reward_paid().deref().clone();

        // begin data upload
        let bundler = bundler
            .transition()
            .await
            .map_err(|e| UploadModeError::UploadError(e.to_string()))?;
        let uploaded = created + bundler.upload_duration();

        Ok(UploadDetails {
            created,
            uploaded,
            data_size,
            cost,
            item_id,
        })
    }
}

pub struct Turbo {
    client: Client,
    wallet: Wallet,
    address: WalletAddress,
}

impl Turbo {
    pub fn new(client: Client, wallet: Wallet) -> Self {
        let address = wallet.address();
        Self {
            client,
            wallet,
            address,
        }
    }
}

#[async_trait]
impl UploadMode for Turbo {
    fn mode(&self) -> Mode {
        Mode::Turbo
    }

    async fn current_price(&self, data_size: ByteSize) -> Result<Money<Winston>, UploadModeError> {
        self.client
            .turbo_price(data_size.as_u64(), Some(&self.address))
            .await
            .map_err(|e| UploadModeError::PricingError(e.to_string()))
    }

    async fn balance(&self) -> Result<Money<Winston>, UploadModeError> {
        self.client
            .turbo_balance(&self.address)
            .await
            .map_err(|e| UploadModeError::BackendError(e.to_string()))
    }

    async fn submit(
        &mut self,
        _drive_id: &DriveId,
        bundler: AsyncBundler<AcceptingItems>,
    ) -> Result<UploadDetails, UploadModeError> {
        let (item_draft, _, reader) = bundler
            .into_nested()
            .await
            .map_err(|e| UploadModeError::PreparationError(e.to_string()))?;

        let item = self
            .wallet
            .sign_bundle_item_draft::<ArweaveScheme>(item_draft)
            .map_err(|e| UploadModeError::PreparationError(e.to_string()))?;

        let len = reader.len();
        let created = Utc::now();

        let (response, data_size, cost) = self
            .client
            .turbo_upload(&item, reader, len)
            .await
            .map_err(|e| UploadModeError::UploadError(e.to_string()))?;

        Ok(UploadDetails {
            created,
            uploaded: response.timestamp,
            data_size: ByteSize::b(data_size),
            cost,
            item_id: response.id.into(),
        })
    }
}

#[async_trait]
pub trait UploadMode {
    fn mode(&self) -> Mode;
    async fn current_price(&self, data_size: ByteSize) -> Result<Money<Winston>, UploadModeError>;
    async fn balance(&self) -> Result<Money<Winston>, UploadModeError>;
    async fn submit(
        &mut self,
        drive_id: &DriveId,
        bundler: AsyncBundler<AcceptingItems>,
    ) -> Result<UploadDetails, UploadModeError>;
}
#[derive(Copy, Clone, PartialEq)]
pub enum Status {
    Pending,
    Success,
    Error,
}

impl Display for Status {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Pending => "Pending",
                Self::Success => "Success",
                Self::Error => "Error",
            }
        )
    }
}

impl FromStr for Status {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("P") {
            Ok(Status::Pending)
        } else if s.eq_ignore_ascii_case("S") {
            Ok(Status::Success)
        } else if s.eq_ignore_ascii_case("E") {
            Ok(Status::Error)
        } else {
            Err(s.to_string())
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum Mode {
    Direct,
    Turbo,
}

impl Display for Mode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Direct => "Direct",
                Self::Turbo => "Turbo",
            }
        )
    }
}

pub struct UploadDetails {
    pub created: DateTime<Utc>,
    pub uploaded: DateTime<Utc>,
    pub data_size: ByteSize,
    pub cost: Money<Winston>,
    pub item_id: ItemId,
}

struct AsyncTempFile<T> {
    inner: T,
    temp_file: Arc<NamedTempFile>,
    parent_dir: Arc<TempDir>,
}

impl AsyncTempFile<Compat<tokio::fs::File>> {
    pub async fn create_rw(parent_dir: Arc<TempDir>) -> Result<Self, std::io::Error> {
        let temp_file = Arc::new({
            let work_dir = parent_dir.clone();
            unblock(move || NamedTempFile::new_in(work_dir.path())).await?
        });
        Ok(Self::new(
            tokio::fs::File::options()
                .create(true)
                .write(true)
                .open(temp_file.path())
                .await?
                .compat_write(),
            temp_file.clone(),
            parent_dir,
        ))
    }

    pub async fn open_ro(
        temp_file: Arc<NamedTempFile>,
        parent_dir: Arc<TempDir>,
    ) -> Result<Self, std::io::Error> {
        Ok(Self::new(
            tokio::fs::File::options()
                .read(true)
                .open(temp_file.path())
                .await?
                .compat_write(),
            temp_file.clone(),
            parent_dir,
        ))
    }
}

impl<T> AsyncTempFile<T> {
    fn new(inner: T, temp_file: Arc<NamedTempFile>, parent_dir: Arc<TempDir>) -> Self {
        Self {
            inner,
            temp_file,
            parent_dir,
        }
    }

    pub fn into_parts(self) -> (T, Arc<NamedTempFile>, Arc<TempDir>) {
        (self.inner, self.temp_file, self.parent_dir)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for AsyncTempFile<T> {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }

    #[inline]
    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read_vectored(cx, bufs)
    }
}

impl<T: AsyncSeek + Unpin> AsyncSeek for AsyncTempFile<T> {
    #[inline]
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<std::io::Result<u64>> {
        Pin::new(&mut self.inner).poll_seek(cx, pos)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for AsyncTempFile<T> {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
