mod db;
pub(crate) mod upload;

use crate::db::Db;
use crate::types::drive::{DriveEntity, DriveId};
use crate::types::file::FileKind;
use crate::types::folder::{FolderEntity, FolderKind};
use crate::types::{ArfsEntity, ArfsEntityId};
use crate::vfs::{InodeError, InodeId};
use crate::{
    Inode, KeyRing, Private, Public, ReadOnly, ReadWrite, State, SyncLimit, UploadLimit,
    UploadService, Vfs, resolve,
};
use ario_client::Client;
use ario_client::graphql::BlockRange;
use ario_core::BlockNumber;
use ario_core::wallet::{Wallet, WalletAddress};
use async_stream::{stream, try_stream};
use chrono::{DateTime, Utc};
use futures_lite::{AsyncReadExt, Stream, StreamExt};
use std::cmp::{max, min};
use std::collections::{HashSet, VecDeque};
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::time::FutureExt;

#[derive(Error, Debug)]
pub enum Error {
    #[error("mode is unsupported: {0}")]
    UnsupportedMode(String),
    #[error("syncer is dead or shutting down")]
    SyncerDead,
    #[error("syncer state is invalid")]
    InvalidState,
    #[error("syncer not starting")]
    StartFailure,
    #[error("unable to acquire sync permit")]
    PermitAcquisitionFailed,
    #[error("acquiring tx timed out")]
    TxAcquisitionTimeout,
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub start_time: DateTime<Utc>,
    pub duration: Duration,
    pub result: SyncResult,
}

#[derive(Debug, Clone)]
pub enum SyncResult {
    OK(Success),
    Error(Option<String>),
}

#[derive(Debug, Clone)]
pub struct Success {
    pub updates: usize,
    pub insertions: usize,
    pub deletions: usize,
    pub block: BlockNumber,
}

#[derive(Debug)]
pub struct Syncer {
    status_rx: watch::Receiver<Status>,
    sync_trigger: mpsc::Sender<oneshot::Sender<()>>,
    task_handle: JoinHandle<Result<(), Error>>,
    task_ct: CancellationToken,
    _drop_guard: DropGuard,
}

impl Syncer {
    pub(crate) async fn new<PRIVACY: Send + Sync + 'static, MODE: Send + Sync + 'static>(
        client: Client,
        db: Db,
        drive_id: DriveId,
        vfs: Vfs,
        privacy: Arc<PRIVACY>,
        mode: Arc<MODE>,
        sync_interval: Duration,
        min_initial_wait: Duration,
        sync_limit: SyncLimit,
        proactive_cache_interval: Option<Duration>,
        upload_limit: UploadLimit,
        upload_batch_settle_time: Duration,
    ) -> Result<Self, crate::Error>
    where
        BackgroundTask<PRIVACY, MODE>: SyncNow,
        BackgroundTask<PRIVACY, MODE>: CacheNow,
        BackgroundTask<PRIVACY, MODE>: UploadNow,
    {
        let root_ct = CancellationToken::new();

        let earliest_sync = Utc::now() + min_initial_wait;
        let last_sync = db.read().await?.latest_sync_log_entry().await?;
        let next_sync = match last_sync.as_ref() {
            Some(log) => {
                let next_sync = log.start_time + log.duration + sync_interval;
                max(next_sync, earliest_sync)
            }
            None => earliest_sync,
        };

        let (status_tx, status_rx) = watch::channel(Status::Idle {
            last_activity: last_sync.map(|l| Activity::Sync { log_entry: l }),
            next_activity: next_sync.clone(),
        });

        let (sync_trigger, sync_trigger_rx) = mpsc::channel(1);

        let task_ct = root_ct.child_token();
        let task = BackgroundTask::new(
            client,
            db,
            drive_id,
            vfs,
            privacy,
            mode,
            task_ct.clone(),
            status_tx,
            sync_trigger_rx,
            next_sync,
            sync_interval,
            sync_limit,
            upload_limit,
            proactive_cache_interval,
            upload_batch_settle_time,
        );
        let task_handle = tokio::spawn(async move { task.run().await });

        Ok(Self {
            status_rx,
            sync_trigger,
            task_handle,
            task_ct,
            _drop_guard: root_ct.drop_guard(),
        })
    }

    pub fn status(&self) -> impl Stream<Item = Status> + Send + Unpin {
        let mut rx = self.status_rx.clone();
        let ct = self.task_ct.clone();

        Box::pin(stream! {
            yield if ct.is_cancelled() {
                Status::Dead
            } else {
                rx.borrow_and_update().clone()
            };

            loop {
                tokio::select! {
                    _ = ct.cancelled() => {
                        break;
                    }
                    _ = rx.changed() => {
                        let status = rx.borrow_and_update().clone();
                        yield status;
                    }
                }
            }
            yield Status::Dead;
        })
    }

    pub async fn sync_now(&self) -> Result<SyncResult, crate::Error> {
        enum State {
            Default,
            ExpectSyncing,
            Syncing,
            Uploading,
            ProactiveCaching,
        }

        if self.task_ct.is_cancelled() {
            Err(Error::SyncerDead)?;
        }

        let mut status_rx = self.status_rx.clone();
        let mut sync_state = State::Default;
        let mut status = status_rx.borrow_and_update().clone();
        loop {
            match status {
                Status::Dead => {
                    return Err(Error::SyncerDead)?;
                }
                Status::Syncing { .. } => sync_state = State::Syncing,
                Status::Uploading { .. } => sync_state = State::Uploading,
                Status::ProactiveCaching { .. } => sync_state = State::ProactiveCaching,
                Status::Idle {
                    last_activity: last_sync,
                    ..
                } => {
                    match sync_state {
                        State::ExpectSyncing | State::Uploading | State::ProactiveCaching => {
                            return Err(Error::StartFailure)?;
                        }
                        State::Syncing => {
                            // completed
                            return Ok(last_sync
                                .map(|a| match a {
                                    Activity::Sync { log_entry } => Some(log_entry),
                                    _ => None,
                                })
                                .flatten()
                                .ok_or_else(|| Error::InvalidState)?
                                .result);
                        }
                        State::Default => {
                            // initiate sync
                            let (ack_tx, ack_rx) = oneshot::channel();
                            match self.sync_trigger.try_send(ack_tx) {
                                Ok(()) => {
                                    // waiting for ack
                                    if let Err(_) = ack_rx.await {
                                        // syncer is gone
                                        return Err(Error::SyncerDead)?;
                                    }
                                }
                                Err(TrySendError::Closed(_)) => {
                                    // syncer is gone
                                    return Err(Error::SyncerDead)?;
                                }
                                Err(TrySendError::Full(_)) => {
                                    // syncer already triggered
                                }
                            }
                            sync_state = State::ExpectSyncing;
                        }
                    }
                }
            }

            status_rx.changed().await.map_err(|_| Error::SyncerDead)?;
            status = status_rx.borrow_and_update().clone();
        }
    }
}

impl Drop for Syncer {
    fn drop(&mut self) {
        self.task_handle.abort();
    }
}

#[derive(Debug, Clone)]
pub enum Status {
    Idle {
        last_activity: Option<Activity>,
        next_activity: DateTime<Utc>,
    },
    Syncing {
        start_time: DateTime<Utc>,
    },
    ProactiveCaching {
        start_time: DateTime<Utc>,
    },
    Uploading {
        start_time: DateTime<Utc>,
    },
    Dead,
}

#[derive(Debug, Clone)]
pub enum Activity {
    Sync { log_entry: LogEntry },
    ProactiveCaching,
    Uploading,
}

trait CacheNow {
    fn cache(&mut self)
    -> impl Future<Output = Result<Option<DateTime<Utc>>, crate::Error>> + Send;
}

trait SyncNow {
    fn sync(&mut self) -> impl Future<Output = Result<Option<Success>, crate::Error>> + Send;
}

trait UploadNow {
    fn initial_upload_pause() -> Duration;
    fn upload(
        &mut self,
    ) -> impl Future<Output = Result<Option<DateTime<Utc>>, crate::Error>> + Send;
}

struct BackgroundTask<PRIVACY, MODE> {
    client: Client,
    db: Db,
    drive_id: DriveId,
    vfs: Vfs,
    privacy: Arc<PRIVACY>,
    mode: Arc<MODE>,
    ct: CancellationToken,
    status_tx: watch::Sender<Status>,
    sync_trigger: mpsc::Receiver<oneshot::Sender<()>>,
    next_upload: DateTime<Utc>,
    next_sync: DateTime<Utc>,
    next_cache: DateTime<Utc>,
    proactive_cache_interval: Option<Duration>,
    sync_interval: Duration,
    sync_limit: SyncLimit,
    upload_limit: UploadLimit,
    upload_batch_settle_time: Duration,
}

impl<PRIVACY, MODE> BackgroundTask<PRIVACY, MODE> {
    fn new(
        client: Client,
        db: Db,
        drive_id: DriveId,
        vfs: Vfs,
        privacy: Arc<PRIVACY>,
        mode: Arc<MODE>,
        ct: CancellationToken,
        status_tx: watch::Sender<Status>,
        sync_trigger: mpsc::Receiver<oneshot::Sender<()>>,
        next_sync: DateTime<Utc>,
        sync_interval: Duration,
        sync_limit: SyncLimit,
        upload_limit: UploadLimit,
        proactive_cache_interval: Option<Duration>,
        upload_batch_settle_time: Duration,
    ) -> Self
    where
        Self: UploadNow,
    {
        let next_cache = match proactive_cache_interval.as_ref() {
            Some(_) => Utc::now() + Duration::from_secs(60), // proactive caching enabled,
            None => Utc::now() + Duration::from_secs(86400 * 365 * 1000), // proactive caching disabled,
        };

        let next_upload = Utc::now() + Self::initial_upload_pause();

        Self {
            client,
            db,
            drive_id,
            vfs,
            privacy,
            mode,
            ct,
            status_tx,
            sync_trigger,
            next_upload,
            next_sync,
            next_cache,
            proactive_cache_interval,
            sync_interval,
            sync_limit,
            upload_limit,
            upload_batch_settle_time,
        }
    }

    #[tracing::instrument(name = "background_run", skip(self))]
    async fn run(mut self) -> Result<(), Error>
    where
        Self: SyncNow,
        Self: CacheNow,
        Self: UploadNow,
    {
        loop {
            let next_upload_in = (self.next_upload - Utc::now())
                .to_std()
                .ok()
                .unwrap_or_default();

            let next_sync_in = (self.next_sync - Utc::now())
                .to_std()
                .ok()
                .unwrap_or_default();

            let next_cache_in = (self.next_cache - Utc::now())
                .to_std()
                .ok()
                .unwrap_or_default();

            tracing::debug!(
                next_activity_in_ms = next_sync_in
                    .as_millis()
                    .min(next_cache_in.as_millis())
                    .min(next_upload_in.as_millis()),
                "sleeping until next sync / upload / proactive caching"
            );
            tokio::select! {
                ack = self.sync_trigger.recv() => {
                    if let Some(ack) = ack {
                        if let Ok(_) = ack.send(()) {
                            // still active, starting sync now
                            self.next_sync = Utc::now();
                            continue;
                        }
                    }
                }
                _ = tokio::time::sleep(next_cache_in) => {
                    let start_time = Utc::now();
                    let _ = self.status_tx.send(Status::ProactiveCaching {
                        start_time
                    });

                    let next_cache_in = match self.cache().await {
                        Ok(Some(next)) => {
                            max(next.signed_duration_since(Utc::now()).to_std().unwrap_or_default(), Duration::from_secs(1))
                        }
                        Ok(None) => {
                            Duration::from_secs(900)
                        }
                        Err(err) => {
                            tracing::error!(error= %err, "proactive caching failed");
                            Duration::from_secs(900)
                        }
                    };

                    self.next_cache = Utc::now() + next_cache_in;

                    let _ = self.status_tx.send(Status::Idle {
                        last_activity: Some(Activity::ProactiveCaching),
                        next_activity: self.next_activity(),
                    });
                }
                _ = tokio::time::sleep(next_sync_in) => {
                    let start_time = Utc::now();
                    let previous_activity = match &*self.status_tx.borrow() {
                        Status::Idle {last_activity, ..} => last_activity.as_ref().map(|a| a.clone()),
                        _ => None
                    };

                    let _ = self.status_tx.send(Status::Syncing {
                        start_time
                    });
                    let result = self.sync().await;
                    let duration = (Utc::now() - start_time).to_std().ok().unwrap_or_default();
                    self.next_sync = Utc::now() + self.sync_interval;

                    let result = match result {
                        Ok(Some(success)) => {
                            if success.insertions > 0 || success.deletions > 0 || success.updates > 0 {
                                // vfs modified
                                if self.proactive_cache_interval.is_some() {
                                    // trigger proactive caching if enabled
                                    self.next_cache = Utc::now() + Duration::from_secs(60);
                                }
                            }
                            tracing::debug!(start_time = %start_time, duration_ms = duration.as_millis(), "sync ok");
                            Some(SyncResult::OK(success))
                        },
                        Ok(None) => {
                            tracing::info!("syncing currently unavailable");
                            None
                        }
                        Err(err) => {
                            tracing::error!(error = %err, start_time = %start_time, duration_ms = duration.as_millis(), "sync error");
                            Some(SyncResult::Error(Some(err.to_string())))
                        }
                    };

                    let last_activity = if let Some(result) = result {
                        let log_entry = LogEntry {
                            start_time,
                            duration,
                            result,
                        };

                        if let Err(err) = self.update_log(&log_entry).await {
                            tracing::error!(error= %err, "update_log failed");
                        }
                        Some(Activity::Sync { log_entry })
                    } else {
                        previous_activity
                    };

                    let _ = self.status_tx.send(Status::Idle {
                        last_activity,
                        next_activity: self.next_activity(),
                    });
                }
                _ = tokio::time::sleep(next_upload_in) => {
                    let start_time = Utc::now();
                    let _ = self.status_tx.send(Status::Uploading {
                        start_time
                    });

                    let next_upload_in = match self.upload().await {
                        Ok(Some(next)) => {
                            max(next.signed_duration_since(Utc::now()).to_std().unwrap_or_default(), Duration::from_secs(1))
                        }
                        Ok(None) => {
                            Duration::from_secs(300)
                        }
                        Err(err) => {
                            tracing::error!(error= %err, "uploading failed");
                            Duration::from_secs(300)
                        }
                    };

                    self.next_upload = Utc::now() + next_upload_in;

                    let _ = self.status_tx.send(Status::Idle {
                        last_activity: Some(Activity::Uploading),
                        next_activity: self.next_activity(),
                    });
                }
                _ = self.ct.cancelled() => {
                    tracing::debug!("cancellation detected");
                    // shutting down
                    break;
                },
            }
        }
        tracing::debug!("end of main loop reached");
        tracing::info!("shutting down");

        Ok(())
    }

    fn next_activity(&self) -> DateTime<Utc> {
        min(self.next_sync, self.next_cache).min(self.next_upload)
    }

    #[tracing::instrument(name = "update_log", skip(self, log_entry))]
    async fn update_log(&self, log_entry: &LogEntry) -> Result<(), crate::Error> {
        let mut tx = self.db.write().await?;
        tx.sync_log_entry(&log_entry).await?;
        tx.commit().await?;
        Ok(())
    }
}

impl<MODE: Send + Sync> CacheNow for BackgroundTask<Public, MODE> {
    #[tracing::instrument(name = "background_proactive_caching_public", skip(self))]
    async fn cache(&mut self) -> Result<Option<DateTime<Utc>>, crate::Error> {
        self._cache(&self.privacy.owner, None).await
    }
}

impl<MODE: Send + Sync> CacheNow for BackgroundTask<Private, MODE> {
    #[tracing::instrument(name = "background_proactive_caching_private", skip(self))]
    async fn cache(&mut self) -> Result<Option<DateTime<Utc>>, crate::Error> {
        self._cache(&self.privacy.owner, Some(&self.privacy.key_ring))
            .await
    }
}

impl<MODE: Send + Sync> SyncNow for BackgroundTask<Public, MODE> {
    #[tracing::instrument(name = "background_sync_public", skip(self))]
    async fn sync(&mut self) -> Result<Option<Success>, crate::Error> {
        self._sync(&self.privacy.owner, None).await
    }
}

impl<MODE: Send + Sync> SyncNow for BackgroundTask<Private, MODE> {
    #[tracing::instrument(name = "background_sync_private", skip(self))]
    async fn sync(&mut self) -> Result<Option<Success>, crate::Error> {
        self._sync(&self.privacy.owner, Some(&self.privacy.key_ring))
            .await
    }
}

impl<PRIVACY: Send + Sync> UploadNow for BackgroundTask<PRIVACY, ReadOnly> {
    fn initial_upload_pause() -> Duration {
        Duration::from_secs(86400 * 365 * 30)
    }

    async fn upload(&mut self) -> Result<Option<DateTime<Utc>>, crate::Error> {
        // nothing to do here
        Ok(Some(Utc::now() + Duration::from_secs(86400 * 365 * 30)))
    }
}

impl UploadNow for BackgroundTask<Public, ReadWrite> {
    fn initial_upload_pause() -> Duration {
        Duration::from_secs(1)
    }

    #[tracing::instrument(name = "background_upload_public", skip(self))]
    async fn upload(&mut self) -> Result<Option<DateTime<Utc>>, crate::Error> {
        let wallet = self.mode.0.clone();
        let upload_service = self.mode.1.clone();
        self._upload(wallet, upload_service, None).await
    }
}

impl UploadNow for BackgroundTask<Private, ReadWrite> {
    fn initial_upload_pause() -> Duration {
        Duration::from_secs(120)
    }

    #[tracing::instrument(name = "background_upload_private", skip(self))]
    async fn upload(&mut self) -> Result<Option<DateTime<Utc>>, crate::Error> {
        let wallet = self.mode.0.clone();
        let upload_service = self.mode.1.clone();
        self._upload(wallet, upload_service, Some(self.privacy.key_ring.clone()))
            .await
    }
}

impl<PRIVACY, MODE> BackgroundTask<PRIVACY, MODE> {
    #[tracing::instrument(skip(self))]
    async fn current_block_height(&self) -> Result<BlockNumber, crate::Error> {
        Ok(self.client.any_gateway_info().await?.height)
    }

    #[tracing::instrument(fields(owner = %owner) skip(self))]
    async fn _sync(
        &self,
        owner: &WalletAddress,
        key_ring: Option<&KeyRing>,
    ) -> Result<Option<Success>, crate::Error> {
        tracing::debug!("waiting for sync permit");
        let _permit = self.sync_limit.acquire_permit().await?;

        tracing::debug!("acquiring write tx");
        let mut tx = self
            .db
            .write()
            .timeout(Duration::from_secs(60))
            .await
            .map_err(|_| Error::TxAcquisitionTimeout)??;

        let mut invalidate_all_caches = false;

        if tx.status().await?.state() == Some(State::Wal) {
            // check if all wal entries have been made permanent
            let uncommitted_cnt = tx.uncommitted_wal_entry_count().await?;
            if uncommitted_cnt > 0 {
                tracing::info!(
                    uncommitted_cnt,
                    "cannot sync now due to uncommitted wal entries"
                );
                return Ok(None);
            }
            tracing::debug!("discarding wal changes prior to syncing");
            tx.discard_wal_changes().await?;
            invalidate_all_caches = true;
        }

        tracing::debug!("starting sync");
        let current_drive_config = tx.config().await?;

        let current_block_height = self.current_block_height().await?;

        tx.set_synced_state(Utc::now(), current_block_height)
            .await?;

        let start_block_height = tx
            .last_sync_block_height()
            .await?
            .map(|b| b.increment(1))
            .unwrap_or_else(|| BlockNumber::from_inner(0));
        let block_range = BlockRange {
            start: start_block_height,
            end: current_block_height,
        };

        if block_range.start > block_range.end {
            tracing::info!("already in sync");
            return Ok(None);
        }

        let latest_drive = self
            .find_latest_drive(
                current_drive_config.drive.id(),
                &current_drive_config.owner,
                key_ring,
                block_range.end,
            )
            .await?;

        let stream = Box::pin(try_stream! {
            let mut folders_ids = VecDeque::new();
            folders_ids.push_back(latest_drive.root_folder().clone());

            let mut processed_entity_ids = Vec::new();

            loop {
                let parent_folder_id = match folders_ids.pop_front() {
                    Some(folder) => folder,
                    None => break,
                };

                let mut stream = resolve::find_entity_ids_by_parent_folder(
                    &self.client,
                    current_drive_config.drive.id(),
                    owner,
                    &parent_folder_id,
                    Some(block_range.clone()),
                );

                while let Some((entity_id, block)) = stream.try_next().await? {
                    // entities are processed newest-first
                    // hence any entity_id we've already seen before is outdated and can be skipped
                    if processed_entity_ids.contains(&entity_id) {
                        continue;
                    }
                    processed_entity_ids.push(entity_id.clone());

                    match entity_id {
                        ArfsEntityId::File(file_id) => {
                            let location = resolve::find_entity_location_by_id_drive::<FileKind>(
                                &self.client,
                                &file_id,
                                current_drive_config.drive.id(),
                                Some(block),
                            )
                            .await?;
                            let file = resolve::file_entity(
                                &file_id,
                                &self.client,
                                &location,
                                current_drive_config.drive.id(),
                                owner,
                                key_ring,
                            )
                            .await?;

                            if file.parent_folder() == &parent_folder_id {
                                yield ArfsEntity::File(file)
                            }
                        }
                        ArfsEntityId::Folder(folder_id) => {
                            let location = resolve::find_entity_location_by_id_drive::<FolderKind>(
                                &self.client,
                                &folder_id,
                                current_drive_config.drive.id(),
                                Some(block),
                            )
                            .await?;
                            let folder = resolve::folder_entity(
                                &folder_id,
                                &self.client,
                                &location,
                                current_drive_config.drive.id(),
                                owner,
                                key_ring,
                            )
                            .await?;

                            if folder.parent_folder() == Some(&parent_folder_id) {
                                if !folder.is_hidden() {
                                    folders_ids.push_back(folder.id().clone());
                                }
                                yield ArfsEntity::Folder(folder)
                            }
                        }
                        _ => {} // ignore
                    }
                }
            }
        });

        let (updates, insertions, deletions, affected_inode_ids) = tx.sync_update(stream).await?;
        tx.commit().await?;

        if invalidate_all_caches {
            self.vfs.invalidate_cache(None).await;
        } else if !affected_inode_ids.is_empty() {
            self.vfs.invalidate_cache(Some(affected_inode_ids)).await;
        }

        Ok(Some(Success {
            updates,
            insertions,
            deletions,
            block: current_block_height,
        }))
    }

    #[tracing::instrument(skip(self))]
    async fn find_latest_drive(
        &self,
        drive_id: &DriveId,
        owner: &WalletAddress,
        key_ring: Option<&KeyRing>,
        max_block: BlockNumber,
    ) -> Result<DriveEntity, crate::Error> {
        tracing::debug!("finding latest drive entity");
        resolve::find_drive_by_id_owner(&self.client, drive_id, owner, key_ring, Some(max_block))
            .await
    }

    #[tracing::instrument(skip(self))]
    async fn _cache(
        &self,
        owner: &WalletAddress,
        key_ring: Option<&KeyRing>,
    ) -> Result<Option<DateTime<Utc>>, crate::Error> {
        let min_cached_interval = self.proactive_cache_interval.unwrap_or_default();
        let min_attempt_interval = Duration::from_secs(3600 * 8);

        let cached_cutoff = Utc::now() - min_cached_interval;
        let attempt_cutoff = Utc::now() - min_attempt_interval;

        let (inode_id, last_success, next_attempt) = match self
            .db
            .read()
            .await?
            .next_proactive_cache_file(&cached_cutoff, &attempt_cutoff)
            .await?
        {
            Some((inode_id, last_success, last_attempt)) => {
                let now = Utc::now();
                let next_attempt = max(
                    last_success
                        .map(|ts| ts + min_cached_interval)
                        .unwrap_or_else(|| now),
                    last_attempt
                        .map(|ts| ts + min_attempt_interval)
                        .unwrap_or_else(|| now),
                );
                (inode_id, last_success, next_attempt)
            }
            None => {
                return Ok(None);
            }
        };

        if next_attempt > Utc::now() {
            return Ok(Some(next_attempt));
        }

        tracing::debug!(inode_id=%inode_id, "proactively caching file");
        let res = read_file(inode_id, &self.vfs).await;
        let ts = Utc::now();
        let last_success = if res.is_ok() { Some(ts) } else { last_success };
        let last_attempt = Some(ts);

        let mut tx = self.db.write().await?;
        tx.update_proactive_cache_file(inode_id, last_success.as_ref(), last_attempt.as_ref())
            .await?;
        tx.commit().await?;

        // looking for the next file

        let cached_cutoff = Utc::now() - min_cached_interval;
        let attempt_cutoff = Utc::now() - min_attempt_interval;

        Ok(
            match self
                .db
                .read()
                .await?
                .next_proactive_cache_file(&cached_cutoff, &attempt_cutoff)
                .await?
            {
                Some((_, last_success, last_attempt)) => {
                    let now = Utc::now();
                    let next_attempt = max(
                        last_success
                            .map(|ts| ts + min_cached_interval)
                            .unwrap_or_else(|| now),
                        last_attempt
                            .map(|ts| ts + min_attempt_interval)
                            .unwrap_or_else(|| now),
                    );
                    Some(next_attempt)
                }
                None => None,
            },
        )
    }
}

impl<PRIVACY> BackgroundTask<PRIVACY, ReadWrite> {
    #[tracing::instrument(skip_all)]
    async fn _upload(
        &mut self,
        wallet: Wallet,
        upload_service: UploadService,
        key_ring: Option<KeyRing>,
    ) -> Result<Option<DateTime<Utc>>, crate::Error> {
        tracing::debug!("waiting for upload permit");
        let _permit = self.upload_limit.acquire_permit().await?;

        tracing::debug!("acquiring write tx");
        let mut tx = self
            .db
            .write()
            .timeout(Duration::from_secs(60))
            .await
            .map_err(|_| Error::TxAcquisitionTimeout)??;

        if tx.status().await?.state() != Some(State::Wal) {
            tracing::debug!("not in wal mode, skipping upload processing");
            return Ok(None);
        }

        crate::db::clear_temp_tables(&mut tx).await?;

        let mut upload_service = match upload_service.lock().timeout(Duration::from_secs(3)).await {
            Ok(upload_service) => upload_service,
            Err(_) => {
                let retry = Duration::from_secs(60);
                tracing::debug!(
                    retry_in_ms = retry.as_millis(),
                    "unable to acquire upload_service lock, will retry later"
                );
                return Ok(Some(Utc::now() + retry));
            }
        };

        let next_pending = upload_service
            .process_pending(&mut tx, &self.drive_id)
            .await?;

        // only process new uploads if no existing ones are pending
        let next_new = if next_pending.is_none() {
            upload_service
                .process_new(
                    &mut tx,
                    &self.drive_id,
                    &wallet,
                    key_ring.as_ref(),
                    self.upload_batch_settle_time,
                )
                .await?
        } else {
            None
        };

        tx.delete_orphaned_entities().await?;
        let affected_inode_ids = crate::db::collect_affected_inode_ids(&mut tx).await?;
        crate::db::clear_temp_tables(&mut tx).await?;
        tx.commit().await?;

        if !affected_inode_ids.is_empty() {
            self.vfs.invalidate_cache(Some(affected_inode_ids)).await;
        }

        Ok(match (next_pending, next_new) {
            (None, Some(next)) | (Some(next), None) => Some(next),
            (Some(next_pending), Some(next_new)) => Some(min(next_pending, next_new)),
            (None, None) => None,
        })
    }
}

async fn read_file(inode_id: InodeId, vfs: &Vfs) -> Result<(), crate::Error> {
    let file = match vfs
        .inode_by_id(inode_id)
        .await?
        .ok_or_else(|| crate::vfs::Error::InodeError(InodeError::NotFound(inode_id)))?
    {
        Inode::File(file) => file,
        _ => Err(std::io::Error::new(ErrorKind::IsADirectory, "not a file"))?,
    };

    let mut fh = vfs.read_file(&file).await?;
    let mut buf = vec![0u8; 1024 * 8];
    loop {
        let read = fh.read(&mut buf).await?;
        if read == 0 {
            return Ok(());
        }
    }
}

fn sort_folders_by_dependency(folders: Vec<FolderEntity>) -> Vec<FolderEntity> {
    let mut remaining = folders.into_iter().collect::<VecDeque<_>>();
    let known = remaining
        .iter()
        .map(|f| f.id().clone())
        .collect::<HashSet<_>>();
    let mut processed = HashSet::with_capacity(remaining.len());
    let mut result = Vec::with_capacity(remaining.len());

    loop {
        match remaining.pop_front() {
            Some(folder) => {
                let process = match folder.parent_folder() {
                    None => true,
                    Some(parent) => {
                        if !known.contains(parent) {
                            true
                        } else {
                            processed.contains(parent)
                        }
                    }
                };

                if process {
                    processed.insert(folder.id().clone());
                    result.push(folder);
                } else {
                    remaining.push_back(folder);
                }
            }
            None => break,
        }
    }

    result
}
