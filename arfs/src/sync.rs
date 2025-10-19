use crate::db::Db;
use crate::types::drive::{DriveEntity, DriveId};
use crate::types::file::{FileEntity, FileKind};
use crate::types::folder::{FolderEntity, FolderId, FolderKind};
use crate::types::{ArfsEntity, ArfsEntityId};
use crate::{Private, Public, resolve};
use ario_client::Client;
use ario_core::BlockNumber;
use ario_core::wallet::WalletAddress;
use async_stream::stream;
use chrono::{DateTime, Utc};
use futures_lite::{Stream, StreamExt};
use std::cmp::max;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

#[derive(Error, Debug)]
pub enum Error {
    #[error("mode is unsupported: {0}")]
    UnsupportedMode(String),
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
    pub insertions: usize,
    pub deletions: usize,
    pub block: BlockNumber,
}

#[derive(Debug)]
pub struct Syncer {
    client: Client,
    db: Db,
    status_rx: watch::Receiver<Status>,
    task_handle: JoinHandle<Result<(), Error>>,
    task_ct: CancellationToken,
    _drop_guard: DropGuard,
}

impl Syncer {
    pub(crate) async fn new<PRIVACY: Send + Sync + 'static>(
        client: Client,
        db: Db,
        privacy: Arc<PRIVACY>,
        sync_interval: Duration,
        min_initial_wait: Duration,
    ) -> Result<Self, crate::Error>
    where
        BackgroundTask<PRIVACY>: SyncNow,
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
            last_sync,
            next_sync: next_sync.clone(),
        });

        let task_ct = root_ct.child_token();
        let task = BackgroundTask::new(
            client.clone(),
            db.clone(),
            privacy,
            task_ct.clone(),
            status_tx,
            next_sync,
            sync_interval,
        );
        let task_handle = tokio::spawn(async move { task.run().await });

        Ok(Self {
            client,
            db,
            status_rx,
            task_handle,
            task_ct,
            _drop_guard: root_ct.drop_guard(),
        })
    }

    pub fn status(&self) -> impl Stream<Item = Status> + Send + Unpin {
        let mut rx = self.status_rx.clone();
        let mut ct = self.task_ct.clone();

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
}

impl Drop for Syncer {
    fn drop(&mut self) {
        self.task_handle.abort();
    }
}

#[derive(Debug, Clone)]
pub enum Status {
    Idle {
        last_sync: Option<LogEntry>,
        next_sync: DateTime<Utc>,
    },
    Syncing {
        start_time: DateTime<Utc>,
    },
    Dead,
}

trait SyncNow {
    fn sync(&mut self) -> impl Future<Output = Result<Success, crate::Error>> + Send;
}

struct BackgroundTask<PRIVACY> {
    client: Client,
    db: Db,
    privacy: Arc<PRIVACY>,
    ct: CancellationToken,
    status_tx: watch::Sender<Status>,
    next_sync: DateTime<Utc>,
    sync_interval: Duration,
}

impl<PRIVACY> BackgroundTask<PRIVACY> {
    fn new(
        client: Client,
        db: Db,
        privacy: Arc<PRIVACY>,
        ct: CancellationToken,
        status_tx: watch::Sender<Status>,
        next_sync: DateTime<Utc>,
        sync_interval: Duration,
    ) -> Self {
        Self {
            client,
            db,
            privacy,
            ct,
            status_tx,
            next_sync,
            sync_interval,
        }
    }

    #[tracing::instrument(name = "background_run", skip(self))]
    async fn run(mut self) -> Result<(), Error>
    where
        Self: SyncNow,
    {
        loop {
            let next_sync_in = (self.next_sync - Utc::now())
                .to_std()
                .ok()
                .unwrap_or_default();

            tracing::debug!(
                next_sync_in_ms = next_sync_in.as_millis(),
                "sleeping until next sync"
            );
            tokio::select! {
                _ = tokio::time::sleep(next_sync_in) => {
                    let start_time = Utc::now();
                    let _ = self.status_tx.send(Status::Syncing {
                        start_time
                    });
                    let result = self.sync().await;
                    let duration = (Utc::now() - start_time).to_std().ok().unwrap_or_default();
                    self.next_sync = Utc::now() + self.sync_interval;

                    let result = match result {
                        Ok(success) => {
                            tracing::debug!(start_time = %start_time, duration_ms = duration.as_millis(), "sync ok");
                            SyncResult::OK(success)
                        },
                        Err(err) => {
                            tracing::error!(error = %err, start_time = %start_time, duration_ms = duration.as_millis(), "sync error");
                            SyncResult::Error(Some(err.to_string()))
                        }
                    };

                    let log_entry = LogEntry {
                        start_time,
                        duration,
                        result,
                    };

                    if let Err(err) = self.update_log(&log_entry).await {
                        tracing::error!(error= %err, "update_log failed");
                    }

                    let _ = self.status_tx.send(Status::Idle {
                        last_sync: Some(log_entry),
                        next_sync: self.next_sync,
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

    #[tracing::instrument(name = "update_log", skip(self, log_entry))]
    async fn update_log(&self, log_entry: &LogEntry) -> Result<(), crate::Error> {
        let mut tx = self.db.write().await?;
        tx.sync_log_entry(&log_entry).await?;
        tx.commit().await?;
        Ok(())
    }
}

impl SyncNow for BackgroundTask<Public> {
    #[tracing::instrument(name = "background_sync_public", skip(self))]
    async fn sync(&mut self) -> Result<Success, crate::Error> {
        self._sync(&self.privacy.owner, None).await
    }
}

impl SyncNow for BackgroundTask<Private> {
    #[tracing::instrument(name = "background_sync_private", skip(self))]
    async fn sync(&mut self) -> Result<Success, crate::Error> {
        Err(Error::UnsupportedMode(
            "private drives are not yet supported".to_string(),
        ))?
    }
}

impl<PRIVACY> BackgroundTask<PRIVACY> {
    #[tracing::instrument(skip(self))]
    async fn current_block_height(&self) -> Result<BlockNumber, crate::Error> {
        Ok(self.client.any_gateway_info().await?.height)
    }

    #[tracing::instrument(skip(self))]
    async fn _sync(
        &self,
        owner: &WalletAddress,
        private: Option<&Private>,
    ) -> Result<Success, crate::Error> {
        tracing::debug!("starting sync");
        let current_drive_config = self.db.read().await?.config().await?;

        let current_block_height = self.current_block_height().await?;
        let latest_drive = self
            .find_latest_drive(
                current_drive_config.drive.id(),
                &current_drive_config.owner,
                None,
            )
            .await?;

        let mut active: HashSet<ArfsEntityId> = [current_drive_config.drive.id().clone().into()]
            .into_iter()
            .collect();

        let mut folders = VecDeque::new();
        folders.push_back(latest_drive.root_folder().clone());

        loop {
            let folder = match folders.pop_front() {
                Some(folder) => folder,
                None => break,
            };

            let mut stream = resolve::find_entity_ids_by_parent_folder(
                &self.client,
                current_drive_config.drive.id(),
                owner,
                private,
                &folder,
            );
            while let Some(entity_id) = stream.try_next().await? {
                match entity_id {
                    ArfsEntityId::File(file_id) => {
                        active.insert(file_id.into());
                    }
                    ArfsEntityId::Folder(folder_id) => {
                        folders.push_back(folder_id);
                    }
                    _ => {} // ignore
                }
            }

            active.insert(folder.into());
        }

        let mut obsolete = vec![];
        let mut present = vec![];

        {
            let mut conn = self.db.read().await?;
            let mut stream = &mut conn.entity_ids().await?;
            while let Some(id) = stream.try_next().await? {
                if !active.contains(&id) {
                    obsolete.push(id);
                } else {
                    present.push(id);
                }
            }
        }

        let new = active
            .into_iter()
            .filter(|id| !present.contains(id))
            .collect::<Vec<_>>();

        let mut new_files = vec![];
        let mut new_folders = vec![];

        for entity_id in new {
            match entity_id {
                ArfsEntityId::File(file_id) => {
                    let location = resolve::find_entity_location_by_id_drive::<FileKind>(
                        &self.client,
                        &file_id,
                        current_drive_config.drive.id(),
                    )
                    .await?;
                    new_files.push(
                        resolve::file_entity(
                            &file_id,
                            &self.client,
                            &location,
                            current_drive_config.drive.id(),
                            owner,
                            private,
                        )
                        .await?,
                    );
                }
                ArfsEntityId::Folder(folder_id) => {
                    let location = resolve::find_entity_location_by_id_drive::<FolderKind>(
                        &self.client,
                        &folder_id,
                        current_drive_config.drive.id(),
                    )
                    .await?;
                    new_folders.push(
                        resolve::folder_entity(
                            &folder_id,
                            &self.client,
                            &location,
                            current_drive_config.drive.id(),
                            owner,
                            private,
                        )
                        .await?,
                    );
                }
                _ => {} // ignore
            }
        }

        let (insertions, deletions) = self.update(obsolete, new_files, new_folders).await?;

        Ok(Success {
            insertions,
            deletions,
            block: current_block_height,
        })
    }

    #[tracing::instrument(skip(self, obsolete, new_files, new_folders))]
    async fn update(
        &self,
        obsolete: Vec<ArfsEntityId>,
        new_files: Vec<FileEntity>,
        new_folders: Vec<FolderEntity>,
    ) -> Result<(usize, usize), crate::Error> {
        let mut tx = self.db.write().await?;
        let (insertions, deletions, affected_inode_ids) =
            tx.sync_update(&obsolete, &new_files, &new_folders).await?;
        tx.commit().await?;
        Ok((insertions, deletions))
    }

    #[tracing::instrument(skip(self))]
    async fn find_latest_drive(
        &self,
        drive_id: &DriveId,
        owner: &WalletAddress,
        private: Option<&Private>,
    ) -> Result<DriveEntity, crate::Error> {
        tracing::debug!("finding latest drive entity");
        resolve::find_drive_by_id_owner(&self.client, drive_id, owner, private).await
    }
}
