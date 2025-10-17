use crate::db::Db;
use crate::types::drive::{DriveEntity, DriveId};
use crate::{Private, Public, resolve};
use ario_client::Client;
use ario_core::BlockNumber;
use ario_core::wallet::WalletAddress;
use chrono::{DateTime, Utc};
use std::cmp::max;
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
    pub modifications: usize,
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

    pub fn status(&self) -> Status {
        if self.task_ct.is_cancelled() {
            Status::Dead
        } else {
            self.status_rx.borrow().clone()
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

    #[tracing::instrument(name = "update_log", skip(self))]
    async fn update_log(&self, log_entry: &LogEntry) -> Result<(), crate::Error> {
        tracing::debug!("starting sync");
        let mut tx = self.db.write().await?;
        tx.sync_log_entry(&log_entry).await?;
        tx.commit().await?;
        Ok(())
    }
}

impl SyncNow for BackgroundTask<Public> {
    #[tracing::instrument(name = "background_sync_public", skip(self))]
    async fn sync(&mut self) -> Result<Success, crate::Error> {
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

        println!("");
        todo!()
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
    async fn find_latest_drive<'a>(
        &self,
        drive_id: &'a DriveId,
        owner: &'a WalletAddress,
        private: Option<&'a Private>,
    ) -> Result<DriveEntity, crate::Error> {
        tracing::debug!("finding latest drive entity");
        resolve::find_drive_by_id_owner(&self.client, drive_id, owner, private).await
    }
}
