use arfs::{ArFs, CacheSettings, DriveId, Scope};
use ario_client::{Cache, Client};
use ario_core::Gateway;
use ario_core::wallet::WalletAddress;
use ars3nal::{Server, ServerHandle, ServerStatus};
use foyer_cache::{FoyerChunkCache, FoyerMetadataCache};
use futures_lite::StreamExt;
use std::str::FromStr;
use std::time::Duration;
use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();
    let (filter, _) = tracing_subscriber::reload::Layer::new(filter);

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::Layer::default())
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()?;
    rt.block_on(run())?;
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let client = Client::builder()
        .gateways([
            //Gateway::from_str("https://permagate.io")?,
            Gateway::default(),
            Gateway::from_str("https://ar-io-gateway.svc.blacksand.xyz")?,
        ])
        .enable_netwatch(false)
        .cache(
            Cache::builder()
                .chunk_l2_cache(
                    FoyerChunkCache::builder()
                        .disk_path(std::env::var("ARTEST_L2_CHUNK_CACHE_PATH")?)
                        .max_disk_space(1024 * 1024 * 100)
                        .build()
                        .await?,
                )
                .metadata_l2_cache(
                    FoyerMetadataCache::builder()
                        .disk_path(std::env::var("ARTEST_L2_METADATA_CACHE_PATH")?)
                        .max_disk_space(1024 * 1024 * 25)
                        .build()
                        .await?,
                )
                .build(),
        )
        .build()
        .await?;

    let mut server = Server::builder().build().await?;

    let drive_1_owner = WalletAddress::from_str("HGoC7PVku6TzOh0SsITsWMJW8iUcOcdGmPaKm3IhvJQ")?;
    let drive_1_id = DriveId::from_str("d669b973-d9d2-430d-b2cc-96072054dc1a")?;

    let arfs = ArFs::builder()
        .client(client.clone())
        .drive_id(drive_1_id)
        .db_dir("/tmp/foo/")
        .scope(Scope::public(drive_1_owner.clone()))
        .cache_settings(
            CacheSettings::builder()
                .path_cache_ttl(Duration::from_secs(7200))
                .build(),
        )
        .build()
        .await?;

    server.insert_bucket("test", arfs)?;

    let drive_2_owner = WalletAddress::from_str("2v22SB6hwA_QuXDlXyYRr9nkhwxop1iPXT_ViGLwOwA")?;
    let drive_2_id = DriveId::from_str("2e7952b2-6246-41dc-9ee9-fcc138723001")?;

    let arfs2 = ArFs::builder()
        .client(client.clone())
        .drive_id(drive_2_id)
        .db_dir("/tmp/foo/")
        .scope(Scope::public(drive_2_owner.clone()))
        .build()
        .await?;

    server.insert_bucket("test2", arfs2)?;

    let drive_3_owner = WalletAddress::from_str("m6eeNI_nADsDdGnpJmy3acX_VurlU_nMLTi05789cl0")?;
    let drive_3_id = DriveId::from_str("680630e3-64b0-4c11-8150-d7929619db48")?;

    let arfs3 = ArFs::builder()
        .client(client.clone())
        .drive_id(drive_3_id)
        .db_dir("/tmp/foo/")
        .scope(Scope::public(drive_3_owner.clone()))
        .build()
        .await?;

    server.insert_bucket("test3", arfs3)?;

    let handle = server.serve();
    let mut status = handle.status();

    let shutdown = tokio::spawn(shutdown_listener(RunGuard(handle.clone())));

    notify_ready().await;

    while let Some(status) = status.next().await {
        match status {
            ServerStatus::Serving => {
                tracing::debug!("received server status: serving");
            }
            ServerStatus::ShuttingDown => {
                tracing::info!("server shutting down");
                notify_stopping().await;
            }
            ServerStatus::Finished => {
                break;
            }
        }
    }

    shutdown.abort();

    tracing::info!("server shutdown complete");

    Ok(())
}

#[repr(transparent)]
struct RunGuard(ServerHandle);

impl Drop for RunGuard {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

#[cfg(target_os = "linux")]
async fn notify_ready() {
    let _ = tokio::task::spawn_blocking(|| {
        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    })
    .await;
}

#[cfg(target_os = "linux")]
async fn notify_stopping() {
    let _ = tokio::task::spawn_blocking(|| {
        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
    })
    .await;
}

#[cfg(not(target_os = "linux"))]
async fn notify_ready() {}

#[cfg(not(target_os = "linux"))]
async fn notify_stopping() {}

#[cfg(unix)]
fn shutdown_listener(guard: RunGuard) -> impl Future<Output = ()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();

    async move {
        let _guard = guard;
        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("SIGINT received, shutting down")
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, shutting down")
            }
        }
        notify_stopping().await;
    }
}

#[cfg(windows)]
fn shutdown_listener(guard: RunGuard) -> impl Future<Output = ()> {
    use tokio::signal::windows::ctrl_break;
    use tokio::signal::windows::ctrl_c;
    use tokio::signal::windows::ctrl_close;

    let mut ctrl_c = ctrl_c()?;
    let mut ctrl_close = ctrl_close()?;
    let mut ctrl_break = ctrl_break()?;

    async move {
        let _guard = guard;
        tokio::select! {
            _ = ctrl_c.recv() => {
                tracing::info!("CTRL_C received, shutting down")
            }
            _ = ctrl_close.recv() => {
                tracing::info!("CTRL_CLOSE received, shutting down")
            }
            _ = ctrl_break.recv() => {
                tracing::info!("CTRL_BREAK received, shutting down")
            }
        }
    }
}
