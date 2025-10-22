use arfs::{ArFs, DriveId, Scope};
use ario_client::Client;
use ario_core::Gateway;
use ario_core::wallet::WalletAddress;
use ars3nal::{Server, ServerStatus};
use futures_lite::StreamExt;
use std::str::FromStr;

fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()?;
    rt.block_on(run())?;
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let client = Client::builder()
        .gateways([Gateway::default()])
        .enable_netwatch(false)
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

    let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());
    let handle = server.serve();
    let mut status = handle.status();

    let mut shutting_down = false;

    loop {
        tokio::select! {
            status = status.next() => {
                match status {
                    Some(ServerStatus::Serving) => {
                        tracing::debug!("received server status: serving");
                    }
                    Some(ServerStatus::ShuttingDown) => {
                        tracing::info!("server shutting down");
                        shutting_down = true;
                    },
                    Some(ServerStatus::Finished) | None => {
                        break;
                    }
                }
            }
            _ = &mut ctrl_c, if !shutting_down => {
                handle.shutdown();
                shutting_down = true;
            }
        }
    }

    tracing::info!("server shutdown complete");

    Ok(())
}
