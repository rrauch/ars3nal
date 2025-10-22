use arfs::{ArFs, DriveId, Scope};
use ario_client::Client;
use ario_core::Gateway;
use ario_core::wallet::WalletAddress;
use ars3nal::Server;
use std::str::FromStr;
use tower::Service;

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

    let drive_owner = WalletAddress::from_str("HGoC7PVku6TzOh0SsITsWMJW8iUcOcdGmPaKm3IhvJQ")?;
    let drive_id = DriveId::from_str("d669b973-d9d2-430d-b2cc-96072054dc1a")?;

    let arfs = ArFs::builder()
        .client(client.clone())
        .drive_id(drive_id)
        .db_dir("/tmp/foo/")
        .scope(Scope::public(drive_owner.clone()))
        .build()
        .await?;

    let mut server = Server::builder().build().await?;
    server.insert_bucket("test", arfs)?;

    let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());
    let ct = server.ct();
    let mut fut = std::pin::pin!(server.run());

    tokio::select! {
        res = fut => {
            // shutting down
            res?
        }
        _ = ctrl_c => {
            ct.cancel();
        }
    }

    Ok(())
}
