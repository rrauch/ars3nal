mod chunk;
mod disk_cache;
mod metadata;

pub use chunk::FoyerChunkCache;
pub use disk_cache::{DiskSpaceConfigError, Error, InvalidConfigError};
pub use foyer::Error as FoyerError;
pub use metadata::FoyerMetadataCache;

const DEFAULT_MEM_BUF_SIZE: usize = 1024 * 1024;

#[cfg(test)]
mod tests {
    use crate::{FoyerChunkCache, FoyerMetadataCache};
    use ario_client::location::BundleItemArl;
    use ario_client::{Cache, Client};
    use ario_core::Gateway;
    use ario_core::blob::Blob;
    use ario_core::bundle::BundleItemId;
    use ario_core::crypto::hash::{Hasher, Sha256, Sha256Hash};
    use ario_core::tx::TxId;
    use futures_lite::io::AsyncReadExt;
    use hex_literal::hex;
    use std::str::FromStr;
    use std::time::Duration;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    async fn read_bundle_item(
        tx_id: TxId,
        item_id: BundleItemId,
        expected_hash: Sha256Hash,
    ) -> anyhow::Result<()> {
        dotenv::dotenv().ok();
        init_tracing();
        {
            let client = Client::builder()
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
                .enable_netwatch(false)
                .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
                .build()
                .await?;

            let location = BundleItemArl::from((tx_id, item_id));
            let item = client.bundle_item(&location).await?.unwrap();
            assert_eq!(item.id(), location.bundle_item_id());

            let len = item.data_size() as usize;

            let mut read = 0;
            let mut reader = client.read_data_item(location).await?;

            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];

            loop {
                let n = reader.read(&mut buf).await?;
                read += n;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[0..n]);
            }
            assert_eq!(read, len);
            let hash = hasher.finalize();
            assert_eq!(hash.as_slice(), expected_hash.as_slice(),);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn read_larger_bundle_item() -> anyhow::Result<()> {
        let tx_id = TxId::from_str("ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk")?;
        let item_id = BundleItemId::from_str("UHVB0gDKDiId6XAeZlCH_9h6h6Tz0we8MuGA0CUYxPE")?;
        let expected_hash = Sha256Hash::try_from(Blob::Slice(&hex!(
            "4f76ec77b3476bcb2b37fbdf9f91ea52b407ee7d3c298d18439a1e53ff37aaf8"
        )))?;
        read_bundle_item(tx_id, item_id, expected_hash).await
    }

    #[ignore]
    #[tokio::test]
    async fn read_small_bundle_item() -> anyhow::Result<()> {
        let tx_id = TxId::from_str("XthaAp3q8Akx1_nqwxSKUtc0JlE-4wAoIavJYv8Dvaw")?;
        let item_id = BundleItemId::from_str("jryeiuBu2rCeWwTUXzU24OPoV4VShl2HYVyjclFe0yQ")?;
        let expected_hash = Sha256Hash::try_from(Blob::Slice(&hex!(
            "77a1bea6e198f36b3267f0ce8c4fc8f96c36baceb367e9145e35fa2a330dd761"
        )))?;
        read_bundle_item(tx_id, item_id, expected_hash).await
    }
}
