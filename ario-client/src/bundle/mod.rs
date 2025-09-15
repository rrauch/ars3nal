mod bundler;

use crate::data_reader::AsyncTxReader;
use crate::{Client, api};
use ario_core::bundle::{Bundle, BundleReader};
use ario_core::tx::TxId;

impl Client {
    pub async fn bundle_by_tx(&self, tx_id: &TxId) -> Result<Option<Bundle>, super::Error> {
        let tx = match self.tx_by_id(tx_id).await? {
            Some(tx) => tx.validate(),
            None => return Ok(None),
        }
        .map_err(|(_, e)| api::Error::TxError(e.into()))?;

        let mut reader = AsyncTxReader::new(self.clone(), &tx).await?;
        Ok(Some(
            BundleReader::new(&tx, &mut reader)
                .await
                .map_err(|e| api::Error::BundleError(e))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use crate::api::Api;
    use ario_core::Gateway;
    use ario_core::bundle::BundleType;
    use ario_core::network::Network;
    use ario_core::tx::TxId;
    use std::str::FromStr;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[ignore]
    #[tokio::test]
    async fn read_bundle() -> anyhow::Result<()> {
        init_tracing();
        let api = Api::new(reqwest::Client::new(), Network::default(), false);
        let client = Client::builder()
            .enable_netwatch(false)
            .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
            .build();

        let tx_id = TxId::from_str("ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk")?;

        let bundle = client.bundle_by_tx(&tx_id).await?.unwrap();
        assert_eq!(bundle.id(), &tx_id);
        assert_eq!(bundle.bundle_type(), BundleType::V2);
        assert_eq!(bundle.len(), 12);
        assert_eq!(bundle.total_size(), 3251342);

        Ok(())
    }
}
