mod bundler;

use crate::data_reader::{AsyncDataReader, AsyncTxReader};
use crate::{Client, api};
use ario_core::bundle::{
    Bundle, BundleItemId, BundleItemReader, BundleReader, UnvalidatedBundleItem,
};
use ario_core::tx::TxId;

impl Client {
    pub async fn bundle_by_tx(&self, tx_id: &TxId) -> Result<Option<Bundle>, super::Error> {
        let tx = match self.validated_tx_by_id(tx_id).await? {
            Some(tx) => tx,
            None => return Ok(None),
        };

        let mut tx_reader = AsyncTxReader::new(self.clone(), &tx).await?;
        Ok(Some(
            BundleReader::new(&tx, &mut tx_reader)
                .await
                .map_err(|e| api::Error::BundleError(e))?,
        ))
    }

    pub async fn bundle_item_by_id_tx(
        &self,
        id: &BundleItemId,
        tx_id: &TxId,
    ) -> Result<Option<UnvalidatedBundleItem<'static>>, super::Error> {
        let bundle = match self.bundle_by_tx(tx_id).await? {
            Some(bundle) => bundle,
            None => return Ok(None),
        };

        let entry = match bundle.entries().find(|e| e.id() == id) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let tx = match self.validated_tx_by_id(tx_id).await? {
            Some(tx) => tx,
            None => return Ok(None),
        };

        let mut tx_reader = AsyncDataReader::new(self.clone(), &tx).await?;

        Ok(Some(
            BundleItemReader::read_async(&entry, &mut tx_reader)
                .await
                .map_err(api::Error::BundleError)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use crate::api::Api;
    use ario_core::Gateway;
    use ario_core::bundle::{BundleItemId, BundleType};
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

    #[ignore]
    #[tokio::test]
    async fn read_bundle_item() -> anyhow::Result<()> {
        init_tracing();
        let api = Api::new(reqwest::Client::new(), Network::default(), false);
        let client = Client::builder()
            .enable_netwatch(false)
            .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
            .build();

        let tx_id = TxId::from_str("XthaAp3q8Akx1_nqwxSKUtc0JlE-4wAoIavJYv8Dvaw")?;
        let item_id = BundleItemId::from_str("jryeiuBu2rCeWwTUXzU24OPoV4VShl2HYVyjclFe0yQ")?;

        //let tx_id = TxId::from_str("ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk")?;
        //let item_id = BundleItemId::from_str("UHVB0gDKDiId6XAeZlCH_9h6h6Tz0we8MuGA0CUYxPE")?;

        let item = client.bundle_item_by_id_tx(&item_id, &tx_id).await?.unwrap().validate()?;
        assert_eq!(item.id(), &item_id);
        Ok(())
    }
}
