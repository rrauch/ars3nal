mod bundler;

use crate::data_reader::{AsyncBundleItemReader, AsyncTxReader};
use crate::{Client, api};
use ario_core::bundle::{
    AuthenticatedBundleItem, Bundle, BundleEntry, BundleId, BundleItemAuthenticator, BundleItemId,
    BundleItemReader, BundleReader,
};
use ario_core::tx::{AuthenticatedTx, TxId};
use futures_lite::{AsyncRead, AsyncSeek};

impl Client {
    pub async fn bundle_by_tx(&self, tx_id: &TxId) -> Result<Option<Bundle>, super::Error> {
        self.0
            .cache
            .get_bundle(tx_id, async |tx_id| self._bundle_by_tx_live(tx_id).await)
            .await
    }

    async fn _bundle_by_tx_live(&self, tx_id: &TxId) -> Result<Option<Bundle>, super::Error> {
        let tx = match self.tx_by_id(tx_id).await? {
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

    pub async fn bundle_item(
        &self,
        item_id: &BundleItemId,
        tx_id: &TxId,
    ) -> Result<Option<AuthenticatedBundleItem<'static>>, super::Error> {
        match self._bundle_item(item_id, tx_id).await? {
            Some((_, item, ..)) => Ok(Some(item)),
            None => Ok(None),
        }
    }

    async fn _bundle_item_live(
        &self,
        bundle_id: &BundleId,
        entry: &BundleEntry<'_>,
        tx: &AuthenticatedTx<'_>,
    ) -> Result<
        (
            AuthenticatedBundleItem<'static>,
            BundleItemAuthenticator<'static>,
        ),
        super::Error,
    > {
        let mut tx_reader = AsyncTxReader::new(self.clone(), tx).await?;

        let (item, authenticator) =
            BundleItemReader::read_async(&entry, &mut tx_reader, bundle_id.clone())
                .await
                .map_err(api::Error::BundleError)?;

        let item = item
            .authenticate()
            .map_err(|e| api::Error::BundleError(e.into()))?;

        Ok((item, authenticator))
    }

    async fn _bundle_item(
        &self,
        item_id: &BundleItemId,
        tx_id: &TxId,
    ) -> Result<
        Option<(
            BundleEntry<'static>,
            AuthenticatedBundleItem<'static>,
            BundleItemAuthenticator<'static>,
            AuthenticatedTx<'static>,
        )>,
        super::Error,
    > {
        let tx = match self.tx_by_id(tx_id).await? {
            Some(tx) => tx,
            None => return Ok(None),
        };

        let bundle = match self.bundle_by_tx(tx_id).await? {
            Some(bundle) => bundle,
            None => return Ok(None),
        };

        let entry = match bundle.entries().find(|e| e.id() == item_id) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        Ok(self
            .0
            .cache
            .get_bundle_item(entry.id(), tx.id(), async |_, _| {
                Ok(Some(
                    self._bundle_item_live(bundle.id(), &entry, &tx).await?,
                ))
            })
            .await?
            .map(|(item, authenticator)| (entry.into_owned(), item, authenticator, tx)))
    }

    pub async fn read_bundle_item(
        &self,
        item: &AuthenticatedBundleItem<'_>,
    ) -> Result<Option<impl AsyncRead + AsyncSeek + Send + Unpin + 'static>, super::Error> {
        let (entry, item, authenticator, tx) =
            match self._bundle_item(item.id(), item.bundle_id()).await? {
                Some((entry, item, authenticator, tx, ..)) => (entry, item, authenticator, tx),
                None => return Ok(None),
            };

        Ok(Some(
            AsyncBundleItemReader::new(self.clone(), entry, item, authenticator, tx).await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use ario_core::Gateway;
    use ario_core::blob::Blob;
    use ario_core::bundle::{BundleItemId, BundleType};
    use ario_core::crypto::hash::{Hasher, Sha256, Sha256Hash};
    use ario_core::tx::TxId;
    use futures_lite::AsyncReadExt;
    use hex_literal::hex;
    use std::str::FromStr;

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
        init_tracing();
        let client = Client::builder()
            .enable_netwatch(false)
            .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
            .build()
            .await?;

        let item = client.bundle_item(&item_id, &tx_id).await?.unwrap();
        assert_eq!(item.id(), &item_id);

        let len = item.data_size() as usize;

        let mut read = 0;
        let mut reader = client.read_bundle_item(&item).await?.unwrap();

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

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn read_bundle() -> anyhow::Result<()> {
        init_tracing();
        let client = Client::builder()
            .enable_netwatch(false)
            .gateways(vec![Gateway::from_str("https://arweave.net")?].into_iter())
            .build()
            .await?;

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
    async fn read_small_bundle_item() -> anyhow::Result<()> {
        let tx_id = TxId::from_str("XthaAp3q8Akx1_nqwxSKUtc0JlE-4wAoIavJYv8Dvaw")?;
        let item_id = BundleItemId::from_str("jryeiuBu2rCeWwTUXzU24OPoV4VShl2HYVyjclFe0yQ")?;
        let expected_hash = Sha256Hash::try_from(Blob::Slice(&hex!(
            "77a1bea6e198f36b3267f0ce8c4fc8f96c36baceb367e9145e35fa2a330dd761"
        )))?;
        read_bundle_item(tx_id, item_id, expected_hash).await
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
}
