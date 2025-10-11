mod bundler;

use crate::location::{Arl, BundleItemArl};
use crate::{Client, api};
use ario_core::Unauthenticated;
use ario_core::bundle::{
    AuthenticatedBundleItem, Bundle, BundleEntry, BundleId, BundleItemAuthenticator,
    BundleItemReader, BundleReader, UnauthenticatedBundleItem,
};

impl Client {
    pub async fn bundle_by_location(&self, location: &Arl) -> Result<Option<Bundle>, super::Error> {
        self.0
            .cache
            .get_bundle(location, async |location| {
                self._bundle_by_location_live(location).await
            })
            .await
    }

    async fn _bundle_by_location_live(
        &self,
        location: &Arl,
    ) -> Result<Option<Bundle>, super::Error> {
        let container = match self.item_by_location(location).await? {
            Some(container) => container,
            None => return Ok(None),
        };
        let mut container_reader = self.read_any(location).await?;
        Ok(Some(
            BundleReader::new(&container, &mut container_reader)
                .await
                .map_err(|e| api::Error::BundleError(e))?,
        ))
    }

    pub async fn bundle_item(
        &self,
        location: &BundleItemArl,
    ) -> Result<Option<AuthenticatedBundleItem<'static>>, super::Error> {
        match self._bundle_item_authenticated(location).await? {
            Some((_, item, ..)) => Ok(Some(item)),
            None => Ok(None),
        }
    }

    pub(crate) async fn _bundle_item_authenticated(
        &self,
        location: &BundleItemArl,
    ) -> Result<
        Option<(
            BundleEntry<'static>,
            AuthenticatedBundleItem<'static>,
            BundleItemAuthenticator<'static>,
        )>,
        super::Error,
    > {
        let (bundle_id, entry) = match self._bundle_entry(location).await? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        Ok(self
            .0
            .cache
            .get_bundle_item(location, async |_| {
                Ok(Some(
                    self._bundle_item_authenticated_live(&bundle_id, &entry, location)
                        .await?,
                ))
            })
            .await?
            .map(|(item, authenticator)| (entry.into_owned(), item, authenticator)))
    }

    async fn _bundle_item_authenticated_live(
        &self,
        bundle_id: &BundleId,
        entry: &BundleEntry<'_>,
        location: &BundleItemArl,
    ) -> Result<
        (
            AuthenticatedBundleItem<'static>,
            BundleItemAuthenticator<'static>,
        ),
        super::Error,
    > {
        let container_location = location.parent();
        let mut container_reader = self.any_reader(&container_location).await?;

        let (item, authenticator) =
            BundleItemReader::read_async(&entry, &mut container_reader, bundle_id.clone())
                .await
                .map_err(api::Error::BundleError)?;

        let item = item
            .authenticate()
            .map_err(|e| api::Error::BundleError(e.into()))?;

        Ok((item, authenticator))
    }

    pub(crate) async fn _bundle_item_unauthenticated(
        &self,
        location: &BundleItemArl,
    ) -> Result<Option<(BundleEntry<'static>, UnauthenticatedBundleItem<'static>)>, super::Error>
    {
        let (bundle_id, entry) = match self._bundle_entry(location).await? {
            Some(entry) => entry,
            None => return Ok(None),
        };

        Ok(self
            .0
            .cache
            .get_unauthenticated_bundle_item(location, async |_| {
                Ok(Some(
                    self._bundle_item_unauthenticated_live(&bundle_id, &entry, &location)
                        .await?,
                ))
            })
            .await?
            .map(|item| (entry.into_owned(), item)))
    }

    async fn _bundle_item_unauthenticated_live(
        &self,
        bundle_id: &BundleId,
        entry: &BundleEntry<'_>,
        location: &BundleItemArl,
    ) -> Result<UnauthenticatedBundleItem<'static>, super::Error> {
        let mut container_reader = self
            .any_reader::<Unauthenticated>(location.parent())
            .await?
            .danger_make_readable();

        Ok(BundleItemReader::read_async_unauthenticated(
            &entry,
            &mut container_reader,
            bundle_id.clone(),
        )
        .await
        .map_err(api::Error::BundleError)?)
    }

    async fn _bundle_entry(
        &self,
        location: &BundleItemArl,
    ) -> Result<Option<(BundleId, BundleEntry<'static>)>, super::Error> {
        let bundle = match self.bundle_by_location(&location.parent()).await? {
            Some(bundle) => bundle,
            None => return Ok(None),
        };

        Ok(
            match bundle
                .entries()
                .find(|e| e.id() == location.bundle_item_id())
            {
                Some(entry) => Some((bundle.id().clone(), entry.into_owned())),
                None => None,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use crate::location::BundleItemArl;
    use ario_core::Gateway;
    use ario_core::blob::Blob;
    use ario_core::bundle::{BundleId, BundleItemId, BundleType};
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

        let location = BundleItemArl::from((tx_id, item_id));
        let item = client.bundle_item(&location).await?.unwrap();
        assert_eq!(item.id(), location.bundle_item_id());

        let len = item.data_size() as usize;

        let mut read = 0;
        let mut reader = client.read_any(location.clone()).await?;

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

        let tx_id = BundleId::from(TxId::from_str(
            "ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk",
        )?);
        let location = client.location_by_item_id(&tx_id).await?;

        let bundle = client.bundle_by_location(&location).await?.unwrap();
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
