use crate::api::RequestMethod::{Get, Post};
use crate::api::ResponseStream;
use crate::api::{
    Api, ApiRequest, ApiRequestBody, ContentType, Payload, TryFromResponseStream, ViaJson,
};
use crate::routemaster::Handle;
use crate::{Client, api};
use ario_core::blob::Blob;
use ario_core::tx::{LastTx, Tx, TxAnchor, TxId, UnvalidatedTx, ValidatedTx};
use ario_core::{BlockNumber, Gateway, JsonValue};
use async_stream::try_stream;
use bytesize::ByteSize;
use futures_lite::Stream;
use serde::Deserialize;
use serde_with::DisplayFromStr;
use serde_with::base64::Base64;
use serde_with::base64::UrlSafe;
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use thiserror::Error;

impl Api {
    async fn tx_by_id(
        &self,
        gateway: &Gateway,
        tx_id: &TxId,
    ) -> Result<Option<UnvalidatedTx>, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join(format!("./tx/{}", tx_id.to_string()).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::mib(18))
            .idempotent(true)
            .build();

        match self.send_optional_api_request(req).await? {
            Some(stream) => {
                let json = <ViaJson<JsonValue> as TryFromResponseStream>::try_from(stream)
                    .await?
                    .0;
                Ok(Some(Tx::from_json(json)?))
            }
            None => Ok(None),
        }
    }

    async fn tx_status(
        &self,
        gateway: &Gateway,
        tx_id: &TxId,
    ) -> Result<Option<Status>, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join(format!("./tx/{}/status", tx_id.to_string()).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::kib(2))
            .idempotent(true)
            .build();

        match self.send_optional_api_request(req).await? {
            Some(stream) => {
                // pending tx responses are returned as text, not json
                let content_type = stream.content_type().unwrap_or(ContentType::Json);
                match content_type {
                    ContentType::Text => {
                        // must be a pending tx
                        let value = <String as TryFromResponseStream>::try_from(stream).await?;
                        if value.trim().eq_ignore_ascii_case("pending") {
                            Ok(Some(Status::Pending))
                        } else {
                            Err(api::Error::UnexpectedResponse(format!(
                                "expected status 'Pending' but got '{}'",
                                value
                            )))
                        }
                    }
                    ContentType::Json => {
                        // must be an accepted tx
                        Ok(Some(Status::Accepted(
                            <ViaJson<Accepted> as TryFromResponseStream>::try_from(stream)
                                .await?
                                .0,
                        )))
                    }
                }
            }
            None => Ok(None),
        }
    }

    async fn tx_offset(&self, gateway: &Gateway, tx_id: &TxId) -> Result<Offset, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join(format!("./tx/{}/offset", tx_id.to_string()).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::kib(1))
            .idempotent(true)
            .build();

        Ok(self.send_api_request::<ViaJson<_>>(req).await?.0)
    }

    async fn tx_anchor(&self, gateway: &Gateway) -> Result<TxAnchor, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join("./tx_anchor")
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::kib(1))
            .idempotent(true)
            .build();

        Ok(
            TxAnchor::from_str(self.send_api_request::<String>(req).await?.as_str())
                .map_err(|e| api::Error::UnexpectedResponse(e.to_string()))?,
        )
    }

    async fn tx_submit(&self, gateway: &Gateway, tx: &ValidatedTx<'_>) -> Result<(), api::Error> {
        let tx_json = tx.to_json()?;

        let req = ApiRequest::builder()
            .endpoint(gateway.join("./tx").map_err(api::Error::InvalidUrl)?)
            .request_method(Post)
            .body(
                ApiRequestBody::builder()
                    .content_type(ContentType::Json)
                    .payload(Payload::Json(&tx_json))
                    .build(),
            )
            .max_response_len(ByteSize::kib(64))
            .build();

        Ok(self.send_api_request(req).await?)
    }
}

impl Client {
    pub async fn tx_by_id(&self, tx_id: &TxId) -> Result<Option<UnvalidatedTx>, super::Error> {
        let api = &self.0.api;
        Ok(self
            .with_gw(async move |gw| api.tx_by_id(gw, tx_id).await)
            .await?)
    }

    pub async fn tx_status(&self, tx_id: &TxId) -> Result<Option<Status>, super::Error> {
        let api = &self.0.api;
        Ok(self
            .with_gw(async move |gw| api.tx_status(gw, tx_id).await)
            .await?)
    }

    pub async fn tx_offset(&self, tx_id: &TxId) -> Result<Offset, super::Error> {
        let api = &self.0.api;
        Ok(self
            .with_gw(async move |gw| api.tx_offset(gw, tx_id).await)
            .await?)
    }

    pub async fn tx_anchor(&self) -> Result<TxAnchor, super::Error> {
        let api = &self.0.api;
        Ok(self
            .with_gw(async move |gw| api.tx_anchor(gw).await)
            .await?)
    }

    pub async fn tx_begin(&self) -> Result<TxSubmission<Prepared>, super::Error> {
        let api = &self.0.api;
        let gw_handle = self.0.routemaster.gateway().await?;
        let tx_anchor = self
            .with_existing_gw(&gw_handle, async move |gw| api.tx_anchor(gw).await)
            .await?;
        Ok(TxSubmission(Prepared {
            gw_handle,
            tx_anchor,
            created: SystemTime::now(),
            client: self.clone(),
        }))
    }
}

pub struct TxSubmission<State>(State);

#[derive(Debug)]
struct Prepared {
    gw_handle: Handle<Gateway>,
    tx_anchor: TxAnchor,
    created: SystemTime,
    client: Client,
}

#[derive(Error, Debug)]
pub enum TxSubmissionError {
    #[error("incorrect tx_anchor found in tx")]
    IncorrectTxAnchor,
    #[error("tx_status not found")]
    TxStatusNotFound,
}

impl TxSubmission<Prepared> {
    pub fn tx_anchor(&self) -> &TxAnchor {
        &self.0.tx_anchor
    }

    pub fn created(&self) -> SystemTime {
        self.0.created
    }

    pub async fn submit(
        self,
        tx: &ValidatedTx<'_>,
    ) -> Result<TxSubmission<Submitted>, super::Error> {
        match tx.last_tx() {
            LastTx::TxAnchor(tx_anchor) => {
                if tx_anchor.as_ref() != self.tx_anchor() {
                    return Err(TxSubmissionError::IncorrectTxAnchor.into());
                }
            }
            LastTx::TxId(_) => {
                // should never happen
                return Err(TxSubmissionError::IncorrectTxAnchor.into());
            }
        }
        let gw_handle = self.0.gw_handle;
        let client = self.0.client;
        let api = &client.0.api;
        client
            .with_existing_gw(&gw_handle, async move |gw| api.tx_submit(gw, tx).await)
            .await?;

        let tx_id = tx.id().clone();

        Ok(TxSubmission(Submitted {
            gw_handle,
            client,
            tx_id,
            created: self.0.created,
            submitted: SystemTime::now(),
        }))
    }
}

#[derive(Debug)]
struct Submitted {
    gw_handle: Handle<Gateway>,
    tx_id: TxId,
    client: Client,
    created: SystemTime,
    submitted: SystemTime,
}

impl TxSubmission<Submitted> {
    pub fn tx_id(&self) -> &TxId {
        &self.0.tx_id
    }

    pub fn created(&self) -> SystemTime {
        self.0.created
    }

    pub fn submitted(&self) -> SystemTime {
        self.0.created
    }

    pub fn status(&self) -> impl Stream<Item = Result<Status, super::Error>> + Send + Unpin {
        const MIN_DELAY: Duration = Duration::from_secs(1);
        const MAX_DELAY: Duration = Duration::from_secs(60);

        let api = &self.0.client.0.api;
        let tx_id = self.tx_id();
        let mut previous_status = None;
        let mut last_change = SystemTime::now();
        let mut avg_duration: Option<Duration> = None;
        let mut current_delay = MIN_DELAY;

        Box::pin(try_stream! {
            loop {
                let status = self
                .0
                .client
                .with_existing_gw(&self.0.gw_handle, async move |gw| {
                    api.tx_status(gw, tx_id).await
                })
                .await?
                .ok_or(TxSubmissionError::TxStatusNotFound)?;

                if previous_status.as_ref() != Some(&status) {
                    // status change detected
                    previous_status = Some(status.clone());

                    let now = SystemTime::now();
                    let duration = now.duration_since(last_change).unwrap_or_default();

                    // Update EMA (α = 0.3, gives 30% weight to latest sample)
                    let duration_secs = duration.as_secs_f64();
                    avg_duration = Some(Duration::from_secs_f64(match avg_duration {
                        Some(prev) => prev.as_secs_f64() * 0.7 + duration_secs * 0.3,
                        None => duration_secs,
                    }));

                    last_change = now;
                    current_delay = Duration::from_secs_f64(avg_duration.unwrap_or(MIN_DELAY).as_secs_f64() / 1.5).max(MIN_DELAY).min(MAX_DELAY);
                    yield status;
                } else {
                    // status remains unchanged, back off and try again later
                    current_delay = Duration::from_secs_f64(current_delay.as_secs_f64() * 1.5).min(MAX_DELAY);
                }

                tokio::time::sleep(current_delay).await;
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status<'a> {
    Pending,
    Accepted(Accepted<'a>),
}

impl<'a> Status<'a> {
    pub fn pending(&self) -> bool {
        match self {
            Self::Pending => true,
            _ => false,
        }
    }

    pub fn accepted(&self) -> bool {
        match self {
            Self::Accepted(_) => true,
            _ => false,
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Accepted<'a> {
    pub block_height: BlockNumber,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub block_indep_hash: Blob<'a>, //todo
    pub number_of_confirmations: u64,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Offset {
    #[serde_as(as = "DisplayFromStr")]
    size: u64,
    #[serde_as(as = "DisplayFromStr")]
    offset: u64,
}

#[cfg(test)]
mod tests {
    use crate::api::Api;
    use crate::tx::Status;
    use anyhow::bail;
    use ario_core::Gateway;
    use ario_core::jwk::Jwk;
    use ario_core::network::Network;
    use ario_core::tx::{Transfer, TxBuilder, TxId};
    use ario_core::wallet::{Wallet, WalletAddress};
    use futures_lite::StreamExt;
    use reqwest::Client;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[ignore]
    #[tokio::test]
    async fn tx_by_id_live() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let api = Api::new(Client::new(), Network::default(), false);

        let tx_id = TxId::from_str("Y0wJvUkHFhcJZAduC8wfaiaDMHkrCoqHMSkenHD75VU")?;
        let tx = api.tx_by_id(&gw, &tx_id).await?.unwrap();
        let tx = tx.validate().map_err(|(_, e)| e)?;
        assert_eq!(tx.id(), &tx_id);

        let tx_id = TxId::from_str("Y0wIvUkHFhcJZAduC8wfaiaDMHkrEoqHMSkenHD75VU")?;
        assert!(api.tx_by_id(&gw, &tx_id).await?.is_none());

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn tx_status_live() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let api = Api::new(Client::new(), Network::default(), false);

        let tx_id = TxId::from_str("Y0wJvUkHFhcJZAduC8wfaiaDMHkrCoqHMSkenHD75VU")?;

        if let Some(Status::Accepted(status)) = api.tx_status(&gw, &tx_id).await? {
            assert!(status.number_of_confirmations > 100);
        } else {
            bail!("should return accepted status")
        }

        let tx_id = TxId::from_str("Y0wIvUkHFhcJZAduC8wfaiaDMHkrEoqHMSkenHD75VU")?;
        assert!(api.tx_status(&gw, &tx_id).await?.is_none());
        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn tx_offset_live() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let api = Api::new(Client::new(), Network::default(), false);

        let tx_id = TxId::from_str("Y0wJvUkHFhcJZAduC8wfaiaDMHkrCoqHMSkenHD75VU")?;
        let offset = api.tx_offset(&gw, &tx_id).await?;
        assert_eq!(offset.size, 41805102);
        assert_eq!(offset.offset, 356657191618084);

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn tx_anchor_live() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let api = Api::new(Client::new(), Network::default(), false);

        let tx_anchor = api.tx_anchor(&gw).await?;
        let _s = tx_anchor.to_string();

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn tx_submit_live() -> anyhow::Result<()> {
        dotenv::dotenv().ok();
        init_tracing();

        let arlocal = std::env::var("ARLOCAL_URL").unwrap();
        let network_id = std::env::var("ARLOCAL_ID").unwrap_or("arlocal".to_string());
        let wallet_jwk = std::env::var("ARLOCAL_WALLET_JWK").unwrap();

        let client = crate::Client::builder()
            .enable_netwatch(false)
            .network(Network::Local(network_id.try_into()?))
            .gateways([Gateway::from_str(arlocal.as_str())?])
            .build();

        let json =
            tokio::fs::read_to_string(<PathBuf as AsRef<Path>>::as_ref(&PathBuf::from(wallet_jwk)))
                .await?;
        let jwk = Jwk::from_json(json.as_str())?;
        let wallet = Wallet::from_jwk(&jwk)?;

        let target = WalletAddress::from_str("4JOmaT9fFe2ojFJEls3Zow5UKO2CBOk7lOirbPTtX1o")?;
        let tx_sub = client.tx_begin().await?;

        let tx_draft = TxBuilder::v2()
            .transfer(Transfer::new(target, "123")?)
            .reward("12")?
            .tx_anchor(tx_sub.tx_anchor().clone())
            .draft();

        let tx = wallet.sign_tx_draft(tx_draft)?;

        let tx_sub = tx_sub.submit(&tx).await?;

        let status = tx_sub.status().try_next().await?.unwrap();
        assert!(status.pending());

        Ok(())
    }
}
