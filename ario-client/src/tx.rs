use crate::api::RequestMethod::{Get, Post};
use crate::api::ResponseStream;
use crate::api::{
    Api, ApiRequest, ApiRequestBody, ContentType, Payload, TryFromResponseStream, ViaJson,
};
use crate::routemaster::Handle;
use crate::{Client, api};
use ario_core::blob::Blob;
use ario_core::data::Verifier;
use ario_core::data::{DataItem, ExternalDataItemVerifier, MaybeOwnedExternalDataItem};
use ario_core::tx::{LastTx, Tx, TxAnchor, TxId, UnvalidatedTx, ValidatedTx};
use ario_core::{BlockNumber, Gateway, JsonValue};
use async_stream::try_stream;
use bytesize::ByteSize;
use derive_where::derive_where;
use futures_lite::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, Stream};
use itertools::Itertools;
use maybe_owned::MaybeOwned;
use serde::Deserialize;
use serde_with::DisplayFromStr;
use serde_with::base64::Base64;
use serde_with::base64::UrlSafe;
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use std::fmt::Debug;
use std::io::SeekFrom;
use std::ops::{Add, Range};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use thiserror::Error;

impl Api {
    async fn tx_by_id(
        &self,
        gateway: &Gateway,
        tx_id: &TxId,
    ) -> Result<Option<UnvalidatedTx<'static>>, api::Error> {
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
    ) -> Result<Option<Status<'_>>, api::Error> {
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
            .max_response_len(ByteSize::kib(512))
            .build();

        Ok(self.send_api_request(req).await?)
    }
}

impl Client {
    pub async fn tx_by_id(
        &self,
        tx_id: &TxId,
    ) -> Result<Option<ValidatedTx<'static>>, super::Error> {
        self.0
            .cache
            .get_tx(tx_id, async |tx_id| self._tx_by_id_live(tx_id).await)
            .await
    }

    async fn _tx_by_id_live(
        &self,
        tx_id: &TxId,
    ) -> Result<Option<ValidatedTx<'static>>, super::Error> {
        let tx = match self
            .with_gw(async |gw| self.0.api.tx_by_id(gw, tx_id).await)
            .await?
        {
            Some(tx) => tx.validate(),
            None => return Ok(None),
        }
        .map_err(|(_, e)| api::Error::TxError(e.into()))?;
        Ok(Some(tx))
    }

    pub async fn tx_status(&self, tx_id: &TxId) -> Result<Option<Status<'_>>, super::Error> {
        Ok(self
            .with_gw(async |gw| self.0.api.tx_status(gw, tx_id).await)
            .await?)
    }

    pub async fn tx_offset(&self, tx_id: &TxId) -> Result<Offset, super::Error> {
        self.0
            .cache
            .get_tx_offset(tx_id, async |tx_id| {
                Ok(Some(self._tx_offset_live(tx_id).await?))
            })
            .await?
            .ok_or(api::Error::NotFoundError.into())
    }

    async fn _tx_offset_live(&self, tx_id: &TxId) -> Result<Offset, super::Error> {
        Ok(self
            .with_gw(async |gw| self.0.api.tx_offset(gw, tx_id).await)
            .await?)
    }

    pub async fn tx_anchor(&self) -> Result<TxAnchor, super::Error> {
        Ok(self
            .with_gw(async |gw| self.0.api.tx_anchor(gw).await)
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

pub enum Submission<'a> {
    AwaitingChunks(TxSubmission<AwaitingData<'a>>),
    Submitted(TxSubmission<Submitted>),
}

#[derive_where(Debug)]
pub struct TxSubmission<State: Debug>(State);

#[derive(Debug)]
pub struct Prepared {
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
    #[error("external data does not match tx data")]
    IncorrectExternalData,
    #[error(transparent)]
    UploadError(#[from] std::io::Error),
}

impl TxSubmission<Prepared> {
    pub fn tx_anchor(&self) -> &TxAnchor {
        &self.0.tx_anchor
    }

    pub fn created(&self) -> SystemTime {
        self.0.created
    }

    pub async fn submit<'a>(self, tx: &'a ValidatedTx<'a>) -> Result<Submission<'a>, super::Error> {
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

        Ok(match tx.data_item() {
            Some(DataItem::External(external)) => {
                Submission::AwaitingChunks(TxSubmission(AwaitingData {
                    gw_handle,
                    client,
                    tx_id,
                    created: self.0.created,
                    data: external,
                }))
            }
            _ => Submission::Submitted(TxSubmission(Submitted {
                gw_handle,
                client,
                tx_id,
                created: self.0.created,
                submitted: SystemTime::now(),
            })),
        })
    }
}

#[derive(Debug)]
pub struct AwaitingData<'a> {
    gw_handle: Handle<Gateway>,
    tx_id: TxId,
    client: Client,
    created: SystemTime,
    data: MaybeOwnedExternalDataItem<'a>,
}

impl<'a> TxSubmission<AwaitingData<'a>> {
    pub fn tx_id(&self) -> &TxId {
        &self.0.tx_id
    }

    pub fn created(&self) -> SystemTime {
        self.0.created
    }

    pub fn data<'b>(
        self,
        verifier: MaybeOwned<'b, ExternalDataItemVerifier<'b>>,
    ) -> Result<TxSubmission<UploadChunks<'b>>, (Self, super::Error)> {
        // make sure the external data matches the tx data
        if self.0.data.as_ref() != verifier.data_item() {
            return Err((self, TxSubmissionError::IncorrectExternalData.into()));
        }

        let chunks = verifier.chunks().map(|c| c.clone()).collect_vec();

        Ok(TxSubmission(UploadChunks {
            gw_handle: self.0.gw_handle,
            tx_id: self.0.tx_id,
            client: self.0.client,
            created: self.0.created,
            data: verifier,
            chunks,
        }))
    }
}

#[derive(Debug)]
pub struct UploadChunks<'a> {
    gw_handle: Handle<Gateway>,
    tx_id: TxId,
    client: Client,
    created: SystemTime,
    data: MaybeOwned<'a, ExternalDataItemVerifier<'a>>,
    chunks: Vec<Range<u64>>,
}

impl<'a> TxSubmission<UploadChunks<'a>> {
    pub fn tx_id(&self) -> &TxId {
        &self.0.tx_id
    }

    pub fn created(&self) -> SystemTime {
        self.0.created
    }

    pub async fn from_async_reader<R: AsyncRead + AsyncSeek + Send + Unpin>(
        mut self,
        reader: &mut R,
    ) -> Result<TxSubmission<Submitted>, (Self, super::Error)> {
        let chunks = self
            .0
            .chunks
            .drain(..)
            .sorted_by(|a, b| Ord::cmp(&a.start, &b.start))
            .collect_vec();

        let mut buffer = vec![0u8; 1024 * 256];

        let mut chunks_iter = chunks.into_iter();
        while let Some(chunk) = chunks_iter.next() {
            if let Err(err) = self.process_chunk(&chunk, &mut buffer, reader).await {
                let mut remaining = vec![chunk];
                remaining.extend(chunks_iter);
                return Err((
                    Self(UploadChunks {
                        gw_handle: self.0.gw_handle,
                        tx_id: self.0.tx_id,
                        client: self.0.client,
                        created: self.0.created,
                        data: self.0.data,
                        chunks: remaining,
                    }),
                    err,
                ));
            }
        }

        // all chunks uploaded, tx submitted
        Ok(TxSubmission(Submitted {
            gw_handle: self.0.gw_handle,
            tx_id: self.0.tx_id,
            client: self.0.client,
            created: self.0.created,
            submitted: SystemTime::now(),
        }))
    }

    async fn process_chunk<R: AsyncRead + AsyncSeek + Send + Unpin>(
        &self,
        chunk: &Range<u64>,
        buf: &mut [u8],
        reader: &mut R,
    ) -> Result<(), super::Error> {
        let len = (chunk.end - chunk.start) as usize;
        Self::read_chunk_data(chunk.start, &mut buf[..len], reader)
            .await
            .map_err(|e| TxSubmissionError::UploadError(e))?;

        let data = &buf[..len];

        self.0
            .client
            .upload_chunk_with_gw(&self.0.gw_handle, &self.0.data, chunk, Blob::Slice(data))
            .await?;

        Ok(())
    }

    async fn read_chunk_data<R: AsyncRead + AsyncSeek + Send + Unpin>(
        offset: u64,
        buf: &mut [u8],
        reader: &mut R,
    ) -> std::io::Result<()> {
        reader.seek(SeekFrom::Start(offset)).await?;
        reader.read_exact(buf).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Submitted {
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

    pub fn status(&self) -> impl Stream<Item = Result<Status<'_>, super::Error>> + Send + Unpin {
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
    pub(crate) size: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub(crate) offset: u128,
}

impl Offset {
    pub fn absolute(&self, relative: u64) -> u128 {
        self.offset
            .saturating_sub(self.size as u128)
            .add((relative + 1) as u128)
    }
}

#[cfg(test)]
mod tests {
    use crate::api::Api;
    use crate::tx::{Status, Submission};
    use anyhow::bail;
    use ario_core::Gateway;
    use ario_core::chunking::DefaultChunker;
    use ario_core::crypto::hash::{Hasher, HasherExt, Sha256};
    use ario_core::data::ExternalDataItemVerifier;
    use ario_core::jwk::Jwk;
    use ario_core::network::Network;
    use ario_core::tx::{Transfer, TxBuilder, TxId};
    use ario_core::wallet::{Wallet, WalletAddress};
    use futures_lite::StreamExt;
    use reqwest::Client;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    static ONE_MB_PATH: &'static str = "./testdata/1mb.bin";

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
    async fn tx_by_id_client() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let client = crate::Client::builder().gateways(vec![gw]).build().await?;

        let tx_id = TxId::from_str("Y0wJvUkHFhcJZAduC8wfaiaDMHkrCoqHMSkenHD75VU")?;
        let tx = client.tx_by_id(&tx_id).await?.unwrap();
        assert_eq!(tx.id(), &tx_id);

        // from cache
        let tx_2 = client.tx_by_id(&tx_id).await?.unwrap();
        assert_eq!(tx, tx_2);
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
    async fn tx_submit_transfer_live() -> anyhow::Result<()> {
        dotenv::dotenv().ok();
        init_tracing();

        let arlocal = std::env::var("ARLOCAL_URL").unwrap();
        let network_id = std::env::var("ARLOCAL_ID").unwrap_or("arlocal".to_string());
        let wallet_jwk = std::env::var("ARLOCAL_WALLET_JWK").unwrap();

        let client = crate::Client::builder()
            .enable_netwatch(false)
            .network(Network::Local(network_id.try_into()?))
            .gateways([Gateway::from_str(arlocal.as_str())?])
            .build()
            .await?;

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

        let tx_sub = match tx_sub.submit(&tx).await? {
            Submission::Submitted(tx_sub) => tx_sub,
            _ => unreachable!(),
        };

        let status = tx_sub.status().try_next().await?.unwrap();
        assert!(status.pending());

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn tx_submit_upload_roundtrip_live() -> anyhow::Result<()> {
        dotenv::dotenv().ok();
        init_tracing();

        let arlocal = std::env::var("ARLOCAL_URL").unwrap();
        let network_id = std::env::var("ARLOCAL_ID").unwrap_or("arlocal".to_string());
        let wallet_jwk = std::env::var("ARLOCAL_WALLET_JWK").unwrap();

        let client = crate::Client::builder()
            .enable_netwatch(false)
            .network(Network::Local(network_id.try_into()?))
            .gateways([Gateway::from_str(arlocal.as_str())?])
            .build()
            .await?;

        let json =
            tokio::fs::read_to_string(<PathBuf as AsRef<Path>>::as_ref(&PathBuf::from(wallet_jwk)))
                .await?;
        let jwk = Jwk::from_json(json.as_str())?;
        let wallet = Wallet::from_jwk(&jwk)?;

        let file = tokio::fs::File::open(ONE_MB_PATH).await?;
        let verifier = ExternalDataItemVerifier::try_from_async_reader(
            &mut file.compat(),
            DefaultChunker::new(),
        )
        .await?;

        let tx_sub = client.tx_begin().await?;

        let tx_draft = TxBuilder::v2()
            .reward("12")?
            .tx_anchor(tx_sub.tx_anchor().clone())
            .data_upload(verifier.data_item().into())
            .draft();

        let tx = wallet.sign_tx_draft(tx_draft)?;

        let tx_sub = match tx_sub.submit(&tx).await? {
            Submission::AwaitingChunks(tx_sub) => tx_sub,
            _ => unreachable!(),
        };

        let tx_sub = tx_sub.data((&verifier).into()).map_err(|(_, err)| err)?;

        let file = tokio::fs::File::open(ONE_MB_PATH).await?;
        let file_len = file.metadata().await?.len();

        let tx_sub = tx_sub
            .from_async_reader(&mut file.compat())
            .await
            .map_err(|(_, err)| err)?;

        // wait for tx to be processed
        let mut status_stream = tx_sub.status();
        loop {
            match status_stream.try_next().await? {
                Some(status) => {
                    if status.accepted() {
                        break;
                    }
                }
                None => {
                    bail!("status stream ended prematurely");
                }
            }
        }
        let mut hasher = Sha256::new();
        let tx_offset = client.tx_offset(tx_sub.tx_id()).await?;
        let data_root = verifier.data_item().data_root();
        let mut total = 0;
        while let Some(chunk) = client
            .retrieve_chunk(tx_offset.absolute(total), total, data_root)
            .await?
        {
            total += chunk.len() as u64;
            hasher.update(&chunk);
            if total >= file_len {
                break;
            }
        }

        assert_eq!(total, file_len);

        let hash = hasher.finalize();
        let expected_hash = Sha256::digest(tokio::fs::read(ONE_MB_PATH).await?);

        assert_eq!(hash, expected_hash);

        Ok(())
    }
}
