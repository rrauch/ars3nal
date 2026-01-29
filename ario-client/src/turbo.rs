use crate::api::RequestMethod::{Get, Post};
use crate::api::{Api, ApiRequest, ApiRequestBody, ContentType, Payload, ViaJson};
use crate::bundle::bundler::{BundleDataReader, BundleItemCombinator};
use crate::{Client, api};
use ario_core::BlockNumber;
use ario_core::bundle::{AuthenticatedBundleItem, BundleItemError, BundleItemId};
use ario_core::money::{Money, Winston};
use ario_core::wallet::WalletAddress;
use bon::Builder;
use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use futures_lite::{AsyncRead, AsyncSeek};
use serde::{Deserialize, Deserializer};
use serde_with::DisplayFromStr;
use serde_with::serde_as;
use std::str::FromStr;
use std::sync::LazyLock;
use thiserror::Error;
use url::Url;

static DEFAULT_PAYMENT_ENDPOINT: LazyLock<Url> = LazyLock::new(|| {
    Url::from_str("https://payment.ardrive.io/v1/")
        .expect("default payment endpoint to be valid url")
});

static DEFAULT_UPLOAD_ENDPOINT: LazyLock<Url> = LazyLock::new(|| {
    Url::from_str("https://upload.ardrive.io/").expect("default upload endpoint to be valid url")
});

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    BundleItemError(#[from] BundleItemError),
    #[error("incorrect data size: expected '{expected}', actual '{actual}'")]
    IncorrectDataSize { expected: u64, actual: u64 },
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Builder, Debug)]
pub struct Turbo {
    #[builder(default = DEFAULT_PAYMENT_ENDPOINT.clone())]
    payment_endpoint: Url,
    #[builder(default = DEFAULT_UPLOAD_ENDPOINT.clone())]
    upload_endpoint: Url,
}

impl Default for Turbo {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Api {
    async fn turbo_balance(
        &self,
        payment_endpoint: &Url,
        address: &WalletAddress,
    ) -> Result<BalanceResponse, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                payment_endpoint
                    .join(format!("./balance?address={}", address).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::kib(1))
            .idempotent(true)
            .build();

        Ok(self.send_api_request::<ViaJson<_>>(req).await?.0)
    }

    async fn turbo_price(
        &self,
        payment_endpoint: &Url,
        bytes: u64,
        destination_address: Option<&WalletAddress>,
    ) -> Result<PriceResponse, api::Error> {
        let mut url = payment_endpoint
            .join(format!("./price/bytes/{}", bytes).as_str())
            .map_err(api::Error::InvalidUrl)?;
        if let Some(addr) = destination_address {
            url = url
                .join(format!("?destinationAddress={}", addr).as_str())
                .map_err(api::Error::InvalidUrl)?;
        }

        let req = ApiRequest::builder()
            .endpoint(url)
            .request_method(Get)
            .max_response_len(ByteSize::kib(1))
            .idempotent(true)
            .build();

        Ok(self.send_api_request::<ViaJson<_>>(req).await?.0)
    }

    async fn turbo_upload(
        &self,
        upload_endpoint: &Url,
        data_len: u64,
        data: impl AsyncRead + Send + Unpin + 'static,
    ) -> Result<UploadResponse, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                upload_endpoint
                    .join(format!("./tx").as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Post)
            .body(
                ApiRequestBody::builder()
                    .content_type(ContentType::OctetStream)
                    .content_length(data_len)
                    .payload(Payload::from_reader(data))
                    .build(),
            )
            .idempotent(false)
            .build();

        Ok(self.send_api_request::<ViaJson<_>>(req).await?.0)
    }
}

impl Client {
    pub async fn turbo_balance(
        &self,
        address: &WalletAddress,
    ) -> Result<Money<Winston>, super::Error> {
        let resp = self
            .0
            .api
            .turbo_balance(&self.0.turbo.payment_endpoint, address)
            .await?;

        Ok(resp.effective_balance)
    }

    pub async fn turbo_price(
        &self,
        data_size: u64,
        destination: Option<&WalletAddress>,
    ) -> Result<Money<Winston>, super::Error> {
        let resp = self
            .0
            .api
            .turbo_price(&self.0.turbo.payment_endpoint, data_size, destination)
            .await?;

        Ok(resp.winc)
    }

    pub async fn turbo_upload(
        &self,
        item: &AuthenticatedBundleItem<'_>,
        data: impl AsyncRead + AsyncSeek + Send + Sync + Unpin + 'static,
        data_size: u64,
    ) -> Result<(UploadResponse, u64, Money<Winston>), super::Error> {
        let header = match &item {
            AuthenticatedBundleItem::V2(v2) => v2
                .try_as_blob()
                .map_err(|e| Error::from(BundleItemError::TagError(e)))?,
        };
        if data_size != item.data_size() {
            Err(Error::IncorrectDataSize {
                expected: item.data_size(),
                actual: data_size,
            })?;
        }

        let data = BundleItemCombinator::single_item(header, data, data_size);
        let total_upload_size = data.len();

        let owner = item.owner();
        let owner_address = owner.address();
        let price = self
            .turbo_price(total_upload_size, Some(&owner_address))
            .await?;

        let resp = self
            .0
            .api
            .turbo_upload(&self.0.turbo.upload_endpoint, total_upload_size, data)
            .await?;

        Ok((resp, total_upload_size, price))
    }
}

#[derive(Debug, Clone, Deserialize)]
struct BalanceResponse {
    #[serde(rename = "controlledWinc")]
    controlled_winc: Money<Winston>,
    winc: Money<Winston>,
    balance: Money<Winston>,
    #[serde(rename = "effectiveBalance")]
    effective_balance: Money<Winston>,
}

#[derive(Debug, Clone, Deserialize)]
struct PriceResponse {
    winc: Money<Winston>,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct UploadResponse {
    #[serde_as(as = "DisplayFromStr")]
    pub id: BundleItemId,
    owner: String,
    #[serde(default, rename = "dataCaches")]
    pub data_caches: Vec<String>,
    #[serde(default, rename = "fastFinalityIndexes")]
    pub fast_finality_indexes: Vec<String>,
    #[serde(rename = "deadlineHeight")]
    pub deadline_height: BlockNumber,
    #[serde(deserialize_with = "deserialize_millis")]
    pub timestamp: DateTime<Utc>,
    pub version: String,
}

fn deserialize_millis<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let millis = i64::deserialize(deserializer)?;
    DateTime::from_timestamp_millis(millis)
        .ok_or_else(|| serde::de::Error::custom("invalid timestamp"))
}
