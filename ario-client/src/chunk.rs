use crate::api::RequestMethod::{Get, Post};
use crate::api::{
    Api, ApiRequest, ApiRequestBody, ContentType, Payload, TryFromResponseStream, ViaJson,
};
use crate::routemaster::Handle;
use crate::{Client, api};
use ario_core::Gateway;
use ario_core::base64::OptionalBase64As;
use ario_core::blob::{AsBlob, Blob};
use ario_core::crypto::merkle::{DefaultProof, ProofError};
use ario_core::data::{
    AuthenticatedTxDataChunk, Authenticator, DataRoot, ExternalDataItemAuthenticator,
    TxDataAuthenticityProof, TxDataChunk,
};
use bytesize::ByteSize;
use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;
use serde_with::base64::Base64;
use serde_with::base64::UrlSafe;
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use std::io::Cursor;
use std::ops::Range;
use thiserror::Error;

impl Api {
    async fn upload_chunk(
        &self,
        gateway: &Gateway,
        chunk: &UploadChunk<'_>,
    ) -> Result<(), api::Error> {
        let chunk_json = serde_json::to_value(chunk)?;

        let req = ApiRequest::builder()
            .endpoint(gateway.join("./chunk").map_err(api::Error::InvalidUrl)?)
            .request_method(Post)
            .body(
                ApiRequestBody::builder()
                    .content_type(ContentType::Json)
                    .payload(Payload::Json(&chunk_json))
                    .build(),
            )
            .max_response_len(ByteSize::kib(64))
            .build();

        Ok(self.send_api_request(req).await?)
    }

    async fn download_chunk(
        &self,
        gateway: &Gateway,
        offset: u128,
    ) -> Result<Option<RawTxDownloadChunk<'static>>, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join(format!("./chunk/{}", offset).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::mib(1))
            .idempotent(true)
            .build();

        match self.send_optional_api_request(req).await? {
            Some(stream) => Ok(Some(
                <ViaJson<_> as TryFromResponseStream>::try_from(stream)
                    .await?
                    .0,
            )),
            None => Ok(None),
        }
    }
}

impl Client {
    pub async fn upload_chunk(
        &self,
        authenticator: &ExternalDataItemAuthenticator<'_>,
        offset: &Range<u64>,
        data: Blob<'_>,
    ) -> Result<(), super::Error> {
        let gw = self.0.routemaster.gateway().await?;
        self.upload_chunk_with_gw(&gw, authenticator, offset, data)
            .await
    }

    pub(crate) async fn upload_chunk_with_gw(
        &self,
        gw_handle: &Handle<Gateway>,
        authenticator: &ExternalDataItemAuthenticator<'_>,
        offset: &Range<u64>,
        data: Blob<'_>,
    ) -> Result<(), super::Error> {
        let len = offset.end - offset.start;
        if len == 0 {
            return Err(UploadError::EmptyChunk.into());
        }
        if data.len() != len as usize {
            return Err(UploadError::IncorrectChunkLen {
                expected: len as usize,
                actual: data.len(),
            }
            .into());
        }

        let proof = authenticator
            .proof(offset)
            .ok_or(UploadError::ProofNotFound(offset.start))?;

        // authenticate data using merkle tree
        authenticator
            .data_item()
            .data_root()
            .authenticate_data(&mut Cursor::new(&data), &proof)
            .map_err(|e| UploadError::ProofError(e.into()))?;

        // looking good, create upload json
        let upload_chunk = UploadChunk {
            data_root: authenticator.data_item().data_root().as_blob(),
            data_size: authenticator.data_item().data_size(),
            data_path: proof.as_blob(),
            offset: offset.start,
            chunk: data,
        };

        let api = &self.0.api;
        let chunk = &upload_chunk;
        self.with_existing_gw(gw_handle, async move |gw| api.upload_chunk(gw, chunk).await)
            .await?;
        Ok(())
    }

    pub async fn retrieve_chunk(
        &self,
        offset: u128,
        relative_offset: u64,
        data_root: &DataRoot,
    ) -> Result<Option<AuthenticatedTxDataChunk<'static>>, super::Error> {
        self.0
            .cache
            .get_chunk(offset, data_root, relative_offset, async |offset| {
                self._retrieve_chunk_live(offset, relative_offset, data_root)
                    .await
            })
            .await
    }

    async fn _retrieve_chunk_live(
        &self,
        offset: u128,
        relative_offset: u64,
        data_root: &DataRoot,
    ) -> Result<Option<ValidatedTxDownloadChunk<'static>>, super::Error> {
        let chunk: UnvalidatedTxDownloadChunk<'static> = match self
            .with_gw(async |gw| self.0.api.download_chunk(gw, offset).await)
            .await?
        {
            Some(chunk) => chunk.into(),
            None => {
                return Ok(None);
            }
        };

        Ok(Some(
            chunk
                .validate(data_root, relative_offset)
                .map_err(DownloadError::ProofError)?,
        ))
    }
}

#[derive(Error, Debug)]
pub enum UploadError {
    #[error(transparent)]
    ProofError(#[from] ProofError),
    #[error("no proof was found for chunk at offset '{0}'")]
    ProofNotFound(u64),
    #[error("chunk cannot be empty")]
    EmptyChunk,
    #[error("chunk length incorrect; expected '{expected}' but got '{actual}'")]
    IncorrectChunkLen { expected: usize, actual: usize },
}

#[derive(Error, Debug)]
pub enum DownloadError {
    #[error(transparent)]
    ProofError(#[from] ProofError),
}

#[serde_as]
#[derive(Clone, Serialize, Debug)]
struct UploadChunk<'a> {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    data_root: Blob<'a>,
    #[serde_as(as = "DisplayFromStr")]
    data_size: u64,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    data_path: Blob<'a>,
    #[serde_as(as = "DisplayFromStr")]
    offset: u64,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    chunk: Blob<'a>,
}

pub(crate) type UnvalidatedTxDownloadChunk<'a> = TxDownloadChunk<'a, false>;
impl<'a> UnvalidatedTxDownloadChunk<'a> {
    pub(crate) fn validate(
        self,
        data_root: &DataRoot,
        relative_offset: u64,
    ) -> Result<ValidatedTxDownloadChunk<'a>, ProofError> {
        let proof = TxDataAuthenticityProof::new(
            data_root.into(),
            DefaultProof::new(
                relative_offset..(relative_offset + self.chunk.len() as u64),
                Blob::Slice(self.data_path.bytes()),
            ),
        );

        let validated = self.chunk.authenticate(&proof).map_err(|(_, e)| e)?;

        Ok(TxDownloadChunk {
            chunk: validated,
            data_path: self.data_path,
            tx_path: self.tx_path,
        })
    }
}

pub(crate) type ValidatedTxDownloadChunk<'a> = TxDownloadChunk<'a, true>;

impl<'a> ValidatedTxDownloadChunk<'a> {
    pub(crate) fn invalidate(self) -> UnvalidatedTxDownloadChunk<'a> {
        TxDownloadChunk {
            chunk: self.chunk.invalidate(),
            data_path: self.data_path,
            tx_path: self.tx_path,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TxDownloadChunk<'a, const VALIDATED: bool> {
    pub(crate) chunk: TxDataChunk<'a, VALIDATED>,
    data_path: Blob<'a>,
    tx_path: Option<Blob<'a>>,
}

impl<'a> From<RawTxDownloadChunk<'a>> for UnvalidatedTxDownloadChunk<'a> {
    fn from(raw: RawTxDownloadChunk<'a>) -> Self {
        Self {
            chunk: TxDataChunk::from_blob(raw.chunk),
            data_path: raw.data_path,
            tx_path: raw.tx_path,
        }
    }
}

impl<'a> From<ValidatedTxDownloadChunk<'a>> for RawTxDownloadChunk<'a> {
    fn from(value: ValidatedTxDownloadChunk<'a>) -> Self {
        Self {
            chunk: value.chunk.into_inner(),
            data_path: value.data_path,
            tx_path: value.tx_path,
        }
    }
}

#[serde_as]
#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct RawTxDownloadChunk<'a> {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub chunk: Blob<'a>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub data_path: Blob<'a>,
    #[serde_as(as = "OptionalBase64As")]
    #[serde(default)]
    pub tx_path: Option<Blob<'a>>,
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use ario_core::Gateway;
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
    async fn download_chunks() -> anyhow::Result<()> {
        init_tracing();

        let client = Client::builder()
            .gateways([Gateway::default()])
            .enable_netwatch(false)
            .build()
            .await?;

        let tx = client
            .tx_by_id(&TxId::from_str(
                "-ynymmePYt7lZMOaCgcvkPUeaK0eFa_F7Ox7CJ629Ak",
            )?)
            .await?
            .unwrap();

        let data_item = tx.data_item().unwrap();
        let data = data_item.data();
        let data_root = data.tx_data_root().unwrap();

        let tx_offset = client.tx_offset(tx.id()).await?;

        let mut total = 0;

        while let Some(chunk) = client
            .retrieve_chunk(tx_offset.absolute(total), total, data_root)
            .await?
        {
            // test cache
            let chunk_2 = client
                .retrieve_chunk(tx_offset.absolute(total), total, data_root)
                .await?
                .unwrap();

            assert_eq!(chunk, chunk_2);

            total += chunk.len() as u64;
            if total >= data_item.size() {
                break;
            }
        }

        assert_eq!(total, data_item.size());

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn download_chunks_local() -> anyhow::Result<()> {
        dotenv::dotenv().ok();
        init_tracing();

        let arlocal = std::env::var("ARLOCAL_URL").unwrap();
        let network_id = std::env::var("ARLOCAL_ID").unwrap_or("arlocal".to_string());

        let client = Client::builder()
            .enable_netwatch(false)
            .network(Network::Local(network_id.try_into()?))
            .gateways([Gateway::from_str(arlocal.as_str())?])
            .build()
            .await?;

        let tx = client
            .tx_by_id(&TxId::from_str(
                "fU8dt860JoHpLQIq_n5b47OyPK9nDNTptRHFR_E1TAc",
            )?)
            .await?
            .unwrap();

        let data_item = tx.data_item().unwrap();
        let data = data_item.data();
        let data_root = data.tx_data_root().unwrap();

        let tx_offset = client.tx_offset(tx.id()).await?;

        let mut total = 0;

        while let Some(chunk) = client
            .retrieve_chunk(tx_offset.absolute(total), total, data_root)
            .await?
        {
            total += chunk.len() as u64;
            if total >= data_item.size() {
                break;
            }
        }

        assert_eq!(total, data_item.size());

        Ok(())
    }
}
