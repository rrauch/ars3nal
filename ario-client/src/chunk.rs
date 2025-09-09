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
use ario_core::data::{DataRoot, ExternalDataItemVerifier, Verifier};
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
    ) -> Result<Option<DownloadChunk<'static>>, api::Error> {
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
        verifier: &ExternalDataItemVerifier<'_>,
        offset: &Range<u64>,
        data: Blob<'_>,
    ) -> Result<(), super::Error> {
        let gw = self.0.routemaster.gateway().await?;
        self.upload_chunk_with_gw(&gw, verifier, offset, data).await
    }

    pub(crate) async fn upload_chunk_with_gw(
        &self,
        gw_handle: &Handle<Gateway>,
        verifier: &ExternalDataItemVerifier<'_>,
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

        let proof = verifier
            .proof(offset)
            .ok_or(UploadError::ProofNotFound(offset.start))?;

        // verify data against merkle tree
        verifier
            .data_item()
            .data_root()
            .verify_data(&mut Cursor::new(&data), &proof)
            .map_err(|e| UploadError::ProofError(e.into()))?;

        // looking good, create upload json
        let upload_chunk = UploadChunk {
            data_root: verifier.data_item().data_root().as_blob(),
            data_size: verifier.data_item().data_size(),
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

    pub async fn download_chunk(
        &self,
        offset: u128,
        relative_offset: u64,
        data_root: &DataRoot,
    ) -> Result<Option<Blob<'static>>, super::Error> {
        let api = &self.0.api;

        let chunk: DownloadChunk<'static> = match self
            .with_gw(async move |gw| api.download_chunk(gw, offset).await)
            .await?
        {
            Some(chunk) => chunk,
            None => {
                return Ok(None);
            }
        };

        let proof = DefaultProof::new(
            relative_offset..(relative_offset + chunk.chunk.len() as u64),
            chunk.data_path,
        );

        data_root
            .verify_data(&mut Cursor::new(chunk.chunk.as_ref()), &proof)
            .map_err(|e| DownloadError::ProofError(e))?;

        // verification passed, chunk data ok
        Ok(Some(chunk.chunk))
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

#[serde_as]
#[derive(Clone, Deserialize, Debug)]
struct DownloadChunk<'a> {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    chunk: Blob<'a>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    data_path: Blob<'a>,
    #[serde_as(as = "OptionalBase64As")]
    #[serde(default)]
    tx_path: Option<Blob<'a>>,
    /*#[serde_as(as = "OptionalBase64As")]
    #[serde(default)]
    data_root: Option<Blob<'a>>,
    #[serde(default)]
    data_size: Option<u64>,
    #[serde(default)]
    offset: Option<u128>,*/
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
            .build();

        let tx = client
            .tx_by_id(&TxId::from_str(
                "-ynymmePYt7lZMOaCgcvkPUeaK0eFa_F7Ox7CJ629Ak",
            )?)
            .await?
            .unwrap()
            .validate()
            .map_err(|(_, e)| e)?;

        let data_item = tx.data_item().unwrap();
        let data = data_item.data();
        let data_root = data.data_root().unwrap();

        let tx_offset = client.tx_offset(tx.id()).await?;

        let mut total = 0;

        while let Some(chunk) = client
            .download_chunk(tx_offset.absolute(total), total, data_root)
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
            .build();

        let tx = client
            .tx_by_id(&TxId::from_str(
                "fU8dt860JoHpLQIq_n5b47OyPK9nDNTptRHFR_E1TAc",
            )?)
            .await?
            .unwrap()
            .validate()
            .map_err(|(_, e)| e)?;

        let data_item = tx.data_item().unwrap();
        let data = data_item.data();
        let data_root = data.data_root().unwrap();

        let tx_offset = client.tx_offset(tx.id()).await?;

        let mut total = 0;

        while let Some(chunk) = client
            .download_chunk(tx_offset.absolute(total), total, data_root)
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
