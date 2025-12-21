use crate::api::RequestMethod::{Get, Post};
use crate::api::{
    Api, ApiRequest, ApiRequestBody, ContentType, Payload, PayloadError, TryFromResponseStream,
    ViaJson,
};
use crate::routemaster::Handle;
use crate::{Client, Error, api};
use ario_core::base64::OptionalBase64As;
use ario_core::blob::{AsBlob, Blob};
use ario_core::buffer::ByteBuffer;
use ario_core::crypto::merkle::ProofError;
use ario_core::data::{
    AuthenticatedTxDataChunk, Authenticator, DataRoot, ExternalDataItemAuthenticator,
    TxDataAuthenticityProof, UnauthenticatedTxDataChunk,
};
use ario_core::tx::TxId;
use ario_core::{AuthenticationState, Gateway};
use bytesize::ByteSize;
use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;
use serde_with::base64::Base64;
use serde_with::base64::UrlSafe;
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use std::io::{Read, Seek};
use std::ops::Range;
use std::time::Duration;

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

    async fn download_chunk_proof(
        &self,
        gateway: &Gateway,
        offset: u128,
    ) -> Result<Option<TxChunkProof<'static>>, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join(format!("./chunk_proof/{}", offset).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::kib(64))
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

    async fn download_chunk_proof2(
        &self,
        gateway: &Gateway,
        offset: u128,
    ) -> Result<Option<TxChunkProof<'static>>, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join(format!("./chunk_proof2/{}", offset).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::kib(64))
            .idempotent(true)
            .build();

        match self.send_optional_api_request(req).await? {
            Some(stream) => {
                let buf = <ByteBuffer<'_> as TryFromResponseStream>::try_from(stream).await?;
                Ok(Some(buf.try_into().map_err(|e| {
                    PayloadError::DeserializationError(format!("error deserializing chunk: {}", e))
                })?))
            }
            None => Ok(None),
        }
    }

    async fn download_raw_tx_data(
        &self,
        gateway: &Gateway,
        tx_id: &TxId,
        range: &Range<u64>,
    ) -> Result<Option<ByteBuffer<'static>>, api::Error> {
        let expected_len = range.end - range.start;

        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join(format!("./{}", tx_id).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::b(expected_len + 1024))
            .range(range.clone())
            .idempotent(true)
            .build();

        match self.send_optional_api_request(req).await? {
            Some(stream) => {
                let buf = <ByteBuffer<'_> as TryFromResponseStream>::try_from(stream).await?;
                if buf.len() != expected_len {
                    Err(PayloadError::IncorrectLength {
                        expected: expected_len,
                        actual: buf.len(),
                    })?;
                }
                Ok(Some(buf))
            }
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
        self.upload_chunk_with_gw(
            &gw,
            authenticator,
            offset,
            UnauthenticatedTxDataChunk::from_byte_buffer(data.into(), offset.start),
        )
        .await
    }

    pub(crate) async fn upload_chunk_with_gw(
        &self,
        gw_handle: &Handle<Gateway>,
        authenticator: &ExternalDataItemAuthenticator<'_>,
        offset: &Range<u64>,
        unauthenticated_data: UnauthenticatedTxDataChunk<'_>,
    ) -> Result<(), super::Error> {
        let len = offset.end - offset.start;
        if len == 0 {
            return Err(UploadError::EmptyChunk.into());
        }
        if unauthenticated_data.len() != len {
            return Err(UploadError::IncorrectChunkLen {
                expected: len,
                actual: unauthenticated_data.len(),
            }
            .into());
        }

        let proof = authenticator
            .proof(offset)
            .ok_or(UploadError::ProofNotFound(offset.start))?;

        let tx_data_proof =
            TxDataAuthenticityProof::new(authenticator.data_item().data_root(), proof.clone());

        let authenticated_data = unauthenticated_data
            .authenticate(&tx_data_proof)
            .map_err(|(_, e)| UploadError::ProofError(e.into()))?;

        // looking good, create upload json
        let upload_chunk = UploadChunk {
            data_root: authenticator.data_item().data_root().as_blob(),
            data_size: authenticator.data_item().data_size(),
            data_path: proof.as_blob(),
            offset: offset.start,
            //chunk: authenticated_data,
            chunk: authenticated_data.authenticated_data().make_contiguous(),
        };

        let api = &self.0.api;
        let chunk = &upload_chunk;
        self.with_existing_gw(gw_handle, async move |gw| api.upload_chunk(gw, chunk).await)
            .await?;
        Ok(())
    }

    pub async fn retrieve_chunk_proof(
        &self,
        offset: u128,
    ) -> Result<Option<TxChunkProof<'static>>, super::Error> {
        self.0
            .cache
            .get_tx_chunk_proof(offset, async |offset| {
                self._retrieve_chunk_proof_live(offset).await
            })
            .await
    }

    async fn _retrieve_chunk_proof_live(
        &self,
        offset: u128,
    ) -> Result<Option<TxChunkProof<'static>>, super::Error> {
        // At the time of writing this, downloading chunk proofs from Arweave gateways is highly unreliable.
        // There is a very high chance of getting a result with a 570 status code when requesting a legitimate chunk proof.
        // Retrying after some time often succeeds. This flakiness severely impacts Arweave's usefulness.
        //
        // This multi-step, retry-heavy approach, while seemingly complex, seems to increase chances of success.
        // Hopefully this will be fixed at one point on the gateway level and the code below can be removed / cleaned up.
        self.with_gw(async |gw| {
            match {
                let mut retry_delay = Duration::from_millis(250);

                let mut proof2_attempts: u8 = 20;
                let mut proof_attempts: u8 = 20;
                loop {
                    if proof2_attempts > 0 {
                        proof2_attempts = proof2_attempts.saturating_sub(1);
                        match self.0.api.download_chunk_proof2(gw, offset).await {
                            Ok(Some(proof)) => break Some(proof),
                            Err(api::Error::HttpResponseError(status_code, _))
                                if status_code == 570 =>
                            {
                                // Temporarily unavailable, retry
                            }
                            _ => break None,
                        }
                    }

                    if proof_attempts > 0 {
                        proof_attempts = proof_attempts.saturating_sub(1);
                        proof2_attempts = proof2_attempts.saturating_sub(1);
                        match self.0.api.download_chunk_proof(gw, offset).await {
                            Ok(Some(proof)) => break Some(proof),
                            Err(api::Error::HttpResponseError(status_code, _))
                                if status_code == 570 =>
                            {
                                // Temporarily unavailable, retry
                            }
                            _ => break None,
                        }
                    }

                    if proof_attempts == 0 && proof2_attempts == 0 {
                        break None;
                    }
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = (retry_delay * 2).min(Duration::from_secs(4));
                }
            } {
                Some(chunk_proof) => {
                    Ok::<Option<TxChunkProof<'_>>, super::Error>(Some(chunk_proof))
                }
                None => Err(DownloadError::ChunkUnobtainable(offset))?,
            }
        })
        .await
    }

    pub(crate) async fn retrieve_unauthenticated_chunk(
        &self,
        relative_range: &Range<u64>,
        tx_id: &TxId,
    ) -> Result<Option<UnauthenticatedTxDataChunk<'static>>, super::Error> {
        self.0
            .cache
            .get_unauthenticated_chunk(relative_range, tx_id, async |range, tx_id| {
                self._retrieve_unauthenticated_chunk_live(range, tx_id)
                    .await
            })
            .await
    }

    async fn _retrieve_unauthenticated_chunk_live(
        &self,
        relative_range: &Range<u64>,
        tx_id: &TxId,
    ) -> Result<Option<UnauthenticatedTxDataChunk<'static>>, super::Error> {
        // Downloads the raw tx data directly using a range request.
        self.with_gw(async |gw| {
            Ok::<Option<UnauthenticatedTxDataChunk<'_>>, super::Error>(
                self.0
                    .api
                    .download_raw_tx_data(gw, tx_id, relative_range)
                    .await?
                    .map(|chunk| {
                        UnauthenticatedTxDataChunk::from_byte_buffer(chunk, relative_range.start)
                    }),
            )
        })
        .await
    }

    pub async fn retrieve_chunk(
        &self,
        offset: u128,
        relative_range: &Range<u64>,
        data_root: &DataRoot,
        tx_id: &TxId,
    ) -> Result<Option<AuthenticatedTxDataChunk<'static>>, super::Error> {
        self.0
            .cache
            .get_authenticated_chunk(
                offset,
                relative_range,
                data_root,
                tx_id,
                async |range, tx_id| {
                    self._retrieve_unauthenticated_chunk_live(range, tx_id)
                        .await
                },
                async |offset| self.retrieve_chunk_proof(offset).await,
            )
            .await
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
    IncorrectChunkLen { expected: u64, actual: u64 },
}

#[derive(Error, Debug)]
pub enum DownloadError {
    #[error(transparent)]
    ProofError(#[from] ProofError),
    #[error(
        "failed to download chunk at offset {0}. this usually indicates a temporary problem with the gateway"
    )]
    ChunkUnobtainable(u128),
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
    //chunk: AuthenticatedTxDataChunk<'a>,
}

fn read_u24_be(reader: &mut impl Read) -> std::io::Result<u32> {
    let mut buf = [0x00, 0x00, 0x00];
    reader.read_exact(&mut buf)?;
    Ok(((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32))
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct TxChunkProof<'a> {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub data_path: Blob<'a>,
    #[serde_as(as = "OptionalBase64As")]
    #[serde(default)]
    pub tx_path: Option<Blob<'a>>,
}

impl<'a> TryFrom<ByteBuffer<'a>> for TxChunkProof<'a> {
    type Error = std::io::Error;

    fn try_from(value: ByteBuffer<'a>) -> Result<Self, Self::Error> {
        let mut reader = value.cursor();

        let tx_path_size = read_u24_be(&mut reader)?;

        reader.seek_relative(tx_path_size as i64)?;
        let data_path_size = read_u24_be(&mut reader)?;

        let (_, value) = value.split_at(3); // Skip tx_path_size bytes
        let (tx_path, value) = value.split_at(tx_path_size as u64);
        let tx_path = if !tx_path.is_empty() {
            Some(tx_path.make_contiguous())
        } else {
            None
        };

        let (_, value) = value.split_at(3); // Skip data_path_size bytes
        let (data_path, _) = value.split_at(data_path_size as u64);
        let data_path = data_path.make_contiguous();

        Ok(Self { tx_path, data_path })
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;
    use ario_core::Gateway;
    use ario_core::network::Network;
    use ario_core::tx::TxId;
    use std::str::FromStr;

    static CHUNK_PATH: &'static str = "./testdata/366659587055863.chunk2";

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

        for range in data_item.chunk_map().unwrap().iter() {
            let chunk = client
                .retrieve_chunk(tx_offset.absolute(total), &range, data_root, tx.id())
                .await?
                .unwrap();

            // test cache
            let chunk_2 = client
                .retrieve_chunk(tx_offset.absolute(total), &range, data_root, tx.id())
                .await?
                .unwrap();

            assert_eq!(chunk, chunk_2);

            total += chunk.len();
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
        let range = total..data_item.size();

        for range in data_item.chunk_map().unwrap().iter() {
            let chunk = client
                .retrieve_chunk(tx_offset.absolute(total), &range, data_root, tx.id())
                .await?
                .unwrap();

            total += chunk.len();
            if total >= data_item.size() {
                break;
            }
        }

        assert_eq!(total, data_item.size());

        Ok(())
    }
}
