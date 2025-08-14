use crate::api::RequestMethod::Post;
use crate::api::{Api, ApiRequest, ApiRequestBody, ContentType, Payload};
use crate::{Client, api};
use ario_core::Gateway;
use ario_core::blob::{AsBlob, Blob};
use ario_core::crypto::merkle::ProofError;
use ario_core::data::VerifiableData;
use bytesize::ByteSize;
use serde::Serialize;
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
}

impl Client {
    pub async fn upload_chunk(&self) {}

    pub(crate) async fn upload_chunk_with_gw(
        &self,
        gateway: &Gateway,
        verifiable: &VerifiableData<'_>,
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

        let proof = verifiable
            .proof(offset)
            .ok_or(UploadError::ProofNotFound(offset.start))?;

        // verify data against merkle tree
        verifiable
            .external_data()
            .root()
            .verify_data(&mut Cursor::new(&data), &proof)
            .map_err(|e| UploadError::ProofError(e.into()))?;

        // looking good, create upload json
        let upload_chunk = UploadChunk {
            data_root: verifiable.external_data().root().as_blob(),
            data_size: verifiable.external_data().size(),
            data_path: proof.as_blob(),
            offset: offset.start,
            chunk: data,
        };

        self.0.api.upload_chunk(gateway, &upload_chunk).await?;
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum UploadError {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    ProofError(#[from] ProofError),
    #[error("no proof was found for chunk at offset '{0}'")]
    ProofNotFound(u64),
    #[error("chunk cannot be empty")]
    EmptyChunk,
    #[error("chunk length incorrect; expected '{expected}' but got '{actual}'")]
    IncorrectChunkLen { expected: usize, actual: usize },
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
