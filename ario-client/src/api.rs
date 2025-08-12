use ario_core::network::Network;
use bon::Builder;
use buf_list::{BufList, Cursor};
use bytes::{Bytes, BytesMut};
use bytesize::ByteSize;
use futures_lite::{Stream, StreamExt};
use maybe_owned::MaybeOwned;
use reqwest::Client as ReqwestClient;
use serde::de::DeserializeOwned;
use std::str::FromStr;
use std::string::FromUtf8Error;
use std::sync::Arc;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone)]
pub struct ApiClient(Arc<Inner>);

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error("http response error, status code:`{0}`, text: `{1}`")]
    HttpResponseError(u16, String),
    #[error("server sent 404 not found")]
    NotFoundError,
    #[error("server sent an unexpected response, details: `{0}`")]
    UnexpectedResponse(String),
    #[error("server response exceeds max length of `{0}` bytes")]
    MaxResponseLenExceeded(u64),
    #[error(transparent)]
    InvalidJson(#[from] serde_json::Error),
    #[error(transparent)]
    InvalidUrl(#[from] url::ParseError),
    #[error(transparent)]
    InvalidUtf8(#[from] FromUtf8Error),
    #[error("server response was empty")]
    UnexpectedEmptyResponse,
}

impl ApiClient {
    pub(crate) fn new(reqwest_client: ReqwestClient, network: Network) -> Self {
        Self(Arc::new(Inner {
            reqwest_client,
            network,
        }))
    }

    pub fn network(&self) -> &Network {
        &self.0.network
    }

    pub(super) async fn send_api_request<'a, T: TryFromResponseStream>(
        &self,
        api_request: ApiRequest<'a>,
    ) -> Result<T, Error> {
        match self.send_optional_api_request(api_request).await {
            Ok(Some(stream)) => Ok(T::try_from(stream).await?),
            Ok(None) => Err(Error::NotFoundError),
            Err(e) => Err(e),
        }
    }

    async fn send_optional_api_request<'a>(
        &self,
        api_request: ApiRequest<'a>,
    ) -> Result<Option<impl ResponseStream>, Error> {
        let req = self
            .0
            .reqwest_client
            .request(
                api_request.request_method.into(),
                api_request.endpoint.into_owned(),
            )
            .header("Accept", "application/json")
            .header::<&str, &str>("x-network", self.network().id())
            .build()
            .map_err(Error::ReqwestError)?;

        let resp = self.0.reqwest_client.execute(req).await?;
        let status = resp.status();

        if status.as_u16() == 404 {
            return Ok(None);
        }

        if status.is_client_error() || status.is_server_error() {
            let text = resp
                .text_with_charset("utf-8")
                .await
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| status.to_string());
            return Err(Error::HttpResponseError(status.as_u16(), text));
        }

        let max_bytes = api_request
            .max_response_len
            .map(|b| b.as_u64())
            .unwrap_or(u64::MAX);

        // check both, the content-length header and the response body
        if let Some(content_len) = [
            resp.content_length(),
            resp.headers()
                .get("Content-Length")
                .map(|v| v.to_str().map(|s| u64::from_str(s).ok()).ok().flatten())
                .flatten(),
        ]
        .into_iter()
        .max()
        .flatten()
        {
            if content_len > max_bytes {
                return Err(Error::MaxResponseLenExceeded(max_bytes));
            }
        }

        Ok(Some(resp.bytes_stream().scan(
            0u64,
            move |total, chunk| match chunk {
                Ok(bytes) => {
                    *total += bytes.len() as u64;
                    if *total > max_bytes {
                        Some(Err(ResponseStreamError::MaxResponseLenExceeded(max_bytes)))
                    } else {
                        Some(Ok(bytes))
                    }
                }
                Err(e) => Some(Err(e.into())),
            },
        )))
    }
}

#[derive(Error, Debug)]
enum ResponseStreamError {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error("server response exceeds max length of `{0}` bytes")]
    MaxResponseLenExceeded(u64),
}

impl From<ResponseStreamError> for Error {
    fn from(value: ResponseStreamError) -> Self {
        match value {
            ResponseStreamError::ReqwestError(err) => Error::ReqwestError(err),
            ResponseStreamError::MaxResponseLenExceeded(len) => Error::MaxResponseLenExceeded(len),
        }
    }
}

pub(super) trait TryFromResponseStream {
    fn try_from<R: ResponseStream>(stream: R) -> impl Future<Output = Result<Self, Error>>
    where
        Self: Sized;
}

pub(crate) struct ViaJson<T: DeserializeOwned>(pub T);

impl<T: DeserializeOwned> TryFromResponseStream for ViaJson<T> {
    async fn try_from<R: ResponseStream>(stream: R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let chunks: BufList = stream.try_collect().await?;

        if chunks.num_bytes() == 0 {
            return Err(Error::UnexpectedEmptyResponse);
        }

        Ok(ViaJson(serde_json::from_reader(Cursor::new(&chunks))?))
    }
}

impl TryFromResponseStream for String {
    async fn try_from<R: ResponseStream>(stream: R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let bytes = stream.try_into_bytes().await?;
        Ok(String::from_utf8(bytes.to_vec())?)
    }
}

pub(crate) trait ResponseStream:
    Stream<Item = Result<Bytes, ResponseStreamError>> + Unpin + Send
{
    fn try_into_bytes(mut self) -> impl Future<Output = Result<Bytes, ResponseStreamError>> + Send
    where
        Self: Sized,
    {
        async move {
            let mut buf = BytesMut::new();
            while let Some(chunk) = self.next().await {
                let chunk = BytesMut::from(chunk?);
                buf.unsplit(chunk);
            }
            Ok(buf.freeze())
        }
    }
}
impl<T> ResponseStream for T where
    T: Stream<Item = Result<Bytes, ResponseStreamError>> + Unpin + Send
{
}

#[derive(Debug, PartialEq, Eq)]
pub enum RequestMethod {
    Get,
    Post,
}

impl From<RequestMethod> for reqwest::Method {
    fn from(value: RequestMethod) -> Self {
        match value {
            RequestMethod::Get => reqwest::Method::GET,
            RequestMethod::Post => reqwest::Method::POST,
        }
    }
}

#[derive(Builder)]
pub(crate) struct ApiRequest<'a> {
    #[builder(into)]
    endpoint: MaybeOwned<'a, Url>,
    request_method: RequestMethod,
    max_response_len: Option<ByteSize>,
}

#[derive(Debug)]
struct Inner {
    reqwest_client: ReqwestClient,
    network: Network,
}
