use ario_core::JsonValue;
use ario_core::network::Network;
use bon::Builder;
use buf_list::{BufList, Cursor};
use bytes::{Bytes, BytesMut};
use bytesize::ByteSize;
use futures_lite::{Stream, StreamExt};
use maybe_owned::MaybeOwned;
use reqwest::Client as ReqwestClient;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::{Debug, Formatter};
use std::pin::Pin;
use std::str::FromStr;
use std::string::{FromUtf8Error, FromUtf16Error};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tracing::instrument;
use url::Url;

#[derive(Debug, Clone)]
pub struct Api(Arc<Inner>);

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
    #[error(transparent)]
    InvalidUtf16(#[from] FromUtf16Error),
    #[error("server response was empty")]
    UnexpectedEmptyResponse,
    #[error(transparent)]
    TxError(#[from] ario_core::tx::TxError),
    #[error(transparent)]
    BundleError(#[from] ario_core::bundle::Error),
    #[error(transparent)]
    PayloadError(#[from] PayloadError),
    #[error("charset '{0:?}' unsupported")]
    UnsupportedCharset(Charset),
    #[cfg(feature = "graphql")]
    #[error(transparent)]
    GraphQlError(#[from] crate::graphql::GraphQlError),
}

impl Api {
    pub(crate) fn new(reqwest_client: ReqwestClient, network: Network, allow_retry: bool) -> Self {
        Self(Arc::new(Inner {
            reqwest_client,
            network,
            allow_retry,
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

    #[instrument(skip(self))]
    pub(super) async fn send_optional_api_request<'a>(
        &self,
        mut api_request: ApiRequest<'a>,
    ) -> Result<Option<impl ResponseStream>, Error> {
        let initiated = SystemTime::now();
        let mut attempts_left: usize =
            if self.0.allow_retry && api_request.is_idempotent && api_request.body.is_none() {
                2
            } else {
                1
            };

        let resp = loop {
            attempts_left = attempts_left.saturating_sub(1);
            let mut builder = self
                .0
                .reqwest_client
                .request(
                    api_request.request_method.into(),
                    api_request.endpoint.clone().into_owned(),
                )
                .header("Accept", api_request.accept.as_str())
                .header::<&str, &str>("x-network", self.network().id());

            if let Some(body) = api_request.body.take() {
                if let Some(content_type) = body.content_type {
                    builder = builder.header("Content-Type", content_type.as_str());
                }
                let body: reqwest::Body = body.payload.try_into()?;
                builder = builder.body(body)
            }

            let req = builder.build().map_err(Error::ReqwestError)?;

            tracing::debug!("sending api request");

            match self.0.reqwest_client.execute(req).await {
                Ok(resp) => break resp,
                Err(err) => {
                    if attempts_left > 0 {
                        // retry failed request
                        tracing::warn!(error = %err, "api request failed, retrying");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                    return Err(err.into());
                }
            }
        };

        let duration = SystemTime::now()
            .duration_since(initiated)
            .unwrap_or_default();

        let status = resp.status();
        tracing::debug!(status = %status, duration_ms = duration.as_millis(), "received api response");

        if status.as_u16() == 404 || status.as_u16() == 204 {
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

        let (content_type, charset) = if let Some(content_type) = resp
            .headers()
            .get("Content-Type")
            .map(|h| h.to_str().ok())
            .flatten()
        {
            let charset = content_type.split(';').skip(1).find_map(|param| {
                let param = param.trim();
                if param.len() > 8 && param[..8].eq_ignore_ascii_case("charset=") {
                    Charset::try_from(param[8..].trim_matches('"')).ok()
                } else {
                    None
                }
            });
            let content_type = ContentType::try_from(content_type).ok();
            (content_type, charset)
        } else {
            (None, None)
        };

        let stream = resp
            .bytes_stream()
            .scan(0u64, move |total, chunk| match chunk {
                Ok(bytes) => {
                    *total += bytes.len() as u64;
                    if *total > max_bytes {
                        Some(Err(ResponseStreamError::MaxResponseLenExceeded(max_bytes)))
                    } else {
                        Some(Ok(bytes))
                    }
                }
                Err(e) => Some(Err(e.into())),
            });

        Ok(Some(ResponseStreamWrapper {
            inner: stream,
            content_type,
            charset,
        }))
    }
}

struct ResponseStreamWrapper<T: Stream<Item = Result<Bytes, ResponseStreamError>> + Unpin + Send> {
    inner: T,
    content_type: Option<ContentType>,
    charset: Option<Charset>,
}

impl<T: Stream<Item = Result<Bytes, ResponseStreamError>> + Unpin + Send> Stream
    for ResponseStreamWrapper<T>
{
    type Item = Result<Bytes, ResponseStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_next(cx)
    }
}

impl<T: Stream<Item = Result<Bytes, ResponseStreamError>> + Unpin + Send> ResponseStream
    for ResponseStreamWrapper<T>
{
    fn content_type(&self) -> Option<ContentType> {
        self.content_type
    }

    fn charset(&self) -> Option<Charset> {
        self.charset
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
        let charset = stream.charset().unwrap_or(Charset::Utf8);
        let bytes = stream.try_into_bytes().await?.to_vec(); // todo: check if this is non-copying
        match charset {
            Charset::Utf8 | Charset::Ascii => Ok(String::from_utf8(bytes)?),
            Charset::Utf16 | Charset::Utf16Be | Charset::Utf16Le => {
                // check for even number of bytes
                if bytes.len() % 2 != 0 {
                    return Err(Error::UnexpectedResponse(
                        "expected even number of bytes in response".to_string(),
                    ));
                }

                let u16_vec = if [Charset::Utf16, Charset::Utf16Be].contains(&charset) {
                    // big endian
                    bytes
                        .chunks_exact(2)
                        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                        .collect::<Vec<_>>()
                } else {
                    // little endian
                    bytes
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect::<Vec<_>>()
                };
                Ok(String::from_utf16(&u16_vec)?)
            }
            unsupported => Err(Error::UnsupportedCharset(unsupported)),
        }
    }
}

impl TryFromResponseStream for () {
    async fn try_from<R: ResponseStream>(_: R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(())
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

    fn content_type(&self) -> Option<ContentType>;
    fn charset(&self) -> Option<Charset>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentType {
    Json,
    Text,
}

impl ContentType {
    fn as_str(&self) -> &str {
        match self {
            Self::Json => "application/json",
            Self::Text => "text/plain",
        }
    }
}

impl<'a> TryFrom<&'a str> for ContentType {
    type Error = &'a str;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let main_type = value.split(';').next().unwrap_or(value).trim();

        if main_type.eq_ignore_ascii_case("application/json") {
            Ok(Self::Json)
        } else if main_type.eq_ignore_ascii_case("text/plain") {
            Ok(Self::Text)
        } else {
            Err(value)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    Utf8,
    Utf16,
    Utf16Le,
    Utf16Be,
    Ascii,
    Latin1,
}

impl Default for Charset {
    fn default() -> Self {
        Self::Utf8
    }
}

impl<'a> TryFrom<&'a str> for Charset {
    type Error = &'a str;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.eq_ignore_ascii_case("utf-8") || value.eq_ignore_ascii_case("utf8") {
            Ok(Self::Utf8)
        } else if value.eq_ignore_ascii_case("utf-16") || value.eq_ignore_ascii_case("utf16") {
            Ok(Self::Utf16)
        } else if value.eq_ignore_ascii_case("utf-16le") || value.eq_ignore_ascii_case("utf16le") {
            Ok(Self::Utf16Le)
        } else if value.eq_ignore_ascii_case("utf-16be") || value.eq_ignore_ascii_case("utf16be") {
            Ok(Self::Utf16Be)
        } else if value.eq_ignore_ascii_case("ascii") || value.eq_ignore_ascii_case("us-ascii") {
            Ok(Self::Ascii)
        } else if value.eq_ignore_ascii_case("latin1") || value.eq_ignore_ascii_case("iso-8859-1") {
            Ok(Self::Latin1)
        } else {
            Err(value)
        }
    }
}

#[derive(Builder, derive_more::Debug)]
pub(crate) struct ApiRequest<'a> {
    #[builder(into)]
    #[debug("{}", endpoint.as_str())]
    endpoint: MaybeOwned<'a, Url>,
    request_method: RequestMethod,
    #[builder(default = ContentType::Json)]
    accept: ContentType,
    body: Option<ApiRequestBody<'a>>,
    max_response_len: Option<ByteSize>,
    #[builder(name = "idempotent", default = false)]
    is_idempotent: bool,
}

#[derive(Builder, Debug)]
pub(crate) struct ApiRequestBody<'a> {
    content_type: Option<ContentType>,
    payload: Payload<'a>,
}

pub(crate) enum Payload<'a> {
    Json(&'a JsonValue),
    #[cfg(feature = "graphql")]
    GraphQL(Vec<u8>),
}

impl<'a> Into<Payload<'a>> for &'a JsonValue {
    fn into(self) -> Payload<'a> {
        Payload::Json(self)
    }
}

#[cfg(feature = "graphql")]
impl<'a, F, V: Serialize> TryFrom<&'a cynic::Operation<F, V>> for Payload<'static> {
    type Error = serde_json::Error;

    fn try_from(value: &'a cynic::Operation<F, V>) -> Result<Self, Self::Error> {
        serde_json::to_vec(value).map(|b| Self::GraphQL(b))
    }
}

impl<'a> Debug for Payload<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(_) => f.write_str("json"),
            #[cfg(feature = "graphql")]
            Self::GraphQL(_) => f.write_str("graphql"),
        }
    }
}

#[derive(Error, Debug)]
pub(crate) enum PayloadError {
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
}

impl<'a> TryInto<reqwest::Body> for Payload<'a> {
    type Error = PayloadError;

    fn try_into(self) -> Result<reqwest::Body, Self::Error> {
        Ok(match self {
            Self::Json(json) => reqwest::Body::from(serde_json::to_vec(json)?),
            #[cfg(feature = "graphql")]
            Self::GraphQL(graphql) => reqwest::Body::from(graphql),
        })
    }
}

#[derive(Debug)]
struct Inner {
    reqwest_client: ReqwestClient,
    network: Network,
    allow_retry: bool,
}
