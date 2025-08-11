use ario_core::network::Network;
use bon::Builder;
use maybe_owned::MaybeOwned;
use reqwest::{Client as ReqwestClient, Response};
use std::borrow::Cow;
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
    #[error(transparent)]
    InvalidJson(#[from] serde_json::Error),
    #[error(transparent)]
    InvalidUrl(#[from] url::ParseError),
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

    pub(super) async fn send_api_request<'a>(&self, api_request: ApiRequest<'a>) -> Result<Response, Error> {
        match self.send_optional_api_request(api_request).await {
            Ok(Some(resp)) => Ok(resp),
            Ok(None) => Err(Error::NotFoundError),
            Err(e) => Err(e),
        }
    }

    pub async fn send_optional_api_request<'a>(
        &self,
        api_request: ApiRequest<'a>,
    ) -> Result<Option<Response>, Error> {
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
        Ok(Some(resp))
    }
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
}

#[derive(Debug)]
struct Inner {
    reqwest_client: ReqwestClient,
    network: Network,
}
