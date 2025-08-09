use crate::{Endpoint, gateway};
use ario_core::network::Network;
use ario_core::{Gateway, JsonValue};
use bon::Builder;
use reqwest::Client as ReqwestClient;
use std::sync::Arc;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone)]
pub struct ApiClient(Arc<Inner>);

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error(transparent)]
    GatewayError(#[from] gateway::Error),
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

    pub async fn send_api_request<'a>(
        &self,
        api_request: &'a ApiRequest<'a>,
    ) -> Result<JsonValue, Error> {
        let url = api_request.endpoint.build_url(api_request.gateway);
        let req = self
            .0
            .reqwest_client
            .get::<Url>(url.into())
            .header("Accept", "application/json")
            .header::<&str, &str>("x-network", self.network().id())
            .build()
            .map_err(Error::ReqwestError)?;

        let resp = self.0.reqwest_client.execute(req).await?;
        let status = resp.status();
        if status.is_client_error() || status.is_server_error() {
            let text = resp
                .text_with_charset("utf-8")
                .await
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "".to_string());
            return Err(Error::GatewayError(gateway::Error::StatusError(text)));
        }
        Ok(resp
            .json()
            .await
            .map_err(|_| Error::GatewayError(gateway::Error::InvalidResponse))?)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RequestMethod {
    Get,
    Post,
}

#[derive(Builder)]
pub struct ApiRequest<'a> {
    endpoint: &'a Endpoint<'a>,
    gateway: &'a Gateway,
    request_type: RequestMethod,
}

#[derive(Debug)]
struct Inner {
    reqwest_client: ReqwestClient,
    network: Network,
}
