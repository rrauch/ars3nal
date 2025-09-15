mod api;
mod bundle;
mod chunk;
mod data_reader;
mod gateway;
#[cfg(feature = "graphql")]
pub mod graphql;
mod price;
mod routemaster;
mod tx;
mod wallet;

use crate::api::Api;
use crate::routemaster::{Handle, Routemaster};
use ario_core::Gateway;
use ario_core::network::Network;
pub use bytesize::ByteSize;
use reqwest::Client as ReqwestClient;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Client(Arc<Inner>);

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    RoutemasterError(#[from] routemaster::Error),
    #[error(transparent)]
    ApiError(#[from] api::Error),
    #[error(transparent)]
    TxSubmissionError(#[from] tx::TxSubmissionError),
    #[error(transparent)]
    UploadError(#[from] chunk::UploadError),
    #[error(transparent)]
    DownloadError(#[from] chunk::DownloadError),
    #[error(transparent)]
    DataReaderError(#[from] data_reader::Error),
}

#[bon::bon]
impl Client {
    #[builder(derive(Debug))]
    pub fn new(
        #[builder(default)] network: Network,
        #[builder(default)] reqwest_client: ReqwestClient,
        #[builder(with = |gws: impl IntoIterator<Item=Gateway>| {
            gws.into_iter().collect::<Vec<_>>()
        })]
        gateways: Vec<Gateway>,
        #[builder(default = 10)] max_simultaneous_gateway_checks: usize,
        #[builder(default = Duration::from_secs(30))] startup_timeout: Duration,
        #[builder(default = Duration::from_secs(5))] regular_timeout: Duration,
        #[builder(default = true)] enable_netwatch: bool,
        #[builder(default = true)] allow_api_retry: bool,
    ) -> Self {
        let api = Api::new(reqwest_client, network, allow_api_retry);
        let routemaster = Routemaster::new(
            api.clone(),
            gateways,
            max_simultaneous_gateway_checks,
            startup_timeout,
            regular_timeout,
            enable_netwatch,
        );
        Self(Arc::new(Inner { api, routemaster }))
    }

    pub(crate) async fn with_gw<T, E: Into<crate::Error>>(
        &self,
        f: impl AsyncFnOnce(&Gateway) -> Result<T, E>,
    ) -> Result<T, Error> {
        let gw_handle = self.0.routemaster.gateway().await?;
        self.with_existing_gw(&gw_handle, f).await
    }

    pub(crate) async fn with_existing_gw<T, E: Into<crate::Error>>(
        &self,
        gw_handle: &Handle<Gateway>,
        f: impl AsyncFnOnce(&Gateway) -> Result<T, E>,
    ) -> Result<T, Error> {
        let start = SystemTime::now();
        let res = f(&gw_handle).await;
        let duration = SystemTime::now().duration_since(start).unwrap_or_default();
        match res {
            Ok(value) => {
                let _ = gw_handle.submit_success(duration).await;
                Ok(value)
            }
            Err(err) => {
                let _ = gw_handle.submit_error(duration).await;
                Err(err.into())
            }
        }
    }
}

#[derive(Debug)]
struct Inner {
    api: Api,
    routemaster: Routemaster,
}
