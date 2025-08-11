mod api;
mod gateway;
mod routemaster;

use crate::api::ApiClient;
use crate::routemaster::Routemaster;
use ario_core::Gateway;
use ario_core::network::Network;
use ario_core::tx::{TxId, ValidatedTx};
use ario_core::wallet::WalletAddress;
use derive_more::{AsRef, Deref, Display, Into};
use reqwest::Client as ReqwestClient;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct Client(Arc<Inner>);

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
        #[builder(default = 10)] max_simultaneous_gateway_checks: u32,
        #[builder(default = Duration::from_secs(30))] startup_timeout: Duration,
        #[builder(default = Duration::from_secs(5))] regular_timeout: Duration,
    ) -> Self {
        let api_client = ApiClient::new(reqwest_client, network);
        let routemaster = Routemaster::new(
            api_client.clone(),
            gateways,
            max_simultaneous_gateway_checks,
            startup_timeout,
            regular_timeout,
        );
        Self(Arc::new(Inner {
            api_client,
            routemaster,
        }))
    }
}

#[derive(Debug)]
struct Inner {
    api_client: ApiClient,
    routemaster: Routemaster,
}

#[derive(Clone, Debug, PartialEq, Eq, AsRef, Deref, Into, Display)]
pub struct EndpointUrl(Url);

pub enum Endpoint<'a> {
    /// /info
    Info,
    /// /peers
    Peers,
    /// /price/{data_size}/{target}
    Price {
        data_size: u64,
        target: Option<&'a WalletAddress>,
    },
    Tx(TxEndpoint<'a>),
    Wallet(WalletEndpoint<'a>),
}

impl<'a> Endpoint<'a> {
    pub(crate) fn build_url(&self, gateway: &Gateway) -> EndpointUrl {
        match self {
            Self::Info => EndpointUrl(
                gateway
                    .join("./info")
                    .expect("url parsing should never fail"),
            ),
            _ => todo!(),
        }
    }
}

pub enum TxEndpoint<'a> {
    /// /tx/{id}
    ById(&'a TxId),
    /// /tx/{id}/offset
    Offset(&'a TxId),
    /// /tx/{id}/status
    Status(&'a TxId),
    /// /tx (Post)
    Submit(&'a ValidatedTx<'a>),
}

pub enum WalletEndpoint<'a> {
    /// /wallet/{address}/balance
    Balance(&'a WalletAddress),
    /// /wallet/{address}/last_tx
    LastTx(&'a WalletAddress),
}
