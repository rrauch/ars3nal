mod gateway;
mod routemaster;

use crate::routemaster::Routemaster;
use ario_core::Gateway;
use ario_core::network::Network;
use ario_core::tx::{TxId, ValidatedTx};
use ario_core::wallet::WalletAddress;
use derive_more::{AsRef, Deref, Display, Into};
use url::Url;

pub struct Client<N: Network> {
    routemaster: Routemaster<N>,
}

#[derive(Debug, PartialEq, Eq)]
enum RequestMethod {
    Get,
    Post,
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
