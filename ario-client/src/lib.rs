mod routermaster;

use ario_core::tx::{TxId, ValidatedTx};
use ario_core::wallet::WalletAddress;
use reqwest::{Client as ReqwestClient, StatusCode};
use ario_core::typed::Typed;

pub struct Client {
    reqwest_client: ReqwestClient,
}

pub struct Mainnet;

pub struct Testnet;


pub struct Devnet;




#[derive(Debug, PartialEq, Eq)]
enum RequestMethod {
    Get,
    Post,
}

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

#[cfg(test)]
mod tests {
    use ario_core::network::{Local, Mainnet, Network, Testnet};

    #[tokio::test]
    async fn my_test() -> anyhow::Result<()> {
        let net = Local::builder().id("foobar123").build();
        println!("{}", net.id());
        assert!(true);
        Ok(())
    }
}
