use crate::api::RequestMethod::Get;
use crate::api::{ApiClient, ApiRequest, ViaJson};
use crate::{Client, api};
use ario_core::Gateway;
use ario_core::money::{Money, Winston};
use ario_core::tx::TxId;
use ario_core::wallet::WalletAddress;
use bytesize::ByteSize;
use std::str::FromStr;

impl ApiClient {
    pub(crate) async fn wallet_balance(
        &self,
        gateway: &Gateway,
        address: &WalletAddress,
    ) -> Result<Money<Winston>, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join(format!("./wallet/{}/balance", address.to_string()).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::kib(1))
            .build();

        Ok(self.send_api_request::<ViaJson<_>>(req).await?.0)
    }

    pub(crate) async fn wallet_last_tx(
        &self,
        gateway: &Gateway,
        address: &WalletAddress,
    ) -> Result<Option<TxId>, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join(format!("./wallet/{}/last_tx", address.to_string()).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::kib(1))
            .build();

        // this endpoint appears to return non-json plaintext responses
        let str: String = self.send_api_request(req).await?;
        if str.is_empty() {
            return Ok(None);
        }
        Ok(Some(TxId::from_str(&str).map_err(|e| {
            api::Error::UnexpectedResponse(e.to_string())
        })?))
    }
}

impl Client {
    pub async fn wallet_balance(
        &self,
        address: &WalletAddress,
    ) -> Result<Money<Winston>, super::Error> {
        let api_client = &self.0.api_client;
        Ok(self
            .with_gw(async move |gw| api_client.wallet_balance(gw, address).await)
            .await?)
    }

    pub async fn wallet_last_tx(
        &self,
        address: &WalletAddress,
    ) -> Result<Option<TxId>, super::Error> {
        let api_client = &self.0.api_client;
        Ok(self
            .with_gw(async move |gw| api_client.wallet_last_tx(gw, address).await)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use crate::api::ApiClient;
    use ario_core::Gateway;
    use ario_core::network::Network;
    use ario_core::wallet::WalletAddress;
    use reqwest::Client;
    use std::str::FromStr;

    #[ignore]
    #[tokio::test]
    async fn wallet_balance_live() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let client = ApiClient::new(Client::new(), Network::default());
        let winston = client
            .wallet_balance(
                &gw,
                &WalletAddress::from_str("4JOmaT9fFe2ojFJEls3Zow5UKO2CBOk7lOirbPTtX1o")?,
            )
            .await?;
        let _s = winston.to_plain_string();
        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn wallet_last_tx_live() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let client = ApiClient::new(Client::new(), Network::default());
        let tx_id = client
            .wallet_last_tx(
                &gw,
                &WalletAddress::from_str("4JOmaT9fFe2ojFJEls3Zow5UKO2CBOk7lOirbPTtX1o")?,
            )
            .await?;
        assert!(tx_id.is_some());
        let _s = tx_id.unwrap().to_string();
        let tx_id2 = client
            .wallet_last_tx(
                &gw,
                &WalletAddress::from_str("3JOmaT9fFe2ojFJEls3Zow5UKO2CBOk7lOirbPTtX1o")?,
            )
            .await?;
        assert!(tx_id2.is_none());
        Ok(())
    }
}
