use crate::api::RequestMethod::Get;
use crate::api::{Api, ApiRequest, ViaJson};
use crate::{Client, api};
use ario_core::Gateway;
use ario_core::money::{Money, Winston};
use ario_core::wallet::WalletAddress;
use bytesize::ByteSize;

impl Api {
    async fn price(
        &self,
        gateway: &Gateway,
        data_size: u64,
        target: Option<&WalletAddress>,
    ) -> Result<Money<Winston>, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(
                gateway
                    .join(format!("./price/{}", to_path(data_size, target)).as_str())
                    .map_err(api::Error::InvalidUrl)?,
            )
            .request_method(Get)
            .max_response_len(ByteSize::kib(1))
            .idempotent(true)
            .build();

        Ok(self.send_api_request::<ViaJson<_>>(req).await?.0)
    }
}

fn to_path(data_size: u64, target: Option<&WalletAddress>) -> String {
    match target {
        Some(target) => format!("{}/{}", data_size, target.to_string()),
        None => format!("{}", data_size),
    }
}

impl Client {
    pub async fn price(
        &self,
        data_size: u64,
        target: Option<&WalletAddress>,
    ) -> Result<Money<Winston>, super::Error> {
        let api = &self.0.api;
        Ok(self
            .with_gw(async move |gw| api.price(gw, data_size, target).await)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use crate::api::Api;
    use crate::price::to_path;
    use ario_core::Gateway;
    use ario_core::money::{Money, Winston};
    use ario_core::network::Network;
    use ario_core::wallet::WalletAddress;
    use reqwest::Client;
    use std::str::FromStr;

    #[test]
    fn price_test_serde() -> anyhow::Result<()> {
        let winston: Money<Winston> = serde_json::from_str("6582968")?;
        assert_eq!(winston.to_plain_string(), "6582968");

        let path = to_path(123, None);
        assert_eq!(path, "123");

        let path = to_path(
            0,
            Some(&WalletAddress::from_str(
                "4JOmaT9fFe2ojFJEls3Zow5UKO2CBOk7lOirbPTtX1o",
            )?),
        );
        assert_eq!(path, "0/4JOmaT9fFe2ojFJEls3Zow5UKO2CBOk7lOirbPTtX1o");

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn price_test_live() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let api = Api::new(Client::new(), Network::default(), false);
        let _winston = api
            .price(
                &gw,
                0,
                Some(&WalletAddress::from_str(
                    "4JOmaT9fFe2ojFJEls3Zow5UKO2CBOk7lOirbPTtX1o",
                )?),
            )
            .await?;
        Ok(())
    }
}
