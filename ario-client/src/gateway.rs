use crate::Endpoint;
use ario_core::blob::Blob;
use ario_core::network::NetworkIdentifier;
use ario_core::{BlockNumber, Gateway};
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::base64::UrlSafe;
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    NetworkError(#[from] reqwest::Error),
    #[error("status error: {0}")]
    StatusError(String),
    #[error("gateway response not understood")]
    InvalidResponse,
    #[error("gateway version '{0}' not supported")]
    UnsupportedVersion(u16),
    #[error("incorrect network: expected '{expected}' but got '{actual}'")]
    IncorrectNetwork { expected: String, actual: String },
}

impl GatewayInfo<'static> {
    pub(crate) async fn retrieve(
        gw: &Gateway,
        reqwest_client: &ReqwestClient,
    ) -> Result<Self, Error> {
        let url = Endpoint::Info.build_url(gw);
        let req = reqwest_client
            .get::<Url>(url.into())
            .header("Accept", "application/json")
            .build()?;
        let resp = reqwest_client.execute(req).await?;
        let status = resp.status();
        if status.is_client_error() || status.is_server_error() {
            let text = resp
                .text_with_charset("utf-8")
                .await
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "".to_string());
            return Err(Error::StatusError(text));
        }
        Ok(resp.json().await.map_err(|_| Error::InvalidResponse)?)
    }
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct GatewayInfo<'a> {
    pub version: u16,
    pub release: u32,
    pub queue_length: u32,
    pub peers: u32,
    pub node_state_latency: u16,
    pub network: NetworkIdentifier,
    pub height: BlockNumber,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub current: Blob<'a>, //todo
    pub blocks: u64,
}

#[cfg(test)]
mod tests {
    use crate::gateway::{Gateway, GatewayInfo};
    use ario_core::base64::ToBase64;
    use ario_core::network::Network;
    use reqwest::Client;
    use std::str::FromStr;

    #[test]
    fn gw_info_serde() -> anyhow::Result<()> {
        let json = r#"
        {"version":5,"release":84,"queue_length":0,"peers":880,"node_state_latency":2,"network":"arweave.N.1","height":1727844,"current":"KBpi1FK6eLMGU6ZYnx2_wlP2_GZ1hzppJrcb41Do-NWW7VytPAgqZn7Mn1oewJhX","blocks":1727845}
        "#;

        let info: GatewayInfo = serde_json::from_str(json)?;
        assert_eq!(info.version, 5);
        assert_eq!(info.release, 84);
        assert_eq!(info.queue_length, 0);
        assert_eq!(info.peers, 880);
        assert_eq!(info.node_state_latency, 2);
        assert_eq!(&info.network, Network::Mainnet.id());
        assert_eq!(*info.height, 1727844);
        assert_eq!(info.blocks, 1727845);

        //todo
        assert_eq!(
            info.current.bytes().to_base64(),
            "KBpi1FK6eLMGU6ZYnx2_wlP2_GZ1hzppJrcb41Do-NWW7VytPAgqZn7Mn1oewJhX"
        );

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn gateway_info() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let client = Client::new();
        let gw = GatewayInfo::retrieve(&gw, &client).await?;
        assert_eq!(&gw.network, Network::Mainnet.id());
        Ok(())
    }
}
