use crate::api::RequestMethod::Get;
use crate::api::{Api, ApiRequest, ViaJson};
use crate::{Client, api};
use ario_core::blob::Blob;
use ario_core::network::NetworkIdentifier;
use ario_core::{BlockNumber, Gateway};
use bytesize::ByteSize;
use derive_more::{AsRef, Deref, Display, Into};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::base64::UrlSafe;
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ApiError(#[from] api::Error),
    #[error("gateway response not understood")]
    InvalidResponse,
    #[error("gateway version '{0}' not supported")]
    UnsupportedVersion(u16),
    #[error("incorrect network: expected '{expected}' but got '{actual}'")]
    IncorrectNetwork { expected: String, actual: String },
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

#[derive(Clone, Debug, PartialEq, Eq, AsRef, Deref, Into, Display, Serialize, Deserialize)]
pub struct Peer(SocketAddr);

impl Api {
    pub(super) async fn gateway_info(
        &self,
        gateway: &Gateway,
    ) -> Result<GatewayInfo<'static>, Error> {
        let req = ApiRequest::builder()
            .endpoint(gateway.join("./info").map_err(api::Error::InvalidUrl)?)
            .request_method(Get)
            .max_response_len(ByteSize::kib(256))
            .idempotent(true)
            .build();

        Ok(self.send_api_request::<ViaJson<_>>(req).await?.0)
    }

    async fn gateway_peers(&self, gateway: &Gateway) -> Result<Vec<Peer>, Error> {
        let req = ApiRequest::builder()
            .endpoint(gateway.join("./peers").map_err(api::Error::InvalidUrl)?)
            .request_method(Get)
            .max_response_len(ByteSize::mib(4))
            .idempotent(true)
            .build();

        Ok(self.send_api_request::<ViaJson<_>>(req).await?.0)
    }
}

impl Client {
    pub async fn gateway_info(&self, gateway: &Gateway) -> Result<GatewayInfo<'static>, Error> {
        self.0.api.gateway_info(gateway).await
    }

    pub async fn gateway_peers(&self, gateway: &Gateway) -> Result<Vec<Peer>, Error> {
        self.0.api.gateway_peers(gateway).await
    }
}

#[cfg(test)]
mod tests {
    use crate::api::Api;
    use crate::gateway::{Gateway, GatewayInfo, Peer};
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
    async fn gw_info_live() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let api = Api::new(Client::new(), Network::default(), false);
        let info = api.gateway_info(&gw).await?;
        assert_eq!(&info.network, Network::Mainnet.id());
        Ok(())
    }

    #[test]
    fn gw_peers_serde() -> anyhow::Result<()> {
        let json = r#"
        ["127.0.0.1:1984","192.168.24.189:1985","[fdc4:d3d9:84ec::]:1983","[2345:0425:2CA1:0:0:0567:5673:23b5]:1984"]
        "#;

        let peers: Vec<Peer> = serde_json::from_str(json)?;
        assert_eq!(peers.len(), 4);

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn gw_peers_live() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let api = Api::new(Client::new(), Network::default(), false);
        let _peers = api.gateway_peers(&gw).await?;
        Ok(())
    }
}
