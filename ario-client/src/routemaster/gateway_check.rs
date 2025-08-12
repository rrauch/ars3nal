use crate::api::ApiClient;
use crate::gateway;
use crate::gateway::GatewayInfo;
use ario_core::Gateway;
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

pub(super) struct GatewayCheckTask {
    ct: CancellationToken,
    gateway: Gateway,
    api_client: ApiClient,
    check_permits: Arc<Semaphore>,
}

pub(super) struct GatewayCheck {
    pub gateway: Gateway,
    pub start_time: SystemTime,
    pub completion_time: SystemTime,
    pub result: Result<GatewayInfo<'static>, gateway::Error>,
}

#[derive(Error, Debug)]
pub(super) enum CheckError {
    #[error("check cancelled")]
    Cancelled,
    #[error(transparent)]
    JoinError(#[from] tokio::task::JoinError),
}

impl GatewayCheckTask {
    pub(super) fn new(
        ct: CancellationToken,
        gateway: Gateway,
        api_client: ApiClient,
        check_permits: Arc<Semaphore>,
    ) -> Self {
        Self {
            ct,
            gateway,
            api_client,
            check_permits,
        }
    }

    #[tracing::instrument(name = "gateway_check", skip(self))]
    pub(super) async fn run(mut self) -> Result<GatewayCheck, CheckError> {
        let cancelled = self.ct.clone().cancelled_owned();
        let check_permits = self.check_permits.clone();
        // waiting for permit before commencing the actual check
        let _permit = tokio::select! {
            res = check_permits.acquire() => {
                res.map_err(|_| CheckError::Cancelled)?
            }
            _ = cancelled => {
                // task was cancelled
                return Err(CheckError::Cancelled)
            }
        };

        let cancelled = self.ct.clone().cancelled_owned();
        let start_time = SystemTime::now();
        tokio::select! {
            result = self.info() => {
                let completion_time = SystemTime::now();
                Ok(GatewayCheck {
                    gateway: self.gateway,
                    result,
                    start_time,
                    completion_time,
                })
            }
            _ = cancelled => {
                // task was cancelled
                Err(CheckError::Cancelled)
            }
        }
    }

    // this is the actual check for gateway liveness
    async fn info(&mut self) -> Result<GatewayInfo<'static>, gateway::Error> {
        let info = self.api_client.gateway_info(&self.gateway).await?;
        if &info.network != self.api_client.network().id() {
            return Err(gateway::Error::IncorrectNetwork {
                expected: self.api_client.network().id().to_string(),
                actual: info.network.to_string(),
            });
        }
        Ok(info)
    }
}
