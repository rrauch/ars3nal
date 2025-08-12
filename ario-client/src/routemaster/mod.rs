mod background_task;
mod gateway_check;
mod netwatch;

use crate::api::ApiClient;
use crate::routemaster::background_task::BackgroundTask;
use crate::routemaster::netwatch::Netwatch;
use ario_core::Gateway;
use derive_where::derive_where;
use itertools::Itertools;
use rand::Rng;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::time::FutureExt;

#[derive(Debug, Clone)]
pub struct Routemaster(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    api_client: ApiClient,
    cmd_tx: mpsc::Sender<Command>,
    active_rx: watch::Receiver<ActiveRoutes>,
    state_rx: watch::Receiver<State>,
    task_handle: JoinHandle<()>,
    netwatch_handle: JoinHandle<()>,
    ct: CancellationToken,
    startup_timeout: Duration,
    regular_timeout: Duration,
    _drop_guard: DropGuard,
}

enum Command {
    AddGateways(Vec<Gateway>),
    RemoveGateways(Vec<Gateway>),
    GatewaySuccess((Gateway, Duration)),
    GatewayError((Gateway, Duration)),
    NetworkChangeDetected,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum State {
    ReStarting,
    Running,
    ShuttingDown,
}

impl State {
    fn shutting_down(&self) -> bool {
        match self {
            Self::ShuttingDown => true,
            _ => false,
        }
    }

    fn running(&self) -> bool {
        match self {
            Self::Running => true,
            _ => false,
        }
    }
}

impl Routemaster {
    pub(crate) fn new(
        api_client: ApiClient,
        initial_gateways: Vec<Gateway>,
        max_simultaneous_checks: u32,
        startup_timeout: Duration,
        regular_timeout: Duration,
        enable_netwatch: bool,
    ) -> Self {
        let ct = CancellationToken::new();
        let check_permits = Arc::new(Semaphore::new(max_simultaneous_checks as usize));
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        let (active_tx, active_rx) = watch::channel(ActiveRoutes::from_iter(vec![]));
        let (state_tx, state_rx) = watch::channel(State::ReStarting);

        let background_task = BackgroundTask::new(
            initial_gateways,
            cmd_rx,
            cmd_tx.clone(),
            active_tx,
            ct.clone(),
            state_tx,
            api_client.clone(),
            check_permits,
        );

        let netwatch_handle = if enable_netwatch {
            let netwatch_task = Netwatch::new(cmd_tx.clone(), state_rx.clone(), ct.child_token());
            tokio::task::spawn(netwatch_task.run())
        } else {
            // dummy task
            tokio::task::spawn(async {})
        };

        Self(Arc::new(Inner {
            api_client,
            cmd_tx,
            active_rx,
            state_rx,
            task_handle: tokio::task::spawn(background_task.run()),
            netwatch_handle,
            _drop_guard: ct.clone().drop_guard(),
            ct,
            startup_timeout,
            regular_timeout,
        }))
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.task_handle.abort();
        self.netwatch_handle.abort();
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Routemaster is shutting down")]
    ShuttingDown,
    #[error("Operation timed out")]
    Timeout,
}

impl Routemaster {
    pub async fn insert_gateways(
        &self,
        gws: impl IntoIterator<Item = Gateway>,
    ) -> Result<(), Error> {
        self.send_cmd(Command::AddGateways(gws.into_iter().collect()))
            .await
    }

    fn state(&self) -> State {
        if self.0.ct.is_cancelled() {
            State::ShuttingDown
        } else {
            self.0.state_rx.borrow().clone()
        }
    }

    async fn send_cmd(&self, cmd: Command) -> Result<(), Error> {
        if self.state().shutting_down() {
            return Err(Error::ShuttingDown);
        }

        self.0
            .cmd_tx
            .send(cmd)
            .timeout(Duration::from_secs(60))
            .await
            .map_err(|_| Error::Timeout)?
            .expect("background task to be running");

        Ok(())
    }

    pub async fn remove_gateways<'a>(
        &self,
        gws: impl IntoIterator<Item = &'a Gateway>,
    ) -> Result<(), Error> {
        self.send_cmd(Command::RemoveGateways(
            gws.into_iter()
                .unique()
                .map(|g| g.clone())
                .collect::<Vec<_>>(),
        ))
        .await
    }

    pub fn try_gateway(&self) -> Option<Handle<Gateway>> {
        if self.state().shutting_down() {
            return None;
        };

        self.0.active_rx.borrow().pick_gateway()
    }

    pub async fn gateway(&self) -> Result<Handle<Gateway>, Error> {
        let state = self.state();
        if state.shutting_down() {
            return Err(Error::ShuttingDown);
        }

        let timeout = match state {
            State::ReStarting => self.0.startup_timeout,
            _ => self.0.regular_timeout,
        };

        {
            // first, try if we can get one straight away
            if let Some(gw) = self.0.active_rx.borrow().pick_gateway() {
                return Ok(gw);
            }
        }

        // looks like we have to wait and see
        let mut active_rx = self.0.active_rx.clone();
        async move {
            loop {
                let gateway = {
                    let route = active_rx.borrow_and_update();
                    route.pick_gateway()
                };

                if let Some(gw) = gateway {
                    return Ok(gw);
                }

                active_rx.changed().await.map_err(|_| Error::ShuttingDown)?;
            }
        }
        .timeout(timeout)
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub fn shutdown(&mut self) {
        self.0.ct.cancel();
    }
}

#[derive_where(Debug, Clone)]
pub struct Handle<T: Debug>(Arc<HandleInner<T>>);

impl Handle<Gateway> {
    fn new(gateway: Gateway, cmd_tx: mpsc::Sender<Command>) -> Self {
        Self(Arc::new(HandleInner {
            inner: gateway,
            cmd_tx,
        }))
    }

    pub async fn submit_success(&self, duration: Duration) {
        let _ = self
            .0
            .cmd_tx
            .try_send(Command::GatewaySuccess((self.0.inner.clone(), duration)));
    }

    pub async fn submit_error(&self, duration: Duration) {
        let _ = self
            .0
            .cmd_tx
            .try_send(Command::GatewayError((self.0.inner.clone(), duration)));
    }
}

impl<T: Debug> Deref for Handle<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0.inner
    }
}

#[derive_where(Debug)]
struct HandleInner<T: Debug> {
    inner: T,
    cmd_tx: mpsc::Sender<Command>,
}

#[derive(Debug, Clone)]
struct ActiveRoutes {
    gateways: Vec<(Handle<Gateway>, usize)>,
    total_weight: u128,
}

impl FromIterator<(Handle<Gateway>, usize)> for ActiveRoutes {
    fn from_iter<T: IntoIterator<Item = (Handle<Gateway>, usize)>>(iter: T) -> Self {
        let mut total_weight = 0u128;
        let gateways = iter
            .into_iter()
            .map(|(handle, weight)| {
                total_weight = total_weight.saturating_add(weight as u128);
                (handle, weight)
            })
            .collect_vec();
        Self {
            gateways,
            total_weight,
        }
    }
}

impl ActiveRoutes {
    fn pick_gateway(&self) -> Option<Handle<Gateway>> {
        if self.gateways.is_empty() {
            return None;
        }

        let mut rng = rand::rng();
        let mut random_weight = rng.random_range(0..self.total_weight);
        for (gateway, weight) in &self.gateways {
            let weight_u128 = *weight as u128;
            if random_weight < weight_u128 {
                return Some(gateway.clone());
            }
            random_weight -= weight_u128;
        }
        unreachable!("one gateway should be picked at any time")
    }
}

#[cfg(test)]
mod tests {
    use crate::api::ApiClient;
    use crate::gateway;
    use crate::routemaster::gateway_check::GatewayCheckTask;
    use crate::routemaster::{ActiveRoutes, Handle, Routemaster};
    use ario_core::Gateway;
    use ario_core::network::Network;
    use reqwest::{Client, ClientBuilder};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{Semaphore, mpsc};
    use tokio_util::sync::CancellationToken;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[test]
    fn active_routes() -> anyhow::Result<()> {
        let (tx, _rx) = mpsc::channel(10);

        let active_routes = ActiveRoutes::from_iter([(
            Handle::new(Gateway::from_str("http://localhost:1984")?, tx.clone()),
            1000,
        )]);
        assert!(active_routes.pick_gateway().is_some());

        let active_routes2 = ActiveRoutes::from_iter([
            (
                Handle::new(Gateway::from_str("http://localhost:1984")?, tx.clone()),
                1000,
            ),
            (
                Handle::new(Gateway::from_str("http://localhost:2984")?, tx.clone()),
                2000,
            ),
            (
                Handle::new(Gateway::from_str("http://localhost:3984")?, tx.clone()),
                3000,
            ),
        ]);
        assert!(active_routes2.pick_gateway().is_some());

        let active_routes3 = ActiveRoutes::from_iter([]);
        assert!(active_routes3.pick_gateway().is_none());

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn gateway_check() -> anyhow::Result<()> {
        let ct = CancellationToken::new();
        let permits = Arc::new(Semaphore::new(10));
        let mainnet_client = ApiClient::new(Client::new(), Network::Mainnet);
        let task = GatewayCheckTask::new(
            ct.clone(),
            Gateway::default(),
            mainnet_client.clone(),
            permits.clone(),
        );
        let gw_check = task.run().await?;
        assert!(gw_check.result.is_ok());

        let testnet_client = ApiClient::new(Client::new(), Network::Testnet);

        let task = GatewayCheckTask::new(
            ct.clone(),
            Gateway::default(),
            testnet_client,
            permits.clone(),
        );
        let gw_check2 = task.run().await?;
        assert!(gw_check2.result.is_err());
        match gw_check2.result {
            Err(gateway::Error::IncorrectNetwork { .. }) => {
                // correct
            }
            _ => panic!("expected incorrect network error"),
        }

        let task = GatewayCheckTask::new(
            ct.clone(),
            Gateway::from_str("https://google.com/")?,
            mainnet_client,
            permits.clone(),
        );
        let gw_check3 = task.run().await?;
        assert!(gw_check3.result.is_err());

        Ok(())
    }

    #[ignore]
    #[tokio::test(flavor = "current_thread")]
    async fn routemaster_live() -> anyhow::Result<()> {
        init_tracing();
        let client = ApiClient::new(ClientBuilder::new().build()?, Network::default());
        let mut routemaster = Routemaster::new(
            client.clone(),
            vec![Gateway::default()],
            10,
            Duration::from_secs(10),
            Duration::from_secs(2),
            false,
        );
        let gw = routemaster.gateway().await?;
        assert_eq!(gw.to_string(), "https://arweave.net/");
        routemaster.shutdown();

        let routemaster = Routemaster::new(
            client.clone(),
            vec![Gateway::default()],
            10,
            Duration::from_secs(10),
            Duration::from_secs(2),
            false,
        );
        {
            let routemaster = routemaster.clone();
            tokio::task::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let _ = routemaster.insert_gateways([Gateway::default()]).await;
            });
        }
        assert!(routemaster.try_gateway().is_none()); // should not be ready
        let gw = routemaster.gateway().await?;
        assert_eq!(gw.to_string(), "https://arweave.net/");

        Ok(())
    }
}
