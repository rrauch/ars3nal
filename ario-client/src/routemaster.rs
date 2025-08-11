use crate::api::{ApiClient, ApiRequest, RequestMethod};
use crate::gateway::GatewayInfo;
use crate::{Endpoint, api, gateway};
use ario_core::Gateway;
use futures_concurrency::future::FutureGroup;
use futures_lite::future;
use futures_lite::stream::StreamExt;
use itertools::Itertools;
use rand::Rng;
use std::collections::HashMap;
use std::ops::Add;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::future::FutureExt;
use tokio_util::sync::{CancellationToken, DropGuard};

#[derive(Debug, Clone)]
pub struct Routemaster(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    api_client: ApiClient,
    cmd_tx: mpsc::Sender<Command>,
    active_rx: watch::Receiver<ActiveRoutes>,
    task_handle: JoinHandle<()>,
    ct: CancellationToken,
    _drop_guard: DropGuard,
}

enum Command {
    AddGateways(Vec<Gateway>),
    RemoveGateways(Vec<Gateway>),
}

struct BackgroundTask {
    routes: HashMap<Gateway, Route>,
    initial_gateways: Vec<Gateway>,
    pending_checks: HashMap<Gateway, DropGuard>,
    cmd_rx: mpsc::Receiver<Command>,
    active_tx: watch::Sender<ActiveRoutes>,
    ct: CancellationToken,
    api_client: ApiClient,
    check_permits: Arc<Semaphore>,
    _drop_guard: DropGuard,
}

impl BackgroundTask {
    fn new(
        initial_gateways: Vec<Gateway>,
        cmd_rx: mpsc::Receiver<Command>,
        active_tx: watch::Sender<ActiveRoutes>,
        ct: CancellationToken,
        api_client: ApiClient,
        check_permits: Arc<Semaphore>,
    ) -> Self {
        let _drop_guard = ct.clone().drop_guard();
        Self {
            routes: HashMap::default(),
            initial_gateways,
            pending_checks: HashMap::default(),
            cmd_rx,
            active_tx,
            ct,
            api_client,
            check_permits,
            _drop_guard,
        }
    }

    #[tracing::instrument(name = "background_run", skip(self))]
    async fn run(mut self) {
        tracing::info!(initial_gateways = self.initial_gateways.len(), "starting");
        let mut cmds = Vec::with_capacity(10);
        cmds.push(Command::AddGateways(std::mem::replace(
            &mut self.initial_gateways,
            vec![],
        )));
        let mut next_checks_due = SystemTime::now().add(Duration::from_secs(60));

        let mut pending_futs = FutureGroup::<
            Pin<Box<dyn Future<Output = (Gateway, Result<GatewayCheck, CheckError>)> + Send>>,
        >::new();
        // add dummy future that never resolves to prevent pending_futs from reaching end of stream
        pending_futs.insert(Box::pin(future::pending::<(
            Gateway,
            Result<GatewayCheck, CheckError>,
        )>()));

        loop {
            tracing::trace!("next loop iteration");
            // first, process outstanding commands
            let mut modified = false;
            for cmd in cmds.drain(..) {
                if self.process_cmd(cmd) {
                    modified = true;
                }
            }
            if modified || (next_checks_due <= SystemTime::now()) {
                // time to initiate new checks
                tracing::info!("new checks are due");
                let (tasks, next) = self.initiate_gw_checks();
                match next {
                    Some(next_at) => next_checks_due = next_at,
                    None => next_checks_due = SystemTime::now().add(Duration::from_secs(60)),
                }
                let mut new_checks_added = 0;
                for (gw, jh) in tasks {
                    let fut = async move {
                        (
                            gw,
                            match jh.await {
                                Ok(Ok(check)) => Ok(check),
                                Ok(Err(err)) => Err(err),
                                Err(err) => Err(CheckError::JoinError(err)),
                            },
                        )
                    };
                    pending_futs.insert(Box::pin(fut));
                    new_checks_added += 1;
                }
                tracing::debug!(new_checks_added, "new checks added");
            }

            assert!(cmds.is_empty());
            let cmds_cap = cmds.capacity();

            let next_check_in = next_checks_due
                .duration_since(SystemTime::now())
                .expect("next_checks_due to never be in the past");

            tokio::select! {
                _ = tokio::time::sleep(next_check_in) => {
                    tracing::trace!("time for the next check");
                }
                n = self.cmd_rx.recv_many(&mut cmds, cmds_cap) => {
                    if n == 0 {
                        // sender gone
                        tracing::warn!("cmd sender disappeared");
                        break;
                    }
                    // cmds received
                    tracing::debug!(num = n, "commands received");
                }
                Some((gw, res)) = pending_futs.next() => {
                    // gateway check completed
                    let success = match &res {
                        Ok(check) => check.result.is_ok(),
                        _ => false
                    };
                    tracing::debug!(gateway = %gw, success, "gateway check complete");
                    let usable = self.is_usable(&gw);
                    self.process_gw_check_result(&gw, res);
                    if self.is_usable(&gw) != usable {
                        // status of route has changed
                        // update active routes
                        let num_active_before = self.active_tx.borrow().gateways.len();
                        self.update_active_routes();
                        let num_active = self.active_tx.borrow().gateways.len();
                        tracing::info!(num_active, num_active_before, "number of active gateways changed");
                    }
                }
                _ = self.ct.cancelled() => {
                    // shutting down
                    break;
                },
            }
        }
        tracing::debug!("end of main loop reached");
        tracing::info!("shutting down");
        self.ct.cancel();
    }

    fn update_active_routes(&mut self) {
        let gateways = self
            .routes
            .iter()
            .filter_map(|(gw, r)| {
                if let Checked::Checked {
                    status, duration, ..
                } = &r.checked
                {
                    if let GatewayStatus::Ok(_) = status {
                        Some((gw, duration))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect_vec();

        // Find max duration to invert weights (higher duration = lower weight)
        let max_duration = gateways
            .iter()
            .map(|(_, d)| d.as_nanos())
            .max()
            .unwrap_or_default();

        let _ = self
            .active_tx
            .send(ActiveRoutes::from_iter(gateways.into_iter().map(
                |(gateway, duration)| {
                    (
                        gateway.clone(),
                        (max_duration - duration.as_nanos() + 1) as usize,
                    )
                },
            )));
    }

    fn is_usable(&self, gw: &Gateway) -> bool {
        if let Some(Route { checked, .. }) = self.routes.get(gw) {
            if let Checked::Checked { status, .. } = checked {
                if let GatewayStatus::Ok(_) = status {
                    return true;
                }
            }
        }
        false
    }

    fn process_gw_check_result(&mut self, gw: &Gateway, res: Result<GatewayCheck, CheckError>) {
        self.pending_checks.remove(gw);
        let route = match self.routes.get_mut(gw) {
            Some(r) => r,
            None => return,
        };
        let check = match res {
            Ok(check) => check,
            Err(_) => {
                // check not completed, do NOT update route
                return;
            }
        };
        let last_check = check.completion_time;
        let duration = check
            .completion_time
            .duration_since(check.start_time)
            .unwrap_or_default();

        let mut retry_num = 0;
        // check if this isn't the first error
        if let Checked::Checked { status, .. } = &route.checked {
            if let GatewayStatus::Error { retry_num: rn, .. } = status {
                retry_num = *rn + 1;
            }
        }

        let status = match check.result {
            Ok(info) => GatewayStatus::Ok(info),
            Err(error) => GatewayStatus::Error { error, retry_num },
        };

        match &mut route.checked {
            Checked::Unchecked => {
                route.checked = Checked::Checked {
                    status,
                    num_checks: 1,
                    last_check,
                    duration,
                };
            }
            Checked::Checked {
                status: st,
                num_checks,
                last_check: lc,
                duration: dur,
            } => {
                *st = status;
                *num_checks = *num_checks + 1;
                *lc = last_check;
                *dur = duration;
            }
        }
    }

    fn process_cmd(&mut self, cmd: Command) -> bool {
        let mut modified = false;
        match cmd {
            Command::AddGateways(gws) => {
                for gw in gws {
                    if !self.routes.contains_key(&gw) {
                        self.routes.insert(gw.clone(), Route::new(gw));
                        modified = true;
                    }
                }
            }
            Command::RemoveGateways(gws) => {
                let len = self.routes.len();
                self.routes.retain(|gw, _| !gws.contains(gw));
                if self.routes.len() != len {
                    modified = true;
                }
                // cancel any pending checks for affected gws
                self.pending_checks.retain(|gw, _| !gws.contains(gw));
            }
        }
        modified
    }

    fn initiate_gw_checks(
        &mut self,
    ) -> (
        Vec<(Gateway, JoinHandle<Result<GatewayCheck, CheckError>>)>,
        Option<SystemTime>,
    ) {
        let mut handles = vec![];
        let mut next_at = None;
        let mut new_tasks = vec![];
        for route in self.routes.iter().filter_map(|(gw, r)| {
            if !self.pending_checks.contains_key(gw) {
                let ready_at = self.next_check_at(r);
                if ready_at <= SystemTime::now() {
                    // ready now
                    Some(r)
                } else {
                    match next_at {
                        None => next_at = Some(ready_at),
                        Some(prev) => {
                            if ready_at < prev {
                                next_at = Some(ready_at)
                            }
                        }
                    }
                    None
                }
            } else {
                None
            }
        }) {
            // route ready to be checked
            // start background checker task
            let ct = self.ct.child_token();
            let drop_guard = ct.clone().drop_guard();
            let task = GatewayCheckTask::new(
                ct,
                route.gateway.clone(),
                self.api_client.clone(),
                self.check_permits.clone(),
            );
            handles.push((route.gateway.clone(), tokio::task::spawn(task.run())));
            new_tasks.push((route.gateway.clone(), drop_guard));
        }
        new_tasks.into_iter().for_each(|(gw, drop_guard)| {
            self.pending_checks.insert(gw, drop_guard);
        });
        (handles, next_at)
    }

    /// determines when a given route is ready to be checked again
    fn next_check_at(&self, route: &Route) -> SystemTime {
        match &route.checked {
            Checked::Unchecked => SystemTime::now(),
            Checked::Checked {
                last_check, status, ..
            } => {
                // todo: this is basically a stub
                // better logic is needed here at one point
                match &status {
                    GatewayStatus::Ok(_) => last_check.add(Duration::from_secs(600)),
                    GatewayStatus::Error { .. } => last_check.add(Duration::from_secs(60)),
                }
            }
        }
    }
}

struct GatewayCheckTask {
    ct: CancellationToken,
    gateway: Gateway,
    api_client: ApiClient,
    check_permits: Arc<Semaphore>,
}

struct GatewayCheck {
    gateway: Gateway,
    start_time: SystemTime,
    completion_time: SystemTime,
    result: Result<GatewayInfo<'static>, gateway::Error>,
}

#[derive(Error, Debug)]
enum CheckError {
    #[error("check cancelled")]
    Cancelled,
    #[error(transparent)]
    JoinError(#[from] tokio::task::JoinError),
}

impl GatewayCheckTask {
    fn new(
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

    async fn run(mut self) -> Result<GatewayCheck, CheckError> {
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

impl Routemaster {
    pub(crate) fn new(
        api_client: ApiClient,
        initial_gateways: Vec<Gateway>,
        max_simultaneous_checks: u32,
    ) -> Self {
        let ct = CancellationToken::new();
        let check_permits = Arc::new(Semaphore::new(max_simultaneous_checks as usize));
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        let (active_tx, active_rx) = watch::channel(ActiveRoutes::from_iter(vec![]));
        let background_task = BackgroundTask::new(
            initial_gateways,
            cmd_rx,
            active_tx,
            ct.clone(),
            api_client.clone(),
            check_permits,
        );

        Self(Arc::new(Inner {
            api_client,
            cmd_tx,
            active_rx,
            task_handle: tokio::task::spawn(background_task.run()),
            _drop_guard: ct.clone().drop_guard(),
            ct,
        }))
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.task_handle.abort();
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

    async fn send_cmd(&self, cmd: Command) -> Result<(), Error> {
        if self.0.ct.is_cancelled() {
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

    pub fn try_gateway(&self) -> Option<Gateway> {
        if self.0.ct.is_cancelled() {
            return None;
        };

        self.0
            .active_rx
            .borrow()
            .pick_gateway()
            .map(|gw| gw.clone())
    }

    pub async fn gateway(&self) -> Result<Gateway, Error> {
        if self.0.ct.is_cancelled() {
            return Err(Error::ShuttingDown);
        }

        // first, try if we can get one straight away
        if let Some(gw) = self.0.active_rx.borrow().pick_gateway() {
            return Ok(gw.clone());
        }

        // looks like we have to wait and see
        let mut active_rx = self.0.active_rx.clone();
        async move {
            loop {
                if let Some(gw) = active_rx.borrow_and_update().pick_gateway() {
                    return Ok(gw.clone());
                }
                active_rx.changed().await.map_err(|_| Error::ShuttingDown)?;
            }
        }
        .timeout(Duration::from_secs(30))
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub fn shutdown(&mut self) {
        self.0.ct.cancel();
    }
}

#[derive(Debug)]
struct Route {
    gateway: Gateway,
    checked: Checked,
}

impl Route {
    fn new(gateway: Gateway) -> Self {
        Self {
            gateway,
            checked: Checked::Unchecked,
        }
    }
}

#[derive(Debug)]
enum Checked {
    Unchecked,
    Checked {
        status: GatewayStatus,
        num_checks: usize,
        last_check: SystemTime,
        duration: Duration,
    },
}

#[derive(Debug)]
enum GatewayStatus {
    Ok(GatewayInfo<'static>),
    Error {
        error: gateway::Error,
        retry_num: usize,
    },
}

#[derive(Debug, Clone)]
struct ActiveRoutes {
    gateways: Vec<(Gateway, usize)>,
    total_weight: u128,
}

impl FromIterator<(Gateway, usize)> for ActiveRoutes {
    fn from_iter<T: IntoIterator<Item = (Gateway, usize)>>(iter: T) -> Self {
        let mut total_weight = 0u128;
        let gateways = iter
            .into_iter()
            .map(|(gw, weight)| {
                total_weight = total_weight.saturating_add(weight as u128);
                (gw, weight)
            })
            .collect_vec();
        Self {
            gateways,
            total_weight,
        }
    }
}

impl ActiveRoutes {
    fn pick_gateway(&self) -> Option<&Gateway> {
        if self.gateways.is_empty() {
            return None;
        }

        let mut rng = rand::rng();
        let mut random_weight = rng.random_range(0..self.total_weight);
        for (gateway, weight) in &self.gateways {
            let weight_u128 = *weight as u128;
            if random_weight < weight_u128 {
                return Some(gateway);
            }
            random_weight -= weight_u128;
        }
        unreachable!("one gateway should be picked at any time")
    }
}

#[cfg(test)]
mod tests {
    use crate::api::ApiClient;
    use crate::gateway::Error;
    use crate::routemaster::{ActiveRoutes, GatewayCheckTask, Routemaster};
    use crate::{Endpoint, api, gateway};
    use ario_core::Gateway;
    use ario_core::network::Network;
    use reqwest::{Client, ClientBuilder};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Semaphore;
    use tokio_util::sync::CancellationToken;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[test]
    fn active_routes() -> anyhow::Result<()> {
        let active_routes =
            ActiveRoutes::from_iter([(Gateway::from_str("http://localhost:1984")?, 1000)]);
        assert!(active_routes.pick_gateway().is_some());

        let active_routes2 = ActiveRoutes::from_iter([
            (Gateway::from_str("http://localhost:1984")?, 1000),
            (Gateway::from_str("http://localhost:2984")?, 2000),
            (Gateway::from_str("http://localhost:3984")?, 3000),
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
    #[tokio::test]
    async fn routemaster_live() -> anyhow::Result<()> {
        init_tracing();
        let client = ApiClient::new(ClientBuilder::new().build()?, Network::default());
        let mut routemaster = Routemaster::new(client.clone(), vec![Gateway::default()], 10);
        let endpoint = Endpoint::Info;
        let url = endpoint.build_url(&routemaster.gateway().await?);
        assert_eq!(url.to_string(), "https://arweave.net/info");
        routemaster.shutdown();

        let routemaster = Routemaster::new(client.clone(), vec![Gateway::default()], 10);
        {
            let routemaster = routemaster.clone();
            tokio::task::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let _ = routemaster.insert_gateways([Gateway::default()]).await;
            });
        }
        assert!(routemaster.try_gateway().is_none()); // should not be ready
        let url = endpoint.build_url(&routemaster.gateway().await?);
        assert_eq!(url.to_string(), "https://arweave.net/info");

        Ok(())
    }
}
