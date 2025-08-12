use crate::api::ApiClient;
use crate::gateway;
use crate::gateway::GatewayInfo;
use ario_core::Gateway;
use derive_where::derive_where;
use futures_concurrency::future::FutureGroup;
use futures_lite::future;
use futures_lite::stream::StreamExt;
use itertools::Itertools;
use n0_watcher::Watcher;
use netwatch::netmon;
use rand::Rng;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::{Add, Deref};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
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

struct BackgroundTask {
    routes: HashMap<Gateway, Route>,
    pending_checks: HashMap<Gateway, DropGuard>,
    cmd_rx: mpsc::Receiver<Command>,
    cmd_tx: mpsc::Sender<Command>,
    active_tx: watch::Sender<ActiveRoutes>,
    ct: CancellationToken,
    state: watch::Sender<State>,
    api_client: ApiClient,
    check_permits: Arc<Semaphore>,
    _drop_guard: DropGuard,
}

impl BackgroundTask {
    fn new(
        initial_gateways: Vec<Gateway>,
        cmd_rx: mpsc::Receiver<Command>,
        cmd_tx: mpsc::Sender<Command>,
        active_tx: watch::Sender<ActiveRoutes>,
        ct: CancellationToken,
        state: watch::Sender<State>,
        api_client: ApiClient,
        check_permits: Arc<Semaphore>,
    ) -> Self {
        let _drop_guard = ct.clone().drop_guard();
        Self {
            routes: initial_gateways
                .into_iter()
                .map(|gw| {
                    let route = Route::new(gw.clone());
                    (gw, route)
                })
                .collect(),
            pending_checks: HashMap::default(),
            cmd_rx,
            cmd_tx,
            active_tx,
            ct,
            state,
            api_client,
            check_permits,
            _drop_guard,
        }
    }

    fn set_state(&self, state: State) {
        let _ = self.state.send(state);
    }

    fn restart(&mut self) {
        tracing::info!(known_gateways = self.routes.len(), "(re)starting");
        self.set_state(State::ReStarting);

        // stop all pending checks
        let num_pending_checks = self.pending_checks.len();
        self.pending_checks.clear();
        tracing::debug!(
            pending_checks = num_pending_checks,
            "pending checks stopped"
        );

        let _ = self.active_tx.send(ActiveRoutes::from_iter([]));

        // clear the command queue
        // drop any unprocessed commands
        loop {
            if let Err(_) = self.cmd_rx.try_recv() {
                break;
            }
        }

        // re-set the state of all known gateways to unprocessed
        self.routes
            .values_mut()
            .for_each(|route| route.checked = Checked::Unchecked);

        tracing::debug!(state = "(re)starting", "state changed");
    }

    #[tracing::instrument(name = "background_run", skip(self))]
    async fn run(mut self) {
        self.restart();

        let mut cmds: Vec<Command> = Vec::with_capacity(10);
        let mut next_checks_due = SystemTime::now();

        let mut pending_futs = FutureGroup::<
            Pin<Box<dyn Future<Output = (Gateway, Result<GatewayCheck, CheckError>)> + Send>>,
        >::new();
        // add dummy future that never resolves to prevent pending_futs from reaching end of stream
        pending_futs.insert(Box::pin(future::pending::<(
            Gateway,
            Result<GatewayCheck, CheckError>,
        )>()));

        'main: loop {
            tracing::trace!("next loop iteration");
            // first, process outstanding commands
            let mut modified = false;
            for cmd in cmds.drain(..) {
                let (mod_by_cmd, restarted) = self.process_cmd(cmd);
                if mod_by_cmd {
                    modified = true;
                }
                if restarted {
                    // routemaster was restarted
                    continue 'main;
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
                    let state = {
                        self.state.borrow().clone()
                    };
                    if let State::ReStarting = state {
                        if self.routes.values().find(|route| route.is_unchecked()).is_none() {
                            // all routes have been checked
                            // transition to Running state
                            let _ = self.state.send(State::Running);
                            tracing::debug!(state = "running", "state changed");
                        }
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
        let _ = self.state.send(State::ShuttingDown);
        tracing::debug!(state = "shutdown", "state changed");
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
                        Handle::new(gateway.clone(), self.cmd_tx.clone()),
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

    fn process_cmd(&mut self, cmd: Command) -> (bool, bool) {
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
            Command::GatewaySuccess((_gw, _duration)) => {
                // todo
            }
            Command::GatewayError((_gw, _duration)) => {
                // todo
            }
            Command::NetworkChangeDetected => {
                tracing::info!("network change detected, restarting routemaster");
                self.restart();
                return (modified, true);
            }
        }
        (modified, false)
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

impl Route {
    fn is_unchecked(&self) -> bool {
        match self.checked {
            Checked::Unchecked => true,
            _ => false,
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

struct Netwatch {
    cmd_tx: mpsc::Sender<Command>,
    state: watch::Receiver<State>,
    ct: CancellationToken,
}

impl Netwatch {
    fn new(
        cmd_tx: mpsc::Sender<Command>,
        state: watch::Receiver<State>,
        ct: CancellationToken,
    ) -> Self {
        Self { cmd_tx, state, ct }
    }

    #[tracing::instrument(name = "netwatch_run", skip(self))]
    async fn run(mut self) {
        let monitor = match netmon::Monitor::new().await {
            Ok(mon) => mon,
            Err(err) => {
                tracing::error!(error = %err, "failed to start network monitor. netwatch unavailable");
                return;
            }
        };
        let mut if_state = monitor.interface_state();
        let mut previous_state = if_state.get();

        let ct = self.ct.clone();
        let mut rm_state_rx = self.state.clone();
        let mut rm_state = { rm_state_rx.borrow_and_update().clone() };

        tracing::info!("netwatch started");

        loop {
            tokio::select! {
                r = if_state.updated() => {
                    match r {
                        Err(err) => {
                            tracing::error!(error = %err, "error watching network state");
                            break;
                        }
                        Ok(network_state) => {
                            let major_change = network_state.is_major_change(&previous_state);
                            previous_state = network_state;
                            if major_change {
                                tracing::info!("major network change detected");
                                if rm_state.running() {
                                    match self.cmd_tx.send(Command::NetworkChangeDetected).timeout(Duration::from_secs(60)).await {
                                        Err(_) => {
                                            tracing::error!("timeout reached when sending command");
                                            break;
                                        },
                                        Ok(Err(err)) => {
                                            tracing::error!(error = %err, "error sending command");
                                            break;
                                        }
                                        Ok(Ok(())) => {
                                            // everything ok here
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                _ = ct.cancelled() => {
                    // shutting down
                    break;
                },
                res = rm_state_rx.changed() => {
                    // routemaster state changed
                    if res.is_err() {
                        break;
                    }
                    rm_state = { rm_state_rx.borrow_and_update().clone() };
                    if rm_state.shutting_down() {
                        break;
                    }
                }
            }
        }
        tracing::info!("netwatch shutting down");
    }
}

#[cfg(test)]
mod tests {
    use crate::api::ApiClient;
    use crate::gateway;
    use crate::routemaster::{ActiveRoutes, GatewayCheckTask, Handle, Routemaster};
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
        let (tx, rx) = mpsc::channel(10);

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
