use crate::api::Api;
use crate::gateway;
use crate::gateway::GatewayInfo;
use crate::routemaster::gateway_check::{CheckError, GatewayCheck, GatewayCheckTask};
use crate::routemaster::{ActiveRoutes, Command, Handle, State};
use ario_core::Gateway;
use futures_concurrency::future::FutureGroup;
use futures_lite::{StreamExt, future};
use itertools::Itertools;
use rand::Rng;
use std::collections::HashMap;
use std::ops::Add;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

pub(super) struct BackgroundTask {
    routes: HashMap<Gateway, Route>,
    pending_checks: HashMap<Gateway, DropGuard>,
    cmd_rx: mpsc::Receiver<Command>,
    cmd_tx: mpsc::Sender<Command>,
    active_tx: watch::Sender<ActiveRoutes>,
    ct: CancellationToken,
    state: watch::Sender<State>,
    api: Api,
    check_permits: Arc<Semaphore>,
    _drop_guard: DropGuard,
}

impl BackgroundTask {
    pub(super) fn new(
        initial_gateways: Vec<Gateway>,
        cmd_rx: mpsc::Receiver<Command>,
        cmd_tx: mpsc::Sender<Command>,
        active_tx: watch::Sender<ActiveRoutes>,
        ct: CancellationToken,
        state: watch::Sender<State>,
        api: Api,
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
            api,
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
    pub(super) async fn run(mut self) {
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
                    status,
                    avg_duration: duration,
                    ..
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
        let latest_duration = check
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
                    avg_duration: latest_duration,
                };
            }
            Checked::Checked {
                status: st,
                num_checks,
                last_check: lc,
                avg_duration,
            } => {
                *st = status;
                *num_checks = *num_checks + 1;
                *lc = last_check;
                *avg_duration = {
                    // Update EMA (α = 0.2, gives 20% weight to latest sample)
                    Duration::from_secs_f64(
                        avg_duration.as_secs_f64() * 0.8 + latest_duration.as_secs_f64() * 0.2,
                    )
                }
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
                self.api.clone(),
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
                let base_duration = match &status {
                    GatewayStatus::Ok(_) => Duration::from_secs(600),
                    GatewayStatus::Error { .. } => Duration::from_secs(60),
                };
                // introduce jitter (+/- 15% range)
                let jitter_factor = rand::rng().random_range(0.85..=1.15);
                let jittered_duration =
                    Duration::from_secs_f64(base_duration.as_secs_f64() * jitter_factor);

                last_check.add(jittered_duration)
            }
        }
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
        avg_duration: Duration,
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
