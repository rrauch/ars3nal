use crate::routemaster::{Command, State};
use n0_watcher::Watcher;
use netwatch::netmon;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio_util::future::FutureExt;
use tokio_util::sync::CancellationToken;

pub(super) struct Netwatch {
    cmd_tx: mpsc::Sender<Command>,
    state: watch::Receiver<State>,
    ct: CancellationToken,
}

impl Netwatch {
    pub(super) fn new(
        cmd_tx: mpsc::Sender<Command>,
        state: watch::Receiver<State>,
        ct: CancellationToken,
    ) -> Self {
        Self { cmd_tx, state, ct }
    }

    #[tracing::instrument(name = "netwatch_run", skip(self))]
    pub(super) async fn run(self) {
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
                    rm_state = rm_state_rx.borrow_and_update().clone();
                    if rm_state.shutting_down() {
                        break;
                    }
                }
            }
        }
        tracing::info!("netwatch shutting down");
    }
}
