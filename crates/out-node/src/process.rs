//! Repository-local testnet/devnet node process assembly.
//!
//! This module wires pinned bootstrap, persistent storage, the bounded memory
//! P2P driver, and authenticated Unix operator control. It installs nothing
//! and does not open TCP/UDP sockets.

use std::io;
use std::path::{Path, PathBuf};

use out_storage::redb_backend::RedbConsensusStore;
use out_storage::rocksdb_backend::RocksdbConsensusStore;
use out_storage::RecoverableConsensusStorage;

use crate::bootstrap::NodeBootstrap;
use crate::dispatcher::{ApplicationDispatcher, DispatcherPolicy};
use crate::driver::{
    BoundedMemoryDriver, DaemonHarness, DaemonPhase, DaemonPolicy, MemoryDriverPolicy,
};
use crate::mempool::MempoolPolicy;
use crate::mining::CpuMiningPolicy;
use crate::operator::{
    OperatorKey, OperatorReply, OperatorServeOutcome, UnixMiningControlServer, UnixOperatorError,
    UnixOperatorPolicy,
};
use crate::peers::{MemoryTransportPolicy, MultiPeerPolicy};
use crate::runtime::{NodeRuntime, RuntimePhase, RuntimePolicy};
use crate::serving::ServingPolicy;
use crate::sync::SyncPolicy;
use crate::{Node, SupportedNetwork};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentBackend {
    Redb,
    Rocksdb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentOpenMode {
    Create,
    Open,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNodeProcessConfig {
    pub network: SupportedNetwork,
    pub backend: PersistentBackend,
    pub open_mode: PersistentOpenMode,
    pub database_path: PathBuf,
    pub operator_socket_path: PathBuf,
    pub maximum_reorganization_blocks: u64,
    pub operator_policy: UnixOperatorPolicy,
}

#[derive(Debug)]
pub enum LocalNodeProcessError {
    Bootstrap(String),
    Application(String),
    Operator(UnixOperatorError),
    UnexpectedPhase(DaemonPhase),
    DrainBudgetExhausted,
    TickOverflow,
}

enum LocalNodeApplication {
    Redb(ApplicationDispatcher<RedbConsensusStore, BoundedMemoryDriver>),
    Rocksdb(ApplicationDispatcher<RocksdbConsensusStore, BoundedMemoryDriver>),
}

impl LocalNodeApplication {
    fn start_and_recover(&mut self) -> Result<(), LocalNodeProcessError> {
        let phase = match self {
            Self::Redb(dispatcher) => dispatcher
                .start()
                .map_err(|error| LocalNodeProcessError::Application(format!("{error:?}")))?,
            Self::Rocksdb(dispatcher) => dispatcher
                .start()
                .map_err(|error| LocalNodeProcessError::Application(format!("{error:?}")))?,
        };
        match phase {
            DaemonPhase::Running => Ok(()),
            DaemonPhase::Recovering => {
                match self {
                    Self::Redb(dispatcher) => dispatcher.recover_storage().map_err(|error| {
                        LocalNodeProcessError::Application(format!("{error:?}"))
                    })?,
                    Self::Rocksdb(dispatcher) => dispatcher.recover_storage().map_err(|error| {
                        LocalNodeProcessError::Application(format!("{error:?}"))
                    })?,
                };
                if self.phase() == DaemonPhase::Running {
                    Ok(())
                } else {
                    Err(LocalNodeProcessError::UnexpectedPhase(self.phase()))
                }
            }
            other => Err(LocalNodeProcessError::UnexpectedPhase(other)),
        }
    }

    fn serve_once(
        &mut self,
        server: &mut UnixMiningControlServer,
    ) -> Result<OperatorServeOutcome, UnixOperatorError> {
        match self {
            Self::Redb(dispatcher) => server.serve_once(dispatcher),
            Self::Rocksdb(dispatcher) => server.serve_once(dispatcher),
        }
    }

    fn phase(&self) -> DaemonPhase {
        match self {
            Self::Redb(dispatcher) => dispatcher.daemon().phase(),
            Self::Rocksdb(dispatcher) => dispatcher.daemon().phase(),
        }
    }

    fn runtime_phase(&self) -> RuntimePhase {
        match self {
            Self::Redb(dispatcher) => dispatcher.daemon().runtime().phase(),
            Self::Rocksdb(dispatcher) => dispatcher.daemon().runtime().phase(),
        }
    }

    fn step(&mut self, tick: u64) -> Result<(), LocalNodeProcessError> {
        match self {
            Self::Redb(dispatcher) => dispatcher
                .step(tick)
                .map(|_| ())
                .map_err(|error| LocalNodeProcessError::Application(format!("{error:?}"))),
            Self::Rocksdb(dispatcher) => dispatcher
                .step(tick)
                .map(|_| ())
                .map_err(|error| LocalNodeProcessError::Application(format!("{error:?}"))),
        }
    }
}

pub fn run_local_node_process(
    config: LocalNodeProcessConfig,
    key: OperatorKey,
) -> Result<(), LocalNodeProcessError> {
    let mut application = open_application(&config)?;
    application.start_and_recover()?;
    let mut server =
        UnixMiningControlServer::bind(&config.operator_socket_path, key, config.operator_policy)
            .map_err(LocalNodeProcessError::Operator)?;
    loop {
        let outcome = match application.serve_once(&mut server) {
            Ok(outcome) => outcome,
            Err(UnixOperatorError::Frame(_)) => continue,
            Err(UnixOperatorError::Io(error)) if recoverable_connection_error(&error) => continue,
            Err(error) => return Err(LocalNodeProcessError::Operator(error)),
        };
        if outcome.reply == OperatorReply::ShutdownRequested {
            break;
        }
    }
    drain_application(&mut application)
}

fn recoverable_connection_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::Interrupted
    )
}

fn open_application(
    config: &LocalNodeProcessConfig,
) -> Result<LocalNodeApplication, LocalNodeProcessError> {
    let bootstrap = NodeBootstrap {
        network: config.network,
        maximum_reorganization_blocks: config.maximum_reorganization_blocks,
    };
    match (config.backend, config.open_mode) {
        (PersistentBackend::Redb, PersistentOpenMode::Create) => bootstrap
            .create_redb(&config.database_path)
            .map_err(|error| LocalNodeProcessError::Bootstrap(format!("{error:?}")))
            .and_then(build_dispatcher)
            .map(LocalNodeApplication::Redb),
        (PersistentBackend::Redb, PersistentOpenMode::Open) => bootstrap
            .open_redb(&config.database_path)
            .map_err(|error| LocalNodeProcessError::Bootstrap(format!("{error:?}")))
            .and_then(build_dispatcher)
            .map(LocalNodeApplication::Redb),
        (PersistentBackend::Rocksdb, PersistentOpenMode::Create) => bootstrap
            .create_rocksdb(&config.database_path)
            .map_err(|error| LocalNodeProcessError::Bootstrap(format!("{error:?}")))
            .and_then(build_dispatcher)
            .map(LocalNodeApplication::Rocksdb),
        (PersistentBackend::Rocksdb, PersistentOpenMode::Open) => bootstrap
            .open_rocksdb(&config.database_path)
            .map_err(|error| LocalNodeProcessError::Bootstrap(format!("{error:?}")))
            .and_then(build_dispatcher)
            .map(LocalNodeApplication::Rocksdb),
    }
}

fn build_dispatcher<S>(
    node: Node<S>,
) -> Result<ApplicationDispatcher<S, BoundedMemoryDriver>, LocalNodeProcessError>
where
    S: RecoverableConsensusStorage,
{
    let runtime = NodeRuntime::new(
        node,
        RuntimePolicy {
            maximum_peers: 8,
            maximum_inbound_events: 16,
            maximum_inbound_bytes: 4_000_000,
            maximum_frame_bytes: 1_000_000,
            maximum_output_events: 16,
            maximum_inbound_events_per_step: 16,
            maximum_peer_polls_per_step: 8,
        },
    )
    .map_err(|_| LocalNodeProcessError::Application("runtime construction failed".into()))?;
    let queue = MemoryTransportPolicy {
        maximum_queued_frames: 16,
        maximum_queued_bytes: 4_000_000,
        maximum_frame_bytes: 1_000_000,
    };
    let driver = BoundedMemoryDriver::new(MemoryDriverPolicy {
        inbound: queue,
        outbound: queue,
    })
    .map_err(|_| LocalNodeProcessError::Application("daemon construction failed".into()))?;
    let daemon = DaemonHarness::new(
        runtime,
        driver,
        DaemonPolicy {
            maximum_transport_receives_per_step: 16,
            maximum_transport_sends_per_step: 16,
            maximum_runtime_outputs_per_step: 16,
            maximum_pending_outbound_frames: 16,
            maximum_pending_outbound_bytes: 4_000_000,
            maximum_local_events: 32,
        },
    )
    .map_err(|_| LocalNodeProcessError::Application("daemon construction failed".into()))?;
    ApplicationDispatcher::new(
        daemon,
        SyncPolicy {
            maximum_overlay_headers: 16,
            maximum_blocks_per_request: 8,
            maximum_locator_entries: 8,
            linear_locator_entries: 2,
            maximum_locator_walk: 10_000,
        },
        MultiPeerPolicy {
            maximum_peers: 8,
            maximum_announcements_per_peer: 16,
            maximum_total_announcements: 64,
            maximum_pending_objects: 16,
            maximum_in_flight_per_peer: 8,
            maximum_retry_attempts: 4,
            request_timeout_ticks: 20,
            base_retry_backoff_ticks: 1,
            maximum_retry_backoff_ticks: 8,
            first_request_id: 100,
            maximum_orphans: 16,
            maximum_orphans_per_peer: 16,
            maximum_orphans_per_parent: 8,
            maximum_orphan_bytes: 4_000_000,
        },
        DispatcherPolicy {
            maximum_events_per_step: 32,
            maximum_commands_per_step: 8,
            first_orphan_replay_request_id: 10_000,
        },
        ServingPolicy {
            maximum_pending_requests: 16,
            maximum_responses_per_step: 4,
            maximum_pending_announcements: 16,
            maximum_announcements_per_step: 4,
            maximum_inventory_entries_per_announcement: 16,
            maximum_headers_per_response: 8,
            maximum_ancestry_records: 10_000,
            maximum_relay_blocks: 16,
            maximum_relay_bytes: 4_000_000,
        },
        MempoolPolicy {
            maximum_transactions: 1_024,
            maximum_total_bytes: 16_000_000,
            maximum_transactions_per_sender: 64,
            maximum_template_transactions: 1_024,
            maximum_template_bytes: 4_000_000,
        },
        CpuMiningPolicy {
            maximum_nonce_attempts: 4_096,
        },
    )
    .map_err(|_| LocalNodeProcessError::Application("dispatcher construction failed".into()))
}

fn drain_application(application: &mut LocalNodeApplication) -> Result<(), LocalNodeProcessError> {
    const MAXIMUM_DRAIN_STEPS: u16 = 1_024;
    let mut tick = 0_u64;
    for _ in 0..MAXIMUM_DRAIN_STEPS {
        if application.phase() == DaemonPhase::Stopped
            && application.runtime_phase() == RuntimePhase::Stopped
        {
            return Ok(());
        }
        application.step(tick)?;
        tick = tick
            .checked_add(1)
            .ok_or(LocalNodeProcessError::TickOverflow)?;
    }
    Err(LocalNodeProcessError::DrainBudgetExhausted)
}

pub fn database_path_exists(path: &Path) -> bool {
    path.exists()
}
