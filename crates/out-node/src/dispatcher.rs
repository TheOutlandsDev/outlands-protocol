//! Deterministic application dispatcher joining daemon events, peer policy,
//! header synchronization, and authoritative complete-block delivery.
//!
//! This module performs no I/O and owns no clock. Inventory and header data are
//! disposable hints; only `Node::deliver_scheduled_block` may commit a block.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use out_codec::{
    Block, DecodeError as ConsensusDecodeError, EncodeError, RegularTransaction, Transaction,
};
use out_consensus::block::BlockLocalFailure;
use out_consensus::chain::{ChainTip, ChildHeaderLocalFailure, ValidatedHeaderView};
use out_consensus::{block_id_from_header_bytes, transaction_id_from_canonical_bytes};
use out_p2p::session::{RequestKind, SessionAction};
use out_p2p::{Hello, InventoryEntry, Message, TYPE_GET_OBJECTS};
use out_primitives::{Amount, BlockId, Nonce, Recipient, TransactionId};
use out_state::Account;
use out_storage::{ConsensusStorage, RecoverableConsensusStorage, RecoveryOutcome, RecoveryStatus};

use crate::driver::{
    DaemonError, DaemonEvent, DaemonHarness, DaemonPeerRemoval, DaemonPhase, DaemonStep,
    TransportDriver,
};
use crate::mempool::{Mempool, MempoolAdmission, MempoolError, MempoolPolicy, MempoolPolicyError};
use crate::mining::{
    build_candidate, CandidateBuildError, CandidateRequest, CpuMiningPolicy, CpuMiningPolicyError,
    MiningCandidate, MiningCoordinator, MiningJobSnapshot, MiningWorkOutcome,
};
use crate::peers::{
    MultiPeerCoordinator, MultiPeerError, MultiPeerPolicy, OrphanAdmission, OrphanBlock,
    PeerDisconnectCleanup, PeerId, RequestAssignment, RetryOutcome, RetryReason,
};
use crate::runtime::{RuntimeCommand, RuntimeError};
use crate::serving::{
    AnnouncementError, InboundServing, RelayAdmission, ServingError, ServingPolicy,
    ServingPolicyError, ServingReply,
};
use crate::sync::{
    BeginBlockRequestError, BlockDeliveryFailure, BlockDeliveryLocal, BlockDeliveryOutcome,
    HeaderBatchFailure, HeaderBatchOutcome, LocatorError, RetryBlockError, SyncCoordinator,
    SyncOpenError, SyncPolicy,
};
use crate::{ActivationOutcome, ProcessBlockError, ProcessBlockOutcome, SupportedNetwork};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatcherPolicy {
    pub maximum_events_per_step: u16,
    pub maximum_commands_per_step: u16,
    pub first_orphan_replay_request_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatcherPolicyError {
    Zero(&'static str),
    PendingObjectsBelowHeaderOverlay { pending: u16, overlay: u16 },
}

impl DispatcherPolicy {
    pub fn validate(
        self,
        sync: SyncPolicy,
        peers: MultiPeerPolicy,
    ) -> Result<Self, DispatcherPolicyError> {
        if self.maximum_events_per_step == 0 {
            return Err(DispatcherPolicyError::Zero("maximum_events_per_step"));
        }
        if self.maximum_commands_per_step == 0 {
            return Err(DispatcherPolicyError::Zero("maximum_commands_per_step"));
        }
        if self.first_orphan_replay_request_id == 0 {
            return Err(DispatcherPolicyError::Zero(
                "first_orphan_replay_request_id",
            ));
        }
        if peers.maximum_pending_objects < sync.maximum_overlay_headers {
            return Err(DispatcherPolicyError::PendingObjectsBelowHeaderOverlay {
                pending: peers.maximum_pending_objects,
                overlay: sync.maximum_overlay_headers,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeaderRequest {
    peer_id: PeerId,
    request_id: u64,
    stop_id: BlockId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum InboundServiceRequest {
    Headers {
        peer_id: PeerId,
        request_id: u64,
        locator: Vec<BlockId>,
        stop_id: BlockId,
    },
    Objects {
        peer_id: PeerId,
        request_id: u64,
        objects: Vec<InventoryEntry>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingAnnouncement {
    peer_id: PeerId,
    entries: Vec<InventoryEntry>,
}

impl InboundServiceRequest {
    const fn peer_id(&self) -> PeerId {
        match self {
            Self::Headers { peer_id, .. } | Self::Objects { peer_id, .. } => *peer_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatcherNotice {
    PeerEstablished {
        peer_id: PeerId,
        best_height: u64,
        best_block_id: BlockId,
    },
    PeerDisconnected {
        peer_id: PeerId,
        requeued_objects: u16,
        detached_orphans: u16,
    },
    InventoryObserved {
        peer_id: PeerId,
        additions: u16,
    },
    InventoryAnnounced {
        peer_id: PeerId,
        entries: u16,
    },
    HeaderRequestStarted {
        peer_id: PeerId,
        request_id: u64,
        stop_id: BlockId,
    },
    HeadersAccepted {
        peer_id: PeerId,
        validated: u16,
        scheduled: u16,
        reached_stop: bool,
    },
    HeaderSyncComplete {
        peer_id: PeerId,
        reached_stop: bool,
    },
    ObjectRequested(RequestAssignment),
    ObjectStored {
        peer_id: PeerId,
        block_id: BlockId,
    },
    TransactionAccepted {
        peer_id: PeerId,
        transaction_id: TransactionId,
    },
    TransactionAlreadyKnown {
        peer_id: PeerId,
        transaction_id: TransactionId,
    },
    TransactionRejected {
        peer_id: PeerId,
        transaction_id: TransactionId,
    },
    TransactionPolicyDropped {
        peer_id: PeerId,
        transaction_id: TransactionId,
    },
    MempoolReconciled {
        retained: u16,
        removed: u16,
    },
    ObjectRetried {
        request_id: u64,
        outcome: RetryOutcome,
    },
    OrphanStored {
        peer_id: PeerId,
        block_id: BlockId,
        parent_block_id: BlockId,
    },
    OrphanReplayed {
        block_id: BlockId,
    },
    HeadersServed {
        peer_id: PeerId,
        request_id: u64,
        count: u16,
    },
    BlockServed {
        peer_id: PeerId,
        request_id: u64,
        block_id: BlockId,
    },
    TransactionServed {
        peer_id: PeerId,
        request_id: u64,
        transaction_id: TransactionId,
    },
    ServiceRejected {
        peer_id: PeerId,
        request_id: u64,
        rejected_type: u16,
        code: u16,
    },
    RelayCached {
        block_id: BlockId,
        evicted: u16,
    },
    RelayNotCached {
        block_id: BlockId,
    },
    FrameRejected {
        peer_id: PeerId,
    },
    SessionFailed {
        peer_id: PeerId,
    },
    SessionPolicyEvent {
        peer_id: PeerId,
    },
    MinedBlockAccepted {
        block_id: BlockId,
        announcements_queued: u16,
    },
    MinedBlockStoredNotSelected {
        block_id: BlockId,
    },
}

pub struct DispatcherStep {
    pub daemon: DaemonStep,
    pub events_processed: u16,
    pub commands_started: u16,
    pub notices: Vec<DispatcherNotice>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerDisconnectOutcome {
    pub peer_id: PeerId,
    pub daemon: DaemonPeerRemoval,
    pub scheduler: Option<PeerDisconnectCleanup>,
    pub discarded_service_requests: u16,
    pub discarded_announcements: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MiningAnnouncementBackpressure {
    pub required: u16,
    pub available: u16,
}

#[derive(Debug)]
pub struct LocalMiningStep {
    pub work: MiningWorkOutcome,
    pub submission: Option<Box<ProcessBlockOutcome>>,
    pub relay_cached: bool,
    pub announcements_queued: u16,
    pub announcement_backpressure: Option<MiningAnnouncementBackpressure>,
    pub notices: Vec<DispatcherNotice>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MiningControlCommand {
    Inspect,
    Start {
        request: CandidateRequest,
        first_nonce: u64,
    },
    Refresh {
        request: CandidateRequest,
        first_nonce: u64,
    },
    Step {
        local_now: u64,
    },
    Cancel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningControlStatus {
    pub network: SupportedNetwork,
    pub canonical_tip: ChainTip,
    pub mempool_revision: u64,
    pub job: Option<MiningJobSnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalAccountStatus {
    pub canonical_tip: ChainTip,
    pub recipient: Recipient,
    pub exists: bool,
    pub balance: Amount,
    pub nonce: Nonce,
}

#[derive(Debug)]
pub enum MiningControlOutcome {
    Inspected(MiningControlStatus),
    Started(MiningJobSnapshot),
    Refreshed {
        previous: MiningJobSnapshot,
        current: MiningJobSnapshot,
    },
    Stepped(Box<LocalMiningStep>),
    Cancelled(Option<MiningJobSnapshot>),
}

#[derive(Debug)]
pub enum DispatcherError<ReadError, MutationError, RecoveryError, TransportError> {
    Policy(DispatcherPolicyError),
    ServingPolicy(ServingPolicyError),
    MempoolPolicy(MempoolPolicyError),
    Mempool(MempoolError<ReadError>),
    MempoolUnavailable,
    Candidate(Box<CandidateBuildError<ReadError>>),
    Mining(CpuMiningPolicyError),
    MiningTipRead(ReadError),
    MiningJobAlreadyActive(Box<MiningJobSnapshot>),
    MiningJobNotActive,
    MiningControlInvariant,
    CanonicalTransactionDecode(ConsensusDecodeError),
    AccountTipRead(ReadError),
    AccountStateRead(ReadError),
    MissingCanonicalAccountState(BlockId),
    AccountStateAnchorMismatch {
        expected: BlockId,
        actual: BlockId,
    },
    DuplicateCanonicalAccount(Recipient),
    MinedBlockEncoding(EncodeError),
    MinedBlock(Box<ProcessBlockError<ReadError, MutationError>>),
    Serving(ServingError<ReadError>),
    Announcement(AnnouncementError<ReadError>),
    PeerNotEstablished(PeerId),
    AnnouncementCapacity {
        maximum: u16,
    },
    EmptyTransactionAnnouncement,
    TransactionAnnouncementTooMany {
        actual: usize,
        maximum: u16,
    },
    DuplicateTransactionAnnouncement(TransactionId),
    TransactionNotRelayed(TransactionId),
    SyncOpen(SyncOpenError<ReadError>),
    SyncUnavailable,
    Daemon(Box<DaemonError<RecoveryError, TransportError>>),
    Runtime(RuntimeError<RecoveryError>),
    MultiPeer(MultiPeerError),
    Locator(LocatorError<ReadError>),
    HeaderBatch(Box<HeaderBatchFailure<ReadError>>),
    HeaderResponseWithoutRequest {
        peer_id: PeerId,
        request_id: u64,
    },
    HeaderResponseMismatch {
        expected_peer: PeerId,
        expected_request: u64,
        actual_peer: PeerId,
        actual_request: u64,
    },
    BeginBlock(BeginBlockRequestError),
    RetryBlock(RetryBlockError),
    NonBlockAssignment(InventoryEntry),
    NonTransactionAssignment(InventoryEntry),
    UnknownObjectRequest(u64),
    ObjectPeerMismatch {
        expected: PeerId,
        actual: PeerId,
    },
    ObjectIdMismatch {
        expected: BlockId,
        actual: BlockId,
    },
    TransactionIdMismatch {
        expected: TransactionId,
        actual: TransactionId,
    },
    BlockDelivery(Box<BlockDeliveryFailure<ReadError, MutationError>>),
    OrphanDecode(ConsensusDecodeError),
    ReplayRequestIdExhausted,
    CountWidth,
    UnexpectedSessionAction,
}

pub type DispatcherResult<T, S, D> = Result<
    T,
    DispatcherError<
        <S as ValidatedHeaderView>::Error,
        <S as ConsensusStorage>::MutationError,
        <S as RecoverableConsensusStorage>::RecoveryError,
        <D as TransportDriver>::Error,
    >,
>;

pub struct ApplicationDispatcher<S, D>
where
    S: RecoverableConsensusStorage,
    D: TransportDriver,
{
    daemon: DaemonHarness<S, D>,
    sync: Option<SyncCoordinator>,
    sync_policy: SyncPolicy,
    peers: MultiPeerCoordinator,
    policy: DispatcherPolicy,
    peer_tips: BTreeMap<PeerId, Hello>,
    header_exhausted: BTreeSet<PeerId>,
    active_header: Option<HeaderRequest>,
    next_orphan_replay_request_id: u64,
    serving: InboundServing,
    mempool: Option<Mempool>,
    mempool_policy: MempoolPolicy,
    mining: MiningCoordinator,
    pending_service: VecDeque<InboundServiceRequest>,
    pending_announcements: VecDeque<PendingAnnouncement>,
}

impl<S, D> ApplicationDispatcher<S, D>
where
    S: RecoverableConsensusStorage,
    D: TransportDriver,
{
    pub fn new(
        daemon: DaemonHarness<S, D>,
        sync_policy: SyncPolicy,
        peer_policy: MultiPeerPolicy,
        policy: DispatcherPolicy,
        serving_policy: ServingPolicy,
        mempool_policy: MempoolPolicy,
        mining_policy: CpuMiningPolicy,
    ) -> DispatcherResult<Self, S, D> {
        let policy = policy
            .validate(sync_policy, peer_policy)
            .map_err(DispatcherError::Policy)?;
        let serving = InboundServing::new(serving_policy, policy.maximum_commands_per_step)
            .map_err(DispatcherError::ServingPolicy)?;
        let mempool_policy = mempool_policy
            .validate()
            .map_err(DispatcherError::MempoolPolicy)?;
        let mining = MiningCoordinator::new(mining_policy).map_err(DispatcherError::Mining)?;
        let sync = if daemon.runtime().node().recovery_status() == RecoveryStatus::Clean {
            Some(
                SyncCoordinator::new(
                    daemon.runtime().node().storage(),
                    daemon.runtime().node().config().network,
                    sync_policy,
                )
                .map_err(DispatcherError::SyncOpen)?,
            )
        } else {
            None
        };
        let mempool = if daemon.runtime().node().recovery_status() == RecoveryStatus::Clean {
            Some(
                Mempool::new(
                    daemon.runtime().node().storage(),
                    daemon.runtime().node().config().network,
                    mempool_policy,
                )
                .map_err(DispatcherError::Mempool)?,
            )
        } else {
            None
        };
        let peers = MultiPeerCoordinator::new(peer_policy).map_err(DispatcherError::MultiPeer)?;
        Ok(Self {
            daemon,
            sync,
            sync_policy,
            peers,
            policy,
            peer_tips: BTreeMap::new(),
            header_exhausted: BTreeSet::new(),
            active_header: None,
            next_orphan_replay_request_id: policy.first_orphan_replay_request_id,
            serving,
            mempool,
            mempool_policy,
            mining,
            pending_service: VecDeque::new(),
            pending_announcements: VecDeque::new(),
        })
    }

    pub const fn daemon(&self) -> &DaemonHarness<S, D> {
        &self.daemon
    }

    pub fn daemon_mut(&mut self) -> &mut DaemonHarness<S, D> {
        &mut self.daemon
    }

    pub const fn sync(&self) -> Option<&SyncCoordinator> {
        self.sync.as_ref()
    }

    pub const fn peers(&self) -> &MultiPeerCoordinator {
        &self.peers
    }

    pub const fn serving(&self) -> &InboundServing {
        &self.serving
    }

    pub const fn mempool(&self) -> Option<&Mempool> {
        self.mempool.as_ref()
    }

    pub const fn mining(&self) -> &MiningCoordinator {
        &self.mining
    }

    pub fn mining_control_status(&self) -> DispatcherResult<MiningControlStatus, S, D> {
        let canonical_tip = self
            .daemon
            .runtime()
            .node()
            .canonical_tip()
            .map_err(DispatcherError::MiningTipRead)?;
        let mempool_revision = self
            .mempool
            .as_ref()
            .ok_or(DispatcherError::MempoolUnavailable)?
            .revision();
        Ok(MiningControlStatus {
            network: self.daemon.runtime().node().config().network,
            canonical_tip,
            mempool_revision,
            job: self.mining.snapshot(),
        })
    }

    /// Executes exactly one typed, transport-independent local mining command.
    /// Starting refuses implicit replacement; refreshing replaces an active job
    /// only after the new candidate has been built successfully.
    pub fn control_mining(
        &mut self,
        command: MiningControlCommand,
    ) -> DispatcherResult<MiningControlOutcome, S, D> {
        match command {
            MiningControlCommand::Inspect => self
                .mining_control_status()
                .map(MiningControlOutcome::Inspected),
            MiningControlCommand::Start {
                request,
                first_nonce,
            } => {
                if let Some(active) = self.mining.snapshot() {
                    return Err(DispatcherError::MiningJobAlreadyActive(Box::new(active)));
                }
                if self.start_mining_job(request, first_nonce)? {
                    return Err(DispatcherError::MiningControlInvariant);
                }
                let job = self
                    .mining
                    .snapshot()
                    .ok_or(DispatcherError::MiningControlInvariant)?;
                Ok(MiningControlOutcome::Started(job))
            }
            MiningControlCommand::Refresh {
                request,
                first_nonce,
            } => {
                let previous = self
                    .mining
                    .snapshot()
                    .ok_or(DispatcherError::MiningJobNotActive)?;
                let candidate = self.build_mining_candidate(request)?;
                if !self.mining.start(candidate, first_nonce) {
                    return Err(DispatcherError::MiningControlInvariant);
                }
                let current = self
                    .mining
                    .snapshot()
                    .ok_or(DispatcherError::MiningControlInvariant)?;
                Ok(MiningControlOutcome::Refreshed { previous, current })
            }
            MiningControlCommand::Step { local_now } => self
                .mine_step(local_now)
                .map(|step| MiningControlOutcome::Stepped(Box::new(step))),
            MiningControlCommand::Cancel => {
                Ok(MiningControlOutcome::Cancelled(self.cancel_mining_job()))
            }
        }
    }

    pub fn submit_transaction(
        &mut self,
        transaction: Transaction,
    ) -> DispatcherResult<MempoolAdmission, S, D> {
        self.mempool
            .as_mut()
            .ok_or(DispatcherError::MempoolUnavailable)?
            .admit(self.daemon.runtime().node().storage(), transaction)
            .map_err(DispatcherError::Mempool)
    }

    pub fn submit_canonical_transaction(
        &mut self,
        canonical_bytes: &[u8],
    ) -> DispatcherResult<MempoolAdmission, S, D> {
        let transaction = RegularTransaction::decode_exact(canonical_bytes)
            .map_err(DispatcherError::CanonicalTransactionDecode)?;
        self.submit_transaction(Transaction::Regular(transaction))
    }

    pub fn canonical_account_status(
        &self,
        recipient: Recipient,
    ) -> DispatcherResult<CanonicalAccountStatus, S, D> {
        let storage = self.daemon.runtime().node().storage();
        let canonical_tip = storage
            .canonical_tip()
            .map_err(DispatcherError::AccountTipRead)?;
        let state = storage
            .parent_state_snapshot(canonical_tip.block_id)
            .map_err(DispatcherError::AccountStateRead)?
            .ok_or(DispatcherError::MissingCanonicalAccountState(
                canonical_tip.block_id,
            ))?;
        if state.anchor_block_id != canonical_tip.block_id {
            return Err(DispatcherError::AccountStateAnchorMismatch {
                expected: canonical_tip.block_id,
                actual: state.anchor_block_id,
            });
        }
        let mut account = None;
        for (candidate, value) in state.accounts {
            if candidate == recipient && account.replace(value).is_some() {
                return Err(DispatcherError::DuplicateCanonicalAccount(recipient));
            }
        }
        let exists = account.is_some();
        let account = account.unwrap_or(Account::EMPTY);
        Ok(CanonicalAccountStatus {
            canonical_tip,
            recipient,
            exists,
            balance: account.balance,
            nonce: account.nonce,
        })
    }

    pub fn build_mining_candidate(
        &mut self,
        request: CandidateRequest,
    ) -> DispatcherResult<MiningCandidate, S, D> {
        let network = self.daemon.runtime().node().config().network;
        let storage = self.daemon.runtime().node().storage();
        let mempool = self
            .mempool
            .as_mut()
            .ok_or(DispatcherError::MempoolUnavailable)?;
        build_candidate(storage, mempool, network, request)
            .map_err(|error| DispatcherError::Candidate(Box::new(error)))
    }

    pub fn start_mining_job(
        &mut self,
        request: CandidateRequest,
        first_nonce: u64,
    ) -> DispatcherResult<bool, S, D> {
        let candidate = self.build_mining_candidate(request)?;
        Ok(self.mining.start(candidate, first_nonce))
    }

    pub fn cancel_mining_job(&mut self) -> Option<MiningJobSnapshot> {
        self.mining.cancel()
    }

    pub fn mine_step(&mut self, now: u64) -> DispatcherResult<LocalMiningStep, S, D> {
        let mut notices = Vec::new();
        self.reconcile_mempool(&mut notices)?;
        let canonical_tip = self
            .daemon
            .runtime()
            .node()
            .canonical_tip()
            .map_err(DispatcherError::MiningTipRead)?;
        let mempool_revision = self
            .mempool
            .as_ref()
            .ok_or(DispatcherError::MempoolUnavailable)?
            .revision();
        let work = self
            .mining
            .step(canonical_tip, mempool_revision)
            .map_err(DispatcherError::Mining)?;
        let Some(solution) = self.mining.solution() else {
            return Ok(LocalMiningStep {
                work,
                submission: None,
                relay_cached: false,
                announcements_queued: 0,
                announcement_backpressure: None,
                notices,
            });
        };
        let raw = solution
            .block
            .encode_non_genesis()
            .map_err(DispatcherError::MinedBlockEncoding)?;
        let relay_possible = u64::try_from(raw.len())
            .is_ok_and(|length| length <= self.serving.policy().maximum_relay_bytes);
        let required = if relay_possible {
            u16::try_from(self.peer_tips.len()).map_err(|_| DispatcherError::CountWidth)?
        } else {
            0
        };
        let maximum = self.serving.policy().maximum_pending_announcements;
        let pending = u16::try_from(self.pending_announcements.len())
            .map_err(|_| DispatcherError::CountWidth)?;
        let available = maximum.saturating_sub(pending);
        if required > available {
            return Ok(LocalMiningStep {
                work,
                submission: None,
                relay_cached: false,
                announcements_queued: 0,
                announcement_backpressure: Some(MiningAnnouncementBackpressure {
                    required,
                    available,
                }),
                notices,
            });
        }
        let block = solution.block.clone();
        let block_id = solution.block_id;
        let process = match self
            .daemon
            .runtime_mut()
            .node_mut()
            .process_block(&raw, now)
        {
            Ok(process) => process,
            Err(error) => {
                self.mining.cancel();
                return Err(DispatcherError::MinedBlock(Box::new(error)));
            }
        };
        self.mining.complete_solution();
        let relay_cached = self.record_relay_admission(block, &mut notices)?;
        self.reconcile_mempool(&mut notices)?;
        let selected_tip = match &process.activation {
            ActivationOutcome::Unchanged { tip } => *tip,
            ActivationOutcome::Applied { new_tip, .. } => *new_tip,
            ActivationOutcome::PolicyPaused { selected_tip, .. } => *selected_tip,
        };
        let mut announcements_queued = 0_u16;
        if selected_tip.block_id == block_id && relay_cached {
            for peer_id in self.peer_tips.keys().copied() {
                self.pending_announcements.push_back(PendingAnnouncement {
                    peer_id,
                    entries: vec![InventoryEntry::Block(block_id)],
                });
                announcements_queued = announcements_queued
                    .checked_add(1)
                    .ok_or(DispatcherError::CountWidth)?;
            }
            notices.push(DispatcherNotice::MinedBlockAccepted {
                block_id,
                announcements_queued,
            });
        } else {
            notices.push(DispatcherNotice::MinedBlockStoredNotSelected { block_id });
        }
        Ok(LocalMiningStep {
            work,
            submission: Some(Box::new(process)),
            relay_cached,
            announcements_queued,
            announcement_backpressure: None,
            notices,
        })
    }

    /// Queues one bounded block inventory notification after proving every ID
    /// is present in the disposable relay and current canonical ancestry.
    pub fn announce_blocks(
        &mut self,
        peer_id: PeerId,
        block_ids: Vec<BlockId>,
    ) -> DispatcherResult<(), S, D> {
        if !self.peer_tips.contains_key(&peer_id) {
            return Err(DispatcherError::PeerNotEstablished(peer_id));
        }
        if self.pending_announcements.len()
            >= usize::from(self.serving.policy().maximum_pending_announcements)
        {
            return Err(DispatcherError::AnnouncementCapacity {
                maximum: self.serving.policy().maximum_pending_announcements,
            });
        }
        let entries = self
            .serving
            .canonical_relay_inventory(self.daemon.runtime().node().storage(), &block_ids)
            .map_err(DispatcherError::Announcement)?;
        self.pending_announcements
            .push_back(PendingAnnouncement { peer_id, entries });
        Ok(())
    }

    pub fn announce_transactions(
        &mut self,
        peer_id: PeerId,
        transaction_ids: Vec<TransactionId>,
    ) -> DispatcherResult<(), S, D> {
        if !self.peer_tips.contains_key(&peer_id) {
            return Err(DispatcherError::PeerNotEstablished(peer_id));
        }
        if self.pending_announcements.len()
            >= usize::from(self.serving.policy().maximum_pending_announcements)
        {
            return Err(DispatcherError::AnnouncementCapacity {
                maximum: self.serving.policy().maximum_pending_announcements,
            });
        }
        if transaction_ids.is_empty() {
            return Err(DispatcherError::EmptyTransactionAnnouncement);
        }
        let maximum = self
            .serving
            .policy()
            .maximum_inventory_entries_per_announcement;
        if transaction_ids.len() > usize::from(maximum) {
            return Err(DispatcherError::TransactionAnnouncementTooMany {
                actual: transaction_ids.len(),
                maximum,
            });
        }
        let mempool = self
            .mempool
            .as_ref()
            .ok_or(DispatcherError::MempoolUnavailable)?;
        let mut unique = BTreeSet::new();
        let mut entries = Vec::with_capacity(transaction_ids.len());
        for transaction_id in transaction_ids {
            if !unique.insert(transaction_id) {
                return Err(DispatcherError::DuplicateTransactionAnnouncement(
                    transaction_id,
                ));
            }
            if !mempool.contains(transaction_id) {
                return Err(DispatcherError::TransactionNotRelayed(transaction_id));
            }
            entries.push(InventoryEntry::Transaction(transaction_id));
        }
        self.pending_announcements
            .push_back(PendingAnnouncement { peer_id, entries });
        Ok(())
    }

    /// Harness-only relay seeding. The caller MUST have observed successful
    /// full validation of this exact block. Serving still checks canonicality.
    pub(crate) fn admit_harness_validated_relay(&mut self, block: Block) -> RelayAdmission {
        self.serving.admit_validated(block)
    }

    pub fn start(&mut self) -> DispatcherResult<DaemonPhase, S, D> {
        self.daemon
            .start()
            .map_err(|error| DispatcherError::Daemon(Box::new(error)))
    }

    pub fn recover_storage(&mut self) -> DispatcherResult<RecoveryOutcome, S, D> {
        let outcome = self
            .daemon
            .recover_storage()
            .map_err(|error| DispatcherError::Daemon(Box::new(error)))?;
        self.sync = Some(
            SyncCoordinator::new(
                self.daemon.runtime().node().storage(),
                self.daemon.runtime().node().config().network,
                self.sync_policy,
            )
            .map_err(DispatcherError::SyncOpen)?,
        );
        self.mempool = Some(
            Mempool::new(
                self.daemon.runtime().node().storage(),
                self.daemon.runtime().node().config().network,
                self.mempool_policy,
            )
            .map_err(DispatcherError::Mempool)?,
        );
        Ok(outcome)
    }

    pub fn register_peer(
        &mut self,
        peer_id: PeerId,
        session: out_p2p::session::PeerSession,
        initial_actions: Vec<SessionAction>,
    ) -> DispatcherResult<(), S, D> {
        self.daemon
            .register_peer(peer_id, session, initial_actions)
            .map_err(|error| DispatcherError::Daemon(Box::new(error)))
    }

    /// Removes a peer across the driver, runtime, daemon, and application
    /// scheduler. Authoritative storage is untouched. In-flight block work is
    /// returned to both synchronization queues, while globally bounded orphan
    /// bytes are retained for full replay and detached from live peer quotas.
    pub fn disconnect_peer(
        &mut self,
        peer_id: PeerId,
    ) -> DispatcherResult<PeerDisconnectOutcome, S, D> {
        let discarded_service_requests = u16::try_from(
            self.pending_service
                .iter()
                .filter(|request| request.peer_id() == peer_id)
                .count(),
        )
        .map_err(|_| DispatcherError::CountWidth)?;
        let discarded_announcements = u16::try_from(
            self.pending_announcements
                .iter()
                .filter(|announcement| announcement.peer_id == peer_id)
                .count(),
        )
        .map_err(|_| DispatcherError::CountWidth)?;
        let daemon = self
            .daemon
            .unregister_peer(peer_id)
            .map_err(|error| DispatcherError::Daemon(Box::new(error)))?;
        let scheduler = if self.peers.contains_peer(peer_id) {
            let cleanup = self
                .peers
                .disconnect_peer(peer_id)
                .map_err(DispatcherError::MultiPeer)?;
            for object in &cleanup.requeued_objects {
                if let InventoryEntry::Block(block_id) = object {
                    self.sync
                        .as_mut()
                        .ok_or(DispatcherError::SyncUnavailable)?
                        .retry_block(*block_id)
                        .map_err(DispatcherError::RetryBlock)?;
                }
            }
            Some(cleanup)
        } else {
            None
        };
        if self
            .active_header
            .is_some_and(|active| active.peer_id == peer_id)
        {
            self.active_header = None;
        }
        self.header_exhausted.remove(&peer_id);
        self.peer_tips.remove(&peer_id);
        self.pending_service
            .retain(|request| request.peer_id() != peer_id);
        self.pending_announcements
            .retain(|announcement| announcement.peer_id != peer_id);
        Ok(PeerDisconnectOutcome {
            peer_id,
            daemon,
            scheduler,
            discarded_service_requests,
            discarded_announcements,
        })
    }

    pub fn request_shutdown(&mut self) -> DispatcherResult<(), S, D> {
        self.daemon
            .request_shutdown()
            .map_err(|error| DispatcherError::Daemon(Box::new(error)))
    }

    pub fn step(&mut self, now: u64) -> DispatcherResult<DispatcherStep, S, D> {
        let daemon = self
            .daemon
            .step(now)
            .map_err(|error| DispatcherError::Daemon(Box::new(error)))?;
        let mut notices = Vec::new();
        if self.mempool.is_some() {
            self.reconcile_mempool(&mut notices)?;
        }
        let mut events_processed = 0_u16;
        while events_processed < self.policy.maximum_events_per_step
            && self.pending_service.len()
                < usize::from(self.serving.policy().maximum_pending_requests)
        {
            let Some(event) = self.daemon.pop_event() else {
                break;
            };
            self.handle_event(event, now, &mut notices)?;
            events_processed = events_processed.saturating_add(1);
        }

        let mut commands_started = 0_u16;
        let mut responses_started = 0_u16;
        let mut announcements_started = 0_u16;
        while commands_started < self.policy.maximum_commands_per_step
            && self.daemon.runtime().command_capacity_available()
        {
            if responses_started < self.serving.policy().maximum_responses_per_step
                && self.start_service_response(&mut notices)?
            {
                commands_started = commands_started.saturating_add(1);
                responses_started = responses_started.saturating_add(1);
                continue;
            }
            if announcements_started < self.serving.policy().maximum_announcements_per_step
                && self.start_inventory_announcement(&mut notices)?
            {
                commands_started = commands_started.saturating_add(1);
                announcements_started = announcements_started.saturating_add(1);
                continue;
            }
            if self.active_header.is_none() && self.start_header_request(now, &mut notices)? {
                commands_started = commands_started.saturating_add(1);
                continue;
            }
            if self.start_object_request(now, &mut notices)? {
                commands_started = commands_started.saturating_add(1);
                continue;
            }
            break;
        }
        Ok(DispatcherStep {
            daemon,
            events_processed,
            commands_started,
            notices,
        })
    }

    fn handle_event(
        &mut self,
        event: DaemonEvent,
        now: u64,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<(), S, D> {
        match event {
            DaemonEvent::FrameRejected { peer_id, .. } => {
                notices.push(DispatcherNotice::FrameRejected { peer_id });
            }
            DaemonEvent::SessionFailed { peer_id, .. } => {
                notices.push(DispatcherNotice::SessionFailed { peer_id });
                let outcome = self.disconnect_peer(peer_id)?;
                notices.push(self.disconnect_notice(&outcome)?);
            }
            DaemonEvent::SessionAction { peer_id, action } => match *action {
                SessionAction::Established { peer, .. } => {
                    if !self.peer_tips.contains_key(&peer_id) {
                        self.peers
                            .register_peer(peer_id)
                            .map_err(DispatcherError::MultiPeer)?;
                    }
                    self.header_exhausted.remove(&peer_id);
                    self.peer_tips.insert(peer_id, peer.clone());
                    notices.push(DispatcherNotice::PeerEstablished {
                        peer_id,
                        best_height: peer.best_height,
                        best_block_id: peer.best_block_id,
                    });
                }
                SessionAction::Deliver {
                    request_id: 0,
                    message: Message::Inventory(entries),
                } => {
                    let additions = self
                        .peers
                        .observe_inventory(peer_id, &entries)
                        .map_err(DispatcherError::MultiPeer)?;
                    let transaction_objects: Vec<_> = additions
                        .iter()
                        .copied()
                        .filter(|entry| match entry {
                            InventoryEntry::Transaction(transaction_id) => self
                                .mempool
                                .as_ref()
                                .is_none_or(|mempool| !mempool.contains(*transaction_id)),
                            InventoryEntry::Block(_) => false,
                        })
                        .collect();
                    if !transaction_objects.is_empty() {
                        self.peers
                            .schedule_objects(&transaction_objects)
                            .map_err(DispatcherError::MultiPeer)?;
                    }
                    notices.push(DispatcherNotice::InventoryObserved {
                        peer_id,
                        additions: u16::try_from(additions.len())
                            .map_err(|_| DispatcherError::CountWidth)?,
                    });
                }
                action @ SessionAction::HeadersResponse { .. } => {
                    self.handle_headers(peer_id, action, now, notices)?;
                }
                action @ SessionAction::Deliver {
                    message: Message::Block(_),
                    ..
                } => {
                    self.handle_block(peer_id, action, now, notices)?;
                }
                action @ SessionAction::Deliver {
                    message: Message::Transaction(_),
                    ..
                } => {
                    self.handle_transaction(peer_id, action, now, notices)?;
                }
                SessionAction::Deliver {
                    request_id,
                    message: Message::GetHeaders { locator, stop_id },
                } => {
                    self.pending_service
                        .push_back(InboundServiceRequest::Headers {
                            peer_id,
                            request_id,
                            locator,
                            stop_id,
                        });
                }
                SessionAction::Deliver {
                    request_id,
                    message: Message::GetObjects(objects),
                } => {
                    self.pending_service
                        .push_back(InboundServiceRequest::Objects {
                            peer_id,
                            request_id,
                            objects,
                        });
                }
                SessionAction::RequestRejected {
                    request_id,
                    rejected_type,
                    ..
                } => {
                    self.handle_terminal_request(
                        peer_id,
                        request_id,
                        Some(rejected_type),
                        RetryReason::Rejected,
                        now,
                        notices,
                    )?;
                }
                SessionAction::RequestTimedOut { request_id, kind } => {
                    let reason = RetryReason::Timeout;
                    match kind {
                        RequestKind::Headers => {
                            self.handle_terminal_request(
                                peer_id, request_id, None, reason, now, notices,
                            )?;
                        }
                        RequestKind::Object => {
                            self.handle_terminal_request(
                                peer_id, request_id, None, reason, now, notices,
                            )?;
                        }
                        RequestKind::Ping => {
                            notices.push(DispatcherNotice::SessionPolicyEvent { peer_id });
                        }
                    }
                }
                SessionAction::Disconnect { .. } => {
                    let outcome = self.disconnect_peer(peer_id)?;
                    notices.push(self.disconnect_notice(&outcome)?);
                }
                SessionAction::Deliver { .. }
                | SessionAction::IgnoredExtension { .. }
                | SessionAction::Misbehavior { .. }
                | SessionAction::Send { .. } => {
                    notices.push(DispatcherNotice::SessionPolicyEvent { peer_id });
                }
            },
        }
        Ok(())
    }

    fn start_service_response(
        &mut self,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<bool, S, D> {
        let Some(request) = self.pending_service.front().cloned() else {
            return Ok(false);
        };
        let (peer_id, request_id, reply) = match &request {
            InboundServiceRequest::Headers {
                peer_id,
                request_id,
                locator,
                stop_id,
            } => (
                *peer_id,
                *request_id,
                self.serving
                    .serve_headers(self.daemon.runtime().node().storage(), locator, *stop_id)
                    .map_err(DispatcherError::Serving)?,
            ),
            InboundServiceRequest::Objects {
                peer_id,
                request_id,
                objects,
            } => {
                let reply = match objects.as_slice() {
                    [InventoryEntry::Transaction(transaction_id)] => {
                        let transaction = self
                            .mempool
                            .as_ref()
                            .and_then(|mempool| mempool.transaction(*transaction_id));
                        self.serving.serve_transaction(*transaction_id, transaction)
                    }
                    _ => self
                        .serving
                        .serve_objects(self.daemon.runtime().node().storage(), objects)
                        .map_err(DispatcherError::Serving)?,
                };
                (*peer_id, *request_id, reply)
            }
        };
        let notice = match &reply {
            ServingReply::Headers { headers } => DispatcherNotice::HeadersServed {
                peer_id,
                request_id,
                count: u16::try_from(headers.len()).map_err(|_| DispatcherError::CountWidth)?,
            },
            ServingReply::Block { block_id, .. } => DispatcherNotice::BlockServed {
                peer_id,
                request_id,
                block_id: *block_id,
            },
            ServingReply::Transaction { transaction_id, .. } => {
                DispatcherNotice::TransactionServed {
                    peer_id,
                    request_id,
                    transaction_id: *transaction_id,
                }
            }
            ServingReply::Reject {
                rejected_type,
                code,
                ..
            } => DispatcherNotice::ServiceRejected {
                peer_id,
                request_id,
                rejected_type: *rejected_type,
                code: *code,
            },
        };
        self.daemon
            .runtime_mut()
            .execute_command(
                peer_id,
                RuntimeCommand::SendResponse {
                    request_id,
                    message: Box::new(reply.into_message()),
                },
            )
            .map_err(DispatcherError::Runtime)?;
        self.pending_service.pop_front();
        notices.push(notice);
        Ok(true)
    }

    fn start_inventory_announcement(
        &mut self,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<bool, S, D> {
        let Some(announcement) = self.pending_announcements.front().cloned() else {
            return Ok(false);
        };
        let count =
            u16::try_from(announcement.entries.len()).map_err(|_| DispatcherError::CountWidth)?;
        self.daemon
            .runtime_mut()
            .execute_command(
                announcement.peer_id,
                RuntimeCommand::AnnounceInventory {
                    entries: announcement.entries,
                },
            )
            .map_err(DispatcherError::Runtime)?;
        self.pending_announcements.pop_front();
        notices.push(DispatcherNotice::InventoryAnnounced {
            peer_id: announcement.peer_id,
            entries: count,
        });
        Ok(true)
    }

    fn disconnect_notice(
        &self,
        outcome: &PeerDisconnectOutcome,
    ) -> DispatcherResult<DispatcherNotice, S, D> {
        let (requeued_objects, detached_orphans) = match &outcome.scheduler {
            Some(cleanup) => (
                u16::try_from(cleanup.requeued_objects.len())
                    .map_err(|_| DispatcherError::CountWidth)?,
                u16::try_from(cleanup.detached_orphans.len())
                    .map_err(|_| DispatcherError::CountWidth)?,
            ),
            None => (0, 0),
        };
        Ok(DispatcherNotice::PeerDisconnected {
            peer_id: outcome.peer_id,
            requeued_objects,
            detached_orphans,
        })
    }

    fn start_header_request(
        &mut self,
        now: u64,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<bool, S, D> {
        let sync_tip = self
            .sync
            .as_ref()
            .ok_or(DispatcherError::SyncUnavailable)?
            .sync_tip();
        let sync_height = self
            .sync
            .as_ref()
            .ok_or(DispatcherError::SyncUnavailable)?
            .sync_tip_height(self.daemon.runtime().node().storage())
            .map_err(DispatcherError::Locator)?;
        let mut selected: Option<(PeerId, u64, BlockId)> = None;
        for (peer_id, tip) in &self.peer_tips {
            if tip.best_block_id == sync_tip
                || tip.best_height < sync_height
                || self.header_exhausted.contains(peer_id)
            {
                continue;
            }
            if selected
                .as_ref()
                .is_none_or(|(_, height, _)| tip.best_height > *height)
            {
                selected = Some((*peer_id, tip.best_height, tip.best_block_id));
            }
        }
        let Some((peer_id, _, stop_id)) = selected else {
            return Ok(false);
        };
        let locator = self
            .sync
            .as_ref()
            .ok_or(DispatcherError::SyncUnavailable)?
            .build_locator(self.daemon.runtime().node().storage())
            .map_err(DispatcherError::Locator)?;
        let outcome = self
            .daemon
            .runtime_mut()
            .execute_command(
                peer_id,
                RuntimeCommand::BeginHeaders {
                    now,
                    locator,
                    stop_id,
                },
            )
            .map_err(DispatcherError::Runtime)?;
        let request_id = outcome
            .request_id
            .ok_or(DispatcherError::UnexpectedSessionAction)?;
        self.active_header = Some(HeaderRequest {
            peer_id,
            request_id,
            stop_id,
        });
        notices.push(DispatcherNotice::HeaderRequestStarted {
            peer_id,
            request_id,
            stop_id,
        });
        Ok(true)
    }

    fn handle_headers(
        &mut self,
        peer_id: PeerId,
        action: SessionAction,
        now: u64,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<(), S, D> {
        let SessionAction::HeadersResponse {
            request_id,
            headers,
        } = action
        else {
            return Err(DispatcherError::UnexpectedSessionAction);
        };
        let Some(active) = self.active_header else {
            return Err(DispatcherError::HeaderResponseWithoutRequest {
                peer_id,
                request_id,
            });
        };
        if active.peer_id != peer_id || active.request_id != request_id {
            return Err(DispatcherError::HeaderResponseMismatch {
                expected_peer: active.peer_id,
                expected_request: active.request_id,
                actual_peer: peer_id,
                actual_request: request_id,
            });
        }
        self.active_header = None;
        if headers.is_empty() {
            let reached_stop = self
                .sync
                .as_ref()
                .ok_or(DispatcherError::SyncUnavailable)?
                .sync_tip()
                == active.stop_id;
            if !reached_stop {
                self.header_exhausted.insert(peer_id);
            }
            notices.push(DispatcherNotice::HeaderSyncComplete {
                peer_id,
                reached_stop,
            });
            return Ok(());
        }
        let outcome = self
            .sync
            .as_mut()
            .ok_or(DispatcherError::SyncUnavailable)?
            .accept_header_batch(
                self.daemon.runtime().node().storage(),
                out_p2p::session::HeaderBatch::Validate(headers),
                now,
            );
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if matches!(error, HeaderBatchFailure::Invalid(_)) {
                    self.header_exhausted.insert(peer_id);
                    self.daemon
                        .runtime_mut()
                        .execute_command(peer_id, RuntimeCommand::ReportInvalidHeaders)
                        .map_err(DispatcherError::Runtime)?;
                }
                return Err(DispatcherError::HeaderBatch(Box::new(error)));
            }
        };
        let HeaderBatchOutcome::Accepted {
            tip,
            validated,
            scheduled,
        } = outcome
        else {
            return Err(DispatcherError::UnexpectedSessionAction);
        };
        let objects: Vec<InventoryEntry> = scheduled
            .iter()
            .copied()
            .map(InventoryEntry::Block)
            .collect();
        self.peers
            .schedule_objects(&objects)
            .map_err(DispatcherError::MultiPeer)?;
        let reached_stop = tip.block_id == active.stop_id;
        notices.push(DispatcherNotice::HeadersAccepted {
            peer_id,
            validated: u16::try_from(validated.len()).map_err(|_| DispatcherError::CountWidth)?,
            scheduled: u16::try_from(scheduled.len()).map_err(|_| DispatcherError::CountWidth)?,
            reached_stop,
        });
        Ok(())
    }

    fn start_object_request(
        &mut self,
        now: u64,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<bool, S, D> {
        let Some(assignment) = self
            .peers
            .next_assignment(now)
            .map_err(DispatcherError::MultiPeer)?
        else {
            return Ok(false);
        };
        if let InventoryEntry::Block(block_id) = assignment.object {
            if let Err(error) = self
                .sync
                .as_mut()
                .ok_or(DispatcherError::SyncUnavailable)?
                .begin_block_request(block_id)
            {
                self.peers
                    .cancel_request(assignment)
                    .map_err(DispatcherError::MultiPeer)?;
                return Err(DispatcherError::BeginBlock(error));
            }
        }
        let result = self.daemon.runtime_mut().execute_command(
            assignment.peer_id,
            RuntimeCommand::BeginObject {
                now,
                request_id: assignment.request_id,
                object: assignment.object,
            },
        );
        if let Err(error) = result {
            if let InventoryEntry::Block(block_id) = assignment.object {
                self.sync
                    .as_mut()
                    .ok_or(DispatcherError::SyncUnavailable)?
                    .retry_block(block_id)
                    .map_err(DispatcherError::RetryBlock)?;
            }
            self.peers
                .cancel_request(assignment)
                .map_err(DispatcherError::MultiPeer)?;
            return Err(DispatcherError::Runtime(error));
        }
        notices.push(DispatcherNotice::ObjectRequested(assignment));
        Ok(true)
    }

    fn handle_terminal_request(
        &mut self,
        peer_id: PeerId,
        request_id: u64,
        rejected_type: Option<u16>,
        reason: RetryReason,
        now: u64,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<(), S, D> {
        if self
            .active_header
            .is_some_and(|active| active.peer_id == peer_id && active.request_id == request_id)
        {
            self.active_header = None;
            self.header_exhausted.insert(peer_id);
            notices.push(DispatcherNotice::HeaderSyncComplete {
                peer_id,
                reached_stop: false,
            });
            return Ok(());
        }
        if rejected_type.is_some_and(|kind| kind != TYPE_GET_OBJECTS) {
            return Err(DispatcherError::UnknownObjectRequest(request_id));
        }
        let assignment = self
            .peers
            .assignment(request_id)
            .ok_or(DispatcherError::UnknownObjectRequest(request_id))?;
        if assignment.peer_id != peer_id {
            return Err(DispatcherError::ObjectPeerMismatch {
                expected: assignment.peer_id,
                actual: peer_id,
            });
        }
        if let InventoryEntry::Block(block_id) = assignment.object {
            self.sync
                .as_mut()
                .ok_or(DispatcherError::SyncUnavailable)?
                .retry_block(block_id)
                .map_err(DispatcherError::RetryBlock)?;
        }
        let outcome = self
            .peers
            .retry_request(assignment, now, reason)
            .map_err(DispatcherError::MultiPeer)?;
        notices.push(DispatcherNotice::ObjectRetried {
            request_id,
            outcome,
        });
        Ok(())
    }

    fn handle_transaction(
        &mut self,
        peer_id: PeerId,
        action: SessionAction,
        now: u64,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<(), S, D> {
        let SessionAction::Deliver {
            request_id,
            message: Message::Transaction(transaction),
        } = action
        else {
            return Err(DispatcherError::UnexpectedSessionAction);
        };
        let assignment = self
            .peers
            .assignment(request_id)
            .ok_or(DispatcherError::UnknownObjectRequest(request_id))?;
        if assignment.peer_id != peer_id {
            return Err(DispatcherError::ObjectPeerMismatch {
                expected: assignment.peer_id,
                actual: peer_id,
            });
        }
        let InventoryEntry::Transaction(expected_id) = assignment.object else {
            return Err(DispatcherError::NonTransactionAssignment(assignment.object));
        };
        let canonical_bytes = transaction
            .encode()
            .map_err(|error| DispatcherError::Mempool(MempoolError::CanonicalEncoding(error)))?;
        let actual_id = transaction_id_from_canonical_bytes(&canonical_bytes);
        if actual_id != expected_id {
            let outcome = self
                .peers
                .retry_request(assignment, now, RetryReason::InvalidResponse)
                .map_err(DispatcherError::MultiPeer)?;
            notices.push(DispatcherNotice::ObjectRetried {
                request_id,
                outcome,
            });
            return Err(DispatcherError::TransactionIdMismatch {
                expected: expected_id,
                actual: actual_id,
            });
        }
        let admission = self
            .mempool
            .as_mut()
            .ok_or(DispatcherError::MempoolUnavailable)?
            .admit(self.daemon.runtime().node().storage(), transaction);
        match admission {
            Ok(MempoolAdmission::Accepted { transaction_id, .. }) => {
                self.peers
                    .complete_request(assignment)
                    .map_err(DispatcherError::MultiPeer)?;
                notices.push(DispatcherNotice::TransactionAccepted {
                    peer_id,
                    transaction_id,
                });
                Ok(())
            }
            Ok(
                MempoolAdmission::AlreadyPresent { transaction_id }
                | MempoolAdmission::AlreadyConfirmed { transaction_id },
            ) => {
                self.peers
                    .complete_request(assignment)
                    .map_err(DispatcherError::MultiPeer)?;
                notices.push(DispatcherNotice::TransactionAlreadyKnown {
                    peer_id,
                    transaction_id,
                });
                Ok(())
            }
            Err(MempoolError::Invalid(_)) | Err(MempoolError::RewardTransaction) => {
                self.peers
                    .complete_request(assignment)
                    .map_err(DispatcherError::MultiPeer)?;
                self.daemon
                    .runtime_mut()
                    .execute_command(peer_id, RuntimeCommand::ReportInvalidTransaction)
                    .map_err(DispatcherError::Runtime)?;
                notices.push(DispatcherNotice::TransactionRejected {
                    peer_id,
                    transaction_id: expected_id,
                });
                Ok(())
            }
            Err(
                MempoolError::TransactionCapacity { .. }
                | MempoolError::SenderCapacity { .. }
                | MempoolError::ByteCapacity { .. },
            ) => {
                self.peers
                    .complete_request(assignment)
                    .map_err(DispatcherError::MultiPeer)?;
                notices.push(DispatcherNotice::TransactionPolicyDropped {
                    peer_id,
                    transaction_id: expected_id,
                });
                Ok(())
            }
            Err(error) => Err(DispatcherError::Mempool(error)),
        }
    }

    fn handle_block(
        &mut self,
        peer_id: PeerId,
        action: SessionAction,
        now: u64,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<(), S, D> {
        let SessionAction::Deliver {
            request_id,
            message: Message::Block(block),
        } = action
        else {
            return Err(DispatcherError::UnexpectedSessionAction);
        };
        let assignment = self
            .peers
            .assignment(request_id)
            .ok_or(DispatcherError::UnknownObjectRequest(request_id))?;
        if assignment.peer_id != peer_id {
            return Err(DispatcherError::ObjectPeerMismatch {
                expected: assignment.peer_id,
                actual: peer_id,
            });
        }
        let InventoryEntry::Block(expected_id) = assignment.object else {
            return Err(DispatcherError::NonBlockAssignment(assignment.object));
        };
        let actual_id = block_id_from_header_bytes(&block.header.encode());
        if actual_id != expected_id {
            self.sync
                .as_mut()
                .ok_or(DispatcherError::SyncUnavailable)?
                .retry_block(expected_id)
                .map_err(DispatcherError::RetryBlock)?;
            let outcome = self
                .peers
                .retry_request(assignment, now, RetryReason::InvalidResponse)
                .map_err(DispatcherError::MultiPeer)?;
            notices.push(DispatcherNotice::ObjectRetried {
                request_id,
                outcome,
            });
            return Err(DispatcherError::ObjectIdMismatch {
                expected: expected_id,
                actual: actual_id,
            });
        }
        let delivery_action = SessionAction::Deliver {
            request_id,
            message: Message::Block(block.clone()),
        };
        let sync = self.sync.as_mut().ok_or(DispatcherError::SyncUnavailable)?;
        let delivery = self
            .daemon
            .runtime_mut()
            .node_mut()
            .deliver_scheduled_block(sync, delivery_action, now);
        match delivery {
            Ok(outcome) => {
                let newly_processed = matches!(&outcome, BlockDeliveryOutcome::Processed { .. });
                self.peers
                    .complete_request(assignment)
                    .map_err(DispatcherError::MultiPeer)?;
                let stored_id = delivery_block_id(&outcome);
                notices.push(DispatcherNotice::ObjectStored {
                    peer_id,
                    block_id: stored_id,
                });
                if newly_processed {
                    self.record_relay_admission(block, notices)?;
                }
                self.reconcile_mempool(notices)?;
                self.replay_orphan_descendants(stored_id, now, notices)?;
                Ok(())
            }
            Err(failure) if missing_parent(&failure) => {
                let parent_block_id = block.header.parent_block_id;
                let admission = self
                    .peers
                    .admit_orphan(peer_id, block, now)
                    .map_err(DispatcherError::MultiPeer)?;
                if !matches!(
                    admission,
                    OrphanAdmission::Stored { block_id } | OrphanAdmission::AlreadyStored { block_id }
                        if block_id == actual_id
                ) {
                    return Err(DispatcherError::ObjectIdMismatch {
                        expected: actual_id,
                        actual: actual_id,
                    });
                }
                self.peers
                    .complete_request(assignment)
                    .map_err(DispatcherError::MultiPeer)?;
                notices.push(DispatcherNotice::OrphanStored {
                    peer_id,
                    block_id: actual_id,
                    parent_block_id,
                });
                Ok(())
            }
            Err(failure @ BlockDeliveryFailure::PeerInvalid { .. }) => {
                let outcome = self
                    .peers
                    .retry_request(assignment, now, RetryReason::InvalidResponse)
                    .map_err(DispatcherError::MultiPeer)?;
                notices.push(DispatcherNotice::ObjectRetried {
                    request_id,
                    outcome,
                });
                Err(DispatcherError::BlockDelivery(Box::new(failure)))
            }
            Err(failure @ BlockDeliveryFailure::TemporarilyUnacceptable { .. }) => {
                self.peers
                    .cancel_request(assignment)
                    .map_err(DispatcherError::MultiPeer)?;
                Err(DispatcherError::BlockDelivery(Box::new(failure)))
            }
            Err(failure) => Err(DispatcherError::BlockDelivery(Box::new(failure))),
        }
    }

    fn replay_orphan_descendants(
        &mut self,
        parent: BlockId,
        now: u64,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<(), S, D> {
        let mut queue: VecDeque<OrphanBlock> = self
            .peers
            .take_orphan_children(parent)
            .map_err(DispatcherError::MultiPeer)?
            .into();
        while let Some(orphan) = queue.pop_front() {
            self.sync
                .as_mut()
                .ok_or(DispatcherError::SyncUnavailable)?
                .begin_block_request(orphan.block_id)
                .map_err(DispatcherError::BeginBlock)?;
            let block = Block::decode_non_genesis_exact(&orphan.canonical_bytes)
                .map_err(DispatcherError::OrphanDecode)?;
            let relay_block = block.clone();
            let request_id = self.next_orphan_replay_request_id;
            self.next_orphan_replay_request_id = request_id
                .checked_add(1)
                .filter(|next| *next != 0)
                .ok_or(DispatcherError::ReplayRequestIdExhausted)?;
            let sync = self.sync.as_mut().ok_or(DispatcherError::SyncUnavailable)?;
            let outcome = self
                .daemon
                .runtime_mut()
                .node_mut()
                .deliver_scheduled_block(
                    sync,
                    SessionAction::Deliver {
                        request_id,
                        message: Message::Block(block),
                    },
                    now,
                )
                .map_err(|error| DispatcherError::BlockDelivery(Box::new(error)))?;
            let block_id = delivery_block_id(&outcome);
            if matches!(&outcome, BlockDeliveryOutcome::Processed { .. }) {
                self.record_relay_admission(relay_block, notices)?;
            }
            self.reconcile_mempool(notices)?;
            notices.push(DispatcherNotice::OrphanReplayed { block_id });
            let children = self
                .peers
                .take_orphan_children(block_id)
                .map_err(DispatcherError::MultiPeer)?;
            queue.extend(children);
        }
        Ok(())
    }

    fn reconcile_mempool(
        &mut self,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<(), S, D> {
        let Some(mempool) = self.mempool.as_mut() else {
            return Err(DispatcherError::MempoolUnavailable);
        };
        if let Some(outcome) = mempool
            .reconcile_if_needed(self.daemon.runtime().node().storage())
            .map_err(DispatcherError::Mempool)?
        {
            notices.push(DispatcherNotice::MempoolReconciled {
                retained: outcome.retained,
                removed: u16::try_from(outcome.removed.len())
                    .map_err(|_| DispatcherError::CountWidth)?,
            });
        }
        Ok(())
    }

    fn record_relay_admission(
        &mut self,
        block: Block,
        notices: &mut Vec<DispatcherNotice>,
    ) -> DispatcherResult<bool, S, D> {
        let cached = match self.serving.admit_validated(block) {
            RelayAdmission::Stored { block_id, evicted } => {
                notices.push(DispatcherNotice::RelayCached {
                    block_id,
                    evicted: u16::try_from(evicted.len())
                        .map_err(|_| DispatcherError::CountWidth)?,
                });
                true
            }
            RelayAdmission::AlreadyStored { block_id } => {
                notices.push(DispatcherNotice::RelayCached {
                    block_id,
                    evicted: 0,
                });
                true
            }
            RelayAdmission::SkippedGenesis { block_id }
            | RelayAdmission::SkippedOversize { block_id, .. }
            | RelayAdmission::ConflictingBody { block_id }
            | RelayAdmission::EncodingFailed { block_id, .. }
            | RelayAdmission::AccountingFailed { block_id } => {
                notices.push(DispatcherNotice::RelayNotCached { block_id });
                false
            }
        };
        Ok(cached)
    }
}

fn delivery_block_id(outcome: &BlockDeliveryOutcome) -> BlockId {
    match outcome {
        BlockDeliveryOutcome::Processed { outcome, .. } => outcome.stored.block_id,
        BlockDeliveryOutcome::AlreadyStored { block_id, .. } => *block_id,
    }
}

fn missing_parent<ReadError, MutationError>(
    failure: &BlockDeliveryFailure<ReadError, MutationError>,
) -> bool {
    matches!(
        failure,
        BlockDeliveryFailure::Local { error, .. }
            if matches!(
                error.as_ref(),
                BlockDeliveryLocal::Consensus(BlockLocalFailure::Header(
                    ChildHeaderLocalFailure::MissingParent(_)
                ))
            )
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use out_codec::MAX_REWARD_EXTRA_BYTES;
    use out_p2p::session::{PeerSession, SessionPolicy, SessionRole};
    use out_p2p::{decode_frame_exact, encode_frame, P2pNetwork, PROTOCOL_VERSION_V0};
    use out_storage::conformance::validated_reward_commit;
    use out_storage::redb_backend::RedbConsensusStore;
    use out_storage::{FaultPoint, InMemoryConsensusStore, RecoveryOutcome};

    use super::*;
    use crate::bootstrap::NodeBootstrap;
    use crate::driver::{
        BoundedMemoryDriver, DaemonPolicy, MemoryDriverPhase, MemoryDriverPolicy, TransportFrame,
    };
    use crate::peers::MemoryTransportPolicy;
    use crate::runtime::{NodeRuntime, RuntimePolicy};
    use crate::{Node, SupportedNetwork};

    type TestDispatcher = ApplicationDispatcher<InMemoryConsensusStore, BoundedMemoryDriver>;

    fn peer(value: u64) -> PeerId {
        PeerId::new(value).expect("peer")
    }

    fn node() -> Node<InMemoryConsensusStore> {
        NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        }
        .create_in_memory()
        .expect("node")
    }

    fn node_hello<S: ConsensusStorage>(node: &Node<S>) -> Hello {
        let tip = node
            .canonical_tip()
            .unwrap_or_else(|_| panic!("canonical tip"));
        let identity = node.config().network.identity();
        Hello {
            min_protocol_version: 0,
            max_protocol_version: 0,
            min_consensus_version: 0,
            max_consensus_version: 0,
            chain_id: identity.chain_id,
            network_id: identity.network_id,
            genesis_commitment: identity.genesis_commitment,
            best_height: tip.height,
            best_block_id: tip.block_id,
        }
    }

    fn source_chain(count: u8) -> (Node<InMemoryConsensusStore>, Vec<Block>) {
        let mut source = node();
        let mut parent = source.canonical_tip().unwrap().block_id;
        let mut blocks = Vec::new();
        for index in 0..count {
            let commit = validated_reward_commit(source.storage(), parent, &[index]);
            let raw = commit.canonical_block_bytes().to_vec();
            let block = Block::decode_non_genesis_exact(&raw).unwrap();
            source.process_block(&raw, block.header.timestamp).unwrap();
            parent = block_id_from_header_bytes(&block.header.encode());
            blocks.push(block);
        }
        (source, blocks)
    }

    fn session_policy() -> SessionPolicy {
        SessionPolicy {
            handshake_timeout_ticks: 20,
            response_timeout_ticks: 20,
            maximum_outstanding_requests: 16,
            disconnect_score: 100,
            protocol_violation_score: 20,
            unexpected_response_score: 10,
            timeout_score: 5,
        }
    }

    fn dispatcher() -> TestDispatcher {
        dispatcher_for_node(node(), 16)
    }

    fn dispatcher_for_node(
        target: Node<InMemoryConsensusStore>,
        outbound_frames: u16,
    ) -> TestDispatcher {
        dispatcher_for_storage(target, outbound_frames)
    }

    fn dispatcher_for_storage<S>(
        target: Node<S>,
        outbound_frames: u16,
    ) -> ApplicationDispatcher<S, BoundedMemoryDriver>
    where
        S: RecoverableConsensusStorage,
    {
        let runtime = NodeRuntime::new(
            target,
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
        .unwrap_or_else(|_| panic!("runtime"));
        let queue = MemoryTransportPolicy {
            maximum_queued_frames: 16,
            maximum_queued_bytes: 4_000_000,
            maximum_frame_bytes: 1_000_000,
        };
        let driver = BoundedMemoryDriver::new(MemoryDriverPolicy {
            inbound: queue,
            outbound: MemoryTransportPolicy {
                maximum_queued_frames: outbound_frames,
                ..queue
            },
        })
        .unwrap();
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
        .unwrap_or_else(|_| panic!("daemon"));
        ApplicationDispatcher::new(
            daemon,
            SyncPolicy {
                maximum_overlay_headers: 16,
                maximum_blocks_per_request: 8,
                maximum_locator_entries: 8,
                linear_locator_entries: 2,
                maximum_locator_walk: 100,
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
                maximum_ancestry_records: 128,
                maximum_relay_blocks: 16,
                maximum_relay_bytes: 4_000_000,
            },
            MempoolPolicy {
                maximum_transactions: 32,
                maximum_total_bytes: 1_000_000,
                maximum_transactions_per_sender: 16,
                maximum_template_transactions: 16,
                maximum_template_bytes: 500_000,
            },
            CpuMiningPolicy {
                maximum_nonce_attempts: 4_096,
            },
        )
        .unwrap_or_else(|_| panic!("dispatcher"))
    }

    fn temporary_redb_path(label: &str) -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "out-dispatcher-{label}-{}-{sequence}.redb",
            std::process::id()
        ))
    }

    fn inject_action(dispatcher: &mut TestDispatcher, peer_id: PeerId, action: SessionAction) {
        let SessionAction::Send {
            request_id,
            message,
        } = action
        else {
            panic!("send action");
        };
        let bytes = encode_frame(P2pNetwork::Devnet, request_id, &message).unwrap();
        dispatcher
            .daemon_mut()
            .driver_mut()
            .inject_inbound(TransportFrame { peer_id, bytes })
            .unwrap();
    }

    fn take_outbound(dispatcher: &mut TestDispatcher) -> TransportFrame {
        dispatcher
            .daemon_mut()
            .driver_mut()
            .take_outbound()
            .unwrap()
            .expect("outbound frame")
    }

    fn establish_peers(
        dispatcher: &mut TestDispatcher,
        sources: &[(PeerId, &Node<InMemoryConsensusStore>)],
        now: u64,
    ) -> BTreeMap<PeerId, PeerSession> {
        let target_hello = node_hello(dispatcher.daemon().runtime().node());
        let mut remotes = BTreeMap::new();
        for (peer_id, source) in sources {
            let (target_session, initial) = PeerSession::new(
                SessionRole::Outbound,
                P2pNetwork::Devnet,
                target_hello.clone(),
                now,
                session_policy(),
            )
            .unwrap();
            dispatcher
                .register_peer(*peer_id, target_session, initial)
                .unwrap();
            let (remote, initial) = PeerSession::new(
                SessionRole::Inbound,
                P2pNetwork::Devnet,
                node_hello(source),
                now,
                session_policy(),
            )
            .unwrap();
            assert!(initial.is_empty());
            remotes.insert(*peer_id, remote);
        }
        dispatcher.step(now).unwrap();
        for _ in sources {
            let carried = take_outbound(dispatcher);
            let frame = decode_frame_exact(&carried.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0)
                .unwrap();
            let actions = remotes
                .get_mut(&carried.peer_id)
                .unwrap()
                .handle_inbound(now, frame)
                .unwrap();
            let acknowledgement = actions
                .into_iter()
                .find(|action| matches!(action, SessionAction::Send { .. }))
                .unwrap();
            inject_action(dispatcher, carried.peer_id, acknowledgement);
        }
        dispatcher.step(now).unwrap();
        remotes
    }

    fn synchronize_headers_and_inventory(
        dispatcher: &mut TestDispatcher,
        remotes: &mut BTreeMap<PeerId, PeerSession>,
        header_peer: PeerId,
        inventory_peers: &[PeerId],
        blocks: &[Block],
        now: u64,
    ) {
        dispatcher.step(now).unwrap();
        let carried = take_outbound(dispatcher);
        assert_eq!(carried.peer_id, header_peer);
        let frame =
            decode_frame_exact(&carried.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0).unwrap();
        let request_id = frame.header.request_id;
        assert!(matches!(frame.message, Message::GetHeaders { .. }));
        let actions = remotes
            .get_mut(&header_peer)
            .unwrap()
            .handle_inbound(now, frame)
            .unwrap();
        assert!(matches!(
            actions.as_slice(),
            [SessionAction::Deliver {
                message: Message::GetHeaders { .. },
                ..
            }]
        ));
        let headers = blocks.iter().map(|block| block.header).collect();
        let response = remotes
            .get(&header_peer)
            .unwrap()
            .make_response(request_id, Message::Headers(headers))
            .unwrap();
        inject_action(dispatcher, header_peer, response);
        let entries: Vec<_> = blocks
            .iter()
            .map(|block| InventoryEntry::Block(block_id_from_header_bytes(&block.header.encode())))
            .collect();
        for peer_id in inventory_peers {
            let bytes =
                encode_frame(P2pNetwork::Devnet, 0, &Message::Inventory(entries.clone())).unwrap();
            dispatcher
                .daemon_mut()
                .driver_mut()
                .inject_inbound(TransportFrame {
                    peer_id: *peer_id,
                    bytes,
                })
                .unwrap();
        }
        dispatcher.step(now).unwrap();
    }

    fn take_object_requests(
        dispatcher: &mut TestDispatcher,
        remotes: &mut BTreeMap<PeerId, PeerSession>,
        now: u64,
    ) -> Vec<(PeerId, u64, InventoryEntry)> {
        dispatcher.step(now).unwrap();
        let mut requests = Vec::new();
        while let Some(carried) = dispatcher
            .daemon_mut()
            .driver_mut()
            .take_outbound()
            .unwrap()
        {
            let frame = decode_frame_exact(&carried.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0)
                .unwrap();
            let Message::GetObjects(objects) = frame.message.clone() else {
                panic!("object request");
            };
            assert_eq!(objects.len(), 1);
            let actions = remotes
                .get_mut(&carried.peer_id)
                .unwrap()
                .handle_inbound(now, frame)
                .unwrap();
            assert!(matches!(
                actions.as_slice(),
                [SessionAction::Deliver {
                    message: Message::GetObjects(_),
                    ..
                }]
            ));
            requests.push((carried.peer_id, actions_request_id(&actions), objects[0]));
        }
        requests
    }

    fn actions_request_id(actions: &[SessionAction]) -> u64 {
        match actions {
            [SessionAction::Deliver { request_id, .. }] => *request_id,
            _ => panic!("one delivered request"),
        }
    }

    #[test]
    fn child_first_delivery_is_retained_then_replayed_to_convergence() {
        let (source, blocks) = source_chain(2);
        let source_tip = source.canonical_tip().unwrap();
        let now = blocks.last().unwrap().header.timestamp;
        let mut dispatcher = dispatcher();
        dispatcher.start().unwrap();
        let mut remotes = establish_peers(&mut dispatcher, &[(peer(1), &source)], now);
        synchronize_headers_and_inventory(
            &mut dispatcher,
            &mut remotes,
            peer(1),
            &[peer(1)],
            &blocks,
            now,
        );
        let requests = take_object_requests(&mut dispatcher, &mut remotes, now);
        assert_eq!(requests.len(), 2);
        let mut responses = Vec::new();
        for (peer_id, request_id, object) in requests {
            let InventoryEntry::Block(block_id) = object else {
                panic!("block request");
            };
            let block = blocks
                .iter()
                .find(|block| block_id_from_header_bytes(&block.header.encode()) == block_id)
                .unwrap()
                .clone();
            let response = remotes
                .get(&peer_id)
                .unwrap()
                .make_response(request_id, Message::Block(block.clone()))
                .unwrap();
            responses.push((block.header.height, peer_id, response));
        }
        responses.sort_by_key(|(height, _, _)| std::cmp::Reverse(*height));
        for (_, peer_id, response) in responses {
            inject_action(&mut dispatcher, peer_id, response);
        }
        let step = dispatcher.step(now).unwrap();
        assert!(step
            .notices
            .iter()
            .any(|notice| matches!(notice, DispatcherNotice::OrphanStored { .. })));
        assert!(step
            .notices
            .iter()
            .any(|notice| matches!(notice, DispatcherNotice::OrphanReplayed { .. })));
        assert_eq!(
            dispatcher
                .daemon()
                .runtime()
                .node()
                .canonical_tip()
                .unwrap(),
            source_tip
        );
        assert_eq!(dispatcher.peers().orphan_count(), 0);
        assert_eq!(dispatcher.serving().relay().block_count(), 2);
    }

    #[test]
    fn correlated_reject_fails_over_to_second_peer_and_converges() {
        let (source, blocks) = source_chain(1);
        let source_tip = source.canonical_tip().unwrap();
        let now = blocks.last().unwrap().header.timestamp;
        let mut dispatcher = dispatcher();
        dispatcher.start().unwrap();
        let mut remotes = establish_peers(
            &mut dispatcher,
            &[(peer(1), &source), (peer(2), &source)],
            now,
        );
        synchronize_headers_and_inventory(
            &mut dispatcher,
            &mut remotes,
            peer(1),
            &[peer(1), peer(2)],
            &blocks,
            now,
        );
        let first = take_object_requests(&mut dispatcher, &mut remotes, now);
        assert_eq!(first.len(), 1);
        let (first_peer, request_id, _) = first[0];
        assert_eq!(first_peer, peer(1));
        let reject = remotes
            .get(&first_peer)
            .unwrap()
            .make_response(
                request_id,
                Message::Reject {
                    rejected_type: TYPE_GET_OBJECTS,
                    code: 1,
                    detail: b"withheld".to_vec(),
                },
            )
            .unwrap();
        inject_action(&mut dispatcher, first_peer, reject);
        let retry = dispatcher.step(now).unwrap();
        assert!(retry.notices.iter().any(|notice| matches!(
            notice,
            DispatcherNotice::ObjectRetried {
                outcome: RetryOutcome::Retrying { failed_peer, .. },
                ..
            } if *failed_peer == peer(1)
        )));
        let second = take_object_requests(&mut dispatcher, &mut remotes, now.saturating_add(1));
        assert_eq!(second.len(), 1);
        let (second_peer, second_request_id, _) = second[0];
        assert_eq!(second_peer, peer(2));
        let response = remotes
            .get(&second_peer)
            .unwrap()
            .make_response(second_request_id, Message::Block(blocks[0].clone()))
            .unwrap();
        inject_action(&mut dispatcher, second_peer, response);
        dispatcher.step(now.saturating_add(1)).unwrap();
        assert_eq!(
            dispatcher
                .daemon()
                .runtime()
                .node()
                .canonical_tip()
                .unwrap(),
            source_tip
        );
    }

    #[test]
    fn explicit_disconnect_requeues_in_flight_block_and_allows_peer_id_reuse() {
        let (source, blocks) = source_chain(1);
        let source_tip = source.canonical_tip().unwrap();
        let now = blocks[0].header.timestamp;
        let mut dispatcher = dispatcher();
        dispatcher.start().unwrap();
        let mut remotes = establish_peers(
            &mut dispatcher,
            &[(peer(1), &source), (peer(2), &source)],
            now,
        );
        synchronize_headers_and_inventory(
            &mut dispatcher,
            &mut remotes,
            peer(1),
            &[peer(1), peer(2)],
            &blocks,
            now,
        );
        let first = take_object_requests(&mut dispatcher, &mut remotes, now);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, peer(1));

        let cleanup = dispatcher.disconnect_peer(peer(1)).expect("disconnect");
        let scheduler = cleanup.scheduler.expect("established scheduler peer");
        assert_eq!(scheduler.requeued_objects, vec![first[0].2]);
        assert!(scheduler.detached_orphans.is_empty());
        assert_eq!(dispatcher.daemon().runtime().peer_count(), 1);
        assert_eq!(dispatcher.peers().peer_count(), 1);

        dispatcher.step(now).unwrap();
        let second = take_object_requests(&mut dispatcher, &mut remotes, now);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].0, peer(2));
        assert_eq!(second[0].2, first[0].2);
        let response = remotes
            .get(&peer(2))
            .unwrap()
            .make_response(second[0].1, Message::Block(blocks[0].clone()))
            .unwrap();
        inject_action(&mut dispatcher, peer(2), response);
        dispatcher.step(now).unwrap();
        assert_eq!(
            dispatcher
                .daemon()
                .runtime()
                .node()
                .canonical_tip()
                .unwrap(),
            source_tip
        );

        let hello = node_hello(dispatcher.daemon().runtime().node());
        let (replacement, initial) = PeerSession::new(
            SessionRole::Outbound,
            P2pNetwork::Devnet,
            hello,
            now,
            session_policy(),
        )
        .unwrap();
        dispatcher
            .register_peer(peer(1), replacement, initial)
            .expect("peer ID may be reused only after complete cleanup");
        assert_eq!(dispatcher.daemon().runtime().peer_count(), 2);
    }

    #[test]
    fn session_disconnect_cleans_handshake_peer_without_scheduler_registration() {
        let mut dispatcher = dispatcher();
        dispatcher.start().unwrap();
        let hello = node_hello(dispatcher.daemon().runtime().node());
        let (session, initial) = PeerSession::new(
            SessionRole::Outbound,
            P2pNetwork::Devnet,
            hello.clone(),
            0,
            session_policy(),
        )
        .unwrap();
        dispatcher.register_peer(peer(9), session, initial).unwrap();
        dispatcher.step(0).unwrap();
        take_outbound(&mut dispatcher);

        let mut wrong = hello;
        let mut wrong_chain_id = wrong.chain_id.into_bytes();
        wrong_chain_id[0] ^= 1;
        wrong.chain_id = out_primitives::ChainId::new(wrong_chain_id);
        let bytes = encode_frame(P2pNetwork::Devnet, 0, &Message::HelloAck(wrong)).unwrap();
        dispatcher
            .daemon_mut()
            .driver_mut()
            .inject_inbound(TransportFrame {
                peer_id: peer(9),
                bytes,
            })
            .unwrap();
        let step = dispatcher.step(0).unwrap();
        assert!(step.notices.iter().any(|notice| matches!(
            notice,
            DispatcherNotice::PeerDisconnected {
                peer_id,
                requeued_objects: 0,
                detached_orphans: 0,
            } if *peer_id == peer(9)
        )));
        assert_eq!(dispatcher.daemon().runtime().peer_count(), 0);
        assert_eq!(dispatcher.peers().peer_count(), 0);
    }

    #[test]
    fn disconnected_orphan_source_is_detached_and_child_still_replays() {
        let (source, blocks) = source_chain(2);
        let source_tip = source.canonical_tip().unwrap();
        let now = blocks[1].header.timestamp;
        let mut dispatcher = dispatcher();
        dispatcher.start().unwrap();
        let mut remotes = establish_peers(
            &mut dispatcher,
            &[(peer(1), &source), (peer(2), &source)],
            now,
        );
        synchronize_headers_and_inventory(
            &mut dispatcher,
            &mut remotes,
            peer(1),
            &[peer(1), peer(2)],
            &blocks,
            now,
        );
        let requests = take_object_requests(&mut dispatcher, &mut remotes, now);
        assert_eq!(requests.len(), 2);
        let request_for_height = |height: u64| {
            requests
                .iter()
                .copied()
                .find(|(_, _, object)| {
                    let InventoryEntry::Block(block_id) = object else {
                        return false;
                    };
                    blocks.iter().any(|block| {
                        block.header.height == height
                            && block_id_from_header_bytes(&block.header.encode()) == *block_id
                    })
                })
                .expect("height request")
        };
        let parent_request = request_for_height(blocks[0].header.height);
        let child_request = request_for_height(blocks[1].header.height);
        assert_ne!(parent_request.0, child_request.0);

        let child_response = remotes
            .get(&child_request.0)
            .unwrap()
            .make_response(child_request.1, Message::Block(blocks[1].clone()))
            .unwrap();
        inject_action(&mut dispatcher, child_request.0, child_response);
        let child_step = dispatcher.step(now).unwrap();
        assert!(child_step
            .notices
            .iter()
            .any(|notice| matches!(notice, DispatcherNotice::OrphanStored { .. })));
        assert_eq!(dispatcher.peers().orphan_count(), 1);

        let cleanup = dispatcher
            .disconnect_peer(child_request.0)
            .expect("disconnect orphan source");
        let child_id = block_id_from_header_bytes(&blocks[1].header.encode());
        assert_eq!(cleanup.scheduler.unwrap().detached_orphans, vec![child_id]);
        assert_eq!(dispatcher.peers().orphan_count(), 1);

        let parent_response = remotes
            .get(&parent_request.0)
            .unwrap()
            .make_response(parent_request.1, Message::Block(blocks[0].clone()))
            .unwrap();
        inject_action(&mut dispatcher, parent_request.0, parent_response);
        let parent_step = dispatcher.step(now).unwrap();
        assert!(parent_step.notices.iter().any(|notice| matches!(
            notice,
            DispatcherNotice::OrphanReplayed { block_id } if *block_id == child_id
        )));
        assert_eq!(dispatcher.peers().orphan_count(), 0);
        assert_eq!(
            dispatcher
                .daemon()
                .runtime()
                .node()
                .canonical_tip()
                .unwrap(),
            source_tip
        );
    }

    #[test]
    fn restart_reconstructs_from_redb_tip_and_discards_transient_sessions() {
        let path = temporary_redb_path("reconstruct");
        let bootstrap = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        };
        let mut persistent = bootstrap.create_redb(&path).expect("create redb");
        let genesis = persistent.canonical_tip().unwrap().block_id;
        let commit = validated_reward_commit(persistent.storage(), genesis, b"restart-tip");
        let raw = commit.canonical_block_bytes().to_vec();
        persistent
            .process_block(&raw, commit.header().header().timestamp)
            .expect("persist block");
        let expected_tip = persistent.canonical_tip().unwrap();

        let hello = node_hello(&persistent);
        let mut before = dispatcher_for_storage(persistent, 16);
        before.start().unwrap();
        let (session, initial) = PeerSession::new(
            SessionRole::Outbound,
            P2pNetwork::Devnet,
            hello,
            expected_tip.height,
            session_policy(),
        )
        .unwrap();
        before.register_peer(peer(7), session, initial).unwrap();
        assert_eq!(before.daemon().runtime().peer_count(), 1);
        drop(before);

        let reopened = bootstrap.open_redb(&path).expect("reopen redb");
        let mut after: ApplicationDispatcher<RedbConsensusStore, BoundedMemoryDriver> =
            dispatcher_for_storage(reopened, 16);
        assert_eq!(after.sync().unwrap().sync_tip(), expected_tip.block_id);
        assert_eq!(after.daemon().runtime().peer_count(), 0);
        assert_eq!(after.peers().peer_count(), 0);
        assert_eq!(after.peers().pending_object_count(), 0);
        assert_eq!(after.peers().orphan_count(), 0);
        assert_eq!(after.serving().relay().block_count(), 0);
        assert_eq!(after.mempool().unwrap().transaction_count(), 0);
        assert_eq!(after.mempool().unwrap().bytes(), 0);
        assert!(after.mining().snapshot().is_none());
        assert!(after.pending_service.is_empty());
        assert!(after.peer_tips.is_empty());
        assert!(after.active_header.is_none());
        after.start().unwrap();
        assert_eq!(after.daemon().phase(), DaemonPhase::Running);
        drop(after);
        fs::remove_file(path).expect("remove redb test database");
    }

    #[test]
    fn inbound_headers_blocks_and_misses_use_exact_correlated_responses() {
        let (local, blocks) = source_chain(2);
        let (remote_source, remote_blocks) = source_chain(2);
        assert_eq!(
            local.canonical_tip().unwrap(),
            remote_source.canonical_tip().unwrap()
        );
        assert_eq!(
            blocks.iter().map(|block| block.header).collect::<Vec<_>>(),
            remote_blocks
                .iter()
                .map(|block| block.header)
                .collect::<Vec<_>>()
        );
        let now = blocks[1].header.timestamp;
        let genesis = blocks[0].header.parent_block_id;
        let stop_id = block_id_from_header_bytes(&blocks[1].header.encode());
        let mut dispatcher = dispatcher_for_node(local, 16);
        for block in blocks.iter().cloned() {
            assert!(matches!(
                dispatcher.serving.admit_validated(block),
                RelayAdmission::Stored { .. }
            ));
        }
        dispatcher.start().unwrap();
        let mut remotes = establish_peers(&mut dispatcher, &[(peer(1), &remote_source)], now);

        let header_request = remotes
            .get_mut(&peer(1))
            .unwrap()
            .begin_headers_request(now, vec![genesis], stop_id)
            .unwrap();
        let header_request_id = match &header_request {
            SessionAction::Send { request_id, .. } => *request_id,
            _ => panic!("header request"),
        };
        inject_action(&mut dispatcher, peer(1), header_request);
        let queued = dispatcher.step(now).unwrap();
        assert!(queued.notices.iter().any(|notice| matches!(
            notice,
            DispatcherNotice::HeadersServed {
                peer_id,
                request_id,
                count: 2,
            } if *peer_id == peer(1) && *request_id == header_request_id
        )));
        dispatcher.step(now).unwrap();
        let header_response = take_outbound(&mut dispatcher);
        let frame = decode_frame_exact(
            &header_response.bytes,
            P2pNetwork::Devnet,
            PROTOCOL_VERSION_V0,
        )
        .unwrap();
        assert_eq!(frame.header.request_id, header_request_id);
        assert_eq!(
            frame.message,
            Message::Headers(blocks.iter().map(|block| block.header).collect())
        );
        assert!(matches!(
            remotes
                .get_mut(&peer(1))
                .unwrap()
                .handle_inbound(now, frame)
                .unwrap()
                .as_slice(),
            [SessionAction::HeadersResponse { request_id, .. }]
                if *request_id == header_request_id
        ));

        let block_request_id = 700;
        let block_request = remotes
            .get_mut(&peer(1))
            .unwrap()
            .begin_object_request(now, block_request_id, InventoryEntry::Block(stop_id))
            .unwrap();
        inject_action(&mut dispatcher, peer(1), block_request);
        dispatcher.step(now).unwrap();
        dispatcher.step(now).unwrap();
        let block_response = take_outbound(&mut dispatcher);
        let frame = decode_frame_exact(
            &block_response.bytes,
            P2pNetwork::Devnet,
            PROTOCOL_VERSION_V0,
        )
        .unwrap();
        assert_eq!(frame.header.request_id, block_request_id);
        assert_eq!(frame.message, Message::Block(blocks[1].clone()));
        assert!(matches!(
            remotes
                .get_mut(&peer(1))
                .unwrap()
                .handle_inbound(now, frame)
                .unwrap()
                .as_slice(),
            [SessionAction::Deliver {
                request_id,
                message: Message::Block(_),
            }] if *request_id == block_request_id
        ));

        let missing_request_id = 701;
        let missing_request = remotes
            .get_mut(&peer(1))
            .unwrap()
            .begin_object_request(
                now,
                missing_request_id,
                InventoryEntry::Block(BlockId::new([0x77; 32])),
            )
            .unwrap();
        inject_action(&mut dispatcher, peer(1), missing_request);
        dispatcher.step(now).unwrap();
        dispatcher.step(now).unwrap();
        let missing_response = take_outbound(&mut dispatcher);
        let frame = decode_frame_exact(
            &missing_response.bytes,
            P2pNetwork::Devnet,
            PROTOCOL_VERSION_V0,
        )
        .unwrap();
        assert_eq!(frame.header.request_id, missing_request_id);
        assert!(matches!(
            frame.message,
            Message::Reject {
                rejected_type: TYPE_GET_OBJECTS,
                code: 2,
                ..
            }
        ));
    }

    #[test]
    fn inbound_response_backpressure_preserves_peer_and_request_order() {
        let local = node();
        let remote_source = node();
        let tip = local.canonical_tip().unwrap().block_id;
        let mut dispatcher = dispatcher_for_node(local, 1);
        dispatcher.start().unwrap();
        let target_hello = node_hello(dispatcher.daemon().runtime().node());
        let mut remotes = BTreeMap::new();
        for peer_id in [peer(1), peer(2)] {
            let (target_session, initial) = PeerSession::new(
                SessionRole::Outbound,
                P2pNetwork::Devnet,
                target_hello.clone(),
                0,
                session_policy(),
            )
            .unwrap();
            dispatcher
                .register_peer(peer_id, target_session, initial)
                .unwrap();
            let (mut remote, initial) = PeerSession::new(
                SessionRole::Inbound,
                P2pNetwork::Devnet,
                node_hello(&remote_source),
                0,
                session_policy(),
            )
            .unwrap();
            assert!(initial.is_empty());
            dispatcher.step(0).unwrap();
            let hello = take_outbound(&mut dispatcher);
            assert_eq!(hello.peer_id, peer_id);
            let frame =
                decode_frame_exact(&hello.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0).unwrap();
            let acknowledgement = remote
                .handle_inbound(0, frame)
                .unwrap()
                .into_iter()
                .find(|action| matches!(action, SessionAction::Send { .. }))
                .unwrap();
            inject_action(&mut dispatcher, peer_id, acknowledgement);
            dispatcher.step(0).unwrap();
            remotes.insert(peer_id, remote);
        }
        let mut request_ids = BTreeMap::new();
        for peer_id in [peer(1), peer(2)] {
            let request = remotes
                .get_mut(&peer_id)
                .unwrap()
                .begin_headers_request(0, vec![tip], tip)
                .unwrap();
            let request_id = match &request {
                SessionAction::Send { request_id, .. } => *request_id,
                _ => panic!("request"),
            };
            request_ids.insert(peer_id, request_id);
            inject_action(&mut dispatcher, peer_id, request);
        }
        dispatcher.step(0).unwrap();
        dispatcher.step(0).unwrap();
        assert_eq!(dispatcher.daemon().pending_outbound_count(), 1);
        let first = take_outbound(&mut dispatcher);
        assert_eq!(first.peer_id, peer(1));
        let first_frame =
            decode_frame_exact(&first.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0).unwrap();
        assert_eq!(first_frame.header.request_id, request_ids[&peer(1)]);
        assert_eq!(first_frame.message, Message::Headers(Vec::new()));
        dispatcher.step(0).unwrap();
        let second = take_outbound(&mut dispatcher);
        assert_eq!(second.peer_id, peer(2));
        let second_frame =
            decode_frame_exact(&second.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0).unwrap();
        assert_eq!(second_frame.header.request_id, request_ids[&peer(2)]);
        assert_eq!(second_frame.message, Message::Headers(Vec::new()));
    }

    #[test]
    fn dispatcher_policy_rejects_unbounded_or_incoherent_configuration() {
        let sync = SyncPolicy {
            maximum_overlay_headers: 8,
            maximum_blocks_per_request: 2,
            maximum_locator_entries: 5,
            linear_locator_entries: 2,
            maximum_locator_walk: 100,
        };
        let peers = MultiPeerPolicy {
            maximum_peers: 2,
            maximum_announcements_per_peer: 8,
            maximum_total_announcements: 16,
            maximum_pending_objects: 4,
            maximum_in_flight_per_peer: 2,
            maximum_retry_attempts: 2,
            request_timeout_ticks: 10,
            base_retry_backoff_ticks: 1,
            maximum_retry_backoff_ticks: 2,
            first_request_id: 100,
            maximum_orphans: 2,
            maximum_orphans_per_peer: 2,
            maximum_orphans_per_parent: 2,
            maximum_orphan_bytes: 1_000,
        };
        let policy = DispatcherPolicy {
            maximum_events_per_step: 1,
            maximum_commands_per_step: 1,
            first_orphan_replay_request_id: 1_000,
        };
        assert_eq!(
            policy.validate(sync, peers),
            Err(DispatcherPolicyError::PendingObjectsBelowHeaderOverlay {
                pending: 4,
                overlay: 8,
            })
        );
        let mut zero = policy;
        zero.maximum_events_per_step = 0;
        assert_eq!(
            zero.validate(
                sync,
                MultiPeerPolicy {
                    maximum_pending_objects: 8,
                    ..peers
                }
            ),
            Err(DispatcherPolicyError::Zero("maximum_events_per_step"))
        );
    }

    #[test]
    fn dispatcher_preserves_transport_backpressure_without_losing_hello() {
        let mut dispatcher = dispatcher_for_node(node(), 1);
        dispatcher.start().unwrap();
        let hello = node_hello(dispatcher.daemon().runtime().node());
        for peer_id in [peer(1), peer(2)] {
            let (session, initial) = PeerSession::new(
                SessionRole::Outbound,
                P2pNetwork::Devnet,
                hello.clone(),
                0,
                session_policy(),
            )
            .unwrap();
            dispatcher.register_peer(peer_id, session, initial).unwrap();
        }
        dispatcher.step(0).unwrap();
        assert_eq!(dispatcher.daemon().pending_outbound_count(), 1);
        let first = take_outbound(&mut dispatcher);
        assert_eq!(first.peer_id, peer(1));
        dispatcher.step(0).unwrap();
        assert_eq!(dispatcher.daemon().pending_outbound_count(), 0);
        let second = take_outbound(&mut dispatcher);
        assert_eq!(second.peer_id, peer(2));
    }

    #[test]
    fn dispatcher_recovery_gate_starts_driver_only_after_clean_storage() {
        let mut damaged = node();
        let genesis = damaged.canonical_tip().unwrap().block_id;
        let commit = validated_reward_commit(damaged.storage(), genesis, b"dispatcher-recovery");
        let raw = commit.canonical_block_bytes().to_vec();
        let block = Block::decode_non_genesis_exact(&raw).unwrap();
        damaged
            .storage_mut()
            .inject_fault_once(FaultPoint::AfterPrepare)
            .unwrap();
        assert!(damaged.process_block(&raw, block.header.timestamp).is_err());
        let mut dispatcher = dispatcher_for_node(damaged, 16);
        assert_eq!(dispatcher.start().unwrap(), DaemonPhase::Recovering);
        assert_eq!(
            dispatcher.daemon().driver().phase(),
            MemoryDriverPhase::Created
        );
        assert_eq!(
            dispatcher.recover_storage().unwrap(),
            RecoveryOutcome::RolledBackPrepared
        );
        assert_eq!(
            dispatcher.daemon().driver().phase(),
            MemoryDriverPhase::Started
        );
    }

    #[test]
    fn mining_control_is_explicit_atomic_and_one_step_bounded() {
        let local = node();
        let genesis = local.canonical_tip().unwrap().block_id;
        let reward_probe = validated_reward_commit(local.storage(), genesis, b"control-recipient");
        let Transaction::Reward(reward) = &reward_probe.block().body.transactions[0] else {
            panic!("reward probe");
        };
        let recipient = reward.body.recipient;
        let parent = local
            .storage()
            .get_validated_header(genesis)
            .unwrap()
            .unwrap();
        let timestamp = parent.header().timestamp + 1;
        let request = CandidateRequest {
            timestamp,
            local_now: timestamp,
            reward_recipient: recipient,
            reward_extra: b"control-start".to_vec(),
        };
        let mut dispatcher = dispatcher_for_node(local, 16);

        let MiningControlOutcome::Inspected(idle) = dispatcher
            .control_mining(MiningControlCommand::Inspect)
            .unwrap()
        else {
            panic!("inspect outcome");
        };
        assert_eq!(idle.network, SupportedNetwork::Devnet);
        assert_eq!(idle.canonical_tip.block_id, genesis);
        assert!(idle.job.is_none());
        assert!(matches!(
            dispatcher.control_mining(MiningControlCommand::Refresh {
                request: request.clone(),
                first_nonce: 0,
            }),
            Err(DispatcherError::MiningJobNotActive)
        ));

        let MiningControlOutcome::Started(started) = dispatcher
            .control_mining(MiningControlCommand::Start {
                request: request.clone(),
                first_nonce: 7,
            })
            .unwrap()
        else {
            panic!("start outcome");
        };
        assert_eq!(started.next_nonce, 7);
        assert_eq!(started.total_attempts, 0);
        assert!(matches!(
            dispatcher.control_mining(MiningControlCommand::Start {
                request: request.clone(),
                first_nonce: 9,
            }),
            Err(DispatcherError::MiningJobAlreadyActive(active)) if *active == started
        ));
        assert_eq!(dispatcher.mining().snapshot(), Some(started.clone()));

        let mut invalid_refresh = request.clone();
        invalid_refresh.reward_extra =
            vec![0; usize::from(MAX_REWARD_EXTRA_BYTES).saturating_add(1)];
        assert!(matches!(
            dispatcher.control_mining(MiningControlCommand::Refresh {
                request: invalid_refresh,
                first_nonce: 11,
            }),
            Err(DispatcherError::Candidate(_))
        ));
        assert_eq!(dispatcher.mining().snapshot(), Some(started.clone()));

        let mut refreshed_request = request.clone();
        refreshed_request.reward_extra = b"control-refresh".to_vec();
        let MiningControlOutcome::Refreshed { previous, current } = dispatcher
            .control_mining(MiningControlCommand::Refresh {
                request: refreshed_request.clone(),
                first_nonce: 13,
            })
            .unwrap()
        else {
            panic!("refresh outcome");
        };
        assert_eq!(previous, started);
        assert_eq!(current.next_nonce, 13);
        assert_eq!(current.total_attempts, 0);

        let MiningControlOutcome::Cancelled(cancelled) = dispatcher
            .control_mining(MiningControlCommand::Cancel)
            .unwrap()
        else {
            panic!("cancel outcome");
        };
        assert_eq!(cancelled, Some(current));
        assert!(matches!(
            dispatcher
                .control_mining(MiningControlCommand::Cancel)
                .unwrap(),
            MiningControlOutcome::Cancelled(None)
        ));

        let MiningControlOutcome::Started(_) = dispatcher
            .control_mining(MiningControlCommand::Start {
                request: refreshed_request,
                first_nonce: 0,
            })
            .unwrap()
        else {
            panic!("restart outcome");
        };
        let MiningControlOutcome::Stepped(step) = dispatcher
            .control_mining(MiningControlCommand::Step {
                local_now: timestamp,
            })
            .unwrap()
        else {
            panic!("step outcome");
        };
        let attempts = match step.work {
            MiningWorkOutcome::Progress { attempts, .. }
            | MiningWorkOutcome::SolutionFound { attempts, .. }
            | MiningWorkOutcome::NonceSpaceExhausted { attempts, .. } => attempts,
            MiningWorkOutcome::Idle
            | MiningWorkOutcome::Stale(_)
            | MiningWorkOutcome::SolutionPending { .. } => panic!("fresh job must perform work"),
        };
        assert!(attempts > 0);
        assert!(attempts <= dispatcher.mining().policy().maximum_nonce_attempts);
    }

    #[test]
    fn local_mining_job_accepts_relays_and_announces_through_normal_paths() {
        let local = node();
        let genesis = local.canonical_tip().unwrap().block_id;
        let reward_probe = validated_reward_commit(local.storage(), genesis, b"miner-recipient");
        let Transaction::Reward(reward) = &reward_probe.block().body.transactions[0] else {
            panic!("reward probe");
        };
        let recipient = reward.body.recipient;
        let parent = local
            .storage()
            .get_validated_header(genesis)
            .unwrap()
            .unwrap();
        let timestamp = parent.header().timestamp + 1;
        let remote = node();
        let mut dispatcher = dispatcher_for_node(local, 16);
        dispatcher.start().unwrap();
        let mut remotes = establish_peers(&mut dispatcher, &[(peer(9), &remote)], timestamp);
        assert!(!dispatcher
            .start_mining_job(
                CandidateRequest {
                    timestamp,
                    local_now: timestamp,
                    reward_recipient: recipient,
                    reward_extra: b"dispatcher-miner".to_vec(),
                },
                0,
            )
            .unwrap());

        for _ in 0..dispatcher.serving.policy().maximum_pending_announcements {
            dispatcher
                .pending_announcements
                .push_back(PendingAnnouncement {
                    peer_id: peer(9),
                    entries: vec![InventoryEntry::Block(genesis)],
                });
        }
        let mut backpressured = None;
        for _ in 0..1_000 {
            let step = dispatcher.mine_step(timestamp).unwrap();
            if step.announcement_backpressure.is_some() {
                backpressured = Some(step);
                break;
            }
        }
        let backpressured = backpressured.expect("fixed devnet fixture solves within bound");
        assert!(backpressured.submission.is_none());
        assert_eq!(
            backpressured.announcement_backpressure,
            Some(MiningAnnouncementBackpressure {
                required: 1,
                available: 0,
            })
        );
        let pending_solution = dispatcher.mining().snapshot().unwrap();
        assert_eq!(
            pending_solution.solution_block_id,
            Some(dispatcher.mining().solution().unwrap().block_id)
        );
        dispatcher.pending_announcements.clear();
        let accepted = dispatcher.mine_step(timestamp).unwrap();
        assert!(matches!(
            accepted.work,
            MiningWorkOutcome::SolutionPending { .. }
        ));
        let submission = accepted.submission.as_ref().unwrap();
        let block_id = submission.stored.block_id;
        assert!(matches!(
            submission.activation,
            ActivationOutcome::Applied { ref new_tip, .. } if new_tip.block_id == block_id
        ));
        assert!(accepted.relay_cached);
        assert_eq!(accepted.announcements_queued, 1);
        assert!(accepted.announcement_backpressure.is_none());
        assert!(accepted.notices.iter().any(|notice| matches!(
            notice,
            DispatcherNotice::MinedBlockAccepted {
                block_id: actual,
                announcements_queued: 1,
            } if *actual == block_id
        )));
        assert!(dispatcher.mining().snapshot().is_none());
        assert_eq!(dispatcher.serving().relay().block_count(), 1);
        assert_eq!(
            dispatcher
                .daemon()
                .runtime()
                .node()
                .canonical_tip()
                .unwrap()
                .block_id,
            block_id
        );

        let mut announced = false;
        for _ in 0..4 {
            dispatcher.step(timestamp).unwrap();
            let Some(carried) = dispatcher
                .daemon_mut()
                .driver_mut()
                .take_outbound()
                .unwrap()
            else {
                continue;
            };
            let frame = decode_frame_exact(&carried.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0)
                .unwrap();
            if frame.message == Message::Inventory(vec![InventoryEntry::Block(block_id)]) {
                assert_eq!(carried.peer_id, peer(9));
                assert_eq!(frame.header.request_id, 0);
                let actions = remotes
                    .get_mut(&peer(9))
                    .unwrap()
                    .handle_inbound(timestamp, frame)
                    .unwrap();
                assert!(matches!(
                    actions.as_slice(),
                    [SessionAction::Deliver {
                        request_id: 0,
                        message: Message::Inventory(entries),
                    }] if entries == &vec![InventoryEntry::Block(block_id)]
                ));
                announced = true;
                break;
            }
        }
        assert!(announced);
    }
}
