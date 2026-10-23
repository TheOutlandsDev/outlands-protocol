//! Two complete application dispatchers joined by bounded memory drivers.
//!
//! The harness opens no sockets, owns no clock or threads, and never fabricates
//! a response. Each direction transfers the exact P2P frame bytes emitted by
//! one dispatcher into the other dispatcher's transport queue.

use std::collections::BTreeSet;

use out_codec::Block;
use out_consensus::block_id_from_header_bytes;
use out_consensus::chain::ValidatedHeaderView;
use out_p2p::session::{PeerSession, SessionError, SessionPolicy, SessionRole};
use out_p2p::{decode_frame_exact, DecodeError, Hello, P2pNetwork, PROTOCOL_VERSION_V0};
use out_primitives::BlockId;
use out_storage::{
    ConsensusStorage, InMemoryConsensusStore, InMemoryMutationError, InMemoryReadError,
};

use crate::dispatcher::{ApplicationDispatcher, DispatcherError, DispatcherNotice, DispatcherStep};
use crate::driver::{BoundedMemoryDriver, MemoryDriverError, TransportFrame};
use crate::peers::PeerId;
use crate::serving::{AnnouncementError, RelayAdmission, ServingError};
use crate::{Node, SupportedNetwork};

pub type MemoryDispatcher = ApplicationDispatcher<InMemoryConsensusStore, BoundedMemoryDriver>;
pub type MemoryDispatcherError = DispatcherError<
    InMemoryReadError,
    InMemoryMutationError,
    InMemoryMutationError,
    MemoryDriverError,
>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DuplexPolicy {
    pub session: SessionPolicy,
    pub maximum_rounds: u16,
    pub maximum_frames_per_direction_per_round: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplexPolicyError {
    Zero(&'static str),
    Session(SessionError),
}

impl DuplexPolicy {
    pub fn validate(self) -> Result<Self, DuplexPolicyError> {
        self.session
            .validate()
            .map_err(DuplexPolicyError::Session)?;
        if self.maximum_rounds == 0 {
            return Err(DuplexPolicyError::Zero("maximum_rounds"));
        }
        if self.maximum_frames_per_direction_per_round == 0 {
            return Err(DuplexPolicyError::Zero(
                "maximum_frames_per_direction_per_round",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplexDirection {
    LeftToRight,
    RightToLeft,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplexTransfer {
    pub direction: DuplexDirection,
    pub request_id: u64,
    pub message_type: u16,
    pub frame_bytes: Vec<u8>,
}

pub struct DuplexRound {
    pub left: DispatcherStep,
    pub right: DispatcherStep,
    pub left_to_right: u16,
    pub right_to_left: u16,
}

#[derive(Debug)]
pub enum DuplexHarnessError {
    Policy(DuplexPolicyError),
    NetworkMismatch,
    Read(InMemoryReadError),
    Session(SessionError),
    Dispatcher(Box<MemoryDispatcherError>),
    Driver(MemoryDriverError),
    Decode(DecodeError),
    HandshakeRoundLimit { maximum: u16 },
    SyncRoundLimit { maximum: u16, expected: BlockId },
    EmptyRelaySeed,
    DuplicateRelayBlock(BlockId),
    GenesisRelayBlock(BlockId),
    RelayBlockNotStored(BlockId),
    RelayHeaderMismatch(BlockId),
    RelayBlockNotCanonical(BlockId),
    RelayAdmission(RelayAdmission),
    Announcement(AnnouncementError<InMemoryReadError>),
    Serving(ServingError<InMemoryReadError>),
}

pub struct TwoDispatcherDuplexHarness {
    left: MemoryDispatcher,
    right: MemoryDispatcher,
    left_peer_id: PeerId,
    right_peer_id: PeerId,
    network: P2pNetwork,
    policy: DuplexPolicy,
    transcript: Vec<DuplexTransfer>,
}

impl TwoDispatcherDuplexHarness {
    pub fn establish(
        mut left: MemoryDispatcher,
        mut right: MemoryDispatcher,
        left_peer_id: PeerId,
        right_peer_id: PeerId,
        now: u64,
        policy: DuplexPolicy,
    ) -> Result<Self, DuplexHarnessError> {
        let policy = policy.validate().map_err(DuplexHarnessError::Policy)?;
        let left_network = left.daemon().runtime().node().config().network;
        let right_network = right.daemon().runtime().node().config().network;
        if left_network != right_network {
            return Err(DuplexHarnessError::NetworkMismatch);
        }
        let network = p2p_network(left_network);
        left.start()
            .map_err(|error| DuplexHarnessError::Dispatcher(Box::new(error)))?;
        right
            .start()
            .map_err(|error| DuplexHarnessError::Dispatcher(Box::new(error)))?;
        let left_hello = node_hello(left.daemon().runtime().node())?;
        let right_hello = node_hello(right.daemon().runtime().node())?;
        let (left_session, left_initial) = PeerSession::new(
            SessionRole::Outbound,
            network,
            left_hello,
            now,
            policy.session,
        )
        .map_err(DuplexHarnessError::Session)?;
        let (right_session, right_initial) = PeerSession::new(
            SessionRole::Inbound,
            network,
            right_hello,
            now,
            policy.session,
        )
        .map_err(DuplexHarnessError::Session)?;
        left.register_peer(right_peer_id, left_session, left_initial)
            .map_err(|error| DuplexHarnessError::Dispatcher(Box::new(error)))?;
        right
            .register_peer(left_peer_id, right_session, right_initial)
            .map_err(|error| DuplexHarnessError::Dispatcher(Box::new(error)))?;
        let mut harness = Self {
            left,
            right,
            left_peer_id,
            right_peer_id,
            network,
            policy,
            transcript: Vec::new(),
        };
        let mut left_established = false;
        let mut right_established = false;
        for _ in 0..policy.maximum_rounds {
            let round = harness.pump_round(now)?;
            left_established |= established_with(&round.left.notices, right_peer_id);
            right_established |= established_with(&round.right.notices, left_peer_id);
            if left_established && right_established {
                return Ok(harness);
            }
        }
        Err(DuplexHarnessError::HandshakeRoundLimit {
            maximum: policy.maximum_rounds,
        })
    }

    pub const fn left(&self) -> &MemoryDispatcher {
        &self.left
    }

    pub const fn right(&self) -> &MemoryDispatcher {
        &self.right
    }

    pub fn left_mut(&mut self) -> &mut MemoryDispatcher {
        &mut self.left
    }

    pub fn right_mut(&mut self) -> &mut MemoryDispatcher {
        &mut self.right
    }

    pub fn transcript(&self) -> &[DuplexTransfer] {
        &self.transcript
    }

    /// Seeds the left relay only after independently checking that every block
    /// is already stored on the left node's exact canonical ancestry.
    pub fn seed_left_relay(
        &mut self,
        blocks: Vec<Block>,
    ) -> Result<Vec<BlockId>, DuplexHarnessError> {
        if blocks.is_empty() {
            return Err(DuplexHarnessError::EmptyRelaySeed);
        }
        let storage = self.left.daemon().runtime().node().storage();
        let canonical = canonical_ids(
            storage,
            self.left.serving().policy().maximum_ancestry_records,
        )?;
        let mut unique = BTreeSet::new();
        let mut checked = Vec::with_capacity(blocks.len());
        for block in blocks {
            let block_id = block_id_from_header_bytes(&block.header.encode());
            if block.header.height == 0 {
                return Err(DuplexHarnessError::GenesisRelayBlock(block_id));
            }
            if !unique.insert(block_id) {
                return Err(DuplexHarnessError::DuplicateRelayBlock(block_id));
            }
            let metadata = storage
                .get_validated_header(block_id)
                .map_err(DuplexHarnessError::Read)?
                .ok_or(DuplexHarnessError::RelayBlockNotStored(block_id))?;
            if metadata.header() != block.header {
                return Err(DuplexHarnessError::RelayHeaderMismatch(block_id));
            }
            if !canonical.contains(&block_id) {
                return Err(DuplexHarnessError::RelayBlockNotCanonical(block_id));
            }
            checked.push((block_id, block));
        }
        let mut ids = Vec::with_capacity(checked.len());
        for (block_id, block) in checked {
            match self.left.admit_harness_validated_relay(block) {
                RelayAdmission::Stored {
                    block_id: actual, ..
                }
                | RelayAdmission::AlreadyStored { block_id: actual }
                    if actual == block_id =>
                {
                    ids.push(block_id);
                }
                admission => return Err(DuplexHarnessError::RelayAdmission(admission)),
            }
        }
        Ok(ids)
    }

    pub fn announce_left_blocks(
        &mut self,
        block_ids: Vec<BlockId>,
    ) -> Result<(), DuplexHarnessError> {
        self.left
            .announce_blocks(self.right_peer_id, block_ids)
            .map_err(|error| DuplexHarnessError::Dispatcher(Box::new(error)))
    }

    /// Advances both complete applications once, then transfers left-to-right
    /// before right-to-left. Each direction has an independent strict bound.
    pub fn pump_round(&mut self, now: u64) -> Result<DuplexRound, DuplexHarnessError> {
        let left = self
            .left
            .step(now)
            .map_err(|error| DuplexHarnessError::Dispatcher(Box::new(error)))?;
        let right = self
            .right
            .step(now)
            .map_err(|error| DuplexHarnessError::Dispatcher(Box::new(error)))?;
        let left_to_right = transfer(
            &mut self.left,
            &mut self.right,
            self.left_peer_id,
            self.network,
            DuplexDirection::LeftToRight,
            self.policy.maximum_frames_per_direction_per_round,
            &mut self.transcript,
        )?;
        let right_to_left = transfer(
            &mut self.right,
            &mut self.left,
            self.right_peer_id,
            self.network,
            DuplexDirection::RightToLeft,
            self.policy.maximum_frames_per_direction_per_round,
            &mut self.transcript,
        )?;
        Ok(DuplexRound {
            left,
            right,
            left_to_right,
            right_to_left,
        })
    }

    pub fn run_until_right_tip(
        &mut self,
        now: u64,
        expected: BlockId,
    ) -> Result<u16, DuplexHarnessError> {
        for round in 1..=self.policy.maximum_rounds {
            self.pump_round(now)?;
            let tip = self
                .right
                .daemon()
                .runtime()
                .node()
                .canonical_tip()
                .map_err(DuplexHarnessError::Read)?;
            if tip.block_id == expected {
                return Ok(round);
            }
        }
        Err(DuplexHarnessError::SyncRoundLimit {
            maximum: self.policy.maximum_rounds,
            expected,
        })
    }
}

fn established_with(notices: &[DispatcherNotice], peer_id: PeerId) -> bool {
    notices.iter().any(|notice| {
        matches!(notice, DispatcherNotice::PeerEstablished { peer_id: actual, .. } if *actual == peer_id)
    })
}

fn transfer(
    source: &mut MemoryDispatcher,
    destination: &mut MemoryDispatcher,
    destination_peer_id: PeerId,
    network: P2pNetwork,
    direction: DuplexDirection,
    maximum: u16,
    transcript: &mut Vec<DuplexTransfer>,
) -> Result<u16, DuplexHarnessError> {
    let mut count = 0_u16;
    while count < maximum {
        let Some(frame) = source
            .daemon_mut()
            .driver_mut()
            .take_outbound()
            .map_err(DuplexHarnessError::Driver)?
        else {
            break;
        };
        let decoded = decode_frame_exact(&frame.bytes, network, PROTOCOL_VERSION_V0)
            .map_err(DuplexHarnessError::Decode)?;
        transcript.push(DuplexTransfer {
            direction,
            request_id: decoded.header.request_id,
            message_type: decoded.header.message_type,
            frame_bytes: frame.bytes.clone(),
        });
        destination
            .daemon_mut()
            .driver_mut()
            .inject_inbound(TransportFrame {
                peer_id: destination_peer_id,
                bytes: frame.bytes,
            })
            .map_err(DuplexHarnessError::Driver)?;
        count = count.saturating_add(1);
    }
    Ok(count)
}

fn p2p_network(network: SupportedNetwork) -> P2pNetwork {
    match network {
        SupportedNetwork::Testnet => P2pNetwork::Testnet,
        SupportedNetwork::Devnet => P2pNetwork::Devnet,
    }
}

fn node_hello(node: &Node<InMemoryConsensusStore>) -> Result<Hello, DuplexHarnessError> {
    let tip = node.canonical_tip().map_err(DuplexHarnessError::Read)?;
    let identity = node.config().network.identity();
    Ok(Hello {
        min_protocol_version: 0,
        max_protocol_version: 0,
        min_consensus_version: 0,
        max_consensus_version: 0,
        chain_id: identity.chain_id,
        network_id: identity.network_id,
        genesis_commitment: identity.genesis_commitment,
        best_height: tip.height,
        best_block_id: tip.block_id,
    })
}

fn canonical_ids(
    storage: &InMemoryConsensusStore,
    maximum: u16,
) -> Result<BTreeSet<BlockId>, DuplexHarnessError> {
    let tip = storage.canonical_tip().map_err(DuplexHarnessError::Read)?;
    let mut current = tip.block_id;
    let mut ids = BTreeSet::new();
    for _ in 0..maximum {
        let metadata = storage
            .get_validated_header(current)
            .map_err(DuplexHarnessError::Read)?
            .ok_or(DuplexHarnessError::RelayBlockNotStored(current))?;
        if metadata.block_id() != current
            || block_id_from_header_bytes(&metadata.header().encode()) != current
        {
            return Err(DuplexHarnessError::RelayHeaderMismatch(current));
        }
        ids.insert(current);
        if metadata.header().height == 0 {
            return Ok(ids);
        }
        current = metadata.header().parent_block_id;
    }
    Err(DuplexHarnessError::RelayBlockNotCanonical(tip.block_id))
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use out_storage::conformance::validated_reward_commit;
    use out_storage::conformance::FaultInjectableConformanceStore;
    use out_storage::redb_backend::RedbConsensusStore;
    use out_storage::rocksdb_backend::RocksdbConsensusStore;
    use out_storage::{FaultPoint, RecoverableConsensusStorage, RecoveryOutcome, RecoveryStatus};

    use out_codec::{RegularTransaction, Transaction};
    use out_consensus::transaction_id_from_canonical_bytes;

    use super::*;
    use crate::bootstrap::NodeBootstrap;
    use crate::dispatcher::DispatcherPolicy;
    use crate::driver::{DaemonHarness, DaemonPolicy, MemoryDriverPolicy};
    use crate::mempool::MempoolPolicy;
    use crate::mining::CpuMiningPolicy;
    use crate::peers::{MemoryTransportPolicy, MultiPeerPolicy};
    use crate::runtime::{NodeRuntime, RuntimePolicy};
    use crate::serving::ServingPolicy;
    use crate::sync::{SyncCoordinator, SyncPolicy};

    type TargetDispatcherError<S> = DispatcherError<
        <S as ValidatedHeaderView>::Error,
        <S as ConsensusStorage>::MutationError,
        <S as RecoverableConsensusStorage>::RecoveryError,
        MemoryDriverError,
    >;

    const VECTOR_TRANSACTION_HEX: &str = "0000000000bc0000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a70003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b800000000000000000029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000075bcd1500000000000003e8000000000000000100000000000003e8000a4f555420766563746f720062000003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b84db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b";

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = char::from(pair[0]).to_digit(16).unwrap();
                let low = char::from(pair[1]).to_digit(16).unwrap();
                u8::try_from((high << 4) | low).unwrap()
            })
            .collect()
    }

    fn vector_transaction() -> RegularTransaction {
        RegularTransaction::decode_exact(&decode_hex(VECTOR_TRANSACTION_HEX)).unwrap()
    }

    fn funded_node() -> Node<InMemoryConsensusStore> {
        let mut funded = node();
        let genesis = funded.canonical_tip().unwrap().block_id;
        let commit =
            validated_reward_commit(funded.storage(), genesis, b"transaction-relay-funding");
        let raw = commit.canonical_block_bytes().to_vec();
        funded
            .process_block(&raw, commit.header().header().timestamp)
            .unwrap();
        funded
    }

    fn node() -> Node<InMemoryConsensusStore> {
        NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        }
        .create_in_memory()
        .unwrap()
    }

    fn append(node: &mut Node<InMemoryConsensusStore>, parent: BlockId, tag: &[u8]) -> Block {
        let commit = validated_reward_commit(node.storage(), parent, tag);
        let raw = commit.canonical_block_bytes().to_vec();
        let block = Block::decode_non_genesis_exact(&raw).unwrap();
        node.process_block(&raw, block.header.timestamp).unwrap();
        block
    }

    fn chain(node: &mut Node<InMemoryConsensusStore>, tags: &[&[u8]]) -> Vec<Block> {
        let mut parent = node.canonical_tip().unwrap().block_id;
        let mut blocks = Vec::new();
        for tag in tags {
            let block = append(node, parent, tag);
            parent = block_id_from_header_bytes(&block.header.encode());
            blocks.push(block);
        }
        blocks
    }

    fn dispatcher(node: Node<InMemoryConsensusStore>) -> MemoryDispatcher {
        dispatcher_for(node)
    }

    fn dispatcher_for<S>(node: Node<S>) -> ApplicationDispatcher<S, BoundedMemoryDriver>
    where
        S: RecoverableConsensusStorage,
        S::Error: Debug,
        S::MutationError: Debug,
        <S as RecoverableConsensusStorage>::RecoveryError: Debug,
    {
        let runtime = NodeRuntime::new(
            node,
            RuntimePolicy {
                maximum_peers: 4,
                maximum_inbound_events: 32,
                maximum_inbound_bytes: 8_000_000,
                maximum_frame_bytes: 1_000_000,
                maximum_output_events: 32,
                maximum_inbound_events_per_step: 16,
                maximum_peer_polls_per_step: 4,
            },
        )
        .unwrap();
        let queue = MemoryTransportPolicy {
            maximum_queued_frames: 32,
            maximum_queued_bytes: 8_000_000,
            maximum_frame_bytes: 1_000_000,
        };
        let driver = BoundedMemoryDriver::new(MemoryDriverPolicy {
            inbound: queue,
            outbound: queue,
        })
        .unwrap();
        let daemon = DaemonHarness::new(
            runtime,
            driver,
            DaemonPolicy {
                maximum_transport_receives_per_step: 16,
                maximum_transport_sends_per_step: 16,
                maximum_runtime_outputs_per_step: 16,
                maximum_pending_outbound_frames: 32,
                maximum_pending_outbound_bytes: 8_000_000,
                maximum_local_events: 64,
            },
        )
        .unwrap();
        ApplicationDispatcher::new(
            daemon,
            SyncPolicy {
                maximum_overlay_headers: 32,
                maximum_blocks_per_request: 16,
                maximum_locator_entries: 16,
                linear_locator_entries: 4,
                maximum_locator_walk: 256,
            },
            MultiPeerPolicy {
                maximum_peers: 4,
                maximum_announcements_per_peer: 32,
                maximum_total_announcements: 128,
                maximum_pending_objects: 32,
                maximum_in_flight_per_peer: 16,
                maximum_retry_attempts: 4,
                request_timeout_ticks: 200,
                base_retry_backoff_ticks: 1,
                maximum_retry_backoff_ticks: 8,
                first_request_id: 100,
                maximum_orphans: 32,
                maximum_orphans_per_peer: 32,
                maximum_orphans_per_parent: 16,
                maximum_orphan_bytes: 8_000_000,
            },
            DispatcherPolicy {
                maximum_events_per_step: 64,
                maximum_commands_per_step: 16,
                first_orphan_replay_request_id: 10_000,
            },
            ServingPolicy {
                maximum_pending_requests: 32,
                maximum_responses_per_step: 8,
                maximum_pending_announcements: 16,
                maximum_announcements_per_step: 4,
                maximum_inventory_entries_per_announcement: 32,
                maximum_headers_per_response: 16,
                maximum_ancestry_records: 256,
                maximum_relay_blocks: 32,
                maximum_relay_bytes: 8_000_000,
            },
            MempoolPolicy {
                maximum_transactions: 64,
                maximum_total_bytes: 1_000_000,
                maximum_transactions_per_sender: 32,
                maximum_template_transactions: 32,
                maximum_template_bytes: 500_000,
            },
            CpuMiningPolicy {
                maximum_nonce_attempts: 4_096,
            },
        )
        .unwrap()
    }

    fn policy(frames: u16) -> DuplexPolicy {
        DuplexPolicy {
            session: SessionPolicy {
                handshake_timeout_ticks: 200,
                response_timeout_ticks: 200,
                maximum_outstanding_requests: 32,
                disconnect_score: 100,
                protocol_violation_score: 20,
                unexpected_response_score: 10,
                timeout_score: 5,
            },
            maximum_rounds: 128,
            maximum_frames_per_direction_per_round: frames,
        }
    }

    fn peer(value: u64) -> PeerId {
        PeerId::new(value).unwrap()
    }

    static NEXT_PERSISTENT_PATH: AtomicU64 = AtomicU64::new(0);

    fn persistent_path(label: &str, extension: Option<&str>) -> PathBuf {
        let sequence = NEXT_PERSISTENT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "out-duplex-{label}-{}-{sequence}",
            std::process::id()
        ));
        match extension {
            Some(extension) => path.with_extension(extension),
            None => path,
        }
    }

    fn hello_for<S>(node: &Node<S>) -> Hello
    where
        S: ConsensusStorage,
        S::Error: Debug,
    {
        let tip = node.canonical_tip().unwrap();
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

    fn move_mixed_frames<From, To>(
        source: &mut ApplicationDispatcher<From, BoundedMemoryDriver>,
        destination: &mut ApplicationDispatcher<To, BoundedMemoryDriver>,
        destination_peer_id: PeerId,
        maximum: u16,
    ) where
        From: RecoverableConsensusStorage,
        To: RecoverableConsensusStorage,
    {
        for _ in 0..maximum {
            let Some(frame) = source.daemon_mut().driver_mut().take_outbound().unwrap() else {
                break;
            };
            destination
                .daemon_mut()
                .driver_mut()
                .inject_inbound(TransportFrame {
                    peer_id: destination_peer_id,
                    bytes: frame.bytes,
                })
                .unwrap();
        }
    }

    fn pump_mixed<S>(
        source: &mut MemoryDispatcher,
        target: &mut ApplicationDispatcher<S, BoundedMemoryDriver>,
        now: u64,
        maximum_frames_per_direction: u16,
    ) -> Result<(), TargetDispatcherError<S>>
    where
        S: RecoverableConsensusStorage,
        S::Error: Debug,
        S::MutationError: Debug,
        S::RecoveryError: Debug,
    {
        source.step(now).unwrap();
        target.step(now)?;
        move_mixed_frames(source, target, peer(1), maximum_frames_per_direction);
        move_mixed_frames(target, source, peer(2), maximum_frames_per_direction);
        Ok(())
    }

    fn connect_running_mixed<S>(
        source: &mut MemoryDispatcher,
        target: &mut ApplicationDispatcher<S, BoundedMemoryDriver>,
        now: u64,
    ) where
        S: RecoverableConsensusStorage,
        S::Error: Debug,
        S::MutationError: Debug,
        S::RecoveryError: Debug,
    {
        let (source_session, source_initial) = PeerSession::new(
            SessionRole::Outbound,
            P2pNetwork::Devnet,
            hello_for(source.daemon().runtime().node()),
            now,
            policy(16).session,
        )
        .unwrap();
        let (target_session, target_initial) = PeerSession::new(
            SessionRole::Inbound,
            P2pNetwork::Devnet,
            hello_for(target.daemon().runtime().node()),
            now,
            policy(16).session,
        )
        .unwrap();
        source
            .register_peer(peer(2), source_session, source_initial)
            .unwrap();
        target
            .register_peer(peer(1), target_session, target_initial)
            .unwrap();
        for _ in 0..16 {
            pump_mixed(source, target, now, 16).unwrap();
            if source.peers().peer_count() == 1 && target.peers().peer_count() == 1 {
                return;
            }
        }
        panic!("mixed dispatcher handshake did not complete");
    }

    fn establish_mixed<S>(
        mut source: MemoryDispatcher,
        mut target: ApplicationDispatcher<S, BoundedMemoryDriver>,
        now: u64,
    ) -> (
        MemoryDispatcher,
        ApplicationDispatcher<S, BoundedMemoryDriver>,
    )
    where
        S: RecoverableConsensusStorage,
        S::Error: Debug,
        S::MutationError: Debug,
        S::RecoveryError: Debug,
    {
        source.start().unwrap();
        target.start().unwrap();
        connect_running_mixed(&mut source, &mut target, now);
        (source, target)
    }

    fn seed_source(source: &mut MemoryDispatcher, blocks: &[Block]) -> Vec<BlockId> {
        let mut ids = Vec::with_capacity(blocks.len());
        for block in blocks {
            let expected = block_id_from_header_bytes(&block.header.encode());
            assert!(matches!(
                source.admit_harness_validated_relay(block.clone()),
                RelayAdmission::Stored { block_id, .. }
                    | RelayAdmission::AlreadyStored { block_id }
                    if block_id == expected
            ));
            ids.push(expected);
        }
        source.announce_blocks(peer(2), ids.clone()).unwrap();
        ids
    }

    fn run_mixed_to_tip<S>(
        source: &mut MemoryDispatcher,
        target: &mut ApplicationDispatcher<S, BoundedMemoryDriver>,
        expected: BlockId,
        now: u64,
    ) where
        S: RecoverableConsensusStorage,
        S::Error: Debug,
        S::MutationError: Debug,
        S::RecoveryError: Debug,
    {
        for _ in 0..128 {
            pump_mixed(source, target, now, 4).unwrap();
            if target
                .daemon()
                .runtime()
                .node()
                .canonical_tip()
                .unwrap()
                .block_id
                == expected
            {
                return;
            }
        }
        panic!(
            "persistent target did not converge: tip={:?} sync_tip={:?} queued={} in_flight={} source_outbound={} target_outbound={}",
            target
                .daemon()
                .runtime()
                .node()
                .canonical_tip()
                .unwrap(),
            target.sync().map(SyncCoordinator::sync_tip),
            target
                .sync()
                .map_or(0, SyncCoordinator::queued_block_count),
            target
                .sync()
                .map_or(0, SyncCoordinator::in_flight_block_count),
            source.daemon().driver().outbound_frame_count(),
            target.daemon().driver().outbound_frame_count(),
        );
    }

    fn persistent_fault_case<S, Recover, Reopen>(
        target_node: Node<S>,
        fault: FaultPoint,
        expected_recovery: RecoveryOutcome,
        recover: Recover,
        reopen: Reopen,
    ) where
        S: RecoverableConsensusStorage + FaultInjectableConformanceStore,
        S::Error: Debug,
        S::MutationError: Debug,
        <S as RecoverableConsensusStorage>::RecoveryError: Debug,
        <S as FaultInjectableConformanceStore>::RecoveryError: Debug,
        Recover: FnOnce() -> RecoveryOutcome,
        Reopen: FnOnce() -> Node<S>,
    {
        let now = 2_000_000_100;
        let mut source_node = node();
        let blocks = chain(&mut source_node, &[b"persistent-fault"]);
        let expected_tip = source_node.canonical_tip().unwrap();
        let expected_state = source_node
            .storage()
            .parent_state_snapshot(expected_tip.block_id)
            .unwrap()
            .unwrap();
        let (mut source, mut target) =
            establish_mixed(dispatcher(source_node), dispatcher_for(target_node), now);
        seed_source(&mut source, &blocks);
        target
            .daemon_mut()
            .runtime_mut()
            .node_mut()
            .storage_mut()
            .inject_conformance_fault(fault)
            .unwrap();
        let mut observed_failure = false;
        for _ in 0..64 {
            if pump_mixed(&mut source, &mut target, now, 2).is_err() {
                observed_failure = true;
                break;
            }
        }
        assert!(observed_failure);
        assert_eq!(
            target.daemon().runtime().node().recovery_status(),
            match fault {
                FaultPoint::AfterPrepare => RecoveryStatus::Prepared,
                FaultPoint::AfterPublish => RecoveryStatus::Published,
                FaultPoint::BeforePrepare => RecoveryStatus::Clean,
            }
        );
        drop(source);
        drop(target);

        assert_eq!(recover(), expected_recovery);
        let clean_target = reopen();
        assert_eq!(clean_target.recovery_status(), RecoveryStatus::Clean);

        let mut replacement_source = node();
        let replacement_blocks = chain(&mut replacement_source, &[b"persistent-fault"]);
        assert_eq!(replacement_source.canonical_tip().unwrap(), expected_tip);
        let (mut source, mut target) = establish_mixed(
            dispatcher(replacement_source),
            dispatcher_for(clean_target),
            now,
        );
        seed_source(&mut source, &replacement_blocks);
        run_mixed_to_tip(&mut source, &mut target, expected_tip.block_id, now);
        assert_eq!(
            target
                .daemon()
                .runtime()
                .node()
                .storage()
                .parent_state_snapshot(expected_tip.block_id)
                .unwrap()
                .unwrap(),
            expected_state
        );
    }

    fn persistent_disconnect_case<S>(target_node: Node<S>)
    where
        S: RecoverableConsensusStorage,
        S::Error: Debug,
        S::MutationError: Debug,
        S::RecoveryError: Debug,
    {
        let now = 2_000_000_100;
        let mut source_node = node();
        let blocks = chain(
            &mut source_node,
            &[b"disconnect-1", b"disconnect-2", b"disconnect-3"],
        );
        let expected_tip = source_node.canonical_tip().unwrap();
        let expected_state = source_node
            .storage()
            .parent_state_snapshot(expected_tip.block_id)
            .unwrap()
            .unwrap();
        let (mut source, mut target) =
            establish_mixed(dispatcher(source_node), dispatcher_for(target_node), now);
        let ids = seed_source(&mut source, &blocks);
        for _ in 0..64 {
            pump_mixed(&mut source, &mut target, now, 1).unwrap();
            let height = target
                .daemon()
                .runtime()
                .node()
                .canonical_tip()
                .unwrap()
                .height;
            if height > 0 && height < expected_tip.height {
                break;
            }
        }
        let partial = target.daemon().runtime().node().canonical_tip().unwrap();
        assert!(partial.height > 0 && partial.height < expected_tip.height);
        source.disconnect_peer(peer(2)).unwrap();
        target.disconnect_peer(peer(1)).unwrap();
        assert_eq!(source.peers().peer_count(), 0);
        assert_eq!(target.peers().peer_count(), 0);

        connect_running_mixed(&mut source, &mut target, now);
        source.announce_blocks(peer(2), ids).unwrap();
        run_mixed_to_tip(&mut source, &mut target, expected_tip.block_id, now);
        assert_eq!(
            target
                .daemon()
                .runtime()
                .node()
                .storage()
                .parent_state_snapshot(expected_tip.block_id)
                .unwrap()
                .unwrap(),
            expected_state
        );
    }

    fn open_redb_store(path: &Path) -> RedbConsensusStore {
        let bootstrap = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        };
        let genesis = bootstrap.pinned_genesis().unwrap();
        RedbConsensusStore::open(
            path,
            genesis.block,
            genesis.metadata,
            &[],
            0,
            SupportedNetwork::Devnet.validation_parameters(),
        )
        .unwrap()
    }

    fn open_rocksdb_store(path: &Path) -> RocksdbConsensusStore {
        let bootstrap = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        };
        let genesis = bootstrap.pinned_genesis().unwrap();
        RocksdbConsensusStore::open(
            path,
            genesis.block,
            genesis.metadata,
            &[],
            0,
            SupportedNetwork::Devnet.validation_parameters(),
        )
        .unwrap()
    }

    #[test]
    fn redb_duplex_recovers_prepare_and_publish_interruptions() {
        let bootstrap = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        };
        for (fault, expected) in [
            (
                FaultPoint::AfterPrepare,
                RecoveryOutcome::RolledBackPrepared,
            ),
            (
                FaultPoint::AfterPublish,
                RecoveryOutcome::FinalizedPublished,
            ),
        ] {
            let path = persistent_path("redb-fault", Some("redb"));
            let target = bootstrap.create_redb(&path).unwrap();
            persistent_fault_case(
                target,
                fault,
                expected,
                || {
                    let mut store = open_redb_store(&path);
                    let expected_status = match fault {
                        FaultPoint::AfterPrepare => RecoveryStatus::Prepared,
                        FaultPoint::AfterPublish => RecoveryStatus::Published,
                        FaultPoint::BeforePrepare => RecoveryStatus::Clean,
                    };
                    assert_eq!(store.recovery_status(), expected_status);
                    store.recover().unwrap()
                },
                || bootstrap.open_redb(&path).unwrap(),
            );
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn rocksdb_duplex_recovers_prepare_and_publish_interruptions() {
        let bootstrap = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        };
        for (fault, expected) in [
            (
                FaultPoint::AfterPrepare,
                RecoveryOutcome::RolledBackPrepared,
            ),
            (
                FaultPoint::AfterPublish,
                RecoveryOutcome::FinalizedPublished,
            ),
        ] {
            let path = persistent_path("rocksdb-fault", None);
            let target = bootstrap.create_rocksdb(&path).unwrap();
            persistent_fault_case(
                target,
                fault,
                expected,
                || {
                    let mut store = open_rocksdb_store(&path);
                    let expected_status = match fault {
                        FaultPoint::AfterPrepare => RecoveryStatus::Prepared,
                        FaultPoint::AfterPublish => RecoveryStatus::Published,
                        FaultPoint::BeforePrepare => RecoveryStatus::Clean,
                    };
                    assert_eq!(store.recovery_status(), expected_status);
                    store.recover().unwrap()
                },
                || bootstrap.open_rocksdb(&path).unwrap(),
            );
            fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn redb_duplex_disconnect_reconnect_resumes_partial_sync() {
        let path = persistent_path("redb-disconnect", Some("redb"));
        let target = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        }
        .create_redb(&path)
        .unwrap();
        persistent_disconnect_case(target);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rocksdb_duplex_disconnect_reconnect_resumes_partial_sync() {
        let path = persistent_path("rocksdb-disconnect", None);
        let target = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        }
        .create_rocksdb(&path)
        .unwrap();
        persistent_disconnect_case(target);
        fs::remove_dir_all(path).unwrap();
    }

    fn synchronized_transcript(frames: u16) -> (Vec<DuplexTransfer>, u16) {
        let mut source = node();
        let blocks = chain(&mut source, &[b"duplex-1", b"duplex-2", b"duplex-3"]);
        let expected = source.canonical_tip().unwrap().block_id;
        let mut harness = TwoDispatcherDuplexHarness::establish(
            dispatcher(source),
            dispatcher(node()),
            peer(1),
            peer(2),
            2_000_000_100,
            policy(frames),
        )
        .unwrap();
        let ids = harness.seed_left_relay(blocks).unwrap();
        harness.announce_left_blocks(ids).unwrap();
        let rounds = harness
            .run_until_right_tip(2_000_000_100, expected)
            .unwrap();
        (harness.transcript().to_vec(), rounds)
    }

    #[test]
    fn complete_dispatchers_converge_through_remote_serving() {
        let (transcript, _) = synchronized_transcript(16);
        assert!(transcript.iter().any(|record| {
            record.direction == DuplexDirection::RightToLeft
                && record.message_type == out_p2p::TYPE_GET_HEADERS
        }));
        assert!(transcript.iter().any(|record| {
            record.direction == DuplexDirection::LeftToRight
                && record.message_type == out_p2p::TYPE_HEADERS
        }));
        assert!(transcript.iter().any(|record| {
            record.direction == DuplexDirection::RightToLeft
                && record.message_type == out_p2p::TYPE_GET_OBJECTS
        }));
        assert!(transcript.iter().any(|record| {
            record.direction == DuplexDirection::LeftToRight
                && record.message_type == out_p2p::TYPE_BLOCK
        }));
        assert!(!transcript.iter().any(|record| {
            record.direction == DuplexDirection::LeftToRight
                && record.message_type == out_p2p::TYPE_GET_HEADERS
        }));
    }

    #[test]
    fn transaction_inventory_request_response_and_admission_complete_end_to_end() {
        let transaction = vector_transaction();
        let transaction_id = transaction_id_from_canonical_bytes(&transaction.encode().unwrap());
        let mut harness = TwoDispatcherDuplexHarness::establish(
            dispatcher(funded_node()),
            dispatcher(funded_node()),
            peer(31),
            peer(32),
            2_000_000_100,
            policy(2),
        )
        .unwrap();
        assert!(matches!(
            harness
                .left_mut()
                .submit_transaction(Transaction::Regular(transaction.clone()))
                .unwrap(),
            crate::mempool::MempoolAdmission::Accepted {
                transaction_id: actual,
                ..
            } if actual == transaction_id
        ));
        harness
            .left_mut()
            .announce_transactions(peer(32), vec![transaction_id])
            .unwrap();

        for _ in 0..harness.policy.maximum_rounds {
            harness.pump_round(2_000_000_100).unwrap();
            if harness
                .right()
                .mempool()
                .unwrap()
                .transaction(transaction_id)
                .is_some()
            {
                break;
            }
        }

        assert_eq!(
            harness
                .right()
                .mempool()
                .unwrap()
                .transaction(transaction_id),
            Some(&transaction)
        );
        assert_eq!(harness.right().mempool().unwrap().transaction_count(), 1);
        assert!(harness.transcript().iter().any(|record| {
            record.direction == DuplexDirection::LeftToRight
                && record.message_type == out_p2p::TYPE_INV
        }));
        assert!(harness.transcript().iter().any(|record| {
            record.direction == DuplexDirection::RightToLeft
                && record.message_type == out_p2p::TYPE_GET_OBJECTS
                && record.request_id != 0
        }));
        assert!(harness.transcript().iter().any(|record| {
            record.direction == DuplexDirection::LeftToRight
                && record.message_type == out_p2p::TYPE_TX
                && record.request_id != 0
        }));
    }

    #[test]
    fn transcript_is_byte_stable_across_identical_runs() {
        let (first, _) = synchronized_transcript(16);
        let (second, _) = synchronized_transcript(16);
        assert_eq!(first, second);
    }

    #[test]
    fn one_frame_directional_budget_preserves_convergence_and_order() {
        let (transcript, rounds) = synchronized_transcript(1);
        assert!(rounds > 1);
        let inventory = transcript
            .iter()
            .position(|record| record.message_type == out_p2p::TYPE_INV)
            .unwrap();
        let object = transcript
            .iter()
            .position(|record| record.message_type == out_p2p::TYPE_GET_OBJECTS)
            .unwrap();
        assert!(inventory < object);
    }

    #[test]
    fn longer_remote_fork_reorganizes_target_through_full_path() {
        let mut source = node();
        let source_blocks = chain(&mut source, &[b"fork-b1", b"fork-b2", b"fork-b3"]);
        let expected = source.canonical_tip().unwrap();
        let mut target = node();
        let target_blocks = chain(&mut target, &[b"fork-a1"]);
        let old_tip = block_id_from_header_bytes(&target_blocks[0].header.encode());
        let mut harness = TwoDispatcherDuplexHarness::establish(
            dispatcher(source),
            dispatcher(target),
            peer(11),
            peer(12),
            2_000_000_100,
            policy(2),
        )
        .unwrap();
        let ids = harness.seed_left_relay(source_blocks).unwrap();
        harness.announce_left_blocks(ids).unwrap();
        harness
            .run_until_right_tip(2_000_000_100, expected.block_id)
            .unwrap();
        let actual = harness
            .right()
            .daemon()
            .runtime()
            .node()
            .canonical_tip()
            .unwrap();
        assert_eq!(actual, expected);
        assert_ne!(actual.block_id, old_tip);
    }

    #[test]
    fn announcement_validation_is_atomic_and_refuses_stale_relay() {
        let mut source = node();
        let blocks = chain(&mut source, &[b"old-tip"]);
        let old_id = block_id_from_header_bytes(&blocks[0].header.encode());
        let mut harness = TwoDispatcherDuplexHarness::establish(
            dispatcher(source),
            dispatcher(node()),
            peer(21),
            peer(22),
            2_000_000_100,
            policy(4),
        )
        .unwrap();
        assert!(matches!(
            harness.announce_left_blocks(vec![old_id]),
            Err(DuplexHarnessError::Dispatcher(error))
                if matches!(*error, DispatcherError::Announcement(AnnouncementError::BlockNotRelayed(id)) if id == old_id)
        ));
        harness.seed_left_relay(blocks).unwrap();
        assert!(matches!(
            harness.announce_left_blocks(vec![old_id, old_id]),
            Err(DuplexHarnessError::Dispatcher(error))
                if matches!(*error, DispatcherError::Announcement(AnnouncementError::Duplicate(_)))
        ));

        let genesis = harness
            .left()
            .daemon()
            .runtime()
            .node()
            .storage()
            .canonical_tip()
            .unwrap();
        let genesis_id = harness
            .left()
            .daemon()
            .runtime()
            .node()
            .storage()
            .get_validated_header(genesis.block_id)
            .unwrap()
            .unwrap()
            .header()
            .parent_block_id;
        let genesis_id = if genesis.height == 0 {
            genesis.block_id
        } else {
            genesis_id
        };
        let first = append(
            harness.left_mut().daemon_mut().runtime_mut().node_mut(),
            genesis_id,
            b"new-fork-1",
        );
        let first_id = block_id_from_header_bytes(&first.header.encode());
        append(
            harness.left_mut().daemon_mut().runtime_mut().node_mut(),
            first_id,
            b"new-fork-2",
        );
        assert!(matches!(
            harness.announce_left_blocks(vec![old_id]),
            Err(DuplexHarnessError::Dispatcher(error))
                if matches!(*error, DispatcherError::Announcement(AnnouncementError::BlockNotCanonical(id)) if id == old_id)
        ));
    }
}
