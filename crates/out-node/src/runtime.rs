//! Pure transport-independent node event loop.
//!
//! The runtime owns no clock, socket, thread, process signal, or host service.
//! Callers provide monotonic ticks, peer sessions, and complete frame bytes.

use std::collections::{BTreeMap, VecDeque};

use out_p2p::session::{PeerSession, SessionAction, SessionError};
use out_p2p::{
    decode_frame_exact, DecodeError, InventoryEntry, Message, P2pNetwork, FRAME_HEADER_BYTES,
    MAX_P2P_PAYLOAD_BYTES, PROTOCOL_VERSION_V0,
};
use out_primitives::BlockId;
use out_storage::{RecoverableConsensusStorage, RecoveryOutcome, RecoveryStatus};

use crate::peers::PeerId;
use crate::{Node, SupportedNetwork};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePhase {
    Starting,
    Recovering,
    Running,
    Draining,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimePolicy {
    pub maximum_peers: u16,
    pub maximum_inbound_events: u16,
    pub maximum_inbound_bytes: u64,
    pub maximum_frame_bytes: u32,
    pub maximum_output_events: u16,
    pub maximum_inbound_events_per_step: u16,
    pub maximum_peer_polls_per_step: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePolicyError {
    Zero(&'static str),
    PerStepInboundAboveQueue,
    PerStepPeersAboveMaximum,
    FrameAboveProtocolMaximum { actual: u32, maximum: u32 },
}

impl RuntimePolicy {
    pub fn validate(self) -> Result<Self, RuntimePolicyError> {
        let nonzero = [
            (u64::from(self.maximum_peers), "maximum_peers"),
            (
                u64::from(self.maximum_inbound_events),
                "maximum_inbound_events",
            ),
            (self.maximum_inbound_bytes, "maximum_inbound_bytes"),
            (u64::from(self.maximum_frame_bytes), "maximum_frame_bytes"),
            (
                u64::from(self.maximum_output_events),
                "maximum_output_events",
            ),
            (
                u64::from(self.maximum_inbound_events_per_step),
                "maximum_inbound_events_per_step",
            ),
            (
                u64::from(self.maximum_peer_polls_per_step),
                "maximum_peer_polls_per_step",
            ),
        ];
        if let Some((_, field)) = nonzero.into_iter().find(|(value, _)| *value == 0) {
            return Err(RuntimePolicyError::Zero(field));
        }
        if self.maximum_inbound_events_per_step > self.maximum_inbound_events {
            return Err(RuntimePolicyError::PerStepInboundAboveQueue);
        }
        if self.maximum_peer_polls_per_step > self.maximum_peers {
            return Err(RuntimePolicyError::PerStepPeersAboveMaximum);
        }
        let protocol_maximum = u32::try_from(FRAME_HEADER_BYTES)
            .unwrap_or(u32::MAX)
            .saturating_add(MAX_P2P_PAYLOAD_BYTES);
        if self.maximum_frame_bytes > protocol_maximum {
            return Err(RuntimePolicyError::FrameAboveProtocolMaximum {
                actual: self.maximum_frame_bytes,
                maximum: protocol_maximum,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InboundFrame {
    peer_id: PeerId,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeOutput {
    SessionActions {
        peer_id: PeerId,
        actions: Vec<SessionAction>,
    },
    FrameRejected {
        peer_id: PeerId,
        error: DecodeError,
    },
    SessionFailed {
        peer_id: PeerId,
        error: SessionError,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeCommand {
    BeginHeaders {
        now: u64,
        locator: Vec<BlockId>,
        stop_id: BlockId,
    },
    BeginObject {
        now: u64,
        request_id: u64,
        object: InventoryEntry,
    },
    SendResponse {
        request_id: u64,
        message: Box<Message>,
    },
    AnnounceInventory {
        entries: Vec<InventoryEntry>,
    },
    ReportInvalidHeaders,
    ReportInvalidTransaction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCommandOutcome {
    pub request_id: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError<RecoveryError> {
    Policy(RuntimePolicyError),
    WrongPhase {
        expected: &'static str,
        actual: RuntimePhase,
    },
    Recovery(RecoveryError),
    RecoveryIncomplete(RecoveryStatus),
    DuplicatePeer(PeerId),
    UnknownPeer(PeerId),
    PeerCapacity {
        maximum: u16,
    },
    PeerNetworkMismatch(PeerId),
    InitialOutputCapacity {
        maximum: u16,
    },
    OutputCapacity {
        maximum: u16,
    },
    SessionCommand {
        peer_id: PeerId,
        error: SessionError,
    },
    InboundEventCapacity {
        maximum: u16,
    },
    InboundByteCapacity {
        maximum: u64,
    },
    FrameTooLarge {
        actual: usize,
        maximum: u32,
    },
    ByteAccounting,
    ClockRegression {
        previous: u64,
        actual: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeStep {
    pub peer_polls: u16,
    pub inbound_events: u16,
    pub output_events_added: u16,
    pub phase: RuntimePhase,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimePeerRemoval {
    pub discarded_inbound_events: u16,
    pub discarded_inbound_bytes: u64,
    pub discarded_output_events: u16,
}

pub struct NodeRuntime<S: RecoverableConsensusStorage> {
    node: Node<S>,
    network: P2pNetwork,
    policy: RuntimePolicy,
    phase: RuntimePhase,
    peers: BTreeMap<PeerId, PeerSession>,
    inbound: VecDeque<InboundFrame>,
    inbound_bytes: u64,
    output: VecDeque<RuntimeOutput>,
    last_tick: Option<u64>,
}

impl<S: RecoverableConsensusStorage> NodeRuntime<S> {
    pub fn new(
        node: Node<S>,
        policy: RuntimePolicy,
    ) -> Result<Self, RuntimeError<S::RecoveryError>> {
        let policy = policy.validate().map_err(RuntimeError::Policy)?;
        let network = match node.config().network {
            SupportedNetwork::Testnet => P2pNetwork::Testnet,
            SupportedNetwork::Devnet => P2pNetwork::Devnet,
        };
        Ok(Self {
            node,
            network,
            policy,
            phase: RuntimePhase::Starting,
            peers: BTreeMap::new(),
            inbound: VecDeque::new(),
            inbound_bytes: 0,
            output: VecDeque::new(),
            last_tick: None,
        })
    }

    pub const fn phase(&self) -> RuntimePhase {
        self.phase
    }

    pub const fn node(&self) -> &Node<S> {
        &self.node
    }

    pub fn node_mut(&mut self) -> &mut Node<S> {
        &mut self.node
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn contains_peer(&self, peer_id: PeerId) -> bool {
        self.peers.contains_key(&peer_id)
    }

    pub fn inbound_event_count(&self) -> usize {
        self.inbound.len()
    }

    pub const fn inbound_bytes(&self) -> u64 {
        self.inbound_bytes
    }

    pub fn output_event_count(&self) -> usize {
        self.output.len()
    }

    pub const fn policy(&self) -> RuntimePolicy {
        self.policy
    }

    pub fn front_output(&self) -> Option<&RuntimeOutput> {
        self.output.front()
    }

    pub fn command_capacity_available(&self) -> bool {
        self.phase == RuntimePhase::Running
            && self.output.len() < usize::from(self.policy.maximum_output_events)
    }

    pub fn start(&mut self) -> Result<RuntimePhase, RuntimeError<S::RecoveryError>> {
        if self.phase != RuntimePhase::Starting {
            return Err(RuntimeError::WrongPhase {
                expected: "starting",
                actual: self.phase,
            });
        }
        self.phase = if self.node.recovery_status() == RecoveryStatus::Clean {
            RuntimePhase::Running
        } else {
            RuntimePhase::Recovering
        };
        Ok(self.phase)
    }

    pub fn recover_storage(&mut self) -> Result<RecoveryOutcome, RuntimeError<S::RecoveryError>> {
        if self.phase != RuntimePhase::Recovering {
            return Err(RuntimeError::WrongPhase {
                expected: "recovering",
                actual: self.phase,
            });
        }
        let outcome = self
            .node
            .recover_storage()
            .map_err(RuntimeError::Recovery)?;
        let status = self.node.recovery_status();
        if status != RecoveryStatus::Clean {
            return Err(RuntimeError::RecoveryIncomplete(status));
        }
        self.phase = RuntimePhase::Running;
        Ok(outcome)
    }

    pub fn register_peer(
        &mut self,
        peer_id: PeerId,
        session: PeerSession,
        initial_actions: Vec<SessionAction>,
    ) -> Result<(), RuntimeError<S::RecoveryError>> {
        self.require_running()?;
        if session.network() != self.network {
            return Err(RuntimeError::PeerNetworkMismatch(peer_id));
        }
        if self.peers.contains_key(&peer_id) {
            return Err(RuntimeError::DuplicatePeer(peer_id));
        }
        if self.peers.len() >= usize::from(self.policy.maximum_peers) {
            return Err(RuntimeError::PeerCapacity {
                maximum: self.policy.maximum_peers,
            });
        }
        let available =
            usize::from(self.policy.maximum_output_events).saturating_sub(self.output.len());
        if !initial_actions.is_empty() && available == 0 {
            return Err(RuntimeError::InitialOutputCapacity {
                maximum: self.policy.maximum_output_events,
            });
        }
        self.peers.insert(peer_id, session);
        if !initial_actions.is_empty() {
            self.output.push_back(RuntimeOutput::SessionActions {
                peer_id,
                actions: initial_actions,
            });
        }
        Ok(())
    }

    /// Removes one peer and all of its already-admitted disposable work. Work
    /// for every other peer retains exact FIFO order. The returned accounting
    /// makes the discard explicit to the application layer.
    pub fn unregister_peer(
        &mut self,
        peer_id: PeerId,
    ) -> Result<RuntimePeerRemoval, RuntimeError<S::RecoveryError>> {
        self.require_running()?;
        if !self.peers.contains_key(&peer_id) {
            return Err(RuntimeError::UnknownPeer(peer_id));
        }
        let mut removal = RuntimePeerRemoval::default();
        for frame in self.inbound.iter().filter(|frame| frame.peer_id == peer_id) {
            removal.discarded_inbound_events = removal
                .discarded_inbound_events
                .checked_add(1)
                .ok_or(RuntimeError::ByteAccounting)?;
            let length =
                u64::try_from(frame.bytes.len()).map_err(|_| RuntimeError::ByteAccounting)?;
            removal.discarded_inbound_bytes = removal
                .discarded_inbound_bytes
                .checked_add(length)
                .ok_or(RuntimeError::ByteAccounting)?;
        }
        for output in &self.output {
            let output_peer = match output {
                RuntimeOutput::SessionActions { peer_id, .. }
                | RuntimeOutput::FrameRejected { peer_id, .. }
                | RuntimeOutput::SessionFailed { peer_id, .. } => *peer_id,
            };
            if output_peer == peer_id {
                removal.discarded_output_events = removal
                    .discarded_output_events
                    .checked_add(1)
                    .ok_or(RuntimeError::ByteAccounting)?;
            }
        }
        self.peers.remove(&peer_id);
        self.inbound.retain(|frame| frame.peer_id != peer_id);
        self.inbound_bytes = self
            .inbound_bytes
            .checked_sub(removal.discarded_inbound_bytes)
            .ok_or(RuntimeError::ByteAccounting)?;
        self.output.retain(|output| match output {
            RuntimeOutput::SessionActions {
                peer_id: output_peer,
                ..
            }
            | RuntimeOutput::FrameRejected {
                peer_id: output_peer,
                ..
            }
            | RuntimeOutput::SessionFailed {
                peer_id: output_peer,
                ..
            } => *output_peer != peer_id,
        });
        Ok(removal)
    }

    pub fn enqueue_frame(
        &mut self,
        peer_id: PeerId,
        bytes: Vec<u8>,
    ) -> Result<(), RuntimeError<S::RecoveryError>> {
        self.check_frame_admission(peer_id, bytes.len())?;
        let length = u64::try_from(bytes.len()).map_err(|_| RuntimeError::InboundByteCapacity {
            maximum: self.policy.maximum_inbound_bytes,
        })?;
        let total =
            self.inbound_bytes
                .checked_add(length)
                .ok_or(RuntimeError::InboundByteCapacity {
                    maximum: self.policy.maximum_inbound_bytes,
                })?;
        self.inbound.push_back(InboundFrame { peer_id, bytes });
        self.inbound_bytes = total;
        Ok(())
    }

    pub fn check_frame_admission(
        &self,
        peer_id: PeerId,
        byte_length: usize,
    ) -> Result<(), RuntimeError<S::RecoveryError>> {
        self.require_running()?;
        if !self.peers.contains_key(&peer_id) {
            return Err(RuntimeError::UnknownPeer(peer_id));
        }
        if byte_length > usize::try_from(self.policy.maximum_frame_bytes).unwrap_or(usize::MAX) {
            return Err(RuntimeError::FrameTooLarge {
                actual: byte_length,
                maximum: self.policy.maximum_frame_bytes,
            });
        }
        if self.inbound.len() >= usize::from(self.policy.maximum_inbound_events) {
            return Err(RuntimeError::InboundEventCapacity {
                maximum: self.policy.maximum_inbound_events,
            });
        }
        let length = u64::try_from(byte_length).map_err(|_| RuntimeError::InboundByteCapacity {
            maximum: self.policy.maximum_inbound_bytes,
        })?;
        let total =
            self.inbound_bytes
                .checked_add(length)
                .ok_or(RuntimeError::InboundByteCapacity {
                    maximum: self.policy.maximum_inbound_bytes,
                })?;
        if total > self.policy.maximum_inbound_bytes {
            return Err(RuntimeError::InboundByteCapacity {
                maximum: self.policy.maximum_inbound_bytes,
            });
        }
        Ok(())
    }

    /// Applies one typed local command to a peer session and atomically queues
    /// its resulting actions. Callers never receive mutable session access.
    pub fn execute_command(
        &mut self,
        peer_id: PeerId,
        command: RuntimeCommand,
    ) -> Result<RuntimeCommandOutcome, RuntimeError<S::RecoveryError>> {
        self.require_running()?;
        if self.output.len() >= usize::from(self.policy.maximum_output_events) {
            return Err(RuntimeError::OutputCapacity {
                maximum: self.policy.maximum_output_events,
            });
        }
        let session = self
            .peers
            .get_mut(&peer_id)
            .ok_or(RuntimeError::UnknownPeer(peer_id))?;
        let (actions, request_id) = match command {
            RuntimeCommand::BeginHeaders {
                now,
                locator,
                stop_id,
            } => {
                let action = session
                    .begin_headers_request(now, locator, stop_id)
                    .map_err(|error| RuntimeError::SessionCommand { peer_id, error })?;
                let SessionAction::Send { request_id, .. } = action else {
                    return Err(RuntimeError::SessionCommand {
                        peer_id,
                        error: SessionError::InvalidResponseType,
                    });
                };
                (vec![action], Some(request_id))
            }
            RuntimeCommand::BeginObject {
                now,
                request_id,
                object,
            } => {
                let action = session
                    .begin_object_request(now, request_id, object)
                    .map_err(|error| RuntimeError::SessionCommand { peer_id, error })?;
                (vec![action], Some(request_id))
            }
            RuntimeCommand::SendResponse {
                request_id,
                message,
            } => {
                let action = session
                    .make_response(request_id, *message)
                    .map_err(|error| RuntimeError::SessionCommand { peer_id, error })?;
                (vec![action], Some(request_id))
            }
            RuntimeCommand::AnnounceInventory { entries } => {
                let action = session
                    .announce_inventory(entries)
                    .map_err(|error| RuntimeError::SessionCommand { peer_id, error })?;
                (vec![action], None)
            }
            RuntimeCommand::ReportInvalidHeaders => {
                let actions = session
                    .report_invalid_header_batch()
                    .map_err(|error| RuntimeError::SessionCommand { peer_id, error })?;
                (actions, None)
            }
            RuntimeCommand::ReportInvalidTransaction => {
                let actions = session
                    .report_invalid_transaction()
                    .map_err(|error| RuntimeError::SessionCommand { peer_id, error })?;
                (actions, None)
            }
        };
        if !actions.is_empty() {
            self.output
                .push_back(RuntimeOutput::SessionActions { peer_id, actions });
        }
        Ok(RuntimeCommandOutcome { request_id })
    }

    pub fn step(&mut self, now: u64) -> Result<RuntimeStep, RuntimeError<S::RecoveryError>> {
        if !matches!(self.phase, RuntimePhase::Running | RuntimePhase::Draining) {
            return Err(RuntimeError::WrongPhase {
                expected: "running or draining",
                actual: self.phase,
            });
        }
        if let Some(previous) = self.last_tick {
            if now < previous {
                return Err(RuntimeError::ClockRegression {
                    previous,
                    actual: now,
                });
            }
        }
        self.last_tick = Some(now);
        let initial_output = self.output.len();
        let mut peer_polls = 0_u16;
        let mut inbound_events = 0_u16;

        if self.phase == RuntimePhase::Running {
            let peer_ids: Vec<PeerId> = self.peers.keys().copied().collect();
            for peer_id in peer_ids {
                if peer_polls >= self.policy.maximum_peer_polls_per_step
                    || self.output.len() >= usize::from(self.policy.maximum_output_events)
                {
                    break;
                }
                let actions = self
                    .peers
                    .get_mut(&peer_id)
                    .ok_or(RuntimeError::UnknownPeer(peer_id))?
                    .poll_timeouts(now);
                peer_polls = peer_polls.saturating_add(1);
                match actions {
                    Ok(actions) if !actions.is_empty() => {
                        self.output
                            .push_back(RuntimeOutput::SessionActions { peer_id, actions });
                    }
                    Ok(_) => {}
                    Err(error) => {
                        self.output
                            .push_back(RuntimeOutput::SessionFailed { peer_id, error });
                    }
                }
            }
        }

        while inbound_events < self.policy.maximum_inbound_events_per_step
            && self.output.len() < usize::from(self.policy.maximum_output_events)
        {
            let Some(inbound) = self.inbound.pop_front() else {
                break;
            };
            let length =
                u64::try_from(inbound.bytes.len()).map_err(|_| RuntimeError::ByteAccounting)?;
            self.inbound_bytes = self
                .inbound_bytes
                .checked_sub(length)
                .ok_or(RuntimeError::ByteAccounting)?;
            inbound_events = inbound_events.saturating_add(1);
            let frame = match decode_frame_exact(&inbound.bytes, self.network, PROTOCOL_VERSION_V0)
            {
                Ok(frame) => frame,
                Err(error) => {
                    self.output.push_back(RuntimeOutput::FrameRejected {
                        peer_id: inbound.peer_id,
                        error,
                    });
                    continue;
                }
            };
            let result = self
                .peers
                .get_mut(&inbound.peer_id)
                .ok_or(RuntimeError::UnknownPeer(inbound.peer_id))?
                .handle_inbound(now, frame);
            match result {
                Ok(actions) => self.output.push_back(RuntimeOutput::SessionActions {
                    peer_id: inbound.peer_id,
                    actions,
                }),
                Err(error) => self.output.push_back(RuntimeOutput::SessionFailed {
                    peer_id: inbound.peer_id,
                    error,
                }),
            }
        }
        self.finish_draining();
        let added = self.output.len().saturating_sub(initial_output);
        Ok(RuntimeStep {
            peer_polls,
            inbound_events,
            output_events_added: u16::try_from(added).unwrap_or(u16::MAX),
            phase: self.phase,
        })
    }

    pub fn pop_output(&mut self) -> Option<RuntimeOutput> {
        let output = self.output.pop_front();
        self.finish_draining();
        output
    }

    pub fn request_shutdown(&mut self) -> Result<(), RuntimeError<S::RecoveryError>> {
        if self.phase != RuntimePhase::Running {
            return Err(RuntimeError::WrongPhase {
                expected: "running",
                actual: self.phase,
            });
        }
        self.phase = RuntimePhase::Draining;
        self.finish_draining();
        Ok(())
    }

    fn require_running(&self) -> Result<(), RuntimeError<S::RecoveryError>> {
        if self.phase == RuntimePhase::Running {
            Ok(())
        } else {
            Err(RuntimeError::WrongPhase {
                expected: "running",
                actual: self.phase,
            })
        }
    }

    fn finish_draining(&mut self) {
        if self.phase == RuntimePhase::Draining && self.inbound.is_empty() && self.output.is_empty()
        {
            self.phase = RuntimePhase::Stopped;
        }
    }
}

#[cfg(test)]
mod tests {
    use out_codec::Block;
    use out_p2p::session::{SessionPolicy, SessionRole};
    use out_p2p::{encode_frame, Hello, Message};
    use out_storage::conformance::validated_reward_commit;
    use out_storage::{FaultPoint, InMemoryConsensusStore};

    use super::*;
    use crate::bootstrap::NodeBootstrap;

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

    fn policy() -> RuntimePolicy {
        RuntimePolicy {
            maximum_peers: 4,
            maximum_inbound_events: 4,
            maximum_inbound_bytes: 1_000_000,
            maximum_frame_bytes: 100_000,
            maximum_output_events: 4,
            maximum_inbound_events_per_step: 4,
            maximum_peer_polls_per_step: 4,
        }
    }

    fn session_policy() -> SessionPolicy {
        SessionPolicy {
            handshake_timeout_ticks: 10,
            response_timeout_ticks: 10,
            maximum_outstanding_requests: 4,
            disconnect_score: 100,
            protocol_violation_score: 20,
            unexpected_response_score: 10,
            timeout_score: 5,
        }
    }

    fn hello() -> Hello {
        let node = node();
        let tip = node.canonical_tip().expect("tip");
        let identity = SupportedNetwork::Devnet.identity();
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

    fn inbound_session(now: u64) -> PeerSession {
        PeerSession::new(
            SessionRole::Inbound,
            P2pNetwork::Devnet,
            hello(),
            now,
            session_policy(),
        )
        .expect("session")
        .0
    }

    fn running_runtime(custom: RuntimePolicy) -> NodeRuntime<InMemoryConsensusStore> {
        let mut runtime = NodeRuntime::new(node(), custom).expect("runtime");
        assert_eq!(runtime.start(), Ok(RuntimePhase::Running));
        runtime
    }

    #[test]
    fn recovery_gate_rejects_peer_work_until_storage_is_clean() {
        let mut damaged = node();
        let genesis = damaged.canonical_tip().unwrap().block_id;
        let commit = validated_reward_commit(damaged.storage(), genesis, b"runtime-recovery");
        let raw = commit.canonical_block_bytes().to_vec();
        let block = Block::decode_non_genesis_exact(&raw).unwrap();
        damaged
            .storage_mut()
            .inject_fault_once(FaultPoint::AfterPrepare)
            .unwrap();
        assert!(damaged.process_block(&raw, block.header.timestamp).is_err());
        let mut runtime = NodeRuntime::new(damaged, policy()).unwrap();
        assert_eq!(runtime.start(), Ok(RuntimePhase::Recovering));
        assert!(matches!(
            runtime.register_peer(peer(1), inbound_session(0), Vec::new()),
            Err(RuntimeError::WrongPhase {
                actual: RuntimePhase::Recovering,
                ..
            })
        ));
        assert_eq!(
            runtime.recover_storage(),
            Ok(RecoveryOutcome::RolledBackPrepared)
        );
        assert_eq!(runtime.phase(), RuntimePhase::Running);
        runtime
            .register_peer(peer(1), inbound_session(0), Vec::new())
            .unwrap();
    }

    #[test]
    fn inbound_frames_are_fifo_and_output_backpressure_is_lossless() {
        let mut bounded = policy();
        bounded.maximum_output_events = 1;
        let mut runtime = running_runtime(bounded);
        runtime
            .register_peer(peer(1), inbound_session(0), Vec::new())
            .unwrap();
        runtime
            .register_peer(peer(2), inbound_session(0), Vec::new())
            .unwrap();
        let first = encode_frame(P2pNetwork::Devnet, 0, &Message::Hello(hello())).unwrap();
        let second = first.clone();
        runtime.enqueue_frame(peer(2), first).unwrap();
        runtime.enqueue_frame(peer(1), second).unwrap();
        let step = runtime.step(1).unwrap();
        assert_eq!(step.inbound_events, 1);
        assert_eq!(runtime.inbound_event_count(), 1);
        assert!(
            matches!(runtime.pop_output(), Some(RuntimeOutput::SessionActions { peer_id, .. }) if peer_id == peer(2))
        );
        runtime.step(1).unwrap();
        assert!(
            matches!(runtime.pop_output(), Some(RuntimeOutput::SessionActions { peer_id, .. }) if peer_id == peer(1))
        );
        assert_eq!(runtime.inbound_bytes(), 0);
    }

    #[test]
    fn malformed_frame_is_reported_without_panicking_or_reaching_session() {
        let mut runtime = running_runtime(policy());
        runtime
            .register_peer(peer(1), inbound_session(0), Vec::new())
            .unwrap();
        runtime.enqueue_frame(peer(1), vec![0; 8]).unwrap();
        runtime.step(1).unwrap();
        assert!(matches!(
            runtime.pop_output(),
            Some(RuntimeOutput::FrameRejected {
                peer_id,
                error: DecodeError::HeaderLength { actual: 8 }
            }) if peer_id == peer(1)
        ));
    }

    #[test]
    fn inbound_count_and_byte_limits_fail_without_partial_enqueue() {
        let mut bounded = policy();
        bounded.maximum_inbound_events = 1;
        bounded.maximum_inbound_events_per_step = 1;
        bounded.maximum_inbound_bytes = 4;
        bounded.maximum_frame_bytes = 4;
        let mut runtime = running_runtime(bounded);
        runtime
            .register_peer(peer(1), inbound_session(0), Vec::new())
            .unwrap();
        runtime.enqueue_frame(peer(1), vec![1, 2, 3, 4]).unwrap();
        assert!(matches!(
            runtime.enqueue_frame(peer(1), vec![5]),
            Err(RuntimeError::InboundEventCapacity { maximum: 1 })
        ));
        assert_eq!(runtime.inbound_event_count(), 1);
        assert_eq!(runtime.inbound_bytes(), 4);
        assert!(matches!(
            runtime.enqueue_frame(peer(1), vec![0; 5]),
            Err(RuntimeError::FrameTooLarge {
                actual: 5,
                maximum: 4
            })
        ));
    }

    #[test]
    fn timeout_polling_is_peer_id_ordered_and_clock_is_monotonic() {
        let mut runtime = running_runtime(policy());
        runtime
            .register_peer(peer(2), inbound_session(0), Vec::new())
            .unwrap();
        runtime
            .register_peer(peer(1), inbound_session(0), Vec::new())
            .unwrap();
        runtime.step(10).unwrap();
        assert!(
            matches!(runtime.pop_output(), Some(RuntimeOutput::SessionActions { peer_id, .. }) if peer_id == peer(1))
        );
        assert!(
            matches!(runtime.pop_output(), Some(RuntimeOutput::SessionActions { peer_id, .. }) if peer_id == peer(2))
        );
        assert_eq!(
            runtime.step(9),
            Err(RuntimeError::ClockRegression {
                previous: 10,
                actual: 9,
            })
        );
    }

    #[test]
    fn graceful_shutdown_drains_existing_work_and_rejects_new_work() {
        let mut runtime = running_runtime(policy());
        runtime
            .register_peer(peer(1), inbound_session(0), Vec::new())
            .unwrap();
        let bytes = encode_frame(P2pNetwork::Devnet, 0, &Message::Hello(hello())).unwrap();
        runtime.enqueue_frame(peer(1), bytes).unwrap();
        runtime.request_shutdown().unwrap();
        assert_eq!(runtime.phase(), RuntimePhase::Draining);
        assert!(matches!(
            runtime.enqueue_frame(peer(1), vec![0]),
            Err(RuntimeError::WrongPhase {
                actual: RuntimePhase::Draining,
                ..
            })
        ));
        runtime.step(1).unwrap();
        assert_eq!(runtime.phase(), RuntimePhase::Draining);
        assert!(runtime.pop_output().is_some());
        assert_eq!(runtime.phase(), RuntimePhase::Stopped);
    }

    #[test]
    fn policy_rejects_zero_and_protocol_oversize_frame_budget() {
        let mut invalid = policy();
        invalid.maximum_peers = 0;
        assert_eq!(
            invalid.validate(),
            Err(RuntimePolicyError::Zero("maximum_peers"))
        );
        invalid = policy();
        invalid.maximum_frame_bytes = 4_194_359;
        assert_eq!(
            invalid.validate(),
            Err(RuntimePolicyError::FrameAboveProtocolMaximum {
                actual: 4_194_359,
                maximum: 4_194_358,
            })
        );
    }
}
