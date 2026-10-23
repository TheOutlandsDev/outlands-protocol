//! Three-node, socket-free integration of sessions, multi-peer scheduling,
//! header sync, block delivery, orphan retention, consensus, and storage.

use std::collections::BTreeMap;

use out_codec::{Block, DecodeError as ConsensusDecodeError};
use out_consensus::block_id_from_header_bytes;
use out_consensus::chain::ValidatedHeaderView;
use out_p2p::session::{
    HeaderBatch, HeaderSync, HeaderSyncError, PeerSession, SessionAction, SessionError,
    SessionPhase, SessionPolicy, SessionRole,
};
use out_p2p::{
    decode_frame_exact, encode_frame, DecodeError, EncodeError, Hello, InventoryEntry, Message,
    P2pNetwork, MAX_HEADERS, MAX_INV_ENTRIES, PROTOCOL_VERSION_V0, TYPE_GET_OBJECTS,
};
use out_primitives::BlockId;
use out_storage::{InMemoryConsensusStore, InMemoryMutationError, InMemoryReadError};

use crate::peers::{
    BoundedMemoryTransport, MemoryTransportError, MemoryTransportPolicy, MultiPeerCoordinator,
    MultiPeerError, MultiPeerPolicy, OrphanAdmission, PeerId, RequestAssignment, RetryOutcome,
    RetryReason,
};
use crate::sync::{
    BeginBlockRequestError, BlockDeliveryFailure, BlockDeliveryLocal, BlockDeliveryOutcome,
    HeaderBatchFailure, HeaderBatchOutcome, LocatorError, SyncCoordinator, SyncOpenError,
    SyncPolicy,
};
use crate::{Node, SupportedNetwork};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultiTransferDirection {
    TargetToRemote,
    RemoteToTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiTransferRecord {
    pub peer_id: PeerId,
    pub direction: MultiTransferDirection,
    pub request_id: u64,
    pub message_type: u16,
    pub frame_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreeNodeHarnessPolicy {
    pub session: SessionPolicy,
    pub sync: SyncPolicy,
    pub peers: MultiPeerPolicy,
    pub transport: MemoryTransportPolicy,
    pub maximum_remote_blocks: u16,
    pub maximum_headers_per_response: u16,
    pub maximum_header_rounds: u16,
    pub first_replay_request_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultiHarnessError {
    ZeroPolicy(&'static str),
    HeaderResponseAboveWireMaximum {
        actual: u16,
        maximum: u16,
    },
    Read(InMemoryReadError),
    SyncOpen(SyncOpenError<InMemoryReadError>),
    MultiPeer(MultiPeerError),
    Transport(MemoryTransportError),
    Session(SessionError),
    Encode(EncodeError),
    Decode(DecodeError),
    ConsensusDecode(ConsensusDecodeError),
    UnexpectedAction,
    HandshakeRejected(PeerId),
    DuplicatePeer(PeerId),
    RemoteCapacity {
        peer_id: PeerId,
        actual: usize,
        maximum: u16,
    },
    RemoteGenesis(PeerId),
    RemoteBlockNotStored {
        peer_id: PeerId,
        block_id: BlockId,
    },
    RemoteBlockNotCanonical {
        peer_id: PeerId,
        block_id: BlockId,
    },
    RemoteHeaderMismatch {
        peer_id: PeerId,
        block_id: BlockId,
    },
    DuplicateRemoteBlock {
        peer_id: PeerId,
        block_id: BlockId,
    },
    UnknownPeer(PeerId),
    MissingCommonAncestor(PeerId),
    HeaderSync(HeaderSyncError),
    HeaderBatch(HeaderBatchFailure<InMemoryReadError>),
    Locator(LocatorError<InMemoryReadError>),
    HeaderRoundLimit {
        maximum: u16,
    },
    NonBlockAssignment(InventoryEntry),
    SyncReservation(BeginBlockRequestError),
    MissingRemoteBlock {
        peer_id: PeerId,
        block_id: BlockId,
    },
    AssignmentMismatch,
    BlockDelivery(BlockDeliveryFailure<InMemoryReadError, InMemoryMutationError>),
    ReplayRequestIdExhausted,
    OrphanWasNotStored(BlockId),
}

pub struct SimulatedRemote {
    pub peer_id: PeerId,
    pub node: Node<InMemoryConsensusStore>,
    pub blocks: Vec<Block>,
}

struct RemoteLink {
    node: Node<InMemoryConsensusStore>,
    blocks: BTreeMap<BlockId, Block>,
    canonical_order: Vec<BlockId>,
    target_session: PeerSession,
    remote_session: PeerSession,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteBehavior {
    Withhold,
    Reject { code: u16, detail: Vec<u8> },
    Deliver,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteStepOutcome {
    Withheld(RequestAssignment),
    Rejected {
        assignment: RequestAssignment,
        retry: RetryOutcome,
    },
    Stored {
        assignment: RequestAssignment,
        delivery: BlockDeliveryOutcome,
    },
    Orphaned {
        assignment: RequestAssignment,
        block_id: BlockId,
        parent_block_id: BlockId,
    },
}

pub struct ThreeNodeHarness {
    target: Node<InMemoryConsensusStore>,
    sync: SyncCoordinator,
    peers: MultiPeerCoordinator,
    links: BTreeMap<PeerId, RemoteLink>,
    transport: BoundedMemoryTransport,
    transcript: Vec<MultiTransferRecord>,
    policy: ThreeNodeHarnessPolicy,
    next_replay_request_id: u64,
}

impl ThreeNodeHarness {
    pub fn establish(
        target: Node<InMemoryConsensusStore>,
        remotes: [SimulatedRemote; 2],
        now: u64,
        policy: ThreeNodeHarnessPolicy,
    ) -> Result<Self, MultiHarnessError> {
        validate_policy(policy)?;
        let sync = SyncCoordinator::new(target.storage(), target.config().network, policy.sync)
            .map_err(MultiHarnessError::SyncOpen)?;
        let peers =
            MultiPeerCoordinator::new(policy.peers).map_err(MultiHarnessError::MultiPeer)?;
        let transport =
            BoundedMemoryTransport::new(policy.transport).map_err(MultiHarnessError::Transport)?;
        let target_hello = node_hello(&target)?;
        let target_network = p2p_network(target.config().network);
        let mut harness = Self {
            target,
            sync,
            peers,
            links: BTreeMap::new(),
            transport,
            transcript: Vec::new(),
            policy,
            next_replay_request_id: policy.first_replay_request_id,
        };

        for remote in remotes {
            if harness.links.contains_key(&remote.peer_id) {
                return Err(MultiHarnessError::DuplicatePeer(remote.peer_id));
            }
            let (blocks, canonical_order) = build_catalog(
                remote.peer_id,
                &remote.node,
                remote.blocks,
                policy.maximum_remote_blocks,
            )?;
            let remote_hello = node_hello(&remote.node)?;
            let remote_network = p2p_network(remote.node.config().network);
            let (remote_session, initial_remote) = PeerSession::new(
                SessionRole::Inbound,
                remote_network,
                remote_hello,
                now,
                policy.session,
            )
            .map_err(MultiHarnessError::Session)?;
            if !initial_remote.is_empty() {
                return Err(MultiHarnessError::UnexpectedAction);
            }
            let (target_session, mut initial_target) = PeerSession::new(
                SessionRole::Outbound,
                target_network,
                target_hello.clone(),
                now,
                policy.session,
            )
            .map_err(MultiHarnessError::Session)?;
            if initial_target.len() != 1 {
                return Err(MultiHarnessError::UnexpectedAction);
            }
            let initial = initial_target
                .pop()
                .ok_or(MultiHarnessError::UnexpectedAction)?;
            let mut link = RemoteLink {
                node: remote.node,
                blocks,
                canonical_order,
                target_session,
                remote_session,
            };
            let hello = transfer(
                &mut harness.transport,
                &mut harness.transcript,
                remote.peer_id,
                MultiTransferDirection::TargetToRemote,
                target_network,
                remote_network,
                initial,
            )?;
            let remote_actions = link
                .remote_session
                .handle_inbound(now, hello)
                .map_err(MultiHarnessError::Session)?;
            let acknowledgement = only_handshake_send(remote_actions, remote.peer_id)?;
            let acknowledgement = transfer(
                &mut harness.transport,
                &mut harness.transcript,
                remote.peer_id,
                MultiTransferDirection::RemoteToTarget,
                remote_network,
                target_network,
                acknowledgement,
            )?;
            let target_actions = link
                .target_session
                .handle_inbound(now, acknowledgement)
                .map_err(MultiHarnessError::Session)?;
            if !target_actions
                .iter()
                .any(|action| matches!(action, SessionAction::Established { .. }))
                || link.target_session.phase() != SessionPhase::Established
                || link.remote_session.phase() != SessionPhase::Established
            {
                return Err(MultiHarnessError::HandshakeRejected(remote.peer_id));
            }
            harness
                .peers
                .register_peer(remote.peer_id)
                .map_err(MultiHarnessError::MultiPeer)?;
            harness.links.insert(remote.peer_id, link);
        }
        Ok(harness)
    }

    pub const fn target(&self) -> &Node<InMemoryConsensusStore> {
        &self.target
    }

    pub const fn sync(&self) -> &SyncCoordinator {
        &self.sync
    }

    pub const fn peers(&self) -> &MultiPeerCoordinator {
        &self.peers
    }

    pub fn transcript(&self) -> &[MultiTransferRecord] {
        &self.transcript
    }

    pub fn synchronize_headers_from(
        &mut self,
        peer_id: PeerId,
        local_now: u64,
    ) -> Result<Vec<BlockId>, MultiHarnessError> {
        let source_tip = self
            .links
            .get(&peer_id)
            .ok_or(MultiHarnessError::UnknownPeer(peer_id))?
            .node
            .canonical_tip()
            .map_err(MultiHarnessError::Read)?;
        let mut header_sync = HeaderSync::new();
        let mut scheduled = Vec::new();
        let mut rounds = 0_u16;
        while self.sync.sync_tip() != source_tip.block_id {
            rounds = rounds
                .checked_add(1)
                .ok_or(MultiHarnessError::HeaderRoundLimit {
                    maximum: self.policy.maximum_header_rounds,
                })?;
            if rounds > self.policy.maximum_header_rounds {
                return Err(MultiHarnessError::HeaderRoundLimit {
                    maximum: self.policy.maximum_header_rounds,
                });
            }
            let locator = self
                .sync
                .build_locator(self.target.storage())
                .map_err(MultiHarnessError::Locator)?;
            let request = {
                let link = self
                    .links
                    .get_mut(&peer_id)
                    .ok_or(MultiHarnessError::UnknownPeer(peer_id))?;
                header_sync
                    .begin(
                        &mut link.target_session,
                        local_now,
                        locator,
                        source_tip.block_id,
                    )
                    .map_err(MultiHarnessError::HeaderSync)?
            };
            let frame = self.wire(peer_id, MultiTransferDirection::TargetToRemote, request)?;
            let source_actions = self
                .links
                .get_mut(&peer_id)
                .ok_or(MultiHarnessError::UnknownPeer(peer_id))?
                .remote_session
                .handle_inbound(local_now, frame)
                .map_err(MultiHarnessError::Session)?;
            let (request_id, locator, stop_id) = delivered_headers_request(source_actions)?;
            let headers = self.headers_after_locator(peer_id, &locator, stop_id)?;
            let response = self
                .links
                .get(&peer_id)
                .ok_or(MultiHarnessError::UnknownPeer(peer_id))?
                .remote_session
                .make_response(request_id, Message::Headers(headers))
                .map_err(MultiHarnessError::Session)?;
            let frame = self.wire(peer_id, MultiTransferDirection::RemoteToTarget, response)?;
            let actions = self
                .links
                .get_mut(&peer_id)
                .ok_or(MultiHarnessError::UnknownPeer(peer_id))?
                .target_session
                .handle_inbound(local_now, frame)
                .map_err(MultiHarnessError::Session)?;
            let response = only_headers_response(actions)?;
            let batch = header_sync
                .accept_response(response)
                .map_err(MultiHarnessError::HeaderSync)?;
            if batch == HeaderBatch::Complete {
                break;
            }
            let outcome = self
                .sync
                .accept_header_batch(self.target.storage(), batch, local_now)
                .map_err(MultiHarnessError::HeaderBatch)?;
            let reached_stop = match outcome {
                HeaderBatchOutcome::Accepted {
                    tip,
                    scheduled: batch_scheduled,
                    ..
                } => {
                    scheduled.extend(batch_scheduled);
                    tip.block_id == source_tip.block_id
                }
                HeaderBatchOutcome::UpToDate { tip } => tip.block_id == source_tip.block_id,
            };
            header_sync
                .validation_accepted(reached_stop)
                .map_err(MultiHarnessError::HeaderSync)?;
        }
        Ok(scheduled)
    }

    pub fn announce_catalog(&mut self, peer_id: PeerId, now: u64) -> Result<(), MultiHarnessError> {
        let entries: Vec<_> = self
            .links
            .get(&peer_id)
            .ok_or(MultiHarnessError::UnknownPeer(peer_id))?
            .canonical_order
            .iter()
            .copied()
            .map(InventoryEntry::Block)
            .collect();
        if entries.len() > usize::from(MAX_INV_ENTRIES) {
            return Err(MultiHarnessError::RemoteCapacity {
                peer_id,
                actual: entries.len(),
                maximum: MAX_INV_ENTRIES,
            });
        }
        let action = SessionAction::Send {
            request_id: 0,
            message: Message::Inventory(entries),
        };
        let frame = self.wire(peer_id, MultiTransferDirection::RemoteToTarget, action)?;
        let actions = self
            .links
            .get_mut(&peer_id)
            .ok_or(MultiHarnessError::UnknownPeer(peer_id))?
            .target_session
            .handle_inbound(now, frame)
            .map_err(MultiHarnessError::Session)?;
        let inventory = only_inventory(actions)?;
        self.peers
            .observe_inventory(peer_id, &inventory)
            .map_err(MultiHarnessError::MultiPeer)?;
        Ok(())
    }

    pub fn schedule_blocks(&mut self, block_ids: &[BlockId]) -> Result<(), MultiHarnessError> {
        let objects: Vec<_> = block_ids
            .iter()
            .copied()
            .map(InventoryEntry::Block)
            .collect();
        self.peers
            .schedule_objects(&objects)
            .map_err(MultiHarnessError::MultiPeer)
    }

    pub fn next_assignment(
        &mut self,
        now: u64,
    ) -> Result<Option<RequestAssignment>, MultiHarnessError> {
        let Some(assignment) = self
            .peers
            .next_assignment(now)
            .map_err(MultiHarnessError::MultiPeer)?
        else {
            return Ok(None);
        };
        let InventoryEntry::Block(block_id) = assignment.object else {
            self.peers
                .cancel_request(assignment)
                .map_err(MultiHarnessError::MultiPeer)?;
            return Err(MultiHarnessError::NonBlockAssignment(assignment.object));
        };
        if !self.sync.is_block_in_flight(block_id) {
            if let Err(error) = self.sync.begin_block_request(block_id) {
                self.peers
                    .cancel_request(assignment)
                    .map_err(MultiHarnessError::MultiPeer)?;
                return Err(MultiHarnessError::SyncReservation(error));
            }
        }
        Ok(Some(assignment))
    }

    pub fn perform(
        &mut self,
        assignment: RequestAssignment,
        behavior: RemoteBehavior,
        now: u64,
    ) -> Result<RemoteStepOutcome, MultiHarnessError> {
        let InventoryEntry::Block(block_id) = assignment.object else {
            return Err(MultiHarnessError::NonBlockAssignment(assignment.object));
        };
        let request = SessionAction::Send {
            request_id: assignment.request_id,
            message: Message::GetObjects(vec![assignment.object]),
        };
        let frame = self.wire(
            assignment.peer_id,
            MultiTransferDirection::TargetToRemote,
            request,
        )?;
        let actions = self
            .links
            .get_mut(&assignment.peer_id)
            .ok_or(MultiHarnessError::UnknownPeer(assignment.peer_id))?
            .remote_session
            .handle_inbound(now, frame)
            .map_err(MultiHarnessError::Session)?;
        require_object_request(actions, assignment)?;
        match behavior {
            RemoteBehavior::Withhold => Ok(RemoteStepOutcome::Withheld(assignment)),
            RemoteBehavior::Reject { code, detail } => {
                let response = self
                    .links
                    .get(&assignment.peer_id)
                    .ok_or(MultiHarnessError::UnknownPeer(assignment.peer_id))?
                    .remote_session
                    .make_response(
                        assignment.request_id,
                        Message::Reject {
                            rejected_type: TYPE_GET_OBJECTS,
                            code,
                            detail,
                        },
                    )
                    .map_err(MultiHarnessError::Session)?;
                let frame = self.wire(
                    assignment.peer_id,
                    MultiTransferDirection::RemoteToTarget,
                    response,
                )?;
                require_rejection_frame(&frame, assignment)?;
                let retry = self
                    .peers
                    .retry_request(assignment, now, RetryReason::Rejected)
                    .map_err(MultiHarnessError::MultiPeer)?;
                Ok(RemoteStepOutcome::Rejected { assignment, retry })
            }
            RemoteBehavior::Deliver => {
                let block = self
                    .links
                    .get(&assignment.peer_id)
                    .ok_or(MultiHarnessError::UnknownPeer(assignment.peer_id))?
                    .blocks
                    .get(&block_id)
                    .cloned()
                    .ok_or(MultiHarnessError::MissingRemoteBlock {
                        peer_id: assignment.peer_id,
                        block_id,
                    })?;
                let response = self
                    .links
                    .get(&assignment.peer_id)
                    .ok_or(MultiHarnessError::UnknownPeer(assignment.peer_id))?
                    .remote_session
                    .make_response(assignment.request_id, Message::Block(block.clone()))
                    .map_err(MultiHarnessError::Session)?;
                let frame = self.wire(
                    assignment.peer_id,
                    MultiTransferDirection::RemoteToTarget,
                    response,
                )?;
                let actions = self
                    .links
                    .get_mut(&assignment.peer_id)
                    .ok_or(MultiHarnessError::UnknownPeer(assignment.peer_id))?
                    .target_session
                    .handle_inbound(now, frame)
                    .map_err(MultiHarnessError::Session)?;
                let delivery = only_block(actions, assignment)?;
                match self
                    .target
                    .deliver_scheduled_block(&mut self.sync, delivery, now)
                {
                    Ok(delivery) => {
                        self.peers
                            .complete_request(assignment)
                            .map_err(MultiHarnessError::MultiPeer)?;
                        Ok(RemoteStepOutcome::Stored {
                            assignment,
                            delivery,
                        })
                    }
                    Err(failure) if missing_parent(&failure) => {
                        let parent_block_id = block.header.parent_block_id;
                        let admission = self
                            .peers
                            .admit_orphan(assignment.peer_id, block, now)
                            .map_err(MultiHarnessError::MultiPeer)?;
                        if admission != (OrphanAdmission::Stored { block_id }) {
                            return Err(MultiHarnessError::OrphanWasNotStored(block_id));
                        }
                        self.peers
                            .complete_request(assignment)
                            .map_err(MultiHarnessError::MultiPeer)?;
                        Ok(RemoteStepOutcome::Orphaned {
                            assignment,
                            block_id,
                            parent_block_id,
                        })
                    }
                    Err(failure) => Err(MultiHarnessError::BlockDelivery(failure)),
                }
            }
        }
    }

    pub fn retry_expired(&mut self, now: u64) -> Result<Vec<RetryOutcome>, MultiHarnessError> {
        let expired = self.peers.expired_assignments(now);
        expired
            .into_iter()
            .map(|assignment| {
                self.peers
                    .retry_request(assignment, now, RetryReason::Timeout)
                    .map_err(MultiHarnessError::MultiPeer)
            })
            .collect()
    }

    pub fn replay_orphan_children(
        &mut self,
        parent: BlockId,
        now: u64,
    ) -> Result<Vec<BlockDeliveryOutcome>, MultiHarnessError> {
        let orphans = self
            .peers
            .take_orphan_children(parent)
            .map_err(MultiHarnessError::MultiPeer)?;
        let mut outcomes = Vec::with_capacity(orphans.len());
        for orphan in orphans {
            self.sync
                .begin_block_request(orphan.block_id)
                .map_err(MultiHarnessError::SyncReservation)?;
            let block = Block::decode_non_genesis_exact(&orphan.canonical_bytes)
                .map_err(MultiHarnessError::ConsensusDecode)?;
            let request_id = self.next_replay_request_id;
            self.next_replay_request_id = request_id
                .checked_add(1)
                .filter(|next| *next != 0)
                .ok_or(MultiHarnessError::ReplayRequestIdExhausted)?;
            let response = self
                .links
                .get(&orphan.peer_id)
                .ok_or(MultiHarnessError::UnknownPeer(orphan.peer_id))?
                .remote_session
                .make_response(request_id, Message::Block(block))
                .map_err(MultiHarnessError::Session)?;
            let frame = self.wire(
                orphan.peer_id,
                MultiTransferDirection::RemoteToTarget,
                response,
            )?;
            let actions = self
                .links
                .get_mut(&orphan.peer_id)
                .ok_or(MultiHarnessError::UnknownPeer(orphan.peer_id))?
                .target_session
                .handle_inbound(now, frame)
                .map_err(MultiHarnessError::Session)?;
            let delivery = only_block_without_assignment(actions, request_id, orphan.block_id)?;
            outcomes.push(
                self.target
                    .deliver_scheduled_block(&mut self.sync, delivery, now)
                    .map_err(MultiHarnessError::BlockDelivery)?,
            );
        }
        Ok(outcomes)
    }

    fn wire(
        &mut self,
        peer_id: PeerId,
        direction: MultiTransferDirection,
        action: SessionAction,
    ) -> Result<out_p2p::Frame, MultiHarnessError> {
        let link = self
            .links
            .get(&peer_id)
            .ok_or(MultiHarnessError::UnknownPeer(peer_id))?;
        let target_network = p2p_network(self.target.config().network);
        let remote_network = p2p_network(link.node.config().network);
        let (sender, receiver) = match direction {
            MultiTransferDirection::TargetToRemote => (target_network, remote_network),
            MultiTransferDirection::RemoteToTarget => (remote_network, target_network),
        };
        transfer(
            &mut self.transport,
            &mut self.transcript,
            peer_id,
            direction,
            sender,
            receiver,
            action,
        )
    }

    fn headers_after_locator(
        &self,
        peer_id: PeerId,
        locator: &[BlockId],
        stop_id: BlockId,
    ) -> Result<Vec<out_codec::BlockHeader>, MultiHarnessError> {
        let link = self
            .links
            .get(&peer_id)
            .ok_or(MultiHarnessError::UnknownPeer(peer_id))?;
        let mut common_height = None;
        for block_id in locator {
            let Some(metadata) = link
                .node
                .storage()
                .get_validated_header(*block_id)
                .map_err(MultiHarnessError::Read)?
            else {
                continue;
            };
            if link
                .node
                .storage()
                .canonical_block_id(metadata.header().height)
                .map_err(MultiHarnessError::Read)?
                == Some(*block_id)
            {
                common_height = Some(metadata.header().height);
                break;
            }
        }
        let common_height =
            common_height.ok_or(MultiHarnessError::MissingCommonAncestor(peer_id))?;
        let mut headers = Vec::new();
        for offset in 1..=u64::from(self.policy.maximum_headers_per_response) {
            let Some(height) = common_height.checked_add(offset) else {
                break;
            };
            let Some(block_id) = link
                .node
                .storage()
                .canonical_block_id(height)
                .map_err(MultiHarnessError::Read)?
            else {
                break;
            };
            let metadata = link
                .node
                .storage()
                .get_validated_header(block_id)
                .map_err(MultiHarnessError::Read)?
                .ok_or(MultiHarnessError::RemoteBlockNotStored { peer_id, block_id })?;
            headers.push(metadata.header());
            if block_id == stop_id {
                break;
            }
        }
        Ok(headers)
    }
}

fn validate_policy(policy: ThreeNodeHarnessPolicy) -> Result<(), MultiHarnessError> {
    policy
        .session
        .validate()
        .map_err(MultiHarnessError::Session)?;
    policy
        .sync
        .validate()
        .map_err(|_| MultiHarnessError::ZeroPolicy("sync"))?;
    policy
        .peers
        .validate()
        .map_err(|error| MultiHarnessError::MultiPeer(MultiPeerError::Policy(error)))?;
    policy
        .transport
        .validate()
        .map_err(|error| MultiHarnessError::Transport(MemoryTransportError::Policy(error)))?;
    for (value, name) in [
        (policy.maximum_remote_blocks, "maximum_remote_blocks"),
        (
            policy.maximum_headers_per_response,
            "maximum_headers_per_response",
        ),
        (policy.maximum_header_rounds, "maximum_header_rounds"),
    ] {
        if value == 0 {
            return Err(MultiHarnessError::ZeroPolicy(name));
        }
    }
    if policy.first_replay_request_id == 0 {
        return Err(MultiHarnessError::ZeroPolicy("first_replay_request_id"));
    }
    if policy.maximum_headers_per_response > MAX_HEADERS {
        return Err(MultiHarnessError::HeaderResponseAboveWireMaximum {
            actual: policy.maximum_headers_per_response,
            maximum: MAX_HEADERS,
        });
    }
    Ok(())
}

fn build_catalog(
    peer_id: PeerId,
    node: &Node<InMemoryConsensusStore>,
    blocks: Vec<Block>,
    maximum: u16,
) -> Result<(BTreeMap<BlockId, Block>, Vec<BlockId>), MultiHarnessError> {
    if blocks.len() > usize::from(maximum) {
        return Err(MultiHarnessError::RemoteCapacity {
            peer_id,
            actual: blocks.len(),
            maximum,
        });
    }
    let mut catalog = BTreeMap::new();
    let mut by_height = BTreeMap::new();
    for block in blocks {
        let block_id = block_id_from_header_bytes(&block.header.encode());
        if block.header.height == 0 {
            return Err(MultiHarnessError::RemoteGenesis(peer_id));
        }
        if catalog.contains_key(&block_id) {
            return Err(MultiHarnessError::DuplicateRemoteBlock { peer_id, block_id });
        }
        let metadata = node
            .storage()
            .get_validated_header(block_id)
            .map_err(MultiHarnessError::Read)?
            .ok_or(MultiHarnessError::RemoteBlockNotStored { peer_id, block_id })?;
        if metadata.header() != block.header {
            return Err(MultiHarnessError::RemoteHeaderMismatch { peer_id, block_id });
        }
        if node
            .storage()
            .canonical_block_id(block.header.height)
            .map_err(MultiHarnessError::Read)?
            != Some(block_id)
        {
            return Err(MultiHarnessError::RemoteBlockNotCanonical { peer_id, block_id });
        }
        by_height.insert(block.header.height, block_id);
        catalog.insert(block_id, block);
    }
    Ok((catalog, by_height.into_values().collect()))
}

fn transfer(
    transport: &mut BoundedMemoryTransport,
    transcript: &mut Vec<MultiTransferRecord>,
    peer_id: PeerId,
    direction: MultiTransferDirection,
    sender_network: P2pNetwork,
    receiver_network: P2pNetwork,
    action: SessionAction,
) -> Result<out_p2p::Frame, MultiHarnessError> {
    let SessionAction::Send {
        request_id,
        message,
    } = action
    else {
        return Err(MultiHarnessError::UnexpectedAction);
    };
    let bytes =
        encode_frame(sender_network, request_id, &message).map_err(MultiHarnessError::Encode)?;
    transport
        .send(peer_id, bytes.clone())
        .map_err(MultiHarnessError::Transport)?;
    let carried = transport
        .receive()
        .map_err(MultiHarnessError::Transport)?
        .ok_or(MultiHarnessError::UnexpectedAction)?;
    if carried.peer_id != peer_id || carried.bytes != bytes {
        return Err(MultiHarnessError::UnexpectedAction);
    }
    let frame = decode_frame_exact(&carried.bytes, receiver_network, PROTOCOL_VERSION_V0)
        .map_err(MultiHarnessError::Decode)?;
    transcript.push(MultiTransferRecord {
        peer_id,
        direction,
        request_id,
        message_type: message.message_type(),
        frame_bytes: carried.bytes,
    });
    Ok(frame)
}

fn node_hello(node: &Node<InMemoryConsensusStore>) -> Result<Hello, MultiHarnessError> {
    let tip = node.canonical_tip().map_err(MultiHarnessError::Read)?;
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

fn p2p_network(network: SupportedNetwork) -> P2pNetwork {
    match network {
        SupportedNetwork::Testnet => P2pNetwork::Testnet,
        SupportedNetwork::Devnet => P2pNetwork::Devnet,
    }
}

fn only_handshake_send(
    actions: Vec<SessionAction>,
    peer_id: PeerId,
) -> Result<SessionAction, MultiHarnessError> {
    let mut send = None;
    let mut established = false;
    for action in actions {
        match action {
            SessionAction::Send { .. } if send.is_none() => send = Some(action),
            SessionAction::Established { .. } if !established => established = true,
            _ => return Err(MultiHarnessError::HandshakeRejected(peer_id)),
        }
    }
    if !established {
        return Err(MultiHarnessError::HandshakeRejected(peer_id));
    }
    send.ok_or(MultiHarnessError::HandshakeRejected(peer_id))
}

fn delivered_headers_request(
    actions: Vec<SessionAction>,
) -> Result<(u64, Vec<BlockId>, BlockId), MultiHarnessError> {
    match actions.as_slice() {
        [SessionAction::Deliver {
            request_id,
            message: Message::GetHeaders { locator, stop_id },
        }] => Ok((*request_id, locator.clone(), *stop_id)),
        _ => Err(MultiHarnessError::UnexpectedAction),
    }
}

fn only_headers_response(actions: Vec<SessionAction>) -> Result<SessionAction, MultiHarnessError> {
    if actions.len() == 1 && matches!(actions[0], SessionAction::HeadersResponse { .. }) {
        actions
            .into_iter()
            .next()
            .ok_or(MultiHarnessError::UnexpectedAction)
    } else {
        Err(MultiHarnessError::UnexpectedAction)
    }
}

fn only_inventory(actions: Vec<SessionAction>) -> Result<Vec<InventoryEntry>, MultiHarnessError> {
    match actions.as_slice() {
        [SessionAction::Deliver {
            request_id: 0,
            message: Message::Inventory(entries),
        }] => Ok(entries.clone()),
        _ => Err(MultiHarnessError::UnexpectedAction),
    }
}

fn require_object_request(
    actions: Vec<SessionAction>,
    assignment: RequestAssignment,
) -> Result<(), MultiHarnessError> {
    match actions.as_slice() {
        [SessionAction::Deliver {
            request_id,
            message: Message::GetObjects(entries),
        }] if *request_id == assignment.request_id && entries.as_slice() == [assignment.object] => {
            Ok(())
        }
        _ => Err(MultiHarnessError::AssignmentMismatch),
    }
}

fn require_rejection_frame(
    frame: &out_p2p::Frame,
    assignment: RequestAssignment,
) -> Result<(), MultiHarnessError> {
    match &frame.message {
        Message::Reject {
            rejected_type: TYPE_GET_OBJECTS,
            ..
        } if frame.header.request_id == assignment.request_id => Ok(()),
        _ => Err(MultiHarnessError::AssignmentMismatch),
    }
}

fn only_block(
    actions: Vec<SessionAction>,
    assignment: RequestAssignment,
) -> Result<SessionAction, MultiHarnessError> {
    match actions.as_slice() {
        [SessionAction::Deliver {
            request_id,
            message: Message::Block(block),
        }] if *request_id == assignment.request_id
            && assignment.object
                == InventoryEntry::Block(block_id_from_header_bytes(&block.header.encode())) => {}
        _ => return Err(MultiHarnessError::AssignmentMismatch),
    }
    actions
        .into_iter()
        .next()
        .ok_or(MultiHarnessError::UnexpectedAction)
}

fn only_block_without_assignment(
    actions: Vec<SessionAction>,
    request_id: u64,
    block_id: BlockId,
) -> Result<SessionAction, MultiHarnessError> {
    match actions.as_slice() {
        [SessionAction::Deliver {
            request_id: actual,
            message: Message::Block(block),
        }] if *actual == request_id
            && block_id_from_header_bytes(&block.header.encode()) == block_id => {}
        _ => return Err(MultiHarnessError::AssignmentMismatch),
    }
    actions
        .into_iter()
        .next()
        .ok_or(MultiHarnessError::UnexpectedAction)
}

fn missing_parent(
    failure: &BlockDeliveryFailure<InMemoryReadError, InMemoryMutationError>,
) -> bool {
    matches!(
        failure,
        BlockDeliveryFailure::Local { error, .. }
            if matches!(
                error.as_ref(),
                BlockDeliveryLocal::Consensus(out_consensus::block::BlockLocalFailure::Header(
                    out_consensus::chain::ChildHeaderLocalFailure::MissingParent(_)
                ))
            )
    )
}

#[cfg(test)]
mod tests {
    use out_storage::conformance::validated_reward_commit;

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

    fn source() -> (Node<InMemoryConsensusStore>, Vec<Block>) {
        let mut source = node();
        let mut parent = source.canonical_tip().expect("tip").block_id;
        let mut blocks = Vec::new();
        for index in 0..2_u8 {
            let commit = validated_reward_commit(source.storage(), parent, &[b'm', index]);
            let block = commit.block().clone();
            let raw = commit.canonical_block_bytes().to_vec();
            parent = source
                .process_block(&raw, block.header.timestamp)
                .expect("store")
                .stored
                .block_id;
            blocks.push(block);
        }
        (source, blocks)
    }

    fn policy() -> ThreeNodeHarnessPolicy {
        ThreeNodeHarnessPolicy {
            session: SessionPolicy {
                handshake_timeout_ticks: 10,
                response_timeout_ticks: 10,
                maximum_outstanding_requests: 4,
                disconnect_score: 100,
                protocol_violation_score: 20,
                unexpected_response_score: 10,
                timeout_score: 5,
            },
            sync: SyncPolicy {
                maximum_overlay_headers: 16,
                maximum_blocks_per_request: 4,
                maximum_locator_entries: 16,
                linear_locator_entries: 4,
                maximum_locator_walk: 64,
            },
            peers: MultiPeerPolicy {
                maximum_peers: 2,
                maximum_announcements_per_peer: 4,
                maximum_total_announcements: 8,
                maximum_pending_objects: 4,
                maximum_in_flight_per_peer: 1,
                maximum_retry_attempts: 3,
                request_timeout_ticks: 10,
                base_retry_backoff_ticks: 5,
                maximum_retry_backoff_ticks: 20,
                first_request_id: 1_000,
                maximum_orphans: 4,
                maximum_orphans_per_peer: 2,
                maximum_orphans_per_parent: 2,
                maximum_orphan_bytes: 1_000_000,
            },
            transport: MemoryTransportPolicy {
                maximum_queued_frames: 2,
                maximum_queued_bytes: 5_000_000,
                maximum_frame_bytes: 4_194_358,
            },
            maximum_remote_blocks: 4,
            maximum_headers_per_response: 4,
            maximum_header_rounds: 4,
            first_replay_request_id: 10_000,
        }
    }

    fn harness() -> ThreeNodeHarness {
        let (first_node, first_blocks) = source();
        let (second_node, second_blocks) = source();
        ThreeNodeHarness::establish(
            node(),
            [
                SimulatedRemote {
                    peer_id: peer(1),
                    node: first_node,
                    blocks: first_blocks,
                },
                SimulatedRemote {
                    peer_id: peer(2),
                    node: second_node,
                    blocks: second_blocks,
                },
            ],
            2_000_000_100,
            policy(),
        )
        .expect("harness")
    }

    #[test]
    fn timeout_fails_over_to_second_peer_and_reaches_the_same_tip() {
        let mut harness = harness();
        let scheduled = harness
            .synchronize_headers_from(peer(1), 2_000_000_100)
            .expect("headers");
        assert_eq!(scheduled.len(), 2);
        harness
            .announce_catalog(peer(1), 2_000_000_100)
            .expect("inventory 1");
        harness
            .announce_catalog(peer(2), 2_000_000_100)
            .expect("inventory 2");
        harness.schedule_blocks(&scheduled).expect("schedule");

        let first = harness.next_assignment(100).unwrap().unwrap();
        assert_eq!(first.peer_id, peer(1));
        assert_eq!(
            harness.perform(first, RemoteBehavior::Withhold, 100),
            Ok(RemoteStepOutcome::Withheld(first))
        );
        assert!(
            matches!(harness.retry_expired(110).as_deref(), Ok([RetryOutcome::Retrying { failed_peer, .. }]) if *failed_peer == peer(1))
        );
        let reassigned = harness.next_assignment(110).unwrap().unwrap();
        assert_eq!(reassigned.peer_id, peer(2));
        assert!(matches!(
            harness.perform(reassigned, RemoteBehavior::Deliver, 2_000_000_100),
            Ok(RemoteStepOutcome::Stored { .. })
        ));
        let second = harness.next_assignment(110).unwrap().unwrap();
        assert_eq!(second.peer_id, peer(2));
        assert!(matches!(
            harness.perform(second, RemoteBehavior::Deliver, 2_000_000_100),
            Ok(RemoteStepOutcome::Stored { .. })
        ));
        let remote_tip = harness
            .links
            .get(&peer(1))
            .unwrap()
            .node
            .canonical_tip()
            .unwrap();
        assert_eq!(harness.target().canonical_tip().unwrap(), remote_tip);
        assert_eq!(harness.sync().in_flight_block_count(), 0);
        assert_eq!(harness.peers().pending_object_count(), 0);
    }

    #[test]
    fn child_arrives_first_is_retained_then_replayed_after_parent() {
        let mut harness = harness();
        let scheduled = harness
            .synchronize_headers_from(peer(1), 2_000_000_100)
            .expect("headers");
        let parent = scheduled[0];
        let child = scheduled[1];
        harness
            .announce_catalog(peer(1), 2_000_000_100)
            .expect("inventory 1");
        harness
            .announce_catalog(peer(2), 2_000_000_100)
            .expect("inventory 2");
        harness.schedule_blocks(&[child, parent]).expect("priority");

        let child_assignment = harness.next_assignment(100).unwrap().unwrap();
        assert_eq!(child_assignment.object, InventoryEntry::Block(child));
        assert!(matches!(
            harness.perform(child_assignment, RemoteBehavior::Deliver, 2_000_000_100),
            Ok(RemoteStepOutcome::Orphaned { block_id, parent_block_id, .. })
                if block_id == child && parent_block_id == parent
        ));
        assert_eq!(harness.peers().orphan_count(), 1);

        let parent_assignment = harness.next_assignment(100).unwrap().unwrap();
        assert_eq!(parent_assignment.object, InventoryEntry::Block(parent));
        assert!(matches!(
            harness.perform(parent_assignment, RemoteBehavior::Deliver, 2_000_000_100),
            Ok(RemoteStepOutcome::Stored { .. })
        ));
        let replayed = harness
            .replay_orphan_children(parent, 2_000_000_100)
            .expect("replay");
        assert_eq!(replayed.len(), 1);
        assert_eq!(harness.peers().orphan_count(), 0);
        assert_eq!(harness.target().canonical_tip().unwrap().block_id, child);
        assert_eq!(harness.sync().in_flight_block_count(), 0);
    }

    #[test]
    fn object_reject_is_correlated_by_coordinator_then_fails_over() {
        let mut harness = harness();
        let scheduled = harness
            .synchronize_headers_from(peer(1), 2_000_000_100)
            .expect("headers");
        harness
            .announce_catalog(peer(1), 2_000_000_100)
            .expect("inventory 1");
        harness
            .announce_catalog(peer(2), 2_000_000_100)
            .expect("inventory 2");
        harness.schedule_blocks(&[scheduled[0]]).expect("schedule");

        let first = harness.next_assignment(100).unwrap().unwrap();
        assert_eq!(first.peer_id, peer(1));
        assert!(matches!(
            harness.perform(
                first,
                RemoteBehavior::Reject {
                    code: 7,
                    detail: b"fixture".to_vec(),
                },
                100,
            ),
            Ok(RemoteStepOutcome::Rejected {
                retry: RetryOutcome::Retrying { failed_peer, .. },
                ..
            }) if failed_peer == peer(1)
        ));
        let second = harness.next_assignment(100).unwrap().unwrap();
        assert_eq!(second.peer_id, peer(2));
        assert!(matches!(
            harness.perform(second, RemoteBehavior::Deliver, 2_000_000_100),
            Ok(RemoteStepOutcome::Stored { .. })
        ));
        assert_eq!(harness.target().canonical_tip().unwrap().height, 1);
    }
}
