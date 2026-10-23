//! Deterministic, in-memory two-node integration harness.
//!
//! This module opens no sockets and reads no clock. Every transfer is encoded as
//! an exact P2P v0 frame, decoded by the receiving network, and then delivered
//! through the peer-session state machine. The source relay catalog is bounded
//! operational data; authoritative consensus state remains in each node store.

use std::collections::{BTreeMap, BTreeSet};

use out_codec::Block;
use out_consensus::block_id_from_header_bytes;
use out_consensus::chain::{ChainTip, ValidatedHeaderView};
use out_p2p::session::{
    HeaderBatch, HeaderSync, HeaderSyncError, PeerSession, SessionAction, SessionError,
    SessionPhase, SessionPolicy, SessionRole,
};
use out_p2p::{
    decode_frame_exact, encode_frame, DecodeError, EncodeError, Frame, Hello, InventoryEntry,
    Message, P2pNetwork, MAX_HEADERS, PROTOCOL_VERSION_V0,
};
use out_primitives::BlockId;
use out_storage::{InMemoryConsensusStore, InMemoryMutationError, InMemoryReadError};

use crate::sync::{
    BlockDeliveryFailure, BlockDeliveryOutcome, HeaderBatchFailure, HeaderBatchOutcome,
    LocatorError, SyncCoordinator, SyncOpenError, SyncPolicy, SyncPolicyError,
};
use crate::{Node, SupportedNetwork};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferDirection {
    SourceToTarget,
    TargetToSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRecord {
    pub direction: TransferDirection,
    pub request_id: u64,
    pub message_type: u16,
    pub frame_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HarnessPolicy {
    pub session: SessionPolicy,
    pub sync: SyncPolicy,
    pub maximum_catalog_blocks: u16,
    pub maximum_headers_per_response: u16,
    pub maximum_sync_rounds: u16,
    pub first_object_request_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessPolicyError {
    Zero(&'static str),
    HeadersPerResponseAboveWireMaximum { actual: u16, maximum: u16 },
    Session(SessionError),
    Sync(SyncPolicyError),
}

impl HarnessPolicy {
    pub fn validate(self) -> Result<Self, HarnessPolicyError> {
        self.session
            .validate()
            .map_err(HarnessPolicyError::Session)?;
        self.sync.validate().map_err(HarnessPolicyError::Sync)?;
        if self.maximum_catalog_blocks == 0 {
            return Err(HarnessPolicyError::Zero("maximum_catalog_blocks"));
        }
        if self.maximum_headers_per_response == 0 {
            return Err(HarnessPolicyError::Zero("maximum_headers_per_response"));
        }
        if self.maximum_headers_per_response > MAX_HEADERS {
            return Err(HarnessPolicyError::HeadersPerResponseAboveWireMaximum {
                actual: self.maximum_headers_per_response,
                maximum: MAX_HEADERS,
            });
        }
        if self.maximum_sync_rounds == 0 {
            return Err(HarnessPolicyError::Zero("maximum_sync_rounds"));
        }
        if self.first_object_request_id == 0 {
            return Err(HarnessPolicyError::Zero("first_object_request_id"));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarnessError {
    Policy(HarnessPolicyError),
    Read(InMemoryReadError),
    SyncOpen(SyncOpenError<InMemoryReadError>),
    Session(SessionError),
    Encode(EncodeError),
    Decode(DecodeError),
    UnexpectedAction,
    HandshakeRejected,
    CatalogCapacity { actual: usize, maximum: u16 },
    DuplicateCatalogBlock(BlockId),
    CatalogGenesis(BlockId),
    CatalogBlockNotStored(BlockId),
    CatalogHeaderMismatch(BlockId),
    CatalogBlockNotCanonical(BlockId),
    HeaderSync(HeaderSyncError),
    HeaderBatch(HeaderBatchFailure<InMemoryReadError>),
    Locator(LocatorError<InMemoryReadError>),
    MissingCommonAncestor,
    ObjectRequestIdExhausted,
    MissingCatalogBlock(BlockId),
    BlockDelivery(BlockDeliveryFailure<InMemoryReadError, InMemoryMutationError>),
    SyncRoundLimit { maximum: u16 },
    SourceTipChanged { expected: BlockId, actual: BlockId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HarnessSyncOutcome {
    pub source_tip: ChainTip,
    pub target_tip: ChainTip,
    pub header_rounds: u16,
    pub blocks_delivered: u64,
}

pub struct InMemoryTwoNodeHarness {
    source: Node<InMemoryConsensusStore>,
    target: Node<InMemoryConsensusStore>,
    source_session: PeerSession,
    target_session: PeerSession,
    header_sync: HeaderSync,
    sync: SyncCoordinator,
    relay_catalog: BTreeMap<BlockId, Block>,
    transcript: Vec<TransferRecord>,
    policy: HarnessPolicy,
    next_object_request_id: u64,
}

impl InMemoryTwoNodeHarness {
    pub fn establish(
        source: Node<InMemoryConsensusStore>,
        target: Node<InMemoryConsensusStore>,
        source_blocks: Vec<Block>,
        now: u64,
        policy: HarnessPolicy,
    ) -> Result<Self, HarnessError> {
        let policy = policy.validate().map_err(HarnessError::Policy)?;
        let source_hello = node_hello(&source)?;
        let target_hello = node_hello(&target)?;
        let source_network = p2p_network(source.config().network);
        let target_network = p2p_network(target.config().network);
        let (source_session, source_initial) = PeerSession::new(
            SessionRole::Inbound,
            source_network,
            source_hello,
            now,
            policy.session,
        )
        .map_err(HarnessError::Session)?;
        if !source_initial.is_empty() {
            return Err(HarnessError::UnexpectedAction);
        }
        let (target_session, mut target_initial) = PeerSession::new(
            SessionRole::Outbound,
            target_network,
            target_hello,
            now,
            policy.session,
        )
        .map_err(HarnessError::Session)?;
        if target_initial.len() != 1 {
            return Err(HarnessError::UnexpectedAction);
        }
        let sync = SyncCoordinator::new(target.storage(), target.config().network, policy.sync)
            .map_err(HarnessError::SyncOpen)?;
        let relay_catalog = build_catalog(&source, source_blocks, policy.maximum_catalog_blocks)?;
        let initial = target_initial.pop().ok_or(HarnessError::UnexpectedAction)?;
        let mut harness = Self {
            source,
            target,
            source_session,
            target_session,
            header_sync: HeaderSync::new(),
            sync,
            relay_catalog,
            transcript: Vec::new(),
            policy,
            next_object_request_id: policy.first_object_request_id,
        };

        let hello = harness.transfer(initial, TransferDirection::TargetToSource)?;
        let source_actions = harness
            .source_session
            .handle_inbound(now, hello)
            .map_err(HarnessError::Session)?;
        let acknowledgement = only_send(source_actions)?;
        let acknowledgement =
            harness.transfer(acknowledgement, TransferDirection::SourceToTarget)?;
        let target_actions = harness
            .target_session
            .handle_inbound(now, acknowledgement)
            .map_err(HarnessError::Session)?;
        if !target_actions
            .iter()
            .any(|action| matches!(action, SessionAction::Established { .. }))
            || harness.source_session.phase() != SessionPhase::Established
            || harness.target_session.phase() != SessionPhase::Established
        {
            return Err(HarnessError::HandshakeRejected);
        }
        Ok(harness)
    }

    pub const fn source(&self) -> &Node<InMemoryConsensusStore> {
        &self.source
    }

    pub const fn target(&self) -> &Node<InMemoryConsensusStore> {
        &self.target
    }

    pub fn transcript(&self) -> &[TransferRecord] {
        &self.transcript
    }

    pub const fn coordinator(&self) -> &SyncCoordinator {
        &self.sync
    }

    /// Decodes a frame as the receiving side would, without changing session
    /// state. This is useful for deterministic corruption and boundary probes.
    pub fn decode_at_receiver(
        &self,
        direction: TransferDirection,
        bytes: &[u8],
    ) -> Result<Frame, DecodeError> {
        let network = match direction {
            TransferDirection::SourceToTarget => self.target_session.network(),
            TransferDirection::TargetToSource => self.source_session.network(),
        };
        decode_frame_exact(bytes, network, PROTOCOL_VERSION_V0)
    }

    pub fn synchronize(&mut self, local_now: u64) -> Result<HarnessSyncOutcome, HarnessError> {
        let source_tip = self.source.canonical_tip().map_err(HarnessError::Read)?;
        let mut header_rounds = 0_u16;
        let mut blocks_delivered = 0_u64;

        while self.sync.sync_tip() != source_tip.block_id {
            header_rounds = header_rounds
                .checked_add(1)
                .ok_or(HarnessError::SyncRoundLimit {
                    maximum: self.policy.maximum_sync_rounds,
                })?;
            if header_rounds > self.policy.maximum_sync_rounds {
                return Err(HarnessError::SyncRoundLimit {
                    maximum: self.policy.maximum_sync_rounds,
                });
            }
            self.exchange_header_batch(source_tip.block_id, local_now)?;
        }

        loop {
            let requested = self.sync.next_block_request();
            if requested.is_empty() {
                break;
            }
            let delivered = self.exchange_blocks(requested, local_now)?;
            blocks_delivered = blocks_delivered
                .checked_add(delivered)
                .ok_or(HarnessError::ObjectRequestIdExhausted)?;
        }

        let actual_source = self.source.canonical_tip().map_err(HarnessError::Read)?;
        if actual_source.block_id != source_tip.block_id {
            return Err(HarnessError::SourceTipChanged {
                expected: source_tip.block_id,
                actual: actual_source.block_id,
            });
        }
        let target_tip = self.target.canonical_tip().map_err(HarnessError::Read)?;
        Ok(HarnessSyncOutcome {
            source_tip,
            target_tip,
            header_rounds,
            blocks_delivered,
        })
    }

    fn exchange_header_batch(
        &mut self,
        stop_id: BlockId,
        local_now: u64,
    ) -> Result<(), HarnessError> {
        let locator = self
            .sync
            .build_locator(self.target.storage())
            .map_err(HarnessError::Locator)?;
        let request = self
            .header_sync
            .begin(&mut self.target_session, local_now, locator, stop_id)
            .map_err(HarnessError::HeaderSync)?;
        let request = self.transfer(request, TransferDirection::TargetToSource)?;
        let source_actions = self
            .source_session
            .handle_inbound(local_now, request)
            .map_err(HarnessError::Session)?;
        let (request_id, locator, requested_stop) = delivered_headers_request(source_actions)?;
        let headers = self.headers_after_locator(&locator, requested_stop)?;
        let response = self
            .source_session
            .make_response(request_id, Message::Headers(headers))
            .map_err(HarnessError::Session)?;
        let response = self.transfer(response, TransferDirection::SourceToTarget)?;
        let target_actions = self
            .target_session
            .handle_inbound(local_now, response)
            .map_err(HarnessError::Session)?;
        let response = only_headers_response(target_actions)?;
        let batch = self
            .header_sync
            .accept_response(response)
            .map_err(HarnessError::HeaderSync)?;
        if batch == HeaderBatch::Complete {
            return Ok(());
        }
        let outcome = self
            .sync
            .accept_header_batch(self.target.storage(), batch, local_now)
            .map_err(HarnessError::HeaderBatch)?;
        let reached_stop = matches!(
            outcome,
            HeaderBatchOutcome::Accepted { tip, .. } if tip.block_id == stop_id
        );
        self.header_sync
            .validation_accepted(reached_stop)
            .map_err(HarnessError::HeaderSync)
    }

    fn exchange_blocks(
        &mut self,
        requested: Vec<BlockId>,
        local_now: u64,
    ) -> Result<u64, HarnessError> {
        let (request_id, delivered_ids) = self.begin_block_request(requested, local_now)?;
        let mut delivered = 0_u64;
        for block_id in delivered_ids {
            let outcome = self.relay_catalog_block(request_id, block_id, local_now)?;
            let _outcome: BlockDeliveryOutcome = outcome.map_err(HarnessError::BlockDelivery)?;
            delivered = delivered
                .checked_add(1)
                .ok_or(HarnessError::ObjectRequestIdExhausted)?;
        }
        Ok(delivered)
    }

    fn begin_block_request(
        &mut self,
        requested: Vec<BlockId>,
        local_now: u64,
    ) -> Result<(u64, Vec<BlockId>), HarnessError> {
        let request_id = self.next_object_request_id;
        self.next_object_request_id = request_id
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(HarnessError::ObjectRequestIdExhausted)?;
        let entries = requested
            .iter()
            .copied()
            .map(InventoryEntry::Block)
            .collect();
        let request = SessionAction::Send {
            request_id,
            message: Message::GetObjects(entries),
        };
        let request = self.transfer(request, TransferDirection::TargetToSource)?;
        let source_actions = self
            .source_session
            .handle_inbound(local_now, request)
            .map_err(HarnessError::Session)?;
        let (delivered_request_id, delivered_ids) = delivered_block_request(source_actions)?;
        if delivered_request_id != request_id || delivered_ids != requested {
            return Err(HarnessError::UnexpectedAction);
        }
        Ok((request_id, delivered_ids))
    }

    fn relay_catalog_block(
        &mut self,
        request_id: u64,
        block_id: BlockId,
        local_now: u64,
    ) -> Result<
        Result<
            BlockDeliveryOutcome,
            BlockDeliveryFailure<InMemoryReadError, InMemoryMutationError>,
        >,
        HarnessError,
    > {
        let block = self
            .relay_catalog
            .get(&block_id)
            .cloned()
            .ok_or(HarnessError::MissingCatalogBlock(block_id))?;
        let response = self
            .source_session
            .make_response(request_id, Message::Block(block))
            .map_err(HarnessError::Session)?;
        let response = self.transfer(response, TransferDirection::SourceToTarget)?;
        let target_actions = self
            .target_session
            .handle_inbound(local_now, response)
            .map_err(HarnessError::Session)?;
        let delivery = only_block_delivery(target_actions)?;
        Ok(self
            .target
            .deliver_scheduled_block(&mut self.sync, delivery, local_now))
    }

    fn headers_after_locator(
        &self,
        locator: &[BlockId],
        stop_id: BlockId,
    ) -> Result<Vec<out_codec::BlockHeader>, HarnessError> {
        let mut common_height = None;
        for block_id in locator {
            let Some(metadata) = self
                .source
                .storage()
                .get_validated_header(*block_id)
                .map_err(HarnessError::Read)?
            else {
                continue;
            };
            if self
                .source
                .storage()
                .canonical_block_id(metadata.header().height)
                .map_err(HarnessError::Read)?
                == Some(*block_id)
            {
                common_height = Some(metadata.header().height);
                break;
            }
        }
        let common_height = common_height.ok_or(HarnessError::MissingCommonAncestor)?;
        let mut headers = Vec::new();
        for offset in 1..=u64::from(self.policy.maximum_headers_per_response) {
            let Some(height) = common_height.checked_add(offset) else {
                break;
            };
            let Some(block_id) = self
                .source
                .storage()
                .canonical_block_id(height)
                .map_err(HarnessError::Read)?
            else {
                break;
            };
            let metadata = self
                .source
                .storage()
                .get_validated_header(block_id)
                .map_err(HarnessError::Read)?
                .ok_or(HarnessError::CatalogBlockNotStored(block_id))?;
            headers.push(metadata.header());
            if block_id == stop_id {
                break;
            }
        }
        Ok(headers)
    }

    fn transfer(
        &mut self,
        action: SessionAction,
        direction: TransferDirection,
    ) -> Result<Frame, HarnessError> {
        let SessionAction::Send {
            request_id,
            message,
        } = action
        else {
            return Err(HarnessError::UnexpectedAction);
        };
        let sender_network = match direction {
            TransferDirection::SourceToTarget => self.source_session.network(),
            TransferDirection::TargetToSource => self.target_session.network(),
        };
        let bytes =
            encode_frame(sender_network, request_id, &message).map_err(HarnessError::Encode)?;
        let frame = self
            .decode_at_receiver(direction, &bytes)
            .map_err(HarnessError::Decode)?;
        self.transcript.push(TransferRecord {
            direction,
            request_id,
            message_type: message.message_type(),
            frame_bytes: bytes,
        });
        Ok(frame)
    }
}

fn p2p_network(network: SupportedNetwork) -> P2pNetwork {
    match network {
        SupportedNetwork::Testnet => P2pNetwork::Testnet,
        SupportedNetwork::Devnet => P2pNetwork::Devnet,
    }
}

fn node_hello(node: &Node<InMemoryConsensusStore>) -> Result<Hello, HarnessError> {
    let tip = node.canonical_tip().map_err(HarnessError::Read)?;
    let identity = node.config().network.identity();
    Ok(Hello {
        min_protocol_version: PROTOCOL_VERSION_V0,
        max_protocol_version: PROTOCOL_VERSION_V0,
        min_consensus_version: 0,
        max_consensus_version: 0,
        chain_id: identity.chain_id,
        network_id: identity.network_id,
        genesis_commitment: identity.genesis_commitment,
        best_height: tip.height,
        best_block_id: tip.block_id,
    })
}

fn build_catalog(
    source: &Node<InMemoryConsensusStore>,
    blocks: Vec<Block>,
    maximum: u16,
) -> Result<BTreeMap<BlockId, Block>, HarnessError> {
    if blocks.len() > usize::from(maximum) {
        return Err(HarnessError::CatalogCapacity {
            actual: blocks.len(),
            maximum,
        });
    }
    let mut catalog = BTreeMap::new();
    for block in blocks {
        let block_id = block_id_from_header_bytes(&block.header.encode());
        if block.header.height == 0 {
            return Err(HarnessError::CatalogGenesis(block_id));
        }
        if catalog.contains_key(&block_id) {
            return Err(HarnessError::DuplicateCatalogBlock(block_id));
        }
        let metadata = source
            .storage()
            .get_validated_header(block_id)
            .map_err(HarnessError::Read)?
            .ok_or(HarnessError::CatalogBlockNotStored(block_id))?;
        if metadata.header() != block.header {
            return Err(HarnessError::CatalogHeaderMismatch(block_id));
        }
        if source
            .storage()
            .canonical_block_id(block.header.height)
            .map_err(HarnessError::Read)?
            != Some(block_id)
        {
            return Err(HarnessError::CatalogBlockNotCanonical(block_id));
        }
        catalog.insert(block_id, block);
    }
    Ok(catalog)
}

fn only_send(actions: Vec<SessionAction>) -> Result<SessionAction, HarnessError> {
    let mut send = None;
    let mut established = false;
    for action in actions {
        match action {
            SessionAction::Send { .. } if send.is_none() => send = Some(action),
            SessionAction::Established { .. } if !established => established = true,
            _ => return Err(HarnessError::HandshakeRejected),
        }
    }
    if !established {
        return Err(HarnessError::HandshakeRejected);
    }
    send.ok_or(HarnessError::HandshakeRejected)
}

fn delivered_headers_request(
    actions: Vec<SessionAction>,
) -> Result<(u64, Vec<BlockId>, BlockId), HarnessError> {
    if actions.len() != 1 {
        return Err(HarnessError::UnexpectedAction);
    }
    match actions.into_iter().next() {
        Some(SessionAction::Deliver {
            request_id,
            message: Message::GetHeaders { locator, stop_id },
        }) => Ok((request_id, locator, stop_id)),
        _ => Err(HarnessError::UnexpectedAction),
    }
}

fn only_headers_response(actions: Vec<SessionAction>) -> Result<SessionAction, HarnessError> {
    if actions.len() != 1 || !matches!(actions.first(), Some(SessionAction::HeadersResponse { .. }))
    {
        return Err(HarnessError::UnexpectedAction);
    }
    actions
        .into_iter()
        .next()
        .ok_or(HarnessError::UnexpectedAction)
}

fn delivered_block_request(
    actions: Vec<SessionAction>,
) -> Result<(u64, Vec<BlockId>), HarnessError> {
    if actions.len() != 1 {
        return Err(HarnessError::UnexpectedAction);
    }
    let Some(SessionAction::Deliver {
        request_id,
        message: Message::GetObjects(entries),
    }) = actions.into_iter().next()
    else {
        return Err(HarnessError::UnexpectedAction);
    };
    let mut seen = BTreeSet::new();
    let mut blocks = Vec::with_capacity(entries.len());
    for entry in entries {
        let InventoryEntry::Block(block_id) = entry else {
            return Err(HarnessError::UnexpectedAction);
        };
        if !seen.insert(block_id) {
            return Err(HarnessError::UnexpectedAction);
        }
        blocks.push(block_id);
    }
    Ok((request_id, blocks))
}

fn only_block_delivery(actions: Vec<SessionAction>) -> Result<SessionAction, HarnessError> {
    if actions.len() != 1
        || !matches!(
            actions.first(),
            Some(SessionAction::Deliver {
                message: Message::Block(_),
                ..
            })
        )
    {
        return Err(HarnessError::UnexpectedAction);
    }
    actions
        .into_iter()
        .next()
        .ok_or(HarnessError::UnexpectedAction)
}

#[cfg(test)]
mod tests {
    use out_codec::Block;
    use out_p2p::session::{HeaderSyncPhase, RequestKind};
    use out_p2p::{
        DecodeError, TYPE_BLOCK, TYPE_GET_HEADERS, TYPE_GET_OBJECTS, TYPE_HEADERS, TYPE_REJECT,
    };
    use out_storage::conformance::validated_reward_commit;
    use out_storage::{FaultPoint, RecoveryOutcome};

    use super::*;
    use crate::bootstrap::NodeBootstrap;
    use crate::sync::{BlockDeliveryInvalid, BlockDeliveryLocal};

    fn policy() -> HarnessPolicy {
        HarnessPolicy {
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
                maximum_overlay_headers: 32,
                maximum_blocks_per_request: 4,
                maximum_locator_entries: 16,
                linear_locator_entries: 4,
                maximum_locator_walk: 128,
            },
            maximum_catalog_blocks: 32,
            maximum_headers_per_response: MAX_HEADERS,
            maximum_sync_rounds: 8,
            first_object_request_id: 1_000,
        }
    }

    fn bootstrap(network: SupportedNetwork) -> Node<InMemoryConsensusStore> {
        NodeBootstrap {
            network,
            maximum_reorganization_blocks: 100,
        }
        .create_in_memory()
        .expect("bootstrap")
    }

    fn source_with_blocks(count: u8) -> (Node<InMemoryConsensusStore>, Vec<Block>) {
        let mut source = bootstrap(SupportedNetwork::Devnet);
        let blocks = append_blocks(&mut source, count, b"source");
        (source, blocks)
    }

    fn append_blocks(
        node: &mut Node<InMemoryConsensusStore>,
        count: u8,
        label: &[u8],
    ) -> Vec<Block> {
        let mut parent = node.canonical_tip().expect("tip").block_id;
        let mut blocks = Vec::new();
        for index in 0..count {
            let mut extra = label.to_vec();
            extra.push(index);
            let commit = validated_reward_commit(node.storage(), parent, &extra);
            let raw = commit.canonical_block_bytes().to_vec();
            let block = Block::decode_non_genesis_exact(&raw).expect("block");
            let outcome = node
                .process_block(&raw, block.header.timestamp)
                .expect("process fixture block");
            parent = outcome.stored.block_id;
            blocks.push(block);
        }
        blocks
    }

    #[test]
    fn harness_header_response_limit_is_nonzero_and_wire_bounded() {
        let mut invalid = policy();
        invalid.maximum_headers_per_response = 0;
        assert_eq!(
            invalid.validate(),
            Err(HarnessPolicyError::Zero("maximum_headers_per_response"))
        );

        invalid.maximum_headers_per_response = MAX_HEADERS + 1;
        assert_eq!(
            invalid.validate(),
            Err(HarnessPolicyError::HeadersPerResponseAboveWireMaximum {
                actual: MAX_HEADERS + 1,
                maximum: MAX_HEADERS,
            })
        );
    }

    #[test]
    fn two_nodes_exchange_real_frames_and_reach_the_same_tip() {
        let (source, blocks) = source_with_blocks(3);
        let target = bootstrap(SupportedNetwork::Devnet);
        let now = source.canonical_tip().expect("tip").height + 2_000_000_000;
        let mut harness = InMemoryTwoNodeHarness::establish(source, target, blocks, now, policy())
            .expect("establish");

        let outcome = harness.synchronize(now).expect("synchronize");
        assert_eq!(outcome.source_tip, outcome.target_tip);
        assert_eq!(outcome.blocks_delivered, 3);
        assert_eq!(outcome.header_rounds, 1);
        assert_eq!(harness.coordinator().overlay_header_count(), 0);
        assert_eq!(harness.coordinator().queued_block_count(), 0);
        assert_eq!(harness.coordinator().in_flight_block_count(), 0);

        let message_types: Vec<_> = harness
            .transcript()
            .iter()
            .map(|record| record.message_type)
            .collect();
        assert!(message_types.contains(&TYPE_GET_HEADERS));
        assert!(message_types.contains(&TYPE_HEADERS));
        assert!(message_types.contains(&TYPE_GET_OBJECTS));
        assert_eq!(
            message_types
                .iter()
                .filter(|message_type| **message_type == TYPE_BLOCK)
                .count(),
            3
        );
    }

    #[test]
    fn transcript_is_byte_for_byte_deterministic() {
        fn run() -> Vec<TransferRecord> {
            let (source, blocks) = source_with_blocks(2);
            let target = bootstrap(SupportedNetwork::Devnet);
            let now = 2_000_000_100;
            let mut harness =
                InMemoryTwoNodeHarness::establish(source, target, blocks, now, policy())
                    .expect("establish");
            harness.synchronize(now).expect("synchronize");
            harness.transcript().to_vec()
        }
        assert_eq!(run(), run());
    }

    #[test]
    fn corrupted_record_is_rejected_without_mutating_the_receiver() {
        let (source, blocks) = source_with_blocks(1);
        let target = bootstrap(SupportedNetwork::Devnet);
        let mut harness =
            InMemoryTwoNodeHarness::establish(source, target, blocks, 2_000_000_100, policy())
                .expect("establish");
        harness.synchronize(2_000_000_100).expect("synchronize");
        let record = harness
            .transcript()
            .iter()
            .find(|record| record.direction == TransferDirection::SourceToTarget)
            .expect("source frame");
        let mut corrupted = record.frame_bytes.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        let before = harness.target().canonical_tip().expect("tip");
        assert_eq!(
            harness.decode_at_receiver(record.direction, &corrupted),
            Err(DecodeError::ChecksumMismatch)
        );
        assert_eq!(harness.target().canonical_tip().expect("tip"), before);
    }

    #[test]
    fn cross_network_handshake_is_rejected_at_the_frame_boundary() {
        let (source, blocks) = source_with_blocks(0);
        let target = bootstrap(SupportedNetwork::Testnet);
        let error =
            InMemoryTwoNodeHarness::establish(source, target, blocks, 2_000_000_100, policy())
                .err()
                .expect("cross-network rejection");
        assert_eq!(error, HarnessError::Decode(DecodeError::WrongNetworkMagic));
    }

    #[test]
    fn header_timeout_and_explicit_reject_return_sync_to_idle() {
        let (source, blocks) = source_with_blocks(1);
        let target = bootstrap(SupportedNetwork::Devnet);
        let now = 2_000_000_100;
        let mut harness = InMemoryTwoNodeHarness::establish(source, target, blocks, now, policy())
            .expect("establish");
        let stop_id = harness.source.canonical_tip().expect("tip").block_id;
        let locator = harness
            .sync
            .build_locator(harness.target.storage())
            .expect("locator");
        let request = harness
            .header_sync
            .begin(&mut harness.target_session, now, locator, stop_id)
            .expect("begin headers");
        let request = harness
            .transfer(request, TransferDirection::TargetToSource)
            .expect("transfer request");
        assert!(matches!(
            harness
                .source_session
                .handle_inbound(now, request)
                .expect("source request")
                .as_slice(),
            [SessionAction::Deliver {
                message: Message::GetHeaders { .. },
                ..
            }]
        ));
        let timeout_actions = harness
            .target_session
            .poll_timeouts(now + policy().session.response_timeout_ticks)
            .expect("timeout poll");
        let timeout = timeout_actions
            .iter()
            .find(|action| {
                matches!(
                    action,
                    SessionAction::RequestTimedOut {
                        kind: RequestKind::Headers,
                        ..
                    }
                )
            })
            .expect("header timeout");
        assert!(harness.header_sync.observe_terminal_action(timeout));
        assert_eq!(harness.header_sync.phase(), HeaderSyncPhase::Idle);

        let locator = harness
            .sync
            .build_locator(harness.target.storage())
            .expect("locator");
        let request = harness
            .header_sync
            .begin(&mut harness.target_session, now + 11, locator, stop_id)
            .expect("retry headers");
        let request = harness
            .transfer(request, TransferDirection::TargetToSource)
            .expect("transfer retry");
        let source_actions = harness
            .source_session
            .handle_inbound(now + 11, request)
            .expect("source retry");
        let (request_id, _, _) = delivered_headers_request(source_actions).expect("delivery");
        let reject = harness
            .source_session
            .make_response(
                request_id,
                Message::Reject {
                    rejected_type: TYPE_GET_HEADERS,
                    code: 1,
                    detail: b"fixture rejection".to_vec(),
                },
            )
            .expect("reject response");
        let reject = harness
            .transfer(reject, TransferDirection::SourceToTarget)
            .expect("transfer reject");
        let reject_actions = harness
            .target_session
            .handle_inbound(now + 11, reject)
            .expect("target reject");
        assert_eq!(reject_actions.len(), 1);
        assert!(harness
            .header_sync
            .observe_terminal_action(&reject_actions[0]));
        assert_eq!(harness.header_sync.phase(), HeaderSyncPhase::Idle);
        assert_eq!(
            harness
                .transcript()
                .last()
                .map(|record| record.message_type),
            Some(TYPE_REJECT)
        );
    }

    #[test]
    fn configured_header_cap_forces_multiple_canonical_batches() {
        let (source, blocks) = source_with_blocks(3);
        let target = bootstrap(SupportedNetwork::Devnet);
        let mut bounded = policy();
        bounded.maximum_headers_per_response = 1;
        let now = 2_000_000_100;
        let mut harness = InMemoryTwoNodeHarness::establish(source, target, blocks, now, bounded)
            .expect("establish");
        let outcome = harness.synchronize(now).expect("multi-batch sync");
        assert_eq!(outcome.header_rounds, 3);
        assert_eq!(outcome.blocks_delivered, 3);
        assert_eq!(outcome.target_tip, outcome.source_tip);
        assert_eq!(
            harness
                .transcript()
                .iter()
                .filter(|record| record.message_type == TYPE_HEADERS)
                .count(),
            3
        );
    }

    #[test]
    fn reordered_and_duplicate_blocks_fail_without_diverging_state() {
        let (source, blocks) = source_with_blocks(2);
        let target = bootstrap(SupportedNetwork::Devnet);
        let now = 2_000_000_100;
        let mut harness = InMemoryTwoNodeHarness::establish(source, target, blocks, now, policy())
            .expect("establish");
        let source_tip = harness.source.canonical_tip().expect("tip");
        harness
            .exchange_header_batch(source_tip.block_id, now)
            .expect("headers");
        let requested = harness.sync.next_block_request();
        assert_eq!(requested.len(), 2);
        let parent_id = requested[0];
        let child_id = requested[1];
        let (request_id, delivered) = harness
            .begin_block_request(requested, now)
            .expect("objects request");
        assert_eq!(delivered, vec![parent_id, child_id]);

        assert!(matches!(
            harness
                .relay_catalog_block(request_id, child_id, now)
                .expect("child frame"),
            Err(BlockDeliveryFailure::Local {
                block_id: Some(actual),
                error,
                ..
            }) if actual == child_id
                && matches!(*error, BlockDeliveryLocal::Consensus(_))
        ));
        assert!(matches!(
            harness
                .relay_catalog_block(request_id, parent_id, now)
                .expect("parent frame"),
            Ok(BlockDeliveryOutcome::Processed { .. })
        ));
        assert!(matches!(
            harness
                .relay_catalog_block(request_id, parent_id, now)
                .expect("duplicate frame"),
            Err(BlockDeliveryFailure::PeerInvalid {
                block_id: Some(actual),
                error,
                ..
            }) if actual == parent_id
                && *error == BlockDeliveryInvalid::UnrequestedBlock(parent_id)
        ));

        let retry = harness.sync.next_block_request();
        assert_eq!(retry, vec![child_id]);
        let (retry_request_id, delivered) = harness
            .begin_block_request(retry, now)
            .expect("retry request");
        assert_eq!(delivered, vec![child_id]);
        assert!(matches!(
            harness
                .relay_catalog_block(retry_request_id, child_id, now)
                .expect("child retry frame"),
            Ok(BlockDeliveryOutcome::Processed { .. })
        ));
        assert_eq!(harness.target.canonical_tip().expect("tip"), source_tip);
    }

    #[test]
    fn longer_source_fork_reorganizes_target_through_normal_sync() {
        let mut source = bootstrap(SupportedNetwork::Devnet);
        let source_blocks = append_blocks(&mut source, 2, b"winning-b");
        let winning_tip = source.canonical_tip().expect("source tip");
        let winning_height_one = block_id_from_header_bytes(&source_blocks[0].header.encode());

        let mut target = bootstrap(SupportedNetwork::Devnet);
        let losing = append_blocks(&mut target, 1, b"losing-a");
        let losing_id = block_id_from_header_bytes(&losing[0].header.encode());
        assert_ne!(losing_id, winning_height_one);

        let now = 2_000_000_100;
        let mut harness =
            InMemoryTwoNodeHarness::establish(source, target, source_blocks, now, policy())
                .expect("establish");
        let outcome = harness.synchronize(now).expect("fork sync");
        assert_eq!(outcome.target_tip, winning_tip);
        assert_eq!(
            harness.target.storage().canonical_block_id(1),
            Ok(Some(winning_height_one))
        );
        assert_eq!(harness.target.storage().contains_block(losing_id), Ok(true));
    }

    #[test]
    fn interrupted_block_store_recovers_and_reconciles_replayed_frame() {
        let (source, blocks) = source_with_blocks(1);
        let target = bootstrap(SupportedNetwork::Devnet);
        let now = 2_000_000_100;
        let mut harness = InMemoryTwoNodeHarness::establish(source, target, blocks, now, policy())
            .expect("establish");
        let source_tip = harness.source.canonical_tip().expect("tip");
        harness
            .exchange_header_batch(source_tip.block_id, now)
            .expect("headers");
        let requested = harness.sync.next_block_request();
        assert_eq!(requested, vec![source_tip.block_id]);
        let (request_id, delivered) = harness
            .begin_block_request(requested, now)
            .expect("objects request");
        assert_eq!(delivered, vec![source_tip.block_id]);
        harness
            .target
            .storage_mut()
            .inject_fault_once(FaultPoint::AfterPublish)
            .expect("inject fault");
        assert!(matches!(
            harness
                .relay_catalog_block(request_id, source_tip.block_id, now)
                .expect("faulted frame"),
            Err(BlockDeliveryFailure::Local { error, .. })
                if matches!(*error, BlockDeliveryLocal::StorageMutation(_))
        ));
        assert_eq!(harness.sync.in_flight_block_count(), 1);
        assert_eq!(
            harness.target.recover_storage(),
            Ok(RecoveryOutcome::FinalizedPublished)
        );
        assert!(matches!(
            harness
                .relay_catalog_block(request_id, source_tip.block_id, now)
                .expect("replayed frame"),
            Ok(BlockDeliveryOutcome::AlreadyStored {
                block_id,
                ..
            }) if block_id == source_tip.block_id
        ));
        assert_eq!(harness.target.canonical_tip().expect("tip"), source_tip);
        assert_eq!(harness.sync.in_flight_block_count(), 0);
    }
}
