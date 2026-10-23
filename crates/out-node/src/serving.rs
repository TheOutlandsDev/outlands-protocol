//! Bounded, socket-free inbound header and block serving policy.
//!
//! Header responses are derived only from validated canonical ancestry. Full
//! block bytes live in a separate non-authoritative relay cache and are
//! rechecked against the current canonical chain before every response.

use std::collections::{BTreeMap, VecDeque};

use out_codec::{Block, BlockHeader, EncodeError, RegularTransaction, Transaction};
use out_consensus::block_id_from_header_bytes;
use out_consensus::chain::ValidatedHeaderMetadata;
use out_p2p::{
    InventoryEntry, Message, MAX_HEADERS, MAX_INV_ENTRIES, TYPE_GET_HEADERS, TYPE_GET_OBJECTS,
};
use out_primitives::{BlockId, TransactionId};
use out_storage::ConsensusStorage;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServingPolicy {
    pub maximum_pending_requests: u16,
    pub maximum_responses_per_step: u16,
    pub maximum_pending_announcements: u16,
    pub maximum_announcements_per_step: u16,
    pub maximum_inventory_entries_per_announcement: u16,
    pub maximum_headers_per_response: u16,
    pub maximum_ancestry_records: u16,
    pub maximum_relay_blocks: u16,
    pub maximum_relay_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServingPolicyError {
    Zero(&'static str),
    HeadersAboveWireMaximum { actual: u16, maximum: u16 },
    ResponsesAboveDispatcherCommands { responses: u16, commands: u16 },
    AnnouncementsAboveDispatcherCommands { announcements: u16, commands: u16 },
    InventoryAboveWireMaximum { actual: u16, maximum: u16 },
}

impl ServingPolicy {
    pub fn validate(self, maximum_dispatcher_commands: u16) -> Result<Self, ServingPolicyError> {
        let nonzero = [
            (
                u64::from(self.maximum_pending_requests),
                "maximum_pending_requests",
            ),
            (
                u64::from(self.maximum_responses_per_step),
                "maximum_responses_per_step",
            ),
            (
                u64::from(self.maximum_headers_per_response),
                "maximum_headers_per_response",
            ),
            (
                u64::from(self.maximum_pending_announcements),
                "maximum_pending_announcements",
            ),
            (
                u64::from(self.maximum_announcements_per_step),
                "maximum_announcements_per_step",
            ),
            (
                u64::from(self.maximum_inventory_entries_per_announcement),
                "maximum_inventory_entries_per_announcement",
            ),
            (
                u64::from(self.maximum_ancestry_records),
                "maximum_ancestry_records",
            ),
            (u64::from(self.maximum_relay_blocks), "maximum_relay_blocks"),
            (self.maximum_relay_bytes, "maximum_relay_bytes"),
        ];
        if let Some((_, field)) = nonzero.into_iter().find(|(value, _)| *value == 0) {
            return Err(ServingPolicyError::Zero(field));
        }
        if self.maximum_headers_per_response > MAX_HEADERS {
            return Err(ServingPolicyError::HeadersAboveWireMaximum {
                actual: self.maximum_headers_per_response,
                maximum: MAX_HEADERS,
            });
        }
        if self.maximum_responses_per_step > maximum_dispatcher_commands {
            return Err(ServingPolicyError::ResponsesAboveDispatcherCommands {
                responses: self.maximum_responses_per_step,
                commands: maximum_dispatcher_commands,
            });
        }
        if self.maximum_announcements_per_step > maximum_dispatcher_commands {
            return Err(ServingPolicyError::AnnouncementsAboveDispatcherCommands {
                announcements: self.maximum_announcements_per_step,
                commands: maximum_dispatcher_commands,
            });
        }
        if self.maximum_inventory_entries_per_announcement > MAX_INV_ENTRIES {
            return Err(ServingPolicyError::InventoryAboveWireMaximum {
                actual: self.maximum_inventory_entries_per_announcement,
                maximum: MAX_INV_ENTRIES,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServingError<E> {
    Store(E),
    MissingCanonicalTip(BlockId),
    CorruptHeader(BlockId),
    BrokenAncestry { child: BlockId, parent: BlockId },
    HeightDiscontinuity { child: BlockId, parent: BlockId },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnnouncementError<E> {
    Empty,
    TooMany { actual: usize, maximum: u16 },
    Duplicate(InventoryEntry),
    BlockNotRelayed(BlockId),
    BlockNotCanonical(BlockId),
    Serving(ServingError<E>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayAdmission {
    Stored {
        block_id: BlockId,
        evicted: Vec<BlockId>,
    },
    AlreadyStored {
        block_id: BlockId,
    },
    SkippedGenesis {
        block_id: BlockId,
    },
    SkippedOversize {
        block_id: BlockId,
        bytes: u64,
        maximum: u64,
    },
    ConflictingBody {
        block_id: BlockId,
    },
    EncodingFailed {
        block_id: BlockId,
        error: EncodeError,
    },
    AccountingFailed {
        block_id: BlockId,
    },
}

#[derive(Clone, Debug)]
struct RelayEntry {
    block: Block,
    canonical_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RelayCache {
    maximum_blocks: u16,
    maximum_bytes: u64,
    entries: BTreeMap<BlockId, RelayEntry>,
    insertion_order: VecDeque<BlockId>,
    bytes: u64,
}

impl RelayCache {
    fn new(policy: ServingPolicy) -> Self {
        Self {
            maximum_blocks: policy.maximum_relay_blocks,
            maximum_bytes: policy.maximum_relay_bytes,
            entries: BTreeMap::new(),
            insertion_order: VecDeque::new(),
            bytes: 0,
        }
    }

    pub fn block_count(&self) -> usize {
        self.entries.len()
    }

    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Admits bytes only after the caller has completed full block validation.
    /// The cache remains non-authoritative: serving always rechecks canonical
    /// ancestry, and cache loss cannot affect consensus.
    pub(crate) fn admit_validated(&mut self, block: Block) -> RelayAdmission {
        let block_id = block_id_from_header_bytes(&block.header.encode());
        if block.header.height == 0 {
            return RelayAdmission::SkippedGenesis { block_id };
        }
        let canonical_bytes = match block.encode_non_genesis() {
            Ok(bytes) => bytes,
            Err(error) => {
                return RelayAdmission::EncodingFailed { block_id, error };
            }
        };
        let byte_length = match u64::try_from(canonical_bytes.len()) {
            Ok(length) => length,
            Err(_) => return RelayAdmission::AccountingFailed { block_id },
        };
        if byte_length > self.maximum_bytes {
            return RelayAdmission::SkippedOversize {
                block_id,
                bytes: byte_length,
                maximum: self.maximum_bytes,
            };
        }
        if let Some(existing) = self.entries.get(&block_id) {
            return if existing.canonical_bytes == canonical_bytes {
                RelayAdmission::AlreadyStored { block_id }
            } else {
                RelayAdmission::ConflictingBody { block_id }
            };
        }

        let mut evicted = Vec::new();
        loop {
            let next_count = match self.entries.len().checked_add(1) {
                Some(count) => count,
                None => return RelayAdmission::AccountingFailed { block_id },
            };
            let next_bytes = match self.bytes.checked_add(byte_length) {
                Some(bytes) => bytes,
                None => return RelayAdmission::AccountingFailed { block_id },
            };
            if next_count <= usize::from(self.maximum_blocks) && next_bytes <= self.maximum_bytes {
                break;
            }
            let Some(oldest) = self.insertion_order.pop_front() else {
                return RelayAdmission::AccountingFailed { block_id };
            };
            let Some(removed) = self.entries.remove(&oldest) else {
                return RelayAdmission::AccountingFailed { block_id };
            };
            let removed_length = match u64::try_from(removed.canonical_bytes.len()) {
                Ok(length) => length,
                Err(_) => return RelayAdmission::AccountingFailed { block_id },
            };
            self.bytes = match self.bytes.checked_sub(removed_length) {
                Some(bytes) => bytes,
                None => return RelayAdmission::AccountingFailed { block_id },
            };
            evicted.push(oldest);
        }
        self.bytes = match self.bytes.checked_add(byte_length) {
            Some(bytes) => bytes,
            None => return RelayAdmission::AccountingFailed { block_id },
        };
        self.entries.insert(
            block_id,
            RelayEntry {
                block,
                canonical_bytes,
            },
        );
        self.insertion_order.push_back(block_id);
        RelayAdmission::Stored { block_id, evicted }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServingReply {
    Headers {
        headers: Vec<BlockHeader>,
    },
    Block {
        block_id: BlockId,
        block: Box<Block>,
    },
    Transaction {
        transaction_id: TransactionId,
        transaction: Box<RegularTransaction>,
    },
    Reject {
        rejected_type: u16,
        code: u16,
        detail: &'static [u8],
    },
}

impl ServingReply {
    pub fn into_message(self) -> Message {
        match self {
            Self::Headers { headers } => Message::Headers(headers),
            Self::Block { block, .. } => Message::Block(*block),
            Self::Transaction { transaction, .. } => {
                Message::Transaction(Transaction::Regular(*transaction))
            }
            Self::Reject {
                rejected_type,
                code,
                detail,
            } => Message::Reject {
                rejected_type,
                code,
                detail: detail.to_vec(),
            },
        }
    }
}

pub struct InboundServing {
    policy: ServingPolicy,
    relay: RelayCache,
}

impl InboundServing {
    pub fn new(
        policy: ServingPolicy,
        maximum_dispatcher_commands: u16,
    ) -> Result<Self, ServingPolicyError> {
        let policy = policy.validate(maximum_dispatcher_commands)?;
        Ok(Self {
            policy,
            relay: RelayCache::new(policy),
        })
    }

    pub const fn policy(&self) -> ServingPolicy {
        self.policy
    }

    pub const fn relay(&self) -> &RelayCache {
        &self.relay
    }

    pub(crate) fn admit_validated(&mut self, block: Block) -> RelayAdmission {
        self.relay.admit_validated(block)
    }

    /// Validates a whole announcement against one canonical-ancestry snapshot.
    /// Relay presence alone is insufficient: stale-fork bodies are refused.
    pub fn canonical_relay_inventory<S: ConsensusStorage>(
        &self,
        storage: &S,
        block_ids: &[BlockId],
    ) -> Result<Vec<InventoryEntry>, AnnouncementError<S::Error>> {
        if block_ids.is_empty() {
            return Err(AnnouncementError::Empty);
        }
        if block_ids.len() > usize::from(self.policy.maximum_inventory_entries_per_announcement) {
            return Err(AnnouncementError::TooMany {
                actual: block_ids.len(),
                maximum: self.policy.maximum_inventory_entries_per_announcement,
            });
        }
        let mut unique = std::collections::BTreeSet::new();
        for block_id in block_ids {
            let entry = InventoryEntry::Block(*block_id);
            if !unique.insert(entry) {
                return Err(AnnouncementError::Duplicate(entry));
            }
            if !self.relay.entries.contains_key(block_id) {
                return Err(AnnouncementError::BlockNotRelayed(*block_id));
            }
        }
        let ancestry = canonical_ancestry(storage, self.policy.maximum_ancestry_records)
            .map_err(AnnouncementError::Serving)?;
        for block_id in block_ids {
            let entry = self
                .relay
                .entries
                .get(block_id)
                .ok_or(AnnouncementError::BlockNotRelayed(*block_id))?;
            let canonical = ancestry.records.iter().any(|metadata| {
                metadata.block_id() == *block_id && metadata.header() == entry.block.header
            });
            if !canonical {
                return Err(AnnouncementError::BlockNotCanonical(*block_id));
            }
        }
        Ok(block_ids
            .iter()
            .copied()
            .map(InventoryEntry::Block)
            .collect())
    }

    pub fn serve_headers<S: ConsensusStorage>(
        &self,
        storage: &S,
        locator: &[BlockId],
        stop_id: BlockId,
    ) -> Result<ServingReply, ServingError<S::Error>> {
        let ancestry = canonical_ancestry(storage, self.policy.maximum_ancestry_records)?;
        let common_index = locator.iter().find_map(|locator_id| {
            ancestry
                .records
                .iter()
                .position(|metadata| metadata.block_id() == *locator_id)
        });
        let Some(common_index) = common_index else {
            return Ok(ServingReply::Reject {
                rejected_type: TYPE_GET_HEADERS,
                code: 1,
                detail: b"no-common-ancestor",
            });
        };
        let mut headers = Vec::with_capacity(usize::from(self.policy.maximum_headers_per_response));
        for metadata in ancestry.records[..common_index].iter().rev() {
            if headers.len() >= usize::from(self.policy.maximum_headers_per_response) {
                break;
            }
            headers.push(metadata.header());
            if metadata.block_id() == stop_id {
                break;
            }
        }
        Ok(ServingReply::Headers { headers })
    }

    pub fn serve_objects<S: ConsensusStorage>(
        &self,
        storage: &S,
        objects: &[InventoryEntry],
    ) -> Result<ServingReply, ServingError<S::Error>> {
        let [InventoryEntry::Block(block_id)] = objects else {
            return Ok(ServingReply::Reject {
                rejected_type: TYPE_GET_OBJECTS,
                code: 1,
                detail: b"exactly-one-block-required",
            });
        };
        let Some(entry) = self.relay.entries.get(block_id) else {
            return Ok(ServingReply::Reject {
                rejected_type: TYPE_GET_OBJECTS,
                code: 2,
                detail: b"block-not-relayed",
            });
        };
        let ancestry = canonical_ancestry(storage, self.policy.maximum_ancestry_records)?;
        let canonical = ancestry.records.iter().any(|metadata| {
            metadata.block_id() == *block_id && metadata.header() == entry.block.header
        });
        if !canonical {
            return Ok(ServingReply::Reject {
                rejected_type: TYPE_GET_OBJECTS,
                code: 2,
                detail: b"block-not-canonical",
            });
        }
        Ok(ServingReply::Block {
            block_id: *block_id,
            block: Box::new(entry.block.clone()),
        })
    }

    pub fn serve_transaction(
        &self,
        transaction_id: TransactionId,
        transaction: Option<&RegularTransaction>,
    ) -> ServingReply {
        match transaction {
            Some(transaction) => ServingReply::Transaction {
                transaction_id,
                transaction: Box::new(transaction.clone()),
            },
            None => ServingReply::Reject {
                rejected_type: TYPE_GET_OBJECTS,
                code: 2,
                detail: b"transaction-not-relayed",
            },
        }
    }
}

struct CanonicalAncestry {
    /// Descending order: canonical tip first, oldest retained record last.
    records: Vec<ValidatedHeaderMetadata>,
}

fn canonical_ancestry<S: ConsensusStorage>(
    storage: &S,
    maximum_records: u16,
) -> Result<CanonicalAncestry, ServingError<S::Error>> {
    let tip = storage.canonical_tip().map_err(ServingError::Store)?;
    let mut current = storage
        .get_validated_header(tip.block_id)
        .map_err(ServingError::Store)?
        .ok_or(ServingError::MissingCanonicalTip(tip.block_id))?;
    if current.tip() != tip
        || block_id_from_header_bytes(&current.header().encode()) != tip.block_id
    {
        return Err(ServingError::CorruptHeader(tip.block_id));
    }
    let mut records = Vec::with_capacity(usize::from(maximum_records));
    for _ in 0..maximum_records {
        let current_id = current.block_id();
        records.push(current);
        if current.header().height == 0 {
            break;
        }
        let parent_id = current.header().parent_block_id;
        let parent = storage
            .get_validated_header(parent_id)
            .map_err(ServingError::Store)?
            .ok_or(ServingError::BrokenAncestry {
                child: current_id,
                parent: parent_id,
            })?;
        if block_id_from_header_bytes(&parent.header().encode()) != parent_id {
            return Err(ServingError::CorruptHeader(parent_id));
        }
        if parent.header().height.checked_add(1) != Some(current.header().height) {
            return Err(ServingError::HeightDiscontinuity {
                child: current_id,
                parent: parent_id,
            });
        }
        current = parent;
    }
    Ok(CanonicalAncestry { records })
}

#[cfg(test)]
mod tests {
    use out_storage::conformance::validated_reward_commit;
    use out_storage::InMemoryConsensusStore;

    use super::*;
    use crate::bootstrap::NodeBootstrap;
    use crate::{Node, SupportedNetwork};

    fn policy() -> ServingPolicy {
        ServingPolicy {
            maximum_pending_requests: 4,
            maximum_responses_per_step: 2,
            maximum_pending_announcements: 4,
            maximum_announcements_per_step: 2,
            maximum_inventory_entries_per_announcement: 8,
            maximum_headers_per_response: 8,
            maximum_ancestry_records: 32,
            maximum_relay_blocks: 4,
            maximum_relay_bytes: 4_000_000,
        }
    }

    fn node() -> Node<InMemoryConsensusStore> {
        NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        }
        .create_in_memory()
        .expect("node")
    }

    fn append(node: &mut Node<InMemoryConsensusStore>, parent: BlockId, tag: &[u8]) -> Block {
        let commit = validated_reward_commit(node.storage(), parent, tag);
        let raw = commit.canonical_block_bytes().to_vec();
        let block = Block::decode_non_genesis_exact(&raw).expect("block");
        node.process_block(&raw, block.header.timestamp)
            .expect("process");
        block
    }

    #[test]
    fn policy_rejects_zero_wire_excess_and_response_budget_mismatch() {
        let mut candidate = policy();
        candidate.maximum_pending_requests = 0;
        assert_eq!(
            candidate.validate(2),
            Err(ServingPolicyError::Zero("maximum_pending_requests"))
        );
        candidate = policy();
        candidate.maximum_headers_per_response = MAX_HEADERS + 1;
        assert!(matches!(
            candidate.validate(2),
            Err(ServingPolicyError::HeadersAboveWireMaximum { .. })
        ));
        candidate = policy();
        candidate.maximum_responses_per_step = 3;
        assert_eq!(
            candidate.validate(2),
            Err(ServingPolicyError::ResponsesAboveDispatcherCommands {
                responses: 3,
                commands: 2,
            })
        );
        candidate = policy();
        candidate.maximum_pending_announcements = 0;
        assert_eq!(
            candidate.validate(2),
            Err(ServingPolicyError::Zero("maximum_pending_announcements"))
        );
        candidate = policy();
        candidate.maximum_announcements_per_step = 3;
        assert_eq!(
            candidate.validate(2),
            Err(ServingPolicyError::AnnouncementsAboveDispatcherCommands {
                announcements: 3,
                commands: 2,
            })
        );
        candidate = policy();
        candidate.maximum_inventory_entries_per_announcement = MAX_INV_ENTRIES + 1;
        assert!(matches!(
            candidate.validate(2),
            Err(ServingPolicyError::InventoryAboveWireMaximum { .. })
        ));
    }

    #[test]
    fn headers_follow_canonical_ancestry_stop_and_response_bound() {
        let mut source = node();
        let genesis = source.canonical_tip().unwrap().block_id;
        let first = append(&mut source, genesis, b"serve-1");
        let first_id = block_id_from_header_bytes(&first.header.encode());
        let second = append(&mut source, first_id, b"serve-2");
        let second_id = block_id_from_header_bytes(&second.header.encode());
        let third = append(&mut source, second_id, b"serve-3");
        let third_id = block_id_from_header_bytes(&third.header.encode());

        let mut bounded = policy();
        bounded.maximum_headers_per_response = 2;
        let serving = InboundServing::new(bounded, 2).unwrap();
        assert_eq!(
            serving
                .serve_headers(source.storage(), &[genesis], third_id)
                .unwrap(),
            ServingReply::Headers {
                headers: vec![first.header, second.header],
            }
        );
        assert_eq!(
            serving
                .serve_headers(source.storage(), &[genesis], first_id)
                .unwrap(),
            ServingReply::Headers {
                headers: vec![first.header],
            }
        );
        assert_eq!(
            serving
                .serve_headers(source.storage(), &[third_id], BlockId::new([0; 32]))
                .unwrap(),
            ServingReply::Headers {
                headers: Vec::new(),
            }
        );
        assert!(matches!(
            serving
                .serve_headers(source.storage(), &[BlockId::new([0x55; 32])], third_id,)
                .unwrap(),
            ServingReply::Reject {
                rejected_type: TYPE_GET_HEADERS,
                ..
            }
        ));
    }

    #[test]
    fn relay_cache_evicts_fifo_and_refuses_noncanonical_or_ambiguous_requests() {
        let mut source = node();
        let genesis = source.canonical_tip().unwrap().block_id;
        let first = append(&mut source, genesis, b"relay-a1");
        let first_id = block_id_from_header_bytes(&first.header.encode());
        let mut bounded = policy();
        bounded.maximum_relay_blocks = 1;
        let mut serving = InboundServing::new(bounded, 2).unwrap();
        assert!(matches!(
            serving.admit_validated(first.clone()),
            RelayAdmission::Stored { ref evicted, .. } if evicted.is_empty()
        ));
        assert!(matches!(
            serving
                .serve_objects(source.storage(), &[])
                .expect("ambiguous reject"),
            ServingReply::Reject {
                detail: b"exactly-one-block-required",
                ..
            }
        ));

        let fork_first = append(&mut source, genesis, b"relay-b1");
        let fork_first_id = block_id_from_header_bytes(&fork_first.header.encode());
        let fork_second = append(&mut source, fork_first_id, b"relay-b2");
        let fork_second_id = block_id_from_header_bytes(&fork_second.header.encode());
        assert_eq!(source.canonical_tip().unwrap().block_id, fork_second_id);
        assert!(matches!(
            serving
                .serve_objects(source.storage(), &[InventoryEntry::Block(first_id)])
                .unwrap(),
            ServingReply::Reject {
                detail: b"block-not-canonical",
                ..
            }
        ));
        assert!(matches!(
            serving.admit_validated(fork_first),
            RelayAdmission::Stored { ref evicted, .. } if evicted == &vec![first_id]
        ));
        assert!(matches!(
            serving
                .serve_objects(source.storage(), &[InventoryEntry::Block(first_id)])
                .unwrap(),
            ServingReply::Reject {
                detail: b"block-not-relayed",
                ..
            }
        ));
        assert!(matches!(
            serving
                .serve_objects(
                    source.storage(),
                    &[InventoryEntry::Block(fork_first_id)],
                )
                .unwrap(),
            ServingReply::Block { block_id, .. } if block_id == fork_first_id
        ));
    }
}
