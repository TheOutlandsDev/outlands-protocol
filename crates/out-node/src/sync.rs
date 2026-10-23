//! Pure testnet/devnet header and block-download synchronization planning.
//!
//! Header-only metadata is a bounded, disposable overlay. Only complete blocks
//! validated and committed through `Node` may enter authoritative storage.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use out_codec::EncodeError;
use out_consensus::block::{BlockInvalid, BlockLocalFailure, BlockValidationFailure};
use out_consensus::chain::{
    validate_child_header, ChainTip, ChildHeaderInvalid, ChildHeaderLocalFailure,
    ChildHeaderValidationFailure, ValidatedHeaderMetadata, ValidatedHeaderView,
};
use out_consensus::{
    block_id_from_header_bytes, IdentityError, NetworkIdentity, TimestampTemporaryFailure,
};
use out_p2p::session::{HeaderBatch, SessionAction};
use out_p2p::{Message, MAX_HEADERS, MAX_INV_ENTRIES, MAX_LOCATOR_ENTRIES};
use out_primitives::BlockId;
use out_storage::ConsensusStorage;

use crate::{
    ActivationError, ActivationOutcome, IngestError, Node, ProcessBlockError, ProcessBlockOutcome,
    StoredBlock, SupportedNetwork,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncPolicy {
    /// Total disposable header-only records retained across batches.
    pub maximum_overlay_headers: u16,
    /// Maximum block IDs emitted by one retrieval work item.
    pub maximum_blocks_per_request: u16,
    /// Maximum entries in a block locator; cannot exceed the wire bound.
    pub maximum_locator_entries: u16,
    /// Initial locator entries, including the tip, that use one-parent steps.
    pub linear_locator_entries: u16,
    /// Maximum parent links read during one locator construction.
    pub maximum_locator_walk: u64,
}

impl SyncPolicy {
    pub fn validate(self) -> Result<Self, SyncPolicyError> {
        if self.maximum_overlay_headers == 0 {
            return Err(SyncPolicyError::Zero("maximum_overlay_headers"));
        }
        if self.maximum_blocks_per_request == 0 {
            return Err(SyncPolicyError::Zero("maximum_blocks_per_request"));
        }
        if self.maximum_blocks_per_request > MAX_INV_ENTRIES {
            return Err(SyncPolicyError::AboveWireMaximum(
                "maximum_blocks_per_request",
            ));
        }
        if self.maximum_locator_entries == 0 {
            return Err(SyncPolicyError::Zero("maximum_locator_entries"));
        }
        if self.maximum_locator_entries > MAX_LOCATOR_ENTRIES {
            return Err(SyncPolicyError::AboveWireMaximum("maximum_locator_entries"));
        }
        if self.linear_locator_entries == 0
            || self.linear_locator_entries > self.maximum_locator_entries
        {
            return Err(SyncPolicyError::InvalidLinearLocatorEntries);
        }
        if self.maximum_locator_walk == 0 {
            return Err(SyncPolicyError::Zero("maximum_locator_walk"));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPolicyError {
    Zero(&'static str),
    AboveWireMaximum(&'static str),
    InvalidLinearLocatorEntries,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncOpenError<E> {
    Policy(SyncPolicyError),
    Store(E),
    MissingCanonicalTip(BlockId),
    CorruptCanonicalTip(BlockId),
    NetworkMismatch(IdentityError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderBatchInvalid {
    EmptyHeaderBatch,
    CountAboveWireMaximum {
        actual: usize,
        maximum: u16,
    },
    DuplicateHeader {
        index: u16,
        block_id: BlockId,
    },
    NonContiguous {
        index: u16,
        expected_parent: BlockId,
        actual_parent: BlockId,
    },
    Header {
        index: u16,
        error: ChildHeaderInvalid,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderBatchTemporary {
    Header {
        index: u16,
        error: out_consensus::TimestampTemporaryFailure,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderBatchLocal<E> {
    OverlayCapacity {
        maximum: u16,
    },
    Store(E),
    Header {
        index: u16,
        error: ChildHeaderLocalFailure<E>,
    },
    HeaderCountWidth,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderBatchFailure<E> {
    Invalid(HeaderBatchInvalid),
    TemporarilyUnacceptable(HeaderBatchTemporary),
    Local(HeaderBatchLocal<E>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderBatchOutcome {
    UpToDate {
        tip: ChainTip,
    },
    Accepted {
        tip: ChainTip,
        validated: Vec<BlockId>,
        scheduled: Vec<BlockId>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocatorError<E> {
    Store(E),
    MissingAncestor(BlockId),
    CorruptMetadata(BlockId),
    WalkLimit { maximum: u64 },
    WalkOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredBlockError<E> {
    Store(E),
    UnknownBlock(BlockId),
    NotStored(BlockId),
    MetadataMismatch(BlockId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryBlockError {
    NotInFlight(BlockId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginBlockRequestError {
    NotQueued(BlockId),
    AlreadyInFlight(BlockId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockDeliveryInvalid {
    ZeroRequestId,
    UnrequestedBlock(BlockId),
    GenesisBlock,
    CanonicalEncoding(EncodeError),
    Block(BlockInvalid),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockDeliveryLocal<ReadError, MutationError> {
    UnexpectedSessionAction,
    StoreRead(ReadError),
    MissingExpectedHeader(BlockId),
    ExpectedHeaderMismatch(BlockId),
    Consensus(BlockLocalFailure<ReadError>),
    ParentStateRead(ReadError),
    AncestorHistoryRead(ReadError),
    StorageMutation(MutationError),
    Coordinator(RetryBlockError),
    Completion(StoredBlockError<ReadError>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockDeliveryOutcome {
    Processed {
        request_id: u64,
        outcome: Box<ProcessBlockOutcome>,
    },
    AlreadyStored {
        request_id: u64,
        block_id: BlockId,
        activation: Box<ActivationOutcome>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockDeliveryFailure<ReadError, MutationError> {
    PeerInvalid {
        request_id: u64,
        block_id: Option<BlockId>,
        error: Box<BlockDeliveryInvalid>,
    },
    TemporarilyUnacceptable {
        request_id: u64,
        block_id: BlockId,
        error: TimestampTemporaryFailure,
    },
    Local {
        request_id: u64,
        block_id: Option<BlockId>,
        error: Box<BlockDeliveryLocal<ReadError, MutationError>>,
    },
    StoredButActivationFailed {
        request_id: u64,
        stored: StoredBlock,
        error: Box<ActivationError<ReadError, MutationError>>,
        completion_error: Option<Box<StoredBlockError<ReadError>>>,
    },
    ProcessedButSyncIncomplete {
        request_id: u64,
        outcome: Box<ProcessBlockOutcome>,
        error: Box<StoredBlockError<ReadError>>,
    },
}

#[derive(Clone, Debug)]
pub struct SyncCoordinator {
    network: SupportedNetwork,
    policy: SyncPolicy,
    overlay: BTreeMap<BlockId, ValidatedHeaderMetadata>,
    sync_tip: BlockId,
    queued: VecDeque<BlockId>,
    queued_set: BTreeSet<BlockId>,
    in_flight: BTreeSet<BlockId>,
}

impl SyncCoordinator {
    pub fn new<S: ConsensusStorage>(
        storage: &S,
        network: SupportedNetwork,
        policy: SyncPolicy,
    ) -> Result<Self, SyncOpenError<S::Error>> {
        let policy = policy.validate().map_err(SyncOpenError::Policy)?;
        let tip = storage.canonical_tip().map_err(SyncOpenError::Store)?;
        let metadata = storage
            .get_validated_header(tip.block_id)
            .map_err(SyncOpenError::Store)?
            .ok_or(SyncOpenError::MissingCanonicalTip(tip.block_id))?;
        if metadata.tip() != tip
            || block_id_from_header_bytes(&metadata.header().encode()) != tip.block_id
        {
            return Err(SyncOpenError::CorruptCanonicalTip(tip.block_id));
        }
        network
            .validation_parameters()
            .header
            .network
            .require_exact(identity_from_metadata(metadata))
            .map_err(SyncOpenError::NetworkMismatch)?;
        Ok(Self {
            network,
            policy,
            overlay: BTreeMap::new(),
            sync_tip: tip.block_id,
            queued: VecDeque::new(),
            queued_set: BTreeSet::new(),
            in_flight: BTreeSet::new(),
        })
    }

    pub const fn network(&self) -> SupportedNetwork {
        self.network
    }

    pub const fn policy(&self) -> SyncPolicy {
        self.policy
    }

    pub const fn sync_tip(&self) -> BlockId {
        self.sync_tip
    }

    pub fn sync_tip_height<S: ConsensusStorage>(
        &self,
        storage: &S,
    ) -> Result<u64, LocatorError<S::Error>> {
        let metadata = if let Some(metadata) = self.overlay.get(&self.sync_tip).copied() {
            metadata
        } else {
            storage
                .get_validated_header(self.sync_tip)
                .map_err(LocatorError::Store)?
                .ok_or(LocatorError::MissingAncestor(self.sync_tip))?
        };
        if metadata.block_id() != self.sync_tip
            || block_id_from_header_bytes(&metadata.header().encode()) != self.sync_tip
        {
            return Err(LocatorError::CorruptMetadata(self.sync_tip));
        }
        Ok(metadata.header().height)
    }

    pub fn overlay_header_count(&self) -> usize {
        self.overlay.len()
    }

    pub fn queued_block_count(&self) -> usize {
        self.queued.len()
    }

    pub fn in_flight_block_count(&self) -> usize {
        self.in_flight.len()
    }

    pub fn is_block_in_flight(&self, block_id: BlockId) -> bool {
        self.in_flight.contains(&block_id)
    }

    pub fn accept_header_batch<S: ConsensusStorage>(
        &mut self,
        storage: &S,
        batch: HeaderBatch,
        local_now: u64,
    ) -> Result<HeaderBatchOutcome, HeaderBatchFailure<S::Error>> {
        let headers = match batch {
            HeaderBatch::Complete => {
                let tip = self
                    .read_metadata(storage, self.sync_tip)
                    .map_err(HeaderBatchFailure::Local)?
                    .tip();
                return Ok(HeaderBatchOutcome::UpToDate { tip });
            }
            HeaderBatch::Validate(headers) => headers,
        };
        if headers.is_empty() {
            return Err(HeaderBatchFailure::Invalid(
                HeaderBatchInvalid::EmptyHeaderBatch,
            ));
        }
        if headers.len() > usize::from(MAX_HEADERS) {
            return Err(HeaderBatchFailure::Invalid(
                HeaderBatchInvalid::CountAboveWireMaximum {
                    actual: headers.len(),
                    maximum: MAX_HEADERS,
                },
            ));
        }

        let mut candidate_overlay = self.overlay.clone();
        let mut seen = BTreeSet::new();
        let mut validated = Vec::with_capacity(headers.len());
        let mut scheduled = Vec::with_capacity(headers.len());
        let mut previous_id = None;
        for (raw_index, header) in headers.into_iter().enumerate() {
            let index = u16::try_from(raw_index)
                .map_err(|_| HeaderBatchFailure::Local(HeaderBatchLocal::HeaderCountWidth))?;
            let block_id = block_id_from_header_bytes(&header.encode());
            if !seen.insert(block_id) {
                return Err(HeaderBatchFailure::Invalid(
                    HeaderBatchInvalid::DuplicateHeader { index, block_id },
                ));
            }
            if let Some(expected_parent) = previous_id {
                if header.parent_block_id != expected_parent {
                    return Err(HeaderBatchFailure::Invalid(
                        HeaderBatchInvalid::NonContiguous {
                            index,
                            expected_parent,
                            actual_parent: header.parent_block_id,
                        },
                    ));
                }
            }

            if let Some(known) = candidate_overlay.get(&block_id).copied() {
                if known.header() != header {
                    return Err(HeaderBatchFailure::Local(HeaderBatchLocal::Header {
                        index,
                        error: ChildHeaderLocalFailure::CorruptValidatedMetadata(block_id),
                    }));
                }
                validated.push(block_id);
                previous_id = Some(block_id);
                continue;
            }
            let stored = storage
                .get_validated_header(block_id)
                .map_err(|error| HeaderBatchFailure::Local(HeaderBatchLocal::Store(error)))?;
            if let Some(known) = stored {
                if known.header() != header {
                    return Err(HeaderBatchFailure::Local(HeaderBatchLocal::Header {
                        index,
                        error: ChildHeaderLocalFailure::CorruptValidatedMetadata(block_id),
                    }));
                }
                validated.push(block_id);
                previous_id = Some(block_id);
                // A durable block may have been published before activation
                // was interrupted. Consensus storage intentionally exposes no
                // raw-block retrieval API, so schedule the body again and let
                // `deliver_scheduled_block` reconcile the stored block and run
                // deterministic best-chain activation.
                if !self.queued_set.contains(&block_id) && !self.in_flight.contains(&block_id) {
                    scheduled.push(block_id);
                }
                continue;
            }
            if candidate_overlay.len() >= usize::from(self.policy.maximum_overlay_headers) {
                return Err(HeaderBatchFailure::Local(
                    HeaderBatchLocal::OverlayCapacity {
                        maximum: self.policy.maximum_overlay_headers,
                    },
                ));
            }
            let metadata = {
                let view = OverlayView {
                    storage,
                    overlay: &candidate_overlay,
                };
                validate_child_header(
                    header,
                    &view,
                    local_now,
                    self.network.validation_parameters().header,
                )
            }
            .map_err(|failure| map_header_failure(index, failure))?;
            candidate_overlay.insert(block_id, metadata);
            validated.push(block_id);
            previous_id = Some(block_id);
            if !self.queued_set.contains(&block_id) && !self.in_flight.contains(&block_id) {
                scheduled.push(block_id);
            }
        }

        let Some(&new_tip_id) = validated.last() else {
            return Err(HeaderBatchFailure::Local(
                HeaderBatchLocal::HeaderCountWidth,
            ));
        };
        let new_tip_metadata = if let Some(metadata) = candidate_overlay.get(&new_tip_id).copied() {
            metadata
        } else {
            storage
                .get_validated_header(new_tip_id)
                .map_err(|error| HeaderBatchFailure::Local(HeaderBatchLocal::Store(error)))?
                .ok_or_else(|| {
                    HeaderBatchFailure::Local(HeaderBatchLocal::Header {
                        index: u16::try_from(validated.len().saturating_sub(1)).unwrap_or(u16::MAX),
                        error: ChildHeaderLocalFailure::MissingParent(new_tip_id),
                    })
                })?
        };
        let new_tip = new_tip_metadata.tip();

        self.overlay = candidate_overlay;
        self.sync_tip = new_tip_id;
        for block_id in scheduled.iter().copied() {
            if self.queued_set.insert(block_id) {
                self.queued.push_back(block_id);
            }
        }
        Ok(HeaderBatchOutcome::Accepted {
            tip: new_tip,
            validated,
            scheduled,
        })
    }

    pub fn build_locator<S: ConsensusStorage>(
        &self,
        storage: &S,
    ) -> Result<Vec<BlockId>, LocatorError<S::Error>> {
        let view = OverlayView {
            storage,
            overlay: &self.overlay,
        };
        let mut current = load_locator_metadata(&view, self.sync_tip)?;
        let mut locator = Vec::with_capacity(usize::from(self.policy.maximum_locator_entries));
        locator.push(current.block_id());
        let mut walked = 0_u64;

        while current.header().height > 0
            && locator.len() < usize::from(self.policy.maximum_locator_entries)
        {
            let reserve_genesis =
                locator.len().saturating_add(1) == usize::from(self.policy.maximum_locator_entries);
            let step = if reserve_genesis {
                current.header().height
            } else if locator.len() < usize::from(self.policy.linear_locator_entries) {
                1
            } else {
                let exponent = locator
                    .len()
                    .saturating_sub(usize::from(self.policy.linear_locator_entries))
                    .saturating_add(1);
                if exponent >= u64::BITS as usize {
                    u64::MAX
                } else {
                    1_u64 << exponent
                }
                .min(current.header().height)
            };
            current = walk_parents(
                &view,
                current,
                step,
                &mut walked,
                self.policy.maximum_locator_walk,
            )?;
            if locator.last().copied() != Some(current.block_id()) {
                locator.push(current.block_id());
            }
        }
        Ok(locator)
    }

    pub fn next_block_request(&mut self) -> Vec<BlockId> {
        let mut output = Vec::with_capacity(usize::from(self.policy.maximum_blocks_per_request));
        while output.len() < usize::from(self.policy.maximum_blocks_per_request) {
            let Some(block_id) = self.queued.pop_front() else {
                break;
            };
            self.queued_set.remove(&block_id);
            if self.in_flight.insert(block_id) {
                output.push(block_id);
            }
        }
        output
    }

    /// Reserves one exact queued block selected by an external peer scheduler.
    /// This changes only disposable synchronization state.
    pub fn begin_block_request(&mut self, block_id: BlockId) -> Result<(), BeginBlockRequestError> {
        if self.in_flight.contains(&block_id) {
            return Err(BeginBlockRequestError::AlreadyInFlight(block_id));
        }
        if !self.queued_set.remove(&block_id) {
            return Err(BeginBlockRequestError::NotQueued(block_id));
        }
        self.queued.retain(|queued| *queued != block_id);
        self.in_flight.insert(block_id);
        Ok(())
    }

    pub fn retry_block(&mut self, block_id: BlockId) -> Result<(), RetryBlockError> {
        if !self.in_flight.remove(&block_id) {
            return Err(RetryBlockError::NotInFlight(block_id));
        }
        if self.queued_set.insert(block_id) {
            self.queued.push_back(block_id);
        }
        Ok(())
    }

    pub fn mark_block_stored<S: ConsensusStorage>(
        &mut self,
        storage: &S,
        block_id: BlockId,
    ) -> Result<(), StoredBlockError<S::Error>> {
        if !self.overlay.contains_key(&block_id)
            && !self.queued_set.contains(&block_id)
            && !self.in_flight.contains(&block_id)
        {
            return Err(StoredBlockError::UnknownBlock(block_id));
        }
        let stored = storage
            .get_validated_header(block_id)
            .map_err(StoredBlockError::Store)?
            .ok_or(StoredBlockError::NotStored(block_id))?;
        if self
            .overlay
            .get(&block_id)
            .is_some_and(|expected| *expected != stored)
        {
            return Err(StoredBlockError::MetadataMismatch(block_id));
        }
        self.overlay.remove(&block_id);
        self.in_flight.remove(&block_id);
        self.queued_set.remove(&block_id);
        self.queued.retain(|queued| *queued != block_id);
        Ok(())
    }

    fn read_metadata<S: ConsensusStorage>(
        &self,
        storage: &S,
        block_id: BlockId,
    ) -> Result<ValidatedHeaderMetadata, HeaderBatchLocal<S::Error>> {
        if let Some(metadata) = self.overlay.get(&block_id).copied() {
            return Ok(metadata);
        }
        storage
            .get_validated_header(block_id)
            .map_err(HeaderBatchLocal::Store)?
            .ok_or(HeaderBatchLocal::Header {
                index: 0,
                error: ChildHeaderLocalFailure::MissingParent(block_id),
            })
    }
}

impl<S: ConsensusStorage> Node<S> {
    /// Processes one decoded P2P session action only when it is a correlated,
    /// scheduled full block. This method performs no transport I/O.
    pub fn deliver_scheduled_block(
        &mut self,
        sync: &mut SyncCoordinator,
        action: SessionAction,
        local_now: u64,
    ) -> Result<BlockDeliveryOutcome, BlockDeliveryFailure<S::Error, S::MutationError>> {
        let (request_id, block) = match action {
            SessionAction::Deliver {
                request_id,
                message: Message::Block(block),
            } => (request_id, block),
            _ => {
                return Err(BlockDeliveryFailure::Local {
                    request_id: 0,
                    block_id: None,
                    error: Box::new(BlockDeliveryLocal::UnexpectedSessionAction),
                });
            }
        };
        let block_id = block_id_from_header_bytes(&block.header.encode());
        if request_id == 0 {
            return Err(BlockDeliveryFailure::PeerInvalid {
                request_id,
                block_id: Some(block_id),
                error: Box::new(BlockDeliveryInvalid::ZeroRequestId),
            });
        }
        if !sync.in_flight.contains(&block_id) {
            return Err(BlockDeliveryFailure::PeerInvalid {
                request_id,
                block_id: Some(block_id),
                error: Box::new(BlockDeliveryInvalid::UnrequestedBlock(block_id)),
            });
        }
        if block.header.height == 0 {
            requeue_or_local(sync, request_id, block_id)?;
            return Err(BlockDeliveryFailure::PeerInvalid {
                request_id,
                block_id: Some(block_id),
                error: Box::new(BlockDeliveryInvalid::GenesisBlock),
            });
        }

        let stored = self
            .storage()
            .get_validated_header(block_id)
            .map_err(|error| BlockDeliveryFailure::Local {
                request_id,
                block_id: Some(block_id),
                error: Box::new(BlockDeliveryLocal::StoreRead(error)),
            })?;
        if let Some(metadata) = stored {
            if metadata.header() != block.header {
                return Err(BlockDeliveryFailure::Local {
                    request_id,
                    block_id: Some(block_id),
                    error: Box::new(BlockDeliveryLocal::ExpectedHeaderMismatch(block_id)),
                });
            }
            let stored = StoredBlock {
                block_id,
                height: metadata.header().height,
            };
            let activation = self.activate_best_chain();
            let completion = sync.mark_block_stored(self.storage(), block_id);
            return match activation {
                Ok(activation) => {
                    completion.map_err(|error| BlockDeliveryFailure::Local {
                        request_id,
                        block_id: Some(block_id),
                        error: Box::new(BlockDeliveryLocal::Completion(error)),
                    })?;
                    Ok(BlockDeliveryOutcome::AlreadyStored {
                        request_id,
                        block_id,
                        activation: Box::new(activation),
                    })
                }
                Err(error) => Err(BlockDeliveryFailure::StoredButActivationFailed {
                    request_id,
                    stored,
                    error: Box::new(error),
                    completion_error: completion.err().map(Box::new),
                }),
            };
        }

        let expected =
            sync.overlay
                .get(&block_id)
                .copied()
                .ok_or_else(|| BlockDeliveryFailure::Local {
                    request_id,
                    block_id: Some(block_id),
                    error: Box::new(BlockDeliveryLocal::MissingExpectedHeader(block_id)),
                })?;
        if expected.header() != block.header {
            return Err(BlockDeliveryFailure::Local {
                request_id,
                block_id: Some(block_id),
                error: Box::new(BlockDeliveryLocal::ExpectedHeaderMismatch(block_id)),
            });
        }

        let raw = match block.encode_non_genesis() {
            Ok(raw) => raw,
            Err(error) => {
                requeue_or_local(sync, request_id, block_id)?;
                return Err(BlockDeliveryFailure::PeerInvalid {
                    request_id,
                    block_id: Some(block_id),
                    error: Box::new(BlockDeliveryInvalid::CanonicalEncoding(error)),
                });
            }
        };
        match self.process_block(&raw, local_now) {
            Ok(outcome) => match sync.mark_block_stored(self.storage(), block_id) {
                Ok(()) => Ok(BlockDeliveryOutcome::Processed {
                    request_id,
                    outcome: Box::new(outcome),
                }),
                Err(error) => Err(BlockDeliveryFailure::ProcessedButSyncIncomplete {
                    request_id,
                    outcome: Box::new(outcome),
                    error: Box::new(error),
                }),
            },
            Err(ProcessBlockError::Ingest(IngestError::Validation(
                BlockValidationFailure::Invalid(error),
            ))) => {
                requeue_or_local(sync, request_id, block_id)?;
                Err(BlockDeliveryFailure::PeerInvalid {
                    request_id,
                    block_id: Some(block_id),
                    error: Box::new(BlockDeliveryInvalid::Block(error)),
                })
            }
            Err(ProcessBlockError::Ingest(IngestError::Validation(
                BlockValidationFailure::TemporarilyUnacceptable(error),
            ))) => {
                requeue_or_local(sync, request_id, block_id)?;
                Err(BlockDeliveryFailure::TemporarilyUnacceptable {
                    request_id,
                    block_id,
                    error,
                })
            }
            Err(ProcessBlockError::Ingest(IngestError::Validation(
                BlockValidationFailure::Local(error),
            ))) => {
                requeue_or_local(sync, request_id, block_id)?;
                Err(BlockDeliveryFailure::Local {
                    request_id,
                    block_id: Some(block_id),
                    error: Box::new(BlockDeliveryLocal::Consensus(error)),
                })
            }
            Err(ProcessBlockError::Ingest(IngestError::ParentStateRead(error))) => {
                requeue_or_local(sync, request_id, block_id)?;
                Err(BlockDeliveryFailure::Local {
                    request_id,
                    block_id: Some(block_id),
                    error: Box::new(BlockDeliveryLocal::ParentStateRead(error)),
                })
            }
            Err(ProcessBlockError::Ingest(IngestError::AncestorHistoryRead(error))) => {
                requeue_or_local(sync, request_id, block_id)?;
                Err(BlockDeliveryFailure::Local {
                    request_id,
                    block_id: Some(block_id),
                    error: Box::new(BlockDeliveryLocal::AncestorHistoryRead(error)),
                })
            }
            Err(ProcessBlockError::Ingest(IngestError::StorageMutation(error))) => {
                Err(BlockDeliveryFailure::Local {
                    request_id,
                    block_id: Some(block_id),
                    error: Box::new(BlockDeliveryLocal::StorageMutation(error)),
                })
            }
            Err(ProcessBlockError::ActivationAfterStore { stored, error }) => {
                let completion_error = sync
                    .mark_block_stored(self.storage(), block_id)
                    .err()
                    .map(Box::new);
                Err(BlockDeliveryFailure::StoredButActivationFailed {
                    request_id,
                    stored,
                    error: Box::new(error),
                    completion_error,
                })
            }
        }
    }
}

fn requeue_or_local<ReadError, MutationError>(
    sync: &mut SyncCoordinator,
    request_id: u64,
    block_id: BlockId,
) -> Result<(), BlockDeliveryFailure<ReadError, MutationError>> {
    sync.retry_block(block_id)
        .map_err(|error| BlockDeliveryFailure::Local {
            request_id,
            block_id: Some(block_id),
            error: Box::new(BlockDeliveryLocal::Coordinator(error)),
        })
}

struct OverlayView<'a, S> {
    storage: &'a S,
    overlay: &'a BTreeMap<BlockId, ValidatedHeaderMetadata>,
}

impl<S: ValidatedHeaderView> ValidatedHeaderView for OverlayView<'_, S> {
    type Error = S::Error;

    fn get_validated_header(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ValidatedHeaderMetadata>, Self::Error> {
        if let Some(metadata) = self.overlay.get(&block_id).copied() {
            Ok(Some(metadata))
        } else {
            self.storage.get_validated_header(block_id)
        }
    }
}

fn identity_from_metadata(metadata: ValidatedHeaderMetadata) -> NetworkIdentity {
    let header = metadata.header();
    NetworkIdentity {
        chain_id: header.chain_id,
        network_id: header.network_id,
        genesis_commitment: header.genesis_commitment,
    }
}

fn map_header_failure<E>(
    index: u16,
    failure: ChildHeaderValidationFailure<E>,
) -> HeaderBatchFailure<E> {
    match failure {
        ChildHeaderValidationFailure::Invalid(error) => {
            HeaderBatchFailure::Invalid(HeaderBatchInvalid::Header { index, error })
        }
        ChildHeaderValidationFailure::TemporarilyUnacceptable(error) => {
            HeaderBatchFailure::TemporarilyUnacceptable(HeaderBatchTemporary::Header {
                index,
                error,
            })
        }
        ChildHeaderValidationFailure::Local(error) => {
            HeaderBatchFailure::Local(HeaderBatchLocal::Header { index, error })
        }
    }
}

fn load_locator_metadata<V: ValidatedHeaderView>(
    view: &V,
    block_id: BlockId,
) -> Result<ValidatedHeaderMetadata, LocatorError<V::Error>> {
    let metadata = view
        .get_validated_header(block_id)
        .map_err(LocatorError::Store)?
        .ok_or(LocatorError::MissingAncestor(block_id))?;
    if metadata.block_id() != block_id
        || block_id_from_header_bytes(&metadata.header().encode()) != block_id
    {
        return Err(LocatorError::CorruptMetadata(block_id));
    }
    Ok(metadata)
}

fn walk_parents<V: ValidatedHeaderView>(
    view: &V,
    mut current: ValidatedHeaderMetadata,
    count: u64,
    walked: &mut u64,
    maximum_walk: u64,
) -> Result<ValidatedHeaderMetadata, LocatorError<V::Error>> {
    for _ in 0..count {
        *walked = walked.checked_add(1).ok_or(LocatorError::WalkOverflow)?;
        if *walked > maximum_walk {
            return Err(LocatorError::WalkLimit {
                maximum: maximum_walk,
            });
        }
        let child = current;
        let parent_id = child.header().parent_block_id;
        let parent = load_locator_metadata(view, parent_id)?;
        if parent.header().height.checked_add(1) != Some(child.header().height) {
            return Err(LocatorError::CorruptMetadata(child.block_id()));
        }
        current = parent;
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use out_codec::{Block, BlockHeader, Transaction};
    use out_consensus::chain::ValidatedHeaderView;
    use out_consensus::{
        block_id_from_header_bytes, pow_hash_from_header_bytes, pow_hash_meets_target,
        DEVNET_POW_LIMIT_V0, MAX_FUTURE_DRIFT_V0,
    };
    use out_p2p::session::HeaderBatch;
    use out_primitives::{StateRoot, TransactionRoot, TESTNET_NETWORK_ID};
    use out_storage::conformance::{devnet_genesis_fixture, validated_reward_commit};
    use out_storage::{ConsensusStorage, FaultPoint, InMemoryConsensusStore, RecoveryOutcome};

    use super::*;
    use crate::NodeConfig;

    fn policy() -> SyncPolicy {
        SyncPolicy {
            maximum_overlay_headers: 8,
            maximum_blocks_per_request: 2,
            maximum_locator_entries: 5,
            linear_locator_entries: 2,
            maximum_locator_walk: 100,
        }
    }

    fn store() -> InMemoryConsensusStore {
        let (genesis, metadata) = devnet_genesis_fixture();
        InMemoryConsensusStore::new(genesis, metadata, &[], 0).expect("store")
    }

    fn mine(mut header: BlockHeader) -> BlockHeader {
        header.nonce = 0;
        loop {
            if pow_hash_meets_target(pow_hash_from_header_bytes(&header.encode()), header.target) {
                return header;
            }
            header.nonce = header.nonce.checked_add(1).expect("test nonce space");
        }
    }

    fn child(parent: BlockHeader, tag: u8) -> BlockHeader {
        mine(BlockHeader {
            consensus_version: parent.consensus_version,
            chain_id: parent.chain_id,
            network_id: parent.network_id,
            genesis_commitment: parent.genesis_commitment,
            height: parent.height.checked_add(1).expect("height"),
            parent_block_id: block_id_from_header_bytes(&parent.encode()),
            timestamp: parent.timestamp.checked_add(1).expect("time"),
            target: DEVNET_POW_LIMIT_V0,
            transaction_root: TransactionRoot::new([tag; 32]),
            state_root: StateRoot::new([tag.wrapping_add(1); 32]),
            nonce: 0,
        })
    }

    fn chain(parent: BlockHeader, count: u8) -> Vec<BlockHeader> {
        let mut output = Vec::with_capacity(usize::from(count));
        let mut current = parent;
        for tag in 1..=count {
            current = child(current, tag);
            output.push(current);
        }
        output
    }

    fn block_action(request_id: u64, block: Block) -> SessionAction {
        SessionAction::Deliver {
            request_id,
            message: Message::Block(block),
        }
    }

    fn scheduled_valid_block(
        extra: &[u8],
    ) -> (
        Node<InMemoryConsensusStore>,
        SyncCoordinator,
        Block,
        BlockId,
    ) {
        let store = store();
        let genesis = store.canonical_tip().unwrap().block_id;
        let commit = validated_reward_commit(&store, genesis, extra);
        let metadata = commit.header();
        let block = commit.block().clone();
        let block_id = metadata.block_id();
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        sync.accept_header_batch(
            &store,
            HeaderBatch::Validate(vec![metadata.header()]),
            metadata.header().timestamp,
        )
        .unwrap();
        assert_eq!(sync.next_block_request(), vec![block_id]);
        let node = Node::new(
            store,
            NodeConfig {
                network: SupportedNetwork::Devnet,
                maximum_reorganization_blocks: 100,
            },
        )
        .unwrap();
        (node, sync, block, block_id)
    }

    #[test]
    fn policy_rejects_zero_and_wire_oversize_values() {
        let mut value = policy();
        value.maximum_overlay_headers = 0;
        assert_eq!(
            value.validate(),
            Err(SyncPolicyError::Zero("maximum_overlay_headers"))
        );
        let mut value = policy();
        value.maximum_blocks_per_request = MAX_INV_ENTRIES + 1;
        assert_eq!(
            value.validate(),
            Err(SyncPolicyError::AboveWireMaximum(
                "maximum_blocks_per_request"
            ))
        );
    }

    #[test]
    fn valid_batch_is_atomic_and_scheduled_in_chain_order() {
        let store = store();
        let genesis = store.canonical_tip().unwrap();
        let genesis_header = store
            .get_validated_header(genesis.block_id)
            .unwrap()
            .unwrap()
            .header();
        let headers = chain(genesis_header, 3);
        let ids: Vec<_> = headers
            .iter()
            .map(|header| block_id_from_header_bytes(&header.encode()))
            .collect();
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        let outcome = sync
            .accept_header_batch(&store, HeaderBatch::Validate(headers), u64::MAX / 2)
            .unwrap();
        assert!(matches!(
            outcome,
            HeaderBatchOutcome::Accepted {
                ref validated,
                ref scheduled,
                ..
            } if validated == &ids && scheduled == &ids
        ));
        assert_eq!(sync.overlay_header_count(), 3);
        assert_eq!(sync.next_block_request(), ids[..2]);
        assert_eq!(sync.next_block_request(), ids[2..]);
    }

    #[test]
    fn stored_inert_header_is_scheduled_for_activation_reconciliation() {
        let mut store = store();
        let genesis = store.canonical_tip().unwrap();
        let commit =
            validated_reward_commit(&store, genesis.block_id, b"stored-inert-reconciliation");
        let metadata = commit.header();
        let block_id = metadata.block_id();
        store.store_validated_block(commit).unwrap();
        assert_eq!(store.canonical_tip().unwrap(), genesis);

        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        let outcome = sync
            .accept_header_batch(
                &store,
                HeaderBatch::Validate(vec![metadata.header()]),
                metadata.header().timestamp,
            )
            .unwrap();
        assert!(matches!(
            outcome,
            HeaderBatchOutcome::Accepted {
                scheduled,
                ..
            } if scheduled == vec![block_id]
        ));
        assert_eq!(sync.next_block_request(), vec![block_id]);
    }

    #[test]
    fn invalid_middle_header_commits_nothing() {
        let store = store();
        let genesis = store.canonical_tip().unwrap();
        let genesis_header = store
            .get_validated_header(genesis.block_id)
            .unwrap()
            .unwrap()
            .header();
        let mut headers = chain(genesis_header, 3);
        headers[1].height = 99;
        headers[1] = mine(headers[1]);
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        assert!(matches!(
            sync.accept_header_batch(&store, HeaderBatch::Validate(headers), u64::MAX / 2),
            Err(HeaderBatchFailure::Invalid(HeaderBatchInvalid::Header {
                index: 1,
                ..
            }))
        ));
        assert_eq!(sync.overlay_header_count(), 0);
        assert_eq!(sync.queued_block_count(), 0);
        assert_eq!(sync.sync_tip(), genesis.block_id);
    }

    #[test]
    fn temporary_and_local_header_failures_remain_distinct_and_atomic() {
        let store = store();
        let genesis = store.canonical_tip().unwrap();
        let genesis_header = store
            .get_validated_header(genesis.block_id)
            .unwrap()
            .unwrap()
            .header();
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();

        let mut future = child(genesis_header, 1);
        future.timestamp = genesis_header
            .timestamp
            .checked_add(MAX_FUTURE_DRIFT_V0)
            .and_then(|value| value.checked_add(1))
            .unwrap();
        future = mine(future);
        assert!(matches!(
            sync.accept_header_batch(
                &store,
                HeaderBatch::Validate(vec![future]),
                genesis_header.timestamp
            ),
            Err(HeaderBatchFailure::TemporarilyUnacceptable(
                HeaderBatchTemporary::Header { index: 0, .. }
            ))
        ));
        assert_eq!(sync.overlay_header_count(), 0);

        let mut orphan = child(genesis_header, 2);
        orphan.parent_block_id = BlockId::new([0xaa; 32]);
        orphan = mine(orphan);
        assert!(matches!(
            sync.accept_header_batch(&store, HeaderBatch::Validate(vec![orphan]), u64::MAX / 2),
            Err(HeaderBatchFailure::Local(HeaderBatchLocal::Header {
                index: 0,
                error: ChildHeaderLocalFailure::MissingParent(_)
            }))
        ));
        assert_eq!(sync.overlay_header_count(), 0);
        assert_eq!(sync.queued_block_count(), 0);

        let mut wrong_network = child(genesis_header, 3);
        wrong_network.network_id = TESTNET_NETWORK_ID;
        wrong_network = mine(wrong_network);
        assert!(matches!(
            sync.accept_header_batch(
                &store,
                HeaderBatch::Validate(vec![wrong_network]),
                u64::MAX / 2
            ),
            Err(HeaderBatchFailure::Invalid(HeaderBatchInvalid::Header {
                index: 0,
                error: ChildHeaderInvalid::Identity(_)
            }))
        ));
        assert_eq!(sync.overlay_header_count(), 0);
    }

    #[test]
    fn duplicate_and_capacity_fail_without_partial_state() {
        let store = store();
        let genesis = store.canonical_tip().unwrap();
        let genesis_header = store
            .get_validated_header(genesis.block_id)
            .unwrap()
            .unwrap()
            .header();
        let first = child(genesis_header, 1);
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        assert!(matches!(
            sync.accept_header_batch(
                &store,
                HeaderBatch::Validate(vec![first, first]),
                u64::MAX / 2
            ),
            Err(HeaderBatchFailure::Invalid(
                HeaderBatchInvalid::DuplicateHeader { index: 1, .. }
            ))
        ));
        assert_eq!(sync.overlay_header_count(), 0);

        let mut small = policy();
        small.maximum_overlay_headers = 1;
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, small).unwrap();
        assert!(matches!(
            sync.accept_header_batch(
                &store,
                HeaderBatch::Validate(chain(genesis_header, 2)),
                u64::MAX / 2
            ),
            Err(HeaderBatchFailure::Local(
                HeaderBatchLocal::OverlayCapacity { maximum: 1 }
            ))
        ));
        assert_eq!(sync.overlay_header_count(), 0);
    }

    #[test]
    fn empty_oversize_and_noncontiguous_batches_are_rejected_early() {
        let store = store();
        let genesis = store.canonical_tip().unwrap();
        let genesis_header = store
            .get_validated_header(genesis.block_id)
            .unwrap()
            .unwrap()
            .header();
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        assert_eq!(
            sync.accept_header_batch(&store, HeaderBatch::Validate(Vec::new()), 0),
            Err(HeaderBatchFailure::Invalid(
                HeaderBatchInvalid::EmptyHeaderBatch
            ))
        );
        assert!(matches!(
            sync.accept_header_batch(
                &store,
                HeaderBatch::Validate(vec![genesis_header; usize::from(MAX_HEADERS) + 1]),
                0
            ),
            Err(HeaderBatchFailure::Invalid(
                HeaderBatchInvalid::CountAboveWireMaximum {
                    maximum: MAX_HEADERS,
                    ..
                }
            ))
        ));

        let first = child(genesis_header, 1);
        let mut second = child(first, 2);
        second.parent_block_id = genesis.block_id;
        second = mine(second);
        assert!(matches!(
            sync.accept_header_batch(
                &store,
                HeaderBatch::Validate(vec![first, second]),
                u64::MAX / 2
            ),
            Err(HeaderBatchFailure::Invalid(
                HeaderBatchInvalid::NonContiguous { index: 1, .. }
            ))
        ));
        assert_eq!(sync.overlay_header_count(), 0);
    }

    #[test]
    fn storage_recovery_failure_is_local_and_commits_no_sync_state() {
        let mut store = store();
        let genesis = store.canonical_tip().unwrap().block_id;
        let commit = validated_reward_commit(&store, genesis, b"sync-read-failure");
        let header = commit.header().header();
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        store.inject_fault_once(FaultPoint::AfterPrepare).unwrap();
        assert!(store.store_validated_block(commit).is_err());
        assert!(matches!(
            sync.accept_header_batch(&store, HeaderBatch::Validate(vec![header]), u64::MAX / 2),
            Err(HeaderBatchFailure::Local(HeaderBatchLocal::Store(_)))
        ));
        assert_eq!(sync.overlay_header_count(), 0);
        assert_eq!(sync.queued_block_count(), 0);
    }

    #[test]
    fn locator_is_deterministic_tip_to_genesis_and_bounded() {
        let store = store();
        let genesis = store.canonical_tip().unwrap();
        let genesis_header = store
            .get_validated_header(genesis.block_id)
            .unwrap()
            .unwrap()
            .header();
        let headers = chain(genesis_header, 8);
        let ids: Vec<_> = headers
            .iter()
            .map(|header| block_id_from_header_bytes(&header.encode()))
            .collect();
        let tip = block_id_from_header_bytes(&headers[7].encode());
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        sync.accept_header_batch(&store, HeaderBatch::Validate(headers), u64::MAX / 2)
            .unwrap();
        let first = sync.build_locator(&store).unwrap();
        let second = sync.build_locator(&store).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.first(), Some(&tip));
        assert_eq!(first.last(), Some(&genesis.block_id));
        assert_eq!(
            first,
            vec![ids[7], ids[6], ids[4], ids[0], genesis.block_id]
        );
    }

    #[test]
    fn locator_walk_limit_is_a_local_failure() {
        let store = store();
        let genesis = store.canonical_tip().unwrap();
        let genesis_header = store
            .get_validated_header(genesis.block_id)
            .unwrap()
            .unwrap()
            .header();
        let mut limited = policy();
        limited.maximum_locator_walk = 2;
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, limited).unwrap();
        sync.accept_header_batch(
            &store,
            HeaderBatch::Validate(chain(genesis_header, 4)),
            u64::MAX / 2,
        )
        .unwrap();
        assert_eq!(
            sync.build_locator(&store),
            Err(LocatorError::WalkLimit { maximum: 2 })
        );
    }

    #[test]
    fn block_completion_requires_authoritative_storage() {
        let mut store = store();
        let genesis = store.canonical_tip().unwrap().block_id;
        let commit = validated_reward_commit(&store, genesis, b"sync-complete");
        let metadata = commit.header();
        let block_id = metadata.block_id();
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        sync.accept_header_batch(
            &store,
            HeaderBatch::Validate(vec![metadata.header()]),
            metadata.header().timestamp,
        )
        .unwrap();
        assert_eq!(sync.next_block_request(), vec![block_id]);
        assert_eq!(
            sync.mark_block_stored(&store, block_id),
            Err(StoredBlockError::NotStored(block_id))
        );
        store.store_validated_block(commit).unwrap();
        sync.mark_block_stored(&store, block_id).unwrap();
        assert_eq!(sync.overlay_header_count(), 0);
        assert_eq!(sync.in_flight_block_count(), 0);
    }

    #[test]
    fn retry_is_explicit_and_deterministic() {
        let store = store();
        let genesis = store.canonical_tip().unwrap();
        let genesis_header = store
            .get_validated_header(genesis.block_id)
            .unwrap()
            .unwrap()
            .header();
        let header = child(genesis_header, 1);
        let block_id = block_id_from_header_bytes(&header.encode());
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        sync.accept_header_batch(&store, HeaderBatch::Validate(vec![header]), u64::MAX / 2)
            .unwrap();
        assert_eq!(sync.next_block_request(), vec![block_id]);
        sync.retry_block(block_id).unwrap();
        assert_eq!(sync.next_block_request(), vec![block_id]);
        assert_eq!(
            sync.retry_block(BlockId::new([0xaa; 32])),
            Err(RetryBlockError::NotInFlight(BlockId::new([0xaa; 32])))
        );
    }

    #[test]
    fn external_scheduler_can_reserve_one_exact_queued_block() {
        let store = store();
        let genesis = store.canonical_tip().unwrap();
        let genesis_header = store
            .get_validated_header(genesis.block_id)
            .unwrap()
            .unwrap()
            .header();
        let headers = chain(genesis_header, 2);
        let first = block_id_from_header_bytes(&headers[0].encode());
        let second = block_id_from_header_bytes(&headers[1].encode());
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        sync.accept_header_batch(&store, HeaderBatch::Validate(headers), u64::MAX / 2)
            .unwrap();

        assert_eq!(sync.begin_block_request(second), Ok(()));
        assert!(sync.is_block_in_flight(second));
        assert_eq!(
            sync.begin_block_request(second),
            Err(BeginBlockRequestError::AlreadyInFlight(second))
        );
        assert_eq!(sync.next_block_request(), vec![first]);
        assert_eq!(
            sync.begin_block_request(BlockId::new([0xbb; 32])),
            Err(BeginBlockRequestError::NotQueued(BlockId::new([0xbb; 32])))
        );
    }

    #[test]
    fn scheduled_block_is_fully_processed_and_retires_sync_state() {
        let (mut node, mut sync, block, block_id) = scheduled_valid_block(b"delivery-success");
        let outcome = node
            .deliver_scheduled_block(
                &mut sync,
                block_action(41, block.clone()),
                block.header.timestamp,
            )
            .unwrap();
        assert!(matches!(
            outcome,
            BlockDeliveryOutcome::Processed { request_id: 41, .. }
        ));
        assert_eq!(sync.overlay_header_count(), 0);
        assert_eq!(sync.in_flight_block_count(), 0);
        assert_eq!(node.canonical_tip().unwrap().block_id, block_id);
    }

    #[test]
    fn invalid_block_body_is_peer_invalid_and_requeued() {
        let (mut node, mut sync, mut block, block_id) = scheduled_valid_block(b"delivery-invalid");
        let Transaction::Reward(reward) = &mut block.body.transactions[0] else {
            panic!("reward transaction");
        };
        reward.body.extra.push(0xff);
        let failure = node
            .deliver_scheduled_block(
                &mut sync,
                block_action(42, block.clone()),
                block.header.timestamp,
            )
            .unwrap_err();
        assert!(matches!(
            failure,
            BlockDeliveryFailure::PeerInvalid {
                request_id: 42,
                block_id: Some(actual),
                error,
            } if actual == block_id && matches!(
                *error,
                BlockDeliveryInvalid::Block(BlockInvalid::TransactionRootMismatch { .. })
            )
        ));
        assert_eq!(sync.in_flight_block_count(), 0);
        assert_eq!(sync.next_block_request(), vec![block_id]);
        assert_eq!(node.canonical_tip().unwrap().height, 0);
    }

    #[test]
    fn zero_request_and_unscheduled_blocks_never_enter_node_validation() {
        let (mut node, mut sync, block, block_id) = scheduled_valid_block(b"delivery-routing");
        assert!(matches!(
            node.deliver_scheduled_block(
                &mut sync,
                block_action(0, block.clone()),
                block.header.timestamp
            ),
            Err(BlockDeliveryFailure::PeerInvalid {
                error,
                ..
            }) if *error == BlockDeliveryInvalid::ZeroRequestId
        ));
        assert_eq!(sync.in_flight_block_count(), 1);

        assert!(matches!(
            node.deliver_scheduled_block(
                &mut sync,
                SessionAction::IgnoredExtension {
                    message_type: 0x8001
                },
                0
            ),
            Err(BlockDeliveryFailure::Local {
                error,
                ..
            }) if *error == BlockDeliveryLocal::UnexpectedSessionAction
        ));

        let mut other = block;
        other.header.nonce = other.header.nonce.wrapping_add(1);
        let other_id = block_id_from_header_bytes(&other.header.encode());
        assert_ne!(other_id, block_id);
        assert!(matches!(
            node.deliver_scheduled_block(
                &mut sync,
                block_action(43, other),
                u64::MAX / 2
            ),
            Err(BlockDeliveryFailure::PeerInvalid {
                block_id: Some(actual),
                error,
                ..
            }) if actual == other_id
                && *error == BlockDeliveryInvalid::UnrequestedBlock(other_id)
        ));
        assert_eq!(node.canonical_tip().unwrap().height, 0);
        assert_eq!(sync.in_flight_block_count(), 1);
    }

    #[test]
    fn temporary_block_timestamp_is_requeued_without_peer_invalidity() {
        let store = store();
        let genesis = store.canonical_tip().unwrap().block_id;
        let parent = store.get_validated_header(genesis).unwrap().unwrap();
        let commit = validated_reward_commit(&store, genesis, b"delivery-temporary");
        let mut block = commit.block().clone();
        block.header.timestamp = parent
            .header()
            .timestamp
            .checked_add(MAX_FUTURE_DRIFT_V0)
            .and_then(|value| value.checked_add(1))
            .unwrap();
        block.header = mine(block.header);
        let block_id = block_id_from_header_bytes(&block.header.encode());
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        sync.accept_header_batch(
            &store,
            HeaderBatch::Validate(vec![block.header]),
            block.header.timestamp,
        )
        .unwrap();
        assert_eq!(sync.next_block_request(), vec![block_id]);
        let mut node = Node::new(
            store,
            NodeConfig {
                network: SupportedNetwork::Devnet,
                maximum_reorganization_blocks: 100,
            },
        )
        .unwrap();
        assert!(matches!(
            node.deliver_scheduled_block(
                &mut sync,
                block_action(44, block),
                parent.header().timestamp
            ),
            Err(BlockDeliveryFailure::TemporarilyUnacceptable {
                request_id: 44,
                block_id: actual,
                ..
            }) if actual == block_id
        ));
        assert_eq!(sync.next_block_request(), vec![block_id]);
        assert_eq!(node.canonical_tip().unwrap().height, 0);
    }

    #[test]
    fn uncertain_store_is_reconciled_then_activated_without_duplicate_ingest() {
        let (mut node, mut sync, block, block_id) = scheduled_valid_block(b"delivery-recovery");
        node.storage_mut()
            .inject_fault_once(FaultPoint::AfterPublish)
            .unwrap();
        let failure = node
            .deliver_scheduled_block(
                &mut sync,
                block_action(45, block.clone()),
                block.header.timestamp,
            )
            .unwrap_err();
        assert!(matches!(
            failure,
            BlockDeliveryFailure::Local {
                error,
                ..
            } if matches!(*error, BlockDeliveryLocal::StorageMutation(_))
        ));
        assert_eq!(sync.in_flight_block_count(), 1);
        assert_eq!(
            node.recover_storage().unwrap(),
            RecoveryOutcome::FinalizedPublished
        );

        let outcome = node
            .deliver_scheduled_block(&mut sync, block_action(45, block), u64::MAX / 2)
            .unwrap();
        assert!(matches!(
            outcome,
            BlockDeliveryOutcome::AlreadyStored {
                request_id: 45,
                block_id: actual,
                activation,
            } if actual == block_id
                && matches!(*activation, ActivationOutcome::Applied { .. })
        ));
        assert_eq!(node.canonical_tip().unwrap().block_id, block_id);
        assert_eq!(sync.overlay_header_count(), 0);
        assert_eq!(sync.in_flight_block_count(), 0);
    }

    #[test]
    fn out_of_order_child_is_local_then_succeeds_after_parent() {
        let mut fixture = store();
        let genesis = fixture.canonical_tip().unwrap().block_id;
        let first_commit = validated_reward_commit(&fixture, genesis, b"delivery-parent");
        let first_id = first_commit.header().block_id();
        let first_block = first_commit.block().clone();
        fixture.store_validated_block(first_commit).unwrap();
        let second_commit = validated_reward_commit(&fixture, first_id, b"delivery-child");
        let second_id = second_commit.header().block_id();
        let second_block = second_commit.block().clone();

        let store = store();
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        sync.accept_header_batch(
            &store,
            HeaderBatch::Validate(vec![first_block.header, second_block.header]),
            second_block.header.timestamp,
        )
        .unwrap();
        assert_eq!(sync.next_block_request(), vec![first_id, second_id]);
        let mut node = Node::new(
            store,
            NodeConfig {
                network: SupportedNetwork::Devnet,
                maximum_reorganization_blocks: 100,
            },
        )
        .unwrap();

        let failure = node
            .deliver_scheduled_block(
                &mut sync,
                block_action(50, second_block.clone()),
                second_block.header.timestamp,
            )
            .unwrap_err();
        assert!(matches!(
            failure,
            BlockDeliveryFailure::Local {
                request_id: 50,
                block_id: Some(actual),
                error,
            } if actual == second_id && matches!(
                *error,
                BlockDeliveryLocal::Consensus(BlockLocalFailure::Header(
                    ChildHeaderLocalFailure::MissingParent(parent)
                )) if parent == first_id
            )
        ));

        assert!(matches!(
            node.deliver_scheduled_block(
                &mut sync,
                block_action(51, first_block.clone()),
                first_block.header.timestamp
            ),
            Ok(BlockDeliveryOutcome::Processed { request_id: 51, .. })
        ));
        assert_eq!(sync.next_block_request(), vec![second_id]);
        assert!(matches!(
            node.deliver_scheduled_block(
                &mut sync,
                block_action(52, second_block.clone()),
                second_block.header.timestamp
            ),
            Ok(BlockDeliveryOutcome::Processed { request_id: 52, .. })
        ));
        assert_eq!(node.canonical_tip().unwrap().block_id, second_id);
        assert_eq!(sync.overlay_header_count(), 0);
    }

    #[test]
    fn complete_batch_reports_current_validated_tip() {
        let store = store();
        let mut sync = SyncCoordinator::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        let outcome = sync
            .accept_header_batch(&store, HeaderBatch::Complete, 0)
            .unwrap();
        assert_eq!(
            outcome,
            HeaderBatchOutcome::UpToDate {
                tip: store.canonical_tip().unwrap()
            }
        );
    }
}
