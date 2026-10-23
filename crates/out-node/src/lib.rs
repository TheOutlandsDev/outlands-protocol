#![forbid(unsafe_code)]

//! Testnet/devnet-only OUT node orchestration.
//!
//! This crate coordinates already specified consensus and storage operations.
//! It does not define consensus and has no networking or host-service runtime.

pub mod bootstrap;
#[cfg(unix)]
pub mod cli;
pub mod dispatcher;
pub mod driver;
pub mod duplex_harness;
pub mod harness;
pub mod mempool;
pub mod mining;
pub mod multi_harness;
#[cfg(unix)]
pub mod operator;
pub mod peers;
#[cfg(unix)]
pub mod process;
pub mod runtime;
pub mod serving;
pub mod sync;

use out_codec::Block;
use out_consensus::block::{
    validate_non_genesis_block, BlockInvalid, BlockValidationFailure, BlockValidationParameters,
};
use out_consensus::chain::{ChainTip, ReorganizationPlan, ReorganizationPlanFailure};
use out_consensus::{IdentityError, NetworkIdentity};
use out_primitives::BlockId;
use out_storage::{ConsensusStorage, RecoverableConsensusStorage, RecoveryOutcome, RecoveryStatus};

/// Frozen public profiles currently safe for node construction. Mainnet is
/// intentionally absent until its benchmark-gated descriptor is ratified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportedNetwork {
    Testnet,
    Devnet,
}

impl SupportedNetwork {
    pub const fn identity(self) -> NetworkIdentity {
        match self {
            Self::Testnet => NetworkIdentity::testnet(),
            Self::Devnet => NetworkIdentity::devnet(),
        }
    }

    pub const fn validation_parameters(self) -> BlockValidationParameters {
        match self {
            Self::Testnet => BlockValidationParameters::testnet_v0(),
            Self::Devnet => BlockValidationParameters::devnet_v0(),
        }
    }
}

/// Local safety policy. This never changes block validity or chain ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeConfig {
    pub network: SupportedNetwork,
    pub maximum_reorganization_blocks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeOpenError<E> {
    Store(E),
    MissingTipMetadata(BlockId),
    CorruptTipMetadata(BlockId),
    NetworkMismatch(IdentityError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredBlock {
    pub block_id: BlockId,
    pub height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngestError<ReadError, MutationError> {
    Validation(BlockValidationFailure<ReadError>),
    ParentStateRead(ReadError),
    AncestorHistoryRead(ReadError),
    StorageMutation(MutationError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationOutcome {
    Unchanged {
        tip: ChainTip,
    },
    Applied {
        plan: ReorganizationPlan,
        new_tip: ChainTip,
    },
    PolicyPaused {
        selected_tip: ChainTip,
        maximum_reorganization_blocks: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationError<ReadError, MutationError> {
    SelectedTipRead(ReadError),
    Plan(ReorganizationPlanFailure<ReadError>),
    Apply(MutationError),
    AppliedTipRead(ReadError),
    AppliedTipMismatch { expected: BlockId, actual: BlockId },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessBlockOutcome {
    pub stored: StoredBlock,
    pub activation: ActivationOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessBlockError<ReadError, MutationError> {
    Ingest(IngestError<ReadError, MutationError>),
    ActivationAfterStore {
        stored: StoredBlock,
        error: ActivationError<ReadError, MutationError>,
    },
}

pub struct Node<S> {
    storage: S,
    config: NodeConfig,
    parameters: BlockValidationParameters,
}

impl<S: ConsensusStorage> Node<S> {
    pub fn new(storage: S, config: NodeConfig) -> Result<Self, NodeOpenError<S::Error>> {
        let parameters = config.network.validation_parameters();
        let tip = storage.canonical_tip().map_err(NodeOpenError::Store)?;
        let metadata = storage
            .get_validated_header(tip.block_id)
            .map_err(NodeOpenError::Store)?
            .ok_or(NodeOpenError::MissingTipMetadata(tip.block_id))?;
        if metadata.tip() != tip {
            return Err(NodeOpenError::CorruptTipMetadata(tip.block_id));
        }
        let header = metadata.header();
        let actual_identity = NetworkIdentity {
            chain_id: header.chain_id,
            network_id: header.network_id,
            genesis_commitment: header.genesis_commitment,
        };
        parameters
            .header
            .network
            .require_exact(actual_identity)
            .map_err(NodeOpenError::NetworkMismatch)?;
        Ok(Self {
            storage,
            config,
            parameters,
        })
    }

    pub const fn config(&self) -> NodeConfig {
        self.config
    }

    pub fn set_maximum_reorganization_blocks(&mut self, maximum: u64) {
        self.config.maximum_reorganization_blocks = maximum;
    }

    pub const fn storage(&self) -> &S {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    pub fn into_storage(self) -> S {
        self.storage
    }

    pub fn canonical_tip(&self) -> Result<ChainTip, S::Error> {
        self.storage.canonical_tip()
    }

    pub fn validate_and_store(
        &mut self,
        raw: &[u8],
        local_now: u64,
    ) -> Result<StoredBlock, IngestError<S::Error, S::MutationError>> {
        let routing_block = Block::decode_non_genesis_exact(raw).map_err(|error| {
            IngestError::Validation(BlockValidationFailure::Invalid(
                BlockInvalid::CanonicalEncoding(error),
            ))
        })?;
        let parent_id = routing_block.header.parent_block_id;
        let parent_state = self
            .storage
            .parent_state_snapshot(parent_id)
            .map_err(IngestError::ParentStateRead)?;
        let ancestor_transactions = self
            .storage
            .ancestor_transaction_snapshot(parent_id)
            .map_err(IngestError::AncestorHistoryRead)?;
        let commit = validate_non_genesis_block(
            raw,
            &self.storage,
            parent_state.as_ref().map(|state| state.as_borrowed()),
            ancestor_transactions
                .as_ref()
                .map(|history| history.as_borrowed()),
            local_now,
            self.parameters,
        )
        .map_err(IngestError::Validation)?;
        let stored = StoredBlock {
            block_id: commit.header().block_id(),
            height: commit.header().header().height,
        };
        self.storage
            .store_validated_block(commit)
            .map_err(IngestError::StorageMutation)?;
        Ok(stored)
    }

    pub fn activate_best_chain(
        &mut self,
    ) -> Result<ActivationOutcome, ActivationError<S::Error, S::MutationError>> {
        let selected_tip = self
            .storage
            .canonical_tip()
            .map_err(ActivationError::SelectedTipRead)?;
        let plan = match self
            .storage
            .plan_best_reorganization(self.config.maximum_reorganization_blocks)
        {
            Ok(plan) => plan,
            Err(ReorganizationPlanFailure::PolicyPause {
                maximum_plan_blocks,
            }) => {
                return Ok(ActivationOutcome::PolicyPaused {
                    selected_tip,
                    maximum_reorganization_blocks: maximum_plan_blocks,
                });
            }
            Err(error) => return Err(ActivationError::Plan(error)),
        };
        if plan.detach.is_empty() && plan.attach.is_empty() {
            return Ok(ActivationOutcome::Unchanged { tip: selected_tip });
        }
        let expected_tip = plan.winning_tip;
        self.storage
            .apply_reorganization(&plan)
            .map_err(ActivationError::Apply)?;
        let new_tip = self
            .storage
            .canonical_tip()
            .map_err(ActivationError::AppliedTipRead)?;
        if new_tip.block_id != expected_tip {
            return Err(ActivationError::AppliedTipMismatch {
                expected: expected_tip,
                actual: new_tip.block_id,
            });
        }
        Ok(ActivationOutcome::Applied { plan, new_tip })
    }

    pub fn process_block(
        &mut self,
        raw: &[u8],
        local_now: u64,
    ) -> Result<ProcessBlockOutcome, ProcessBlockError<S::Error, S::MutationError>> {
        let stored = self
            .validate_and_store(raw, local_now)
            .map_err(ProcessBlockError::Ingest)?;
        match self.activate_best_chain() {
            Ok(activation) => Ok(ProcessBlockOutcome { stored, activation }),
            Err(error) => Err(ProcessBlockError::ActivationAfterStore { stored, error }),
        }
    }
}

impl<S: RecoverableConsensusStorage> Node<S> {
    pub fn recovery_status(&self) -> RecoveryStatus {
        self.storage.recovery_status()
    }

    pub fn recover_storage(&mut self) -> Result<RecoveryOutcome, S::RecoveryError> {
        self.storage.recover()
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Debug;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use out_consensus::block::BlockValidationParameters;
    use out_consensus::chain::ValidatedHeaderView;
    use out_storage::conformance::{devnet_genesis_fixture, validated_reward_commit};
    use out_storage::redb_backend::RedbConsensusStore;
    use out_storage::rocksdb_backend::RocksdbConsensusStore;
    use out_storage::{FaultPoint, InMemoryConsensusStore, InMemoryMutationError};

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn temporary_path(label: &str) -> PathBuf {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "out-node-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn devnet_node(maximum_reorganization_blocks: u64) -> Node<InMemoryConsensusStore> {
        let (genesis, metadata) = devnet_genesis_fixture();
        let store = InMemoryConsensusStore::new(genesis, metadata, &[], 0).expect("store");
        Node::new(
            store,
            NodeConfig {
                network: SupportedNetwork::Devnet,
                maximum_reorganization_blocks,
            },
        )
        .expect("node")
    }

    fn assert_backend_processes_block<S>(store: S)
    where
        S: ConsensusStorage,
        S::Error: Debug,
        S::MutationError: Debug,
    {
        let mut node = Node::new(
            store,
            NodeConfig {
                network: SupportedNetwork::Devnet,
                maximum_reorganization_blocks: 100,
            },
        )
        .expect("node");
        let genesis = node.canonical_tip().expect("tip").block_id;
        let commit = validated_reward_commit(node.storage(), genesis, b"persistent-node");
        let expected = commit.header().block_id();
        let raw = commit.canonical_block_bytes().to_vec();
        node.process_block(&raw, commit.header().header().timestamp)
            .expect("process");
        assert_eq!(node.canonical_tip().expect("tip").block_id, expected);
    }

    #[test]
    fn devnet_store_cannot_open_as_testnet() {
        let (genesis, metadata) = devnet_genesis_fixture();
        let store = InMemoryConsensusStore::new(genesis, metadata, &[], 0).expect("store");
        assert!(matches!(
            Node::new(
                store,
                NodeConfig {
                    network: SupportedNetwork::Testnet,
                    maximum_reorganization_blocks: 100,
                }
            ),
            Err(NodeOpenError::NetworkMismatch(_))
        ));
    }

    #[test]
    fn valid_block_is_stored_then_activated() {
        let mut node = devnet_node(100);
        let genesis = node.canonical_tip().expect("tip").block_id;
        let commit = validated_reward_commit(node.storage(), genesis, b"node-activate");
        let expected = commit.header().block_id();
        let raw = commit.canonical_block_bytes().to_vec();
        let outcome = node
            .process_block(&raw, commit.header().header().timestamp)
            .expect("process");
        assert_eq!(outcome.stored.block_id, expected);
        assert!(matches!(
            outcome.activation,
            ActivationOutcome::Applied { new_tip, .. } if new_tip.block_id == expected
        ));
        assert_eq!(node.canonical_tip().expect("tip").block_id, expected);
    }

    #[test]
    fn zero_reorganization_limit_stores_but_pauses_activation() {
        let mut node = devnet_node(0);
        let genesis = node.canonical_tip().expect("tip").block_id;
        let commit = validated_reward_commit(node.storage(), genesis, b"node-pause");
        let expected = commit.header().block_id();
        let raw = commit.canonical_block_bytes().to_vec();
        let outcome = node
            .process_block(&raw, commit.header().header().timestamp)
            .expect("process");
        assert_eq!(outcome.stored.block_id, expected);
        assert!(matches!(
            outcome.activation,
            ActivationOutcome::PolicyPaused {
                selected_tip,
                maximum_reorganization_blocks: 0,
            } if selected_tip.block_id == genesis
        ));
        assert_eq!(node.canonical_tip().expect("tip").block_id, genesis);
        assert!(node
            .storage()
            .get_validated_header(expected)
            .expect("header")
            .is_some());

        node.set_maximum_reorganization_blocks(100);
        let activation = node.activate_best_chain().expect("activate later");
        assert!(matches!(
            activation,
            ActivationOutcome::Applied { new_tip, .. } if new_tip.block_id == expected
        ));
    }

    #[test]
    fn malformed_bytes_are_never_stored() {
        let mut node = devnet_node(100);
        let original_tip = node.canonical_tip().expect("tip");
        assert!(matches!(
            node.process_block(&[0xff, 0x00], 0),
            Err(ProcessBlockError::Ingest(IngestError::Validation(
                BlockValidationFailure::Invalid(BlockInvalid::CanonicalEncoding(_))
            )))
        ));
        assert_eq!(node.canonical_tip().expect("tip"), original_tip);
    }

    #[test]
    fn interrupted_store_is_explicitly_recoverable() {
        let mut node = devnet_node(100);
        let genesis = node.canonical_tip().expect("tip").block_id;
        let commit = validated_reward_commit(node.storage(), genesis, b"node-recovery");
        let raw = commit.canonical_block_bytes().to_vec();
        node.storage_mut()
            .inject_fault_once(FaultPoint::AfterPrepare)
            .expect("fault");
        assert!(matches!(
            node.process_block(&raw, commit.header().header().timestamp),
            Err(ProcessBlockError::Ingest(IngestError::StorageMutation(
                InMemoryMutationError::FaultInjected(FaultPoint::AfterPrepare)
            )))
        ));
        assert_eq!(node.recovery_status(), RecoveryStatus::Prepared);
        assert!(node.canonical_tip().is_err());
        assert_eq!(
            node.recover_storage(),
            Ok(RecoveryOutcome::RolledBackPrepared)
        );
        assert_eq!(node.recovery_status(), RecoveryStatus::Clean);
        assert_eq!(node.canonical_tip().expect("tip").block_id, genesis);
    }

    #[test]
    fn supported_profiles_are_exact_frozen_consensus_parameters() {
        assert_eq!(
            SupportedNetwork::Testnet.validation_parameters(),
            BlockValidationParameters::testnet_v0()
        );
        assert_eq!(
            SupportedNetwork::Devnet.validation_parameters(),
            BlockValidationParameters::devnet_v0()
        );
    }

    #[test]
    fn redb_executes_the_same_node_flow() {
        let path = temporary_path("redb").with_extension("redb");
        let (genesis, metadata) = devnet_genesis_fixture();
        let store = RedbConsensusStore::create(
            &path,
            genesis,
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("store");
        assert_backend_processes_block(store);
        fs::remove_file(path).expect("remove redb test database");
    }

    #[test]
    fn rocksdb_executes_the_same_node_flow() {
        let path = temporary_path("rocksdb");
        let (genesis, metadata) = devnet_genesis_fixture();
        let store = RocksdbConsensusStore::create(
            &path,
            genesis,
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("store");
        assert_backend_processes_block(store);
        fs::remove_dir_all(path).expect("remove rocksdb test database");
    }
}
