//! Reusable behavioral tests for every OUT consensus-storage backend.
//!
//! Adapter crates SHOULD enable the `conformance` feature only for tests and
//! invoke both public assertion functions with a factory that creates a fresh
//! backend from the supplied pinned devnet genesis.

use core::fmt::Debug;
use std::collections::BTreeMap;

use out_codec::{Block, BlockBody, BlockHeader, RewardTransaction, Transaction};
use out_consensus::block::{
    validate_non_genesis_block, BlockValidationParameters, ValidatedBlockCommit,
};
use out_consensus::chain::{
    validate_pinned_genesis_header, HeaderChainParameters, ReorganizationPlanFailure,
    ValidatedHeaderMetadata,
};
use out_consensus::{
    pow_hash_from_header_bytes, pow_hash_meets_target, transaction_id_from_canonical_bytes,
    transaction_merkle_root, DEVNET_POW_LIMIT_V0,
};
use out_primitives::{Amount, BlockId};
use out_state::{compute_state_root, subsidy_at_height, Account};

use crate::redb_backend::{RedbConsensusStore, RedbStorageError};
use crate::rocksdb_backend::{RocksdbConsensusStore, RocksdbStorageError};
use crate::{
    ConsensusStorage, FaultPoint, InMemoryConsensusStore, InMemoryMutationError, RecoveryOutcome,
    RecoveryStatus,
};

const VECTOR_REWARD_HEX: &str = "0001000000810000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000010003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8000000001dcd650000000000000003e800000000";
const VECTOR_HEADER_HEX: &str = "000000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a937280000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda2fb959f81d652879472f8c56076e63a2fb3587dda94754f316328e7ec431403d30a2588a2f688edd9b29af2bb3b522db2deb731709dbfb53fadefab69c21470000000000000ac5";

/// Test-only recovery and fault-injection surface. This is deliberately not a
/// production consensus-storage requirement.
pub trait FaultInjectableConformanceStore: ConsensusStorage {
    type RecoveryError;

    fn inject_conformance_fault(&mut self, point: FaultPoint) -> Result<(), Self::MutationError>;
    fn conformance_recovery_status(&self) -> RecoveryStatus;
    fn recover_for_conformance(&mut self) -> Result<RecoveryOutcome, Self::RecoveryError>;
}

impl FaultInjectableConformanceStore for InMemoryConsensusStore {
    type RecoveryError = InMemoryMutationError;

    fn inject_conformance_fault(&mut self, point: FaultPoint) -> Result<(), Self::MutationError> {
        self.inject_fault_once(point)
    }

    fn conformance_recovery_status(&self) -> RecoveryStatus {
        self.recovery_status()
    }

    fn recover_for_conformance(&mut self) -> Result<RecoveryOutcome, Self::RecoveryError> {
        self.recover()
    }
}

impl FaultInjectableConformanceStore for RedbConsensusStore {
    type RecoveryError = RedbStorageError;

    fn inject_conformance_fault(&mut self, point: FaultPoint) -> Result<(), Self::MutationError> {
        self.inject_fault_once(point)
    }

    fn conformance_recovery_status(&self) -> RecoveryStatus {
        self.recovery_status()
    }

    fn recover_for_conformance(&mut self) -> Result<RecoveryOutcome, Self::RecoveryError> {
        self.recover()
    }
}

impl FaultInjectableConformanceStore for RocksdbConsensusStore {
    type RecoveryError = RocksdbStorageError;

    fn inject_conformance_fault(&mut self, point: FaultPoint) -> Result<(), Self::MutationError> {
        self.inject_fault_once(point)
    }

    fn conformance_recovery_status(&self) -> RecoveryStatus {
        self.recovery_status()
    }

    fn recover_for_conformance(&mut self) -> Result<RecoveryOutcome, Self::RecoveryError> {
        self.recover()
    }
}

/// Verifies branch storage, deterministic best-chain planning, bounded reorg
/// policy, branch-local snapshots, rollback, and forward application.
pub fn assert_consensus_storage_conformance<S, Make, MakeError>(mut make: Make)
where
    S: ConsensusStorage,
    S::Error: Debug,
    S::MutationError: Debug,
    Make: FnMut(Block, ValidatedHeaderMetadata) -> Result<S, MakeError>,
    MakeError: Debug,
{
    let mut store = make_devnet_store(&mut make);
    let genesis = store.canonical_tip().expect("canonical genesis").block_id;

    let a1_commit = validated_reward_commit(&store, genesis, b"conformance-a1");
    let a1 = a1_commit.header().block_id();
    store
        .store_validated_block(a1_commit.clone())
        .expect("store first branch block");
    assert!(store
        .get_validated_header(a1)
        .expect("read stored block")
        .is_some());
    assert_eq!(store.canonical_tip().expect("tip").block_id, genesis);
    assert!(store.store_validated_block(a1_commit).is_err());

    let activation = store
        .plan_best_reorganization(100)
        .expect("activation plan");
    assert!(activation.detach.is_empty());
    assert_eq!(activation.attach, vec![a1]);
    store
        .apply_reorganization(&activation)
        .expect("activate first branch");
    assert_eq!(store.canonical_tip().expect("tip").block_id, a1);

    let b1_commit = validated_reward_commit(&store, genesis, b"conformance-b1");
    let b1 = b1_commit.header().block_id();
    store
        .store_validated_block(b1_commit)
        .expect("store competing branch");
    let branch_snapshot = store
        .parent_state_snapshot(b1)
        .expect("branch state read")
        .expect("branch state");
    assert_eq!(branch_snapshot.anchor_block_id, b1);
    assert_eq!(branch_snapshot.issued_supply, 500_000_000);
    assert_eq!(store.canonical_tip().expect("tip").block_id, a1);

    let b2_commit = validated_reward_commit(&store, b1, b"conformance-b2");
    let b2 = b2_commit.header().block_id();
    store
        .store_validated_block(b2_commit)
        .expect("extend competing branch");
    assert!(matches!(
        store.plan_best_reorganization(1),
        Err(ReorganizationPlanFailure::PolicyPause {
            maximum_plan_blocks: 1
        })
    ));
    let reorganization = store
        .plan_best_reorganization(100)
        .expect("fork reorganization plan");
    assert_eq!(reorganization.common_ancestor, genesis);
    assert_eq!(reorganization.detach, vec![a1]);
    assert_eq!(reorganization.attach, vec![b1, b2]);
    store
        .apply_reorganization(&reorganization)
        .expect("fork reorganization");
    assert_eq!(store.canonical_tip().expect("tip").block_id, b2);

    let final_snapshot = store
        .parent_state_snapshot(b2)
        .expect("final state read")
        .expect("final state");
    assert_eq!(final_snapshot.anchor_block_id, b2);
    assert_eq!(final_snapshot.issued_supply, 1_000_000_000);
    assert_eq!(final_snapshot.accounts.len(), 1);
    assert_eq!(final_snapshot.accounts[0].1.balance.get(), 1_000_000_000);
}

/// Verifies fail-closed reads and exact prepared/published recovery outcomes
/// for both block storage and canonical reorganization.
pub fn assert_recovery_conformance<S, Make, MakeError>(mut make: Make)
where
    S: FaultInjectableConformanceStore,
    S::Error: Debug,
    S::MutationError: Debug,
    S::RecoveryError: Debug,
    Make: FnMut(Block, ValidatedHeaderMetadata) -> Result<S, MakeError>,
    MakeError: Debug,
{
    let mut prepared = make_devnet_store(&mut make);
    let genesis = prepared
        .canonical_tip()
        .expect("canonical genesis")
        .block_id;
    let prepared_commit = validated_reward_commit(&prepared, genesis, b"prepared");
    let prepared_id = prepared_commit.header().block_id();
    prepared
        .inject_conformance_fault(FaultPoint::AfterPrepare)
        .expect("configure prepare fault");
    assert!(prepared.store_validated_block(prepared_commit).is_err());
    assert_eq!(
        prepared.conformance_recovery_status(),
        RecoveryStatus::Prepared
    );
    assert!(prepared.canonical_tip().is_err());
    assert!(prepared.get_validated_header(prepared_id).is_err());
    assert_eq!(
        prepared
            .recover_for_conformance()
            .expect("recover prepared state"),
        RecoveryOutcome::RolledBackPrepared
    );
    assert!(prepared
        .get_validated_header(prepared_id)
        .expect("read after prepared recovery")
        .is_none());
    assert_eq!(prepared.canonical_tip().expect("tip").block_id, genesis);

    let mut published = make_devnet_store(&mut make);
    let genesis = published
        .canonical_tip()
        .expect("canonical genesis")
        .block_id;
    let published_commit = validated_reward_commit(&published, genesis, b"published");
    let published_id = published_commit.header().block_id();
    published
        .inject_conformance_fault(FaultPoint::AfterPublish)
        .expect("configure publish fault");
    assert!(published.store_validated_block(published_commit).is_err());
    assert_eq!(
        published.conformance_recovery_status(),
        RecoveryStatus::Published
    );
    assert!(published.get_validated_header(published_id).is_err());
    assert_eq!(
        published
            .recover_for_conformance()
            .expect("recover published state"),
        RecoveryOutcome::FinalizedPublished
    );
    assert!(published
        .get_validated_header(published_id)
        .expect("read after published recovery")
        .is_some());
    assert_eq!(published.canonical_tip().expect("tip").block_id, genesis);

    let mut reorg = make_devnet_store(&mut make);
    let genesis = reorg.canonical_tip().expect("canonical genesis").block_id;
    let a1_commit = validated_reward_commit(&reorg, genesis, b"reorg-a1");
    let a1 = a1_commit.header().block_id();
    reorg
        .store_validated_block(a1_commit)
        .expect("store selected branch");
    let activation = reorg
        .plan_best_reorganization(100)
        .expect("activation plan");
    reorg
        .apply_reorganization(&activation)
        .expect("activate selected branch");
    let b1_commit = validated_reward_commit(&reorg, genesis, b"reorg-b1");
    let b1 = b1_commit.header().block_id();
    reorg.store_validated_block(b1_commit).expect("store fork");
    let b2_commit = validated_reward_commit(&reorg, b1, b"reorg-b2");
    let b2 = b2_commit.header().block_id();
    reorg.store_validated_block(b2_commit).expect("extend fork");
    let plan = reorg
        .plan_best_reorganization(100)
        .expect("fork reorganization plan");

    reorg
        .inject_conformance_fault(FaultPoint::AfterPrepare)
        .expect("configure reorg prepare fault");
    assert!(reorg.apply_reorganization(&plan).is_err());
    assert!(reorg.canonical_tip().is_err());
    assert_eq!(
        reorg
            .recover_for_conformance()
            .expect("recover prepared reorganization"),
        RecoveryOutcome::RolledBackPrepared
    );
    assert_eq!(reorg.canonical_tip().expect("tip").block_id, a1);

    reorg
        .inject_conformance_fault(FaultPoint::AfterPublish)
        .expect("configure reorg publish fault");
    assert!(reorg.apply_reorganization(&plan).is_err());
    assert!(reorg.canonical_tip().is_err());
    assert_eq!(
        reorg
            .recover_for_conformance()
            .expect("recover published reorganization"),
        RecoveryOutcome::FinalizedPublished
    );
    assert_eq!(reorg.canonical_tip().expect("tip").block_id, b2);
}

fn make_devnet_store<S, Make, MakeError>(make: &mut Make) -> S
where
    Make: FnMut(Block, ValidatedHeaderMetadata) -> Result<S, MakeError>,
    MakeError: Debug,
{
    let (genesis, metadata) = devnet_genesis_fixture();
    make(genesis, metadata).expect("create conformance backend")
}

pub fn devnet_genesis_fixture() -> (Block, ValidatedHeaderMetadata) {
    let header = BlockHeader::decode_exact(&hex(VECTOR_HEADER_HEX)).expect("genesis header");
    let metadata =
        validate_pinned_genesis_header(header, header, HeaderChainParameters::devnet_v0())
            .expect("pinned genesis");
    let genesis = Block {
        header,
        body: BlockBody {
            transactions: Vec::new(),
        },
    };
    (genesis, metadata)
}

pub fn validated_reward_commit<S>(
    store: &S,
    parent_id: BlockId,
    extra: &[u8],
) -> ValidatedBlockCommit
where
    S: ConsensusStorage,
    S::Error: Debug,
{
    let parent = store
        .get_validated_header(parent_id)
        .expect("store read")
        .expect("parent");
    let state = store
        .parent_state_snapshot(parent_id)
        .expect("store read")
        .expect("parent state");
    let ancestry = store
        .ancestor_transaction_snapshot(parent_id)
        .expect("store read")
        .expect("ancestor transactions");
    let height = parent.header().height.checked_add(1).expect("test height");

    let mut reward = RewardTransaction::decode_exact(&hex(VECTOR_REWARD_HEX)).expect("reward");
    reward.body.height = height;
    reward.body.subsidy = Amount::new(subsidy_at_height(height));
    reward.body.fees = Amount::ZERO;
    reward.body.extra = extra.to_vec();
    let recipient = reward.body.recipient;
    let body = BlockBody {
        transactions: vec![Transaction::Reward(reward)],
    };
    let transaction_ids: Vec<_> = body
        .transactions
        .iter()
        .map(|transaction| {
            transaction_id_from_canonical_bytes(&transaction.encode().expect("transaction"))
        })
        .collect();
    let transaction_root = transaction_merkle_root(&transaction_ids).expect("merkle root");

    let mut accounts: BTreeMap<_, _> = state.accounts.iter().copied().collect();
    let before = accounts.get(&recipient).copied().unwrap_or(Account::EMPTY);
    let balance = before
        .balance
        .checked_add(Amount::new(subsidy_at_height(height)))
        .expect("reward balance");
    accounts.insert(recipient, Account::new(balance, before.nonce));
    let resulting_accounts: Vec<_> = accounts.into_iter().collect();
    let state_root = compute_state_root(&resulting_accounts).expect("state root");

    let parent_header = parent.header();
    let header = mine(BlockHeader {
        consensus_version: parent_header.consensus_version,
        chain_id: parent_header.chain_id,
        network_id: parent_header.network_id,
        genesis_commitment: parent_header.genesis_commitment,
        height,
        parent_block_id: parent.block_id(),
        timestamp: parent_header.timestamp.checked_add(1).expect("timestamp"),
        target: DEVNET_POW_LIMIT_V0,
        transaction_root,
        state_root,
        nonce: 0,
    });
    let block = Block { header, body };
    let raw = block.encode_non_genesis().expect("block");
    validate_non_genesis_block(
        &raw,
        store,
        Some(state.as_borrowed()),
        Some(ancestry.as_borrowed()),
        header.timestamp,
        BlockValidationParameters::devnet_v0(),
    )
    .expect("validated block")
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

fn hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16).expect("hex");
            let low = char::from(pair[1]).to_digit(16).expect("hex");
            u8::try_from((high << 4) | low).expect("hex byte")
        })
        .collect()
}
