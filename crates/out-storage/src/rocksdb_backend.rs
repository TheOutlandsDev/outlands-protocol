//! Crash-safe RocksDB adapter for the OUT consensus-storage interface.
//!
//! RocksDB supplies only ordered key/value durability. Canonical records,
//! replay validation, recovery markers, and generation seals are shared with
//! the redb adapter and therefore remain database-independent.

use std::collections::BTreeMap;
use std::path::Path;

use out_codec::Block;
use out_consensus::block::BlockValidationParameters;
use out_consensus::chain::{
    ChainTip, ReorganizationPlan, ReorganizationPlanFailure, ValidatedHeaderMetadata,
    ValidatedHeaderView,
};
use out_primitives::{BlockId, Recipient};
use out_state::Account;
use rocksdb::{IteratorMode, Options, WriteBatch, WriteOptions, DB};

use crate::records::{StorageKey, StorageManifest, StorageMutationKind, StorageRecoveryMarker};
use crate::redb_backend::{
    build_records, key_generation, load_visible_blocks, read_manifest, read_recovery_marker,
    rebuild_inner, require_expected_records, validate_all_record_envelopes,
    validate_marker_manifest, PersistentStorageError,
};
use crate::{
    ConsensusStorage, FaultPoint, InMemoryConsensusStore, OwnedAncestorTransactionSnapshot,
    OwnedParentStateSnapshot, RecoverableConsensusStorage, RecoveryOutcome, RecoveryStatus,
};

pub type RocksdbStorageError = PersistentStorageError;

pub struct RocksdbConsensusStore {
    database: DB,
    inner: InMemoryConsensusStore,
    manifest: StorageManifest,
    marker: StorageRecoveryMarker,
    blocks: BTreeMap<BlockId, Vec<u8>>,
    fault_once: Option<FaultPoint>,
}

impl RocksdbConsensusStore {
    pub fn create(
        path: impl AsRef<Path>,
        genesis_block: Block,
        genesis_metadata: ValidatedHeaderMetadata,
        genesis_accounts: &[(Recipient, Account)],
        issued_supply: u128,
        parameters: BlockValidationParameters,
    ) -> Result<Self, RocksdbStorageError> {
        let identity = parameters.header.network;
        let header = genesis_block.header;
        if header.chain_id != identity.chain_id
            || header.network_id != identity.network_id
            || header.genesis_commitment != identity.genesis_commitment
        {
            return Err(RocksdbStorageError::Corrupt("genesis_identity"));
        }
        let genesis_bytes = genesis_block
            .encode_genesis()
            .map_err(|_| RocksdbStorageError::Encoding)?;
        let genesis_id = genesis_metadata.block_id();
        let inner = InMemoryConsensusStore::new(
            genesis_block,
            genesis_metadata,
            genesis_accounts,
            issued_supply,
        )
        .map_err(RocksdbStorageError::InnerMutation)?;
        let database = open_database(path, true)?;
        if database_has_records(&database)? {
            return Err(RocksdbStorageError::AlreadyInitialized);
        }
        let manifest = StorageManifest {
            identity,
            genesis_block_id: genesis_id,
            active_generation: 0,
            active_tip: genesis_id,
        };
        let marker = StorageRecoveryMarker::Clean {
            active_generation: 0,
            active_tip: genesis_id,
        };
        let mut blocks = BTreeMap::new();
        blocks.insert(genesis_id, genesis_bytes);
        let records = build_records(&inner, &blocks, manifest, marker)?;
        insert_records(&database, &records)?;
        Ok(Self {
            database,
            inner,
            manifest,
            marker,
            blocks,
            fault_once: None,
        })
    }

    pub fn open(
        path: impl AsRef<Path>,
        genesis_block: Block,
        genesis_metadata: ValidatedHeaderMetadata,
        genesis_accounts: &[(Recipient, Account)],
        issued_supply: u128,
        parameters: BlockValidationParameters,
    ) -> Result<Self, RocksdbStorageError> {
        let database = open_database(path, false)?;
        let records = read_records(&database)?;
        if records.is_empty() {
            return Err(RocksdbStorageError::MissingStore);
        }
        validate_all_record_envelopes(&records)?;
        let manifest = read_manifest(&records)?;
        let marker = read_recovery_marker(&records)?;
        validate_marker_manifest(manifest, marker)?;
        let expected_identity = parameters.header.network;
        if manifest.identity != expected_identity
            || genesis_block.header.chain_id != expected_identity.chain_id
            || genesis_block.header.network_id != expected_identity.network_id
            || genesis_block.header.genesis_commitment != expected_identity.genesis_commitment
            || manifest.genesis_block_id != genesis_metadata.block_id()
        {
            return Err(RocksdbStorageError::Corrupt("manifest_identity"));
        }
        let blocks = load_visible_blocks(&records, manifest.genesis_block_id)?;
        let expected_genesis = genesis_block
            .encode_genesis()
            .map_err(|_| RocksdbStorageError::Encoding)?;
        if blocks.get(&manifest.genesis_block_id) != Some(&expected_genesis) {
            return Err(RocksdbStorageError::Corrupt("genesis_bytes"));
        }
        let inner = rebuild_inner(
            genesis_block,
            genesis_metadata,
            genesis_accounts,
            issued_supply,
            parameters,
            &blocks,
            manifest.active_tip,
        )?;
        let expected_records = build_records(&inner, &blocks, manifest, marker)?;
        require_expected_records(&records, &expected_records)?;
        Ok(Self {
            database,
            inner,
            manifest,
            marker,
            blocks,
            fault_once: None,
        })
    }

    pub fn inject_fault_once(&mut self, point: FaultPoint) -> Result<(), RocksdbStorageError> {
        self.require_clean()?;
        self.fault_once = Some(point);
        Ok(())
    }

    pub const fn recovery_status(&self) -> RecoveryStatus {
        match self.marker {
            StorageRecoveryMarker::Clean { .. } => RecoveryStatus::Clean,
            StorageRecoveryMarker::Prepared { .. } => RecoveryStatus::Prepared,
            StorageRecoveryMarker::Published { .. } => RecoveryStatus::Published,
        }
    }

    pub fn recover(&mut self) -> Result<RecoveryOutcome, RocksdbStorageError> {
        match self.marker {
            StorageRecoveryMarker::Clean { .. } => Ok(RecoveryOutcome::AlreadyClean),
            StorageRecoveryMarker::Prepared {
                base_generation,
                candidate_generation,
                subject,
                ..
            } => {
                if self.manifest.active_generation != base_generation {
                    return Err(RocksdbStorageError::Corrupt("prepared_manifest_generation"));
                }
                let clean = StorageRecoveryMarker::Clean {
                    active_generation: base_generation,
                    active_tip: self.manifest.active_tip,
                };
                cleanup_prepared(&self.database, candidate_generation, subject, clean)?;
                self.marker = clean;
                Ok(RecoveryOutcome::RolledBackPrepared)
            }
            StorageRecoveryMarker::Published {
                candidate_generation,
                expected_tip,
                ..
            } => {
                if self.manifest.active_generation != candidate_generation
                    || self.manifest.active_tip != expected_tip
                    || self
                        .inner
                        .canonical_tip()
                        .map_err(RocksdbStorageError::InnerRead)?
                        .block_id
                        != expected_tip
                {
                    return Err(RocksdbStorageError::Corrupt("published_manifest"));
                }
                let clean = StorageRecoveryMarker::Clean {
                    active_generation: candidate_generation,
                    active_tip: expected_tip,
                };
                write_recovery_marker(&self.database, clean)?;
                self.marker = clean;
                Ok(RecoveryOutcome::FinalizedPublished)
            }
        }
    }

    pub fn contains_block(&self, block_id: BlockId) -> Result<bool, RocksdbStorageError> {
        self.require_clean()?;
        Ok(self.blocks.contains_key(&block_id))
    }

    pub fn canonical_block_id(&self, height: u64) -> Result<Option<BlockId>, RocksdbStorageError> {
        self.require_clean()?;
        self.inner
            .canonical_block_id(height)
            .map_err(RocksdbStorageError::InnerRead)
    }

    fn require_clean(&self) -> Result<(), RocksdbStorageError> {
        if matches!(self.marker, StorageRecoveryMarker::Clean { .. }) {
            Ok(())
        } else {
            Err(RocksdbStorageError::RecoveryRequired)
        }
    }

    fn take_fault(&mut self, point: FaultPoint) -> bool {
        if self.fault_once == Some(point) {
            self.fault_once = None;
            true
        } else {
            false
        }
    }

    fn publish_candidate(
        &mut self,
        mutation: StorageMutationKind,
        subject: BlockId,
        candidate_inner: InMemoryConsensusStore,
        candidate_blocks: BTreeMap<BlockId, Vec<u8>>,
    ) -> Result<(), RocksdbStorageError> {
        self.require_clean()?;
        if self.take_fault(FaultPoint::BeforePrepare) {
            return Err(RocksdbStorageError::FaultInjected(
                FaultPoint::BeforePrepare,
            ));
        }
        let base_generation = self.manifest.active_generation;
        let candidate_generation = base_generation
            .checked_add(1)
            .ok_or(RocksdbStorageError::GenerationOverflow)?;
        let expected_tip = candidate_inner
            .canonical_tip()
            .map_err(RocksdbStorageError::InnerRead)?
            .block_id;
        let prepared = StorageRecoveryMarker::Prepared {
            mutation,
            base_generation,
            candidate_generation,
            subject,
            expected_tip,
        };
        write_recovery_marker(&self.database, prepared)?;
        self.marker = prepared;
        if self.take_fault(FaultPoint::AfterPrepare) {
            return Err(RocksdbStorageError::FaultInjected(FaultPoint::AfterPrepare));
        }

        let candidate_manifest = StorageManifest {
            active_generation: candidate_generation,
            active_tip: expected_tip,
            ..self.manifest
        };
        let published = StorageRecoveryMarker::Published {
            mutation,
            base_generation,
            candidate_generation,
            subject,
            expected_tip,
        };
        let candidate_records = build_records(
            &candidate_inner,
            &candidate_blocks,
            candidate_manifest,
            published,
        )?;
        insert_records(&self.database, &candidate_records)?;
        self.inner = candidate_inner;
        self.blocks = candidate_blocks;
        self.manifest = candidate_manifest;
        self.marker = published;
        if self.take_fault(FaultPoint::AfterPublish) {
            return Err(RocksdbStorageError::FaultInjected(FaultPoint::AfterPublish));
        }

        let clean = StorageRecoveryMarker::Clean {
            active_generation: candidate_generation,
            active_tip: expected_tip,
        };
        write_recovery_marker(&self.database, clean)?;
        self.marker = clean;
        Ok(())
    }
}

impl ValidatedHeaderView for RocksdbConsensusStore {
    type Error = RocksdbStorageError;

    fn get_validated_header(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ValidatedHeaderMetadata>, Self::Error> {
        self.require_clean()?;
        self.inner
            .get_validated_header(block_id)
            .map_err(RocksdbStorageError::InnerRead)
    }
}

impl ConsensusStorage for RocksdbConsensusStore {
    type MutationError = RocksdbStorageError;

    fn canonical_tip(&self) -> Result<ChainTip, Self::Error> {
        self.require_clean()?;
        self.inner
            .canonical_tip()
            .map_err(RocksdbStorageError::InnerRead)
    }

    fn parent_state_snapshot(
        &self,
        block_id: BlockId,
    ) -> Result<Option<OwnedParentStateSnapshot>, Self::Error> {
        self.require_clean()?;
        self.inner
            .parent_state_snapshot(block_id)
            .map_err(RocksdbStorageError::InnerRead)
    }

    fn ancestor_transaction_snapshot(
        &self,
        block_id: BlockId,
    ) -> Result<Option<OwnedAncestorTransactionSnapshot>, Self::Error> {
        self.require_clean()?;
        self.inner
            .ancestor_transaction_snapshot(block_id)
            .map_err(RocksdbStorageError::InnerRead)
    }

    fn store_validated_block(
        &mut self,
        commit: out_consensus::block::ValidatedBlockCommit,
    ) -> Result<(), Self::MutationError> {
        self.require_clean()?;
        let block_id = commit.header().block_id();
        let raw = commit.canonical_block_bytes().to_vec();
        let mut candidate_inner = self.inner.clone();
        candidate_inner
            .store_validated_block(commit)
            .map_err(RocksdbStorageError::InnerMutation)?;
        let mut candidate_blocks = self.blocks.clone();
        if candidate_blocks.insert(block_id, raw).is_some() {
            return Err(RocksdbStorageError::Corrupt("duplicate_block_map"));
        }
        self.publish_candidate(
            StorageMutationKind::StoreBlock,
            block_id,
            candidate_inner,
            candidate_blocks,
        )
    }

    fn plan_best_reorganization(
        &self,
        maximum_plan_blocks: u64,
    ) -> Result<ReorganizationPlan, ReorganizationPlanFailure<Self::Error>> {
        self.require_clean()
            .map_err(ReorganizationPlanFailure::Store)?;
        self.inner
            .plan_best_reorganization(maximum_plan_blocks)
            .map_err(|failure| match failure {
                ReorganizationPlanFailure::Store(error) => {
                    ReorganizationPlanFailure::Store(RocksdbStorageError::InnerRead(error))
                }
                ReorganizationPlanFailure::MissingValidatedBlock(id) => {
                    ReorganizationPlanFailure::MissingValidatedBlock(id)
                }
                ReorganizationPlanFailure::CorruptValidatedMetadata(id) => {
                    ReorganizationPlanFailure::CorruptValidatedMetadata(id)
                }
                ReorganizationPlanFailure::WinningTipNotPreferred => {
                    ReorganizationPlanFailure::WinningTipNotPreferred
                }
                ReorganizationPlanFailure::NoCommonAncestor => {
                    ReorganizationPlanFailure::NoCommonAncestor
                }
                ReorganizationPlanFailure::PolicyPause {
                    maximum_plan_blocks,
                } => ReorganizationPlanFailure::PolicyPause {
                    maximum_plan_blocks,
                },
            })
    }

    fn apply_reorganization(
        &mut self,
        plan: &ReorganizationPlan,
    ) -> Result<(), Self::MutationError> {
        self.require_clean()?;
        if plan.detach.is_empty() && plan.attach.is_empty() {
            return Ok(());
        }
        let mut candidate_inner = self.inner.clone();
        candidate_inner
            .apply_reorganization(plan)
            .map_err(RocksdbStorageError::InnerMutation)?;
        self.publish_candidate(
            StorageMutationKind::Reorganization,
            plan.winning_tip,
            candidate_inner,
            self.blocks.clone(),
        )
    }
}

impl RecoverableConsensusStorage for RocksdbConsensusStore {
    type RecoveryError = RocksdbStorageError;

    fn recovery_status(&self) -> RecoveryStatus {
        RocksdbConsensusStore::recovery_status(self)
    }

    fn recover(&mut self) -> Result<RecoveryOutcome, Self::RecoveryError> {
        RocksdbConsensusStore::recover(self)
    }
}

fn open_database(path: impl AsRef<Path>, create: bool) -> Result<DB, RocksdbStorageError> {
    let mut options = Options::default();
    options.create_if_missing(create);
    options.set_paranoid_checks(true);
    DB::open(&options, path).map_err(|_| RocksdbStorageError::Database("rocksdb_open"))
}

fn durable_write_options() -> WriteOptions {
    let mut options = WriteOptions::default();
    options.set_sync(true);
    options
}

fn database_has_records(database: &DB) -> Result<bool, RocksdbStorageError> {
    match database.iterator(IteratorMode::Start).next() {
        None => Ok(false),
        Some(Ok(_)) => Ok(true),
        Some(Err(_)) => Err(RocksdbStorageError::Database("rocksdb_iterate")),
    }
}

fn insert_records(
    database: &DB,
    records: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<(), RocksdbStorageError> {
    let mut batch = WriteBatch::default();
    for (key, value) in records {
        batch.put(key, value);
    }
    database
        .write_opt(batch, &durable_write_options())
        .map_err(|_| RocksdbStorageError::Database("rocksdb_write"))
}

fn write_recovery_marker(
    database: &DB,
    marker: StorageRecoveryMarker,
) -> Result<(), RocksdbStorageError> {
    let mut records = BTreeMap::new();
    records.insert(
        StorageKey::Recovery.encode(),
        marker.encode().map_err(|_| RocksdbStorageError::Encoding)?,
    );
    insert_records(database, &records)
}

fn read_records(database: &DB) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, RocksdbStorageError> {
    let mut records = BTreeMap::new();
    for entry in database.iterator(IteratorMode::Start) {
        let (key, value) = entry.map_err(|_| RocksdbStorageError::Database("rocksdb_entry"))?;
        if records.insert(key.to_vec(), value.to_vec()).is_some() {
            return Err(RocksdbStorageError::Corrupt("duplicate_database_key"));
        }
    }
    Ok(records)
}

fn cleanup_prepared(
    database: &DB,
    candidate_generation: u64,
    subject: BlockId,
    clean: StorageRecoveryMarker,
) -> Result<(), RocksdbStorageError> {
    let records = read_records(database)?;
    let subject_visible = records.contains_key(&StorageKey::BlockVisible(subject).encode());
    let mut batch = WriteBatch::default();
    for key in records.keys() {
        let decoded = StorageKey::decode_exact(key)
            .map_err(|_| RocksdbStorageError::Corrupt("cleanup_key"))?;
        let candidate_key = key_generation(key) == Some(candidate_generation);
        let unpublished_subject = !subject_visible
            && matches!(
                decoded,
                StorageKey::BlockBytes(id)
                    | StorageKey::BlockTransaction { block_id: id, .. }
                    | StorageKey::BranchAccount { block_id: id, .. }
                    | StorageKey::AccountDelta { block_id: id, .. }
                    if id == subject
            );
        if candidate_key || unpublished_subject {
            batch.delete(key);
        }
    }
    let marker = clean.encode().map_err(|_| RocksdbStorageError::Encoding)?;
    batch.put(StorageKey::Recovery.encode(), marker);
    database
        .write_opt(batch, &durable_write_options())
        .map_err(|_| RocksdbStorageError::Database("rocksdb_recovery_write"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::conformance::{
        assert_consensus_storage_conformance, assert_recovery_conformance, devnet_genesis_fixture,
        validated_reward_commit,
    };

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn temporary_path(label: &str) -> PathBuf {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "out-rocksdb-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn remove_paths(paths: &[PathBuf]) {
        for path in paths {
            if let Err(error) = fs::remove_dir_all(path) {
                assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            }
        }
    }

    #[test]
    fn rocksdb_passes_reusable_core_conformance() {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let factory_paths = Arc::clone(&paths);
        assert_consensus_storage_conformance(move |genesis, metadata| {
            let path = temporary_path("core");
            factory_paths.lock().expect("paths").push(path.clone());
            RocksdbConsensusStore::create(
                path,
                genesis,
                metadata,
                &[],
                0,
                BlockValidationParameters::devnet_v0(),
            )
        });
        remove_paths(&paths.lock().expect("paths"));
    }

    #[test]
    fn rocksdb_passes_reusable_recovery_conformance() {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let factory_paths = Arc::clone(&paths);
        assert_recovery_conformance(move |genesis, metadata| {
            let path = temporary_path("recovery");
            factory_paths.lock().expect("paths").push(path.clone());
            RocksdbConsensusStore::create(
                path,
                genesis,
                metadata,
                &[],
                0,
                BlockValidationParameters::devnet_v0(),
            )
        });
        remove_paths(&paths.lock().expect("paths"));
    }

    #[test]
    fn reopen_revalidates_blocks_and_restores_best_chain() {
        let path = temporary_path("reopen");
        let (genesis, metadata) = devnet_genesis_fixture();
        let genesis_id = metadata.block_id();
        let mut store = RocksdbConsensusStore::create(
            &path,
            genesis.clone(),
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("create");
        let a1 = validated_reward_commit(&store, genesis_id, b"reopen-a1");
        store.store_validated_block(a1).expect("store a1");
        let plan = store.plan_best_reorganization(100).expect("plan a1");
        store.apply_reorganization(&plan).expect("activate a1");
        let a1_id = store.canonical_tip().expect("tip").block_id;
        let a2 = validated_reward_commit(&store, a1_id, b"reopen-a2");
        store.store_validated_block(a2).expect("store a2");
        let plan = store.plan_best_reorganization(100).expect("plan a2");
        store.apply_reorganization(&plan).expect("activate a2");
        let expected_tip = store.canonical_tip().expect("tip");
        drop(store);

        let reopened = RocksdbConsensusStore::open(
            &path,
            genesis,
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("reopen");
        assert_eq!(reopened.canonical_tip().expect("tip"), expected_tip);
        assert_eq!(
            reopened.canonical_block_id(2),
            Ok(Some(expected_tip.block_id))
        );
        drop(reopened);
        remove_paths(&[path]);
    }

    #[test]
    fn prepared_and_published_markers_survive_reopen() {
        let prepared_path = temporary_path("prepared-reopen");
        let (genesis, metadata) = devnet_genesis_fixture();
        let genesis_id = metadata.block_id();
        let mut prepared = RocksdbConsensusStore::create(
            &prepared_path,
            genesis.clone(),
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("create prepared");
        let commit = validated_reward_commit(&prepared, genesis_id, b"prepared-reopen");
        let block_id = commit.header().block_id();
        prepared
            .inject_fault_once(FaultPoint::AfterPrepare)
            .expect("fault");
        assert!(prepared.store_validated_block(commit).is_err());
        drop(prepared);
        let mut prepared = RocksdbConsensusStore::open(
            &prepared_path,
            genesis.clone(),
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("open prepared");
        assert_eq!(prepared.recovery_status(), RecoveryStatus::Prepared);
        assert_eq!(prepared.recover(), Ok(RecoveryOutcome::RolledBackPrepared));
        assert_eq!(prepared.contains_block(block_id), Ok(false));
        drop(prepared);

        let published_path = temporary_path("published-reopen");
        let mut published = RocksdbConsensusStore::create(
            &published_path,
            genesis.clone(),
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("create published");
        let commit = validated_reward_commit(&published, genesis_id, b"published-reopen");
        let block_id = commit.header().block_id();
        published
            .inject_fault_once(FaultPoint::AfterPublish)
            .expect("fault");
        assert!(published.store_validated_block(commit).is_err());
        drop(published);
        let mut published = RocksdbConsensusStore::open(
            &published_path,
            genesis,
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("open published");
        assert_eq!(published.recovery_status(), RecoveryStatus::Published);
        assert_eq!(published.recover(), Ok(RecoveryOutcome::FinalizedPublished));
        assert_eq!(published.contains_block(block_id), Ok(true));
        drop(published);
        remove_paths(&[prepared_path, published_path]);
    }

    #[test]
    fn published_fork_reorganization_survives_reopen_and_finalizes() {
        let path = temporary_path("published-reorg-reopen");
        let (genesis, metadata) = devnet_genesis_fixture();
        let genesis_id = metadata.block_id();
        let mut store = RocksdbConsensusStore::create(
            &path,
            genesis.clone(),
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("create");
        let a1 = validated_reward_commit(&store, genesis_id, b"selected-a1");
        store.store_validated_block(a1).expect("store a1");
        let activation = store.plan_best_reorganization(100).expect("activate plan");
        store
            .apply_reorganization(&activation)
            .expect("activate a1");
        let a1_id = store.canonical_tip().expect("tip").block_id;
        let b1 = validated_reward_commit(&store, genesis_id, b"winning-b1");
        let b1_id = b1.header().block_id();
        store.store_validated_block(b1).expect("store b1");
        let b2 = validated_reward_commit(&store, b1_id, b"winning-b2");
        let b2_id = b2.header().block_id();
        store.store_validated_block(b2).expect("store b2");
        let reorganization = store.plan_best_reorganization(100).expect("reorg plan");
        assert_eq!(reorganization.detach, vec![a1_id]);
        assert_eq!(reorganization.attach, vec![b1_id, b2_id]);
        store
            .inject_fault_once(FaultPoint::AfterPublish)
            .expect("fault");
        assert!(store.apply_reorganization(&reorganization).is_err());
        drop(store);

        let mut reopened = RocksdbConsensusStore::open(
            &path,
            genesis,
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("reopen published reorg");
        assert_eq!(reopened.recovery_status(), RecoveryStatus::Published);
        assert_eq!(reopened.recover(), Ok(RecoveryOutcome::FinalizedPublished));
        assert_eq!(reopened.canonical_tip().expect("tip").block_id, b2_id);
        assert_eq!(reopened.canonical_block_id(1), Ok(Some(b1_id)));
        assert_eq!(reopened.canonical_block_id(2), Ok(Some(b2_id)));
        drop(reopened);
        remove_paths(&[path]);
    }

    #[test]
    fn record_checksum_corruption_fails_closed_on_open() {
        let path = temporary_path("corrupt");
        let (genesis, metadata) = devnet_genesis_fixture();
        let store = RocksdbConsensusStore::create(
            &path,
            genesis.clone(),
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("create");
        drop(store);

        let database = open_database(&path, false).expect("raw open");
        let key = StorageKey::Manifest.encode();
        let mut corrupt = database.get(&key).expect("read").expect("manifest");
        corrupt[12] ^= 1;
        database
            .put_opt(key, corrupt, &durable_write_options())
            .expect("corrupt write");
        drop(database);

        assert!(matches!(
            RocksdbConsensusStore::open(
                &path,
                genesis,
                metadata,
                &[],
                0,
                BlockValidationParameters::devnet_v0(),
            ),
            Err(RocksdbStorageError::Corrupt(_))
        ));
        remove_paths(&[path]);
    }
}
