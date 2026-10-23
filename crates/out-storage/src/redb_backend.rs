//! Crash-safe redb reference adapter for the OUT consensus-storage interface.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use out_codec::Block;
use out_consensus::block::{validate_non_genesis_block, BlockValidationParameters};
use out_consensus::chain::{
    plan_reorganization, ChainTip, ReorganizationPlan, ReorganizationPlanFailure,
    ValidatedHeaderMetadata, ValidatedHeaderView,
};
use out_consensus::{block_id_from_header_bytes, transaction_id_from_canonical_bytes};
use out_primitives::{BlockId, Recipient};
use out_state::Account;
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};

use crate::records::{
    decode_block_visibility, decode_storage_block_id, decode_storage_record_exact,
    decode_storage_transaction_id, encode_block_visibility, encode_storage_block_id,
    encode_storage_record, encode_storage_transaction_id, storage_generation_digest,
    StorageAccountDeltaRecord, StorageAccountRecord, StorageCanonicalTipRecord,
    StorageGenerationSeal, StorageKey, StorageManifest, StorageMutationKind, StorageRecordKind,
    StorageRecoveryMarker,
};
use crate::{
    ConsensusStorage, FaultPoint, InMemoryConsensusStore, InMemoryMutationError, InMemoryReadError,
    OwnedAncestorTransactionSnapshot, OwnedParentStateSnapshot, RecoverableConsensusStorage,
    RecoveryOutcome, RecoveryStatus,
};

const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("out_storage_v0");

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistentStorageError {
    RecoveryRequired,
    Database(&'static str),
    AlreadyInitialized,
    MissingStore,
    Corrupt(&'static str),
    Encoding,
    GenerationOverflow,
    PersistedBlockValidation,
    InnerRead(InMemoryReadError),
    InnerMutation(InMemoryMutationError),
    FaultInjected(FaultPoint),
}

/// Backend-neutral failures produced by the shared durable-record and replay
/// layer. Kept as an alias for the existing redb public API.
pub type RedbStorageError = PersistentStorageError;

pub struct RedbConsensusStore {
    database: Database,
    inner: InMemoryConsensusStore,
    manifest: StorageManifest,
    marker: StorageRecoveryMarker,
    blocks: BTreeMap<BlockId, Vec<u8>>,
    fault_once: Option<FaultPoint>,
}

impl RedbConsensusStore {
    pub fn create(
        path: impl AsRef<Path>,
        genesis_block: Block,
        genesis_metadata: ValidatedHeaderMetadata,
        genesis_accounts: &[(Recipient, Account)],
        issued_supply: u128,
        parameters: BlockValidationParameters,
    ) -> Result<Self, RedbStorageError> {
        let identity = parameters.header.network;
        let header = genesis_block.header;
        if header.chain_id != identity.chain_id
            || header.network_id != identity.network_id
            || header.genesis_commitment != identity.genesis_commitment
        {
            return Err(RedbStorageError::Corrupt("genesis_identity"));
        }
        let genesis_bytes = genesis_block
            .encode_genesis()
            .map_err(|_| RedbStorageError::Encoding)?;
        let genesis_id = genesis_metadata.block_id();
        let inner = InMemoryConsensusStore::new(
            genesis_block,
            genesis_metadata,
            genesis_accounts,
            issued_supply,
        )
        .map_err(RedbStorageError::InnerMutation)?;
        let database = Database::create(path).map_err(|_| RedbStorageError::Database("create"))?;
        if database_has_records(&database)? {
            return Err(RedbStorageError::AlreadyInitialized);
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
    ) -> Result<Self, RedbStorageError> {
        let mut database = Database::open(path).map_err(|_| RedbStorageError::Database("open"))?;
        database
            .check_integrity()
            .map_err(|_| RedbStorageError::Database("integrity"))?;
        let records = read_records(&database)?;
        if records.is_empty() {
            return Err(RedbStorageError::MissingStore);
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
            return Err(RedbStorageError::Corrupt("manifest_identity"));
        }
        let blocks = load_visible_blocks(&records, manifest.genesis_block_id)?;
        let expected_genesis = genesis_block
            .encode_genesis()
            .map_err(|_| RedbStorageError::Encoding)?;
        if blocks.get(&manifest.genesis_block_id) != Some(&expected_genesis) {
            return Err(RedbStorageError::Corrupt("genesis_bytes"));
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

    pub fn inject_fault_once(&mut self, point: FaultPoint) -> Result<(), RedbStorageError> {
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

    pub fn recover(&mut self) -> Result<RecoveryOutcome, RedbStorageError> {
        match self.marker {
            StorageRecoveryMarker::Clean { .. } => Ok(RecoveryOutcome::AlreadyClean),
            StorageRecoveryMarker::Prepared {
                base_generation,
                candidate_generation,
                subject,
                ..
            } => {
                if self.manifest.active_generation != base_generation {
                    return Err(RedbStorageError::Corrupt("prepared_manifest_generation"));
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
                        .map_err(RedbStorageError::InnerRead)?
                        .block_id
                        != expected_tip
                {
                    return Err(RedbStorageError::Corrupt("published_manifest"));
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

    pub fn contains_block(&self, block_id: BlockId) -> Result<bool, RedbStorageError> {
        self.require_clean()?;
        Ok(self.blocks.contains_key(&block_id))
    }

    pub fn canonical_block_id(&self, height: u64) -> Result<Option<BlockId>, RedbStorageError> {
        self.require_clean()?;
        self.inner
            .canonical_block_id(height)
            .map_err(RedbStorageError::InnerRead)
    }

    fn require_clean(&self) -> Result<(), RedbStorageError> {
        if matches!(self.marker, StorageRecoveryMarker::Clean { .. }) {
            Ok(())
        } else {
            Err(RedbStorageError::RecoveryRequired)
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
    ) -> Result<(), RedbStorageError> {
        self.require_clean()?;
        if self.take_fault(FaultPoint::BeforePrepare) {
            return Err(RedbStorageError::FaultInjected(FaultPoint::BeforePrepare));
        }
        let base_generation = self.manifest.active_generation;
        let candidate_generation = base_generation
            .checked_add(1)
            .ok_or(RedbStorageError::GenerationOverflow)?;
        let expected_tip = candidate_inner
            .canonical_tip()
            .map_err(RedbStorageError::InnerRead)?
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
            return Err(RedbStorageError::FaultInjected(FaultPoint::AfterPrepare));
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
            return Err(RedbStorageError::FaultInjected(FaultPoint::AfterPublish));
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

impl ValidatedHeaderView for RedbConsensusStore {
    type Error = RedbStorageError;

    fn get_validated_header(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ValidatedHeaderMetadata>, Self::Error> {
        self.require_clean()?;
        self.inner
            .get_validated_header(block_id)
            .map_err(RedbStorageError::InnerRead)
    }
}

impl ConsensusStorage for RedbConsensusStore {
    type MutationError = RedbStorageError;

    fn canonical_tip(&self) -> Result<ChainTip, Self::Error> {
        self.require_clean()?;
        self.inner
            .canonical_tip()
            .map_err(RedbStorageError::InnerRead)
    }

    fn parent_state_snapshot(
        &self,
        block_id: BlockId,
    ) -> Result<Option<OwnedParentStateSnapshot>, Self::Error> {
        self.require_clean()?;
        self.inner
            .parent_state_snapshot(block_id)
            .map_err(RedbStorageError::InnerRead)
    }

    fn ancestor_transaction_snapshot(
        &self,
        block_id: BlockId,
    ) -> Result<Option<OwnedAncestorTransactionSnapshot>, Self::Error> {
        self.require_clean()?;
        self.inner
            .ancestor_transaction_snapshot(block_id)
            .map_err(RedbStorageError::InnerRead)
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
            .map_err(RedbStorageError::InnerMutation)?;
        let mut candidate_blocks = self.blocks.clone();
        if candidate_blocks.insert(block_id, raw).is_some() {
            return Err(RedbStorageError::Corrupt("duplicate_block_map"));
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
                    ReorganizationPlanFailure::Store(RedbStorageError::InnerRead(error))
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
            .map_err(RedbStorageError::InnerMutation)?;
        self.publish_candidate(
            StorageMutationKind::Reorganization,
            plan.winning_tip,
            candidate_inner,
            self.blocks.clone(),
        )
    }
}

impl RecoverableConsensusStorage for RedbConsensusStore {
    type RecoveryError = RedbStorageError;

    fn recovery_status(&self) -> RecoveryStatus {
        RedbConsensusStore::recovery_status(self)
    }

    fn recover(&mut self) -> Result<RecoveryOutcome, Self::RecoveryError> {
        RedbConsensusStore::recover(self)
    }
}

fn database_has_records(database: &Database) -> Result<bool, RedbStorageError> {
    let write = database
        .begin_write()
        .map_err(|_| RedbStorageError::Database("begin_write"))?;
    let has_records = {
        let table = write
            .open_table(RECORDS)
            .map_err(|_| RedbStorageError::Database("open_table"))?;
        !table
            .is_empty()
            .map_err(|_| RedbStorageError::Database("table_is_empty"))?
    };
    drop(write);
    Ok(has_records)
}

fn insert_records(
    database: &Database,
    records: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<(), RedbStorageError> {
    let mut write = database
        .begin_write()
        .map_err(|_| RedbStorageError::Database("begin_write"))?;
    write
        .set_durability(Durability::Immediate)
        .map_err(|_| RedbStorageError::Database("durability"))?;
    {
        let mut table = write
            .open_table(RECORDS)
            .map_err(|_| RedbStorageError::Database("open_table"))?;
        for (key, value) in records {
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|_| RedbStorageError::Database("insert"))?;
        }
    }
    write
        .commit()
        .map_err(|_| RedbStorageError::Database("commit"))
}

fn write_recovery_marker(
    database: &Database,
    marker: StorageRecoveryMarker,
) -> Result<(), RedbStorageError> {
    let mut records = BTreeMap::new();
    records.insert(
        StorageKey::Recovery.encode(),
        marker.encode().map_err(|_| RedbStorageError::Encoding)?,
    );
    insert_records(database, &records)
}

fn read_records(database: &Database) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, RedbStorageError> {
    let read = database
        .begin_read()
        .map_err(|_| RedbStorageError::Database("begin_read"))?;
    let table = read
        .open_table(RECORDS)
        .map_err(|_| RedbStorageError::Database("open_table"))?;
    let mut records = BTreeMap::new();
    let iterator = table
        .iter()
        .map_err(|_| RedbStorageError::Database("iterate"))?;
    for entry in iterator {
        let (key, value) = entry.map_err(|_| RedbStorageError::Database("entry"))?;
        if records
            .insert(key.value().to_vec(), value.value().to_vec())
            .is_some()
        {
            return Err(RedbStorageError::Corrupt("duplicate_database_key"));
        }
    }
    Ok(records)
}

pub(crate) fn build_records(
    inner: &InMemoryConsensusStore,
    blocks: &BTreeMap<BlockId, Vec<u8>>,
    manifest: StorageManifest,
    marker: StorageRecoveryMarker,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, RedbStorageError> {
    let mut records = BTreeMap::new();
    put_record(
        &mut records,
        StorageKey::Manifest.encode(),
        manifest.encode().map_err(|_| RedbStorageError::Encoding)?,
    )?;
    put_record(
        &mut records,
        StorageKey::Recovery.encode(),
        marker.encode().map_err(|_| RedbStorageError::Encoding)?,
    )?;

    for (&block_id, raw) in blocks {
        let block = decode_block(raw, block_id == manifest.genesis_block_id)?;
        if block_id_from_header_bytes(&block.header.encode()) != block_id {
            return Err(RedbStorageError::Corrupt("block_id"));
        }
        put_record(
            &mut records,
            StorageKey::BlockVisible(block_id).encode(),
            encode_block_visibility().map_err(|_| RedbStorageError::Encoding)?,
        )?;
        put_record(
            &mut records,
            StorageKey::BlockBytes(block_id).encode(),
            encode_storage_record(StorageRecordKind::Block, raw)
                .map_err(|_| RedbStorageError::Encoding)?,
        )?;
        for (index, transaction) in block.body.transactions.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| RedbStorageError::Encoding)?;
            let transaction_id = transaction_id_from_canonical_bytes(
                &transaction
                    .encode()
                    .map_err(|_| RedbStorageError::Encoding)?,
            );
            put_record(
                &mut records,
                StorageKey::BlockTransaction { block_id, index }.encode(),
                encode_storage_transaction_id(transaction_id)
                    .map_err(|_| RedbStorageError::Encoding)?,
            )?;
        }
        let state = inner
            .parent_state_snapshot(block_id)
            .map_err(RedbStorageError::InnerRead)?
            .ok_or(RedbStorageError::Corrupt("missing_branch_state"))?;
        for &(recipient, account) in &state.accounts {
            put_record(
                &mut records,
                StorageKey::BranchAccount {
                    block_id,
                    recipient,
                }
                .encode(),
                StorageAccountRecord { account }
                    .encode()
                    .map_err(|_| RedbStorageError::Encoding)?,
            )?;
        }
        if block.header.height != 0 {
            let parent = inner
                .parent_state_snapshot(block.header.parent_block_id)
                .map_err(RedbStorageError::InnerRead)?
                .ok_or(RedbStorageError::Corrupt("missing_parent_state"))?;
            for (recipient, before, after) in account_differences(&parent.accounts, &state.accounts)
            {
                put_record(
                    &mut records,
                    StorageKey::AccountDelta {
                        block_id,
                        recipient,
                    }
                    .encode(),
                    StorageAccountDeltaRecord { before, after }
                        .encode()
                        .map_err(|_| RedbStorageError::Encoding)?,
                )?;
            }
        }
    }

    let tip = inner.canonical_tip().map_err(RedbStorageError::InnerRead)?;
    if tip.block_id != manifest.active_tip {
        return Err(RedbStorageError::Corrupt("manifest_tip"));
    }
    let tip_metadata = inner
        .get_validated_header(tip.block_id)
        .map_err(RedbStorageError::InnerRead)?
        .ok_or(RedbStorageError::Corrupt("tip_metadata"))?;
    let tip_state = inner
        .parent_state_snapshot(tip.block_id)
        .map_err(RedbStorageError::InnerRead)?
        .ok_or(RedbStorageError::Corrupt("tip_state"))?;
    put_record(
        &mut records,
        StorageKey::CanonicalTip(manifest.active_generation).encode(),
        StorageCanonicalTipRecord {
            block_id: tip.block_id,
            state_root: tip_metadata.header().state_root,
            issued_supply: tip_state.issued_supply,
        }
        .encode()
        .map_err(|_| RedbStorageError::Encoding)?,
    )?;

    let mut transaction_count = 0_u64;
    for height in 0..=tip.height {
        let block_id = inner
            .canonical_block_id(height)
            .map_err(RedbStorageError::InnerRead)?
            .ok_or(RedbStorageError::Corrupt("canonical_height"))?;
        put_record(
            &mut records,
            StorageKey::CanonicalHeight {
                generation: manifest.active_generation,
                height,
            }
            .encode(),
            encode_storage_block_id(block_id).map_err(|_| RedbStorageError::Encoding)?,
        )?;
        let raw = blocks
            .get(&block_id)
            .ok_or(RedbStorageError::Corrupt("canonical_block_bytes"))?;
        let block = decode_block(raw, height == 0)?;
        for transaction in block.body.transactions {
            let transaction_id = transaction_id_from_canonical_bytes(
                &transaction
                    .encode()
                    .map_err(|_| RedbStorageError::Encoding)?,
            );
            put_record(
                &mut records,
                StorageKey::CanonicalTransaction {
                    generation: manifest.active_generation,
                    transaction_id,
                }
                .encode(),
                encode_storage_block_id(block_id).map_err(|_| RedbStorageError::Encoding)?,
            )?;
            transaction_count = transaction_count
                .checked_add(1)
                .ok_or(RedbStorageError::Encoding)?;
        }
    }
    for &(recipient, account) in &tip_state.accounts {
        put_record(
            &mut records,
            StorageKey::CanonicalAccount {
                generation: manifest.active_generation,
                recipient,
            }
            .encode(),
            StorageAccountRecord { account }
                .encode()
                .map_err(|_| RedbStorageError::Encoding)?,
        )?;
    }

    let generation_pairs: Vec<_> = records
        .iter()
        .filter(|(key, _)| key_generation(key) == Some(manifest.active_generation))
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect();
    let digest = storage_generation_digest(generation_pairs)
        .map_err(|_| RedbStorageError::Corrupt("generation_digest"))?;
    let seal = StorageGenerationSeal {
        generation: manifest.active_generation,
        tip: tip.block_id,
        state_root: tip_metadata.header().state_root,
        issued_supply: tip_state.issued_supply,
        height_count: tip
            .height
            .checked_add(1)
            .ok_or(RedbStorageError::Encoding)?,
        transaction_count,
        account_count: u64::try_from(tip_state.accounts.len())
            .map_err(|_| RedbStorageError::Encoding)?,
        records_digest: digest,
    };
    put_record(
        &mut records,
        StorageKey::GenerationSeal(manifest.active_generation).encode(),
        seal.encode().map_err(|_| RedbStorageError::Encoding)?,
    )?;
    Ok(records)
}

pub(crate) fn rebuild_inner(
    genesis_block: Block,
    genesis_metadata: ValidatedHeaderMetadata,
    genesis_accounts: &[(Recipient, Account)],
    issued_supply: u128,
    parameters: BlockValidationParameters,
    blocks: &BTreeMap<BlockId, Vec<u8>>,
    expected_tip: BlockId,
) -> Result<InMemoryConsensusStore, RedbStorageError> {
    let genesis_id = genesis_metadata.block_id();
    let mut inner = InMemoryConsensusStore::new(
        genesis_block,
        genesis_metadata,
        genesis_accounts,
        issued_supply,
    )
    .map_err(RedbStorageError::InnerMutation)?;
    let mut ordered = Vec::new();
    for (&block_id, raw) in blocks {
        if block_id == genesis_id {
            continue;
        }
        let block = decode_block(raw, false)?;
        if block_id_from_header_bytes(&block.header.encode()) != block_id {
            return Err(RedbStorageError::Corrupt("persisted_block_id"));
        }
        ordered.push((block.header.height, block_id, raw));
    }
    ordered.sort_unstable_by_key(|(height, block_id, _)| (*height, *block_id));
    for (_, _, raw) in ordered {
        let block = Block::decode_non_genesis_exact(raw)
            .map_err(|_| RedbStorageError::Corrupt("persisted_block_encoding"))?;
        let parent_id = block.header.parent_block_id;
        let state = inner
            .parent_state_snapshot(parent_id)
            .map_err(RedbStorageError::InnerRead)?;
        let ancestry = inner
            .ancestor_transaction_snapshot(parent_id)
            .map_err(RedbStorageError::InnerRead)?;
        let commit = validate_non_genesis_block(
            raw,
            &inner,
            state.as_ref().map(OwnedParentStateSnapshot::as_borrowed),
            ancestry
                .as_ref()
                .map(OwnedAncestorTransactionSnapshot::as_borrowed),
            block.header.timestamp,
            parameters,
        )
        .map_err(|_| RedbStorageError::PersistedBlockValidation)?;
        inner
            .store_validated_block(commit)
            .map_err(RedbStorageError::InnerMutation)?;
    }
    let selected = inner.canonical_tip().map_err(RedbStorageError::InnerRead)?;
    let winning = inner
        .get_validated_header(expected_tip)
        .map_err(RedbStorageError::InnerRead)?
        .ok_or(RedbStorageError::Corrupt("persisted_tip_header"))?
        .tip();
    let plan = plan_reorganization(&inner, selected, winning, u64::MAX)
        .map_err(|_| RedbStorageError::Corrupt("persisted_chain_plan"))?;
    inner
        .apply_reorganization(&plan)
        .map_err(RedbStorageError::InnerMutation)?;
    if inner
        .canonical_tip()
        .map_err(RedbStorageError::InnerRead)?
        .block_id
        != expected_tip
    {
        return Err(RedbStorageError::Corrupt("persisted_best_tip"));
    }
    Ok(inner)
}

pub(crate) fn load_visible_blocks(
    records: &BTreeMap<Vec<u8>, Vec<u8>>,
    genesis_id: BlockId,
) -> Result<BTreeMap<BlockId, Vec<u8>>, RedbStorageError> {
    let mut blocks = BTreeMap::new();
    for (key, value) in records {
        let decoded =
            StorageKey::decode_exact(key).map_err(|_| RedbStorageError::Corrupt("storage_key"))?;
        let StorageKey::BlockVisible(block_id) = decoded else {
            continue;
        };
        decode_block_visibility(value)
            .map_err(|_| RedbStorageError::Corrupt("block_visibility"))?;
        let bytes_key = StorageKey::BlockBytes(block_id).encode();
        let bytes_record = records
            .get(&bytes_key)
            .ok_or(RedbStorageError::Corrupt("missing_block_bytes"))?;
        let raw = block_record_payload(bytes_record)?;
        let block = decode_block(raw, block_id == genesis_id)?;
        if block_id_from_header_bytes(&block.header.encode()) != block_id {
            return Err(RedbStorageError::Corrupt("visible_block_id"));
        }
        blocks.insert(block_id, raw.to_vec());
    }
    if !blocks.contains_key(&genesis_id) {
        return Err(RedbStorageError::Corrupt("missing_genesis"));
    }
    Ok(blocks)
}

pub(crate) fn validate_all_record_envelopes(
    records: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<(), RedbStorageError> {
    for (key, value) in records {
        match StorageKey::decode_exact(key).map_err(|_| RedbStorageError::Corrupt("storage_key"))? {
            StorageKey::Manifest => {
                StorageManifest::decode_exact(value)
                    .map_err(|_| RedbStorageError::Corrupt("manifest_record"))?;
            }
            StorageKey::Recovery => {
                StorageRecoveryMarker::decode_exact(value)
                    .map_err(|_| RedbStorageError::Corrupt("recovery_record"))?;
            }
            StorageKey::BlockVisible(_) => {
                decode_block_visibility(value)
                    .map_err(|_| RedbStorageError::Corrupt("visibility_record"))?;
            }
            StorageKey::BlockBytes(_) => {
                block_record_payload(value)?;
            }
            StorageKey::BlockTransaction { .. } => {
                decode_storage_transaction_id(value)
                    .map_err(|_| RedbStorageError::Corrupt("transaction_id_record"))?;
            }
            StorageKey::BranchAccount { .. } | StorageKey::CanonicalAccount { .. } => {
                StorageAccountRecord::decode_exact(value)
                    .map_err(|_| RedbStorageError::Corrupt("account_record"))?;
            }
            StorageKey::AccountDelta { .. } => {
                StorageAccountDeltaRecord::decode_exact(value)
                    .map_err(|_| RedbStorageError::Corrupt("delta_record"))?;
            }
            StorageKey::StateNode(_) => {
                let record = decode_storage_record_exact(value)
                    .map_err(|_| RedbStorageError::Corrupt("state_node_record"))?;
                if record.kind != StorageRecordKind::StateNode {
                    return Err(RedbStorageError::Corrupt("state_node_kind"));
                }
            }
            StorageKey::GenerationSeal(_) => {
                StorageGenerationSeal::decode_exact(value)
                    .map_err(|_| RedbStorageError::Corrupt("generation_seal"))?;
            }
            StorageKey::CanonicalTip(_) => {
                StorageCanonicalTipRecord::decode_exact(value)
                    .map_err(|_| RedbStorageError::Corrupt("canonical_tip_record"))?;
            }
            StorageKey::CanonicalHeight { .. } | StorageKey::CanonicalTransaction { .. } => {
                decode_storage_block_id(value)
                    .map_err(|_| RedbStorageError::Corrupt("block_id_record"))?;
            }
        }
    }
    Ok(())
}

pub(crate) fn read_manifest(
    records: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<StorageManifest, RedbStorageError> {
    StorageManifest::decode_exact(
        records
            .get(&StorageKey::Manifest.encode())
            .ok_or(RedbStorageError::Corrupt("missing_manifest"))?,
    )
    .map_err(|_| RedbStorageError::Corrupt("manifest"))
}

pub(crate) fn read_recovery_marker(
    records: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<StorageRecoveryMarker, RedbStorageError> {
    StorageRecoveryMarker::decode_exact(
        records
            .get(&StorageKey::Recovery.encode())
            .ok_or(RedbStorageError::Corrupt("missing_recovery"))?,
    )
    .map_err(|_| RedbStorageError::Corrupt("recovery"))
}

pub(crate) fn validate_marker_manifest(
    manifest: StorageManifest,
    marker: StorageRecoveryMarker,
) -> Result<(), RedbStorageError> {
    let valid = match marker {
        StorageRecoveryMarker::Clean {
            active_generation,
            active_tip,
        } => manifest.active_generation == active_generation && manifest.active_tip == active_tip,
        StorageRecoveryMarker::Prepared {
            base_generation, ..
        } => manifest.active_generation == base_generation,
        StorageRecoveryMarker::Published {
            candidate_generation,
            expected_tip,
            ..
        } => {
            manifest.active_generation == candidate_generation
                && manifest.active_tip == expected_tip
        }
    };
    if valid {
        Ok(())
    } else {
        Err(RedbStorageError::Corrupt("marker_manifest"))
    }
}

pub(crate) fn require_expected_records(
    actual: &BTreeMap<Vec<u8>, Vec<u8>>,
    expected: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<(), RedbStorageError> {
    for (key, value) in expected {
        if actual.get(key) != Some(value) {
            return Err(RedbStorageError::Corrupt("record_mismatch"));
        }
    }
    let manifest = read_manifest(actual)?;
    let marker = read_recovery_marker(actual)?;
    for key in actual.keys() {
        if expected.contains_key(key) {
            continue;
        }
        let decoded = StorageKey::decode_exact(key)
            .map_err(|_| RedbStorageError::Corrupt("unexpected_key"))?;
        let old_generation =
            key_generation(key).is_some_and(|generation| generation < manifest.active_generation);
        let prepared_candidate = matches!(
            marker,
            StorageRecoveryMarker::Prepared {
                candidate_generation,
                ..
            } if key_generation(key) == Some(candidate_generation)
        );
        let prepared_subject = matches!(
            marker,
            StorageRecoveryMarker::Prepared { subject, .. }
                if matches!(
                    decoded,
                    StorageKey::BlockBytes(id)
                        | StorageKey::BlockTransaction { block_id: id, .. }
                        | StorageKey::BranchAccount { block_id: id, .. }
                        | StorageKey::AccountDelta { block_id: id, .. }
                        if id == subject
                )
        );
        if !old_generation && !prepared_candidate && !prepared_subject {
            return Err(RedbStorageError::Corrupt("unexpected_record"));
        }
    }
    Ok(())
}

fn cleanup_prepared(
    database: &Database,
    candidate_generation: u64,
    subject: BlockId,
    clean: StorageRecoveryMarker,
) -> Result<(), RedbStorageError> {
    let records = read_records(database)?;
    let subject_visible = records.contains_key(&StorageKey::BlockVisible(subject).encode());
    let mut remove = Vec::new();
    for key in records.keys() {
        let decoded =
            StorageKey::decode_exact(key).map_err(|_| RedbStorageError::Corrupt("cleanup_key"))?;
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
            remove.push(key.clone());
        }
    }
    let mut write = database
        .begin_write()
        .map_err(|_| RedbStorageError::Database("begin_recovery"))?;
    write
        .set_durability(Durability::Immediate)
        .map_err(|_| RedbStorageError::Database("recovery_durability"))?;
    {
        let mut table = write
            .open_table(RECORDS)
            .map_err(|_| RedbStorageError::Database("recovery_table"))?;
        for key in remove {
            table
                .remove(key.as_slice())
                .map_err(|_| RedbStorageError::Database("recovery_remove"))?;
        }
        let marker = clean.encode().map_err(|_| RedbStorageError::Encoding)?;
        table
            .insert(StorageKey::Recovery.encode().as_slice(), marker.as_slice())
            .map_err(|_| RedbStorageError::Database("recovery_marker"))?;
    }
    write
        .commit()
        .map_err(|_| RedbStorageError::Database("recovery_commit"))
}

pub(crate) fn key_generation(key: &[u8]) -> Option<u64> {
    match StorageKey::decode_exact(key).ok()? {
        StorageKey::GenerationSeal(generation)
        | StorageKey::CanonicalTip(generation)
        | StorageKey::CanonicalHeight { generation, .. }
        | StorageKey::CanonicalTransaction { generation, .. }
        | StorageKey::CanonicalAccount { generation, .. } => Some(generation),
        _ => None,
    }
}

fn put_record(
    records: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    key: Vec<u8>,
    value: Vec<u8>,
) -> Result<(), RedbStorageError> {
    if records.insert(key, value).is_some() {
        Err(RedbStorageError::Corrupt("duplicate_record"))
    } else {
        Ok(())
    }
}

fn block_record_payload(value: &[u8]) -> Result<&[u8], RedbStorageError> {
    let record = decode_storage_record_exact(value)
        .map_err(|_| RedbStorageError::Corrupt("block_record"))?;
    if record.kind != StorageRecordKind::Block {
        return Err(RedbStorageError::Corrupt("block_record_kind"));
    }
    Ok(record.payload)
}

fn decode_block(raw: &[u8], genesis: bool) -> Result<Block, RedbStorageError> {
    if genesis {
        Block::decode_genesis_exact(raw)
    } else {
        Block::decode_non_genesis_exact(raw)
    }
    .map_err(|_| RedbStorageError::Corrupt("block_encoding"))
}

fn account_differences(
    before: &[(Recipient, Account)],
    after: &[(Recipient, Account)],
) -> Vec<(Recipient, Account, Account)> {
    let before: BTreeMap<_, _> = before.iter().copied().collect();
    let after: BTreeMap<_, _> = after.iter().copied().collect();
    let recipients: BTreeSet<_> = before.keys().chain(after.keys()).copied().collect();
    recipients
        .into_iter()
        .filter_map(|recipient| {
            let before = before.get(&recipient).copied().unwrap_or(Account::EMPTY);
            let after = after.get(&recipient).copied().unwrap_or(Account::EMPTY);
            (before != after).then_some((recipient, before, after))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use out_consensus::block::BlockValidationParameters;
    use redb::{Database, Durability};

    use super::*;
    use crate::conformance::{
        assert_consensus_storage_conformance, assert_recovery_conformance, devnet_genesis_fixture,
        validated_reward_commit,
    };

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn temporary_path(label: &str) -> PathBuf {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "out-redb-{label}-{}-{sequence}.redb",
            std::process::id()
        ))
    }

    fn remove_paths(paths: &[PathBuf]) {
        for path in paths {
            if let Err(error) = fs::remove_file(path) {
                assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            }
        }
    }

    #[test]
    fn redb_passes_reusable_core_conformance() {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let factory_paths = Arc::clone(&paths);
        assert_consensus_storage_conformance(move |genesis, metadata| {
            let path = temporary_path("core");
            factory_paths.lock().expect("paths").push(path.clone());
            RedbConsensusStore::create(
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
    fn redb_passes_reusable_recovery_conformance() {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let factory_paths = Arc::clone(&paths);
        assert_recovery_conformance(move |genesis, metadata| {
            let path = temporary_path("recovery");
            factory_paths.lock().expect("paths").push(path.clone());
            RedbConsensusStore::create(
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
        let mut store = RedbConsensusStore::create(
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

        let reopened = RedbConsensusStore::open(
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
        let mut prepared = RedbConsensusStore::create(
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
        let mut prepared = RedbConsensusStore::open(
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
        let mut published = RedbConsensusStore::create(
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
        let mut published = RedbConsensusStore::open(
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
        let mut store = RedbConsensusStore::create(
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

        let mut reopened = RedbConsensusStore::open(
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
    fn checksum_corruption_fails_closed_on_open() {
        let path = temporary_path("corrupt");
        let (genesis, metadata) = devnet_genesis_fixture();
        let store = RedbConsensusStore::create(
            &path,
            genesis.clone(),
            metadata,
            &[],
            0,
            BlockValidationParameters::devnet_v0(),
        )
        .expect("create");
        drop(store);

        let database = Database::open(&path).expect("raw open");
        let mut write = database.begin_write().expect("write");
        write
            .set_durability(Durability::Immediate)
            .expect("durability");
        {
            let mut table = write.open_table(RECORDS).expect("table");
            let key = StorageKey::Manifest.encode();
            let current = table
                .get(key.as_slice())
                .expect("read")
                .expect("manifest")
                .value()
                .to_vec();
            let mut corrupt = current;
            corrupt[12] ^= 1;
            table
                .insert(key.as_slice(), corrupt.as_slice())
                .expect("corrupt insert");
        }
        write.commit().expect("commit corruption");
        drop(database);

        assert!(matches!(
            RedbConsensusStore::open(
                &path,
                genesis,
                metadata,
                &[],
                0,
                BlockValidationParameters::devnet_v0(),
            ),
            Err(RedbStorageError::Corrupt(_))
        ));
        remove_paths(&[path]);
    }
}
