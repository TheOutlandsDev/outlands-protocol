#![forbid(unsafe_code)]

#[cfg(any(test, feature = "conformance"))]
pub mod conformance;
pub mod records;
pub mod redb_backend;
pub mod rocksdb_backend;

use std::collections::{BTreeMap, BTreeSet};

use out_codec::Block;
use out_consensus::block::{
    AccountDelta, AncestorTransactionSnapshot, ParentStateSnapshot, ValidatedBlockCommit,
};
use out_consensus::chain::{
    compare_chain_tips, plan_reorganization, ChainTip, ReorganizationPlan,
    ReorganizationPlanFailure, ValidatedHeaderMetadata, ValidatedHeaderView,
};
use out_consensus::{
    block_id_from_header_bytes, checked_cumulative_work, exact_block_work,
    transaction_id_from_canonical_bytes,
};
use out_primitives::{BlockId, Recipient, StateRoot, TransactionId, MAX_MONEY};
use out_state::{compute_state_root, subsidy_at_height, Account};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedParentStateSnapshot {
    pub anchor_block_id: BlockId,
    pub accounts: Vec<(Recipient, Account)>,
    pub issued_supply: u128,
}

impl OwnedParentStateSnapshot {
    pub fn as_borrowed(&self) -> ParentStateSnapshot<'_> {
        ParentStateSnapshot {
            anchor_block_id: self.anchor_block_id,
            accounts: &self.accounts,
            issued_supply: self.issued_supply,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedAncestorTransactionSnapshot {
    pub anchor_block_id: BlockId,
    pub confirmed_transaction_ids: BTreeSet<TransactionId>,
}

impl OwnedAncestorTransactionSnapshot {
    pub fn as_borrowed(&self) -> AncestorTransactionSnapshot<'_> {
        AncestorTransactionSnapshot {
            anchor_block_id: self.anchor_block_id,
            confirmed_transaction_ids: &self.confirmed_transaction_ids,
        }
    }
}

pub trait ConsensusStorage: ValidatedHeaderView {
    type MutationError;

    fn canonical_tip(&self) -> Result<ChainTip, Self::Error>;

    fn parent_state_snapshot(
        &self,
        block_id: BlockId,
    ) -> Result<Option<OwnedParentStateSnapshot>, Self::Error>;

    fn ancestor_transaction_snapshot(
        &self,
        block_id: BlockId,
    ) -> Result<Option<OwnedAncestorTransactionSnapshot>, Self::Error>;

    fn store_validated_block(
        &mut self,
        commit: ValidatedBlockCommit,
    ) -> Result<(), Self::MutationError>;

    fn plan_best_reorganization(
        &self,
        maximum_plan_blocks: u64,
    ) -> Result<ReorganizationPlan, ReorganizationPlanFailure<Self::Error>>;

    fn apply_reorganization(
        &mut self,
        plan: &ReorganizationPlan,
    ) -> Result<(), Self::MutationError>;
}

/// Production recovery capability for stores whose durable mutations have
/// explicit prepare/publish phases. Consensus readers remain fail-closed until
/// `recover` returns successfully.
pub trait RecoverableConsensusStorage: ConsensusStorage {
    type RecoveryError;

    fn recovery_status(&self) -> RecoveryStatus;
    fn recover(&mut self) -> Result<RecoveryOutcome, Self::RecoveryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InMemoryReadError {
    RecoveryRequired,
    CorruptDurableState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrityError {
    GenesisStructure,
    HeaderMismatch,
    BlockIdMismatch,
    MissingParent(BlockId),
    ParentMismatch,
    CanonicalBytes,
    TransactionIds,
    DuplicateTransactionId(TransactionId),
    AncestorDuplicate(TransactionId),
    StateRoot,
    Supply,
    DuplicateAccount(Recipient),
    NonNormalizedAccount(Recipient),
    AccountOrder,
    Work,
    DeltaOrder,
    DeltaBeforeMismatch(Recipient),
    DeltaResultMismatch,
    CanonicalHeightIndex,
    CanonicalTransactionIndex,
    CanonicalState,
    BrokenAncestry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    BeforePrepare,
    AfterPrepare,
    AfterPublish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryStatus {
    Clean,
    Prepared,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    AlreadyClean,
    RolledBackPrepared,
    FinalizedPublished,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InMemoryMutationError {
    RecoveryRequired,
    DuplicateBlock(BlockId),
    Integrity(IntegrityError),
    InvalidReorganization,
    FaultInjected(FaultPoint),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredBlock {
    canonical_bytes: Vec<u8>,
    block: Block,
    metadata: ValidatedHeaderMetadata,
    transaction_ids: Vec<TransactionId>,
    accounts: BTreeMap<Recipient, Account>,
    account_deltas: Vec<AccountDelta>,
    issued_supply: u128,
    total_fees: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoreState {
    blocks: BTreeMap<BlockId, StoredBlock>,
    canonical_tip: BlockId,
    canonical_by_height: BTreeMap<u64, BlockId>,
    canonical_transaction_index: BTreeMap<TransactionId, BlockId>,
    canonical_accounts: BTreeMap<Recipient, Account>,
    canonical_supply: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecoveryState {
    Clean,
    Prepared(Box<StoreState>),
    Published,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryConsensusStore {
    durable: StoreState,
    recovery: RecoveryState,
    fault_once: Option<FaultPoint>,
}

impl InMemoryConsensusStore {
    pub fn new(
        genesis_block: Block,
        genesis_metadata: ValidatedHeaderMetadata,
        genesis_accounts: &[(Recipient, Account)],
        issued_supply: u128,
    ) -> Result<Self, InMemoryMutationError> {
        if genesis_block.header.height != 0
            || genesis_block.header.parent_block_id != BlockId::new([0; 32])
            || !genesis_block.body.transactions.is_empty()
            || genesis_block.header != genesis_metadata.header()
        {
            return Err(InMemoryMutationError::Integrity(
                IntegrityError::GenesisStructure,
            ));
        }
        let canonical_bytes = genesis_block
            .encode_genesis()
            .map_err(|_| InMemoryMutationError::Integrity(IntegrityError::CanonicalBytes))?;
        let accounts =
            normalized_accounts(genesis_accounts).map_err(InMemoryMutationError::Integrity)?;
        validate_accounts(&accounts, issued_supply, genesis_block.header.state_root)
            .map_err(InMemoryMutationError::Integrity)?;
        if block_id_from_header_bytes(&genesis_block.header.encode()) != genesis_metadata.block_id()
            || exact_block_work(genesis_block.header.target).ok()
                != Some(genesis_metadata.block_work())
            || genesis_metadata.cumulative_work() != genesis_metadata.block_work()
        {
            return Err(InMemoryMutationError::Integrity(IntegrityError::Work));
        }
        let block_id = genesis_metadata.block_id();
        let stored = StoredBlock {
            canonical_bytes,
            block: genesis_block,
            metadata: genesis_metadata,
            transaction_ids: Vec::new(),
            accounts: accounts.clone(),
            account_deltas: Vec::new(),
            issued_supply,
            total_fees: 0,
        };
        let mut blocks = BTreeMap::new();
        blocks.insert(block_id, stored);
        let mut canonical_by_height = BTreeMap::new();
        canonical_by_height.insert(0, block_id);
        let durable = StoreState {
            blocks,
            canonical_tip: block_id,
            canonical_by_height,
            canonical_transaction_index: BTreeMap::new(),
            canonical_accounts: accounts,
            canonical_supply: issued_supply,
        };
        validate_store_state(&durable).map_err(InMemoryMutationError::Integrity)?;
        Ok(Self {
            durable,
            recovery: RecoveryState::Clean,
            fault_once: None,
        })
    }

    pub const fn recovery_status(&self) -> RecoveryStatus {
        match self.recovery {
            RecoveryState::Clean => RecoveryStatus::Clean,
            RecoveryState::Prepared(_) => RecoveryStatus::Prepared,
            RecoveryState::Published => RecoveryStatus::Published,
        }
    }

    pub fn inject_fault_once(&mut self, point: FaultPoint) -> Result<(), InMemoryMutationError> {
        self.require_clean_mutation()?;
        self.fault_once = Some(point);
        Ok(())
    }

    pub fn recover(&mut self) -> Result<RecoveryOutcome, InMemoryMutationError> {
        let outcome = match self.recovery {
            RecoveryState::Clean => RecoveryOutcome::AlreadyClean,
            RecoveryState::Prepared(_) => RecoveryOutcome::RolledBackPrepared,
            RecoveryState::Published => RecoveryOutcome::FinalizedPublished,
        };
        validate_store_state(&self.durable).map_err(InMemoryMutationError::Integrity)?;
        self.recovery = RecoveryState::Clean;
        Ok(outcome)
    }

    pub fn contains_block(&self, block_id: BlockId) -> Result<bool, InMemoryReadError> {
        self.require_clean_read()?;
        Ok(self.durable.blocks.contains_key(&block_id))
    }

    pub fn canonical_block_id(&self, height: u64) -> Result<Option<BlockId>, InMemoryReadError> {
        self.require_clean_read()?;
        Ok(self.durable.canonical_by_height.get(&height).copied())
    }

    fn require_clean_read(&self) -> Result<(), InMemoryReadError> {
        if matches!(self.recovery, RecoveryState::Clean) {
            Ok(())
        } else {
            Err(InMemoryReadError::RecoveryRequired)
        }
    }

    fn require_clean_mutation(&self) -> Result<(), InMemoryMutationError> {
        if matches!(self.recovery, RecoveryState::Clean) {
            Ok(())
        } else {
            Err(InMemoryMutationError::RecoveryRequired)
        }
    }

    fn publish_candidate(&mut self, candidate: StoreState) -> Result<(), InMemoryMutationError> {
        self.require_clean_mutation()?;
        validate_store_state(&candidate).map_err(InMemoryMutationError::Integrity)?;
        if self.take_fault(FaultPoint::BeforePrepare) {
            return Err(InMemoryMutationError::FaultInjected(
                FaultPoint::BeforePrepare,
            ));
        }
        self.recovery = RecoveryState::Prepared(Box::new(candidate));
        if self.take_fault(FaultPoint::AfterPrepare) {
            return Err(InMemoryMutationError::FaultInjected(
                FaultPoint::AfterPrepare,
            ));
        }
        let prepared = match std::mem::replace(&mut self.recovery, RecoveryState::Published) {
            RecoveryState::Prepared(prepared) => prepared,
            RecoveryState::Clean | RecoveryState::Published => {
                return Err(InMemoryMutationError::Integrity(
                    IntegrityError::CanonicalState,
                ));
            }
        };
        self.durable = *prepared;
        if self.take_fault(FaultPoint::AfterPublish) {
            return Err(InMemoryMutationError::FaultInjected(
                FaultPoint::AfterPublish,
            ));
        }
        self.recovery = RecoveryState::Clean;
        Ok(())
    }

    fn take_fault(&mut self, point: FaultPoint) -> bool {
        if self.fault_once == Some(point) {
            self.fault_once = None;
            true
        } else {
            false
        }
    }
}

impl ValidatedHeaderView for InMemoryConsensusStore {
    type Error = InMemoryReadError;

    fn get_validated_header(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ValidatedHeaderMetadata>, Self::Error> {
        self.require_clean_read()?;
        Ok(self
            .durable
            .blocks
            .get(&block_id)
            .map(|stored| stored.metadata))
    }
}

impl ConsensusStorage for InMemoryConsensusStore {
    type MutationError = InMemoryMutationError;

    fn canonical_tip(&self) -> Result<ChainTip, Self::Error> {
        self.require_clean_read()?;
        self.durable
            .blocks
            .get(&self.durable.canonical_tip)
            .map(|stored| stored.metadata.tip())
            .ok_or(InMemoryReadError::CorruptDurableState)
    }

    fn parent_state_snapshot(
        &self,
        block_id: BlockId,
    ) -> Result<Option<OwnedParentStateSnapshot>, Self::Error> {
        self.require_clean_read()?;
        Ok(self
            .durable
            .blocks
            .get(&block_id)
            .map(|stored| OwnedParentStateSnapshot {
                anchor_block_id: block_id,
                accounts: stored
                    .accounts
                    .iter()
                    .map(|(&recipient, &account)| (recipient, account))
                    .collect(),
                issued_supply: stored.issued_supply,
            }))
    }

    fn ancestor_transaction_snapshot(
        &self,
        block_id: BlockId,
    ) -> Result<Option<OwnedAncestorTransactionSnapshot>, Self::Error> {
        self.require_clean_read()?;
        let Some(mut current) = self.durable.blocks.get(&block_id) else {
            return Ok(None);
        };
        let mut confirmed = BTreeSet::new();
        loop {
            for &transaction_id in current.transaction_ids.iter().skip(1) {
                confirmed.insert(transaction_id);
            }
            if current.block.header.height == 0 {
                break;
            }
            current = self
                .durable
                .blocks
                .get(&current.block.header.parent_block_id)
                .ok_or(InMemoryReadError::CorruptDurableState)?;
        }
        Ok(Some(OwnedAncestorTransactionSnapshot {
            anchor_block_id: block_id,
            confirmed_transaction_ids: confirmed,
        }))
    }

    fn store_validated_block(
        &mut self,
        commit: ValidatedBlockCommit,
    ) -> Result<(), Self::MutationError> {
        self.require_clean_mutation()?;
        let block_id = commit.header().block_id();
        if self.durable.blocks.contains_key(&block_id) {
            return Err(InMemoryMutationError::DuplicateBlock(block_id));
        }
        let stored = stored_block_from_commit(&self.durable, commit)
            .map_err(InMemoryMutationError::Integrity)?;
        let mut candidate = self.durable.clone();
        candidate.blocks.insert(block_id, stored);
        self.publish_candidate(candidate)
    }

    fn plan_best_reorganization(
        &self,
        maximum_plan_blocks: u64,
    ) -> Result<ReorganizationPlan, ReorganizationPlanFailure<Self::Error>> {
        let selected = self
            .canonical_tip()
            .map_err(ReorganizationPlanFailure::Store)?;
        let winning = self
            .durable
            .blocks
            .values()
            .map(|stored| stored.metadata.tip())
            .max_by(compare_chain_tips)
            .ok_or(ReorganizationPlanFailure::Store(
                InMemoryReadError::CorruptDurableState,
            ))?;
        plan_reorganization(self, selected, winning, maximum_plan_blocks)
    }

    fn apply_reorganization(
        &mut self,
        plan: &ReorganizationPlan,
    ) -> Result<(), Self::MutationError> {
        self.require_clean_mutation()?;
        let selected = self
            .durable
            .blocks
            .get(&self.durable.canonical_tip)
            .ok_or(InMemoryMutationError::Integrity(
                IntegrityError::CanonicalState,
            ))?
            .metadata
            .tip();
        let winning = self
            .durable
            .blocks
            .get(&plan.winning_tip)
            .ok_or(InMemoryMutationError::InvalidReorganization)?
            .metadata
            .tip();
        let expected = plan_reorganization(self, selected, winning, u64::MAX)
            .map_err(|_| InMemoryMutationError::InvalidReorganization)?;
        if &expected != plan {
            return Err(InMemoryMutationError::InvalidReorganization);
        }
        if plan.detach.is_empty() && plan.attach.is_empty() {
            return Ok(());
        }
        let mut candidate = self.durable.clone();
        apply_plan(&mut candidate, plan).map_err(InMemoryMutationError::Integrity)?;
        self.publish_candidate(candidate)
    }
}

impl RecoverableConsensusStorage for InMemoryConsensusStore {
    type RecoveryError = InMemoryMutationError;

    fn recovery_status(&self) -> RecoveryStatus {
        InMemoryConsensusStore::recovery_status(self)
    }

    fn recover(&mut self) -> Result<RecoveryOutcome, Self::RecoveryError> {
        InMemoryConsensusStore::recover(self)
    }
}

fn stored_block_from_commit(
    state: &StoreState,
    commit: ValidatedBlockCommit,
) -> Result<StoredBlock, IntegrityError> {
    let metadata = commit.header();
    let block = commit.block();
    if block.header != metadata.header() {
        return Err(IntegrityError::HeaderMismatch);
    }
    if block_id_from_header_bytes(&block.header.encode()) != metadata.block_id() {
        return Err(IntegrityError::BlockIdMismatch);
    }
    let parent = state
        .blocks
        .get(&block.header.parent_block_id)
        .ok_or(IntegrityError::MissingParent(block.header.parent_block_id))?;
    if parent.metadata.block_id() != block.header.parent_block_id
        || parent.block.header.height.checked_add(1) != Some(block.header.height)
        || commit.parent_state_root() != parent.block.header.state_root
    {
        return Err(IntegrityError::ParentMismatch);
    }
    let reencoded = block
        .encode_non_genesis()
        .map_err(|_| IntegrityError::CanonicalBytes)?;
    if reencoded != commit.canonical_block_bytes() {
        return Err(IntegrityError::CanonicalBytes);
    }
    let transaction_ids = recompute_transaction_ids(block)?;
    if transaction_ids != commit.transaction_ids() {
        return Err(IntegrityError::TransactionIds);
    }
    validate_transaction_uniqueness(state, parent.metadata.block_id(), &transaction_ids)?;

    let accounts = normalized_accounts(commit.resulting_accounts())?;
    if commit.resulting_state_root() != block.header.state_root {
        return Err(IntegrityError::StateRoot);
    }
    validate_accounts(
        &accounts,
        commit.issued_supply(),
        commit.resulting_state_root(),
    )?;
    let expected_supply = parent
        .issued_supply
        .checked_add(u128::from(subsidy_at_height(block.header.height)))
        .ok_or(IntegrityError::Supply)?;
    if expected_supply != commit.issued_supply() || commit.total_fees() > u128::from(MAX_MONEY) {
        return Err(IntegrityError::Supply);
    }
    validate_work(parent, metadata)?;
    validate_deltas(&parent.accounts, &accounts, commit.account_deltas())?;
    Ok(StoredBlock {
        canonical_bytes: commit.canonical_block_bytes().to_vec(),
        block: block.clone(),
        metadata,
        transaction_ids,
        accounts,
        account_deltas: commit.account_deltas().to_vec(),
        issued_supply: commit.issued_supply(),
        total_fees: commit.total_fees(),
    })
}

fn recompute_transaction_ids(block: &Block) -> Result<Vec<TransactionId>, IntegrityError> {
    let mut ids = Vec::with_capacity(block.body.transactions.len());
    for transaction in &block.body.transactions {
        let encoded = transaction
            .encode()
            .map_err(|_| IntegrityError::CanonicalBytes)?;
        ids.push(transaction_id_from_canonical_bytes(&encoded));
    }
    Ok(ids)
}

fn validate_transaction_uniqueness(
    state: &StoreState,
    mut parent_id: BlockId,
    transaction_ids: &[TransactionId],
) -> Result<(), IntegrityError> {
    let mut within = BTreeSet::new();
    for &transaction_id in transaction_ids {
        if !within.insert(transaction_id) {
            return Err(IntegrityError::DuplicateTransactionId(transaction_id));
        }
    }
    let regular_ids: BTreeSet<_> = transaction_ids.iter().copied().skip(1).collect();
    loop {
        let parent = state
            .blocks
            .get(&parent_id)
            .ok_or(IntegrityError::MissingParent(parent_id))?;
        for &ancestor_id in parent.transaction_ids.iter().skip(1) {
            if regular_ids.contains(&ancestor_id) {
                return Err(IntegrityError::AncestorDuplicate(ancestor_id));
            }
        }
        if parent.block.header.height == 0 {
            return Ok(());
        }
        parent_id = parent.block.header.parent_block_id;
    }
}

fn validate_work(
    parent: &StoredBlock,
    metadata: ValidatedHeaderMetadata,
) -> Result<(), IntegrityError> {
    let work = exact_block_work(metadata.header().target).map_err(|_| IntegrityError::Work)?;
    let cumulative =
        checked_cumulative_work(parent.metadata.cumulative_work(), metadata.header().target)
            .map_err(|_| IntegrityError::Work)?;
    if work != metadata.block_work() || cumulative != metadata.cumulative_work() {
        return Err(IntegrityError::Work);
    }
    Ok(())
}

fn normalized_accounts(
    accounts: &[(Recipient, Account)],
) -> Result<BTreeMap<Recipient, Account>, IntegrityError> {
    let mut output = BTreeMap::new();
    let mut previous = None;
    for &(recipient, account) in accounts {
        if previous.is_some_and(|value| value >= recipient) {
            return Err(if previous == Some(recipient) {
                IntegrityError::DuplicateAccount(recipient)
            } else {
                IntegrityError::AccountOrder
            });
        }
        if account.is_absent() {
            return Err(IntegrityError::NonNormalizedAccount(recipient));
        }
        output.insert(recipient, account);
        previous = Some(recipient);
    }
    Ok(output)
}

fn validate_accounts(
    accounts: &BTreeMap<Recipient, Account>,
    issued_supply: u128,
    expected_root: StateRoot,
) -> Result<(), IntegrityError> {
    if issued_supply > u128::from(MAX_MONEY) {
        return Err(IntegrityError::Supply);
    }
    let mut balances = 0_u128;
    let pairs: Vec<_> = accounts
        .iter()
        .map(|(&recipient, &account)| {
            balances = balances
                .checked_add(u128::from(account.balance.get()))
                .ok_or(IntegrityError::Supply)?;
            Ok((recipient, account))
        })
        .collect::<Result<_, IntegrityError>>()?;
    if balances != issued_supply || balances > u128::from(MAX_MONEY) {
        return Err(IntegrityError::Supply);
    }
    let root = compute_state_root(&pairs).map_err(|_| IntegrityError::StateRoot)?;
    if root != expected_root {
        return Err(IntegrityError::StateRoot);
    }
    Ok(())
}

fn validate_deltas(
    parent: &BTreeMap<Recipient, Account>,
    resulting: &BTreeMap<Recipient, Account>,
    deltas: &[AccountDelta],
) -> Result<(), IntegrityError> {
    let mut applied = parent.clone();
    let mut previous = None;
    for delta in deltas {
        if previous.is_some_and(|recipient| recipient >= delta.recipient) {
            return Err(IntegrityError::DeltaOrder);
        }
        let before = applied
            .get(&delta.recipient)
            .copied()
            .unwrap_or(Account::EMPTY);
        if before != delta.before {
            return Err(IntegrityError::DeltaBeforeMismatch(delta.recipient));
        }
        put_account(&mut applied, delta.recipient, delta.after);
        previous = Some(delta.recipient);
    }
    if &applied != resulting {
        return Err(IntegrityError::DeltaResultMismatch);
    }
    Ok(())
}

fn apply_plan(state: &mut StoreState, plan: &ReorganizationPlan) -> Result<(), IntegrityError> {
    let mut current = state.canonical_tip;
    for &block_id in &plan.detach {
        if block_id != current {
            return Err(IntegrityError::CanonicalHeightIndex);
        }
        let block = state
            .blocks
            .get(&block_id)
            .ok_or(IntegrityError::MissingParent(block_id))?;
        if state.canonical_by_height.get(&block.block.header.height) != Some(&block_id) {
            return Err(IntegrityError::CanonicalHeightIndex);
        }
        for delta in &block.account_deltas {
            let current_account = state
                .canonical_accounts
                .get(&delta.recipient)
                .copied()
                .unwrap_or(Account::EMPTY);
            if current_account != delta.after {
                return Err(IntegrityError::DeltaBeforeMismatch(delta.recipient));
            }
            put_account(&mut state.canonical_accounts, delta.recipient, delta.before);
        }
        for transaction_id in &block.transaction_ids {
            if state.canonical_transaction_index.get(transaction_id) == Some(&block_id) {
                state.canonical_transaction_index.remove(transaction_id);
            }
        }
        state.canonical_by_height.remove(&block.block.header.height);
        current = block.block.header.parent_block_id;
        let parent = state
            .blocks
            .get(&current)
            .ok_or(IntegrityError::MissingParent(current))?;
        state.canonical_supply = parent.issued_supply;
    }
    if current != plan.common_ancestor {
        return Err(IntegrityError::BrokenAncestry);
    }
    for &block_id in &plan.attach {
        let block = state
            .blocks
            .get(&block_id)
            .ok_or(IntegrityError::MissingParent(block_id))?;
        if block.block.header.parent_block_id != current {
            return Err(IntegrityError::BrokenAncestry);
        }
        for delta in &block.account_deltas {
            let current_account = state
                .canonical_accounts
                .get(&delta.recipient)
                .copied()
                .unwrap_or(Account::EMPTY);
            if current_account != delta.before {
                return Err(IntegrityError::DeltaBeforeMismatch(delta.recipient));
            }
            put_account(&mut state.canonical_accounts, delta.recipient, delta.after);
        }
        for &transaction_id in &block.transaction_ids {
            if state
                .canonical_transaction_index
                .insert(transaction_id, block_id)
                .is_some()
            {
                return Err(IntegrityError::CanonicalTransactionIndex);
            }
        }
        if state
            .canonical_by_height
            .insert(block.block.header.height, block_id)
            .is_some()
        {
            return Err(IntegrityError::CanonicalHeightIndex);
        }
        state.canonical_supply = block.issued_supply;
        current = block_id;
    }
    if current != plan.winning_tip {
        return Err(IntegrityError::BrokenAncestry);
    }
    let winning = state
        .blocks
        .get(&current)
        .ok_or(IntegrityError::MissingParent(current))?;
    if state.canonical_accounts != winning.accounts
        || state.canonical_supply != winning.issued_supply
    {
        return Err(IntegrityError::CanonicalState);
    }
    state.canonical_tip = current;
    Ok(())
}

fn put_account(
    accounts: &mut BTreeMap<Recipient, Account>,
    recipient: Recipient,
    account: Account,
) {
    if account.is_absent() {
        accounts.remove(&recipient);
    } else {
        accounts.insert(recipient, account);
    }
}

fn validate_store_state(state: &StoreState) -> Result<(), IntegrityError> {
    let tip = state
        .blocks
        .get(&state.canonical_tip)
        .ok_or(IntegrityError::CanonicalState)?;
    if tip.accounts != state.canonical_accounts || tip.issued_supply != state.canonical_supply {
        return Err(IntegrityError::CanonicalState);
    }
    for (&block_id, block) in &state.blocks {
        if block.metadata.block_id() != block_id
            || block.metadata.header() != block.block.header
            || block_id_from_header_bytes(&block.block.header.encode()) != block_id
        {
            return Err(IntegrityError::BlockIdMismatch);
        }
        let encoded = if block.block.header.height == 0 {
            block.block.encode_genesis()
        } else {
            block.block.encode_non_genesis()
        }
        .map_err(|_| IntegrityError::CanonicalBytes)?;
        if encoded != block.canonical_bytes {
            return Err(IntegrityError::CanonicalBytes);
        }
        if recompute_transaction_ids(&block.block)? != block.transaction_ids {
            return Err(IntegrityError::TransactionIds);
        }
        validate_accounts(
            &block.accounts,
            block.issued_supply,
            block.block.header.state_root,
        )?;
        if block.block.header.height == 0 {
            if block.block.header.parent_block_id != BlockId::new([0; 32])
                || !block.transaction_ids.is_empty()
                || !block.account_deltas.is_empty()
                || block.total_fees != 0
                || block.metadata.cumulative_work() != block.metadata.block_work()
            {
                return Err(IntegrityError::GenesisStructure);
            }
        } else {
            let parent = state
                .blocks
                .get(&block.block.header.parent_block_id)
                .ok_or(IntegrityError::MissingParent(
                    block.block.header.parent_block_id,
                ))?;
            validate_work(parent, block.metadata)?;
            validate_deltas(&parent.accounts, &block.accounts, &block.account_deltas)?;
            let expected_supply = parent
                .issued_supply
                .checked_add(u128::from(subsidy_at_height(block.block.header.height)))
                .ok_or(IntegrityError::Supply)?;
            if expected_supply != block.issued_supply || block.total_fees > u128::from(MAX_MONEY) {
                return Err(IntegrityError::Supply);
            }
            validate_transaction_uniqueness(
                state,
                parent.metadata.block_id(),
                &block.transaction_ids,
            )?;
        }
    }

    let mut expected_heights = BTreeMap::new();
    let mut expected_transactions = BTreeMap::new();
    let mut current = tip;
    loop {
        expected_heights.insert(current.block.header.height, current.metadata.block_id());
        for &transaction_id in &current.transaction_ids {
            if expected_transactions
                .insert(transaction_id, current.metadata.block_id())
                .is_some()
            {
                return Err(IntegrityError::CanonicalTransactionIndex);
            }
        }
        if current.block.header.height == 0 {
            break;
        }
        current = state
            .blocks
            .get(&current.block.header.parent_block_id)
            .ok_or(IntegrityError::BrokenAncestry)?;
    }
    if expected_heights != state.canonical_by_height {
        return Err(IntegrityError::CanonicalHeightIndex);
    }
    if expected_transactions != state.canonical_transaction_index {
        return Err(IntegrityError::CanonicalTransactionIndex);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use out_codec::{Block, BlockBody, BlockHeader, RewardTransaction, Transaction};
    use out_consensus::block::{validate_non_genesis_block, BlockValidationParameters};
    use out_consensus::chain::{
        validate_pinned_genesis_header, HeaderChainParameters, ValidatedHeaderView,
    };
    use out_consensus::{
        pow_hash_from_header_bytes, pow_hash_meets_target, transaction_id_from_canonical_bytes,
        transaction_merkle_root, DEVNET_POW_LIMIT_V0,
    };
    use out_primitives::{Amount, BlockId};

    use super::*;

    const VECTOR_REWARD_HEX: &str = "0001000000810000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000010003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8000000001dcd650000000000000003e800000000";
    const VECTOR_HEADER_HEX: &str = "000000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a937280000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda2fb959f81d652879472f8c56076e63a2fb3587dda94754f316328e7ec431403d30a2588a2f688edd9b29af2bb3b522db2deb731709dbfb53fadefab69c21470000000000000ac5";

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

    fn mine(mut header: BlockHeader) -> BlockHeader {
        header.nonce = 0;
        loop {
            if pow_hash_meets_target(pow_hash_from_header_bytes(&header.encode()), header.target) {
                return header;
            }
            header.nonce = header.nonce.checked_add(1).expect("test nonce space");
        }
    }

    fn new_store() -> InMemoryConsensusStore {
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
        InMemoryConsensusStore::new(genesis, metadata, &[], 0).expect("genesis store")
    }

    fn reward_commit(
        store: &InMemoryConsensusStore,
        parent_id: BlockId,
        extra: &[u8],
    ) -> ValidatedBlockCommit {
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

        let mut reward =
            RewardTransaction::decode_exact(&hex(VECTOR_REWARD_HEX)).expect("reward vector");
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
            .expect("test reward balance");
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

    fn store_block(store: &mut InMemoryConsensusStore, commit: ValidatedBlockCommit) -> BlockId {
        let block_id = commit.header().block_id();
        store.store_validated_block(commit).expect("stored block");
        block_id
    }

    fn canonicalize_best(store: &mut InMemoryConsensusStore) -> ReorganizationPlan {
        let plan = store
            .plan_best_reorganization(100)
            .expect("reorganization plan");
        store.apply_reorganization(&plan).expect("reorganization");
        plan
    }

    #[test]
    fn validated_commit_is_inert_until_canonical_reorganization() {
        let mut store = new_store();
        let genesis = store.canonical_tip().expect("tip").block_id;
        let commit = reward_commit(&store, genesis, b"a1");
        let block_id = store_block(&mut store, commit);

        assert_eq!(store.contains_block(block_id), Ok(true));
        assert_eq!(store.canonical_tip().expect("tip").block_id, genesis);
        assert_eq!(store.canonical_block_id(1), Ok(None));

        let plan = canonicalize_best(&mut store);
        assert!(plan.detach.is_empty());
        assert_eq!(plan.attach, vec![block_id]);
        assert_eq!(store.canonical_tip().expect("tip").block_id, block_id);
        assert_eq!(store.canonical_block_id(1), Ok(Some(block_id)));

        let snapshot = store
            .parent_state_snapshot(block_id)
            .expect("read")
            .expect("snapshot");
        assert_eq!(snapshot.issued_supply, 500_000_000);
        assert_eq!(snapshot.accounts.len(), 1);
        assert_eq!(snapshot.accounts[0].1.balance.get(), 500_000_000);
    }

    #[test]
    fn fork_reorganization_rolls_back_then_applies_forward() {
        let mut store = new_store();
        let genesis = store.canonical_tip().expect("tip").block_id;
        let a1_commit = reward_commit(&store, genesis, b"a1");
        let a1 = store_block(&mut store, a1_commit);
        canonicalize_best(&mut store);

        let b1_commit = reward_commit(&store, genesis, b"b1");
        let b1 = store_block(&mut store, b1_commit);
        let b2_commit = reward_commit(&store, b1, b"b2");
        let b2 = store_block(&mut store, b2_commit);
        let plan = store
            .plan_best_reorganization(100)
            .expect("fork reorganization plan");
        assert_eq!(plan.common_ancestor, genesis);
        assert_eq!(plan.detach, vec![a1]);
        assert_eq!(plan.attach, vec![b1, b2]);

        store
            .apply_reorganization(&plan)
            .expect("fork reorganization");
        assert_eq!(store.canonical_tip().expect("tip").block_id, b2);
        assert_eq!(store.canonical_block_id(0), Ok(Some(genesis)));
        assert_eq!(store.canonical_block_id(1), Ok(Some(b1)));
        assert_eq!(store.canonical_block_id(2), Ok(Some(b2)));
        let snapshot = store
            .parent_state_snapshot(b2)
            .expect("read")
            .expect("snapshot");
        assert_eq!(snapshot.issued_supply, 1_000_000_000);
        assert_eq!(snapshot.accounts[0].1.balance.get(), 1_000_000_000);
    }

    #[test]
    fn prepared_store_fault_requires_recovery_and_rolls_back() {
        let mut store = new_store();
        let genesis = store.canonical_tip().expect("tip").block_id;
        let commit = reward_commit(&store, genesis, b"prepared");
        let block_id = commit.header().block_id();
        store
            .inject_fault_once(FaultPoint::AfterPrepare)
            .expect("fault configured");

        assert_eq!(
            store.store_validated_block(commit),
            Err(InMemoryMutationError::FaultInjected(
                FaultPoint::AfterPrepare
            ))
        );
        assert_eq!(store.recovery_status(), RecoveryStatus::Prepared);
        assert_eq!(
            store.canonical_tip(),
            Err(InMemoryReadError::RecoveryRequired)
        );
        assert_eq!(
            store.contains_block(block_id),
            Err(InMemoryReadError::RecoveryRequired)
        );
        assert_eq!(store.recover(), Ok(RecoveryOutcome::RolledBackPrepared));
        assert_eq!(store.recovery_status(), RecoveryStatus::Clean);
        assert_eq!(store.contains_block(block_id), Ok(false));
        assert_eq!(store.canonical_tip().expect("tip").block_id, genesis);
    }

    #[test]
    fn published_store_fault_requires_recovery_and_finalizes() {
        let mut store = new_store();
        let genesis = store.canonical_tip().expect("tip").block_id;
        let commit = reward_commit(&store, genesis, b"published");
        let block_id = commit.header().block_id();
        store
            .inject_fault_once(FaultPoint::AfterPublish)
            .expect("fault configured");

        assert_eq!(
            store.store_validated_block(commit),
            Err(InMemoryMutationError::FaultInjected(
                FaultPoint::AfterPublish
            ))
        );
        assert_eq!(store.recovery_status(), RecoveryStatus::Published);
        assert_eq!(
            store.contains_block(block_id),
            Err(InMemoryReadError::RecoveryRequired)
        );
        assert_eq!(store.recover(), Ok(RecoveryOutcome::FinalizedPublished));
        assert_eq!(store.contains_block(block_id), Ok(true));
        assert_eq!(store.canonical_tip().expect("tip").block_id, genesis);
    }

    #[test]
    fn pre_prepare_fault_leaves_store_clean() {
        let mut store = new_store();
        let genesis = store.canonical_tip().expect("tip").block_id;
        let commit = reward_commit(&store, genesis, b"before");
        let block_id = commit.header().block_id();
        store
            .inject_fault_once(FaultPoint::BeforePrepare)
            .expect("fault configured");
        assert_eq!(
            store.store_validated_block(commit),
            Err(InMemoryMutationError::FaultInjected(
                FaultPoint::BeforePrepare
            ))
        );
        assert_eq!(store.recovery_status(), RecoveryStatus::Clean);
        assert_eq!(store.contains_block(block_id), Ok(false));
        assert_eq!(store.recover(), Ok(RecoveryOutcome::AlreadyClean));
    }

    #[test]
    fn reorganization_faults_never_expose_a_mixed_branch() {
        let mut store = new_store();
        let genesis = store.canonical_tip().expect("tip").block_id;
        let a1_commit = reward_commit(&store, genesis, b"a1");
        let a1 = store_block(&mut store, a1_commit);
        canonicalize_best(&mut store);
        let b1_commit = reward_commit(&store, genesis, b"b1");
        let b1 = store_block(&mut store, b1_commit);
        let b2_commit = reward_commit(&store, b1, b"b2");
        let b2 = store_block(&mut store, b2_commit);
        let plan = store.plan_best_reorganization(100).expect("plan");

        store
            .inject_fault_once(FaultPoint::AfterPrepare)
            .expect("fault configured");
        assert_eq!(
            store.apply_reorganization(&plan),
            Err(InMemoryMutationError::FaultInjected(
                FaultPoint::AfterPrepare
            ))
        );
        assert_eq!(
            store.canonical_block_id(1),
            Err(InMemoryReadError::RecoveryRequired)
        );
        assert_eq!(store.recover(), Ok(RecoveryOutcome::RolledBackPrepared));
        assert_eq!(store.canonical_tip().expect("tip").block_id, a1);
        assert_eq!(store.canonical_block_id(1), Ok(Some(a1)));
        assert_eq!(store.canonical_block_id(2), Ok(None));

        store
            .inject_fault_once(FaultPoint::AfterPublish)
            .expect("fault configured");
        assert_eq!(
            store.apply_reorganization(&plan),
            Err(InMemoryMutationError::FaultInjected(
                FaultPoint::AfterPublish
            ))
        );
        assert_eq!(
            store.canonical_tip(),
            Err(InMemoryReadError::RecoveryRequired)
        );
        assert_eq!(store.recover(), Ok(RecoveryOutcome::FinalizedPublished));
        assert_eq!(store.canonical_tip().expect("tip").block_id, b2);
        assert_eq!(store.canonical_block_id(1), Ok(Some(b1)));
        assert_eq!(store.canonical_block_id(2), Ok(Some(b2)));
    }

    #[test]
    fn noncanonical_branch_snapshots_are_branch_local() {
        let mut store = new_store();
        let genesis = store.canonical_tip().expect("tip").block_id;
        let a1_commit = reward_commit(&store, genesis, b"a1");
        let a1 = store_block(&mut store, a1_commit);
        canonicalize_best(&mut store);
        let b1_commit = reward_commit(&store, genesis, b"b1");
        let b1 = store_block(&mut store, b1_commit);

        assert_eq!(store.canonical_tip().expect("tip").block_id, a1);
        let branch_state = store
            .parent_state_snapshot(b1)
            .expect("read")
            .expect("branch state");
        assert_eq!(branch_state.anchor_block_id, b1);
        assert_eq!(branch_state.issued_supply, 500_000_000);
        let ancestry = store
            .ancestor_transaction_snapshot(b1)
            .expect("read")
            .expect("branch ancestry");
        assert_eq!(ancestry.anchor_block_id, b1);
        assert!(ancestry.confirmed_transaction_ids.is_empty());
    }

    #[test]
    fn in_memory_backend_passes_reusable_core_conformance() {
        crate::conformance::assert_consensus_storage_conformance(|genesis, metadata| {
            InMemoryConsensusStore::new(genesis, metadata, &[], 0)
        });
    }

    #[test]
    fn in_memory_backend_passes_reusable_recovery_conformance() {
        crate::conformance::assert_recovery_conformance(|genesis, metadata| {
            InMemoryConsensusStore::new(genesis, metadata, &[], 0)
        });
    }
}
