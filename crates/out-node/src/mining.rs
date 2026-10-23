//! Deterministic testnet/devnet candidate construction and bounded CPU PoW.
//!
//! This module is non-authoritative. It composes frozen consensus routines to
//! construct work candidates, and a solved block still requires ordinary full
//! block validation and atomic storage before it can affect chain state.

use std::collections::{BTreeMap, BTreeSet};

use out_codec::{
    Block, BlockBody, BlockHeader, EncodeError, RegularTransaction, RewardBody, RewardTransaction,
    Transaction, MAX_BLOCK_BODY_BYTES, MAX_REWARD_EXTRA_BYTES, MAX_TXS_PER_BLOCK,
};
use out_consensus::chain::{
    prepare_child_header, ChainTip, ChildHeaderValidationFailure, PreparedChildHeader,
};
use out_consensus::{
    block_id_from_header_bytes, pow_hash_from_header_bytes, pow_hash_meets_target,
    transaction_merkle_root, validate_and_apply_regular_transaction,
    validate_and_apply_reward_transaction, MerkleError, RegularValidationContext,
    RegularValidationFailure, RewardValidationContext, RewardValidationFailure,
};
use out_primitives::{Amount, BlockId, Hash32, Recipient, StateRoot, TransactionId, MAX_MONEY};
use out_state::{compute_state_root, subsidy_at_height, Account, StateTreeError};
use out_storage::ConsensusStorage;

use crate::mempool::{Mempool, MempoolError};
use crate::SupportedNetwork;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRequest {
    pub timestamp: u64,
    pub local_now: u64,
    pub reward_recipient: Recipient,
    pub reward_extra: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateBuildError<E> {
    RewardExtraTooLarge {
        actual: usize,
        maximum: u16,
    },
    MempoolNetworkMismatch {
        expected: SupportedNetwork,
        actual: SupportedNetwork,
    },
    Mempool(MempoolError<E>),
    Store(E),
    Header(ChildHeaderValidationFailure<E>),
    TipChanged(Box<(ChainTip, ChainTip)>),
    MissingParentState(BlockId),
    ParentStateAnchorMismatch {
        expected: BlockId,
        actual: BlockId,
    },
    MissingAncestorHistory(BlockId),
    AncestorHistoryAnchorMismatch {
        expected: BlockId,
        actual: BlockId,
    },
    DuplicateParentAccount(Recipient),
    ParentBalanceAboveMaximum {
        recipient: Recipient,
        balance: u64,
    },
    ParentSupplyAboveMaximum(u128),
    ParentBalanceOverflow,
    ParentSupplyMismatch {
        expected: u128,
        actual: u128,
    },
    ParentStateTree(StateTreeError),
    ParentStateRootMismatch {
        expected: StateRoot,
        actual: StateRoot,
    },
    CanonicalEncoding(EncodeError),
    BodySizeArithmetic,
    ConfirmedTransaction(TransactionId),
    DuplicateTransaction(TransactionId),
    Regular {
        transaction_id: TransactionId,
        failure: RegularValidationFailure,
    },
    FeeWidth(u128),
    Reward(RewardValidationFailure),
    ResultingBalanceOverflow,
    ResultingSupplyMismatch {
        expected: u128,
        actual: u128,
    },
    ResultingStateTree(StateTreeError),
    Merkle(MerkleError),
    CountWidth,
    InternalInvariant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningCandidate {
    block: Block,
    parent_tip: ChainTip,
    selected_regular_transactions: u16,
    deferred_transactions: u16,
    transaction_ids: Vec<TransactionId>,
    total_fees: u128,
    issued_supply: u128,
    mempool_revision: u64,
}

impl MiningCandidate {
    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub const fn parent_tip(&self) -> ChainTip {
        self.parent_tip
    }

    pub const fn selected_regular_transactions(&self) -> u16 {
        self.selected_regular_transactions
    }

    pub const fn deferred_transactions(&self) -> u16 {
        self.deferred_transactions
    }

    pub fn transaction_ids(&self) -> &[TransactionId] {
        &self.transaction_ids
    }

    pub const fn total_fees(&self) -> u128 {
        self.total_fees
    }

    pub const fn issued_supply(&self) -> u128 {
        self.issued_supply
    }

    pub const fn mempool_revision(&self) -> u64 {
        self.mempool_revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuMiningPolicy {
    pub maximum_nonce_attempts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuMiningPolicyError {
    ZeroMaximumNonceAttempts,
    AttemptAccountingOverflow,
}

impl CpuMiningPolicy {
    pub const fn validate(self) -> Result<Self, CpuMiningPolicyError> {
        if self.maximum_nonce_attempts == 0 {
            return Err(CpuMiningPolicyError::ZeroMaximumNonceAttempts);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinedBlock {
    pub block: Block,
    pub block_id: BlockId,
    pub pow_hash: Hash32,
    pub attempts: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CpuMiningOutcome {
    Solved(Box<MinedBlock>),
    BudgetExhausted { attempts: u64, next_nonce: u64 },
    NonceSpaceExhausted { attempts: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningJobSnapshot {
    pub parent_tip: ChainTip,
    pub height: u64,
    pub mempool_revision: u64,
    pub next_nonce: u64,
    pub total_attempts: u128,
    pub solution_block_id: Option<BlockId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MiningStaleReason {
    CanonicalTipChanged(Box<(ChainTip, ChainTip)>),
    MempoolChanged { expected: u64, actual: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MiningWorkOutcome {
    Idle,
    Stale(MiningStaleReason),
    Progress {
        attempts: u64,
        total_attempts: u128,
        next_nonce: u64,
    },
    SolutionFound {
        attempts: u64,
        total_attempts: u128,
        block_id: BlockId,
    },
    SolutionPending {
        total_attempts: u128,
        block_id: BlockId,
    },
    NonceSpaceExhausted {
        attempts: u64,
        total_attempts: u128,
    },
}

struct MiningJob {
    candidate: MiningCandidate,
    next_nonce: u64,
    total_attempts: u128,
    solution: Option<Box<MinedBlock>>,
}

pub struct MiningCoordinator {
    policy: CpuMiningPolicy,
    job: Option<MiningJob>,
}

impl MiningCoordinator {
    pub fn new(policy: CpuMiningPolicy) -> Result<Self, CpuMiningPolicyError> {
        Ok(Self {
            policy: policy.validate()?,
            job: None,
        })
    }

    pub const fn policy(&self) -> CpuMiningPolicy {
        self.policy
    }

    pub fn start(&mut self, candidate: MiningCandidate, first_nonce: u64) -> bool {
        let replaced = self.job.is_some();
        self.job = Some(MiningJob {
            candidate,
            next_nonce: first_nonce,
            total_attempts: 0,
            solution: None,
        });
        replaced
    }

    pub fn snapshot(&self) -> Option<MiningJobSnapshot> {
        self.job.as_ref().map(MiningJob::snapshot)
    }

    pub fn cancel(&mut self) -> Option<MiningJobSnapshot> {
        self.job.take().map(|job| job.snapshot())
    }

    pub fn solution(&self) -> Option<&MinedBlock> {
        self.job.as_ref().and_then(|job| job.solution.as_deref())
    }

    pub fn complete_solution(&mut self) -> Option<MiningJobSnapshot> {
        self.solution()?;
        self.cancel()
    }

    pub fn step(
        &mut self,
        canonical_tip: ChainTip,
        mempool_revision: u64,
    ) -> Result<MiningWorkOutcome, CpuMiningPolicyError> {
        let Some(job) = self.job.as_mut() else {
            return Ok(MiningWorkOutcome::Idle);
        };
        if canonical_tip != job.candidate.parent_tip() {
            let expected = job.candidate.parent_tip();
            self.job = None;
            return Ok(MiningWorkOutcome::Stale(
                MiningStaleReason::CanonicalTipChanged(Box::new((expected, canonical_tip))),
            ));
        }
        if mempool_revision != job.candidate.mempool_revision() {
            let expected = job.candidate.mempool_revision();
            self.job = None;
            return Ok(MiningWorkOutcome::Stale(
                MiningStaleReason::MempoolChanged {
                    expected,
                    actual: mempool_revision,
                },
            ));
        }
        if let Some(solution) = &job.solution {
            return Ok(MiningWorkOutcome::SolutionPending {
                total_attempts: job.total_attempts,
                block_id: solution.block_id,
            });
        }
        match mine_cpu(&job.candidate, job.next_nonce, self.policy)? {
            CpuMiningOutcome::Solved(solution) => {
                job.total_attempts = job
                    .total_attempts
                    .checked_add(u128::from(solution.attempts))
                    .ok_or(CpuMiningPolicyError::AttemptAccountingOverflow)?;
                let outcome = MiningWorkOutcome::SolutionFound {
                    attempts: solution.attempts,
                    total_attempts: job.total_attempts,
                    block_id: solution.block_id,
                };
                job.solution = Some(solution);
                Ok(outcome)
            }
            CpuMiningOutcome::BudgetExhausted {
                attempts,
                next_nonce,
            } => {
                job.total_attempts = job
                    .total_attempts
                    .checked_add(u128::from(attempts))
                    .ok_or(CpuMiningPolicyError::AttemptAccountingOverflow)?;
                job.next_nonce = next_nonce;
                Ok(MiningWorkOutcome::Progress {
                    attempts,
                    total_attempts: job.total_attempts,
                    next_nonce,
                })
            }
            CpuMiningOutcome::NonceSpaceExhausted { attempts } => {
                let total_attempts = job
                    .total_attempts
                    .checked_add(u128::from(attempts))
                    .ok_or(CpuMiningPolicyError::AttemptAccountingOverflow)?;
                self.job = None;
                Ok(MiningWorkOutcome::NonceSpaceExhausted {
                    attempts,
                    total_attempts,
                })
            }
        }
    }
}

impl MiningJob {
    fn snapshot(&self) -> MiningJobSnapshot {
        MiningJobSnapshot {
            parent_tip: self.candidate.parent_tip(),
            height: self.candidate.block().header.height,
            mempool_revision: self.candidate.mempool_revision(),
            next_nonce: self.next_nonce,
            total_attempts: self.total_attempts,
            solution_block_id: self.solution.as_ref().map(|solution| solution.block_id),
        }
    }
}

pub fn build_candidate<S: ConsensusStorage>(
    storage: &S,
    mempool: &mut Mempool,
    network: SupportedNetwork,
    request: CandidateRequest,
) -> Result<MiningCandidate, CandidateBuildError<S::Error>> {
    if request.reward_extra.len() > usize::from(MAX_REWARD_EXTRA_BYTES) {
        return Err(CandidateBuildError::RewardExtraTooLarge {
            actual: request.reward_extra.len(),
            maximum: MAX_REWARD_EXTRA_BYTES,
        });
    }
    if mempool.network() != network {
        return Err(CandidateBuildError::MempoolNetworkMismatch {
            expected: network,
            actual: mempool.network(),
        });
    }
    mempool
        .reconcile_if_needed(storage)
        .map_err(CandidateBuildError::Mempool)?;
    let parent_tip = storage
        .canonical_tip()
        .map_err(CandidateBuildError::Store)?;
    let parameters = network.validation_parameters();
    let prepared = prepare_child_header(
        parent_tip.block_id,
        request.timestamp,
        storage,
        request.local_now,
        parameters.header,
    )
    .map_err(CandidateBuildError::Header)?;
    if prepared.parent.tip() != parent_tip {
        return Err(CandidateBuildError::TipChanged(Box::new((
            parent_tip,
            prepared.parent.tip(),
        ))));
    }

    let selected = select_regular_transactions(
        mempool.template(),
        prepared,
        network,
        request.reward_recipient,
        &request.reward_extra,
    )?;
    let state = storage
        .parent_state_snapshot(parent_tip.block_id)
        .map_err(CandidateBuildError::Store)?
        .ok_or(CandidateBuildError::MissingParentState(parent_tip.block_id))?;
    if state.anchor_block_id != parent_tip.block_id {
        return Err(CandidateBuildError::ParentStateAnchorMismatch {
            expected: parent_tip.block_id,
            actual: state.anchor_block_id,
        });
    }
    let history = storage
        .ancestor_transaction_snapshot(parent_tip.block_id)
        .map_err(CandidateBuildError::Store)?
        .ok_or(CandidateBuildError::MissingAncestorHistory(
            parent_tip.block_id,
        ))?;
    if history.anchor_block_id != parent_tip.block_id {
        return Err(CandidateBuildError::AncestorHistoryAnchorMismatch {
            expected: parent_tip.block_id,
            actual: history.anchor_block_id,
        });
    }

    let mut accounts = verify_parent_accounts(
        &state.accounts,
        state.issued_supply,
        prepared.parent.header().state_root,
    )?;
    let regular_context = RegularValidationContext {
        network: network.identity(),
        block_height: prepared.height,
        active_tx_version: parameters.active_transaction_version,
        minimum_fee: parameters.minimum_fee,
    };
    let mut total_fees = 0_u128;
    let mut regular_ids = Vec::with_capacity(selected.len());
    let mut seen = BTreeSet::new();
    for transaction in &selected {
        let raw = transaction
            .encode()
            .map_err(CandidateBuildError::CanonicalEncoding)?;
        let transaction_id = out_consensus::transaction_id_from_canonical_bytes(&raw);
        if history.confirmed_transaction_ids.contains(&transaction_id) {
            return Err(CandidateBuildError::ConfirmedTransaction(transaction_id));
        }
        if !seen.insert(transaction_id) {
            return Err(CandidateBuildError::DuplicateTransaction(transaction_id));
        }
        let sender_before = account_or_empty(&accounts, transaction.body.sender);
        let recipient_before = account_or_empty(&accounts, transaction.body.recipient);
        let applied = validate_and_apply_regular_transaction(
            &raw,
            regular_context,
            sender_before,
            recipient_before,
            total_fees,
        )
        .map_err(|failure| CandidateBuildError::Regular {
            transaction_id,
            failure,
        })?;
        if applied.authenticated.transaction_id != transaction_id {
            return Err(CandidateBuildError::InternalInvariant);
        }
        for change in applied.outcome.changes {
            put_normalized_account(&mut accounts, change.recipient, change.account);
        }
        total_fees = applied.outcome.fee_total;
        regular_ids.push(transaction_id);
    }

    let fee_u64 =
        u64::try_from(total_fees).map_err(|_| CandidateBuildError::FeeWidth(total_fees))?;
    let identity = network.identity();
    let reward = RewardTransaction {
        body: RewardBody {
            tx_version: parameters.active_transaction_version,
            chain_id: identity.chain_id,
            network_id: identity.network_id,
            genesis_commitment: identity.genesis_commitment,
            height: prepared.height,
            recipient: request.reward_recipient,
            subsidy: Amount::new(subsidy_at_height(prepared.height)),
            fees: Amount::new(fee_u64),
            extra: request.reward_extra,
        },
    };
    let reward_before = account_or_empty(&accounts, reward.body.recipient);
    let applied_reward = validate_and_apply_reward_transaction(
        &reward,
        RewardValidationContext {
            network: identity,
            block_height: prepared.height,
            active_tx_version: parameters.active_transaction_version,
        },
        reward_before,
        total_fees,
        state.issued_supply,
    )
    .map_err(CandidateBuildError::Reward)?;
    put_normalized_account(
        &mut accounts,
        reward.body.recipient,
        applied_reward.outcome.account,
    );
    let actual_supply =
        checked_balance_sum(&accounts).ok_or(CandidateBuildError::ResultingBalanceOverflow)?;
    if actual_supply != applied_reward.outcome.issued_supply {
        return Err(CandidateBuildError::ResultingSupplyMismatch {
            expected: applied_reward.outcome.issued_supply,
            actual: actual_supply,
        });
    }
    let account_pairs: Vec<_> = accounts
        .iter()
        .map(|(&recipient, &account)| (recipient, account))
        .collect();
    let state_root =
        compute_state_root(&account_pairs).map_err(CandidateBuildError::ResultingStateTree)?;

    let mut transaction_ids = Vec::with_capacity(regular_ids.len().saturating_add(1));
    transaction_ids.push(applied_reward.transaction_id);
    transaction_ids.extend(regular_ids);
    let transaction_root =
        transaction_merkle_root(&transaction_ids).map_err(CandidateBuildError::Merkle)?;
    let mut transactions = Vec::with_capacity(selected.len().saturating_add(1));
    transactions.push(Transaction::Reward(reward));
    transactions.extend(selected.into_iter().map(Transaction::Regular));
    let block = Block {
        header: BlockHeader {
            consensus_version: parameters.header.active_consensus_version,
            chain_id: identity.chain_id,
            network_id: identity.network_id,
            genesis_commitment: identity.genesis_commitment,
            height: prepared.height,
            parent_block_id: parent_tip.block_id,
            timestamp: request.timestamp,
            target: prepared.required_target,
            transaction_root,
            state_root,
            nonce: 0,
        },
        body: BlockBody { transactions },
    };
    block
        .encode_non_genesis()
        .map_err(CandidateBuildError::CanonicalEncoding)?;
    let selected_regular_transactions = u16::try_from(block.body.transactions.len() - 1)
        .map_err(|_| CandidateBuildError::CountWidth)?;
    let deferred = mempool
        .transaction_count()
        .checked_sub(usize::from(selected_regular_transactions))
        .ok_or(CandidateBuildError::InternalInvariant)?;
    let deferred_transactions =
        u16::try_from(deferred).map_err(|_| CandidateBuildError::CountWidth)?;
    let final_tip = storage
        .canonical_tip()
        .map_err(CandidateBuildError::Store)?;
    if final_tip != parent_tip {
        return Err(CandidateBuildError::TipChanged(Box::new((
            parent_tip, final_tip,
        ))));
    }
    Ok(MiningCandidate {
        block,
        parent_tip,
        selected_regular_transactions,
        deferred_transactions,
        transaction_ids,
        total_fees,
        issued_supply: applied_reward.outcome.issued_supply,
        mempool_revision: mempool.revision(),
    })
}

pub fn mine_cpu(
    candidate: &MiningCandidate,
    first_nonce: u64,
    policy: CpuMiningPolicy,
) -> Result<CpuMiningOutcome, CpuMiningPolicyError> {
    let policy = policy.validate()?;
    let mut nonce = first_nonce;
    let mut attempts = 0_u64;
    loop {
        let mut header = candidate.block.header;
        header.nonce = nonce;
        let header_bytes = header.encode();
        let pow_hash = pow_hash_from_header_bytes(&header_bytes);
        let Some(next_attempts) = attempts.checked_add(1) else {
            return Ok(CpuMiningOutcome::NonceSpaceExhausted { attempts });
        };
        attempts = next_attempts;
        if pow_hash_meets_target(pow_hash, header.target) {
            let mut block = candidate.block.clone();
            block.header = header;
            return Ok(CpuMiningOutcome::Solved(Box::new(MinedBlock {
                block,
                block_id: block_id_from_header_bytes(&header_bytes),
                pow_hash,
                attempts,
            })));
        }
        if attempts == policy.maximum_nonce_attempts {
            return match nonce.checked_add(1) {
                Some(next_nonce) => Ok(CpuMiningOutcome::BudgetExhausted {
                    attempts,
                    next_nonce,
                }),
                None => Ok(CpuMiningOutcome::NonceSpaceExhausted { attempts }),
            };
        }
        let Some(next_nonce) = nonce.checked_add(1) else {
            return Ok(CpuMiningOutcome::NonceSpaceExhausted { attempts });
        };
        nonce = next_nonce;
    }
}

fn select_regular_transactions<E>(
    offered: Vec<RegularTransaction>,
    prepared: PreparedChildHeader,
    network: SupportedNetwork,
    reward_recipient: Recipient,
    reward_extra: &[u8],
) -> Result<Vec<RegularTransaction>, CandidateBuildError<E>> {
    let identity = network.identity();
    let reward = RewardTransaction {
        body: RewardBody {
            tx_version: network.validation_parameters().active_transaction_version,
            chain_id: identity.chain_id,
            network_id: identity.network_id,
            genesis_commitment: identity.genesis_commitment,
            height: prepared.height,
            recipient: reward_recipient,
            subsidy: Amount::new(subsidy_at_height(prepared.height)),
            fees: Amount::ZERO,
            extra: reward_extra.to_vec(),
        },
    };
    let reward_length = reward
        .encode()
        .map_err(CandidateBuildError::CanonicalEncoding)?
        .len();
    let maximum_body = usize::try_from(MAX_BLOCK_BODY_BYTES)
        .map_err(|_| CandidateBuildError::BodySizeArithmetic)?;
    let maximum_transactions =
        usize::try_from(MAX_TXS_PER_BLOCK).map_err(|_| CandidateBuildError::BodySizeArithmetic)?;
    let mut body_length = 5_usize
        .checked_add(4)
        .and_then(|length| length.checked_add(reward_length))
        .ok_or(CandidateBuildError::BodySizeArithmetic)?;
    let mut selected = Vec::new();
    for transaction in offered {
        if selected.len().saturating_add(1) >= maximum_transactions {
            break;
        }
        let encoded = transaction
            .encode()
            .map_err(CandidateBuildError::CanonicalEncoding)?;
        let next_length = body_length
            .checked_add(4)
            .and_then(|length| length.checked_add(encoded.len()))
            .ok_or(CandidateBuildError::BodySizeArithmetic)?;
        if next_length > maximum_body {
            break;
        }
        body_length = next_length;
        selected.push(transaction);
    }
    Ok(selected)
}

fn verify_parent_accounts<E>(
    pairs: &[(Recipient, Account)],
    issued_supply: u128,
    expected_root: StateRoot,
) -> Result<BTreeMap<Recipient, Account>, CandidateBuildError<E>> {
    if issued_supply > u128::from(MAX_MONEY) {
        return Err(CandidateBuildError::ParentSupplyAboveMaximum(issued_supply));
    }
    let mut accounts = BTreeMap::new();
    let mut balances = 0_u128;
    for &(recipient, account) in pairs {
        if account.balance.get() > MAX_MONEY {
            return Err(CandidateBuildError::ParentBalanceAboveMaximum {
                recipient,
                balance: account.balance.get(),
            });
        }
        if accounts.insert(recipient, account).is_some() {
            return Err(CandidateBuildError::DuplicateParentAccount(recipient));
        }
        balances = balances
            .checked_add(u128::from(account.balance.get()))
            .ok_or(CandidateBuildError::ParentBalanceOverflow)?;
    }
    if balances != issued_supply {
        return Err(CandidateBuildError::ParentSupplyMismatch {
            expected: issued_supply,
            actual: balances,
        });
    }
    accounts.retain(|_, account| !account.is_absent());
    let normalized: Vec<_> = accounts
        .iter()
        .map(|(&recipient, &account)| (recipient, account))
        .collect();
    let actual_root =
        compute_state_root(&normalized).map_err(CandidateBuildError::ParentStateTree)?;
    if actual_root != expected_root {
        return Err(CandidateBuildError::ParentStateRootMismatch {
            expected: expected_root,
            actual: actual_root,
        });
    }
    Ok(accounts)
}

fn account_or_empty(accounts: &BTreeMap<Recipient, Account>, recipient: Recipient) -> Account {
    accounts.get(&recipient).copied().unwrap_or(Account::EMPTY)
}

fn put_normalized_account(
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

fn checked_balance_sum(accounts: &BTreeMap<Recipient, Account>) -> Option<u128> {
    let mut total = 0_u128;
    for account in accounts.values() {
        total = total.checked_add(u128::from(account.balance.get()))?;
        if total > u128::from(MAX_MONEY) {
            return None;
        }
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use out_consensus::chain::{ChildHeaderInvalid, ValidatedHeaderView};
    use out_consensus::{TimestampInvalid, DEVNET_POW_LIMIT_V0};
    use out_storage::conformance::validated_reward_commit;
    use out_storage::InMemoryConsensusStore;

    use super::*;
    use crate::bootstrap::NodeBootstrap;
    use crate::mempool::{MempoolAdmission, MempoolPolicy, MempoolRemovalReason};
    use crate::Node;

    const VECTOR_TRANSACTION_HEX: &str = "0000000000bc0000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a70003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b800000000000000000029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000075bcd1500000000000003e8000000000000000100000000000003e8000a4f555420766563746f720062000003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b84db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b";

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = char::from(pair[0]).to_digit(16).unwrap();
                let low = char::from(pair[1]).to_digit(16).unwrap();
                u8::try_from((high << 4) | low).unwrap()
            })
            .collect()
    }

    fn vector_transaction() -> RegularTransaction {
        RegularTransaction::decode_exact(&decode_hex(VECTOR_TRANSACTION_HEX)).unwrap()
    }

    fn mempool_policy() -> MempoolPolicy {
        MempoolPolicy {
            maximum_transactions: 16,
            maximum_total_bytes: 500_000,
            maximum_transactions_per_sender: 8,
            maximum_template_transactions: 8,
            maximum_template_bytes: 250_000,
        }
    }

    fn funded_node() -> Node<InMemoryConsensusStore> {
        let mut node = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        }
        .create_in_memory()
        .unwrap();
        let genesis = node.canonical_tip().unwrap().block_id;
        let commit = validated_reward_commit(node.storage(), genesis, b"candidate-funding");
        let raw = commit.canonical_block_bytes().to_vec();
        node.process_block(&raw, commit.header().header().timestamp)
            .unwrap();
        node
    }

    fn request(node: &Node<InMemoryConsensusStore>, recipient: Recipient) -> CandidateRequest {
        let tip = node.canonical_tip().unwrap();
        let parent = node
            .storage()
            .get_validated_header(tip.block_id)
            .unwrap()
            .unwrap();
        let timestamp = parent.header().timestamp + 1;
        CandidateRequest {
            timestamp,
            local_now: timestamp,
            reward_recipient: recipient,
            reward_extra: b"OUT CPU reference".to_vec(),
        }
    }

    #[test]
    fn candidate_replays_mempool_prefix_and_is_byte_deterministic() {
        let node = funded_node();
        let transaction = vector_transaction();
        let transaction_id =
            out_consensus::transaction_id_from_canonical_bytes(&transaction.encode().unwrap());
        let mut mempool =
            Mempool::new(node.storage(), SupportedNetwork::Devnet, mempool_policy()).unwrap();
        assert!(matches!(
            mempool
                .admit(node.storage(), Transaction::Regular(transaction.clone()))
                .unwrap(),
            MempoolAdmission::Accepted { .. }
        ));
        let request = request(&node, transaction.body.sender);
        let first = build_candidate(
            node.storage(),
            &mut mempool,
            SupportedNetwork::Devnet,
            request.clone(),
        )
        .unwrap();
        let second = build_candidate(
            node.storage(),
            &mut mempool,
            SupportedNetwork::Devnet,
            request,
        )
        .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.selected_regular_transactions(), 1);
        assert_eq!(first.deferred_transactions(), 0);
        assert_eq!(first.total_fees(), u128::from(transaction.body.fee.get()));
        assert_eq!(first.block().header.target, DEVNET_POW_LIMIT_V0);
        assert_eq!(first.block().body.transactions.len(), 2);
        assert_eq!(first.transaction_ids()[1], transaction_id);
        let Transaction::Reward(reward) = &first.block().body.transactions[0] else {
            panic!("reward first");
        };
        assert_eq!(reward.body.fees, transaction.body.fee);
        assert_eq!(reward.body.height, first.block().header.height);
        assert_eq!(
            first.block().encode_non_genesis(),
            second.block().encode_non_genesis()
        );
    }

    #[test]
    fn bounded_cpu_solution_passes_full_consensus_and_reconciles_mempool() {
        let mut node = funded_node();
        let transaction = vector_transaction();
        let transaction_id =
            out_consensus::transaction_id_from_canonical_bytes(&transaction.encode().unwrap());
        let mut mempool =
            Mempool::new(node.storage(), SupportedNetwork::Devnet, mempool_policy()).unwrap();
        mempool
            .admit(node.storage(), Transaction::Regular(transaction.clone()))
            .unwrap();
        let request = request(&node, transaction.body.sender);
        let candidate = build_candidate(
            node.storage(),
            &mut mempool,
            SupportedNetwork::Devnet,
            request.clone(),
        )
        .unwrap();
        let solved = match mine_cpu(
            &candidate,
            0,
            CpuMiningPolicy {
                maximum_nonce_attempts: 1_000_000,
            },
        )
        .unwrap()
        {
            CpuMiningOutcome::Solved(solved) => solved,
            other => panic!("fixture must solve: {other:?}"),
        };
        assert_eq!(
            mine_cpu(
                &candidate,
                0,
                CpuMiningPolicy {
                    maximum_nonce_attempts: solved.attempts,
                },
            )
            .unwrap(),
            CpuMiningOutcome::Solved(solved.clone())
        );
        assert_eq!(
            solved.pow_hash,
            pow_hash_from_header_bytes(&solved.block.header.encode())
        );
        assert!(pow_hash_meets_target(
            solved.pow_hash,
            solved.block.header.target
        ));
        assert_eq!(
            solved.block_id,
            block_id_from_header_bytes(&solved.block.header.encode())
        );
        if solved.block.header.nonce > 0 {
            assert_eq!(
                mine_cpu(
                    &candidate,
                    0,
                    CpuMiningPolicy {
                        maximum_nonce_attempts: solved.block.header.nonce,
                    },
                )
                .unwrap(),
                CpuMiningOutcome::BudgetExhausted {
                    attempts: solved.block.header.nonce,
                    next_nonce: solved.block.header.nonce,
                }
            );
        }

        let raw = solved.block.encode_non_genesis().unwrap();
        node.process_block(&raw, request.local_now).unwrap();
        assert_eq!(node.canonical_tip().unwrap().block_id, solved.block_id);
        let reconciliation = mempool
            .reconcile_if_needed(node.storage())
            .unwrap()
            .unwrap();
        assert_eq!(reconciliation.removed.len(), 1);
        assert_eq!(reconciliation.removed[0].transaction_id, transaction_id);
        assert_eq!(
            reconciliation.removed[0].reason,
            MempoolRemovalReason::Confirmed
        );
        assert_eq!(mempool.transaction_count(), 0);
    }

    #[test]
    fn invalid_timestamp_and_unbounded_mining_policy_fail_closed() {
        let node = funded_node();
        let transaction = vector_transaction();
        let mut mempool =
            Mempool::new(node.storage(), SupportedNetwork::Devnet, mempool_policy()).unwrap();
        let tip = node.canonical_tip().unwrap();
        let parent = node
            .storage()
            .get_validated_header(tip.block_id)
            .unwrap()
            .unwrap();
        let request = CandidateRequest {
            timestamp: parent.header().timestamp,
            local_now: parent.header().timestamp,
            reward_recipient: transaction.body.sender,
            reward_extra: Vec::new(),
        };
        assert!(matches!(
            build_candidate(
                node.storage(),
                &mut mempool,
                SupportedNetwork::Devnet,
                request,
            ),
            Err(CandidateBuildError::Header(
                ChildHeaderValidationFailure::Invalid(ChildHeaderInvalid::Timestamp(
                    TimestampInvalid::NotAfterMedian { .. }
                ))
            ))
        ));
        assert_eq!(
            CpuMiningPolicy {
                maximum_nonce_attempts: 0
            }
            .validate(),
            Err(CpuMiningPolicyError::ZeroMaximumNonceAttempts)
        );
    }

    #[test]
    fn coordinator_is_bounded_resumable_and_revision_stale() {
        let node = funded_node();
        let transaction = vector_transaction();
        let mut mempool =
            Mempool::new(node.storage(), SupportedNetwork::Devnet, mempool_policy()).unwrap();
        mempool
            .admit(node.storage(), Transaction::Regular(transaction.clone()))
            .unwrap();
        let candidate = build_candidate(
            node.storage(),
            &mut mempool,
            SupportedNetwork::Devnet,
            request(&node, transaction.body.sender),
        )
        .unwrap();
        let tip = node.canonical_tip().unwrap();
        let revision = mempool.revision();
        let mut stale = MiningCoordinator::new(CpuMiningPolicy {
            maximum_nonce_attempts: 1,
        })
        .unwrap();
        assert!(!stale.start(candidate.clone(), 0));
        assert_eq!(
            stale.step(tip, revision + 1).unwrap(),
            MiningWorkOutcome::Stale(MiningStaleReason::MempoolChanged {
                expected: revision,
                actual: revision + 1,
            })
        );
        assert!(stale.snapshot().is_none());

        let mut coordinator = MiningCoordinator::new(CpuMiningPolicy {
            maximum_nonce_attempts: 1,
        })
        .unwrap();
        assert!(!coordinator.start(candidate, 0));
        let mut solution = None;
        for _ in 0..1_000_000 {
            match coordinator.step(tip, revision).unwrap() {
                MiningWorkOutcome::Progress { attempts: 1, .. } => {}
                MiningWorkOutcome::SolutionFound {
                    attempts: 1,
                    block_id,
                    ..
                } => {
                    solution = Some(block_id);
                    break;
                }
                other => panic!("unexpected coordinator result: {other:?}"),
            }
        }
        let solution = solution.expect("fixed devnet fixture solves within bound");
        assert_eq!(coordinator.solution().unwrap().block_id, solution);
        assert!(matches!(
            coordinator.step(tip, revision).unwrap(),
            MiningWorkOutcome::SolutionPending { block_id, .. } if block_id == solution
        ));
        assert!(coordinator.complete_solution().is_some());
        assert_eq!(
            coordinator.step(tip, revision).unwrap(),
            MiningWorkOutcome::Idle
        );
    }
}
