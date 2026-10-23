//! Deterministic, bounded, non-consensus transaction holding policy.
//!
//! This module never changes transaction or block validity. It authenticates
//! regular transactions with the frozen consensus routines, evaluates them in
//! FIFO admission order against a canonical-state snapshot plus prior pending
//! changes, and rebuilds that disposable overlay whenever the canonical tip
//! changes.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use out_codec::{EncodeError, RegularTransaction, Transaction, MAX_TX_BYTES};
use out_consensus::chain::ChainTip;
use out_consensus::{
    transaction_id_from_canonical_bytes, validate_and_apply_regular_transaction, RegularInvalid,
    RegularLocalFailure, RegularValidationContext, RegularValidationFailure,
};
use out_primitives::{BlockId, Recipient, TransactionId};
use out_state::Account;
use out_storage::{ConsensusStorage, OwnedAncestorTransactionSnapshot, OwnedParentStateSnapshot};

use crate::SupportedNetwork;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MempoolPolicy {
    pub maximum_transactions: u16,
    pub maximum_total_bytes: u64,
    pub maximum_transactions_per_sender: u16,
    pub maximum_template_transactions: u16,
    pub maximum_template_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MempoolPolicyError {
    Zero(&'static str),
    TemplateTransactionsAbovePool,
    TemplateBytesAbovePool,
}

impl MempoolPolicy {
    pub fn validate(self) -> Result<Self, MempoolPolicyError> {
        let nonzero = [
            (u64::from(self.maximum_transactions), "maximum_transactions"),
            (self.maximum_total_bytes, "maximum_total_bytes"),
            (
                u64::from(self.maximum_transactions_per_sender),
                "maximum_transactions_per_sender",
            ),
            (
                u64::from(self.maximum_template_transactions),
                "maximum_template_transactions",
            ),
            (self.maximum_template_bytes, "maximum_template_bytes"),
        ];
        if let Some((_, field)) = nonzero.into_iter().find(|(value, _)| *value == 0) {
            return Err(MempoolPolicyError::Zero(field));
        }
        if self.maximum_template_transactions > self.maximum_transactions {
            return Err(MempoolPolicyError::TemplateTransactionsAbovePool);
        }
        if self.maximum_template_bytes > self.maximum_total_bytes {
            return Err(MempoolPolicyError::TemplateBytesAbovePool);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MempoolError<E> {
    Policy(MempoolPolicyError),
    Store(E),
    MissingCanonicalState(BlockId),
    MissingCanonicalHistory(BlockId),
    StateAnchorMismatch { expected: BlockId, actual: BlockId },
    HistoryAnchorMismatch { expected: BlockId, actual: BlockId },
    HeightOverflow,
    RewardTransaction,
    CanonicalEncoding(EncodeError),
    CanonicalLength { actual: usize, maximum: u32 },
    Invalid(RegularInvalid),
    Local(RegularLocalFailure),
    TransactionCapacity { maximum: u16 },
    SenderCapacity { sender: Recipient, maximum: u16 },
    ByteCapacity { maximum: u64 },
    RevisionOverflow,
    Accounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MempoolAdmission {
    Accepted {
        transaction_id: TransactionId,
        bytes: u32,
    },
    AlreadyPresent {
        transaction_id: TransactionId,
    },
    AlreadyConfirmed {
        transaction_id: TransactionId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MempoolRemovalReason {
    Confirmed,
    Invalid(RegularInvalid),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MempoolRemoval {
    pub transaction_id: TransactionId,
    pub reason: MempoolRemovalReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MempoolReconciliation {
    pub previous_tip: BlockId,
    pub new_tip: BlockId,
    pub retained: u16,
    pub removed: Vec<MempoolRemoval>,
}

#[derive(Clone, Debug)]
struct MempoolEntry {
    transaction: RegularTransaction,
    canonical_bytes: Vec<u8>,
}

pub struct Mempool {
    policy: MempoolPolicy,
    network: SupportedNetwork,
    anchor: ChainTip,
    base_accounts: Vec<(Recipient, Account)>,
    confirmed: BTreeSet<TransactionId>,
    working_accounts: BTreeMap<Recipient, Account>,
    entries: BTreeMap<TransactionId, MempoolEntry>,
    admission_order: VecDeque<TransactionId>,
    sender_counts: BTreeMap<Recipient, u16>,
    bytes: u64,
    revision: u64,
}

impl Mempool {
    pub fn new<S: ConsensusStorage>(
        storage: &S,
        network: SupportedNetwork,
        policy: MempoolPolicy,
    ) -> Result<Self, MempoolError<S::Error>> {
        let policy = policy.validate().map_err(MempoolError::Policy)?;
        let (anchor, state, history) = canonical_snapshots(storage)?;
        Self::from_snapshots(policy, network, anchor, state, history)
    }

    pub const fn policy(&self) -> MempoolPolicy {
        self.policy
    }

    pub const fn network(&self) -> SupportedNetwork {
        self.network
    }

    pub const fn anchor(&self) -> ChainTip {
        self.anchor
    }

    pub fn transaction_count(&self) -> usize {
        self.entries.len()
    }

    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn contains(&self, transaction_id: TransactionId) -> bool {
        self.entries.contains_key(&transaction_id)
    }

    pub fn transaction(&self, transaction_id: TransactionId) -> Option<&RegularTransaction> {
        self.entries
            .get(&transaction_id)
            .map(|entry| &entry.transaction)
    }

    pub fn transaction_ids(&self) -> Vec<TransactionId> {
        self.admission_order.iter().copied().collect()
    }

    pub fn template(&self) -> Vec<RegularTransaction> {
        let mut transactions = Vec::new();
        let mut bytes = 0_u64;
        for transaction_id in &self.admission_order {
            if transactions.len() >= usize::from(self.policy.maximum_template_transactions) {
                break;
            }
            let Some(entry) = self.entries.get(transaction_id) else {
                break;
            };
            let Ok(length) = u64::try_from(entry.canonical_bytes.len()) else {
                break;
            };
            let Some(next_bytes) = bytes.checked_add(length) else {
                break;
            };
            if next_bytes > self.policy.maximum_template_bytes {
                break;
            }
            transactions.push(entry.transaction.clone());
            bytes = next_bytes;
        }
        transactions
    }

    pub fn admit<S: ConsensusStorage>(
        &mut self,
        storage: &S,
        transaction: Transaction,
    ) -> Result<MempoolAdmission, MempoolError<S::Error>> {
        self.reconcile_if_needed(storage)?;
        let Transaction::Regular(transaction) = transaction else {
            return Err(MempoolError::RewardTransaction);
        };
        self.admit_regular(transaction)
    }

    pub fn reconcile_if_needed<S: ConsensusStorage>(
        &mut self,
        storage: &S,
    ) -> Result<Option<MempoolReconciliation>, MempoolError<S::Error>> {
        let tip = storage.canonical_tip().map_err(MempoolError::Store)?;
        if tip == self.anchor {
            return Ok(None);
        }
        let previous_tip = self.anchor.block_id;
        let (_, state, history) = canonical_snapshots_at(storage, tip)?;
        let old_order = self.admission_order.clone();
        let old_entries = self.entries.clone();
        let mut replacement = Self::from_snapshots(self.policy, self.network, tip, state, history)?;
        let mut removed = Vec::new();
        for transaction_id in old_order {
            let Some(entry) = old_entries.get(&transaction_id) else {
                return Err(MempoolError::Accounting);
            };
            match replacement.admit_regular(entry.transaction.clone()) {
                Ok(MempoolAdmission::Accepted { .. }) => {}
                Ok(MempoolAdmission::AlreadyConfirmed { .. }) => {
                    removed.push(MempoolRemoval {
                        transaction_id,
                        reason: MempoolRemovalReason::Confirmed,
                    });
                }
                Ok(MempoolAdmission::AlreadyPresent { .. }) => {
                    return Err(MempoolError::Accounting);
                }
                Err(MempoolError::Invalid(error)) => removed.push(MempoolRemoval {
                    transaction_id,
                    reason: MempoolRemovalReason::Invalid(error),
                }),
                Err(error) => return Err(error),
            }
        }
        let retained =
            u16::try_from(replacement.entries.len()).map_err(|_| MempoolError::Accounting)?;
        replacement.revision = self
            .revision
            .checked_add(1)
            .ok_or(MempoolError::RevisionOverflow)?;
        *self = replacement;
        Ok(Some(MempoolReconciliation {
            previous_tip,
            new_tip: tip.block_id,
            retained,
            removed,
        }))
    }

    fn from_snapshots<E>(
        policy: MempoolPolicy,
        network: SupportedNetwork,
        anchor: ChainTip,
        state: OwnedParentStateSnapshot,
        history: OwnedAncestorTransactionSnapshot,
    ) -> Result<Self, MempoolError<E>> {
        if state.anchor_block_id != anchor.block_id {
            return Err(MempoolError::StateAnchorMismatch {
                expected: anchor.block_id,
                actual: state.anchor_block_id,
            });
        }
        if history.anchor_block_id != anchor.block_id {
            return Err(MempoolError::HistoryAnchorMismatch {
                expected: anchor.block_id,
                actual: history.anchor_block_id,
            });
        }
        Ok(Self {
            policy,
            network,
            anchor,
            base_accounts: state.accounts,
            confirmed: history.confirmed_transaction_ids,
            working_accounts: BTreeMap::new(),
            entries: BTreeMap::new(),
            admission_order: VecDeque::new(),
            sender_counts: BTreeMap::new(),
            bytes: 0,
            revision: 0,
        })
    }

    fn admit_regular<E>(
        &mut self,
        transaction: RegularTransaction,
    ) -> Result<MempoolAdmission, MempoolError<E>> {
        let canonical_bytes = transaction
            .encode()
            .map_err(MempoolError::CanonicalEncoding)?;
        if canonical_bytes.len() > usize::try_from(MAX_TX_BYTES).unwrap_or(usize::MAX) {
            return Err(MempoolError::CanonicalLength {
                actual: canonical_bytes.len(),
                maximum: MAX_TX_BYTES,
            });
        }
        let transaction_id = transaction_id_from_canonical_bytes(&canonical_bytes);
        if self.entries.contains_key(&transaction_id) {
            return Ok(MempoolAdmission::AlreadyPresent { transaction_id });
        }
        if self.confirmed.contains(&transaction_id) {
            return Ok(MempoolAdmission::AlreadyConfirmed { transaction_id });
        }
        if self.entries.len() >= usize::from(self.policy.maximum_transactions) {
            return Err(MempoolError::TransactionCapacity {
                maximum: self.policy.maximum_transactions,
            });
        }
        let sender = transaction.body.sender;
        let sender_count = self.sender_counts.get(&sender).copied().unwrap_or(0);
        if sender_count >= self.policy.maximum_transactions_per_sender {
            return Err(MempoolError::SenderCapacity {
                sender,
                maximum: self.policy.maximum_transactions_per_sender,
            });
        }
        let length = u64::try_from(canonical_bytes.len()).map_err(|_| MempoolError::Accounting)?;
        let next_bytes = self
            .bytes
            .checked_add(length)
            .ok_or(MempoolError::ByteCapacity {
                maximum: self.policy.maximum_total_bytes,
            })?;
        if next_bytes > self.policy.maximum_total_bytes {
            return Err(MempoolError::ByteCapacity {
                maximum: self.policy.maximum_total_bytes,
            });
        }
        let candidate_height = self
            .anchor
            .height
            .checked_add(1)
            .ok_or(MempoolError::HeightOverflow)?;
        let sender_before = self.account(transaction.body.sender);
        let recipient_before = self.account(transaction.body.recipient);
        let parameters = self.network.validation_parameters();
        let applied = validate_and_apply_regular_transaction(
            &canonical_bytes,
            RegularValidationContext {
                network: self.network.identity(),
                block_height: candidate_height,
                active_tx_version: parameters.active_transaction_version,
                minimum_fee: parameters.minimum_fee,
            },
            sender_before,
            recipient_before,
            0,
        )
        .map_err(|failure| match failure {
            RegularValidationFailure::Invalid(error) => MempoolError::Invalid(error),
            RegularValidationFailure::Local(error) => MempoolError::Local(error),
        })?;
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(MempoolError::RevisionOverflow)?;
        for change in applied.outcome.changes {
            self.working_accounts
                .insert(change.recipient, change.account);
        }
        self.bytes = next_bytes;
        self.entries.insert(
            transaction_id,
            MempoolEntry {
                transaction,
                canonical_bytes,
            },
        );
        self.admission_order.push_back(transaction_id);
        self.sender_counts.insert(
            sender,
            sender_count
                .checked_add(1)
                .ok_or(MempoolError::Accounting)?,
        );
        self.revision = next_revision;
        Ok(MempoolAdmission::Accepted {
            transaction_id,
            bytes: u32::try_from(length).map_err(|_| MempoolError::Accounting)?,
        })
    }

    fn account(&self, recipient: Recipient) -> Account {
        if let Some(account) = self.working_accounts.get(&recipient).copied() {
            return account;
        }
        self.base_accounts
            .binary_search_by_key(&recipient, |(candidate, _)| *candidate)
            .ok()
            .and_then(|index| self.base_accounts.get(index).map(|(_, account)| *account))
            .unwrap_or(Account::EMPTY)
    }
}

fn canonical_snapshots<S: ConsensusStorage>(
    storage: &S,
) -> Result<
    (
        ChainTip,
        OwnedParentStateSnapshot,
        OwnedAncestorTransactionSnapshot,
    ),
    MempoolError<S::Error>,
> {
    let tip = storage.canonical_tip().map_err(MempoolError::Store)?;
    canonical_snapshots_at(storage, tip)
}

fn canonical_snapshots_at<S: ConsensusStorage>(
    storage: &S,
    tip: ChainTip,
) -> Result<
    (
        ChainTip,
        OwnedParentStateSnapshot,
        OwnedAncestorTransactionSnapshot,
    ),
    MempoolError<S::Error>,
> {
    let state = storage
        .parent_state_snapshot(tip.block_id)
        .map_err(MempoolError::Store)?
        .ok_or(MempoolError::MissingCanonicalState(tip.block_id))?;
    let history = storage
        .ancestor_transaction_snapshot(tip.block_id)
        .map_err(MempoolError::Store)?
        .ok_or(MempoolError::MissingCanonicalHistory(tip.block_id))?;
    Ok((tip, state, history))
}

#[cfg(test)]
mod tests {
    use out_consensus::block::ValidatedBlockCommit;
    use out_consensus::chain::{
        ReorganizationPlan, ReorganizationPlanFailure, ValidatedHeaderMetadata, ValidatedHeaderView,
    };
    use out_storage::conformance::validated_reward_commit;
    use out_storage::InMemoryConsensusStore;

    use super::*;
    use crate::bootstrap::NodeBootstrap;
    use crate::Node;

    const VECTOR_TRANSACTION_HEX: &str = "0000000000bc0000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a70003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b800000000000000000029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000075bcd1500000000000003e8000000000000000100000000000003e8000a4f555420766563746f720062000003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b84db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b";

    fn hex(input: &str) -> Vec<u8> {
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

    fn policy() -> MempoolPolicy {
        MempoolPolicy {
            maximum_transactions: 8,
            maximum_total_bytes: 100_000,
            maximum_transactions_per_sender: 4,
            maximum_template_transactions: 4,
            maximum_template_bytes: 50_000,
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
        let commit = validated_reward_commit(node.storage(), genesis, b"mempool-funding");
        let raw = commit.canonical_block_bytes().to_vec();
        node.process_block(&raw, commit.header().header().timestamp)
            .unwrap();
        node
    }

    fn vector_transaction() -> RegularTransaction {
        RegularTransaction::decode_exact(&hex(VECTOR_TRANSACTION_HEX)).unwrap()
    }

    #[test]
    fn policy_rejects_zero_and_incoherent_template_limits() {
        let mut candidate = policy();
        candidate.maximum_transactions = 0;
        assert_eq!(
            candidate.validate(),
            Err(MempoolPolicyError::Zero("maximum_transactions"))
        );
        candidate = policy();
        candidate.maximum_template_transactions = candidate.maximum_transactions + 1;
        assert_eq!(
            candidate.validate(),
            Err(MempoolPolicyError::TemplateTransactionsAbovePool)
        );
        candidate = policy();
        candidate.maximum_template_bytes = candidate.maximum_total_bytes + 1;
        assert_eq!(
            candidate.validate(),
            Err(MempoolPolicyError::TemplateBytesAbovePool)
        );
    }

    #[test]
    fn valid_admission_is_canonical_bounded_and_duplicate_stable() {
        let node = funded_node();
        let transaction = vector_transaction();
        let raw = transaction.encode().unwrap();
        let expected_id = transaction_id_from_canonical_bytes(&raw);
        let mut mempool = Mempool::new(node.storage(), SupportedNetwork::Devnet, policy()).unwrap();
        assert_eq!(
            mempool
                .admit(node.storage(), Transaction::Regular(transaction.clone()))
                .unwrap(),
            MempoolAdmission::Accepted {
                transaction_id: expected_id,
                bytes: u32::try_from(raw.len()).unwrap(),
            }
        );
        let accepted_bytes = mempool.bytes();
        assert_eq!(
            mempool
                .admit(node.storage(), Transaction::Regular(transaction.clone()))
                .unwrap(),
            MempoolAdmission::AlreadyPresent {
                transaction_id: expected_id,
            }
        );
        assert_eq!(mempool.transaction_count(), 1);
        assert_eq!(mempool.bytes(), accepted_bytes);
        assert_eq!(mempool.transaction_ids(), vec![expected_id]);
        assert_eq!(mempool.template(), vec![transaction]);
    }

    #[test]
    fn invalid_reward_and_capacity_fail_without_partial_mutation() {
        let node = funded_node();
        let mut bounded = policy();
        bounded.maximum_transactions = 1;
        bounded.maximum_template_transactions = 1;
        let mut mempool = Mempool::new(node.storage(), SupportedNetwork::Devnet, bounded).unwrap();
        let transaction = vector_transaction();
        mempool
            .admit(node.storage(), Transaction::Regular(transaction.clone()))
            .unwrap();
        let before_bytes = mempool.bytes();
        let mut changed = transaction;
        changed.body.memo.push(0);
        assert_eq!(
            mempool.admit(node.storage(), Transaction::Regular(changed)),
            Err(MempoolError::TransactionCapacity { maximum: 1 })
        );
        let reward = validated_reward_commit(
            node.storage(),
            node.canonical_tip().unwrap().block_id,
            b"reward-not-mempool",
        )
        .block()
        .body
        .transactions[0]
            .clone();
        assert_eq!(
            mempool.admit(node.storage(), reward),
            Err(MempoolError::RewardTransaction)
        );
        assert_eq!(mempool.transaction_count(), 1);
        assert_eq!(mempool.bytes(), before_bytes);
    }

    struct SnapshotStore {
        tip: ChainTip,
        state: OwnedParentStateSnapshot,
        history: OwnedAncestorTransactionSnapshot,
    }

    impl ValidatedHeaderView for SnapshotStore {
        type Error = ();

        fn get_validated_header(
            &self,
            _block_id: BlockId,
        ) -> Result<Option<ValidatedHeaderMetadata>, Self::Error> {
            Ok(None)
        }
    }

    impl ConsensusStorage for SnapshotStore {
        type MutationError = ();

        fn canonical_tip(&self) -> Result<ChainTip, Self::Error> {
            Ok(self.tip)
        }

        fn parent_state_snapshot(
            &self,
            block_id: BlockId,
        ) -> Result<Option<OwnedParentStateSnapshot>, Self::Error> {
            Ok((block_id == self.tip.block_id).then(|| self.state.clone()))
        }

        fn ancestor_transaction_snapshot(
            &self,
            block_id: BlockId,
        ) -> Result<Option<OwnedAncestorTransactionSnapshot>, Self::Error> {
            Ok((block_id == self.tip.block_id).then(|| self.history.clone()))
        }

        fn store_validated_block(
            &mut self,
            _commit: ValidatedBlockCommit,
        ) -> Result<(), Self::MutationError> {
            Err(())
        }

        fn plan_best_reorganization(
            &self,
            _maximum_plan_blocks: u64,
        ) -> Result<ReorganizationPlan, ReorganizationPlanFailure<Self::Error>> {
            panic!("not used")
        }

        fn apply_reorganization(
            &mut self,
            _plan: &ReorganizationPlan,
        ) -> Result<(), Self::MutationError> {
            Err(())
        }
    }

    #[test]
    fn tip_change_removes_confirmed_transaction_deterministically() {
        let node = funded_node();
        let tip = node.canonical_tip().unwrap();
        let mut store = SnapshotStore {
            tip,
            state: node
                .storage()
                .parent_state_snapshot(tip.block_id)
                .unwrap()
                .unwrap(),
            history: node
                .storage()
                .ancestor_transaction_snapshot(tip.block_id)
                .unwrap()
                .unwrap(),
        };
        let transaction = vector_transaction();
        let transaction_id = transaction_id_from_canonical_bytes(&transaction.encode().unwrap());
        let mut mempool = Mempool::new(&store, SupportedNetwork::Devnet, policy()).unwrap();
        mempool
            .admit(&store, Transaction::Regular(transaction))
            .unwrap();

        let new_tip = BlockId::new([0x77; 32]);
        store.tip = ChainTip {
            block_id: new_tip,
            height: tip.height + 1,
            cumulative_work: tip.cumulative_work,
        };
        store.state.anchor_block_id = new_tip;
        store.history.anchor_block_id = new_tip;
        store
            .history
            .confirmed_transaction_ids
            .insert(transaction_id);
        assert_eq!(
            mempool.reconcile_if_needed(&store).unwrap(),
            Some(MempoolReconciliation {
                previous_tip: tip.block_id,
                new_tip,
                retained: 0,
                removed: vec![MempoolRemoval {
                    transaction_id,
                    reason: MempoolRemovalReason::Confirmed,
                }],
            })
        );
        assert_eq!(mempool.transaction_count(), 0);
        assert_eq!(mempool.bytes(), 0);
    }
}
