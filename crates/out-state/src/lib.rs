#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use out_crypto::{Blake3Hasher, ConsensusDomain, ConsensusHasher};
use out_primitives::{Amount, Hash32, Nonce, Recipient, StateRoot, MAX_MONEY};

pub const STATE_TREE_DEPTH: u16 = 256;
pub const STATE_TREE_VERSION_V0: u8 = 0;
pub const EMPTY_LEAF_TAG: u8 = 0;
pub const OCCUPIED_LEAF_TAG: u8 = 1;
pub const ACCOUNT_RECORD_VERSION_V0: u8 = 0;
pub const ACCOUNT_RECORD_LEN: usize = 50;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Account {
    pub balance: Amount,
    pub nonce: Nonce,
}

impl Account {
    pub const EMPTY: Self = Self {
        balance: Amount::ZERO,
        nonce: Nonce::ZERO,
    };
    pub const fn new(balance: Amount, nonce: Nonce) -> Self {
        Self { balance, nonce }
    }
    pub const fn is_absent(self) -> bool {
        self.balance.get() == 0 && self.nonce.get() == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateTreeError {
    DuplicateAccount,
    AccountKeyCollision,
    InternalTreeInvariant,
}

#[derive(Clone, Copy)]
struct HashedLeaf {
    key: Hash32,
    hash: Hash32,
}

pub fn canonical_account_record(recipient: Recipient, account: Account) -> [u8; 50] {
    let mut record = [0_u8; ACCOUNT_RECORD_LEN];
    record[0] = ACCOUNT_RECORD_VERSION_V0;
    record[1..34].copy_from_slice(recipient.as_bytes());
    record[34..42].copy_from_slice(&account.balance.get().to_be_bytes());
    record[42..50].copy_from_slice(&account.nonce.get().to_be_bytes());
    record
}

pub fn account_key(recipient: Recipient) -> Hash32 {
    let mut material = [0_u8; 34];
    material[0] = STATE_TREE_VERSION_V0;
    material[1..].copy_from_slice(recipient.as_bytes());
    Blake3Hasher.hash_32(ConsensusDomain::AccountKey, &material)
}

pub fn occupied_leaf_hash(recipient: Recipient, account: Account) -> Option<Hash32> {
    if account.is_absent() {
        return None;
    }
    let key = account_key(recipient);
    let record = canonical_account_record(recipient, account);
    let mut material = [0_u8; 84];
    material[0] = STATE_TREE_VERSION_V0;
    material[1] = OCCUPIED_LEAF_TAG;
    material[2..34].copy_from_slice(key.as_bytes());
    material[34..].copy_from_slice(&record);
    Some(Blake3Hasher.hash_32(ConsensusDomain::StateLeaf, &material))
}

pub fn empty_subtree_hashes() -> [Hash32; 257] {
    let empty_leaf_material = [STATE_TREE_VERSION_V0, EMPTY_LEAF_TAG];
    let empty_leaf = Blake3Hasher.hash_32(ConsensusDomain::StateLeaf, &empty_leaf_material);
    let mut hashes = [empty_leaf; 257];
    for height in 1..=STATE_TREE_DEPTH {
        hashes[usize::from(height)] = internal_node_hash(
            height,
            hashes[usize::from(height - 1)],
            hashes[usize::from(height - 1)],
        );
    }
    hashes
}

pub fn empty_state_root() -> StateRoot {
    StateRoot::new(empty_subtree_hashes()[usize::from(STATE_TREE_DEPTH)].into_bytes())
}

pub fn compute_state_root(accounts: &[(Recipient, Account)]) -> Result<StateRoot, StateTreeError> {
    let mut recipients = BTreeSet::new();
    let mut leaves = Vec::with_capacity(accounts.len());
    for &(recipient, account) in accounts {
        if !recipients.insert(recipient) {
            return Err(StateTreeError::DuplicateAccount);
        }
        if let Some(hash) = occupied_leaf_hash(recipient, account) {
            leaves.push(HashedLeaf {
                key: account_key(recipient),
                hash,
            });
        }
    }
    leaves.sort_unstable_by_key(|leaf| leaf.key);
    if leaves.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return Err(StateTreeError::AccountKeyCollision);
    }

    let empty = empty_subtree_hashes();
    let root = sparse_fold(&leaves, STATE_TREE_DEPTH, &empty)?;
    Ok(StateRoot::new(root.into_bytes()))
}

fn internal_node_hash(height: u16, left: Hash32, right: Hash32) -> Hash32 {
    let mut material = [0_u8; 67];
    material[0] = STATE_TREE_VERSION_V0;
    material[1..3].copy_from_slice(&height.to_be_bytes());
    material[3..35].copy_from_slice(left.as_bytes());
    material[35..].copy_from_slice(right.as_bytes());
    Blake3Hasher.hash_32(ConsensusDomain::StateNode, &material)
}

fn sparse_fold(
    leaves: &[HashedLeaf],
    height: u16,
    empty: &[Hash32; 257],
) -> Result<Hash32, StateTreeError> {
    if leaves.is_empty() {
        return empty
            .get(usize::from(height))
            .copied()
            .ok_or(StateTreeError::InternalTreeInvariant);
    }
    if height == 0 {
        return match leaves {
            [leaf] => Ok(leaf.hash),
            _ => Err(StateTreeError::AccountKeyCollision),
        };
    }

    let bit_index = usize::from(STATE_TREE_DEPTH - height);
    let split = leaves.partition_point(|leaf| !key_bit(leaf.key, bit_index));
    let left = sparse_fold(&leaves[..split], height - 1, empty)?;
    let right = sparse_fold(&leaves[split..], height - 1, empty)?;
    Ok(internal_node_hash(height, left, right))
}

fn key_bit(key: Hash32, bit_index: usize) -> bool {
    let byte = key.as_bytes()[bit_index / 8];
    let shift = 7 - (bit_index % 8);
    ((byte >> shift) & 1) == 1
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegularTransfer {
    pub sender: Recipient,
    pub recipient: Recipient,
    pub nonce: Nonce,
    pub amount: Amount,
    pub fee: Amount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountChange {
    pub recipient: Recipient,
    pub account: Account,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegularOutcome {
    pub changes: Vec<AccountChange>,
    pub fee_total: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    ZeroAmount,
    FeeBelowMinimum,
    NonceMismatch,
    NonceOverflow,
    MonetaryOverflow,
    MaximumMoneyExceeded,
    InsufficientFunds,
    RewardMismatch,
}

fn checked_money_add(left: u64, right: u64) -> Result<u64, TransitionError> {
    let sum = u128::from(left)
        .checked_add(u128::from(right))
        .ok_or(TransitionError::MonetaryOverflow)?;
    if sum > u128::from(MAX_MONEY) {
        return Err(TransitionError::MaximumMoneyExceeded);
    }
    u64::try_from(sum).map_err(|_| TransitionError::MonetaryOverflow)
}

pub fn apply_regular(
    sender_before: Account,
    recipient_before: Account,
    transfer: RegularTransfer,
    fee_total_before: u128,
    minimum_fee: Amount,
) -> Result<RegularOutcome, TransitionError> {
    if transfer.amount.get() == 0 {
        return Err(TransitionError::ZeroAmount);
    }
    if transfer.fee < minimum_fee {
        return Err(TransitionError::FeeBelowMinimum);
    }
    if transfer.nonce != sender_before.nonce {
        return Err(TransitionError::NonceMismatch);
    }
    let next_nonce = sender_before
        .nonce
        .checked_increment()
        .map_err(|_| TransitionError::NonceOverflow)?;
    let required = u128::from(transfer.amount.get())
        .checked_add(u128::from(transfer.fee.get()))
        .ok_or(TransitionError::MonetaryOverflow)?;
    if required > u128::from(MAX_MONEY) || required > u128::from(u64::MAX) {
        return Err(TransitionError::MaximumMoneyExceeded);
    }
    if u128::from(sender_before.balance.get()) < required {
        return Err(TransitionError::InsufficientFunds);
    }
    let debit = u64::try_from(required).map_err(|_| TransitionError::MonetaryOverflow)?;
    let debited_sender = Account::new(Amount::new(sender_before.balance.get() - debit), next_nonce);
    let mut changes = Vec::with_capacity(if transfer.sender == transfer.recipient {
        1
    } else {
        2
    });
    if transfer.sender == transfer.recipient {
        let final_balance = checked_money_add(debited_sender.balance.get(), transfer.amount.get())?;
        changes.push(AccountChange {
            recipient: transfer.sender,
            account: Account::new(Amount::new(final_balance), next_nonce),
        });
    } else {
        let recipient_balance =
            checked_money_add(recipient_before.balance.get(), transfer.amount.get())?;
        changes.push(AccountChange {
            recipient: transfer.sender,
            account: debited_sender,
        });
        changes.push(AccountChange {
            recipient: transfer.recipient,
            account: Account::new(Amount::new(recipient_balance), recipient_before.nonce),
        });
    }
    let fee_total = fee_total_before
        .checked_add(u128::from(transfer.fee.get()))
        .ok_or(TransitionError::MonetaryOverflow)?;
    if fee_total > u128::from(MAX_MONEY) {
        return Err(TransitionError::MaximumMoneyExceeded);
    }
    Ok(RegularOutcome { changes, fee_total })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RewardOutcome {
    pub account: Account,
    pub issued_supply: u128,
}

pub fn apply_reward(
    account_before: Account,
    declared_subsidy: Amount,
    expected_subsidy: Amount,
    declared_fees: Amount,
    fee_total: u128,
    supply_before: u128,
) -> Result<RewardOutcome, TransitionError> {
    if declared_subsidy != expected_subsidy || u128::from(declared_fees.get()) != fee_total {
        return Err(TransitionError::RewardMismatch);
    }
    let reward_total = u128::from(declared_subsidy.get())
        .checked_add(fee_total)
        .ok_or(TransitionError::MonetaryOverflow)?;
    if reward_total > u128::from(MAX_MONEY) || reward_total > u128::from(u64::MAX) {
        return Err(TransitionError::MaximumMoneyExceeded);
    }
    let issued_supply = supply_before
        .checked_add(u128::from(declared_subsidy.get()))
        .ok_or(TransitionError::MonetaryOverflow)?;
    if issued_supply > u128::from(MAX_MONEY) {
        return Err(TransitionError::MaximumMoneyExceeded);
    }
    let reward_u64 = u64::try_from(reward_total).map_err(|_| TransitionError::MonetaryOverflow)?;
    let balance = checked_money_add(account_before.balance.get(), reward_u64)?;
    Ok(RewardOutcome {
        account: Account::new(Amount::new(balance), account_before.nonce),
        issued_supply,
    })
}

pub const fn subsidy_at_height(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let era = (height - 1) / 2_102_400;
    if era >= 29 {
        0
    } else {
        500_000_000_u64 >> era
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient(last: u8) -> Recipient {
        let mut bytes = [0_u8; 33];
        bytes[32] = last;
        Recipient::from_bytes(bytes).expect("v0 recipient")
    }

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        assert_eq!(input.len(), N * 2);
        let mut output = [0_u8; N];
        for (index, pair) in input.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = char::from(pair[0]).to_digit(16).expect("valid hex");
            let low = char::from(pair[1]).to_digit(16).expect("valid hex");
            output[index] = u8::try_from((high << 4) | low).expect("hex byte");
        }
        output
    }

    fn vector_recipient(input: &str) -> Recipient {
        Recipient::from_bytes(hex::<33>(input)).expect("v0 recipient")
    }

    #[test]
    fn empty_and_two_account_roots_match_verified_vectors() {
        let first =
            vector_recipient("0003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
        let second =
            vector_recipient("0029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7");
        assert_eq!(
            account_key(first).into_bytes(),
            hex::<32>("6619ac8e10fadf1fd35737c0f437d0c75d76bb19c33e4b0ca3953e30c85fa4f8")
        );
        assert_eq!(
            account_key(second).into_bytes(),
            hex::<32>("516c6fc142ec3bda9eb3744f9c3d7608e81e1cf0c4d567ac5f30e9d499eab948")
        );
        assert_eq!(
            empty_state_root().into_bytes(),
            hex::<32>("3d30a2588a2f688edd9b29af2bb3b522db2deb731709dbfb53fadefab69c2147")
        );

        let accounts = [
            (
                first,
                Account::new(Amount::new(1_376_543_211), Nonce::new(1)),
            ),
            (second, Account::new(Amount::new(123_456_789), Nonce::ZERO)),
        ];
        assert_eq!(
            compute_state_root(&accounts)
                .expect("state root")
                .into_bytes(),
            hex::<32>("25484208231a78f132d97102067e49ddd3bf1fe904212116af2af81fa47923aa")
        );

        let reversed = [accounts[1], accounts[0]];
        assert_eq!(compute_state_root(&accounts), compute_state_root(&reversed));
    }

    #[test]
    fn absent_accounts_do_not_create_leaves() {
        let account = recipient(9);
        assert_eq!(
            compute_state_root(&[(account, Account::EMPTY)]),
            Ok(empty_state_root())
        );
    }

    #[test]
    fn duplicate_accounts_are_rejected() {
        let account = recipient(9);
        assert_eq!(
            compute_state_root(&[(account, Account::EMPTY), (account, Account::EMPTY)]),
            Err(StateTreeError::DuplicateAccount)
        );
    }

    #[test]
    fn verified_transfer_then_reward_values_match() {
        let sender = recipient(1);
        let recipient = recipient(2);
        let transfer = RegularTransfer {
            sender,
            recipient,
            nonce: Nonce::ZERO,
            amount: Amount::new(123_456_789),
            fee: Amount::new(1_000),
        };
        let regular = apply_regular(
            Account::new(Amount::new(1_000_000_000), Nonce::ZERO),
            Account::EMPTY,
            transfer,
            0,
            Amount::ZERO,
        )
        .expect("regular");
        assert_eq!(
            regular.changes[0].account,
            Account::new(Amount::new(876_542_211), Nonce::new(1))
        );
        assert_eq!(
            regular.changes[1].account,
            Account::new(Amount::new(123_456_789), Nonce::ZERO)
        );
        let reward = apply_reward(
            regular.changes[0].account,
            Amount::new(500_000_000),
            Amount::new(subsidy_at_height(1)),
            Amount::new(1_000),
            regular.fee_total,
            0,
        )
        .expect("reward");
        assert_eq!(
            reward.account,
            Account::new(Amount::new(1_376_543_211), Nonce::new(1))
        );
    }

    #[test]
    fn self_send_loses_only_fee() {
        let owner = recipient(1);
        let transfer = RegularTransfer {
            sender: owner,
            recipient: owner,
            nonce: Nonce::new(7),
            amount: Amount::new(40),
            fee: Amount::new(3),
        };
        let outcome = apply_regular(
            Account::new(Amount::new(100), Nonce::new(7)),
            Account::new(Amount::new(100), Nonce::new(7)),
            transfer,
            0,
            Amount::ZERO,
        )
        .expect("self send");
        assert_eq!(
            outcome.changes,
            vec![AccountChange {
                recipient: owner,
                account: Account::new(Amount::new(97), Nonce::new(8))
            }]
        );
    }

    #[test]
    fn nonce_maximum_is_rejected() {
        let sender = recipient(1);
        let recipient = recipient(2);
        let transfer = RegularTransfer {
            sender,
            recipient,
            nonce: Nonce::new(u64::MAX),
            amount: Amount::new(1),
            fee: Amount::ZERO,
        };
        assert_eq!(
            apply_regular(
                Account::new(Amount::new(10), Nonce::new(u64::MAX)),
                Account::EMPTY,
                transfer,
                0,
                Amount::ZERO
            ),
            Err(TransitionError::NonceOverflow)
        );
    }
}
