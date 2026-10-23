use std::collections::{BTreeMap, BTreeSet};

use out_codec::{Block, DecodeError, EncodeError, Transaction};
use out_primitives::{
    Amount, BlockId, Recipient, StateRoot, TransactionId, TransactionRoot, MAX_MONEY,
};
use out_state::{
    apply_regular, apply_reward, compute_state_root, subsidy_at_height, Account, RegularTransfer,
    StateTreeError,
};

use crate::chain::{
    validate_child_header_with_parent, ChildHeaderInvalid, ChildHeaderLocalFailure,
    ChildHeaderValidationFailure, HeaderChainParameters, ValidatedHeaderMetadata,
    ValidatedHeaderView,
};
use crate::{
    transaction_id_from_canonical_bytes, transaction_merkle_root,
    validate_regular_transaction_structure, validate_reward_transaction_structure,
    verify_regular_transaction_signature, MerkleError, RegularInvalid, RegularLocalFailure,
    RegularValidationContext, RegularValidationFailure, RewardInvalid, RewardLocalFailure,
    RewardValidationContext, RewardValidationFailure, TimestampTemporaryFailure,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockValidationParameters {
    pub header: HeaderChainParameters,
    pub active_transaction_version: u16,
    pub minimum_fee: Amount,
}

impl BlockValidationParameters {
    pub const fn devnet_v0() -> Self {
        Self {
            header: HeaderChainParameters::devnet_v0(),
            active_transaction_version: 0,
            minimum_fee: Amount::ZERO,
        }
    }

    pub const fn testnet_v0() -> Self {
        Self {
            header: HeaderChainParameters::testnet_v0(),
            active_transaction_version: 0,
            minimum_fee: Amount::ZERO,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ParentStateSnapshot<'a> {
    pub anchor_block_id: BlockId,
    pub accounts: &'a [(Recipient, Account)],
    pub issued_supply: u128,
}

#[derive(Clone, Copy, Debug)]
pub struct AncestorTransactionSnapshot<'a> {
    pub anchor_block_id: BlockId,
    pub confirmed_transaction_ids: &'a BTreeSet<TransactionId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountDelta {
    pub recipient: Recipient,
    pub before: Account,
    pub after: Account,
}

/// Pure validation output. Storage MUST persist this block's exact bytes,
/// metadata, branch state, and deltas atomically. A later canonical-tip/index
/// change MUST be an independently atomic reorganization operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedBlockCommit {
    canonical_block_bytes: Vec<u8>,
    block: Block,
    header: ValidatedHeaderMetadata,
    transaction_ids: Vec<TransactionId>,
    parent_state_root: StateRoot,
    resulting_state_root: StateRoot,
    resulting_accounts: Vec<(Recipient, Account)>,
    account_deltas: Vec<AccountDelta>,
    total_fees: u128,
    issued_supply: u128,
}

impl ValidatedBlockCommit {
    pub fn canonical_block_bytes(&self) -> &[u8] {
        &self.canonical_block_bytes
    }

    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub const fn header(&self) -> ValidatedHeaderMetadata {
        self.header
    }

    pub fn transaction_ids(&self) -> &[TransactionId] {
        &self.transaction_ids
    }

    pub const fn parent_state_root(&self) -> StateRoot {
        self.parent_state_root
    }

    pub const fn resulting_state_root(&self) -> StateRoot {
        self.resulting_state_root
    }

    pub fn resulting_accounts(&self) -> &[(Recipient, Account)] {
        &self.resulting_accounts
    }

    pub fn account_deltas(&self) -> &[AccountDelta] {
        &self.account_deltas
    }

    pub const fn total_fees(&self) -> u128 {
        self.total_fees
    }

    pub const fn issued_supply(&self) -> u128 {
        self.issued_supply
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParentStateLocalError {
    AnchorMismatch {
        expected: BlockId,
        actual: BlockId,
    },
    DuplicateAccount(Recipient),
    BalanceAboveMaximum {
        recipient: Recipient,
        balance: u64,
    },
    SupplyAboveMaximum(u128),
    SupplyDoesNotMatchBalances {
        supply: u128,
        balances: u128,
    },
    MonetaryOverflow,
    StateTree(StateTreeError),
    RootMismatch {
        expected: StateRoot,
        actual: StateRoot,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockInvalid {
    CanonicalEncoding(DecodeError),
    NonCanonicalRoundTrip,
    Header(ChildHeaderInvalid),
    BodyStructure,
    Merkle(MerkleError),
    TransactionRootMismatch {
        expected: TransactionRoot,
        actual: TransactionRoot,
    },
    AncestorDuplicate {
        index: u32,
        transaction_id: TransactionId,
    },
    Regular {
        index: u32,
        error: RegularInvalid,
    },
    Reward(RewardInvalid),
    StateRootMismatch {
        expected: StateRoot,
        actual: StateRoot,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockLocalFailure<E> {
    Header(ChildHeaderLocalFailure<E>),
    CanonicalReencoding(EncodeError),
    MissingParentState,
    MissingAncestorTransactionHistory,
    AncestorAnchorMismatch {
        expected: BlockId,
        actual: BlockId,
    },
    ParentState(ParentStateLocalError),
    Regular {
        index: u32,
        error: RegularLocalFailure,
    },
    Reward(RewardLocalFailure),
    StateTree(StateTreeError),
    InternalInvariant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockValidationFailure<E> {
    Invalid(BlockInvalid),
    TemporarilyUnacceptable(TimestampTemporaryFailure),
    Local(BlockLocalFailure<E>),
}

pub fn validate_non_genesis_block<V: ValidatedHeaderView>(
    raw: &[u8],
    view: &V,
    parent_state: Option<ParentStateSnapshot<'_>>,
    ancestor_transactions: Option<AncestorTransactionSnapshot<'_>>,
    local_now: u64,
    parameters: BlockValidationParameters,
) -> Result<ValidatedBlockCommit, BlockValidationFailure<V::Error>> {
    let block = Block::decode_non_genesis_exact(raw)
        .map_err(|error| BlockValidationFailure::Invalid(BlockInvalid::CanonicalEncoding(error)))?;
    let reencoded = block.encode_non_genesis().map_err(|error| {
        BlockValidationFailure::Local(BlockLocalFailure::CanonicalReencoding(error))
    })?;
    if reencoded.as_slice() != raw {
        return Err(BlockValidationFailure::Invalid(
            BlockInvalid::NonCanonicalRoundTrip,
        ));
    }

    let validated_header =
        validate_child_header_with_parent(block.header, view, local_now, parameters.header)
            .map_err(map_header_failure)?;

    let mut canonical_transactions = Vec::with_capacity(block.body.transactions.len());
    let mut transaction_ids = Vec::with_capacity(block.body.transactions.len());
    for transaction in &block.body.transactions {
        let encoded = transaction.encode().map_err(|error| {
            BlockValidationFailure::Local(BlockLocalFailure::CanonicalReencoding(error))
        })?;
        transaction_ids.push(transaction_id_from_canonical_bytes(&encoded));
        canonical_transactions.push(encoded);
    }
    let transaction_root = transaction_merkle_root(&transaction_ids)
        .map_err(|error| BlockValidationFailure::Invalid(BlockInvalid::Merkle(error)))?;
    if transaction_root != block.header.transaction_root {
        return Err(BlockValidationFailure::Invalid(
            BlockInvalid::TransactionRootMismatch {
                expected: block.header.transaction_root,
                actual: transaction_root,
            },
        ));
    }

    let ancestry = ancestor_transactions.ok_or(BlockValidationFailure::Local(
        BlockLocalFailure::MissingAncestorTransactionHistory,
    ))?;
    if ancestry.anchor_block_id != validated_header.parent.block_id() {
        return Err(BlockValidationFailure::Local(
            BlockLocalFailure::AncestorAnchorMismatch {
                expected: validated_header.parent.block_id(),
                actual: ancestry.anchor_block_id,
            },
        ));
    }
    for (index, transaction_id) in transaction_ids.iter().copied().enumerate().skip(1) {
        if ancestry.confirmed_transaction_ids.contains(&transaction_id) {
            return Err(BlockValidationFailure::Invalid(
                BlockInvalid::AncestorDuplicate {
                    index: checked_index(index)?,
                    transaction_id,
                },
            ));
        }
    }

    let reward = match block.body.transactions.first() {
        Some(Transaction::Reward(transaction)) => transaction,
        _ => {
            return Err(BlockValidationFailure::Invalid(BlockInvalid::BodyStructure));
        }
    };
    let reward_context = RewardValidationContext {
        network: parameters.header.network,
        block_height: block.header.height,
        active_tx_version: parameters.active_transaction_version,
    };
    let structurally_validated_reward =
        validate_reward_transaction_structure(reward, reward_context)
            .map_err(map_reward_failure)?;
    if structurally_validated_reward.transaction_id != transaction_ids[0] {
        return Err(BlockValidationFailure::Local(
            BlockLocalFailure::InternalInvariant,
        ));
    }

    let regular_context = RegularValidationContext {
        network: parameters.header.network,
        block_height: block.header.height,
        active_tx_version: parameters.active_transaction_version,
        minimum_fee: parameters.minimum_fee,
    };
    let mut structurally_validated = Vec::with_capacity(transaction_ids.len().saturating_sub(1));
    for (index, transaction) in block.body.transactions.iter().enumerate().skip(1) {
        if !matches!(transaction, Transaction::Regular(_)) {
            return Err(BlockValidationFailure::Invalid(BlockInvalid::BodyStructure));
        }
        let index_u32 = checked_index(index)?;
        let validated =
            validate_regular_transaction_structure(&canonical_transactions[index], regular_context)
                .map_err(|failure| map_regular_failure(index_u32, failure))?;
        if validated.transaction_id != transaction_ids[index] {
            return Err(BlockValidationFailure::Local(
                BlockLocalFailure::InternalInvariant,
            ));
        }
        structurally_validated.push((index_u32, validated));
    }

    let mut authenticated = Vec::with_capacity(structurally_validated.len());
    for (index, transaction) in structurally_validated {
        let authenticated_transaction = verify_regular_transaction_signature(transaction)
            .map_err(|failure| map_regular_failure(index, failure))?;
        authenticated.push((index, authenticated_transaction));
    }

    let parent_state = parent_state.ok_or(BlockValidationFailure::Local(
        BlockLocalFailure::MissingParentState,
    ))?;
    let parent_accounts = prepare_parent_state(
        parent_state,
        validated_header.parent.block_id(),
        validated_header.parent.header().state_root,
    )
    .map_err(|error| BlockValidationFailure::Local(BlockLocalFailure::ParentState(error)))?;
    let mut resulting_accounts = parent_accounts.clone();
    let mut touched = BTreeSet::new();
    let mut total_fees = 0_u128;

    for (index, transaction) in &authenticated {
        let body = &transaction.transaction.body;
        let sender_before = account_or_empty(&resulting_accounts, body.sender);
        let recipient_before = account_or_empty(&resulting_accounts, body.recipient);
        let outcome = apply_regular(
            sender_before,
            recipient_before,
            RegularTransfer {
                sender: body.sender,
                recipient: body.recipient,
                nonce: body.nonce,
                amount: body.amount,
                fee: body.fee,
            },
            total_fees,
            parameters.minimum_fee,
        )
        .map_err(|error| {
            BlockValidationFailure::Invalid(BlockInvalid::Regular {
                index: *index,
                error: RegularInvalid::StateTransition(error),
            })
        })?;
        for change in outcome.changes {
            touched.insert(change.recipient);
            put_normalized_account(&mut resulting_accounts, change.recipient, change.account);
        }
        total_fees = outcome.fee_total;
    }

    let reward_recipient = reward.body.recipient;
    let reward_before = account_or_empty(&resulting_accounts, reward_recipient);
    let expected_subsidy = Amount::new(subsidy_at_height(block.header.height));
    let reward_outcome = apply_reward(
        reward_before,
        reward.body.subsidy,
        expected_subsidy,
        reward.body.fees,
        total_fees,
        parent_state.issued_supply,
    )
    .map_err(|error| {
        BlockValidationFailure::Invalid(BlockInvalid::Reward(RewardInvalid::StateTransition(error)))
    })?;
    touched.insert(reward_recipient);
    put_normalized_account(
        &mut resulting_accounts,
        reward_recipient,
        reward_outcome.account,
    );

    let resulting_supply = checked_balance_sum(&resulting_accounts).ok_or(
        BlockValidationFailure::Local(BlockLocalFailure::InternalInvariant),
    )?;
    if resulting_supply != reward_outcome.issued_supply {
        return Err(BlockValidationFailure::Local(
            BlockLocalFailure::InternalInvariant,
        ));
    }
    let resulting_pairs: Vec<_> = resulting_accounts
        .iter()
        .map(|(&recipient, &account)| (recipient, account))
        .collect();
    let resulting_state_root = compute_state_root(&resulting_pairs)
        .map_err(|error| BlockValidationFailure::Local(BlockLocalFailure::StateTree(error)))?;
    if resulting_state_root != block.header.state_root {
        return Err(BlockValidationFailure::Invalid(
            BlockInvalid::StateRootMismatch {
                expected: block.header.state_root,
                actual: resulting_state_root,
            },
        ));
    }

    let account_deltas = touched
        .into_iter()
        .filter_map(|recipient| {
            let before = account_or_empty(&parent_accounts, recipient);
            let after = account_or_empty(&resulting_accounts, recipient);
            (before != after).then_some(AccountDelta {
                recipient,
                before,
                after,
            })
        })
        .collect();
    Ok(ValidatedBlockCommit {
        canonical_block_bytes: reencoded,
        block,
        header: validated_header.child,
        transaction_ids,
        parent_state_root: validated_header.parent.header().state_root,
        resulting_state_root,
        resulting_accounts: resulting_pairs,
        account_deltas,
        total_fees,
        issued_supply: reward_outcome.issued_supply,
    })
}

fn prepare_parent_state(
    snapshot: ParentStateSnapshot<'_>,
    expected_anchor: BlockId,
    expected_root: StateRoot,
) -> Result<BTreeMap<Recipient, Account>, ParentStateLocalError> {
    if snapshot.anchor_block_id != expected_anchor {
        return Err(ParentStateLocalError::AnchorMismatch {
            expected: expected_anchor,
            actual: snapshot.anchor_block_id,
        });
    }
    if snapshot.issued_supply > u128::from(MAX_MONEY) {
        return Err(ParentStateLocalError::SupplyAboveMaximum(
            snapshot.issued_supply,
        ));
    }
    let mut accounts = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut balances = 0_u128;
    for &(recipient, account) in snapshot.accounts {
        if account.balance.get() > MAX_MONEY {
            return Err(ParentStateLocalError::BalanceAboveMaximum {
                recipient,
                balance: account.balance.get(),
            });
        }
        if !seen.insert(recipient) {
            return Err(ParentStateLocalError::DuplicateAccount(recipient));
        }
        balances = balances
            .checked_add(u128::from(account.balance.get()))
            .ok_or(ParentStateLocalError::MonetaryOverflow)?;
        if !account.is_absent() {
            accounts.insert(recipient, account);
        }
    }
    if balances != snapshot.issued_supply {
        return Err(ParentStateLocalError::SupplyDoesNotMatchBalances {
            supply: snapshot.issued_supply,
            balances,
        });
    }
    let pairs: Vec<_> = accounts
        .iter()
        .map(|(&recipient, &account)| (recipient, account))
        .collect();
    let actual_root = compute_state_root(&pairs).map_err(ParentStateLocalError::StateTree)?;
    if actual_root != expected_root {
        return Err(ParentStateLocalError::RootMismatch {
            expected: expected_root,
            actual: actual_root,
        });
    }
    Ok(accounts)
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

fn checked_index<E>(index: usize) -> Result<u32, BlockValidationFailure<E>> {
    u32::try_from(index)
        .map_err(|_| BlockValidationFailure::Local(BlockLocalFailure::InternalInvariant))
}

fn map_header_failure<E>(failure: ChildHeaderValidationFailure<E>) -> BlockValidationFailure<E> {
    match failure {
        ChildHeaderValidationFailure::Invalid(error) => {
            BlockValidationFailure::Invalid(BlockInvalid::Header(error))
        }
        ChildHeaderValidationFailure::TemporarilyUnacceptable(error) => {
            BlockValidationFailure::TemporarilyUnacceptable(error)
        }
        ChildHeaderValidationFailure::Local(error) => {
            BlockValidationFailure::Local(BlockLocalFailure::Header(error))
        }
    }
}

fn map_regular_failure<E>(
    index: u32,
    failure: RegularValidationFailure,
) -> BlockValidationFailure<E> {
    match failure {
        RegularValidationFailure::Invalid(error) => {
            BlockValidationFailure::Invalid(BlockInvalid::Regular { index, error })
        }
        RegularValidationFailure::Local(error) => {
            BlockValidationFailure::Local(BlockLocalFailure::Regular { index, error })
        }
    }
}

fn map_reward_failure<E>(failure: RewardValidationFailure) -> BlockValidationFailure<E> {
    match failure {
        RewardValidationFailure::Invalid(error) => {
            BlockValidationFailure::Invalid(BlockInvalid::Reward(error))
        }
        RewardValidationFailure::Local(error) => {
            BlockValidationFailure::Local(BlockLocalFailure::Reward(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use out_codec::{BlockBody, BlockHeader, RegularTransaction, RewardTransaction, Transaction};
    use out_primitives::{Nonce, U256Be};
    use out_state::TransitionError;

    use super::*;
    use crate::chain::{
        validate_pinned_genesis_header, ValidatedHeaderMetadata, ValidatedHeaderView,
    };
    use crate::{pow_hash_from_header_bytes, pow_hash_meets_target, DEVNET_POW_LIMIT_V0};

    const VECTOR_TRANSACTION_HEX: &str = "0000000000bc0000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a70003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b800000000000000000029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000075bcd1500000000000003e8000000000000000100000000000003e8000a4f555420766563746f720062000003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b84db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b";
    const VECTOR_REWARD_HEX: &str = "0001000000810000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000010003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8000000001dcd650000000000000003e800000000";
    const VECTOR_HEADER_HEX: &str = "000000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a937280000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda2fb959f81d652879472f8c56076e63a2fb3587dda94754f316328e7ec431403d30a2588a2f688edd9b29af2bb3b522db2deb731709dbfb53fadefab69c21470000000000000ac5";

    #[derive(Default)]
    struct MemoryView(BTreeMap<BlockId, ValidatedHeaderMetadata>);

    impl ValidatedHeaderView for MemoryView {
        type Error = &'static str;

        fn get_validated_header(
            &self,
            block_id: BlockId,
        ) -> Result<Option<ValidatedHeaderMetadata>, Self::Error> {
            Ok(self.0.get(&block_id).copied())
        }
    }

    struct Fixture {
        raw: Vec<u8>,
        view: MemoryView,
        parent: ValidatedHeaderMetadata,
        accounts: Vec<(Recipient, Account)>,
        ancestry: BTreeSet<TransactionId>,
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

    fn hex_32(input: &str) -> [u8; 32] {
        hex(input).try_into().expect("32-byte hex")
    }

    fn mine(mut header: BlockHeader) -> BlockHeader {
        header.nonce = 0;
        loop {
            let hash = pow_hash_from_header_bytes(&header.encode());
            if pow_hash_meets_target(hash, header.target) {
                return header;
            }
            header.nonce = header.nonce.checked_add(1).expect("test nonce space");
        }
    }

    fn build_fixture(
        parent_balance: u64,
        declared_reward_fees: u64,
        claimed_state_root: StateRoot,
    ) -> Fixture {
        let regular =
            RegularTransaction::decode_exact(&hex(VECTOR_TRANSACTION_HEX)).expect("regular");
        let mut reward = RewardTransaction::decode_exact(&hex(VECTOR_REWARD_HEX)).expect("reward");
        reward.body.fees = Amount::new(declared_reward_fees);
        let sender = regular.body.sender;
        let accounts = vec![(
            sender,
            Account::new(Amount::new(parent_balance), Nonce::ZERO),
        )];
        let parent_root = compute_state_root(&accounts).expect("parent root");

        let mut parent_header = BlockHeader::decode_exact(&hex(VECTOR_HEADER_HEX)).expect("header");
        parent_header.state_root = parent_root;
        parent_header = mine(parent_header);
        let parent = validate_pinned_genesis_header(
            parent_header,
            parent_header,
            HeaderChainParameters::devnet_v0(),
        )
        .expect("test parent");
        let mut view = MemoryView::default();
        view.0.insert(parent.block_id(), parent);

        let body = BlockBody {
            transactions: vec![Transaction::Reward(reward), Transaction::Regular(regular)],
        };
        let transaction_ids: Vec<_> = body
            .transactions
            .iter()
            .map(|transaction| {
                transaction_id_from_canonical_bytes(&transaction.encode().expect("transaction"))
            })
            .collect();
        let transaction_root = transaction_merkle_root(&transaction_ids).expect("merkle root");
        let parent_fields = parent.header();
        let child_header = mine(BlockHeader {
            consensus_version: 0,
            chain_id: parent_fields.chain_id,
            network_id: parent_fields.network_id,
            genesis_commitment: parent_fields.genesis_commitment,
            height: 1,
            parent_block_id: parent.block_id(),
            timestamp: parent_fields.timestamp + 1,
            target: DEVNET_POW_LIMIT_V0,
            transaction_root,
            state_root: claimed_state_root,
            nonce: 0,
        });
        let block = Block {
            header: child_header,
            body,
        };
        Fixture {
            raw: block.encode_non_genesis().expect("block"),
            view,
            parent,
            accounts,
            ancestry: BTreeSet::new(),
        }
    }

    fn valid_fixture() -> Fixture {
        build_fixture(
            1_000_000_000,
            1_000,
            StateRoot::new(hex_32(
                "25484208231a78f132d97102067e49ddd3bf1fe904212116af2af81fa47923aa",
            )),
        )
    }

    fn replace_body(fixture: &mut Fixture, body: BlockBody) {
        let transaction_ids: Vec<_> = body
            .transactions
            .iter()
            .map(|transaction| {
                transaction_id_from_canonical_bytes(&transaction.encode().expect("transaction"))
            })
            .collect();
        let transaction_root = transaction_merkle_root(&transaction_ids).expect("merkle root");
        let mut block = Block::decode_non_genesis_exact(&fixture.raw).expect("block");
        block.header.transaction_root = transaction_root;
        block.header = mine(block.header);
        block.body = body;
        fixture.raw = block.encode_non_genesis().expect("block");
    }

    fn validate(fixture: &Fixture) -> Result<ValidatedBlockCommit, BlockValidationFailure<&str>> {
        validate_non_genesis_block(
            &fixture.raw,
            &fixture.view,
            Some(ParentStateSnapshot {
                anchor_block_id: fixture.parent.block_id(),
                accounts: &fixture.accounts,
                issued_supply: u128::from(fixture.accounts[0].1.balance.get()),
            }),
            Some(AncestorTransactionSnapshot {
                anchor_block_id: fixture.parent.block_id(),
                confirmed_transaction_ids: &fixture.ancestry,
            }),
            fixture.parent.header().timestamp + 1,
            BlockValidationParameters::devnet_v0(),
        )
    }

    #[test]
    fn complete_block_validation_matches_verified_transition() {
        let fixture = valid_fixture();
        let commit = validate(&fixture).expect("valid block");
        assert_eq!(commit.canonical_block_bytes, fixture.raw);
        assert_eq!(commit.header.header().height, 1);
        assert_eq!(commit.transaction_ids.len(), 2);
        assert_eq!(commit.total_fees, 1_000);
        assert_eq!(commit.issued_supply, 1_500_000_000);
        assert_eq!(
            commit.resulting_state_root.into_bytes(),
            hex_32("25484208231a78f132d97102067e49ddd3bf1fe904212116af2af81fa47923aa")
        );
        assert_eq!(commit.account_deltas.len(), 2);
        assert!(commit.account_deltas[0].recipient < commit.account_deltas[1].recipient);
        assert_eq!(commit.account_deltas[0].before, fixture.accounts[0].1);
        assert_eq!(
            commit.account_deltas[0].after,
            commit.resulting_accounts[0].1
        );
        assert_eq!(
            commit.resulting_accounts[0].1,
            Account::new(Amount::new(1_376_543_211), Nonce::new(1))
        );
        assert_eq!(
            commit.resulting_accounts[1].1,
            Account::new(Amount::new(123_456_789), Nonce::ZERO)
        );
        let mut cumulative = [0_u8; 32];
        cumulative[30..].copy_from_slice(&8_192_u16.to_be_bytes());
        assert_eq!(commit.header.cumulative_work(), U256Be::new(cumulative));
    }

    #[test]
    fn malformed_and_duplicate_ancestor_transactions_fail_before_state() {
        let fixture = valid_fixture();
        let mut trailing = fixture.raw.clone();
        trailing.push(0);
        assert_eq!(
            validate_non_genesis_block(
                &trailing,
                &fixture.view,
                None,
                None,
                fixture.parent.header().timestamp + 1,
                BlockValidationParameters::devnet_v0()
            ),
            Err(BlockValidationFailure::Invalid(
                BlockInvalid::CanonicalEncoding(DecodeError::TrailingBytes)
            ))
        );

        let mut duplicate_fixture = valid_fixture();
        let block = Block::decode_non_genesis_exact(&duplicate_fixture.raw).expect("block");
        let regular_id = transaction_id_from_canonical_bytes(
            &block.body.transactions[1].encode().expect("regular"),
        );
        duplicate_fixture.ancestry.insert(regular_id);
        assert_eq!(
            validate(&duplicate_fixture),
            Err(BlockValidationFailure::Invalid(
                BlockInvalid::AncestorDuplicate {
                    index: 1,
                    transaction_id: regular_id
                }
            ))
        );
    }

    #[test]
    fn missing_or_mismatched_parent_state_is_local() {
        let fixture = valid_fixture();
        assert_eq!(
            validate_non_genesis_block(
                &fixture.raw,
                &fixture.view,
                None,
                Some(AncestorTransactionSnapshot {
                    anchor_block_id: fixture.parent.block_id(),
                    confirmed_transaction_ids: &fixture.ancestry
                }),
                fixture.parent.header().timestamp + 1,
                BlockValidationParameters::devnet_v0()
            ),
            Err(BlockValidationFailure::Local(
                BlockLocalFailure::MissingParentState
            ))
        );

        let wrong_accounts = [(
            fixture.accounts[0].0,
            Account::new(Amount::new(999_999_999), Nonce::ZERO),
        )];
        let actual = compute_state_root(&wrong_accounts).expect("wrong root");
        assert_eq!(
            validate_non_genesis_block(
                &fixture.raw,
                &fixture.view,
                Some(ParentStateSnapshot {
                    anchor_block_id: fixture.parent.block_id(),
                    accounts: &wrong_accounts,
                    issued_supply: 999_999_999
                }),
                Some(AncestorTransactionSnapshot {
                    anchor_block_id: fixture.parent.block_id(),
                    confirmed_transaction_ids: &fixture.ancestry
                }),
                fixture.parent.header().timestamp + 1,
                BlockValidationParameters::devnet_v0()
            ),
            Err(BlockValidationFailure::Local(
                BlockLocalFailure::ParentState(ParentStateLocalError::RootMismatch {
                    expected: fixture.parent.header().state_root,
                    actual
                })
            ))
        );
    }

    #[test]
    fn state_transition_and_reward_failures_do_not_mutate_parent_snapshot() {
        let insufficient = build_fixture(
            1,
            1_000,
            StateRoot::new(hex_32(
                "25484208231a78f132d97102067e49ddd3bf1fe904212116af2af81fa47923aa",
            )),
        );
        let before = insufficient.accounts.clone();
        assert_eq!(
            validate(&insufficient),
            Err(BlockValidationFailure::Invalid(BlockInvalid::Regular {
                index: 1,
                error: RegularInvalid::StateTransition(TransitionError::InsufficientFunds)
            }))
        );
        assert_eq!(insufficient.accounts, before);

        let wrong_reward = build_fixture(
            1_000_000_000,
            999,
            StateRoot::new(hex_32(
                "25484208231a78f132d97102067e49ddd3bf1fe904212116af2af81fa47923aa",
            )),
        );
        let before = wrong_reward.accounts.clone();
        assert_eq!(
            validate(&wrong_reward),
            Err(BlockValidationFailure::Invalid(BlockInvalid::Reward(
                RewardInvalid::StateTransition(TransitionError::RewardMismatch)
            )))
        );
        assert_eq!(wrong_reward.accounts, before);
    }

    #[test]
    fn resulting_state_root_must_match_header() {
        let claimed = StateRoot::new([9; 32]);
        let fixture = build_fixture(1_000_000_000, 1_000, claimed);
        assert_eq!(
            validate(&fixture),
            Err(BlockValidationFailure::Invalid(
                BlockInvalid::StateRootMismatch {
                    expected: claimed,
                    actual: StateRoot::new(hex_32(
                        "25484208231a78f132d97102067e49ddd3bf1fe904212116af2af81fa47923aa"
                    ))
                }
            ))
        );
    }

    #[test]
    fn every_transaction_structure_is_checked_before_signature_equations() {
        let mut fixture = valid_fixture();
        let block = Block::decode_non_genesis_exact(&fixture.raw).expect("block");
        let reward = block.body.transactions[0].clone();
        let mut bad_signature = match block.body.transactions[1].clone() {
            Transaction::Regular(transaction) => transaction,
            Transaction::Reward(_) => panic!("fixture regular"),
        };
        bad_signature.auth.signature[63] ^= 1;
        let mut wrong_network = match block.body.transactions[1].clone() {
            Transaction::Regular(transaction) => transaction,
            Transaction::Reward(_) => panic!("fixture regular"),
        };
        wrong_network.body.network_id = out_primitives::TESTNET_NETWORK_ID;
        replace_body(
            &mut fixture,
            BlockBody {
                transactions: vec![
                    reward,
                    Transaction::Regular(bad_signature),
                    Transaction::Regular(wrong_network),
                ],
            },
        );
        assert_eq!(
            validate(&fixture),
            Err(BlockValidationFailure::Invalid(BlockInvalid::Regular {
                index: 2,
                error: RegularInvalid::Identity(crate::IdentityError::NetworkId)
            }))
        );
    }
}
