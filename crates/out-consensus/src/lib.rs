#![forbid(unsafe_code)]

pub mod block;
pub mod chain;

use std::collections::BTreeSet;

use out_codec::{
    BlockBody, BlockHeader, DecodeError, EncodeError, RegularTransaction, RewardTransaction,
    MAX_TXS_PER_BLOCK,
};
use out_crypto::{
    Blake3Hasher, ConsensusDomain, ConsensusHasher, DalekStrictVerifier, SignatureError,
    StrictEd25519Verifier,
};
use out_primitives::{
    Amount, BlockId, ChainId, GenesisCommitment, Hash32, NetworkId, TransactionId, TransactionRoot,
    U256ArithmeticError, U256Be, DEVNET_NETWORK_ID, OUT_CHAIN_ID, TESTNET_NETWORK_ID,
};
use out_state::{
    apply_regular, apply_reward, subsidy_at_height, Account, RegularOutcome, RegularTransfer,
    RewardOutcome, TransitionError,
};

pub const DEVNET_GENESIS_COMMITMENT: GenesisCommitment = GenesisCommitment::new([
    0xba, 0xa2, 0x6e, 0x3b, 0xdd, 0xa0, 0xa7, 0xb3, 0x19, 0x6e, 0x89, 0x36, 0x7f, 0x32, 0xa9, 0xd0,
    0x55, 0x58, 0xea, 0x5e, 0xa1, 0x96, 0x87, 0x5f, 0x30, 0x88, 0x0f, 0x05, 0x5e, 0x52, 0x26, 0xa7,
]);
pub const TESTNET_GENESIS_COMMITMENT: GenesisCommitment = GenesisCommitment::new([
    0x2a, 0x0c, 0xd6, 0x92, 0x18, 0x65, 0xd4, 0x51, 0x4f, 0x26, 0x4c, 0xd9, 0x6e, 0xd3, 0xf8, 0xfb,
    0x05, 0xdb, 0xa5, 0x05, 0x74, 0x7f, 0x74, 0x12, 0xe4, 0x03, 0x56, 0x0a, 0x72, 0xa7, 0xeb, 0xe6,
]);
pub const TARGET_SPACING_V0: u64 = 60;
pub const RETARGET_WINDOW_V0: u32 = 720;
pub const RETARGET_DOWN_NUMERATOR_V0: u32 = 1;
pub const RETARGET_DOWN_DENOMINATOR_V0: u32 = 4;
pub const RETARGET_UP_NUMERATOR_V0: u32 = 4;
pub const RETARGET_UP_DENOMINATOR_V0: u32 = 1;
pub const MEDIAN_TIME_WINDOW_V0: u16 = 11;
pub const MAX_FUTURE_DRIFT_V0: u64 = 7_200;
pub const TESTNET_DELAYED_MINIMUM_THRESHOLD_V0: u64 = 1_200;
pub const DEVNET_POW_LIMIT_V0: U256Be = U256Be::new([
    0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
]);
pub const TESTNET_POW_LIMIT_V0: U256Be = U256Be::new([
    0x00, 0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkIdentity {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub genesis_commitment: GenesisCommitment,
}

impl NetworkIdentity {
    pub const fn testnet() -> Self {
        Self {
            chain_id: OUT_CHAIN_ID,
            network_id: TESTNET_NETWORK_ID,
            genesis_commitment: TESTNET_GENESIS_COMMITMENT,
        }
    }
    pub const fn devnet() -> Self {
        Self {
            chain_id: OUT_CHAIN_ID,
            network_id: DEVNET_NETWORK_ID,
            genesis_commitment: DEVNET_GENESIS_COMMITMENT,
        }
    }
    pub fn require_exact(self, actual: Self) -> Result<(), IdentityError> {
        if self.chain_id != actual.chain_id {
            return Err(IdentityError::ChainId);
        }
        if self.network_id != actual.network_id {
            return Err(IdentityError::NetworkId);
        }
        if self.genesis_commitment != actual.genesis_commitment {
            return Err(IdentityError::GenesisCommitment);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    ChainId,
    NetworkId,
    GenesisCommitment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegularValidationContext {
    pub network: NetworkIdentity,
    pub block_height: u64,
    pub active_tx_version: u16,
    pub minimum_fee: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructurallyValidatedRegularTransaction {
    pub transaction: RegularTransaction,
    pub signing_digest: Hash32,
    pub transaction_id: TransactionId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedRegularTransaction {
    pub transaction: RegularTransaction,
    pub signing_digest: Hash32,
    pub transaction_id: TransactionId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedRegularTransaction {
    pub authenticated: AuthenticatedRegularTransaction,
    pub outcome: RegularOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegularInvalid {
    CanonicalEncoding(DecodeError),
    Identity(IdentityError),
    InactiveTransactionVersion {
        expected: u16,
        actual: u16,
    },
    HeightOutsideInterval {
        block_height: u64,
        valid_from: u64,
        expires_at: u64,
    },
    PublicKey(SignatureError),
    SenderKeyMismatch,
    SignatureEncoding(SignatureError),
    Signature(SignatureError),
    StateTransition(TransitionError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegularLocalFailure {
    CanonicalReencoding(EncodeError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegularValidationFailure {
    Invalid(RegularInvalid),
    Local(RegularLocalFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleError {
    EmptyNonGenesis,
    TooManyTransactions { actual: usize, maximum: usize },
    DuplicateTransactionId(TransactionId),
    SizeOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedBlockBody {
    pub body: BlockBody,
    pub transaction_ids: Vec<TransactionId>,
    pub transaction_root: TransactionRoot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockBodyInvalid {
    CanonicalEncoding(DecodeError),
    Merkle(MerkleError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockBodyLocalFailure {
    CanonicalReencoding(EncodeError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockBodyValidationFailure {
    Invalid(BlockBodyInvalid),
    Local(BlockBodyLocalFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RewardValidationContext {
    pub network: NetworkIdentity,
    pub block_height: u64,
    pub active_tx_version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedRewardTransaction {
    pub transaction_id: TransactionId,
    pub outcome: RewardOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructurallyValidatedRewardTransaction {
    pub transaction_id: TransactionId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RewardInvalid {
    RewardInGenesis,
    Identity(IdentityError),
    InactiveTransactionVersion { expected: u16, actual: u16 },
    HeightMismatch { expected: u64, actual: u64 },
    RecipientKey(SignatureError),
    StateTransition(TransitionError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RewardLocalFailure {
    CanonicalReencoding(EncodeError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RewardValidationFailure {
    Invalid(RewardInvalid),
    Local(RewardLocalFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderPowContext {
    pub network: NetworkIdentity,
    pub active_consensus_version: u16,
    pub pow_limit: U256Be,
    pub required_target: U256Be,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderPowResult {
    pub block_id: BlockId,
    pub pow_hash: Hash32,
    pub pow_value: U256Be,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderPowInvalid {
    Identity(IdentityError),
    InactiveConsensusVersion { expected: u16, actual: u16 },
    ZeroTarget,
    TargetAbovePowLimit,
    UnexpectedTarget,
    PowAboveTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderPowLocalFailure {
    InvalidPowParameters,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderPowValidationFailure {
    Invalid(HeaderPowInvalid),
    Local(HeaderPowLocalFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkError {
    ZeroTarget,
    Arithmetic(U256ArithmeticError),
    CumulativeOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimestampAcceptance {
    pub median_time_past: u64,
    /// Mathematical upper bound. This may be greater than `u64::MAX`.
    pub future_limit: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampInvalid {
    NotAfterMedian {
        candidate: u64,
        median_time_past: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampTemporaryFailure {
    TooFarFuture { candidate: u64, future_limit: u128 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampLocalFailure {
    InvalidMedianWindow,
    MissingParentHistory,
    ExcessParentHistory { actual: usize, maximum: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampValidationFailure {
    Invalid(TimestampInvalid),
    TemporarilyUnacceptable(TimestampTemporaryFailure),
    Local(TimestampLocalFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowTargetMode {
    StandardEpoch,
    DevelopmentFixed,
    TestnetDelayedMinimum { threshold: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DifficultyParameters {
    pub pow_limit: U256Be,
    pub genesis_target: U256Be,
    pub target_spacing: u64,
    pub retarget_window: u32,
    pub down_numerator: u32,
    pub down_denominator: u32,
    pub up_numerator: u32,
    pub up_denominator: u32,
    pub mode: PowTargetMode,
}

impl DifficultyParameters {
    pub const fn devnet_v0() -> Self {
        Self {
            pow_limit: DEVNET_POW_LIMIT_V0,
            genesis_target: DEVNET_POW_LIMIT_V0,
            target_spacing: TARGET_SPACING_V0,
            retarget_window: RETARGET_WINDOW_V0,
            down_numerator: RETARGET_DOWN_NUMERATOR_V0,
            down_denominator: RETARGET_DOWN_DENOMINATOR_V0,
            up_numerator: RETARGET_UP_NUMERATOR_V0,
            up_denominator: RETARGET_UP_DENOMINATOR_V0,
            mode: PowTargetMode::DevelopmentFixed,
        }
    }

    pub const fn testnet_v0() -> Self {
        Self {
            pow_limit: TESTNET_POW_LIMIT_V0,
            genesis_target: TESTNET_POW_LIMIT_V0,
            target_spacing: TARGET_SPACING_V0,
            retarget_window: RETARGET_WINDOW_V0,
            down_numerator: RETARGET_DOWN_NUMERATOR_V0,
            down_denominator: RETARGET_DOWN_DENOMINATOR_V0,
            up_numerator: RETARGET_UP_NUMERATOR_V0,
            up_denominator: RETARGET_UP_DENOMINATOR_V0,
            mode: PowTargetMode::TestnetDelayedMinimum {
                threshold: TESTNET_DELAYED_MINIMUM_THRESHOLD_V0,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetargetSpan {
    pub expected: u128,
    pub raw_actual: u128,
    pub lower: u128,
    pub upper: u128,
    pub clamped_actual: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DifficultyError {
    ZeroPowLimit,
    ZeroGenesisTarget,
    GenesisTargetAbovePowLimit,
    InvalidWindow,
    ZeroTargetSpacing,
    ZeroClampDenominator,
    InvalidClamp,
    FixedTargetMismatch,
    DelayedMinimumTargetMismatch,
    ZeroDelayedMinimumThreshold,
    InvalidBaseTarget,
    GenesisHasNoPriorEpoch,
    ArithmeticOverflow,
    TargetArithmetic(U256ArithmeticError),
}

pub fn exact_block_work(target: U256Be) -> Result<U256Be, WorkError> {
    target.exact_work().map_err(|error| match error {
        U256ArithmeticError::ZeroTarget => WorkError::ZeroTarget,
        other => WorkError::Arithmetic(other),
    })
}

pub fn checked_cumulative_work(
    parent_cumulative_work: U256Be,
    target: U256Be,
) -> Result<U256Be, WorkError> {
    let work = exact_block_work(target)?;
    parent_cumulative_work
        .checked_add(work)
        .map_err(|error| match error {
            U256ArithmeticError::Overflow => WorkError::CumulativeOverflow,
            other => WorkError::Arithmetic(other),
        })
}

pub fn validate_candidate_timestamp(
    candidate: u64,
    parent_timestamps: &[u64],
    local_now: u64,
    median_window: u16,
    future_drift: u64,
) -> Result<TimestampAcceptance, TimestampValidationFailure> {
    if median_window < 3 || median_window.is_multiple_of(2) {
        return Err(TimestampValidationFailure::Local(
            TimestampLocalFailure::InvalidMedianWindow,
        ));
    }
    let maximum = usize::from(median_window);
    if parent_timestamps.is_empty() {
        return Err(TimestampValidationFailure::Local(
            TimestampLocalFailure::MissingParentHistory,
        ));
    }
    if parent_timestamps.len() > maximum {
        return Err(TimestampValidationFailure::Local(
            TimestampLocalFailure::ExcessParentHistory {
                actual: parent_timestamps.len(),
                maximum,
            },
        ));
    }

    let mut sorted = parent_timestamps.to_vec();
    sorted.sort_unstable();
    let median_time_past = sorted[sorted.len() / 2];
    if candidate <= median_time_past {
        return Err(TimestampValidationFailure::Invalid(
            TimestampInvalid::NotAfterMedian {
                candidate,
                median_time_past,
            },
        ));
    }

    let future_limit = u128::from(local_now) + u128::from(future_drift);
    if u128::from(candidate) > future_limit {
        return Err(TimestampValidationFailure::TemporarilyUnacceptable(
            TimestampTemporaryFailure::TooFarFuture {
                candidate,
                future_limit,
            },
        ));
    }
    Ok(TimestampAcceptance {
        median_time_past,
        future_limit,
    })
}

pub fn epoch_at_height(height: u64, retarget_window: u32) -> Result<u64, DifficultyError> {
    if retarget_window < 2 {
        return Err(DifficultyError::InvalidWindow);
    }
    Ok(height / u64::from(retarget_window))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorEpochHeights {
    pub first: u64,
    pub last: u64,
}

pub fn prior_epoch_heights(
    epoch: u64,
    retarget_window: u32,
) -> Result<PriorEpochHeights, DifficultyError> {
    if retarget_window < 2 {
        return Err(DifficultyError::InvalidWindow);
    }
    let previous_epoch = epoch
        .checked_sub(1)
        .ok_or(DifficultyError::GenesisHasNoPriorEpoch)?;
    let window = u64::from(retarget_window);
    let first = previous_epoch
        .checked_mul(window)
        .ok_or(DifficultyError::ArithmeticOverflow)?;
    let last = epoch
        .checked_mul(window)
        .and_then(|height| height.checked_sub(1))
        .ok_or(DifficultyError::ArithmeticOverflow)?;
    Ok(PriorEpochHeights { first, last })
}

pub fn retarget_span(
    first_timestamp: u64,
    last_timestamp: u64,
    parameters: DifficultyParameters,
) -> Result<RetargetSpan, DifficultyError> {
    validate_difficulty_parameters(parameters)?;
    let expected = u128::from(parameters.retarget_window - 1)
        .checked_mul(u128::from(parameters.target_spacing))
        .ok_or(DifficultyError::ArithmeticOverflow)?;
    let raw_actual = if last_timestamp > first_timestamp {
        u128::from(last_timestamp - first_timestamp)
    } else {
        1
    };
    let lower_numerator = expected
        .checked_mul(u128::from(parameters.down_numerator))
        .ok_or(DifficultyError::ArithmeticOverflow)?;
    let lower = checked_ceil_div(lower_numerator, u128::from(parameters.down_denominator))?;
    let upper_numerator = expected
        .checked_mul(u128::from(parameters.up_numerator))
        .ok_or(DifficultyError::ArithmeticOverflow)?;
    let upper = upper_numerator / u128::from(parameters.up_denominator);
    if lower == 0 || lower > upper {
        return Err(DifficultyError::InvalidClamp);
    }
    Ok(RetargetSpan {
        expected,
        raw_actual,
        lower,
        upper,
        clamped_actual: raw_actual.clamp(lower, upper),
    })
}

pub fn retarget_epoch_target(
    previous_epoch_target: U256Be,
    first_timestamp: u64,
    last_timestamp: u64,
    parameters: DifficultyParameters,
) -> Result<U256Be, DifficultyError> {
    validate_difficulty_parameters(parameters)?;
    if matches!(parameters.mode, PowTargetMode::DevelopmentFixed) {
        return Ok(parameters.genesis_target);
    }
    require_valid_base_target(previous_epoch_target, parameters.pow_limit)?;
    let span = retarget_span(first_timestamp, last_timestamp, parameters)?;
    let mut candidate =
        match previous_epoch_target.checked_mul_div_u128(span.clamped_actual, span.expected) {
            Ok(candidate) => candidate,
            // The mathematical quotient is above 2^256-1 and therefore also above
            // every encodable pow limit. The specified result is the pow limit.
            Err(U256ArithmeticError::NarrowingOverflow) => parameters.pow_limit,
            Err(error) => return Err(DifficultyError::TargetArithmetic(error)),
        };
    if candidate.is_zero() {
        candidate = U256Be::ONE;
    }
    if candidate > parameters.pow_limit {
        candidate = parameters.pow_limit;
    }
    Ok(candidate)
}

pub fn required_target_for_candidate(
    epoch_base_target: U256Be,
    candidate_timestamp: u64,
    parent_timestamp: u64,
    parameters: DifficultyParameters,
) -> Result<U256Be, DifficultyError> {
    validate_difficulty_parameters(parameters)?;
    match parameters.mode {
        PowTargetMode::DevelopmentFixed => Ok(parameters.genesis_target),
        PowTargetMode::StandardEpoch => {
            require_valid_base_target(epoch_base_target, parameters.pow_limit)?;
            Ok(epoch_base_target)
        }
        PowTargetMode::TestnetDelayedMinimum { threshold } => {
            require_valid_base_target(epoch_base_target, parameters.pow_limit)?;
            let deadline = u128::from(parent_timestamp) + u128::from(threshold);
            if u128::from(candidate_timestamp) > deadline {
                Ok(parameters.pow_limit)
            } else {
                Ok(epoch_base_target)
            }
        }
    }
}

fn validate_difficulty_parameters(parameters: DifficultyParameters) -> Result<(), DifficultyError> {
    if parameters.pow_limit.is_zero() {
        return Err(DifficultyError::ZeroPowLimit);
    }
    if parameters.genesis_target.is_zero() {
        return Err(DifficultyError::ZeroGenesisTarget);
    }
    if parameters.genesis_target > parameters.pow_limit {
        return Err(DifficultyError::GenesisTargetAbovePowLimit);
    }
    if parameters.retarget_window < 2 {
        return Err(DifficultyError::InvalidWindow);
    }
    if parameters.target_spacing == 0 {
        return Err(DifficultyError::ZeroTargetSpacing);
    }
    if parameters.down_denominator == 0 || parameters.up_denominator == 0 {
        return Err(DifficultyError::ZeroClampDenominator);
    }
    let expected = u128::from(parameters.retarget_window - 1)
        .checked_mul(u128::from(parameters.target_spacing))
        .ok_or(DifficultyError::ArithmeticOverflow)?;
    let lower_numerator = expected
        .checked_mul(u128::from(parameters.down_numerator))
        .ok_or(DifficultyError::ArithmeticOverflow)?;
    let lower = checked_ceil_div(lower_numerator, u128::from(parameters.down_denominator))?;
    let upper_numerator = expected
        .checked_mul(u128::from(parameters.up_numerator))
        .ok_or(DifficultyError::ArithmeticOverflow)?;
    let upper = upper_numerator / u128::from(parameters.up_denominator);
    if lower == 0 || lower > upper {
        return Err(DifficultyError::InvalidClamp);
    }
    match parameters.mode {
        PowTargetMode::StandardEpoch => {}
        PowTargetMode::DevelopmentFixed => {
            if parameters.genesis_target != parameters.pow_limit {
                return Err(DifficultyError::FixedTargetMismatch);
            }
        }
        PowTargetMode::TestnetDelayedMinimum { threshold } => {
            if parameters.genesis_target != parameters.pow_limit {
                return Err(DifficultyError::DelayedMinimumTargetMismatch);
            }
            if threshold == 0 {
                return Err(DifficultyError::ZeroDelayedMinimumThreshold);
            }
        }
    }
    Ok(())
}

fn require_valid_base_target(target: U256Be, pow_limit: U256Be) -> Result<(), DifficultyError> {
    if target.is_zero() || target > pow_limit {
        return Err(DifficultyError::InvalidBaseTarget);
    }
    Ok(())
}

fn checked_ceil_div(numerator: u128, denominator: u128) -> Result<u128, DifficultyError> {
    if denominator == 0 {
        return Err(DifficultyError::ZeroClampDenominator);
    }
    let quotient = numerator / denominator;
    let increment = u128::from(!numerator.is_multiple_of(denominator));
    quotient
        .checked_add(increment)
        .ok_or(DifficultyError::ArithmeticOverflow)
}

pub fn transaction_id_from_canonical_bytes(raw: &[u8]) -> TransactionId {
    TransactionId::new(
        Blake3Hasher
            .hash_32(ConsensusDomain::TransactionId, raw)
            .into_bytes(),
    )
}

pub fn indexed_transaction_leaf(index: u32, transaction_id: TransactionId) -> Hash32 {
    let mut material = [0_u8; 38];
    material[0] = 0;
    material[1] = 1;
    material[2..6].copy_from_slice(&index.to_be_bytes());
    material[6..].copy_from_slice(transaction_id.as_bytes());
    Blake3Hasher.hash_32(ConsensusDomain::TransactionMerkleLeaf, &material)
}

pub fn genesis_empty_transaction_root() -> TransactionRoot {
    let material = [0_u8, 2, 0, 0, 0, 0];
    TransactionRoot::new(
        Blake3Hasher
            .hash_32(ConsensusDomain::TransactionMerkleLeaf, &material)
            .into_bytes(),
    )
}

pub fn transaction_merkle_root(
    transaction_ids: &[TransactionId],
) -> Result<TransactionRoot, MerkleError> {
    if transaction_ids.is_empty() {
        return Err(MerkleError::EmptyNonGenesis);
    }
    let maximum = usize::try_from(MAX_TXS_PER_BLOCK).map_err(|_| MerkleError::SizeOverflow)?;
    if transaction_ids.len() > maximum {
        return Err(MerkleError::TooManyTransactions {
            actual: transaction_ids.len(),
            maximum,
        });
    }

    let mut seen = BTreeSet::new();
    for &transaction_id in transaction_ids {
        if !seen.insert(transaction_id) {
            return Err(MerkleError::DuplicateTransactionId(transaction_id));
        }
    }

    let leaf_count = transaction_ids
        .len()
        .checked_next_power_of_two()
        .ok_or(MerkleError::SizeOverflow)?;
    let mut nodes = Vec::with_capacity(leaf_count);
    for index in 0..leaf_count {
        let index_u32 = u32::try_from(index).map_err(|_| MerkleError::SizeOverflow)?;
        if let Some(&transaction_id) = transaction_ids.get(index) {
            nodes.push(indexed_transaction_leaf(index_u32, transaction_id));
        } else {
            nodes.push(padding_transaction_leaf(index_u32));
        }
    }

    let mut level = 1_u16;
    while nodes.len() > 1 {
        let pairs = nodes.as_slice().as_chunks::<2>().0;
        let mut parents = Vec::with_capacity(pairs.len());
        for [left, right] in pairs {
            parents.push(transaction_merkle_node(level, *left, *right));
        }
        nodes = parents;
        level = level.checked_add(1).ok_or(MerkleError::SizeOverflow)?;
    }
    let root = nodes.first().copied().ok_or(MerkleError::SizeOverflow)?;
    Ok(TransactionRoot::new(root.into_bytes()))
}

pub fn validate_non_genesis_block_body(
    raw: &[u8],
) -> Result<ValidatedBlockBody, BlockBodyValidationFailure> {
    let body = BlockBody::decode_non_genesis_exact(raw).map_err(|error| {
        BlockBodyValidationFailure::Invalid(BlockBodyInvalid::CanonicalEncoding(error))
    })?;
    let mut transaction_ids = Vec::with_capacity(body.transactions.len());
    for transaction in &body.transactions {
        let encoded = transaction.encode().map_err(|error| {
            BlockBodyValidationFailure::Local(BlockBodyLocalFailure::CanonicalReencoding(error))
        })?;
        transaction_ids.push(transaction_id_from_canonical_bytes(&encoded));
    }
    let transaction_root = transaction_merkle_root(&transaction_ids)
        .map_err(|error| BlockBodyValidationFailure::Invalid(BlockBodyInvalid::Merkle(error)))?;
    Ok(ValidatedBlockBody {
        body,
        transaction_ids,
        transaction_root,
    })
}

pub fn validate_reward_transaction_structure(
    transaction: &RewardTransaction,
    context: RewardValidationContext,
) -> Result<StructurallyValidatedRewardTransaction, RewardValidationFailure> {
    if context.block_height == 0 {
        return Err(RewardValidationFailure::Invalid(
            RewardInvalid::RewardInGenesis,
        ));
    }
    let actual_identity = NetworkIdentity {
        chain_id: transaction.body.chain_id,
        network_id: transaction.body.network_id,
        genesis_commitment: transaction.body.genesis_commitment,
    };
    context
        .network
        .require_exact(actual_identity)
        .map_err(|error| RewardValidationFailure::Invalid(RewardInvalid::Identity(error)))?;
    if transaction.body.tx_version != context.active_tx_version {
        return Err(RewardValidationFailure::Invalid(
            RewardInvalid::InactiveTransactionVersion {
                expected: context.active_tx_version,
                actual: transaction.body.tx_version,
            },
        ));
    }
    if transaction.body.height != context.block_height {
        return Err(RewardValidationFailure::Invalid(
            RewardInvalid::HeightMismatch {
                expected: context.block_height,
                actual: transaction.body.height,
            },
        ));
    }
    DalekStrictVerifier::validate_public_key(&transaction.body.recipient.payload_bytes())
        .map_err(|error| RewardValidationFailure::Invalid(RewardInvalid::RecipientKey(error)))?;

    let encoded = transaction.encode().map_err(|error| {
        RewardValidationFailure::Local(RewardLocalFailure::CanonicalReencoding(error))
    })?;
    Ok(StructurallyValidatedRewardTransaction {
        transaction_id: transaction_id_from_canonical_bytes(&encoded),
    })
}

pub fn validate_and_apply_reward_transaction(
    transaction: &RewardTransaction,
    context: RewardValidationContext,
    account_before: Account,
    fee_total: u128,
    supply_before: u128,
) -> Result<AppliedRewardTransaction, RewardValidationFailure> {
    let structurally_validated = validate_reward_transaction_structure(transaction, context)?;

    let expected_subsidy = Amount::new(subsidy_at_height(context.block_height));
    let outcome = apply_reward(
        account_before,
        transaction.body.subsidy,
        expected_subsidy,
        transaction.body.fees,
        fee_total,
        supply_before,
    )
    .map_err(|error| RewardValidationFailure::Invalid(RewardInvalid::StateTransition(error)))?;
    Ok(AppliedRewardTransaction {
        transaction_id: structurally_validated.transaction_id,
        outcome,
    })
}

pub fn block_id_from_header_bytes(header_bytes: &[u8; 223]) -> BlockId {
    BlockId::new(
        Blake3Hasher
            .hash_32(ConsensusDomain::BlockId, header_bytes)
            .into_bytes(),
    )
}

pub fn pow_hash_from_header_bytes(header_bytes: &[u8; 223]) -> Hash32 {
    Blake3Hasher.hash_32(ConsensusDomain::ProofOfWork, header_bytes)
}

pub fn pow_hash_meets_target(pow_hash: Hash32, target: U256Be) -> bool {
    U256Be::new(pow_hash.into_bytes()) <= target
}

pub fn validate_header_identity_target_and_pow(
    header: BlockHeader,
    context: HeaderPowContext,
) -> Result<HeaderPowResult, HeaderPowValidationFailure> {
    if context.pow_limit.is_zero()
        || context.required_target.is_zero()
        || context.required_target > context.pow_limit
    {
        return Err(HeaderPowValidationFailure::Local(
            HeaderPowLocalFailure::InvalidPowParameters,
        ));
    }
    let actual_identity = NetworkIdentity {
        chain_id: header.chain_id,
        network_id: header.network_id,
        genesis_commitment: header.genesis_commitment,
    };
    context
        .network
        .require_exact(actual_identity)
        .map_err(|error| HeaderPowValidationFailure::Invalid(HeaderPowInvalid::Identity(error)))?;
    if header.consensus_version != context.active_consensus_version {
        return Err(HeaderPowValidationFailure::Invalid(
            HeaderPowInvalid::InactiveConsensusVersion {
                expected: context.active_consensus_version,
                actual: header.consensus_version,
            },
        ));
    }
    if header.target.is_zero() {
        return Err(HeaderPowValidationFailure::Invalid(
            HeaderPowInvalid::ZeroTarget,
        ));
    }
    if header.target > context.pow_limit {
        return Err(HeaderPowValidationFailure::Invalid(
            HeaderPowInvalid::TargetAbovePowLimit,
        ));
    }
    if header.target != context.required_target {
        return Err(HeaderPowValidationFailure::Invalid(
            HeaderPowInvalid::UnexpectedTarget,
        ));
    }

    let header_bytes = header.encode();
    let pow_hash = pow_hash_from_header_bytes(&header_bytes);
    let pow_value = U256Be::new(pow_hash.into_bytes());
    if pow_value > header.target {
        return Err(HeaderPowValidationFailure::Invalid(
            HeaderPowInvalid::PowAboveTarget,
        ));
    }
    Ok(HeaderPowResult {
        block_id: block_id_from_header_bytes(&header_bytes),
        pow_hash,
        pow_value,
    })
}

fn padding_transaction_leaf(index: u32) -> Hash32 {
    let mut material = [0_u8; 6];
    material[0] = 0;
    material[1] = 0;
    material[2..].copy_from_slice(&index.to_be_bytes());
    Blake3Hasher.hash_32(ConsensusDomain::TransactionMerkleLeaf, &material)
}

fn transaction_merkle_node(level: u16, left: Hash32, right: Hash32) -> Hash32 {
    let mut material = [0_u8; 67];
    material[0] = 0;
    material[1..3].copy_from_slice(&level.to_be_bytes());
    material[3..35].copy_from_slice(left.as_bytes());
    material[35..].copy_from_slice(right.as_bytes());
    Blake3Hasher.hash_32(ConsensusDomain::TransactionMerkleNode, &material)
}

pub fn validate_regular_transaction_structure(
    raw: &[u8],
    context: RegularValidationContext,
) -> Result<StructurallyValidatedRegularTransaction, RegularValidationFailure> {
    let transaction = RegularTransaction::decode_exact(raw).map_err(|error| {
        RegularValidationFailure::Invalid(RegularInvalid::CanonicalEncoding(error))
    })?;

    let actual_identity = NetworkIdentity {
        chain_id: transaction.body.chain_id,
        network_id: transaction.body.network_id,
        genesis_commitment: transaction.body.genesis_commitment,
    };
    context
        .network
        .require_exact(actual_identity)
        .map_err(|error| RegularValidationFailure::Invalid(RegularInvalid::Identity(error)))?;

    if transaction.body.tx_version != context.active_tx_version {
        return Err(RegularValidationFailure::Invalid(
            RegularInvalid::InactiveTransactionVersion {
                expected: context.active_tx_version,
                actual: transaction.body.tx_version,
            },
        ));
    }

    if context.block_height < transaction.body.valid_from_height
        || context.block_height > transaction.body.expires_at_height
    {
        return Err(RegularValidationFailure::Invalid(
            RegularInvalid::HeightOutsideInterval {
                block_height: context.block_height,
                valid_from: transaction.body.valid_from_height,
                expires_at: transaction.body.expires_at_height,
            },
        ));
    }

    DalekStrictVerifier::validate_public_key(&transaction.auth.public_key)
        .map_err(|error| RegularValidationFailure::Invalid(RegularInvalid::PublicKey(error)))?;
    if transaction.body.sender.payload_bytes() != transaction.auth.public_key {
        return Err(RegularValidationFailure::Invalid(
            RegularInvalid::SenderKeyMismatch,
        ));
    }
    DalekStrictVerifier::validate_signature_encoding(&transaction.auth.signature).map_err(
        |error| RegularValidationFailure::Invalid(RegularInvalid::SignatureEncoding(error)),
    )?;

    let signing_material = transaction.signing_material().map_err(|error| {
        RegularValidationFailure::Local(RegularLocalFailure::CanonicalReencoding(error))
    })?;
    let signing_digest =
        Blake3Hasher.hash_32(ConsensusDomain::TransactionSigning, &signing_material);
    let transaction_id = transaction_id_from_canonical_bytes(raw);
    Ok(StructurallyValidatedRegularTransaction {
        transaction,
        signing_digest,
        transaction_id,
    })
}

pub fn verify_regular_transaction_signature(
    structurally_validated: StructurallyValidatedRegularTransaction,
) -> Result<AuthenticatedRegularTransaction, RegularValidationFailure> {
    DalekStrictVerifier
        .verify_strict(
            &structurally_validated.transaction.auth.public_key,
            structurally_validated.signing_digest.as_bytes(),
            &structurally_validated.transaction.auth.signature,
        )
        .map_err(|error| RegularValidationFailure::Invalid(RegularInvalid::Signature(error)))?;
    Ok(AuthenticatedRegularTransaction {
        transaction: structurally_validated.transaction,
        signing_digest: structurally_validated.signing_digest,
        transaction_id: structurally_validated.transaction_id,
    })
}

pub fn authenticate_regular_transaction(
    raw: &[u8],
    context: RegularValidationContext,
) -> Result<AuthenticatedRegularTransaction, RegularValidationFailure> {
    let structurally_validated = validate_regular_transaction_structure(raw, context)?;
    verify_regular_transaction_signature(structurally_validated)
}

pub fn validate_and_apply_regular_transaction(
    raw: &[u8],
    context: RegularValidationContext,
    sender_before: Account,
    recipient_before: Account,
    fee_total_before: u128,
) -> Result<AppliedRegularTransaction, RegularValidationFailure> {
    let authenticated = authenticate_regular_transaction(raw, context)?;
    let body = &authenticated.transaction.body;
    let transfer = RegularTransfer {
        sender: body.sender,
        recipient: body.recipient,
        nonce: body.nonce,
        amount: body.amount,
        fee: body.fee,
    };
    let outcome = apply_regular(
        sender_before,
        recipient_before,
        transfer,
        fee_total_before,
        context.minimum_fee,
    )
    .map_err(|error| RegularValidationFailure::Invalid(RegularInvalid::StateTransition(error)))?;
    Ok(AppliedRegularTransaction {
        authenticated,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR_TRANSACTION_HEX: &str = "0000000000bc0000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a70003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b800000000000000000029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000075bcd1500000000000003e8000000000000000100000000000003e8000a4f555420766563746f720062000003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b84db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b";
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
                let high = char::from(pair[0]).to_digit(16).expect("valid hex");
                let low = char::from(pair[1]).to_digit(16).expect("valid hex");
                u8::try_from((high << 4) | low).expect("hex byte")
            })
            .collect()
    }

    fn hex_32(input: &str) -> [u8; 32] {
        hex(input).try_into().expect("32-byte hex")
    }

    fn vector_block_body(regular_count: usize) -> Vec<u8> {
        let reward = hex(VECTOR_REWARD_HEX);
        let regular = hex(VECTOR_TRANSACTION_HEX);
        let count = u32::try_from(regular_count + 1).expect("test count");
        let mut body = Vec::new();
        body.push(0);
        body.extend_from_slice(&count.to_be_bytes());
        body.extend_from_slice(
            &u32::try_from(reward.len())
                .expect("reward len")
                .to_be_bytes(),
        );
        body.extend_from_slice(&reward);
        for _ in 0..regular_count {
            body.extend_from_slice(
                &u32::try_from(regular.len())
                    .expect("regular len")
                    .to_be_bytes(),
            );
            body.extend_from_slice(&regular);
        }
        body
    }

    fn vector_header() -> BlockHeader {
        BlockHeader::decode_exact(&hex(VECTOR_HEADER_HEX)).expect("verified header")
    }

    fn devnet_target() -> U256Be {
        U256Be::new(hex_32(
            "000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ))
    }

    fn context(network: NetworkIdentity, height: u64) -> RegularValidationContext {
        RegularValidationContext {
            network,
            block_height: height,
            active_tx_version: 0,
            minimum_fee: Amount::ZERO,
        }
    }

    #[test]
    fn cross_network_identity_is_rejected_before_signature_work() {
        assert_eq!(
            NetworkIdentity::testnet().require_exact(NetworkIdentity::devnet()),
            Err(IdentityError::NetworkId)
        );
    }

    #[test]
    fn complete_validated_transaction_matches_verified_vectors() {
        let raw = hex(VECTOR_TRANSACTION_HEX);
        let authenticated =
            authenticate_regular_transaction(&raw, context(NetworkIdentity::devnet(), 1))
                .expect("valid transaction");
        assert_eq!(
            authenticated.signing_digest.into_bytes(),
            hex_32("cd232a5f2e62648203b9c1acba9865e6459f210c8bf7a3c90805f698ac6d2c7e")
        );
        assert_eq!(
            authenticated.transaction_id.into_bytes(),
            hex_32("8f027a546e612be5185e6ed78932f3b7f0f14749e6d9ec1c378144c4343a9c13")
        );
    }

    #[test]
    fn indexed_merkle_leaves_and_root_match_verified_vectors() {
        let reward_id = TransactionId::new(hex_32(
            "51b4a115df0f7719829f2588379695413e76b4f3d252ed74eac4690ef804d814",
        ));
        let regular_id = TransactionId::new(hex_32(
            "8f027a546e612be5185e6ed78932f3b7f0f14749e6d9ec1c378144c4343a9c13",
        ));
        assert_eq!(
            indexed_transaction_leaf(0, reward_id).into_bytes(),
            hex_32("b9f8144af04fff5a03b25b60f4635fe1fd205a7ff76013e803faf6bad9143079")
        );
        assert_eq!(
            indexed_transaction_leaf(1, regular_id).into_bytes(),
            hex_32("033ce606e17c03c54df04ceb18e7b949a0457094c4c314ff6edbb26b82ff6bd6")
        );
        assert_eq!(
            transaction_merkle_root(&[reward_id, regular_id])
                .expect("root")
                .into_bytes(),
            hex_32("03064f29a3a594ff910cf4d42f1f1fb332a43fb1559befd1928a60cc53d39cef")
        );
    }

    #[test]
    fn empty_genesis_root_matches_verified_header_vector() {
        assert_eq!(
            genesis_empty_transaction_root().into_bytes(),
            hex_32("da2fb959f81d652879472f8c56076e63a2fb3587dda94754f316328e7ec43140")
        );
    }

    #[test]
    fn complete_block_body_ids_and_root_match_vectors() {
        let validated = validate_non_genesis_block_body(&vector_block_body(1)).expect("valid body");
        assert_eq!(
            validated.transaction_ids,
            vec![
                TransactionId::new(hex_32(
                    "51b4a115df0f7719829f2588379695413e76b4f3d252ed74eac4690ef804d814"
                )),
                TransactionId::new(hex_32(
                    "8f027a546e612be5185e6ed78932f3b7f0f14749e6d9ec1c378144c4343a9c13"
                ))
            ]
        );
        assert_eq!(
            validated.transaction_root.into_bytes(),
            hex_32("03064f29a3a594ff910cf4d42f1f1fb332a43fb1559befd1928a60cc53d39cef")
        );
    }

    #[test]
    fn duplicate_transaction_ids_are_consensus_invalid() {
        let regular_id = TransactionId::new(hex_32(
            "8f027a546e612be5185e6ed78932f3b7f0f14749e6d9ec1c378144c4343a9c13",
        ));
        assert_eq!(
            transaction_merkle_root(&[regular_id, regular_id]),
            Err(MerkleError::DuplicateTransactionId(regular_id))
        );
        assert_eq!(
            validate_non_genesis_block_body(&vector_block_body(2)),
            Err(BlockBodyValidationFailure::Invalid(
                BlockBodyInvalid::Merkle(MerkleError::DuplicateTransactionId(regular_id))
            ))
        );
    }

    #[test]
    fn merkle_count_bound_precedes_all_leaf_work() {
        let id = TransactionId::new([7; 32]);
        let ids = vec![id; 8_193];
        assert_eq!(
            transaction_merkle_root(&ids),
            Err(MerkleError::TooManyTransactions {
                actual: 8_193,
                maximum: 8_192
            })
        );
    }

    #[test]
    fn reward_semantics_and_credit_match_verified_vector() {
        let reward = RewardTransaction::decode_exact(&hex(VECTOR_REWARD_HEX)).expect("reward");
        let applied = validate_and_apply_reward_transaction(
            &reward,
            RewardValidationContext {
                network: NetworkIdentity::devnet(),
                block_height: 1,
                active_tx_version: 0,
            },
            Account::new(Amount::new(876_542_211), out_primitives::Nonce::new(1)),
            1_000,
            0,
        )
        .expect("valid reward");
        assert_eq!(
            applied.transaction_id.into_bytes(),
            hex_32("51b4a115df0f7719829f2588379695413e76b4f3d252ed74eac4690ef804d814")
        );
        assert_eq!(
            applied.outcome.account,
            Account::new(Amount::new(1_376_543_211), out_primitives::Nonce::new(1))
        );
        assert_eq!(applied.outcome.issued_supply, 500_000_000);
    }

    #[test]
    fn reward_height_and_amount_must_match_exactly() {
        let reward = RewardTransaction::decode_exact(&hex(VECTOR_REWARD_HEX)).expect("reward");
        let context = RewardValidationContext {
            network: NetworkIdentity::devnet(),
            block_height: 2,
            active_tx_version: 0,
        };
        assert_eq!(
            validate_and_apply_reward_transaction(&reward, context, Account::EMPTY, 1_000, 0),
            Err(RewardValidationFailure::Invalid(
                RewardInvalid::HeightMismatch {
                    expected: 2,
                    actual: 1
                }
            ))
        );

        let mut overclaim = reward;
        overclaim.body.subsidy = Amount::new(500_000_001);
        let context = RewardValidationContext {
            network: NetworkIdentity::devnet(),
            block_height: 1,
            active_tx_version: 0,
        };
        assert_eq!(
            validate_and_apply_reward_transaction(&overclaim, context, Account::EMPTY, 1_000, 0),
            Err(RewardValidationFailure::Invalid(
                RewardInvalid::StateTransition(TransitionError::RewardMismatch)
            ))
        );
    }

    #[test]
    fn header_block_id_and_pow_match_verified_vectors() {
        let result = validate_header_identity_target_and_pow(
            vector_header(),
            HeaderPowContext {
                network: NetworkIdentity::devnet(),
                active_consensus_version: 0,
                pow_limit: devnet_target(),
                required_target: devnet_target(),
            },
        )
        .expect("valid mined header");
        assert_eq!(
            result.block_id.into_bytes(),
            hex_32("bd31ae362fa769dab143ef308f7706a7bea9ae671c8fe21793cd8200d73135c9")
        );
        assert_eq!(
            result.pow_hash.into_bytes(),
            hex_32("00089b59cde9abecc6421d2cfd06f2abcba5c07dfcb9f3ab1c62e7c22b6b71c5")
        );
        assert!(pow_hash_meets_target(result.pow_hash, devnet_target()));
    }

    #[test]
    fn pow_uses_inclusive_unsigned_big_endian_comparison() {
        let exact = Hash32::new(hex_32(
            "0000000000000000000000000000000000000000000000000000000000000100",
        ));
        let equal_target = U256Be::new(exact.into_bytes());
        assert!(pow_hash_meets_target(exact, equal_target));
        let lower_target = U256Be::new(hex_32(
            "00000000000000000000000000000000000000000000000000000000000000ff",
        ));
        assert!(!pow_hash_meets_target(exact, lower_target));
    }

    #[test]
    fn zero_wrong_and_failed_pow_targets_are_rejected() {
        let context = HeaderPowContext {
            network: NetworkIdentity::devnet(),
            active_consensus_version: 0,
            pow_limit: devnet_target(),
            required_target: devnet_target(),
        };

        let mut zero = vector_header();
        zero.target = U256Be::ZERO;
        assert_eq!(
            validate_header_identity_target_and_pow(zero, context),
            Err(HeaderPowValidationFailure::Invalid(
                HeaderPowInvalid::ZeroTarget
            ))
        );

        let mut above_limit = vector_header();
        above_limit.target = U256Be::new([0xff; 32]);
        assert_eq!(
            validate_header_identity_target_and_pow(above_limit, context),
            Err(HeaderPowValidationFailure::Invalid(
                HeaderPowInvalid::TargetAbovePowLimit
            ))
        );

        let mut failed_pow = vector_header();
        failed_pow.nonce = 0;
        assert_eq!(
            pow_hash_from_header_bytes(&failed_pow.encode()).into_bytes(),
            hex_32("ea376e4cc2a555ecf0b087051f6f6604a8c7216927194e60f07b68e8535486e1")
        );
        assert_eq!(
            validate_header_identity_target_and_pow(failed_pow, context),
            Err(HeaderPowValidationFailure::Invalid(
                HeaderPowInvalid::PowAboveTarget
            ))
        );

        let mut unexpected = vector_header();
        let mut easier_bytes = devnet_target().into_bytes();
        easier_bytes[31] -= 1;
        unexpected.target = U256Be::new(easier_bytes);
        assert_eq!(
            validate_header_identity_target_and_pow(unexpected, context),
            Err(HeaderPowValidationFailure::Invalid(
                HeaderPowInvalid::UnexpectedTarget
            ))
        );
    }

    #[test]
    fn canonical_failure_precedes_identity_and_crypto() {
        let mut raw = hex(VECTOR_TRANSACTION_HEX);
        raw.push(0);
        assert_eq!(
            authenticate_regular_transaction(&raw, context(NetworkIdentity::testnet(), 2_000)),
            Err(RegularValidationFailure::Invalid(
                RegularInvalid::CanonicalEncoding(DecodeError::TrailingBytes)
            ))
        );
    }

    #[test]
    fn network_failure_precedes_height_and_crypto() {
        let raw = hex(VECTOR_TRANSACTION_HEX);
        assert_eq!(
            authenticate_regular_transaction(&raw, context(NetworkIdentity::testnet(), 2_000)),
            Err(RegularValidationFailure::Invalid(RegularInvalid::Identity(
                IdentityError::NetworkId
            )))
        );
    }

    #[test]
    fn height_failure_precedes_signature_verification() {
        let raw = hex(VECTOR_TRANSACTION_HEX);
        assert_eq!(
            authenticate_regular_transaction(&raw, context(NetworkIdentity::devnet(), 2_000)),
            Err(RegularValidationFailure::Invalid(
                RegularInvalid::HeightOutsideInterval {
                    block_height: 2_000,
                    valid_from: 1,
                    expires_at: 1_000
                }
            ))
        );
    }

    #[test]
    fn sender_binding_failure_precedes_signature_equation() {
        let raw = hex(VECTOR_TRANSACTION_HEX);
        let mut transaction = RegularTransaction::decode_exact(&raw).expect("fixture");
        let mut sender = transaction.body.sender.into_bytes();
        sender[32] ^= 1;
        transaction.body.sender = out_primitives::Recipient::from_bytes(sender).expect("v0 sender");
        let changed = transaction.encode().expect("changed transaction");
        assert_eq!(
            authenticate_regular_transaction(&changed, context(NetworkIdentity::devnet(), 1)),
            Err(RegularValidationFailure::Invalid(
                RegularInvalid::SenderKeyMismatch
            ))
        );
    }

    #[test]
    fn changed_signature_reaches_equation_failure() {
        let raw = hex(VECTOR_TRANSACTION_HEX);
        let mut transaction = RegularTransaction::decode_exact(&raw).expect("fixture");
        transaction.auth.signature[63] ^= 1;
        let changed = transaction.encode().expect("changed transaction");
        assert_eq!(
            authenticate_regular_transaction(&changed, context(NetworkIdentity::devnet(), 1)),
            Err(RegularValidationFailure::Invalid(
                RegularInvalid::Signature(SignatureError::EquationMismatch)
            ))
        );
    }

    #[test]
    fn valid_authentication_then_checked_state_transition_matches_vector() {
        let raw = hex(VECTOR_TRANSACTION_HEX);
        let applied = validate_and_apply_regular_transaction(
            &raw,
            context(NetworkIdentity::devnet(), 1),
            Account::new(Amount::new(1_000_000_000), out_primitives::Nonce::ZERO),
            Account::EMPTY,
            0,
        )
        .expect("valid and applied");
        assert_eq!(applied.outcome.fee_total, 1_000);
        assert_eq!(
            applied.outcome.changes[0].account,
            Account::new(Amount::new(876_542_211), out_primitives::Nonce::new(1))
        );
        assert_eq!(
            applied.outcome.changes[1].account,
            Account::new(Amount::new(123_456_789), out_primitives::Nonce::ZERO)
        );
    }

    #[test]
    fn failed_state_transition_returns_no_changes() {
        let raw = hex(VECTOR_TRANSACTION_HEX);
        assert_eq!(
            validate_and_apply_regular_transaction(
                &raw,
                context(NetworkIdentity::devnet(), 1),
                Account::new(Amount::new(1), out_primitives::Nonce::ZERO),
                Account::EMPTY,
                0,
            ),
            Err(RegularValidationFailure::Invalid(
                RegularInvalid::StateTransition(TransitionError::InsufficientFunds)
            ))
        );
    }

    #[test]
    fn consensus_minimum_fee_is_enforced_after_authentication() {
        let raw = hex(VECTOR_TRANSACTION_HEX);
        let mut validation_context = context(NetworkIdentity::devnet(), 1);
        validation_context.minimum_fee = Amount::new(1_001);
        assert_eq!(
            validate_and_apply_regular_transaction(
                &raw,
                validation_context,
                Account::new(Amount::new(1_000_000_000), out_primitives::Nonce::ZERO),
                Account::EMPTY,
                0,
            ),
            Err(RegularValidationFailure::Invalid(
                RegularInvalid::StateTransition(TransitionError::FeeBelowMinimum)
            ))
        );
    }

    #[test]
    fn exact_work_and_cumulative_work_match_consensus_boundaries() {
        let mut expected_work = [0_u8; 32];
        expected_work[30..].copy_from_slice(&4_096_u16.to_be_bytes());
        assert_eq!(
            exact_block_work(DEVNET_POW_LIMIT_V0),
            Ok(U256Be::new(expected_work))
        );
        assert_eq!(
            checked_cumulative_work(U256Be::ZERO, DEVNET_POW_LIMIT_V0),
            Ok(U256Be::new(expected_work))
        );
        assert_eq!(
            checked_cumulative_work(U256Be::MAX, U256Be::MAX),
            Err(WorkError::CumulativeOverflow)
        );
        assert_eq!(exact_block_work(U256Be::ZERO), Err(WorkError::ZeroTarget));
    }

    #[test]
    fn median_time_past_uses_sorted_upper_median() {
        let accepted = validate_candidate_timestamp(21, &[20, 10], 21, MEDIAN_TIME_WINDOW_V0, 0)
            .expect("upper median accepted");
        assert_eq!(accepted.median_time_past, 20);

        let accepted = validate_candidate_timestamp(
            107,
            &[105, 100, 104, 102, 103, 101, 106],
            107,
            MEDIAN_TIME_WINDOW_V0,
            0,
        )
        .expect("sorted median accepted");
        assert_eq!(accepted.median_time_past, 103);
    }

    #[test]
    fn timestamp_failures_preserve_permanent_and_temporary_classes() {
        assert_eq!(
            validate_candidate_timestamp(20, &[20, 10], 20, MEDIAN_TIME_WINDOW_V0, 0),
            Err(TimestampValidationFailure::Invalid(
                TimestampInvalid::NotAfterMedian {
                    candidate: 20,
                    median_time_past: 20
                }
            ))
        );
        assert_eq!(
            validate_candidate_timestamp(121, &[100], 100, MEDIAN_TIME_WINDOW_V0, 20),
            Err(TimestampValidationFailure::TemporarilyUnacceptable(
                TimestampTemporaryFailure::TooFarFuture {
                    candidate: 121,
                    future_limit: 120
                }
            ))
        );
        assert_eq!(
            validate_candidate_timestamp(101, &[100], 101, 2, 0),
            Err(TimestampValidationFailure::Local(
                TimestampLocalFailure::InvalidMedianWindow
            ))
        );
    }

    #[test]
    fn future_limit_uses_wide_addition_without_wrapping() {
        let accepted = validate_candidate_timestamp(
            u64::MAX,
            &[u64::MAX - 1],
            u64::MAX,
            MEDIAN_TIME_WINDOW_V0,
            MAX_FUTURE_DRIFT_V0,
        )
        .expect("mathematical bound exceeds u64");
        assert_eq!(
            accepted.future_limit,
            u128::from(u64::MAX) + u128::from(MAX_FUTURE_DRIFT_V0)
        );
    }

    #[test]
    fn retarget_span_applies_exact_epoch_and_clamps() {
        let parameters = DifficultyParameters::testnet_v0();
        let exact = retarget_span(1_000, 44_140, parameters).expect("exact span");
        assert_eq!(exact.expected, 43_140);
        assert_eq!(exact.raw_actual, 43_140);
        assert_eq!(exact.lower, 10_785);
        assert_eq!(exact.upper, 172_560);
        assert_eq!(exact.clamped_actual, 43_140);

        let reversed = retarget_span(2_000, 1_000, parameters).expect("reversed endpoints");
        assert_eq!(reversed.raw_actual, 1);
        assert_eq!(reversed.clamped_actual, 10_785);
        let high = retarget_span(0, u64::MAX, parameters).expect("large span");
        assert_eq!(high.clamped_actual, 172_560);
    }

    #[test]
    fn epoch_retarget_uses_floor_wide_arithmetic_and_pow_limit_clamp() {
        let parameters = DifficultyParameters::testnet_v0();
        assert_eq!(
            retarget_epoch_target(TESTNET_POW_LIMIT_V0, 1_000, 44_140, parameters),
            Ok(TESTNET_POW_LIMIT_V0)
        );

        let quarter = TESTNET_POW_LIMIT_V0
            .checked_mul_div_u128(1, 4)
            .expect("quarter");
        assert_eq!(
            retarget_epoch_target(TESTNET_POW_LIMIT_V0, 2_000, 1_000, parameters),
            Ok(quarter)
        );

        let standard_max = DifficultyParameters {
            pow_limit: U256Be::MAX,
            genesis_target: U256Be::MAX,
            mode: PowTargetMode::StandardEpoch,
            ..parameters
        };
        assert_eq!(
            retarget_epoch_target(U256Be::MAX, 0, u64::MAX, standard_max),
            Ok(U256Be::MAX)
        );
    }

    #[test]
    fn retarget_never_returns_zero() {
        let parameters = DifficultyParameters {
            pow_limit: U256Be::MAX,
            genesis_target: U256Be::MAX,
            mode: PowTargetMode::StandardEpoch,
            ..DifficultyParameters::testnet_v0()
        };
        assert_eq!(
            retarget_epoch_target(U256Be::ONE, 2_000, 1_000, parameters),
            Ok(U256Be::ONE)
        );
    }

    #[test]
    fn delayed_testnet_minimum_is_strictly_after_threshold() {
        let parameters = DifficultyParameters::testnet_v0();
        let base = TESTNET_POW_LIMIT_V0
            .checked_mul_div_u128(1, 2)
            .expect("harder base");
        assert_eq!(
            required_target_for_candidate(base, 2_200, 1_000, parameters),
            Ok(base)
        );
        assert_eq!(
            required_target_for_candidate(base, 2_201, 1_000, parameters),
            Ok(TESTNET_POW_LIMIT_V0)
        );
        assert_eq!(
            required_target_for_candidate(base, u64::MAX, u64::MAX - 100, parameters),
            Ok(base)
        );
    }

    #[test]
    fn devnet_target_is_fixed_and_epoch_boundaries_are_exact() {
        let parameters = DifficultyParameters::devnet_v0();
        assert_eq!(
            required_target_for_candidate(U256Be::ZERO, 0, 0, parameters),
            Ok(DEVNET_POW_LIMIT_V0)
        );
        assert_eq!(epoch_at_height(719, RETARGET_WINDOW_V0), Ok(0));
        assert_eq!(epoch_at_height(720, RETARGET_WINDOW_V0), Ok(1));
        assert_eq!(
            prior_epoch_heights(1, RETARGET_WINDOW_V0),
            Ok(PriorEpochHeights {
                first: 0,
                last: 719
            })
        );
        assert_eq!(
            prior_epoch_heights(2, RETARGET_WINDOW_V0),
            Ok(PriorEpochHeights {
                first: 720,
                last: 1_439
            })
        );
        assert_eq!(
            prior_epoch_heights(0, RETARGET_WINDOW_V0),
            Err(DifficultyError::GenesisHasNoPriorEpoch)
        );
        assert_eq!(
            prior_epoch_heights(u64::MAX, RETARGET_WINDOW_V0),
            Err(DifficultyError::ArithmeticOverflow)
        );
    }

    #[test]
    fn invalid_difficulty_descriptors_fail_closed() {
        let invalid = DifficultyParameters {
            down_numerator: 0,
            ..DifficultyParameters::testnet_v0()
        };
        assert_eq!(
            required_target_for_candidate(TESTNET_POW_LIMIT_V0, 0, 0, invalid),
            Err(DifficultyError::InvalidClamp)
        );
        let invalid = DifficultyParameters {
            mode: PowTargetMode::TestnetDelayedMinimum { threshold: 0 },
            ..DifficultyParameters::testnet_v0()
        };
        assert_eq!(
            required_target_for_candidate(TESTNET_POW_LIMIT_V0, 0, 0, invalid),
            Err(DifficultyError::ZeroDelayedMinimumThreshold)
        );
    }
}
