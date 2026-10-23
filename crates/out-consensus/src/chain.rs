use core::cmp::Ordering;

use out_codec::BlockHeader;
use out_primitives::{BlockId, Hash32, U256Be};

use crate::{
    block_id_from_header_bytes, checked_cumulative_work, epoch_at_height, exact_block_work,
    pow_hash_from_header_bytes, prior_epoch_heights, required_target_for_candidate,
    retarget_epoch_target, validate_candidate_timestamp, validate_header_identity_target_and_pow,
    DifficultyError, DifficultyParameters, HeaderPowContext, HeaderPowInvalid,
    HeaderPowLocalFailure, HeaderPowValidationFailure, NetworkIdentity, PowTargetMode,
    TimestampAcceptance, TimestampInvalid, TimestampLocalFailure, TimestampTemporaryFailure,
    TimestampValidationFailure, WorkError, MAX_FUTURE_DRIFT_V0, MEDIAN_TIME_WINDOW_V0,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderChainParameters {
    pub network: NetworkIdentity,
    pub active_consensus_version: u16,
    pub difficulty: DifficultyParameters,
    pub median_time_window: u16,
    pub max_future_drift: u64,
}

impl HeaderChainParameters {
    pub const fn devnet_v0() -> Self {
        Self {
            network: NetworkIdentity::devnet(),
            active_consensus_version: 0,
            difficulty: DifficultyParameters::devnet_v0(),
            median_time_window: MEDIAN_TIME_WINDOW_V0,
            max_future_drift: MAX_FUTURE_DRIFT_V0,
        }
    }

    pub const fn testnet_v0() -> Self {
        Self {
            network: NetworkIdentity::testnet(),
            active_consensus_version: 0,
            difficulty: DifficultyParameters::testnet_v0(),
            median_time_window: MEDIAN_TIME_WINDOW_V0,
            max_future_drift: MAX_FUTURE_DRIFT_V0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHeaderMetadata {
    header: BlockHeader,
    block_id: BlockId,
    pow_hash: Hash32,
    block_work: U256Be,
    cumulative_work: U256Be,
    epoch_base_target: U256Be,
}

impl ValidatedHeaderMetadata {
    pub const fn header(self) -> BlockHeader {
        self.header
    }

    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn pow_hash(self) -> Hash32 {
        self.pow_hash
    }

    pub const fn block_work(self) -> U256Be {
        self.block_work
    }

    pub const fn cumulative_work(self) -> U256Be {
        self.cumulative_work
    }

    pub const fn epoch_base_target(self) -> U256Be {
        self.epoch_base_target
    }

    pub const fn tip(self) -> ChainTip {
        ChainTip {
            block_id: self.block_id,
            height: self.header.height,
            cumulative_work: self.cumulative_work,
        }
    }
}

pub trait ValidatedHeaderView {
    type Error;

    /// Returns metadata from one immutable validation snapshot. Implementations
    /// MUST NOT change the visible branch during a validation call.
    fn get_validated_header(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ValidatedHeaderMetadata>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedChildHeader {
    pub parent: ValidatedHeaderMetadata,
    pub child: ValidatedHeaderMetadata,
}

/// Pure, pre-PoW context for constructing one child of an exact validated
/// parent. This is derived from the same ancestry, timestamp, and difficulty
/// routines used by complete header validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedChildHeader {
    pub parent: ValidatedHeaderMetadata,
    pub height: u64,
    pub timestamp: TimestampAcceptance,
    pub required_target: U256Be,
    pub epoch_base_target: U256Be,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisHeaderInvalid {
    NotPinnedHeader,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisHeaderLocalFailure {
    InvalidPinnedConfiguration,
    Difficulty(DifficultyError),
    Work(WorkError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisHeaderValidationFailure {
    Invalid(GenesisHeaderInvalid),
    Local(GenesisHeaderLocalFailure),
}

pub fn validate_pinned_genesis_header(
    candidate: BlockHeader,
    pinned: BlockHeader,
    parameters: HeaderChainParameters,
) -> Result<ValidatedHeaderMetadata, GenesisHeaderValidationFailure> {
    let zero_parent = BlockId::new([0; 32]);
    if pinned.height != 0
        || pinned.parent_block_id != zero_parent
        || pinned.target != parameters.difficulty.genesis_target
    {
        return Err(GenesisHeaderValidationFailure::Local(
            GenesisHeaderLocalFailure::InvalidPinnedConfiguration,
        ));
    }
    let required_target = required_target_for_candidate(
        parameters.difficulty.genesis_target,
        pinned.timestamp,
        pinned.timestamp,
        parameters.difficulty,
    )
    .map_err(|error| {
        GenesisHeaderValidationFailure::Local(GenesisHeaderLocalFailure::Difficulty(error))
    })?;
    let pow = validate_header_identity_target_and_pow(
        pinned,
        HeaderPowContext {
            network: parameters.network,
            active_consensus_version: parameters.active_consensus_version,
            pow_limit: parameters.difficulty.pow_limit,
            required_target,
        },
    )
    .map_err(|_| {
        GenesisHeaderValidationFailure::Local(GenesisHeaderLocalFailure::InvalidPinnedConfiguration)
    })?;
    if candidate != pinned {
        return Err(GenesisHeaderValidationFailure::Invalid(
            GenesisHeaderInvalid::NotPinnedHeader,
        ));
    }
    let block_work = exact_block_work(candidate.target).map_err(|error| {
        GenesisHeaderValidationFailure::Local(GenesisHeaderLocalFailure::Work(error))
    })?;
    Ok(ValidatedHeaderMetadata {
        header: candidate,
        block_id: pow.block_id,
        pow_hash: pow.pow_hash,
        block_work,
        cumulative_work: block_work,
        epoch_base_target: parameters.difficulty.genesis_target,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChildHeaderInvalid {
    Identity(crate::IdentityError),
    InactiveConsensusVersion { expected: u16, actual: u16 },
    GenesisRequiresPinnedPath,
    ParentHeightOverflow,
    HeightMismatch { expected: u64, actual: u64 },
    Timestamp(TimestampInvalid),
    HeaderPow(HeaderPowInvalid),
    Work(WorkError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChildHeaderLocalFailure<E> {
    Store(E),
    MissingParent(BlockId),
    MissingAncestor(BlockId),
    CorruptValidatedMetadata(BlockId),
    Timestamp(TimestampLocalFailure),
    Difficulty(DifficultyError),
    HeaderPow(HeaderPowLocalFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChildHeaderValidationFailure<E> {
    Invalid(ChildHeaderInvalid),
    TemporarilyUnacceptable(TimestampTemporaryFailure),
    Local(ChildHeaderLocalFailure<E>),
}

pub fn validate_child_header<V: ValidatedHeaderView>(
    candidate: BlockHeader,
    view: &V,
    local_now: u64,
    parameters: HeaderChainParameters,
) -> Result<ValidatedHeaderMetadata, ChildHeaderValidationFailure<V::Error>> {
    validate_child_header_with_parent(candidate, view, local_now, parameters)
        .map(|validated| validated.child)
}

pub fn prepare_child_header<V: ValidatedHeaderView>(
    parent_block_id: BlockId,
    candidate_timestamp: u64,
    view: &V,
    local_now: u64,
    parameters: HeaderChainParameters,
) -> Result<PreparedChildHeader, ChildHeaderValidationFailure<V::Error>> {
    let parent = load_header(view, parent_block_id, true)?;
    let height = parent.header.height.checked_add(1).ok_or_else(|| {
        ChildHeaderValidationFailure::Invalid(ChildHeaderInvalid::ParentHeightOverflow)
    })?;
    prepare_child_header_with_parent(
        parent,
        height,
        candidate_timestamp,
        view,
        local_now,
        parameters,
    )
}

pub fn validate_child_header_with_parent<V: ValidatedHeaderView>(
    candidate: BlockHeader,
    view: &V,
    local_now: u64,
    parameters: HeaderChainParameters,
) -> Result<ValidatedChildHeader, ChildHeaderValidationFailure<V::Error>> {
    let actual_identity = NetworkIdentity {
        chain_id: candidate.chain_id,
        network_id: candidate.network_id,
        genesis_commitment: candidate.genesis_commitment,
    };
    parameters
        .network
        .require_exact(actual_identity)
        .map_err(|error| {
            ChildHeaderValidationFailure::Invalid(ChildHeaderInvalid::Identity(error))
        })?;
    if candidate.consensus_version != parameters.active_consensus_version {
        return Err(ChildHeaderValidationFailure::Invalid(
            ChildHeaderInvalid::InactiveConsensusVersion {
                expected: parameters.active_consensus_version,
                actual: candidate.consensus_version,
            },
        ));
    }
    if candidate.height == 0 {
        return Err(ChildHeaderValidationFailure::Invalid(
            ChildHeaderInvalid::GenesisRequiresPinnedPath,
        ));
    }

    let parent = load_header(view, candidate.parent_block_id, true)?;
    let expected_height = parent.header.height.checked_add(1).ok_or_else(|| {
        ChildHeaderValidationFailure::Invalid(ChildHeaderInvalid::ParentHeightOverflow)
    })?;
    if candidate.height != expected_height {
        return Err(ChildHeaderValidationFailure::Invalid(
            ChildHeaderInvalid::HeightMismatch {
                expected: expected_height,
                actual: candidate.height,
            },
        ));
    }

    let prepared = prepare_child_header_with_parent(
        parent,
        expected_height,
        candidate.timestamp,
        view,
        local_now,
        parameters,
    )?;
    let pow = validate_header_identity_target_and_pow(
        candidate,
        HeaderPowContext {
            network: parameters.network,
            active_consensus_version: parameters.active_consensus_version,
            pow_limit: parameters.difficulty.pow_limit,
            required_target: prepared.required_target,
        },
    )
    .map_err(|failure| match failure {
        HeaderPowValidationFailure::Invalid(error) => {
            ChildHeaderValidationFailure::Invalid(ChildHeaderInvalid::HeaderPow(error))
        }
        HeaderPowValidationFailure::Local(error) => {
            ChildHeaderValidationFailure::Local(ChildHeaderLocalFailure::HeaderPow(error))
        }
    })?;
    let block_work = exact_block_work(candidate.target)
        .map_err(|error| ChildHeaderValidationFailure::Invalid(ChildHeaderInvalid::Work(error)))?;
    let cumulative_work = checked_cumulative_work(parent.cumulative_work, candidate.target)
        .map_err(|error| ChildHeaderValidationFailure::Invalid(ChildHeaderInvalid::Work(error)))?;
    let child = ValidatedHeaderMetadata {
        header: candidate,
        block_id: pow.block_id,
        pow_hash: pow.pow_hash,
        block_work,
        cumulative_work,
        epoch_base_target: prepared.epoch_base_target,
    };
    Ok(ValidatedChildHeader {
        parent: prepared.parent,
        child,
    })
}

fn prepare_child_header_with_parent<V: ValidatedHeaderView>(
    parent: ValidatedHeaderMetadata,
    height: u64,
    candidate_timestamp: u64,
    view: &V,
    local_now: u64,
    parameters: HeaderChainParameters,
) -> Result<PreparedChildHeader, ChildHeaderValidationFailure<V::Error>> {
    if parameters.median_time_window < 3 || parameters.median_time_window.is_multiple_of(2) {
        return Err(ChildHeaderValidationFailure::Local(
            ChildHeaderLocalFailure::Timestamp(TimestampLocalFailure::InvalidMedianWindow),
        ));
    }
    let timestamps = collect_recent_timestamps(view, parent, parameters.median_time_window)?;
    let timestamp = validate_candidate_timestamp(
        candidate_timestamp,
        &timestamps,
        local_now,
        parameters.median_time_window,
        parameters.max_future_drift,
    )
    .map_err(map_timestamp_failure)?;
    let epoch_base_target =
        epoch_base_target_for_child(height, candidate_timestamp, parent, view, parameters)?;
    let required_target = required_target_for_candidate(
        epoch_base_target,
        candidate_timestamp,
        parent.header.timestamp,
        parameters.difficulty,
    )
    .map_err(|error| {
        ChildHeaderValidationFailure::Local(ChildHeaderLocalFailure::Difficulty(error))
    })?;
    Ok(PreparedChildHeader {
        parent,
        height,
        timestamp,
        required_target,
        epoch_base_target,
    })
}

fn map_timestamp_failure<E>(
    failure: TimestampValidationFailure,
) -> ChildHeaderValidationFailure<E> {
    match failure {
        TimestampValidationFailure::Invalid(error) => {
            ChildHeaderValidationFailure::Invalid(ChildHeaderInvalid::Timestamp(error))
        }
        TimestampValidationFailure::TemporarilyUnacceptable(error) => {
            ChildHeaderValidationFailure::TemporarilyUnacceptable(error)
        }
        TimestampValidationFailure::Local(error) => {
            ChildHeaderValidationFailure::Local(ChildHeaderLocalFailure::Timestamp(error))
        }
    }
}

fn epoch_base_target_for_child<V: ValidatedHeaderView>(
    candidate_height: u64,
    candidate_timestamp: u64,
    parent: ValidatedHeaderMetadata,
    view: &V,
    parameters: HeaderChainParameters,
) -> Result<U256Be, ChildHeaderValidationFailure<V::Error>> {
    if matches!(parameters.difficulty.mode, PowTargetMode::DevelopmentFixed) {
        return required_target_for_candidate(
            parameters.difficulty.genesis_target,
            candidate_timestamp,
            parent.header.timestamp,
            parameters.difficulty,
        )
        .map_err(|error| {
            ChildHeaderValidationFailure::Local(ChildHeaderLocalFailure::Difficulty(error))
        });
    }

    let window = u64::from(parameters.difficulty.retarget_window);
    if window == 0 || !candidate_height.is_multiple_of(window) {
        return Ok(parent.epoch_base_target);
    }
    let epoch = epoch_at_height(candidate_height, parameters.difficulty.retarget_window).map_err(
        |error| ChildHeaderValidationFailure::Local(ChildHeaderLocalFailure::Difficulty(error)),
    )?;
    let heights =
        prior_epoch_heights(epoch, parameters.difficulty.retarget_window).map_err(|error| {
            ChildHeaderValidationFailure::Local(ChildHeaderLocalFailure::Difficulty(error))
        })?;
    if parent.header.height != heights.last {
        return Err(ChildHeaderValidationFailure::Local(
            ChildHeaderLocalFailure::CorruptValidatedMetadata(parent.block_id),
        ));
    }
    let first = ancestor_at_height(view, parent, heights.first)?;
    retarget_epoch_target(
        parent.epoch_base_target,
        first.header.timestamp,
        parent.header.timestamp,
        parameters.difficulty,
    )
    .map_err(|error| {
        ChildHeaderValidationFailure::Local(ChildHeaderLocalFailure::Difficulty(error))
    })
}

fn collect_recent_timestamps<V: ValidatedHeaderView>(
    view: &V,
    parent: ValidatedHeaderMetadata,
    window: u16,
) -> Result<Vec<u64>, ChildHeaderValidationFailure<V::Error>> {
    let maximum = usize::from(window);
    let mut timestamps = Vec::with_capacity(maximum);
    let mut current = parent;
    loop {
        timestamps.push(current.header.timestamp);
        if timestamps.len() == maximum || current.header.height == 0 {
            return Ok(timestamps);
        }
        current = load_parent_for_child(view, current)?;
    }
}

fn ancestor_at_height<V: ValidatedHeaderView>(
    view: &V,
    mut current: ValidatedHeaderMetadata,
    target_height: u64,
) -> Result<ValidatedHeaderMetadata, ChildHeaderValidationFailure<V::Error>> {
    loop {
        if current.header.height == target_height {
            return Ok(current);
        }
        if current.header.height < target_height || current.header.height == 0 {
            return Err(ChildHeaderValidationFailure::Local(
                ChildHeaderLocalFailure::CorruptValidatedMetadata(current.block_id),
            ));
        }
        current = load_parent_for_child(view, current)?;
    }
}

fn load_header<V: ValidatedHeaderView>(
    view: &V,
    block_id: BlockId,
    direct_parent: bool,
) -> Result<ValidatedHeaderMetadata, ChildHeaderValidationFailure<V::Error>> {
    let metadata = view
        .get_validated_header(block_id)
        .map_err(|error| {
            ChildHeaderValidationFailure::Local(ChildHeaderLocalFailure::Store(error))
        })?
        .ok_or_else(|| {
            ChildHeaderValidationFailure::Local(if direct_parent {
                ChildHeaderLocalFailure::MissingParent(block_id)
            } else {
                ChildHeaderLocalFailure::MissingAncestor(block_id)
            })
        })?;
    if !metadata_is_self_consistent(metadata, block_id) {
        return Err(ChildHeaderValidationFailure::Local(
            ChildHeaderLocalFailure::CorruptValidatedMetadata(block_id),
        ));
    }
    Ok(metadata)
}

fn load_parent_for_child<V: ValidatedHeaderView>(
    view: &V,
    child: ValidatedHeaderMetadata,
) -> Result<ValidatedHeaderMetadata, ChildHeaderValidationFailure<V::Error>> {
    let parent = load_header(view, child.header.parent_block_id, false)?;
    if !parent_child_metadata_agree(parent, child) {
        return Err(ChildHeaderValidationFailure::Local(
            ChildHeaderLocalFailure::CorruptValidatedMetadata(child.block_id),
        ));
    }
    Ok(parent)
}

fn metadata_is_self_consistent(metadata: ValidatedHeaderMetadata, requested: BlockId) -> bool {
    if metadata.block_id != requested
        || block_id_from_header_bytes(&metadata.header.encode()) != metadata.block_id
        || pow_hash_from_header_bytes(&metadata.header.encode()) != metadata.pow_hash
    {
        return false;
    }
    matches!(exact_block_work(metadata.header.target), Ok(work) if work == metadata.block_work)
}

fn parent_child_metadata_agree(
    parent: ValidatedHeaderMetadata,
    child: ValidatedHeaderMetadata,
) -> bool {
    if child.header.parent_block_id != parent.block_id
        || parent.header.height.checked_add(1) != Some(child.header.height)
    {
        return false;
    }
    matches!(
        parent.cumulative_work.checked_add(child.block_work),
        Ok(cumulative) if cumulative == child.cumulative_work
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainTip {
    pub block_id: BlockId,
    pub height: u64,
    pub cumulative_work: U256Be,
}

pub fn compare_chain_tips(left: &ChainTip, right: &ChainTip) -> Ordering {
    left.cumulative_work
        .cmp(&right.cumulative_work)
        .then_with(|| left.height.cmp(&right.height))
        .then_with(|| right.block_id.cmp(&left.block_id))
}

pub fn select_best_tip<I>(tips: I) -> Option<ChainTip>
where
    I: IntoIterator<Item = ChainTip>,
{
    tips.into_iter().max_by(compare_chain_tips)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReorganizationPlan {
    pub selected_tip: BlockId,
    pub winning_tip: BlockId,
    pub common_ancestor: BlockId,
    /// Old-tip to ancestor-child order, suitable for rollback.
    pub detach: Vec<BlockId>,
    /// Ancestor-child to new-tip order, suitable for forward application.
    pub attach: Vec<BlockId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReorganizationPlanFailure<E> {
    Store(E),
    MissingValidatedBlock(BlockId),
    CorruptValidatedMetadata(BlockId),
    WinningTipNotPreferred,
    NoCommonAncestor,
    PolicyPause { maximum_plan_blocks: u64 },
}

pub fn plan_reorganization<V: ValidatedHeaderView>(
    view: &V,
    selected_tip: ChainTip,
    winning_tip: ChainTip,
    maximum_plan_blocks: u64,
) -> Result<ReorganizationPlan, ReorganizationPlanFailure<V::Error>> {
    if selected_tip != winning_tip
        && compare_chain_tips(&winning_tip, &selected_tip) != Ordering::Greater
    {
        return Err(ReorganizationPlanFailure::WinningTipNotPreferred);
    }
    let mut selected = load_reorg_tip(view, selected_tip)?;
    let mut winning = load_reorg_tip(view, winning_tip)?;
    let mut detach = Vec::new();
    let mut reverse_attach = Vec::new();
    let mut planned = 0_u64;

    while selected.header.height > winning.header.height {
        push_plan_id(
            &mut detach,
            selected.block_id,
            &mut planned,
            maximum_plan_blocks,
        )?;
        selected = load_reorg_parent(view, selected)?;
    }
    while winning.header.height > selected.header.height {
        push_plan_id(
            &mut reverse_attach,
            winning.block_id,
            &mut planned,
            maximum_plan_blocks,
        )?;
        winning = load_reorg_parent(view, winning)?;
    }
    while selected.block_id != winning.block_id {
        if selected.header.height == 0 || winning.header.height == 0 {
            return Err(ReorganizationPlanFailure::NoCommonAncestor);
        }
        push_plan_id(
            &mut detach,
            selected.block_id,
            &mut planned,
            maximum_plan_blocks,
        )?;
        push_plan_id(
            &mut reverse_attach,
            winning.block_id,
            &mut planned,
            maximum_plan_blocks,
        )?;
        selected = load_reorg_parent(view, selected)?;
        winning = load_reorg_parent(view, winning)?;
    }

    reverse_attach.reverse();
    Ok(ReorganizationPlan {
        selected_tip: selected_tip.block_id,
        winning_tip: winning_tip.block_id,
        common_ancestor: selected.block_id,
        detach,
        attach: reverse_attach,
    })
}

fn load_reorg_tip<V: ValidatedHeaderView>(
    view: &V,
    tip: ChainTip,
) -> Result<ValidatedHeaderMetadata, ReorganizationPlanFailure<V::Error>> {
    let metadata = load_reorg_header(view, tip.block_id)?;
    if metadata.tip() != tip {
        return Err(ReorganizationPlanFailure::CorruptValidatedMetadata(
            tip.block_id,
        ));
    }
    Ok(metadata)
}

fn load_reorg_header<V: ValidatedHeaderView>(
    view: &V,
    block_id: BlockId,
) -> Result<ValidatedHeaderMetadata, ReorganizationPlanFailure<V::Error>> {
    let metadata = view
        .get_validated_header(block_id)
        .map_err(ReorganizationPlanFailure::Store)?
        .ok_or(ReorganizationPlanFailure::MissingValidatedBlock(block_id))?;
    if !metadata_is_self_consistent(metadata, block_id) {
        return Err(ReorganizationPlanFailure::CorruptValidatedMetadata(
            block_id,
        ));
    }
    Ok(metadata)
}

fn load_reorg_parent<V: ValidatedHeaderView>(
    view: &V,
    child: ValidatedHeaderMetadata,
) -> Result<ValidatedHeaderMetadata, ReorganizationPlanFailure<V::Error>> {
    if child.header.height == 0 {
        return Err(ReorganizationPlanFailure::NoCommonAncestor);
    }
    let parent = load_reorg_header(view, child.header.parent_block_id)?;
    if !parent_child_metadata_agree(parent, child) {
        return Err(ReorganizationPlanFailure::CorruptValidatedMetadata(
            child.block_id,
        ));
    }
    Ok(parent)
}

fn push_plan_id<E>(
    output: &mut Vec<BlockId>,
    block_id: BlockId,
    planned: &mut u64,
    maximum: u64,
) -> Result<(), ReorganizationPlanFailure<E>> {
    let next = planned
        .checked_add(1)
        .ok_or(ReorganizationPlanFailure::PolicyPause {
            maximum_plan_blocks: maximum,
        })?;
    if next > maximum {
        return Err(ReorganizationPlanFailure::PolicyPause {
            maximum_plan_blocks: maximum,
        });
    }
    output.push(block_id);
    *planned = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use out_codec::BlockHeader;
    use out_primitives::{StateRoot, TransactionRoot};

    use super::*;
    use crate::{pow_hash_meets_target, TimestampTemporaryFailure};

    const VECTOR_HEADER_HEX: &str = "000000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a937280000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda2fb959f81d652879472f8c56076e63a2fb3587dda94754f316328e7ec431403d30a2588a2f688edd9b29af2bb3b522db2deb731709dbfb53fadefab69c21470000000000000ac5";

    #[derive(Default)]
    struct MemoryView {
        headers: BTreeMap<BlockId, ValidatedHeaderMetadata>,
        fail: bool,
    }

    impl ValidatedHeaderView for MemoryView {
        type Error = &'static str;

        fn get_validated_header(
            &self,
            block_id: BlockId,
        ) -> Result<Option<ValidatedHeaderMetadata>, Self::Error> {
            if self.fail {
                Err("store failure")
            } else {
                Ok(self.headers.get(&block_id).copied())
            }
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

    fn u256(value: u64) -> U256Be {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        U256Be::new(bytes)
    }

    fn genesis() -> ValidatedHeaderMetadata {
        let header = BlockHeader::decode_exact(&hex(VECTOR_HEADER_HEX)).expect("genesis header");
        validate_pinned_genesis_header(header, header, HeaderChainParameters::devnet_v0())
            .expect("pinned genesis")
    }

    fn mined_child(
        parent: ValidatedHeaderMetadata,
        timestamp: u64,
        distinguishing_byte: u8,
    ) -> BlockHeader {
        let parent_header = parent.header();
        let mut header = BlockHeader {
            consensus_version: 0,
            chain_id: parent_header.chain_id,
            network_id: parent_header.network_id,
            genesis_commitment: parent_header.genesis_commitment,
            height: parent_header.height.checked_add(1).expect("test height"),
            parent_block_id: parent.block_id(),
            timestamp,
            target: DifficultyParameters::devnet_v0().genesis_target,
            transaction_root: TransactionRoot::new([distinguishing_byte; 32]),
            state_root: StateRoot::new([distinguishing_byte.wrapping_add(1); 32]),
            nonce: 0,
        };
        loop {
            let pow_hash = pow_hash_from_header_bytes(&header.encode());
            if pow_hash_meets_target(pow_hash, header.target) {
                return header;
            }
            header.nonce = header.nonce.checked_add(1).expect("test nonce space");
        }
    }

    fn insert_genesis(view: &mut MemoryView) -> ValidatedHeaderMetadata {
        let genesis = genesis();
        view.headers.insert(genesis.block_id(), genesis);
        genesis
    }

    fn add_child(
        view: &mut MemoryView,
        parent: ValidatedHeaderMetadata,
        timestamp: u64,
        distinguishing_byte: u8,
    ) -> ValidatedHeaderMetadata {
        add_child_with_parameters(
            view,
            parent,
            timestamp,
            distinguishing_byte,
            HeaderChainParameters::devnet_v0(),
        )
    }

    fn add_child_with_parameters(
        view: &mut MemoryView,
        parent: ValidatedHeaderMetadata,
        timestamp: u64,
        distinguishing_byte: u8,
        parameters: HeaderChainParameters,
    ) -> ValidatedHeaderMetadata {
        let header = mined_child(parent, timestamp, distinguishing_byte);
        let metadata =
            validate_child_header(header, view, timestamp, parameters).expect("valid child");
        view.headers.insert(metadata.block_id(), metadata);
        metadata
    }

    #[test]
    fn pinned_genesis_and_parent_aware_child_produce_checked_work() {
        let mut view = MemoryView::default();
        let genesis = insert_genesis(&mut view);
        let child = add_child(&mut view, genesis, genesis.header().timestamp + 1, 1);
        assert_eq!(child.header().parent_block_id, genesis.block_id());
        assert_eq!(child.header().height, 1);
        assert_eq!(child.block_work(), u256(4_096));
        assert_eq!(child.cumulative_work(), u256(8_192));
        assert_eq!(child.epoch_base_target(), genesis.epoch_base_target());
    }

    #[test]
    fn missing_history_and_store_faults_remain_local() {
        let genesis = genesis();
        let child_header = mined_child(genesis, genesis.header().timestamp + 1, 2);
        let empty = MemoryView::default();
        assert_eq!(
            validate_child_header(
                child_header,
                &empty,
                child_header.timestamp,
                HeaderChainParameters::devnet_v0()
            ),
            Err(ChildHeaderValidationFailure::Local(
                ChildHeaderLocalFailure::MissingParent(genesis.block_id())
            ))
        );

        let failing = MemoryView {
            fail: true,
            ..MemoryView::default()
        };
        assert_eq!(
            validate_child_header(
                child_header,
                &failing,
                child_header.timestamp,
                HeaderChainParameters::devnet_v0()
            ),
            Err(ChildHeaderValidationFailure::Local(
                ChildHeaderLocalFailure::Store("store failure")
            ))
        );

        let mut partial = MemoryView::default();
        let mut full = MemoryView::default();
        let root = insert_genesis(&mut full);
        let first = add_child(&mut full, root, root.header().timestamp + 1, 3);
        partial.headers.insert(first.block_id(), first);
        let second_header = mined_child(first, first.header().timestamp + 1, 4);
        assert_eq!(
            validate_child_header(
                second_header,
                &partial,
                second_header.timestamp,
                HeaderChainParameters::devnet_v0()
            ),
            Err(ChildHeaderValidationFailure::Local(
                ChildHeaderLocalFailure::MissingAncestor(root.block_id())
            ))
        );
    }

    #[test]
    fn height_mtp_and_future_failures_have_distinct_classes() {
        let mut view = MemoryView::default();
        let genesis = insert_genesis(&mut view);
        let mut wrong_height = mined_child(genesis, genesis.header().timestamp + 1, 5);
        wrong_height.height = 2;
        assert_eq!(
            validate_child_header(
                wrong_height,
                &view,
                wrong_height.timestamp,
                HeaderChainParameters::devnet_v0()
            ),
            Err(ChildHeaderValidationFailure::Invalid(
                ChildHeaderInvalid::HeightMismatch {
                    expected: 1,
                    actual: 2
                }
            ))
        );

        let stale = mined_child(genesis, genesis.header().timestamp, 6);
        assert_eq!(
            validate_child_header(
                stale,
                &view,
                stale.timestamp,
                HeaderChainParameters::devnet_v0()
            ),
            Err(ChildHeaderValidationFailure::Invalid(
                ChildHeaderInvalid::Timestamp(TimestampInvalid::NotAfterMedian {
                    candidate: genesis.header().timestamp,
                    median_time_past: genesis.header().timestamp
                })
            ))
        );

        let future_timestamp = genesis.header().timestamp + MAX_FUTURE_DRIFT_V0 + 1;
        let future = mined_child(genesis, future_timestamp, 7);
        assert_eq!(
            validate_child_header(
                future,
                &view,
                genesis.header().timestamp,
                HeaderChainParameters::devnet_v0()
            ),
            Err(ChildHeaderValidationFailure::TemporarilyUnacceptable(
                TimestampTemporaryFailure::TooFarFuture {
                    candidate: future_timestamp,
                    future_limit: u128::from(genesis.header().timestamp)
                        + u128::from(MAX_FUTURE_DRIFT_V0)
                }
            ))
        );
    }

    #[test]
    fn best_tip_order_is_work_then_height_then_smaller_id() {
        let low_id = BlockId::new([1; 32]);
        let high_id = BlockId::new([2; 32]);
        let lower_work = ChainTip {
            block_id: low_id,
            height: 100,
            cumulative_work: u256(9),
        };
        let higher_work = ChainTip {
            block_id: high_id,
            height: 1,
            cumulative_work: u256(10),
        };
        assert_eq!(
            compare_chain_tips(&higher_work, &lower_work),
            Ordering::Greater
        );

        let shorter = ChainTip {
            block_id: low_id,
            height: 9,
            cumulative_work: u256(10),
        };
        let taller = ChainTip {
            block_id: high_id,
            height: 10,
            cumulative_work: u256(10),
        };
        assert_eq!(compare_chain_tips(&taller, &shorter), Ordering::Greater);

        let small_id_tip = ChainTip {
            block_id: low_id,
            height: 10,
            cumulative_work: u256(10),
        };
        let large_id_tip = ChainTip {
            block_id: high_id,
            ..small_id_tip
        };
        assert_eq!(
            compare_chain_tips(&small_id_tip, &large_id_tip),
            Ordering::Greater
        );
        for tips in [
            vec![small_id_tip, large_id_tip, lower_work],
            vec![lower_work, large_id_tip, small_id_tip],
            vec![large_id_tip, small_id_tip, lower_work],
        ] {
            assert_eq!(select_best_tip(tips), Some(small_id_tip));
        }
    }

    #[test]
    fn reorganization_plan_has_exact_rollback_and_forward_order() {
        let mut view = MemoryView::default();
        let root = insert_genesis(&mut view);
        let a1 = add_child(&mut view, root, root.header().timestamp + 1, 10);
        let a2 = add_child(&mut view, a1, root.header().timestamp + 2, 11);
        let b1 = add_child(&mut view, root, root.header().timestamp + 1, 20);
        let b2 = add_child(&mut view, b1, root.header().timestamp + 2, 21);
        let b3 = add_child(&mut view, b2, root.header().timestamp + 3, 22);

        let plan = plan_reorganization(&view, a2.tip(), b3.tip(), 10).expect("reorg plan");
        assert_eq!(plan.selected_tip, a2.block_id());
        assert_eq!(plan.winning_tip, b3.block_id());
        assert_eq!(plan.common_ancestor, root.block_id());
        assert_eq!(plan.detach, vec![a2.block_id(), a1.block_id()]);
        assert_eq!(
            plan.attach,
            vec![b1.block_id(), b2.block_id(), b3.block_id()]
        );

        assert_eq!(
            plan_reorganization(&view, a2.tip(), b3.tip(), 4),
            Err(ReorganizationPlanFailure::PolicyPause {
                maximum_plan_blocks: 4
            })
        );
        assert_eq!(
            plan_reorganization(&view, b3.tip(), a2.tip(), 10),
            Err(ReorganizationPlanFailure::WinningTipNotPreferred)
        );
    }

    #[test]
    fn epoch_boundary_reads_exact_endpoints_from_candidate_branch() {
        let parameters = HeaderChainParameters {
            difficulty: DifficultyParameters {
                target_spacing: 1,
                retarget_window: 4,
                mode: PowTargetMode::StandardEpoch,
                ..DifficultyParameters::devnet_v0()
            },
            median_time_window: 3,
            ..HeaderChainParameters::devnet_v0()
        };
        let header = BlockHeader::decode_exact(&hex(VECTOR_HEADER_HEX)).expect("genesis header");
        let root = validate_pinned_genesis_header(header, header, parameters).expect("genesis");
        let mut view = MemoryView::default();
        view.headers.insert(root.block_id(), root);
        let first =
            add_child_with_parameters(&mut view, root, root.header().timestamp + 1, 30, parameters);
        let second = add_child_with_parameters(
            &mut view,
            first,
            root.header().timestamp + 2,
            31,
            parameters,
        );
        let third = add_child_with_parameters(
            &mut view,
            second,
            root.header().timestamp + 3,
            32,
            parameters,
        );
        let boundary_header = mined_child(third, root.header().timestamp + 4, 33);
        let boundary = validate_child_header(
            boundary_header,
            &view,
            boundary_header.timestamp,
            parameters,
        )
        .expect("boundary target");
        assert_eq!(boundary.header().height, 4);
        assert_eq!(boundary.epoch_base_target(), root.epoch_base_target());

        view.headers.remove(&root.block_id());
        assert_eq!(
            validate_child_header(
                boundary_header,
                &view,
                boundary_header.timestamp,
                parameters
            ),
            Err(ChildHeaderValidationFailure::Local(
                ChildHeaderLocalFailure::MissingAncestor(root.block_id())
            ))
        );
    }

    #[test]
    fn no_op_reorganization_is_empty() {
        let mut view = MemoryView::default();
        let root = insert_genesis(&mut view);
        assert_eq!(
            plan_reorganization(&view, root.tip(), root.tip(), 0),
            Ok(ReorganizationPlan {
                selected_tip: root.block_id(),
                winning_tip: root.block_id(),
                common_ancestor: root.block_id(),
                detach: Vec::new(),
                attach: Vec::new()
            })
        );
    }
}
