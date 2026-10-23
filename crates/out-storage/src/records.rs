//! Versioned operational records shared by persistent storage adapters.
//!
//! These bytes are deliberately outside consensus. They MUST be decoded and
//! integrity-checked before use, but they never replace canonical block,
//! transaction, state-root, or work validation.

use blake3::Hasher;
use out_codec::MAX_BLOCK_BYTES;
use out_consensus::NetworkIdentity;
use out_primitives::{
    Amount, BlockId, ChainId, GenesisCommitment, Hash32, NetworkId, Nonce, Recipient, StateRoot,
    TransactionId, MAX_MONEY,
};
use out_state::Account;

pub const STORAGE_SCHEMA_V0: u16 = 0;
pub const STORAGE_RECORD_MAGIC: [u8; 4] = *b"OUTS";
pub const STORAGE_RECORD_HEADER_LEN: usize = 12;
pub const STORAGE_RECORD_CHECKSUM_LEN: usize = 32;
pub const MAX_STORAGE_RECORD_PAYLOAD_BYTES: u32 = MAX_BLOCK_BYTES;
pub const MAX_STORAGE_KEY_BYTES: usize = 80;
pub const STORAGE_RECORD_CHECKSUM_CONTEXT: &str = "OUT/storage-record-checksum/v0";
pub const STORAGE_GENERATION_DIGEST_CONTEXT: &str = "OUT/storage-generation-digest/v0";

const MANIFEST_PAYLOAD_LEN: usize = 140;
const RECOVERY_PAYLOAD_LEN: usize = 84;
const GENERATION_SEAL_PAYLOAD_LEN: usize = 144;
const ACCOUNT_PAYLOAD_LEN: usize = 16;
const ACCOUNT_DELTA_PAYLOAD_LEN: usize = 32;
const CANONICAL_TIP_PAYLOAD_LEN: usize = 80;
const ZERO_BLOCK_ID: BlockId = BlockId::new([0; 32]);

const KEY_MANIFEST: u8 = 0x00;
const KEY_RECOVERY: u8 = 0x01;
const KEY_BLOCK_VISIBLE: u8 = 0x10;
const KEY_BLOCK_BYTES: u8 = 0x11;
const KEY_BLOCK_TRANSACTION: u8 = 0x12;
const KEY_BRANCH_ACCOUNT: u8 = 0x13;
const KEY_ACCOUNT_DELTA: u8 = 0x14;
const KEY_STATE_NODE: u8 = 0x15;
const KEY_GENERATION_SEAL: u8 = 0x20;
const KEY_CANONICAL_TIP: u8 = 0x21;
const KEY_CANONICAL_HEIGHT: u8 = 0x22;
const KEY_CANONICAL_TRANSACTION: u8 = 0x23;
const KEY_CANONICAL_ACCOUNT: u8 = 0x24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StorageRecordKind {
    Manifest = 0x00,
    Recovery = 0x01,
    GenerationSeal = 0x02,
    Block = 0x10,
    BlockVisibility = 0x11,
    TransactionId = 0x12,
    Account = 0x13,
    AccountDelta = 0x14,
    StateNode = 0x15,
    CanonicalTip = 0x20,
    BlockId = 0x21,
}

impl StorageRecordKind {
    fn from_tag(tag: u8) -> Result<Self, StorageRecordDecodeError> {
        match tag {
            0x00 => Ok(Self::Manifest),
            0x01 => Ok(Self::Recovery),
            0x02 => Ok(Self::GenerationSeal),
            0x10 => Ok(Self::Block),
            0x11 => Ok(Self::BlockVisibility),
            0x12 => Ok(Self::TransactionId),
            0x13 => Ok(Self::Account),
            0x14 => Ok(Self::AccountDelta),
            0x15 => Ok(Self::StateNode),
            0x20 => Ok(Self::CanonicalTip),
            0x21 => Ok(Self::BlockId),
            value => Err(StorageRecordDecodeError::UnknownKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageKey {
    Manifest,
    Recovery,
    BlockVisible(BlockId),
    BlockBytes(BlockId),
    BlockTransaction {
        block_id: BlockId,
        index: u32,
    },
    BranchAccount {
        block_id: BlockId,
        recipient: Recipient,
    },
    AccountDelta {
        block_id: BlockId,
        recipient: Recipient,
    },
    StateNode(Hash32),
    GenerationSeal(u64),
    CanonicalTip(u64),
    CanonicalHeight {
        generation: u64,
        height: u64,
    },
    CanonicalTransaction {
        generation: u64,
        transaction_id: TransactionId,
    },
    CanonicalAccount {
        generation: u64,
        recipient: Recipient,
    },
}

impl StorageKey {
    pub fn encode(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(MAX_STORAGE_KEY_BYTES);
        match self {
            Self::Manifest => output.push(KEY_MANIFEST),
            Self::Recovery => output.push(KEY_RECOVERY),
            Self::BlockVisible(block_id) => {
                output.push(KEY_BLOCK_VISIBLE);
                output.extend_from_slice(block_id.as_bytes());
            }
            Self::BlockBytes(block_id) => {
                output.push(KEY_BLOCK_BYTES);
                output.extend_from_slice(block_id.as_bytes());
            }
            Self::BlockTransaction { block_id, index } => {
                output.push(KEY_BLOCK_TRANSACTION);
                output.extend_from_slice(block_id.as_bytes());
                output.extend_from_slice(&index.to_be_bytes());
            }
            Self::BranchAccount {
                block_id,
                recipient,
            } => {
                output.push(KEY_BRANCH_ACCOUNT);
                output.extend_from_slice(block_id.as_bytes());
                output.extend_from_slice(recipient.as_bytes());
            }
            Self::AccountDelta {
                block_id,
                recipient,
            } => {
                output.push(KEY_ACCOUNT_DELTA);
                output.extend_from_slice(block_id.as_bytes());
                output.extend_from_slice(recipient.as_bytes());
            }
            Self::StateNode(hash) => {
                output.push(KEY_STATE_NODE);
                output.extend_from_slice(hash.as_bytes());
            }
            Self::GenerationSeal(generation) => {
                output.push(KEY_GENERATION_SEAL);
                output.extend_from_slice(&generation.to_be_bytes());
            }
            Self::CanonicalTip(generation) => {
                output.push(KEY_CANONICAL_TIP);
                output.extend_from_slice(&generation.to_be_bytes());
            }
            Self::CanonicalHeight { generation, height } => {
                output.push(KEY_CANONICAL_HEIGHT);
                output.extend_from_slice(&generation.to_be_bytes());
                output.extend_from_slice(&height.to_be_bytes());
            }
            Self::CanonicalTransaction {
                generation,
                transaction_id,
            } => {
                output.push(KEY_CANONICAL_TRANSACTION);
                output.extend_from_slice(&generation.to_be_bytes());
                output.extend_from_slice(transaction_id.as_bytes());
            }
            Self::CanonicalAccount {
                generation,
                recipient,
            } => {
                output.push(KEY_CANONICAL_ACCOUNT);
                output.extend_from_slice(&generation.to_be_bytes());
                output.extend_from_slice(recipient.as_bytes());
            }
        }
        output
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, StorageKeyDecodeError> {
        let tag = *input.first().ok_or(StorageKeyDecodeError::Truncated)?;
        match tag {
            KEY_MANIFEST => {
                require_key_len(input, 1)?;
                Ok(Self::Manifest)
            }
            KEY_RECOVERY => {
                require_key_len(input, 1)?;
                Ok(Self::Recovery)
            }
            KEY_BLOCK_VISIBLE => {
                require_key_len(input, 33)?;
                Ok(Self::BlockVisible(BlockId::new(array_at(input, 1)?)))
            }
            KEY_BLOCK_BYTES => {
                require_key_len(input, 33)?;
                Ok(Self::BlockBytes(BlockId::new(array_at(input, 1)?)))
            }
            KEY_BLOCK_TRANSACTION => {
                require_key_len(input, 37)?;
                Ok(Self::BlockTransaction {
                    block_id: BlockId::new(array_at(input, 1)?),
                    index: u32::from_be_bytes(array_at(input, 33)?),
                })
            }
            KEY_BRANCH_ACCOUNT => {
                require_key_len(input, 66)?;
                Ok(Self::BranchAccount {
                    block_id: BlockId::new(array_at(input, 1)?),
                    recipient: decode_recipient(array_at(input, 33)?)?,
                })
            }
            KEY_ACCOUNT_DELTA => {
                require_key_len(input, 66)?;
                Ok(Self::AccountDelta {
                    block_id: BlockId::new(array_at(input, 1)?),
                    recipient: decode_recipient(array_at(input, 33)?)?,
                })
            }
            KEY_STATE_NODE => {
                require_key_len(input, 33)?;
                Ok(Self::StateNode(Hash32::new(array_at(input, 1)?)))
            }
            KEY_GENERATION_SEAL => {
                require_key_len(input, 9)?;
                Ok(Self::GenerationSeal(u64::from_be_bytes(array_at(
                    input, 1,
                )?)))
            }
            KEY_CANONICAL_TIP => {
                require_key_len(input, 9)?;
                Ok(Self::CanonicalTip(u64::from_be_bytes(array_at(input, 1)?)))
            }
            KEY_CANONICAL_HEIGHT => {
                require_key_len(input, 17)?;
                Ok(Self::CanonicalHeight {
                    generation: u64::from_be_bytes(array_at(input, 1)?),
                    height: u64::from_be_bytes(array_at(input, 9)?),
                })
            }
            KEY_CANONICAL_TRANSACTION => {
                require_key_len(input, 41)?;
                Ok(Self::CanonicalTransaction {
                    generation: u64::from_be_bytes(array_at(input, 1)?),
                    transaction_id: TransactionId::new(array_at(input, 9)?),
                })
            }
            KEY_CANONICAL_ACCOUNT => {
                require_key_len(input, 42)?;
                Ok(Self::CanonicalAccount {
                    generation: u64::from_be_bytes(array_at(input, 1)?),
                    recipient: decode_recipient(array_at(input, 9)?)?,
                })
            }
            value => Err(StorageKeyDecodeError::UnknownTag(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageKeyDecodeError {
    Truncated,
    WrongLength { actual: usize, expected: usize },
    UnknownTag(u8),
    UnsupportedRecipientVersion(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRecordEncodeError {
    PayloadTooLong { actual: usize, maximum: u32 },
    LengthOverflow,
    NonCanonicalField(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRecordDecodeError {
    Truncated,
    TrailingBytes,
    RecordTooLong,
    InvalidMagic,
    UnsupportedSchema(u16),
    UnknownKind(u8),
    NonzeroFlags(u8),
    PayloadTooLong { actual: u32, maximum: u32 },
    ChecksumMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedStorageRecord<'a> {
    pub kind: StorageRecordKind,
    pub payload: &'a [u8],
}

pub fn encode_storage_record(
    kind: StorageRecordKind,
    payload: &[u8],
) -> Result<Vec<u8>, StorageRecordEncodeError> {
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| StorageRecordEncodeError::PayloadTooLong {
            actual: payload.len(),
            maximum: MAX_STORAGE_RECORD_PAYLOAD_BYTES,
        })?;
    if payload_len > MAX_STORAGE_RECORD_PAYLOAD_BYTES {
        return Err(StorageRecordEncodeError::PayloadTooLong {
            actual: payload.len(),
            maximum: MAX_STORAGE_RECORD_PAYLOAD_BYTES,
        });
    }
    let total = STORAGE_RECORD_HEADER_LEN
        .checked_add(payload.len())
        .and_then(|value| value.checked_add(STORAGE_RECORD_CHECKSUM_LEN))
        .ok_or(StorageRecordEncodeError::LengthOverflow)?;
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&STORAGE_RECORD_MAGIC);
    output.extend_from_slice(&STORAGE_SCHEMA_V0.to_be_bytes());
    output.push(kind as u8);
    output.push(0);
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(payload);
    let checksum = storage_checksum(&output);
    output.extend_from_slice(&checksum);
    Ok(output)
}

pub fn decode_storage_record_exact(
    input: &[u8],
) -> Result<DecodedStorageRecord<'_>, StorageRecordDecodeError> {
    let input_len =
        u64::try_from(input.len()).map_err(|_| StorageRecordDecodeError::RecordTooLong)?;
    let maximum_total = u64::try_from(STORAGE_RECORD_HEADER_LEN).expect("header length fits u64")
        + u64::from(MAX_STORAGE_RECORD_PAYLOAD_BYTES)
        + u64::try_from(STORAGE_RECORD_CHECKSUM_LEN).expect("checksum length fits u64");
    if input_len > maximum_total {
        return Err(StorageRecordDecodeError::RecordTooLong);
    }
    if input.len() < STORAGE_RECORD_HEADER_LEN + STORAGE_RECORD_CHECKSUM_LEN {
        return Err(StorageRecordDecodeError::Truncated);
    }
    if input[..4] != STORAGE_RECORD_MAGIC {
        return Err(StorageRecordDecodeError::InvalidMagic);
    }
    let schema = u16::from_be_bytes([input[4], input[5]]);
    if schema != STORAGE_SCHEMA_V0 {
        return Err(StorageRecordDecodeError::UnsupportedSchema(schema));
    }
    let kind = StorageRecordKind::from_tag(input[6])?;
    if input[7] != 0 {
        return Err(StorageRecordDecodeError::NonzeroFlags(input[7]));
    }
    let payload_len = u32::from_be_bytes([input[8], input[9], input[10], input[11]]);
    if payload_len > MAX_STORAGE_RECORD_PAYLOAD_BYTES {
        return Err(StorageRecordDecodeError::PayloadTooLong {
            actual: payload_len,
            maximum: MAX_STORAGE_RECORD_PAYLOAD_BYTES,
        });
    }
    let payload_len =
        usize::try_from(payload_len).map_err(|_| StorageRecordDecodeError::RecordTooLong)?;
    let expected = STORAGE_RECORD_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|value| value.checked_add(STORAGE_RECORD_CHECKSUM_LEN))
        .ok_or(StorageRecordDecodeError::RecordTooLong)?;
    if input.len() < expected {
        return Err(StorageRecordDecodeError::Truncated);
    }
    if input.len() > expected {
        return Err(StorageRecordDecodeError::TrailingBytes);
    }
    let checksum_offset = STORAGE_RECORD_HEADER_LEN + payload_len;
    let expected_checksum = storage_checksum(&input[..checksum_offset]);
    if input[checksum_offset..] != expected_checksum {
        return Err(StorageRecordDecodeError::ChecksumMismatch);
    }
    Ok(DecodedStorageRecord {
        kind,
        payload: &input[STORAGE_RECORD_HEADER_LEN..checksum_offset],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedStorageRecordError {
    Record(StorageRecordDecodeError),
    WrongKind {
        expected: StorageRecordKind,
        actual: StorageRecordKind,
    },
    WrongPayloadLength {
        actual: usize,
        expected: usize,
    },
    NonCanonicalField(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageManifest {
    pub identity: NetworkIdentity,
    pub genesis_block_id: BlockId,
    pub active_generation: u64,
    pub active_tip: BlockId,
}

impl StorageManifest {
    pub fn encode(self) -> Result<Vec<u8>, StorageRecordEncodeError> {
        let mut payload = Vec::with_capacity(MANIFEST_PAYLOAD_LEN);
        payload.extend_from_slice(self.identity.chain_id.as_bytes());
        payload.extend_from_slice(&self.identity.network_id.get().to_be_bytes());
        payload.extend_from_slice(self.identity.genesis_commitment.as_bytes());
        payload.extend_from_slice(self.genesis_block_id.as_bytes());
        payload.extend_from_slice(&self.active_generation.to_be_bytes());
        payload.extend_from_slice(self.active_tip.as_bytes());
        encode_storage_record(StorageRecordKind::Manifest, &payload)
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, TypedStorageRecordError> {
        let payload = typed_payload(input, StorageRecordKind::Manifest, MANIFEST_PAYLOAD_LEN)?;
        Ok(Self {
            identity: NetworkIdentity {
                chain_id: ChainId::new(typed_array(payload, 0)?),
                network_id: NetworkId::new(u32::from_be_bytes(typed_array(payload, 32)?)),
                genesis_commitment: GenesisCommitment::new(typed_array(payload, 36)?),
            },
            genesis_block_id: BlockId::new(typed_array(payload, 68)?),
            active_generation: u64::from_be_bytes(typed_array(payload, 100)?),
            active_tip: BlockId::new(typed_array(payload, 108)?),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StorageMutationKind {
    StoreBlock = 1,
    Reorganization = 2,
}

impl StorageMutationKind {
    fn from_tag(tag: u8) -> Result<Self, TypedStorageRecordError> {
        match tag {
            1 => Ok(Self::StoreBlock),
            2 => Ok(Self::Reorganization),
            _ => Err(TypedStorageRecordError::NonCanonicalField("mutation_kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRecoveryMarker {
    Clean {
        active_generation: u64,
        active_tip: BlockId,
    },
    Prepared {
        mutation: StorageMutationKind,
        base_generation: u64,
        candidate_generation: u64,
        subject: BlockId,
        expected_tip: BlockId,
    },
    Published {
        mutation: StorageMutationKind,
        base_generation: u64,
        candidate_generation: u64,
        subject: BlockId,
        expected_tip: BlockId,
    },
}

impl StorageRecoveryMarker {
    pub fn encode(self) -> Result<Vec<u8>, StorageRecordEncodeError> {
        let (state, mutation, base, candidate, subject, expected_tip) = match self {
            Self::Clean {
                active_generation,
                active_tip,
            } => (
                0,
                0,
                active_generation,
                active_generation,
                ZERO_BLOCK_ID,
                active_tip,
            ),
            Self::Prepared {
                mutation,
                base_generation,
                candidate_generation,
                subject,
                expected_tip,
            } => (
                1,
                mutation as u8,
                base_generation,
                candidate_generation,
                subject,
                expected_tip,
            ),
            Self::Published {
                mutation,
                base_generation,
                candidate_generation,
                subject,
                expected_tip,
            } => (
                2,
                mutation as u8,
                base_generation,
                candidate_generation,
                subject,
                expected_tip,
            ),
        };
        if state != 0 && base.checked_add(1) != Some(candidate) {
            return Err(StorageRecordEncodeError::NonCanonicalField(
                "candidate_generation",
            ));
        }
        let mut payload = Vec::with_capacity(RECOVERY_PAYLOAD_LEN);
        payload.push(state);
        payload.push(mutation);
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&base.to_be_bytes());
        payload.extend_from_slice(&candidate.to_be_bytes());
        payload.extend_from_slice(subject.as_bytes());
        payload.extend_from_slice(expected_tip.as_bytes());
        encode_storage_record(StorageRecordKind::Recovery, &payload)
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, TypedStorageRecordError> {
        let payload = typed_payload(input, StorageRecordKind::Recovery, RECOVERY_PAYLOAD_LEN)?;
        if payload[2..4] != [0, 0] {
            return Err(TypedStorageRecordError::NonCanonicalField("reserved"));
        }
        let base = u64::from_be_bytes(typed_array(payload, 4)?);
        let candidate = u64::from_be_bytes(typed_array(payload, 12)?);
        let subject = BlockId::new(typed_array(payload, 20)?);
        let expected_tip = BlockId::new(typed_array(payload, 52)?);
        match payload[0] {
            0 => {
                if payload[1] != 0 || candidate != base || subject != ZERO_BLOCK_ID {
                    return Err(TypedStorageRecordError::NonCanonicalField("clean_marker"));
                }
                Ok(Self::Clean {
                    active_generation: base,
                    active_tip: expected_tip,
                })
            }
            state @ (1 | 2) => {
                let mutation = StorageMutationKind::from_tag(payload[1])?;
                if base.checked_add(1) != Some(candidate) {
                    return Err(TypedStorageRecordError::NonCanonicalField(
                        "candidate_generation",
                    ));
                }
                if state == 1 {
                    Ok(Self::Prepared {
                        mutation,
                        base_generation: base,
                        candidate_generation: candidate,
                        subject,
                        expected_tip,
                    })
                } else {
                    Ok(Self::Published {
                        mutation,
                        base_generation: base,
                        candidate_generation: candidate,
                        subject,
                        expected_tip,
                    })
                }
            }
            _ => Err(TypedStorageRecordError::NonCanonicalField("recovery_state")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageGenerationSeal {
    pub generation: u64,
    pub tip: BlockId,
    pub state_root: StateRoot,
    pub issued_supply: u128,
    pub height_count: u64,
    pub transaction_count: u64,
    pub account_count: u64,
    pub records_digest: Hash32,
}

impl StorageGenerationSeal {
    pub fn encode(self) -> Result<Vec<u8>, StorageRecordEncodeError> {
        if self.issued_supply > u128::from(MAX_MONEY) {
            return Err(StorageRecordEncodeError::NonCanonicalField("issued_supply"));
        }
        let mut payload = Vec::with_capacity(GENERATION_SEAL_PAYLOAD_LEN);
        payload.extend_from_slice(&self.generation.to_be_bytes());
        payload.extend_from_slice(self.tip.as_bytes());
        payload.extend_from_slice(self.state_root.as_bytes());
        payload.extend_from_slice(&self.issued_supply.to_be_bytes());
        payload.extend_from_slice(&self.height_count.to_be_bytes());
        payload.extend_from_slice(&self.transaction_count.to_be_bytes());
        payload.extend_from_slice(&self.account_count.to_be_bytes());
        payload.extend_from_slice(self.records_digest.as_bytes());
        encode_storage_record(StorageRecordKind::GenerationSeal, &payload)
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, TypedStorageRecordError> {
        let payload = typed_payload(
            input,
            StorageRecordKind::GenerationSeal,
            GENERATION_SEAL_PAYLOAD_LEN,
        )?;
        let issued_supply = u128::from_be_bytes(typed_array(payload, 72)?);
        if issued_supply > u128::from(MAX_MONEY) {
            return Err(TypedStorageRecordError::NonCanonicalField("issued_supply"));
        }
        Ok(Self {
            generation: u64::from_be_bytes(typed_array(payload, 0)?),
            tip: BlockId::new(typed_array(payload, 8)?),
            state_root: StateRoot::new(typed_array(payload, 40)?),
            issued_supply,
            height_count: u64::from_be_bytes(typed_array(payload, 88)?),
            transaction_count: u64::from_be_bytes(typed_array(payload, 96)?),
            account_count: u64::from_be_bytes(typed_array(payload, 104)?),
            records_digest: Hash32::new(typed_array(payload, 112)?),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageAccountRecord {
    pub account: Account,
}

impl StorageAccountRecord {
    pub fn encode(self) -> Result<Vec<u8>, StorageRecordEncodeError> {
        validate_stored_account(self.account, false)
            .map_err(StorageRecordEncodeError::NonCanonicalField)?;
        let mut payload = Vec::with_capacity(ACCOUNT_PAYLOAD_LEN);
        payload.extend_from_slice(&self.account.balance.get().to_be_bytes());
        payload.extend_from_slice(&self.account.nonce.get().to_be_bytes());
        encode_storage_record(StorageRecordKind::Account, &payload)
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, TypedStorageRecordError> {
        let payload = typed_payload(input, StorageRecordKind::Account, ACCOUNT_PAYLOAD_LEN)?;
        let account = Account::new(
            Amount::new(u64::from_be_bytes(typed_array(payload, 0)?)),
            Nonce::new(u64::from_be_bytes(typed_array(payload, 8)?)),
        );
        validate_stored_account(account, false)
            .map_err(TypedStorageRecordError::NonCanonicalField)?;
        Ok(Self { account })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageAccountDeltaRecord {
    pub before: Account,
    pub after: Account,
}

impl StorageAccountDeltaRecord {
    pub fn encode(self) -> Result<Vec<u8>, StorageRecordEncodeError> {
        validate_stored_account(self.before, true)
            .map_err(StorageRecordEncodeError::NonCanonicalField)?;
        validate_stored_account(self.after, true)
            .map_err(StorageRecordEncodeError::NonCanonicalField)?;
        if self.before == self.after {
            return Err(StorageRecordEncodeError::NonCanonicalField(
                "unchanged_delta",
            ));
        }
        let mut payload = Vec::with_capacity(ACCOUNT_DELTA_PAYLOAD_LEN);
        payload.extend_from_slice(&self.before.balance.get().to_be_bytes());
        payload.extend_from_slice(&self.before.nonce.get().to_be_bytes());
        payload.extend_from_slice(&self.after.balance.get().to_be_bytes());
        payload.extend_from_slice(&self.after.nonce.get().to_be_bytes());
        encode_storage_record(StorageRecordKind::AccountDelta, &payload)
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, TypedStorageRecordError> {
        let payload = typed_payload(
            input,
            StorageRecordKind::AccountDelta,
            ACCOUNT_DELTA_PAYLOAD_LEN,
        )?;
        let before = Account::new(
            Amount::new(u64::from_be_bytes(typed_array(payload, 0)?)),
            Nonce::new(u64::from_be_bytes(typed_array(payload, 8)?)),
        );
        let after = Account::new(
            Amount::new(u64::from_be_bytes(typed_array(payload, 16)?)),
            Nonce::new(u64::from_be_bytes(typed_array(payload, 24)?)),
        );
        validate_stored_account(before, true)
            .map_err(TypedStorageRecordError::NonCanonicalField)?;
        validate_stored_account(after, true).map_err(TypedStorageRecordError::NonCanonicalField)?;
        if before == after {
            return Err(TypedStorageRecordError::NonCanonicalField(
                "unchanged_delta",
            ));
        }
        Ok(Self { before, after })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCanonicalTipRecord {
    pub block_id: BlockId,
    pub state_root: StateRoot,
    pub issued_supply: u128,
}

impl StorageCanonicalTipRecord {
    pub fn encode(self) -> Result<Vec<u8>, StorageRecordEncodeError> {
        if self.issued_supply > u128::from(MAX_MONEY) {
            return Err(StorageRecordEncodeError::NonCanonicalField("issued_supply"));
        }
        let mut payload = Vec::with_capacity(CANONICAL_TIP_PAYLOAD_LEN);
        payload.extend_from_slice(self.block_id.as_bytes());
        payload.extend_from_slice(self.state_root.as_bytes());
        payload.extend_from_slice(&self.issued_supply.to_be_bytes());
        encode_storage_record(StorageRecordKind::CanonicalTip, &payload)
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, TypedStorageRecordError> {
        let payload = typed_payload(
            input,
            StorageRecordKind::CanonicalTip,
            CANONICAL_TIP_PAYLOAD_LEN,
        )?;
        let issued_supply = u128::from_be_bytes(typed_array(payload, 64)?);
        if issued_supply > u128::from(MAX_MONEY) {
            return Err(TypedStorageRecordError::NonCanonicalField("issued_supply"));
        }
        Ok(Self {
            block_id: BlockId::new(typed_array(payload, 0)?),
            state_root: StateRoot::new(typed_array(payload, 32)?),
            issued_supply,
        })
    }
}

pub fn encode_storage_block_id(block_id: BlockId) -> Result<Vec<u8>, StorageRecordEncodeError> {
    encode_storage_record(StorageRecordKind::BlockId, block_id.as_bytes())
}

pub fn decode_storage_block_id(input: &[u8]) -> Result<BlockId, TypedStorageRecordError> {
    let payload = typed_payload(input, StorageRecordKind::BlockId, 32)?;
    Ok(BlockId::new(typed_array(payload, 0)?))
}

pub fn encode_storage_transaction_id(
    transaction_id: TransactionId,
) -> Result<Vec<u8>, StorageRecordEncodeError> {
    encode_storage_record(StorageRecordKind::TransactionId, transaction_id.as_bytes())
}

pub fn decode_storage_transaction_id(
    input: &[u8],
) -> Result<TransactionId, TypedStorageRecordError> {
    let payload = typed_payload(input, StorageRecordKind::TransactionId, 32)?;
    Ok(TransactionId::new(typed_array(payload, 0)?))
}

pub fn encode_block_visibility() -> Result<Vec<u8>, StorageRecordEncodeError> {
    encode_storage_record(StorageRecordKind::BlockVisibility, &[])
}

pub fn decode_block_visibility(input: &[u8]) -> Result<(), TypedStorageRecordError> {
    typed_payload(input, StorageRecordKind::BlockVisibility, 0).map(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationDigestError {
    KeyTooLong { actual: usize, maximum: usize },
    ValueTooLong { actual: usize, maximum: u32 },
    NonIncreasingKey,
    EntryCountOverflow,
}

/// Hashes strictly increasing key/value records, excluding the generation
/// seal itself. This detects operational corruption and is not a consensus
/// commitment.
pub fn storage_generation_digest<'a, I>(entries: I) -> Result<Hash32, GenerationDigestError>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let mut hasher = Hasher::new_derive_key(STORAGE_GENERATION_DIGEST_CONTEXT);
    let mut previous: Option<Vec<u8>> = None;
    let mut count = 0_u64;
    for (key, value) in entries {
        if key.len() > MAX_STORAGE_KEY_BYTES {
            return Err(GenerationDigestError::KeyTooLong {
                actual: key.len(),
                maximum: MAX_STORAGE_KEY_BYTES,
            });
        }
        let key_len = u16::try_from(key.len()).map_err(|_| GenerationDigestError::KeyTooLong {
            actual: key.len(),
            maximum: MAX_STORAGE_KEY_BYTES,
        })?;
        let value_len =
            u32::try_from(value.len()).map_err(|_| GenerationDigestError::ValueTooLong {
                actual: value.len(),
                maximum: MAX_STORAGE_RECORD_PAYLOAD_BYTES,
            })?;
        if value_len > MAX_STORAGE_RECORD_PAYLOAD_BYTES {
            return Err(GenerationDigestError::ValueTooLong {
                actual: value.len(),
                maximum: MAX_STORAGE_RECORD_PAYLOAD_BYTES,
            });
        }
        if previous.as_deref().is_some_and(|prior| prior >= key) {
            return Err(GenerationDigestError::NonIncreasingKey);
        }
        hasher.update(&[0]);
        hasher.update(&key_len.to_be_bytes());
        hasher.update(key);
        hasher.update(&value_len.to_be_bytes());
        hasher.update(value);
        previous = Some(key.to_vec());
        count = count
            .checked_add(1)
            .ok_or(GenerationDigestError::EntryCountOverflow)?;
    }
    hasher.update(&[0xff]);
    hasher.update(&count.to_be_bytes());
    Ok(Hash32::new(*hasher.finalize().as_bytes()))
}

fn storage_checksum(input: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(STORAGE_RECORD_CHECKSUM_CONTEXT);
    hasher.update(input);
    *hasher.finalize().as_bytes()
}

fn typed_payload(
    input: &[u8],
    expected_kind: StorageRecordKind,
    expected_len: usize,
) -> Result<&[u8], TypedStorageRecordError> {
    let record = decode_storage_record_exact(input).map_err(TypedStorageRecordError::Record)?;
    if record.kind != expected_kind {
        return Err(TypedStorageRecordError::WrongKind {
            expected: expected_kind,
            actual: record.kind,
        });
    }
    if record.payload.len() != expected_len {
        return Err(TypedStorageRecordError::WrongPayloadLength {
            actual: record.payload.len(),
            expected: expected_len,
        });
    }
    Ok(record.payload)
}

fn typed_array<const N: usize>(
    input: &[u8],
    offset: usize,
) -> Result<[u8; N], TypedStorageRecordError> {
    let end = offset
        .checked_add(N)
        .ok_or(TypedStorageRecordError::NonCanonicalField("offset"))?;
    input
        .get(offset..end)
        .ok_or(TypedStorageRecordError::NonCanonicalField(
            "truncated_payload",
        ))?
        .try_into()
        .map_err(|_| TypedStorageRecordError::NonCanonicalField("field_width"))
}

fn require_key_len(input: &[u8], expected: usize) -> Result<(), StorageKeyDecodeError> {
    if input.len() == expected {
        Ok(())
    } else {
        Err(StorageKeyDecodeError::WrongLength {
            actual: input.len(),
            expected,
        })
    }
}

fn array_at<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], StorageKeyDecodeError> {
    let end = offset
        .checked_add(N)
        .ok_or(StorageKeyDecodeError::Truncated)?;
    input
        .get(offset..end)
        .ok_or(StorageKeyDecodeError::Truncated)?
        .try_into()
        .map_err(|_| StorageKeyDecodeError::Truncated)
}

fn decode_recipient(bytes: [u8; 33]) -> Result<Recipient, StorageKeyDecodeError> {
    Recipient::from_bytes(bytes)
        .map_err(|_| StorageKeyDecodeError::UnsupportedRecipientVersion(bytes[0]))
}

fn validate_stored_account(account: Account, allow_absent: bool) -> Result<(), &'static str> {
    if account.balance.get() > MAX_MONEY {
        return Err("account_balance");
    }
    if !allow_absent && account.is_absent() {
        return Err("absent_account");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use out_consensus::NetworkIdentity;
    use out_primitives::{Hash32, Recipient};

    use super::*;

    fn recipient(byte: u8) -> Recipient {
        let mut bytes = [byte; 33];
        bytes[0] = 0;
        Recipient::from_bytes(bytes).expect("recipient")
    }

    #[test]
    fn every_storage_key_is_exact_and_round_trips() {
        let block = BlockId::new([0x11; 32]);
        let transaction = TransactionId::new([0x22; 32]);
        let account = recipient(0x33);
        let keys = [
            StorageKey::Manifest,
            StorageKey::Recovery,
            StorageKey::BlockVisible(block),
            StorageKey::BlockBytes(block),
            StorageKey::BlockTransaction {
                block_id: block,
                index: 7,
            },
            StorageKey::BranchAccount {
                block_id: block,
                recipient: account,
            },
            StorageKey::AccountDelta {
                block_id: block,
                recipient: account,
            },
            StorageKey::StateNode(Hash32::new([0x44; 32])),
            StorageKey::GenerationSeal(9),
            StorageKey::CanonicalTip(9),
            StorageKey::CanonicalHeight {
                generation: 9,
                height: 10,
            },
            StorageKey::CanonicalTransaction {
                generation: 9,
                transaction_id: transaction,
            },
            StorageKey::CanonicalAccount {
                generation: 9,
                recipient: account,
            },
        ];
        for key in keys {
            let encoded = key.encode();
            assert!(encoded.len() <= MAX_STORAGE_KEY_BYTES);
            assert_eq!(StorageKey::decode_exact(&encoded), Ok(key));
            let mut trailing = encoded;
            trailing.push(0);
            assert!(matches!(
                StorageKey::decode_exact(&trailing),
                Err(StorageKeyDecodeError::WrongLength { .. })
            ));
        }
        assert_eq!(StorageKey::Manifest.encode(), vec![0x00]);
        assert_eq!(
            StorageKey::CanonicalHeight {
                generation: 1,
                height: 2
            }
            .encode(),
            [
                vec![0x22],
                1_u64.to_be_bytes().to_vec(),
                2_u64.to_be_bytes().to_vec()
            ]
            .concat()
        );
    }

    #[test]
    fn keys_reject_unknown_tags_and_recipient_versions() {
        assert_eq!(
            StorageKey::decode_exact(&[0xff]),
            Err(StorageKeyDecodeError::UnknownTag(0xff))
        );
        let mut key = StorageKey::CanonicalAccount {
            generation: 1,
            recipient: recipient(7),
        }
        .encode();
        key[9] = 1;
        assert_eq!(
            StorageKey::decode_exact(&key),
            Err(StorageKeyDecodeError::UnsupportedRecipientVersion(1))
        );
    }

    #[test]
    fn record_envelope_round_trips_and_detects_corruption() {
        let record = encode_storage_record(StorageRecordKind::Account, b"account").expect("record");
        let decoded = decode_storage_record_exact(&record).expect("decode");
        assert_eq!(decoded.kind, StorageRecordKind::Account);
        assert_eq!(decoded.payload, b"account");

        let mut corrupt = record.clone();
        corrupt[STORAGE_RECORD_HEADER_LEN] ^= 1;
        assert_eq!(
            decode_storage_record_exact(&corrupt),
            Err(StorageRecordDecodeError::ChecksumMismatch)
        );
        let mut trailing = record.clone();
        trailing.push(0);
        assert_eq!(
            decode_storage_record_exact(&trailing),
            Err(StorageRecordDecodeError::TrailingBytes)
        );
        assert_eq!(
            decode_storage_record_exact(&record[..record.len() - 1]),
            Err(StorageRecordDecodeError::Truncated)
        );
    }

    #[test]
    fn schema_flags_kind_and_length_fail_before_checksum() {
        let record = encode_storage_record(StorageRecordKind::Account, b"x").expect("record");
        let mut schema = record.clone();
        schema[5] = 1;
        assert_eq!(
            decode_storage_record_exact(&schema),
            Err(StorageRecordDecodeError::UnsupportedSchema(1))
        );
        let mut kind = record.clone();
        kind[6] = 0xff;
        assert_eq!(
            decode_storage_record_exact(&kind),
            Err(StorageRecordDecodeError::UnknownKind(0xff))
        );
        let mut flags = record.clone();
        flags[7] = 1;
        assert_eq!(
            decode_storage_record_exact(&flags),
            Err(StorageRecordDecodeError::NonzeroFlags(1))
        );
        let mut oversized = record;
        oversized[8..12].copy_from_slice(&(MAX_STORAGE_RECORD_PAYLOAD_BYTES + 1).to_be_bytes());
        assert!(matches!(
            decode_storage_record_exact(&oversized),
            Err(StorageRecordDecodeError::PayloadTooLong { .. })
        ));
    }

    #[test]
    fn manifest_round_trips_and_wrong_kind_is_rejected() {
        let manifest = StorageManifest {
            identity: NetworkIdentity::devnet(),
            genesis_block_id: BlockId::new([0x55; 32]),
            active_generation: 7,
            active_tip: BlockId::new([0x66; 32]),
        };
        let encoded = manifest.encode().expect("manifest");
        assert_eq!(StorageManifest::decode_exact(&encoded), Ok(manifest));
        let wrong = encode_storage_record(StorageRecordKind::Account, &[0; MANIFEST_PAYLOAD_LEN])
            .expect("wrong kind");
        assert!(matches!(
            StorageManifest::decode_exact(&wrong),
            Err(TypedStorageRecordError::WrongKind { .. })
        ));
    }

    #[test]
    fn recovery_markers_round_trip_and_require_next_generation() {
        let tip = BlockId::new([0x77; 32]);
        let subject = BlockId::new([0x88; 32]);
        let markers = [
            StorageRecoveryMarker::Clean {
                active_generation: 4,
                active_tip: tip,
            },
            StorageRecoveryMarker::Prepared {
                mutation: StorageMutationKind::StoreBlock,
                base_generation: 4,
                candidate_generation: 5,
                subject,
                expected_tip: tip,
            },
            StorageRecoveryMarker::Published {
                mutation: StorageMutationKind::Reorganization,
                base_generation: 4,
                candidate_generation: 5,
                subject,
                expected_tip: subject,
            },
        ];
        for marker in markers {
            let encoded = marker.encode().expect("marker");
            assert_eq!(StorageRecoveryMarker::decode_exact(&encoded), Ok(marker));
        }
        assert_eq!(
            StorageRecoveryMarker::Prepared {
                mutation: StorageMutationKind::StoreBlock,
                base_generation: 4,
                candidate_generation: 6,
                subject,
                expected_tip: tip,
            }
            .encode(),
            Err(StorageRecordEncodeError::NonCanonicalField(
                "candidate_generation"
            ))
        );
    }

    #[test]
    fn generation_seal_round_trips_and_enforces_money_cap() {
        let seal = StorageGenerationSeal {
            generation: 3,
            tip: BlockId::new([1; 32]),
            state_root: StateRoot::new([2; 32]),
            issued_supply: 500_000_000,
            height_count: 2,
            transaction_count: 1,
            account_count: 1,
            records_digest: Hash32::new([3; 32]),
        };
        let encoded = seal.encode().expect("seal");
        assert_eq!(StorageGenerationSeal::decode_exact(&encoded), Ok(seal));
        assert_eq!(
            StorageGenerationSeal {
                issued_supply: u128::from(MAX_MONEY) + 1,
                ..seal
            }
            .encode(),
            Err(StorageRecordEncodeError::NonCanonicalField("issued_supply"))
        );
    }

    #[test]
    fn fixed_operational_values_round_trip_and_reject_noncanonical_accounts() {
        let account = Account::new(Amount::new(42), Nonce::new(3));
        let account_record = StorageAccountRecord { account };
        let encoded = account_record.encode().expect("account record");
        assert_eq!(
            StorageAccountRecord::decode_exact(&encoded),
            Ok(account_record)
        );
        assert_eq!(
            StorageAccountRecord {
                account: Account::EMPTY
            }
            .encode(),
            Err(StorageRecordEncodeError::NonCanonicalField(
                "absent_account"
            ))
        );

        let delta = StorageAccountDeltaRecord {
            before: Account::EMPTY,
            after: account,
        };
        let encoded = delta.encode().expect("delta record");
        assert_eq!(StorageAccountDeltaRecord::decode_exact(&encoded), Ok(delta));
        assert_eq!(
            StorageAccountDeltaRecord {
                before: account,
                after: account,
            }
            .encode(),
            Err(StorageRecordEncodeError::NonCanonicalField(
                "unchanged_delta"
            ))
        );

        let tip = StorageCanonicalTipRecord {
            block_id: BlockId::new([0x91; 32]),
            state_root: StateRoot::new([0x92; 32]),
            issued_supply: 42,
        };
        let encoded = tip.encode().expect("tip record");
        assert_eq!(StorageCanonicalTipRecord::decode_exact(&encoded), Ok(tip));

        let block_id = BlockId::new([0x93; 32]);
        assert_eq!(
            decode_storage_block_id(&encode_storage_block_id(block_id).expect("block id")),
            Ok(block_id)
        );
        let transaction_id = TransactionId::new([0x94; 32]);
        assert_eq!(
            decode_storage_transaction_id(
                &encode_storage_transaction_id(transaction_id).expect("transaction id")
            ),
            Ok(transaction_id)
        );
        assert_eq!(
            decode_block_visibility(&encode_block_visibility().expect("visibility")),
            Ok(())
        );
    }

    #[test]
    fn generation_digest_is_ordered_bounded_and_sensitive() {
        let entries = [(b"a".as_slice(), b"one".as_slice()), (b"b", b"two")];
        let digest = storage_generation_digest(entries).expect("digest");
        assert_eq!(storage_generation_digest(entries), Ok(digest));
        assert_ne!(
            storage_generation_digest([(b"a".as_slice(), b"one".as_slice()), (b"b", b"changed")]),
            Ok(digest)
        );
        assert_eq!(
            storage_generation_digest([(b"b".as_slice(), b"two".as_slice()), (b"a", b"one")]),
            Err(GenerationDigestError::NonIncreasingKey)
        );
        assert_eq!(
            storage_generation_digest([(b"a".as_slice(), b"one".as_slice()), (b"a", b"one")]),
            Err(GenerationDigestError::NonIncreasingKey)
        );
    }
}
