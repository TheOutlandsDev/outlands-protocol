#![forbid(unsafe_code)]

//! Bounded, canonical OUT P2P v0 frame and message codec.

pub mod session;

use std::collections::BTreeSet;

use out_codec::{
    Block, BlockHeader, DecodeError as ConsensusDecodeError, Encoder, Transaction,
    BLOCK_HEADER_LEN, MAX_BLOCK_BYTES, MAX_TX_BYTES,
};
use out_crypto::{Blake3Hasher, ConsensusDomain, ConsensusHasher};
use out_primitives::{BlockId, ChainId, GenesisCommitment, Hash32, NetworkId, TransactionId};

pub const PROTOCOL_VERSION_V0: u16 = 0;
pub const FRAME_HEADER_BYTES: usize = 54;
pub const MAX_P2P_PAYLOAD_BYTES: u32 = 4_194_304;
pub const MAX_INV_ENTRIES: u16 = 2_048;
pub const MAX_LOCATOR_ENTRIES: u16 = 128;
pub const MAX_HEADERS: u16 = 2_000;
pub const MAX_REJECT_DETAIL_BYTES: u16 = 256;
pub const HELLO_PAYLOAD_BYTES: u32 = 116;

pub const TYPE_HELLO: u16 = 0x0001;
pub const TYPE_HELLO_ACK: u16 = 0x0002;
pub const TYPE_PING: u16 = 0x0003;
pub const TYPE_PONG: u16 = 0x0004;
pub const TYPE_INV: u16 = 0x0010;
pub const TYPE_GET_OBJECTS: u16 = 0x0011;
pub const TYPE_TX: u16 = 0x0012;
pub const TYPE_BLOCK: u16 = 0x0013;
pub const TYPE_GET_HEADERS: u16 = 0x0020;
pub const TYPE_HEADERS: u16 = 0x0021;
pub const TYPE_REJECT: u16 = 0x007f;
pub const IGNORABLE_TYPE_START: u16 = 0x8000;

const TESTNET_MAGIC: [u8; 4] = [0xb1, 0xe4, 0xaa, 0x74];
const DEVNET_MAGIC: [u8; 4] = [0x6b, 0xb4, 0x9c, 0x33];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2pNetwork {
    Testnet,
    Devnet,
}

impl P2pNetwork {
    pub const fn magic(self) -> [u8; 4] {
        match self {
            Self::Testnet => TESTNET_MAGIC,
            Self::Devnet => DEVNET_MAGIC,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hello {
    pub min_protocol_version: u16,
    pub max_protocol_version: u16,
    pub min_consensus_version: u16,
    pub max_consensus_version: u16,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub genesis_commitment: GenesisCommitment,
    pub best_height: u64,
    pub best_block_id: BlockId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloIdentityError {
    ChainId,
    NetworkId,
    GenesisCommitment,
}

impl Hello {
    pub fn require_identity(
        &self,
        chain_id: ChainId,
        network_id: NetworkId,
        genesis_commitment: GenesisCommitment,
    ) -> Result<(), HelloIdentityError> {
        if self.chain_id != chain_id {
            return Err(HelloIdentityError::ChainId);
        }
        if self.network_id != network_id {
            return Err(HelloIdentityError::NetworkId);
        }
        if self.genesis_commitment != genesis_commitment {
            return Err(HelloIdentityError::GenesisCommitment);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InventoryEntry {
    Transaction(TransactionId),
    Block(BlockId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Hello(Hello),
    HelloAck(Hello),
    Ping(u64),
    Pong(u64),
    Inventory(Vec<InventoryEntry>),
    GetObjects(Vec<InventoryEntry>),
    Transaction(Transaction),
    Block(Block),
    GetHeaders {
        locator: Vec<BlockId>,
        stop_id: BlockId,
    },
    Headers(Vec<BlockHeader>),
    Reject {
        rejected_type: u16,
        code: u16,
        detail: Vec<u8>,
    },
    IgnorableExtension {
        message_type: u16,
        payload: Vec<u8>,
    },
}

impl Message {
    pub const fn message_type(&self) -> u16 {
        match self {
            Self::Hello(_) => TYPE_HELLO,
            Self::HelloAck(_) => TYPE_HELLO_ACK,
            Self::Ping(_) => TYPE_PING,
            Self::Pong(_) => TYPE_PONG,
            Self::Inventory(_) => TYPE_INV,
            Self::GetObjects(_) => TYPE_GET_OBJECTS,
            Self::Transaction(_) => TYPE_TX,
            Self::Block(_) => TYPE_BLOCK,
            Self::GetHeaders { .. } => TYPE_GET_HEADERS,
            Self::Headers(_) => TYPE_HEADERS,
            Self::Reject { .. } => TYPE_REJECT,
            Self::IgnorableExtension { message_type, .. } => *message_type,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub network_magic: [u8; 4],
    pub protocol_version: u16,
    pub message_type: u16,
    pub flags: u16,
    pub request_id: u64,
    pub payload_len: u32,
    pub payload_checksum: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub header: FrameHeader,
    pub message: Message,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    InvalidVersionRange(&'static str),
    CountExceeds { field: &'static str, maximum: u16 },
    EmptyLocator,
    DuplicateInventory,
    ExtensionTypeMustBeIgnorable(u16),
    PayloadTooLarge { actual: u32, maximum: u32 },
    TypePayloadLength { message_type: u16, actual: u32 },
    ConsensusObject,
    IntegerWidth,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    HeaderLength { actual: usize },
    WrongNetworkMagic,
    UnsupportedProtocolVersion(u16),
    NonzeroFlags(u16),
    UnknownMandatoryType(u16),
    PayloadTooLarge { declared: u32, maximum: u32 },
    TypePayloadLength { message_type: u16, declared: u32 },
    TruncatedFrame { declared: u32, available: usize },
    TrailingFrameBytes { declared: u32, trailing: usize },
    ChecksumMismatch,
    PayloadTruncated,
    PayloadTrailingBytes,
    InvalidVersionRange(&'static str),
    CountOutOfRange { field: &'static str, count: u16 },
    InvalidInventoryKind(u8),
    DuplicateInventory,
    ConsensusObject(ConsensusDecodeError),
    InvalidBlockEnvelope,
    IntegerWidth,
}

pub fn encode_frame(
    network: P2pNetwork,
    request_id: u64,
    message: &Message,
) -> Result<Vec<u8>, EncodeError> {
    let message_type = message.message_type();
    let payload = encode_payload(message)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| EncodeError::IntegerWidth)?;
    validate_declared_length(message_type, payload_len).map_err(map_length_encode_error)?;
    let checksum = payload_checksum(
        PROTOCOL_VERSION_V0,
        message_type,
        request_id,
        payload_len,
        &payload,
    );
    let total = FRAME_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(EncodeError::IntegerWidth)?;
    let mut output = Encoder::with_capacity(total);
    output.write_fixed(&network.magic());
    output.write_u16(PROTOCOL_VERSION_V0);
    output.write_u16(message_type);
    output.write_u16(0);
    output.write_u64(request_id);
    output.write_u32(payload_len);
    output.write_fixed(checksum.as_bytes());
    output.write_fixed(&payload);
    Ok(output.into_bytes())
}

/// Decodes and bounds exactly one 54-byte frame header. This function performs
/// no payload allocation and is suitable for transport preflight checks.
pub fn decode_frame_header(
    input: &[u8],
    expected_network: P2pNetwork,
    negotiated_version: u16,
) -> Result<FrameHeader, DecodeError> {
    if input.len() != FRAME_HEADER_BYTES {
        return Err(DecodeError::HeaderLength {
            actual: input.len(),
        });
    }
    let network_magic: [u8; 4] = input[0..4]
        .try_into()
        .map_err(|_| DecodeError::IntegerWidth)?;
    if network_magic != expected_network.magic() {
        return Err(DecodeError::WrongNetworkMagic);
    }
    let protocol_version = u16::from_be_bytes(
        input[4..6]
            .try_into()
            .map_err(|_| DecodeError::IntegerWidth)?,
    );
    if protocol_version != negotiated_version || protocol_version != PROTOCOL_VERSION_V0 {
        return Err(DecodeError::UnsupportedProtocolVersion(protocol_version));
    }
    let message_type = u16::from_be_bytes(
        input[6..8]
            .try_into()
            .map_err(|_| DecodeError::IntegerWidth)?,
    );
    let flags = u16::from_be_bytes(
        input[8..10]
            .try_into()
            .map_err(|_| DecodeError::IntegerWidth)?,
    );
    if flags != 0 {
        return Err(DecodeError::NonzeroFlags(flags));
    }
    require_known_or_ignorable(message_type)?;
    let request_id = u64::from_be_bytes(
        input[10..18]
            .try_into()
            .map_err(|_| DecodeError::IntegerWidth)?,
    );
    let payload_len = u32::from_be_bytes(
        input[18..22]
            .try_into()
            .map_err(|_| DecodeError::IntegerWidth)?,
    );
    validate_declared_length(message_type, payload_len)?;
    let payload_checksum = Hash32::new(
        input[22..54]
            .try_into()
            .map_err(|_| DecodeError::IntegerWidth)?,
    );
    Ok(FrameHeader {
        network_magic,
        protocol_version,
        message_type,
        flags,
        request_id,
        payload_len,
        payload_checksum,
    })
}

pub fn decode_frame_exact(
    input: &[u8],
    expected_network: P2pNetwork,
    negotiated_version: u16,
) -> Result<Frame, DecodeError> {
    if input.len() < FRAME_HEADER_BYTES {
        return Err(DecodeError::HeaderLength {
            actual: input.len(),
        });
    }
    let header = decode_frame_header(
        &input[..FRAME_HEADER_BYTES],
        expected_network,
        negotiated_version,
    )?;
    let payload_len = usize::try_from(header.payload_len).map_err(|_| DecodeError::IntegerWidth)?;
    let expected_total = FRAME_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(DecodeError::IntegerWidth)?;
    if input.len() < expected_total {
        return Err(DecodeError::TruncatedFrame {
            declared: header.payload_len,
            available: input.len().saturating_sub(FRAME_HEADER_BYTES),
        });
    }
    if input.len() > expected_total {
        return Err(DecodeError::TrailingFrameBytes {
            declared: header.payload_len,
            trailing: input.len() - expected_total,
        });
    }
    let payload = &input[FRAME_HEADER_BYTES..expected_total];
    let checksum = payload_checksum(
        header.protocol_version,
        header.message_type,
        header.request_id,
        header.payload_len,
        payload,
    );
    if checksum != header.payload_checksum {
        return Err(DecodeError::ChecksumMismatch);
    }
    let message = decode_payload(header.message_type, payload)?;
    Ok(Frame { header, message })
}

pub fn select_protocol_version(
    local_min: u16,
    local_max: u16,
    peer_min: u16,
    peer_max: u16,
) -> Option<u16> {
    if local_min > local_max || peer_min > peer_max {
        return None;
    }
    let selected_min = local_min.max(peer_min);
    let selected_max = local_max.min(peer_max);
    (selected_min <= selected_max).then_some(selected_max)
}

fn payload_checksum(
    protocol_version: u16,
    message_type: u16,
    request_id: u64,
    payload_len: u32,
    payload: &[u8],
) -> Hash32 {
    let mut preimage = Vec::with_capacity(16 + payload.len());
    preimage.extend_from_slice(&protocol_version.to_be_bytes());
    preimage.extend_from_slice(&message_type.to_be_bytes());
    preimage.extend_from_slice(&request_id.to_be_bytes());
    preimage.extend_from_slice(&payload_len.to_be_bytes());
    preimage.extend_from_slice(payload);
    Blake3Hasher.hash_32(ConsensusDomain::P2pChecksum, &preimage)
}

fn encode_payload(message: &Message) -> Result<Vec<u8>, EncodeError> {
    match message {
        Message::Hello(hello) | Message::HelloAck(hello) => encode_hello(hello),
        Message::Ping(token) | Message::Pong(token) => Ok(token.to_be_bytes().to_vec()),
        Message::Inventory(entries) | Message::GetObjects(entries) => encode_inventory(entries),
        Message::Transaction(transaction) => transaction
            .encode()
            .map_err(|_| EncodeError::ConsensusObject),
        Message::Block(block) => {
            if block.header.height == 0 {
                block
                    .encode_genesis()
                    .map_err(|_| EncodeError::ConsensusObject)
            } else {
                block
                    .encode_non_genesis()
                    .map_err(|_| EncodeError::ConsensusObject)
            }
        }
        Message::GetHeaders { locator, stop_id } => encode_get_headers(locator, *stop_id),
        Message::Headers(headers) => encode_headers(headers),
        Message::Reject {
            rejected_type,
            code,
            detail,
        } => encode_reject(*rejected_type, *code, detail),
        Message::IgnorableExtension {
            message_type,
            payload,
        } => {
            if *message_type < IGNORABLE_TYPE_START {
                return Err(EncodeError::ExtensionTypeMustBeIgnorable(*message_type));
            }
            Ok(payload.clone())
        }
    }
}

fn decode_payload(message_type: u16, payload: &[u8]) -> Result<Message, DecodeError> {
    match message_type {
        TYPE_HELLO => decode_hello(payload).map(Message::Hello),
        TYPE_HELLO_ACK => decode_hello(payload).map(Message::HelloAck),
        TYPE_PING => decode_token(payload).map(Message::Ping),
        TYPE_PONG => decode_token(payload).map(Message::Pong),
        TYPE_INV => decode_inventory(payload).map(Message::Inventory),
        TYPE_GET_OBJECTS => decode_inventory(payload).map(Message::GetObjects),
        TYPE_TX => Transaction::decode_exact(payload)
            .map(Message::Transaction)
            .map_err(DecodeError::ConsensusObject),
        TYPE_BLOCK => decode_block(payload).map(Message::Block),
        TYPE_GET_HEADERS => decode_get_headers(payload),
        TYPE_HEADERS => decode_headers(payload).map(Message::Headers),
        TYPE_REJECT => decode_reject(payload),
        value if value >= IGNORABLE_TYPE_START => Ok(Message::IgnorableExtension {
            message_type: value,
            payload: payload.to_vec(),
        }),
        value => Err(DecodeError::UnknownMandatoryType(value)),
    }
}

fn encode_hello(hello: &Hello) -> Result<Vec<u8>, EncodeError> {
    if hello.min_protocol_version > hello.max_protocol_version {
        return Err(EncodeError::InvalidVersionRange("protocol"));
    }
    if hello.min_consensus_version > hello.max_consensus_version {
        return Err(EncodeError::InvalidVersionRange("consensus"));
    }
    let mut output = Encoder::with_capacity(116);
    output.write_u16(hello.min_protocol_version);
    output.write_u16(hello.max_protocol_version);
    output.write_u16(hello.min_consensus_version);
    output.write_u16(hello.max_consensus_version);
    output.write_fixed(hello.chain_id.as_bytes());
    output.write_u32(hello.network_id.get());
    output.write_fixed(hello.genesis_commitment.as_bytes());
    output.write_u64(hello.best_height);
    output.write_fixed(hello.best_block_id.as_bytes());
    Ok(output.into_bytes())
}

fn decode_hello(payload: &[u8]) -> Result<Hello, DecodeError> {
    let min_protocol_version = read_u16(payload, 0)?;
    let max_protocol_version = read_u16(payload, 2)?;
    let min_consensus_version = read_u16(payload, 4)?;
    let max_consensus_version = read_u16(payload, 6)?;
    if min_protocol_version > max_protocol_version {
        return Err(DecodeError::InvalidVersionRange("protocol"));
    }
    if min_consensus_version > max_consensus_version {
        return Err(DecodeError::InvalidVersionRange("consensus"));
    }
    Ok(Hello {
        min_protocol_version,
        max_protocol_version,
        min_consensus_version,
        max_consensus_version,
        chain_id: ChainId::new(read_array(payload, 8)?),
        network_id: NetworkId::new(read_u32(payload, 40)?),
        genesis_commitment: GenesisCommitment::new(read_array(payload, 44)?),
        best_height: read_u64(payload, 76)?,
        best_block_id: BlockId::new(read_array(payload, 84)?),
    })
}

fn encode_inventory(entries: &[InventoryEntry]) -> Result<Vec<u8>, EncodeError> {
    if entries.len() > usize::from(MAX_INV_ENTRIES) {
        return Err(EncodeError::CountExceeds {
            field: "inventory",
            maximum: MAX_INV_ENTRIES,
        });
    }
    let count = u16::try_from(entries.len()).map_err(|_| EncodeError::IntegerWidth)?;
    let mut seen = BTreeSet::new();
    let mut output = Encoder::with_capacity(2 + entries.len() * 33);
    output.write_u16(count);
    for entry in entries {
        if !seen.insert(*entry) {
            return Err(EncodeError::DuplicateInventory);
        }
        match entry {
            InventoryEntry::Transaction(id) => {
                output.write_u8(0);
                output.write_fixed(id.as_bytes());
            }
            InventoryEntry::Block(id) => {
                output.write_u8(1);
                output.write_fixed(id.as_bytes());
            }
        }
    }
    Ok(output.into_bytes())
}

fn decode_inventory(payload: &[u8]) -> Result<Vec<InventoryEntry>, DecodeError> {
    let count = read_u16(payload, 0)?;
    if count > MAX_INV_ENTRIES {
        return Err(DecodeError::CountOutOfRange {
            field: "inventory",
            count,
        });
    }
    let expected = 2_usize
        .checked_add(
            usize::from(count)
                .checked_mul(33)
                .ok_or(DecodeError::IntegerWidth)?,
        )
        .ok_or(DecodeError::IntegerWidth)?;
    require_payload_length(payload, expected)?;
    let mut entries = Vec::with_capacity(usize::from(count));
    let mut seen = BTreeSet::new();
    for index in 0..usize::from(count) {
        let offset = 2 + index * 33;
        let kind = payload[offset];
        let raw = read_array(payload, offset + 1)?;
        let entry = match kind {
            0 => InventoryEntry::Transaction(TransactionId::new(raw)),
            1 => InventoryEntry::Block(BlockId::new(raw)),
            value => return Err(DecodeError::InvalidInventoryKind(value)),
        };
        if !seen.insert(entry) {
            return Err(DecodeError::DuplicateInventory);
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn encode_get_headers(locator: &[BlockId], stop_id: BlockId) -> Result<Vec<u8>, EncodeError> {
    if locator.is_empty() {
        return Err(EncodeError::EmptyLocator);
    }
    if locator.len() > usize::from(MAX_LOCATOR_ENTRIES) {
        return Err(EncodeError::CountExceeds {
            field: "locator",
            maximum: MAX_LOCATOR_ENTRIES,
        });
    }
    let count = u16::try_from(locator.len()).map_err(|_| EncodeError::IntegerWidth)?;
    let mut output = Encoder::with_capacity(34 + locator.len() * 32);
    output.write_u16(count);
    for id in locator {
        output.write_fixed(id.as_bytes());
    }
    output.write_fixed(stop_id.as_bytes());
    Ok(output.into_bytes())
}

fn decode_get_headers(payload: &[u8]) -> Result<Message, DecodeError> {
    let count = read_u16(payload, 0)?;
    if count == 0 || count > MAX_LOCATOR_ENTRIES {
        return Err(DecodeError::CountOutOfRange {
            field: "locator",
            count,
        });
    }
    let entries_len = usize::from(count)
        .checked_mul(32)
        .ok_or(DecodeError::IntegerWidth)?;
    let expected = 34_usize
        .checked_add(entries_len)
        .ok_or(DecodeError::IntegerWidth)?;
    require_payload_length(payload, expected)?;
    let mut locator = Vec::with_capacity(usize::from(count));
    for index in 0..usize::from(count) {
        locator.push(BlockId::new(read_array(payload, 2 + index * 32)?));
    }
    let stop_id = BlockId::new(read_array(payload, 2 + entries_len)?);
    Ok(Message::GetHeaders { locator, stop_id })
}

fn encode_headers(headers: &[BlockHeader]) -> Result<Vec<u8>, EncodeError> {
    if headers.len() > usize::from(MAX_HEADERS) {
        return Err(EncodeError::CountExceeds {
            field: "headers",
            maximum: MAX_HEADERS,
        });
    }
    let count = u16::try_from(headers.len()).map_err(|_| EncodeError::IntegerWidth)?;
    let mut output = Encoder::with_capacity(2 + headers.len() * usize::from(BLOCK_HEADER_LEN));
    output.write_u16(count);
    for header in headers {
        output.write_fixed(&header.encode());
    }
    Ok(output.into_bytes())
}

fn decode_headers(payload: &[u8]) -> Result<Vec<BlockHeader>, DecodeError> {
    let count = read_u16(payload, 0)?;
    if count > MAX_HEADERS {
        return Err(DecodeError::CountOutOfRange {
            field: "headers",
            count,
        });
    }
    let header_len = usize::from(BLOCK_HEADER_LEN);
    let body_len = usize::from(count)
        .checked_mul(header_len)
        .ok_or(DecodeError::IntegerWidth)?;
    let expected = 2_usize
        .checked_add(body_len)
        .ok_or(DecodeError::IntegerWidth)?;
    require_payload_length(payload, expected)?;
    let mut headers = Vec::with_capacity(usize::from(count));
    for index in 0..usize::from(count) {
        let start = 2 + index * header_len;
        let end = start + header_len;
        headers.push(
            BlockHeader::decode_exact(&payload[start..end])
                .map_err(DecodeError::ConsensusObject)?,
        );
    }
    Ok(headers)
}

fn encode_reject(rejected_type: u16, code: u16, detail: &[u8]) -> Result<Vec<u8>, EncodeError> {
    if detail.len() > usize::from(MAX_REJECT_DETAIL_BYTES) {
        return Err(EncodeError::CountExceeds {
            field: "reject_detail",
            maximum: MAX_REJECT_DETAIL_BYTES,
        });
    }
    let detail_len = u16::try_from(detail.len()).map_err(|_| EncodeError::IntegerWidth)?;
    let mut output = Encoder::with_capacity(6 + detail.len());
    output.write_u16(rejected_type);
    output.write_u16(code);
    output.write_u16(detail_len);
    output.write_fixed(detail);
    Ok(output.into_bytes())
}

fn decode_reject(payload: &[u8]) -> Result<Message, DecodeError> {
    let rejected_type = read_u16(payload, 0)?;
    let code = read_u16(payload, 2)?;
    let detail_len = read_u16(payload, 4)?;
    if detail_len > MAX_REJECT_DETAIL_BYTES {
        return Err(DecodeError::CountOutOfRange {
            field: "reject_detail",
            count: detail_len,
        });
    }
    let expected = 6_usize
        .checked_add(usize::from(detail_len))
        .ok_or(DecodeError::IntegerWidth)?;
    require_payload_length(payload, expected)?;
    Ok(Message::Reject {
        rejected_type,
        code,
        detail: payload[6..expected].to_vec(),
    })
}

fn decode_token(payload: &[u8]) -> Result<u64, DecodeError> {
    require_payload_length(payload, 8)?;
    read_u64(payload, 0)
}

fn decode_block(payload: &[u8]) -> Result<Block, DecodeError> {
    let header_len = usize::from(BLOCK_HEADER_LEN);
    let header_start = 3_usize;
    let header_end = header_start
        .checked_add(header_len)
        .ok_or(DecodeError::IntegerWidth)?;
    if payload.len() < header_end || payload.first().copied() != Some(0) {
        return Err(DecodeError::InvalidBlockEnvelope);
    }
    let declared_header_len = u16::from_be_bytes(
        payload[1..3]
            .try_into()
            .map_err(|_| DecodeError::InvalidBlockEnvelope)?,
    );
    if declared_header_len != BLOCK_HEADER_LEN {
        return Err(DecodeError::InvalidBlockEnvelope);
    }
    let header = BlockHeader::decode_exact(&payload[header_start..header_end])
        .map_err(DecodeError::ConsensusObject)?;
    if header.height == 0 {
        Block::decode_genesis_exact(payload).map_err(DecodeError::ConsensusObject)
    } else {
        Block::decode_non_genesis_exact(payload).map_err(DecodeError::ConsensusObject)
    }
}

fn require_known_or_ignorable(message_type: u16) -> Result<(), DecodeError> {
    if matches!(
        message_type,
        TYPE_HELLO
            | TYPE_HELLO_ACK
            | TYPE_PING
            | TYPE_PONG
            | TYPE_INV
            | TYPE_GET_OBJECTS
            | TYPE_TX
            | TYPE_BLOCK
            | TYPE_GET_HEADERS
            | TYPE_HEADERS
            | TYPE_REJECT
    ) || message_type >= IGNORABLE_TYPE_START
    {
        Ok(())
    } else {
        Err(DecodeError::UnknownMandatoryType(message_type))
    }
}

fn validate_declared_length(message_type: u16, payload_len: u32) -> Result<(), DecodeError> {
    if payload_len > MAX_P2P_PAYLOAD_BYTES {
        return Err(DecodeError::PayloadTooLarge {
            declared: payload_len,
            maximum: MAX_P2P_PAYLOAD_BYTES,
        });
    }
    let valid = match message_type {
        TYPE_HELLO | TYPE_HELLO_ACK => payload_len == HELLO_PAYLOAD_BYTES,
        TYPE_PING | TYPE_PONG => payload_len == 8,
        TYPE_INV | TYPE_GET_OBJECTS => (2..=67_586).contains(&payload_len),
        TYPE_TX => payload_len <= MAX_TX_BYTES,
        TYPE_BLOCK => payload_len <= MAX_BLOCK_BYTES,
        TYPE_GET_HEADERS => (66..=4_130).contains(&payload_len),
        TYPE_HEADERS => (2..=446_002).contains(&payload_len),
        TYPE_REJECT => (6..=262).contains(&payload_len),
        value if value >= IGNORABLE_TYPE_START => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(DecodeError::TypePayloadLength {
            message_type,
            declared: payload_len,
        })
    }
}

fn map_length_encode_error(error: DecodeError) -> EncodeError {
    match error {
        DecodeError::PayloadTooLarge { declared, maximum } => EncodeError::PayloadTooLarge {
            actual: declared,
            maximum,
        },
        DecodeError::TypePayloadLength {
            message_type,
            declared,
        } => EncodeError::TypePayloadLength {
            message_type,
            actual: declared,
        },
        _ => EncodeError::IntegerWidth,
    }
}

fn require_payload_length(payload: &[u8], expected: usize) -> Result<(), DecodeError> {
    if payload.len() < expected {
        Err(DecodeError::PayloadTruncated)
    } else if payload.len() > expected {
        Err(DecodeError::PayloadTrailingBytes)
    } else {
        Ok(())
    }
}

fn read_array<const N: usize>(payload: &[u8], offset: usize) -> Result<[u8; N], DecodeError> {
    let end = offset.checked_add(N).ok_or(DecodeError::IntegerWidth)?;
    payload
        .get(offset..end)
        .ok_or(DecodeError::PayloadTruncated)?
        .try_into()
        .map_err(|_| DecodeError::IntegerWidth)
}

fn read_u16(payload: &[u8], offset: usize) -> Result<u16, DecodeError> {
    Ok(u16::from_be_bytes(read_array(payload, offset)?))
}

fn read_u32(payload: &[u8], offset: usize) -> Result<u32, DecodeError> {
    Ok(u32::from_be_bytes(read_array(payload, offset)?))
}

fn read_u64(payload: &[u8], offset: usize) -> Result<u64, DecodeError> {
    Ok(u64::from_be_bytes(read_array(payload, offset)?))
}

#[cfg(test)]
mod tests {
    use out_codec::RewardTransaction;
    use out_primitives::{Amount, Recipient};

    use super::*;

    fn hello() -> Hello {
        Hello {
            min_protocol_version: 0,
            max_protocol_version: 0,
            min_consensus_version: 0,
            max_consensus_version: 0,
            chain_id: ChainId::new([1; 32]),
            network_id: NetworkId::new(3),
            genesis_commitment: GenesisCommitment::new([2; 32]),
            best_height: 42,
            best_block_id: BlockId::new([3; 32]),
        }
    }

    fn reward_transaction() -> Transaction {
        let mut recipient = [4; 33];
        recipient[0] = 0;
        Transaction::Reward(RewardTransaction {
            body: out_codec::RewardBody {
                tx_version: 0,
                chain_id: ChainId::new([1; 32]),
                network_id: NetworkId::new(3),
                genesis_commitment: GenesisCommitment::new([2; 32]),
                height: 1,
                recipient: Recipient::from_bytes(recipient).expect("recipient"),
                subsidy: Amount::new(500_000_000),
                fees: Amount::ZERO,
                extra: Vec::new(),
            },
        })
    }

    fn round_trip(message: Message) {
        let encoded = encode_frame(P2pNetwork::Devnet, 7, &message).expect("encode");
        let decoded = decode_frame_exact(&encoded, P2pNetwork::Devnet, 0).expect("decode");
        assert_eq!(decoded.message, message);
        assert_eq!(decoded.header.request_id, 7);
        assert_eq!(decoded.header.flags, 0);
    }

    #[test]
    fn fixed_messages_round_trip() {
        round_trip(Message::Hello(hello()));
        round_trip(Message::HelloAck(hello()));
        round_trip(Message::Ping(0x0102_0304_0506_0708));
        round_trip(Message::Pong(9));
        round_trip(Message::Reject {
            rejected_type: TYPE_TX,
            code: 2,
            detail: b"bad transaction".to_vec(),
        });
    }

    #[test]
    fn inventory_and_locator_messages_round_trip() {
        let entries = vec![
            InventoryEntry::Transaction(TransactionId::new([1; 32])),
            InventoryEntry::Block(BlockId::new([2; 32])),
        ];
        round_trip(Message::Inventory(entries.clone()));
        round_trip(Message::GetObjects(entries));
        round_trip(Message::GetHeaders {
            locator: vec![BlockId::new([3; 32]), BlockId::new([4; 32])],
            stop_id: BlockId::new([0; 32]),
        });
    }

    #[test]
    fn consensus_objects_and_headers_round_trip() {
        round_trip(Message::Transaction(reward_transaction()));
        let header = BlockHeader {
            consensus_version: 0,
            chain_id: ChainId::new([1; 32]),
            network_id: NetworkId::new(3),
            genesis_commitment: GenesisCommitment::new([2; 32]),
            height: 0,
            parent_block_id: BlockId::new([0; 32]),
            timestamp: 1,
            target: out_primitives::U256Be::new([0xff; 32]),
            transaction_root: out_primitives::TransactionRoot::new([5; 32]),
            state_root: out_primitives::StateRoot::new([6; 32]),
            nonce: 7,
        };
        round_trip(Message::Headers(vec![header]));
        round_trip(Message::Block(Block {
            header,
            body: out_codec::BlockBody {
                transactions: Vec::new(),
            },
        }));
    }

    #[test]
    fn unknown_ignorable_round_trips_and_unknown_mandatory_fails_header() {
        round_trip(Message::IgnorableExtension {
            message_type: 0x8001,
            payload: vec![1, 2, 3],
        });
        let mut encoded = encode_frame(P2pNetwork::Devnet, 0, &Message::Ping(1)).expect("frame");
        encoded[6..8].copy_from_slice(&0x0100_u16.to_be_bytes());
        assert_eq!(
            decode_frame_header(&encoded[..FRAME_HEADER_BYTES], P2pNetwork::Devnet, 0),
            Err(DecodeError::UnknownMandatoryType(0x0100))
        );
    }

    #[test]
    fn header_preflight_rejects_length_before_payload_buffering() {
        let mut encoded = encode_frame(P2pNetwork::Devnet, 0, &Message::Ping(1)).expect("frame");
        encoded[18..22].copy_from_slice(&(MAX_P2P_PAYLOAD_BYTES + 1).to_be_bytes());
        assert_eq!(
            decode_frame_header(&encoded[..FRAME_HEADER_BYTES], P2pNetwork::Devnet, 0),
            Err(DecodeError::PayloadTooLarge {
                declared: MAX_P2P_PAYLOAD_BYTES + 1,
                maximum: MAX_P2P_PAYLOAD_BYTES,
            })
        );

        encoded[6..8].copy_from_slice(&TYPE_BLOCK.to_be_bytes());
        encoded[18..22].copy_from_slice(&(MAX_BLOCK_BYTES + 1).to_be_bytes());
        assert_eq!(
            decode_frame_header(&encoded[..FRAME_HEADER_BYTES], P2pNetwork::Devnet, 0),
            Err(DecodeError::TypePayloadLength {
                message_type: TYPE_BLOCK,
                declared: MAX_BLOCK_BYTES + 1,
            })
        );
    }

    #[test]
    fn wrong_magic_version_flags_checksum_truncation_and_trailing_fail() {
        let encoded = encode_frame(P2pNetwork::Devnet, 0, &Message::Ping(1)).expect("frame");
        assert_eq!(
            decode_frame_exact(&encoded, P2pNetwork::Testnet, 0),
            Err(DecodeError::WrongNetworkMagic)
        );
        let mut changed = encoded.clone();
        changed[4..6].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_frame_exact(&changed, P2pNetwork::Devnet, 0),
            Err(DecodeError::UnsupportedProtocolVersion(1))
        );
        let mut changed = encoded.clone();
        changed[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_frame_exact(&changed, P2pNetwork::Devnet, 0),
            Err(DecodeError::NonzeroFlags(1))
        );
        let mut changed = encoded.clone();
        changed[FRAME_HEADER_BYTES] ^= 1;
        assert_eq!(
            decode_frame_exact(&changed, P2pNetwork::Devnet, 0),
            Err(DecodeError::ChecksumMismatch)
        );
        assert!(matches!(
            decode_frame_exact(&encoded[..encoded.len() - 1], P2pNetwork::Devnet, 0),
            Err(DecodeError::TruncatedFrame { .. })
        ));
        let mut changed = encoded;
        changed.push(0);
        assert!(matches!(
            decode_frame_exact(&changed, P2pNetwork::Devnet, 0),
            Err(DecodeError::TrailingFrameBytes { .. })
        ));
    }

    #[test]
    fn duplicate_inventory_and_bad_kind_fail() {
        let duplicate = Message::Inventory(vec![
            InventoryEntry::Block(BlockId::new([1; 32])),
            InventoryEntry::Block(BlockId::new([1; 32])),
        ]);
        assert_eq!(
            encode_frame(P2pNetwork::Devnet, 0, &duplicate),
            Err(EncodeError::DuplicateInventory)
        );

        let message = Message::Inventory(vec![InventoryEntry::Block(BlockId::new([1; 32]))]);
        let mut encoded = encode_frame(P2pNetwork::Devnet, 0, &message).expect("frame");
        encoded[FRAME_HEADER_BYTES + 2] = 2;
        let payload_len = u32::from_be_bytes(encoded[18..22].try_into().expect("len"));
        let payload = &encoded[FRAME_HEADER_BYTES..];
        let checksum = payload_checksum(0, TYPE_INV, 0, payload_len, payload);
        encoded[22..54].copy_from_slice(checksum.as_bytes());
        assert_eq!(
            decode_frame_exact(&encoded, P2pNetwork::Devnet, 0),
            Err(DecodeError::InvalidInventoryKind(2))
        );
    }

    #[test]
    fn count_and_type_specific_bounds_fail() {
        let too_many =
            vec![InventoryEntry::Block(BlockId::new([1; 32])); usize::from(MAX_INV_ENTRIES) + 1];
        assert!(matches!(
            encode_frame(P2pNetwork::Devnet, 0, &Message::Inventory(too_many)),
            Err(EncodeError::CountExceeds {
                field: "inventory",
                ..
            })
        ));
        assert_eq!(
            encode_frame(
                P2pNetwork::Devnet,
                0,
                &Message::GetHeaders {
                    locator: Vec::new(),
                    stop_id: BlockId::new([0; 32]),
                }
            ),
            Err(EncodeError::EmptyLocator)
        );
        assert!(matches!(
            encode_frame(
                P2pNetwork::Devnet,
                0,
                &Message::Reject {
                    rejected_type: 0,
                    code: 0,
                    detail: vec![0; usize::from(MAX_REJECT_DETAIL_BYTES) + 1],
                }
            ),
            Err(EncodeError::CountExceeds {
                field: "reject_detail",
                ..
            })
        ));

        assert!(matches!(
            encode_frame(
                P2pNetwork::Devnet,
                0,
                &Message::GetHeaders {
                    locator: vec![BlockId::new([0; 32]); usize::from(MAX_LOCATOR_ENTRIES) + 1],
                    stop_id: BlockId::new([0; 32]),
                }
            ),
            Err(EncodeError::CountExceeds {
                field: "locator",
                ..
            })
        ));
        assert_eq!(
            encode_frame(
                P2pNetwork::Devnet,
                0,
                &Message::IgnorableExtension {
                    message_type: TYPE_PING,
                    payload: Vec::new(),
                }
            ),
            Err(EncodeError::ExtensionTypeMustBeIgnorable(TYPE_PING))
        );
    }

    #[test]
    fn maximum_inventory_and_reject_detail_are_accepted() {
        let entries: Vec<_> = (0..MAX_INV_ENTRIES)
            .map(|index| {
                let mut id = [0_u8; 32];
                id[30..32].copy_from_slice(&index.to_be_bytes());
                InventoryEntry::Block(BlockId::new(id))
            })
            .collect();
        round_trip(Message::Inventory(entries));
        round_trip(Message::Reject {
            rejected_type: TYPE_BLOCK,
            code: 1,
            detail: vec![0x5a; usize::from(MAX_REJECT_DETAIL_BYTES)],
        });
    }

    #[test]
    fn hello_ranges_and_typed_trailing_bytes_are_rejected() {
        let mut invalid = hello();
        invalid.min_protocol_version = 1;
        assert_eq!(
            encode_frame(P2pNetwork::Devnet, 0, &Message::Hello(invalid)),
            Err(EncodeError::InvalidVersionRange("protocol"))
        );

        let message = Message::Inventory(vec![InventoryEntry::Block(BlockId::new([1; 32]))]);
        let mut encoded = encode_frame(P2pNetwork::Devnet, 0, &message).expect("frame");
        encoded[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + 2].copy_from_slice(&0_u16.to_be_bytes());
        let payload_len = u32::from_be_bytes(encoded[18..22].try_into().expect("len"));
        let checksum =
            payload_checksum(0, TYPE_INV, 0, payload_len, &encoded[FRAME_HEADER_BYTES..]);
        encoded[22..54].copy_from_slice(checksum.as_bytes());
        assert_eq!(
            decode_frame_exact(&encoded, P2pNetwork::Devnet, 0),
            Err(DecodeError::PayloadTrailingBytes)
        );
    }

    #[test]
    fn version_negotiation_selects_highest_overlap() {
        assert_eq!(select_protocol_version(0, 3, 2, 4), Some(3));
        assert_eq!(select_protocol_version(0, 1, 2, 3), None);
        assert_eq!(select_protocol_version(2, 1, 0, 3), None);
    }

    #[test]
    fn hello_identity_components_fail_independently() {
        let value = hello();
        assert_eq!(
            value.require_identity(value.chain_id, value.network_id, value.genesis_commitment),
            Ok(())
        );
        assert_eq!(
            value.require_identity(
                ChainId::new([9; 32]),
                value.network_id,
                value.genesis_commitment
            ),
            Err(HelloIdentityError::ChainId)
        );
        assert_eq!(
            value.require_identity(value.chain_id, NetworkId::new(2), value.genesis_commitment),
            Err(HelloIdentityError::NetworkId)
        );
        assert_eq!(
            value.require_identity(
                value.chain_id,
                value.network_id,
                GenesisCommitment::new([9; 32])
            ),
            Err(HelloIdentityError::GenesisCommitment)
        );
    }
}
