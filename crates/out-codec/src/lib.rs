#![forbid(unsafe_code)]

use out_primitives::{
    Amount, BlockId, ChainId, GenesisCommitment, NetworkId, Nonce, Recipient, StateRoot,
    TransactionRoot, U256Be,
};

pub const ENVELOPE_CODEC_V0: u8 = 0;
pub const REGULAR_KIND: u8 = 0;
pub const REWARD_KIND: u8 = 1;
pub const TX_VERSION_V0: u16 = 0;
pub const AUTH_VERSION_V0: u8 = 0;
pub const ED25519_SCHEME: u8 = 0;
pub const REGULAR_AUTH_LEN: u16 = 98;
pub const MAX_MEMO_BYTES: u16 = 256;
pub const MAX_REWARD_EXTRA_BYTES: u16 = 100;
pub const MAX_TX_BYTES: u32 = 16_384;
pub const BLOCK_BODY_CODEC_V0: u8 = 0;
pub const MAX_TXS_PER_BLOCK: u32 = 8_192;
pub const MAX_BLOCK_BODY_BYTES: u32 = 2_097_152;
pub const BLOCK_HEADER_CODEC_V0: u8 = 0;
pub const BLOCK_HEADER_LEN: u16 = 223;
pub const BLOCK_CODEC_V0: u8 = 0;
pub const MAX_BLOCK_BYTES: u32 = 2_097_382;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    LengthExceeds { actual: usize, maximum: usize },
    IntegerWidth,
    InvalidField(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Truncated,
    TrailingBytes,
    LengthExceeds { actual: usize, maximum: usize },
    InvalidTag { field: &'static str, value: u64 },
    InvalidField(&'static str),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }
    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    pub fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    pub fn write_fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_array::<1>()?[0])
    }
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let slice = self.read_slice(N)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(slice);
        Ok(output)
    }
    pub fn read_slice(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DecodeError::Truncated)?;
        let slice = self
            .input
            .get(self.offset..end)
            .ok_or(DecodeError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegularBody {
    pub tx_version: u16,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub genesis_commitment: GenesisCommitment,
    pub sender: Recipient,
    pub nonce: Nonce,
    pub recipient: Recipient,
    pub amount: Amount,
    pub fee: Amount,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub memo: Vec<u8>,
}

impl RegularBody {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        if self.tx_version != TX_VERSION_V0 {
            return Err(EncodeError::InvalidField("tx_version"));
        }
        if self.amount.get() == 0 {
            return Err(EncodeError::InvalidField("amount"));
        }
        if self.valid_from_height > self.expires_at_height {
            return Err(EncodeError::InvalidField("height_interval"));
        }
        let maximum_memo = usize::from(MAX_MEMO_BYTES);
        if self.memo.len() > maximum_memo {
            return Err(EncodeError::LengthExceeds {
                actual: self.memo.len(),
                maximum: maximum_memo,
            });
        }
        let memo_len = u16::try_from(self.memo.len()).map_err(|_| EncodeError::IntegerWidth)?;
        let mut output = Encoder::with_capacity(178 + self.memo.len());
        output.write_u16(self.tx_version);
        output.write_fixed(self.chain_id.as_bytes());
        output.write_u32(self.network_id.get());
        output.write_fixed(self.genesis_commitment.as_bytes());
        output.write_fixed(self.sender.as_bytes());
        output.write_u64(self.nonce.get());
        output.write_fixed(self.recipient.as_bytes());
        output.write_u64(self.amount.get());
        output.write_u64(self.fee.get());
        output.write_u64(self.valid_from_height);
        output.write_u64(self.expires_at_height);
        output.write_u16(memo_len);
        output.write_fixed(&self.memo);
        Ok(output.into_bytes())
    }

    fn decode_exact(input: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let tx_version = decoder.read_u16()?;
        if tx_version != TX_VERSION_V0 {
            return Err(DecodeError::InvalidTag {
                field: "tx_version",
                value: u64::from(tx_version),
            });
        }
        let chain_id = ChainId::new(decoder.read_array()?);
        let network_id = NetworkId::new(decoder.read_u32()?);
        let genesis_commitment = GenesisCommitment::new(decoder.read_array()?);
        let sender = Recipient::from_bytes(decoder.read_array()?)
            .map_err(|_| DecodeError::InvalidField("sender"))?;
        let nonce = Nonce::new(decoder.read_u64()?);
        let recipient = Recipient::from_bytes(decoder.read_array()?)
            .map_err(|_| DecodeError::InvalidField("recipient"))?;
        let amount = Amount::new(decoder.read_u64()?);
        if amount.get() == 0 {
            return Err(DecodeError::InvalidField("amount"));
        }
        let fee = Amount::new(decoder.read_u64()?);
        let valid_from_height = decoder.read_u64()?;
        let expires_at_height = decoder.read_u64()?;
        if valid_from_height > expires_at_height {
            return Err(DecodeError::InvalidField("height_interval"));
        }
        let memo_len = usize::from(decoder.read_u16()?);
        let maximum_memo = usize::from(MAX_MEMO_BYTES);
        if memo_len > maximum_memo {
            return Err(DecodeError::LengthExceeds {
                actual: memo_len,
                maximum: maximum_memo,
            });
        }
        let memo = decoder.read_slice(memo_len)?.to_vec();
        decoder.finish()?;
        Ok(Self {
            tx_version,
            chain_id,
            network_id,
            genesis_commitment,
            sender,
            nonce,
            recipient,
            amount,
            fee,
            valid_from_height,
            expires_at_height,
            memo,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegularAuth {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl RegularAuth {
    fn encode(&self) -> [u8; 98] {
        let mut output = [0_u8; 98];
        output[0] = AUTH_VERSION_V0;
        output[1] = ED25519_SCHEME;
        output[2..34].copy_from_slice(&self.public_key);
        output[34..].copy_from_slice(&self.signature);
        output
    }

    fn decode_exact(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() != usize::from(REGULAR_AUTH_LEN) {
            return Err(DecodeError::InvalidField("auth_len"));
        }
        let mut decoder = Decoder::new(input);
        let auth_version = decoder.read_u8()?;
        if auth_version != AUTH_VERSION_V0 {
            return Err(DecodeError::InvalidTag {
                field: "auth_version",
                value: u64::from(auth_version),
            });
        }
        let scheme = decoder.read_u8()?;
        if scheme != ED25519_SCHEME {
            return Err(DecodeError::InvalidTag {
                field: "signature_scheme",
                value: u64::from(scheme),
            });
        }
        let public_key = decoder.read_array()?;
        let signature = decoder.read_array()?;
        decoder.finish()?;
        Ok(Self {
            public_key,
            signature,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegularTransaction {
    pub body: RegularBody,
    pub auth: RegularAuth,
}

impl RegularTransaction {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let body = self.body.encode()?;
        let auth = self.auth.encode();
        let body_len = u32::try_from(body.len()).map_err(|_| EncodeError::IntegerWidth)?;
        let auth_len = u16::try_from(auth.len()).map_err(|_| EncodeError::IntegerWidth)?;
        let total = 8_usize
            .checked_add(body.len())
            .and_then(|value| value.checked_add(auth.len()))
            .ok_or(EncodeError::IntegerWidth)?;
        let maximum_tx = usize::try_from(MAX_TX_BYTES).map_err(|_| EncodeError::IntegerWidth)?;
        if total > maximum_tx {
            return Err(EncodeError::LengthExceeds {
                actual: total,
                maximum: maximum_tx,
            });
        }
        let mut output = Encoder::with_capacity(total);
        output.write_u8(ENVELOPE_CODEC_V0);
        output.write_u8(REGULAR_KIND);
        output.write_u32(body_len);
        output.write_fixed(&body);
        output.write_u16(auth_len);
        output.write_fixed(&auth);
        Ok(output.into_bytes())
    }

    pub fn signing_material(&self) -> Result<Vec<u8>, EncodeError> {
        let body = self.body.encode()?;
        let body_len = u32::try_from(body.len()).map_err(|_| EncodeError::IntegerWidth)?;
        let mut output = Encoder::with_capacity(7 + body.len());
        output.write_u8(0);
        output.write_u8(ENVELOPE_CODEC_V0);
        output.write_u8(REGULAR_KIND);
        output.write_u32(body_len);
        output.write_fixed(&body);
        Ok(output.into_bytes())
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, DecodeError> {
        let maximum_tx =
            usize::try_from(MAX_TX_BYTES).map_err(|_| DecodeError::InvalidField("max_tx_bytes"))?;
        if input.len() > maximum_tx {
            return Err(DecodeError::LengthExceeds {
                actual: input.len(),
                maximum: maximum_tx,
            });
        }
        let mut decoder = Decoder::new(input);
        let codec = decoder.read_u8()?;
        if codec != ENVELOPE_CODEC_V0 {
            return Err(DecodeError::InvalidTag {
                field: "envelope_codec",
                value: u64::from(codec),
            });
        }
        let kind = decoder.read_u8()?;
        if kind != REGULAR_KIND {
            return Err(DecodeError::InvalidTag {
                field: "tx_kind",
                value: u64::from(kind),
            });
        }
        let body_len = usize::try_from(decoder.read_u32()?)
            .map_err(|_| DecodeError::InvalidField("body_len"))?;
        let maximum_body = maximum_tx
            .checked_sub(8)
            .ok_or(DecodeError::InvalidField("max_tx_bytes"))?;
        if body_len > maximum_body {
            return Err(DecodeError::LengthExceeds {
                actual: body_len,
                maximum: maximum_body,
            });
        }
        if body_len > decoder.remaining().saturating_sub(2) {
            return Err(DecodeError::Truncated);
        }
        let body = RegularBody::decode_exact(decoder.read_slice(body_len)?)?;
        let auth_len = usize::from(decoder.read_u16()?);
        if auth_len != usize::from(REGULAR_AUTH_LEN) {
            return Err(DecodeError::InvalidField("auth_len"));
        }
        let auth = RegularAuth::decode_exact(decoder.read_slice(auth_len)?)?;
        decoder.finish()?;
        Ok(Self { body, auth })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardBody {
    pub tx_version: u16,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub genesis_commitment: GenesisCommitment,
    pub height: u64,
    pub recipient: Recipient,
    pub subsidy: Amount,
    pub fees: Amount,
    pub extra: Vec<u8>,
}

impl RewardBody {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        if self.tx_version != TX_VERSION_V0 {
            return Err(EncodeError::InvalidField("tx_version"));
        }
        let maximum_extra = usize::from(MAX_REWARD_EXTRA_BYTES);
        if self.extra.len() > maximum_extra {
            return Err(EncodeError::LengthExceeds {
                actual: self.extra.len(),
                maximum: maximum_extra,
            });
        }
        let extra_len = u16::try_from(self.extra.len()).map_err(|_| EncodeError::IntegerWidth)?;
        let mut output = Encoder::with_capacity(129 + self.extra.len());
        output.write_u16(self.tx_version);
        output.write_fixed(self.chain_id.as_bytes());
        output.write_u32(self.network_id.get());
        output.write_fixed(self.genesis_commitment.as_bytes());
        output.write_u64(self.height);
        output.write_fixed(self.recipient.as_bytes());
        output.write_u64(self.subsidy.get());
        output.write_u64(self.fees.get());
        output.write_u16(extra_len);
        output.write_fixed(&self.extra);
        Ok(output.into_bytes())
    }

    fn decode_exact(input: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let tx_version = decoder.read_u16()?;
        if tx_version != TX_VERSION_V0 {
            return Err(DecodeError::InvalidTag {
                field: "tx_version",
                value: u64::from(tx_version),
            });
        }
        let chain_id = ChainId::new(decoder.read_array()?);
        let network_id = NetworkId::new(decoder.read_u32()?);
        let genesis_commitment = GenesisCommitment::new(decoder.read_array()?);
        let height = decoder.read_u64()?;
        let recipient = Recipient::from_bytes(decoder.read_array()?)
            .map_err(|_| DecodeError::InvalidField("recipient"))?;
        let subsidy = Amount::new(decoder.read_u64()?);
        let fees = Amount::new(decoder.read_u64()?);
        let extra_len = usize::from(decoder.read_u16()?);
        let maximum_extra = usize::from(MAX_REWARD_EXTRA_BYTES);
        if extra_len > maximum_extra {
            return Err(DecodeError::LengthExceeds {
                actual: extra_len,
                maximum: maximum_extra,
            });
        }
        let extra = decoder.read_slice(extra_len)?.to_vec();
        decoder.finish()?;
        Ok(Self {
            tx_version,
            chain_id,
            network_id,
            genesis_commitment,
            height,
            recipient,
            subsidy,
            fees,
            extra,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardTransaction {
    pub body: RewardBody,
}

impl RewardTransaction {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let body = self.body.encode()?;
        let body_len = u32::try_from(body.len()).map_err(|_| EncodeError::IntegerWidth)?;
        let total = 8_usize
            .checked_add(body.len())
            .ok_or(EncodeError::IntegerWidth)?;
        let maximum_tx = usize::try_from(MAX_TX_BYTES).map_err(|_| EncodeError::IntegerWidth)?;
        if total > maximum_tx {
            return Err(EncodeError::LengthExceeds {
                actual: total,
                maximum: maximum_tx,
            });
        }
        let mut output = Encoder::with_capacity(total);
        output.write_u8(ENVELOPE_CODEC_V0);
        output.write_u8(REWARD_KIND);
        output.write_u32(body_len);
        output.write_fixed(&body);
        output.write_u16(0);
        Ok(output.into_bytes())
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, DecodeError> {
        let maximum_tx =
            usize::try_from(MAX_TX_BYTES).map_err(|_| DecodeError::InvalidField("max_tx_bytes"))?;
        if input.len() > maximum_tx {
            return Err(DecodeError::LengthExceeds {
                actual: input.len(),
                maximum: maximum_tx,
            });
        }
        let mut decoder = Decoder::new(input);
        let codec = decoder.read_u8()?;
        if codec != ENVELOPE_CODEC_V0 {
            return Err(DecodeError::InvalidTag {
                field: "envelope_codec",
                value: u64::from(codec),
            });
        }
        let kind = decoder.read_u8()?;
        if kind != REWARD_KIND {
            return Err(DecodeError::InvalidTag {
                field: "tx_kind",
                value: u64::from(kind),
            });
        }
        let body_len = usize::try_from(decoder.read_u32()?)
            .map_err(|_| DecodeError::InvalidField("body_len"))?;
        let maximum_body = maximum_tx
            .checked_sub(8)
            .ok_or(DecodeError::InvalidField("max_tx_bytes"))?;
        if body_len > maximum_body {
            return Err(DecodeError::LengthExceeds {
                actual: body_len,
                maximum: maximum_body,
            });
        }
        if body_len > decoder.remaining().saturating_sub(2) {
            return Err(DecodeError::Truncated);
        }
        let body = RewardBody::decode_exact(decoder.read_slice(body_len)?)?;
        let auth_len = decoder.read_u16()?;
        if auth_len != 0 {
            return Err(DecodeError::InvalidField("auth_len"));
        }
        decoder.finish()?;
        Ok(Self { body })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transaction {
    Regular(RegularTransaction),
    Reward(RewardTransaction),
}

impl Transaction {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        match self {
            Self::Regular(transaction) => transaction.encode(),
            Self::Reward(transaction) => transaction.encode(),
        }
    }

    pub const fn kind(&self) -> u8 {
        match self {
            Self::Regular(_) => REGULAR_KIND,
            Self::Reward(_) => REWARD_KIND,
        }
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, DecodeError> {
        let maximum_tx =
            usize::try_from(MAX_TX_BYTES).map_err(|_| DecodeError::InvalidField("max_tx_bytes"))?;
        if input.len() > maximum_tx {
            return Err(DecodeError::LengthExceeds {
                actual: input.len(),
                maximum: maximum_tx,
            });
        }
        let codec = *input.first().ok_or(DecodeError::Truncated)?;
        if codec != ENVELOPE_CODEC_V0 {
            return Err(DecodeError::InvalidTag {
                field: "envelope_codec",
                value: u64::from(codec),
            });
        }
        let kind = *input.get(1).ok_or(DecodeError::Truncated)?;
        match kind {
            REGULAR_KIND => RegularTransaction::decode_exact(input).map(Self::Regular),
            REWARD_KIND => RewardTransaction::decode_exact(input).map(Self::Reward),
            value => Err(DecodeError::InvalidTag {
                field: "tx_kind",
                value: u64::from(value),
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockBody {
    pub transactions: Vec<Transaction>,
}

impl BlockBody {
    pub fn encode_non_genesis(&self) -> Result<Vec<u8>, EncodeError> {
        validate_non_genesis_order_encode(&self.transactions)?;
        let count =
            u32::try_from(self.transactions.len()).map_err(|_| EncodeError::IntegerWidth)?;
        if count > MAX_TXS_PER_BLOCK {
            return Err(EncodeError::LengthExceeds {
                actual: self.transactions.len(),
                maximum: usize::try_from(MAX_TXS_PER_BLOCK)
                    .map_err(|_| EncodeError::IntegerWidth)?,
            });
        }

        let mut encoded = Vec::with_capacity(self.transactions.len());
        let mut total = 5_usize;
        for transaction in &self.transactions {
            let bytes = transaction.encode()?;
            total = total
                .checked_add(4)
                .and_then(|value| value.checked_add(bytes.len()))
                .ok_or(EncodeError::IntegerWidth)?;
            encoded.push(bytes);
        }
        let maximum_body =
            usize::try_from(MAX_BLOCK_BODY_BYTES).map_err(|_| EncodeError::IntegerWidth)?;
        if total > maximum_body {
            return Err(EncodeError::LengthExceeds {
                actual: total,
                maximum: maximum_body,
            });
        }

        let mut output = Encoder::with_capacity(total);
        output.write_u8(BLOCK_BODY_CODEC_V0);
        output.write_u32(count);
        for bytes in encoded {
            output.write_u32(u32::try_from(bytes.len()).map_err(|_| EncodeError::IntegerWidth)?);
            output.write_fixed(&bytes);
        }
        Ok(output.into_bytes())
    }

    pub fn encode_genesis(&self) -> Result<Vec<u8>, EncodeError> {
        if !self.transactions.is_empty() {
            return Err(EncodeError::InvalidField("genesis_tx_count"));
        }
        Ok(vec![BLOCK_BODY_CODEC_V0, 0, 0, 0, 0])
    }

    pub fn decode_non_genesis_exact(input: &[u8]) -> Result<Self, DecodeError> {
        let body = Self::decode_entries(input, false)?;
        validate_non_genesis_order_decode(&body.transactions)?;
        Ok(body)
    }

    pub fn decode_genesis_exact(input: &[u8]) -> Result<Self, DecodeError> {
        Self::decode_entries(input, true)
    }

    fn decode_entries(input: &[u8], genesis: bool) -> Result<Self, DecodeError> {
        let maximum_body = usize::try_from(MAX_BLOCK_BODY_BYTES)
            .map_err(|_| DecodeError::InvalidField("max_block_body_bytes"))?;
        if input.len() > maximum_body {
            return Err(DecodeError::LengthExceeds {
                actual: input.len(),
                maximum: maximum_body,
            });
        }
        let mut decoder = Decoder::new(input);
        let codec = decoder.read_u8()?;
        if codec != BLOCK_BODY_CODEC_V0 {
            return Err(DecodeError::InvalidTag {
                field: "body_codec",
                value: u64::from(codec),
            });
        }
        let count = decoder.read_u32()?;
        if count > MAX_TXS_PER_BLOCK {
            return Err(DecodeError::LengthExceeds {
                actual: usize::try_from(count)
                    .map_err(|_| DecodeError::InvalidField("tx_count"))?,
                maximum: usize::try_from(MAX_TXS_PER_BLOCK)
                    .map_err(|_| DecodeError::InvalidField("max_txs_per_block"))?,
            });
        }
        if genesis {
            if count != 0 {
                return Err(DecodeError::InvalidField("genesis_tx_count"));
            }
        } else if count == 0 {
            return Err(DecodeError::InvalidField("tx_count"));
        }

        let capacity = usize::try_from(count).map_err(|_| DecodeError::InvalidField("tx_count"))?;
        let mut transactions = Vec::with_capacity(capacity);
        for _ in 0..count {
            let tx_len = usize::try_from(decoder.read_u32()?)
                .map_err(|_| DecodeError::InvalidField("tx_len"))?;
            if tx_len == 0 {
                return Err(DecodeError::InvalidField("tx_len"));
            }
            let maximum_tx = usize::try_from(MAX_TX_BYTES)
                .map_err(|_| DecodeError::InvalidField("max_tx_bytes"))?;
            if tx_len > maximum_tx {
                return Err(DecodeError::LengthExceeds {
                    actual: tx_len,
                    maximum: maximum_tx,
                });
            }
            let bytes = decoder.read_slice(tx_len)?;
            transactions.push(Transaction::decode_exact(bytes)?);
        }
        decoder.finish()?;
        Ok(Self { transactions })
    }
}

fn validate_non_genesis_order_encode(transactions: &[Transaction]) -> Result<(), EncodeError> {
    if transactions.is_empty() {
        return Err(EncodeError::InvalidField("tx_count"));
    }
    if !matches!(transactions.first(), Some(Transaction::Reward(_))) {
        return Err(EncodeError::InvalidField("reward_position"));
    }
    if transactions[1..]
        .iter()
        .any(|transaction| !matches!(transaction, Transaction::Regular(_)))
    {
        return Err(EncodeError::InvalidField("transaction_kind_order"));
    }
    Ok(())
}

fn validate_non_genesis_order_decode(transactions: &[Transaction]) -> Result<(), DecodeError> {
    if !matches!(transactions.first(), Some(Transaction::Reward(_))) {
        return Err(DecodeError::InvalidField("reward_position"));
    }
    if transactions[1..]
        .iter()
        .any(|transaction| !matches!(transaction, Transaction::Regular(_)))
    {
        return Err(DecodeError::InvalidField("transaction_kind_order"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    pub consensus_version: u16,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub genesis_commitment: GenesisCommitment,
    pub height: u64,
    pub parent_block_id: BlockId,
    pub timestamp: u64,
    pub target: U256Be,
    pub transaction_root: TransactionRoot,
    pub state_root: StateRoot,
    pub nonce: u64,
}

impl BlockHeader {
    pub fn encode(self) -> [u8; 223] {
        let mut output = Encoder::with_capacity(usize::from(BLOCK_HEADER_LEN));
        output.write_u8(BLOCK_HEADER_CODEC_V0);
        output.write_u16(self.consensus_version);
        output.write_fixed(self.chain_id.as_bytes());
        output.write_u32(self.network_id.get());
        output.write_fixed(self.genesis_commitment.as_bytes());
        output.write_u64(self.height);
        output.write_fixed(self.parent_block_id.as_bytes());
        output.write_u64(self.timestamp);
        output.write_fixed(self.target.as_bytes());
        output.write_fixed(self.transaction_root.as_bytes());
        output.write_fixed(self.state_root.as_bytes());
        output.write_u64(self.nonce);
        output
            .into_bytes()
            .try_into()
            .expect("fixed block header layout")
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(input);
        let codec = decoder.read_u8()?;
        if codec != BLOCK_HEADER_CODEC_V0 {
            return Err(DecodeError::InvalidTag {
                field: "header_codec",
                value: u64::from(codec),
            });
        }
        let consensus_version = decoder.read_u16()?;
        let chain_id = ChainId::new(decoder.read_array()?);
        let network_id = NetworkId::new(decoder.read_u32()?);
        let genesis_commitment = GenesisCommitment::new(decoder.read_array()?);
        let height = decoder.read_u64()?;
        let parent_block_id = BlockId::new(decoder.read_array()?);
        let timestamp = decoder.read_u64()?;
        let target = U256Be::new(decoder.read_array()?);
        let transaction_root = TransactionRoot::new(decoder.read_array()?);
        let state_root = StateRoot::new(decoder.read_array()?);
        let nonce = decoder.read_u64()?;
        decoder.finish()?;
        Ok(Self {
            consensus_version,
            chain_id,
            network_id,
            genesis_commitment,
            height,
            parent_block_id,
            timestamp,
            target,
            transaction_root,
            state_root,
            nonce,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
}

impl Block {
    pub fn encode_non_genesis(&self) -> Result<Vec<u8>, EncodeError> {
        self.encode_with_body(self.body.encode_non_genesis()?)
    }

    pub fn encode_genesis(&self) -> Result<Vec<u8>, EncodeError> {
        self.encode_with_body(self.body.encode_genesis()?)
    }

    pub fn decode_non_genesis_exact(input: &[u8]) -> Result<Self, DecodeError> {
        let (header, body_bytes) = Self::decode_envelope(input)?;
        let body = BlockBody::decode_non_genesis_exact(body_bytes)?;
        Ok(Self { header, body })
    }

    pub fn decode_genesis_exact(input: &[u8]) -> Result<Self, DecodeError> {
        let (header, body_bytes) = Self::decode_envelope(input)?;
        let body = BlockBody::decode_genesis_exact(body_bytes)?;
        Ok(Self { header, body })
    }

    fn encode_with_body(&self, body: Vec<u8>) -> Result<Vec<u8>, EncodeError> {
        let body_len = u32::try_from(body.len()).map_err(|_| EncodeError::IntegerWidth)?;
        if body_len > MAX_BLOCK_BODY_BYTES {
            return Err(EncodeError::LengthExceeds {
                actual: body.len(),
                maximum: usize::try_from(MAX_BLOCK_BODY_BYTES)
                    .map_err(|_| EncodeError::IntegerWidth)?,
            });
        }
        let total = 230_usize
            .checked_add(body.len())
            .ok_or(EncodeError::IntegerWidth)?;
        if total > usize::try_from(MAX_BLOCK_BYTES).map_err(|_| EncodeError::IntegerWidth)? {
            return Err(EncodeError::LengthExceeds {
                actual: total,
                maximum: usize::try_from(MAX_BLOCK_BYTES).map_err(|_| EncodeError::IntegerWidth)?,
            });
        }
        let mut output = Encoder::with_capacity(total);
        output.write_u8(BLOCK_CODEC_V0);
        output.write_u16(BLOCK_HEADER_LEN);
        output.write_fixed(&self.header.encode());
        output.write_u32(body_len);
        output.write_fixed(&body);
        Ok(output.into_bytes())
    }

    fn decode_envelope(input: &[u8]) -> Result<(BlockHeader, &[u8]), DecodeError> {
        let maximum_block = usize::try_from(MAX_BLOCK_BYTES)
            .map_err(|_| DecodeError::InvalidField("max_block_bytes"))?;
        if input.len() > maximum_block {
            return Err(DecodeError::LengthExceeds {
                actual: input.len(),
                maximum: maximum_block,
            });
        }
        let mut decoder = Decoder::new(input);
        let codec = decoder.read_u8()?;
        if codec != BLOCK_CODEC_V0 {
            return Err(DecodeError::InvalidTag {
                field: "block_codec",
                value: u64::from(codec),
            });
        }
        let header_len = decoder.read_u16()?;
        if header_len != BLOCK_HEADER_LEN {
            return Err(DecodeError::InvalidField("header_len"));
        }
        let header = BlockHeader::decode_exact(decoder.read_slice(usize::from(header_len))?)?;
        let body_len = usize::try_from(decoder.read_u32()?)
            .map_err(|_| DecodeError::InvalidField("body_len"))?;
        let maximum_body = usize::try_from(MAX_BLOCK_BODY_BYTES)
            .map_err(|_| DecodeError::InvalidField("max_block_body_bytes"))?;
        if body_len > maximum_body {
            return Err(DecodeError::LengthExceeds {
                actual: body_len,
                maximum: maximum_body,
            });
        }
        let body = decoder.read_slice(body_len)?;
        decoder.finish()?;
        Ok((header, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        input
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = char::from(pair[0]).to_digit(16).expect("valid fixture hex");
                let low = char::from(pair[1]).to_digit(16).expect("valid fixture hex");
                u8::try_from((high << 4) | low).expect("fixture byte")
            })
            .collect()
    }

    fn vector_transaction() -> RegularTransaction {
        let sender = Recipient::from_bytes(
            hex("0003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
                .try_into()
                .expect("recipient"),
        )
        .expect("v0");
        let recipient = Recipient::from_bytes(
            hex("0029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7")
                .try_into()
                .expect("recipient"),
        )
        .expect("v0");
        let chain_id = ChainId::new(
            hex("fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c4")
                .try_into()
                .expect("chain id"),
        );
        let genesis_commitment = GenesisCommitment::new(
            hex("baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a7")
                .try_into()
                .expect("commitment"),
        );
        let public_key = hex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
            .try_into()
            .expect("public key");
        let signature = hex("4db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b").try_into().expect("signature");
        RegularTransaction {
            body: RegularBody {
                tx_version: 0,
                chain_id,
                network_id: NetworkId::new(3),
                genesis_commitment,
                sender,
                nonce: Nonce::ZERO,
                recipient,
                amount: Amount::new(123_456_789),
                fee: Amount::new(1_000),
                valid_from_height: 1,
                expires_at_height: 1_000,
                memo: b"OUT vector".to_vec(),
            },
            auth: RegularAuth {
                public_key,
                signature,
            },
        }
    }

    fn vector_reward() -> RewardTransaction {
        RewardTransaction::decode_exact(&hex("0001000000810000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000010003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8000000001dcd650000000000000003e800000000"))
            .expect("verified reward")
    }

    fn vector_header_bytes() -> Vec<u8> {
        hex("000000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a937280000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda2fb959f81d652879472f8c56076e63a2fb3587dda94754f316328e7ec431403d30a2588a2f688edd9b29af2bb3b522db2deb731709dbfb53fadefab69c21470000000000000ac5")
    }

    #[test]
    fn regular_body_matches_verified_vector() {
        let expected = hex("0000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a70003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b800000000000000000029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000075bcd1500000000000003e8000000000000000100000000000003e8000a4f555420766563746f72");
        assert_eq!(
            vector_transaction().body.encode().expect("encode"),
            expected
        );
    }

    #[test]
    fn exact_decode_round_trips_and_rejects_trailing_byte() {
        let encoded = vector_transaction().encode().expect("encode");
        let decoded = RegularTransaction::decode_exact(&encoded).expect("decode");
        assert_eq!(decoded.encode().expect("re-encode"), encoded);
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            RegularTransaction::decode_exact(&trailing),
            Err(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn reward_encoding_matches_verified_vector() {
        let expected = hex("0001000000810000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000010003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8000000001dcd650000000000000003e800000000");
        assert_eq!(vector_reward().encode().expect("encode"), expected);
        assert_eq!(
            Transaction::decode_exact(&expected),
            Ok(Transaction::Reward(vector_reward()))
        );
    }

    #[test]
    fn block_body_round_trips_with_reward_first() {
        let body = BlockBody {
            transactions: vec![
                Transaction::Reward(vector_reward()),
                Transaction::Regular(vector_transaction()),
            ],
        };
        let encoded = body.encode_non_genesis().expect("encode body");
        assert_eq!(encoded.len(), 444);
        assert_eq!(BlockBody::decode_non_genesis_exact(&encoded), Ok(body));
    }

    #[test]
    fn block_body_rejects_wrong_kind_order() {
        let body = BlockBody {
            transactions: vec![Transaction::Regular(vector_transaction())],
        };
        assert_eq!(
            body.encode_non_genesis(),
            Err(EncodeError::InvalidField("reward_position"))
        );

        let two_rewards = BlockBody {
            transactions: vec![
                Transaction::Reward(vector_reward()),
                Transaction::Reward(vector_reward()),
            ],
        };
        assert_eq!(
            two_rewards.encode_non_genesis(),
            Err(EncodeError::InvalidField("transaction_kind_order"))
        );
    }

    #[test]
    fn genesis_body_is_exact_and_separate() {
        let body = BlockBody {
            transactions: Vec::new(),
        };
        let encoded = body.encode_genesis().expect("genesis body");
        assert_eq!(encoded, vec![0, 0, 0, 0, 0]);
        assert_eq!(BlockBody::decode_genesis_exact(&encoded), Ok(body));
        assert_eq!(
            BlockBody::decode_non_genesis_exact(&encoded),
            Err(DecodeError::InvalidField("tx_count"))
        );
    }

    #[test]
    fn unknown_transaction_kind_is_rejected() {
        assert_eq!(
            Transaction::decode_exact(&[ENVELOPE_CODEC_V0, 2]),
            Err(DecodeError::InvalidTag {
                field: "tx_kind",
                value: 2
            })
        );
    }

    #[test]
    fn block_body_bounds_are_checked_before_entry_allocation() {
        let mut excessive_count = vec![BLOCK_BODY_CODEC_V0];
        excessive_count.extend_from_slice(&(MAX_TXS_PER_BLOCK + 1).to_be_bytes());
        assert_eq!(
            BlockBody::decode_non_genesis_exact(&excessive_count),
            Err(DecodeError::LengthExceeds {
                actual: 8_193,
                maximum: 8_192
            })
        );

        let mut excessive_transaction = vec![BLOCK_BODY_CODEC_V0];
        excessive_transaction.extend_from_slice(&1_u32.to_be_bytes());
        excessive_transaction.extend_from_slice(&(MAX_TX_BYTES + 1).to_be_bytes());
        assert_eq!(
            BlockBody::decode_non_genesis_exact(&excessive_transaction),
            Err(DecodeError::LengthExceeds {
                actual: 16_385,
                maximum: 16_384
            })
        );
    }

    #[test]
    fn reward_extra_bound_is_enforced() {
        let mut reward = vector_reward();
        reward.body.extra = vec![0; usize::from(MAX_REWARD_EXTRA_BYTES) + 1];
        assert_eq!(
            reward.encode(),
            Err(EncodeError::LengthExceeds {
                actual: 101,
                maximum: 100
            })
        );
    }

    #[test]
    fn block_header_matches_verified_223_byte_vector() {
        let expected = vector_header_bytes();
        assert_eq!(expected.len(), usize::from(BLOCK_HEADER_LEN));
        let header = BlockHeader::decode_exact(&expected).expect("header");
        assert_eq!(header.height, 0);
        assert_eq!(header.timestamp, 1_788_048_000);
        assert_eq!(header.nonce, 2_757);
        assert_eq!(header.encode().as_slice(), expected);
    }

    #[test]
    fn genesis_block_envelope_round_trips_exactly() {
        let block = Block {
            header: BlockHeader::decode_exact(&vector_header_bytes()).expect("header"),
            body: BlockBody {
                transactions: Vec::new(),
            },
        };
        let encoded = block.encode_genesis().expect("genesis block");
        assert_eq!(encoded.len(), 235);
        assert_eq!(Block::decode_genesis_exact(&encoded), Ok(block));

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            Block::decode_genesis_exact(&trailing),
            Err(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn block_envelope_rejects_wrong_header_and_body_lengths_early() {
        assert_eq!(
            Block::decode_genesis_exact(&[BLOCK_CODEC_V0, 0, 222]),
            Err(DecodeError::InvalidField("header_len"))
        );

        let mut oversized_body_claim = Vec::new();
        oversized_body_claim.push(BLOCK_CODEC_V0);
        oversized_body_claim.extend_from_slice(&BLOCK_HEADER_LEN.to_be_bytes());
        oversized_body_claim.extend_from_slice(&vector_header_bytes());
        oversized_body_claim.extend_from_slice(&(MAX_BLOCK_BODY_BYTES + 1).to_be_bytes());
        assert_eq!(
            Block::decode_genesis_exact(&oversized_body_claim),
            Err(DecodeError::LengthExceeds {
                actual: 2_097_153,
                maximum: 2_097_152
            })
        );
    }
}
