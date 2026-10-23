//! Strict repository-local command-line parsing and operator client helpers.

use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use out_codec::{MAX_REWARD_EXTRA_BYTES, MAX_TX_BYTES};
use out_primitives::Recipient;

use crate::mining::CandidateRequest;
use crate::operator::{
    decode_operator_response, encode_operator_request, read_framed_operator_message,
    write_framed_operator_message, AuthenticatedOperatorResponse, OperatorCommand,
    OperatorFrameError, OperatorKey, OperatorKeyError, UnixOperatorError, UnixOperatorPolicy,
};
use crate::process::{LocalNodeProcessConfig, PersistentBackend, PersistentOpenMode};
use crate::{dispatcher::MiningControlCommand, SupportedNetwork};

pub const NODE_USAGE: &str = "out-node-local <create|open> <redb|rocksdb> <testnet|devnet> <database-path> <operator-socket-path> [maximum-reorganization-blocks]";
pub const OPERATOR_USAGE: &str = "out-operator <operator-socket-path> <sequence> <inspect|account|submit-tx|cancel|shutdown|step|start|refresh> [command fields]";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliParseError {
    Usage(&'static str),
    UnknownOpenMode(String),
    UnknownBackend(String),
    UnknownNetwork(String),
    UnknownCommand(String),
    InvalidInteger(&'static str),
    ZeroSequence,
    EmptyPath(&'static str),
    InvalidRecipientHex,
    InvalidRewardExtraHex,
    InvalidTransactionHex,
    RewardExtraTooLarge { actual: usize, maximum: u16 },
    TransactionTooLarge { actual: usize, maximum: u32 },
}

#[derive(Debug)]
pub enum OperatorKeyInputError {
    Io(io::Error),
    WrongLength,
    NoncanonicalHex,
    Key(OperatorKeyError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorClientConfig {
    pub socket_path: PathBuf,
    pub sequence: u64,
    pub command: OperatorCommand,
    pub timeout_millis: u64,
}

#[derive(Debug)]
pub enum OperatorClientError {
    Io(io::Error),
    Frame(OperatorFrameError),
    Transport(UnixOperatorError),
    ResponseSequenceMismatch { expected: u64, actual: u64 },
    ResponseCommandMismatch { expected: u8, actual: u8 },
}

pub fn parse_node_arguments<I, T>(arguments: I) -> Result<LocalNodeProcessConfig, CliParseError>
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    let values: Vec<String> = arguments.into_iter().map(Into::into).collect();
    if !(values.len() == 5 || values.len() == 6) {
        return Err(CliParseError::Usage(NODE_USAGE));
    }
    let open_mode = match values[0].as_str() {
        "create" => PersistentOpenMode::Create,
        "open" => PersistentOpenMode::Open,
        other => return Err(CliParseError::UnknownOpenMode(other.to_owned())),
    };
    let backend = match values[1].as_str() {
        "redb" => PersistentBackend::Redb,
        "rocksdb" => PersistentBackend::Rocksdb,
        other => return Err(CliParseError::UnknownBackend(other.to_owned())),
    };
    let network = match values[2].as_str() {
        "testnet" => SupportedNetwork::Testnet,
        "devnet" => SupportedNetwork::Devnet,
        other => return Err(CliParseError::UnknownNetwork(other.to_owned())),
    };
    if values[3].is_empty() {
        return Err(CliParseError::EmptyPath("database-path"));
    }
    if values[4].is_empty() {
        return Err(CliParseError::EmptyPath("operator-socket-path"));
    }
    let maximum_reorganization_blocks = if let Some(value) = values.get(5) {
        parse_u64("maximum-reorganization-blocks", value)?
    } else {
        100
    };
    Ok(LocalNodeProcessConfig {
        network,
        backend,
        open_mode,
        database_path: PathBuf::from(&values[3]),
        operator_socket_path: PathBuf::from(&values[4]),
        maximum_reorganization_blocks,
        operator_policy: UnixOperatorPolicy {
            read_timeout_millis: 5_000,
            write_timeout_millis: 5_000,
        },
    })
}

pub fn parse_operator_arguments<I, T>(arguments: I) -> Result<OperatorClientConfig, CliParseError>
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    let values: Vec<String> = arguments.into_iter().map(Into::into).collect();
    if values.len() < 3 {
        return Err(CliParseError::Usage(OPERATOR_USAGE));
    }
    if values[0].is_empty() {
        return Err(CliParseError::EmptyPath("operator-socket-path"));
    }
    let sequence = parse_u64("sequence", &values[1])?;
    if sequence == 0 {
        return Err(CliParseError::ZeroSequence);
    }
    let command = match values[2].as_str() {
        "inspect" if values.len() == 3 => OperatorCommand::Mining(MiningControlCommand::Inspect),
        "cancel" if values.len() == 3 => OperatorCommand::Mining(MiningControlCommand::Cancel),
        "shutdown" if values.len() == 3 => OperatorCommand::Shutdown,
        "account" if values.len() == 4 => {
            let recipient = Recipient::from_bytes(
                decode_lower_hex_array::<33>(values[3].as_bytes())
                    .ok_or(CliParseError::InvalidRecipientHex)?,
            )
            .map_err(|_| CliParseError::InvalidRecipientHex)?;
            OperatorCommand::Account(recipient)
        }
        "submit-tx" if values.len() == 4 => {
            let maximum_hex = usize::try_from(MAX_TX_BYTES)
                .ok()
                .and_then(|value| value.checked_mul(2))
                .ok_or(CliParseError::InvalidTransactionHex)?;
            if values[3].len() > maximum_hex {
                return Err(CliParseError::TransactionTooLarge {
                    actual: values[3].len() / 2,
                    maximum: MAX_TX_BYTES,
                });
            }
            OperatorCommand::SubmitTransaction(
                decode_lower_hex(values[3].as_bytes())
                    .ok_or(CliParseError::InvalidTransactionHex)?,
            )
        }
        "step" if values.len() == 4 => OperatorCommand::Mining(MiningControlCommand::Step {
            local_now: parse_u64("local-now", &values[3])?,
        }),
        "start" if values.len() == 8 => OperatorCommand::Mining(MiningControlCommand::Start {
            request: parse_candidate(&values[3..7])?,
            first_nonce: parse_u64("first-nonce", &values[7])?,
        }),
        "refresh" if values.len() == 8 => OperatorCommand::Mining(MiningControlCommand::Refresh {
            request: parse_candidate(&values[3..7])?,
            first_nonce: parse_u64("first-nonce", &values[7])?,
        }),
        "inspect" | "account" | "submit-tx" | "cancel" | "shutdown" | "step" | "start"
        | "refresh" => {
            return Err(CliParseError::Usage(OPERATOR_USAGE));
        }
        other => return Err(CliParseError::UnknownCommand(other.to_owned())),
    };
    Ok(OperatorClientConfig {
        socket_path: PathBuf::from(&values[0]),
        sequence,
        command,
        timeout_millis: 5_000,
    })
}

pub fn read_operator_key(reader: impl Read) -> Result<OperatorKey, OperatorKeyInputError> {
    let mut bytes = Vec::with_capacity(66);
    reader
        .take(66)
        .read_to_end(&mut bytes)
        .map_err(OperatorKeyInputError::Io)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.len() != 64 {
        bytes.fill(0);
        return Err(OperatorKeyInputError::WrongLength);
    }
    let decoded = decode_lower_hex_array::<32>(&bytes).ok_or_else(|| {
        bytes.fill(0);
        OperatorKeyInputError::NoncanonicalHex
    })?;
    bytes.fill(0);
    OperatorKey::from_bytes(decoded).map_err(OperatorKeyInputError::Key)
}

pub fn run_operator_client(
    config: &OperatorClientConfig,
    key: &OperatorKey,
) -> Result<AuthenticatedOperatorResponse, OperatorClientError> {
    let request = encode_operator_request(config.sequence, &config.command, key)
        .map_err(OperatorClientError::Frame)?;
    let mut stream = UnixStream::connect(&config.socket_path).map_err(OperatorClientError::Io)?;
    stream
        .set_read_timeout(Some(Duration::from_millis(config.timeout_millis)))
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_millis(config.timeout_millis))))
        .map_err(OperatorClientError::Io)?;
    write_framed_operator_message(&mut stream, &request).map_err(OperatorClientError::Transport)?;
    let response =
        read_framed_operator_message(&mut stream).map_err(OperatorClientError::Transport)?;
    let response = decode_operator_response(&response, key).map_err(OperatorClientError::Frame)?;
    if response.sequence != config.sequence {
        return Err(OperatorClientError::ResponseSequenceMismatch {
            expected: config.sequence,
            actual: response.sequence,
        });
    }
    let expected_command = operator_command_tag(&config.command);
    if response.command_tag != expected_command {
        return Err(OperatorClientError::ResponseCommandMismatch {
            expected: expected_command,
            actual: response.command_tag,
        });
    }
    Ok(response)
}

fn parse_candidate(values: &[String]) -> Result<CandidateRequest, CliParseError> {
    let timestamp = parse_u64("timestamp", &values[0])?;
    let local_now = parse_u64("local-now", &values[1])?;
    let recipient_bytes = decode_lower_hex_array::<33>(values[2].as_bytes())
        .ok_or(CliParseError::InvalidRecipientHex)?;
    let reward_recipient =
        Recipient::from_bytes(recipient_bytes).map_err(|_| CliParseError::InvalidRecipientHex)?;
    let reward_extra = if values[3] == "-" {
        Vec::new()
    } else {
        decode_lower_hex(values[3].as_bytes()).ok_or(CliParseError::InvalidRewardExtraHex)?
    };
    if reward_extra.len() > usize::from(MAX_REWARD_EXTRA_BYTES) {
        return Err(CliParseError::RewardExtraTooLarge {
            actual: reward_extra.len(),
            maximum: MAX_REWARD_EXTRA_BYTES,
        });
    }
    Ok(CandidateRequest {
        timestamp,
        local_now,
        reward_recipient,
        reward_extra,
    })
}

fn parse_u64(field: &'static str, value: &str) -> Result<u64, CliParseError> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(CliParseError::InvalidInteger(field));
    }
    value
        .parse()
        .map_err(|_| CliParseError::InvalidInteger(field))
}

fn decode_lower_hex(input: &[u8]) -> Option<Vec<u8>> {
    let (pairs, remainder) = input.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let mut output = Vec::with_capacity(input.len() / 2);
    for pair in pairs {
        let high = nibble(pair[0])?;
        let low = nibble(pair[1])?;
        output.push((high << 4) | low);
    }
    Some(output)
}

fn decode_lower_hex_array<const N: usize>(input: &[u8]) -> Option<[u8; N]> {
    let expected = N.checked_mul(2)?;
    if input.len() != expected {
        return None;
    }
    let decoded = decode_lower_hex(input)?;
    decoded.try_into().ok()
}

const fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn operator_command_tag(command: &OperatorCommand) -> u8 {
    match command {
        OperatorCommand::Mining(MiningControlCommand::Inspect) => 1,
        OperatorCommand::Mining(MiningControlCommand::Start { .. }) => 2,
        OperatorCommand::Mining(MiningControlCommand::Refresh { .. }) => 3,
        OperatorCommand::Mining(MiningControlCommand::Step { .. }) => 4,
        OperatorCommand::Mining(MiningControlCommand::Cancel) => 5,
        OperatorCommand::Shutdown => 6,
        OperatorCommand::Account(_) => 7,
        OperatorCommand::SubmitTransaction(_) => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_arguments_are_explicit_and_mainnet_is_absent() {
        let parsed = parse_node_arguments([
            "create",
            "redb",
            "devnet",
            "/tmp/out.redb",
            "/tmp/out.sock",
            "50",
        ])
        .unwrap();
        assert_eq!(parsed.network, SupportedNetwork::Devnet);
        assert_eq!(parsed.maximum_reorganization_blocks, 50);
        assert!(matches!(
            parse_node_arguments([
                "create",
                "redb",
                "mainnet",
                "/tmp/out.redb",
                "/tmp/out.sock",
            ]),
            Err(CliParseError::UnknownNetwork(network)) if network == "mainnet"
        ));
    }

    #[test]
    fn operator_arguments_are_canonical_and_bounded() {
        assert_eq!(
            parse_operator_arguments(["/tmp/out.sock", "1", "shutdown"])
                .unwrap()
                .command,
            OperatorCommand::Shutdown
        );
        assert!(matches!(
            parse_operator_arguments(["/tmp/out.sock", "01", "inspect"]),
            Err(CliParseError::InvalidInteger("sequence"))
        ));
        assert!(matches!(
            parse_operator_arguments(["/tmp/out.sock", "0", "inspect"]),
            Err(CliParseError::ZeroSequence)
        ));

        let recipient_hex = format!("00{}", "11".repeat(32));
        assert_eq!(
            parse_operator_arguments([
                "/tmp/out.sock".to_owned(),
                "2".to_owned(),
                "account".to_owned(),
                recipient_hex,
            ])
            .unwrap()
            .command,
            OperatorCommand::Account(
                Recipient::from_bytes({
                    let mut bytes = [0x11; 33];
                    bytes[0] = 0;
                    bytes
                })
                .unwrap()
            )
        );
        assert_eq!(
            parse_operator_arguments(["/tmp/out.sock", "3", "submit-tx", "000102"])
                .unwrap()
                .command,
            OperatorCommand::SubmitTransaction(vec![0, 1, 2])
        );
        assert!(matches!(
            parse_operator_arguments(["/tmp/out.sock", "4", "submit-tx", "00AA"]),
            Err(CliParseError::InvalidTransactionHex)
        ));
        let oversized = "aa".repeat(usize::try_from(MAX_TX_BYTES).unwrap() + 1);
        assert!(matches!(
            parse_operator_arguments([
                "/tmp/out.sock".to_owned(),
                "5".to_owned(),
                "submit-tx".to_owned(),
                oversized,
            ]),
            Err(CliParseError::TransactionTooLarge {
                actual,
                maximum: MAX_TX_BYTES,
            }) if actual == usize::try_from(MAX_TX_BYTES).unwrap() + 1
        ));
    }

    #[test]
    fn key_input_is_bounded_lowercase_and_redacted() {
        let text = format!("{}\n", "5a".repeat(32));
        assert_eq!(
            format!("{:?}", read_operator_key(text.as_bytes()).unwrap()),
            "OperatorKey([REDACTED])"
        );
        assert!(matches!(
            read_operator_key("5A".repeat(32).as_bytes()),
            Err(OperatorKeyInputError::NoncanonicalHex)
        ));
        assert!(matches!(
            read_operator_key("5a".repeat(33).as_bytes()),
            Err(OperatorKeyInputError::WrongLength)
        ));
    }
}
