//! Authenticated, bounded local mining control over a Unix-domain socket.
//!
//! This is an operational boundary, never a consensus encoding. The server
//! accepts exactly one connection and one command per explicit `serve_once`
//! call. It creates no threads, tasks, timers, TCP/UDP sockets, or services.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use out_codec::{MAX_REWARD_EXTRA_BYTES, MAX_TX_BYTES};
use out_consensus::chain::ChainTip;
use out_primitives::{BlockId, Recipient, U256Be};
use out_storage::RecoverableConsensusStorage;

use crate::dispatcher::{
    ApplicationDispatcher, CanonicalAccountStatus, DispatcherError, LocalMiningStep,
    MiningAnnouncementBackpressure, MiningControlCommand, MiningControlOutcome,
    MiningControlStatus,
};
use crate::driver::TransportDriver;
use crate::mempool::{MempoolAdmission, MempoolError};
use crate::mining::{CandidateRequest, MiningJobSnapshot, MiningStaleReason, MiningWorkOutcome};
use crate::SupportedNetwork;

pub const OPERATOR_PROTOCOL_VERSION_V0: u8 = 0;
pub const MAX_OPERATOR_FRAME_BYTES: u16 = 16_512;
const MAGIC: [u8; 4] = *b"OUTO";
const REQUEST_DIRECTION: u8 = 0;
const RESPONSE_DIRECTION: u8 = 1;
const HEADER_BYTES: usize = 18;
const TAG_BYTES: usize = 32;
const REQUEST_MAC_DOMAIN: &[u8] = b"OUT/operator/request/v0";
const RESPONSE_MAC_DOMAIN: &[u8] = b"OUT/operator/response/v0";

pub struct OperatorKey([u8; 32]);

impl OperatorKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, OperatorKeyError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(OperatorKeyError::AllZero);
        }
        Ok(Self(bytes))
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OperatorKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorKey([REDACTED])")
    }
}

impl Drop for OperatorKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorKeyError {
    AllZero,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixOperatorPolicy {
    pub read_timeout_millis: u64,
    pub write_timeout_millis: u64,
}

impl UnixOperatorPolicy {
    pub fn validate(self) -> Result<Self, UnixOperatorPolicyError> {
        if self.read_timeout_millis == 0 {
            return Err(UnixOperatorPolicyError::ZeroReadTimeout);
        }
        if self.write_timeout_millis == 0 {
            return Err(UnixOperatorPolicyError::ZeroWriteTimeout);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnixOperatorPolicyError {
    ZeroReadTimeout,
    ZeroWriteTimeout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedOperatorRequest {
    pub sequence: u64,
    pub command: OperatorCommand,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperatorCommand {
    Mining(MiningControlCommand),
    Shutdown,
    Account(Recipient),
    SubmitTransaction(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum OperatorRejectCode {
    Replay = 1,
    JobAlreadyActive = 2,
    JobNotActive = 3,
    ControlUnavailable = 4,
    CandidateRejected = 5,
    MiningFailed = 6,
    LocalFailure = 7,
    InvalidTransaction = 8,
    TransactionPolicy = 9,
    AccountUnavailable = 10,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorStepSummary {
    pub work: MiningWorkOutcome,
    pub submission_block_id: Option<BlockId>,
    pub relay_cached: bool,
    pub announcements_queued: u16,
    pub announcement_backpressure: Option<MiningAnnouncementBackpressure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperatorReply {
    Inspected(MiningControlStatus),
    Started(MiningJobSnapshot),
    Refreshed(MiningJobSnapshot),
    Stepped(OperatorStepSummary),
    Cancelled(Option<MiningJobSnapshot>),
    ShutdownRequested,
    Account(CanonicalAccountStatus),
    Transaction(MempoolAdmission),
    Rejected(OperatorRejectCode),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedOperatorResponse {
    pub sequence: u64,
    pub command_tag: u8,
    pub reply: OperatorReply,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperatorFrameError {
    TooShort,
    TooLarge { actual: usize, maximum: u16 },
    WrongMagic,
    WrongVersion(u8),
    WrongDirection { expected: u8, actual: u8 },
    NonzeroFlags(u8),
    ZeroSequence,
    PayloadLengthMismatch,
    AuthenticationFailed,
    UnknownCommand(u8),
    UnknownReply(u8),
    UnknownRejectCode(u16),
    InvalidLength,
    InvalidBoolean(u8),
    InvalidNetwork(u8),
    InvalidRecipient,
    RewardExtraTooLarge { actual: usize, maximum: u16 },
    TransactionTooLarge { actual: usize, maximum: u32 },
    TrailingBytes,
}

#[derive(Debug)]
pub enum UnixOperatorError {
    Policy(UnixOperatorPolicyError),
    PathAlreadyExists(PathBuf),
    Io(io::Error),
    Frame(OperatorFrameError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorServeOutcome {
    pub sequence: u64,
    pub command_tag: u8,
    pub reply: OperatorReply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

pub struct UnixMiningControlServer {
    listener: UnixListener,
    path: PathBuf,
    identity: SocketIdentity,
    key: OperatorKey,
    policy: UnixOperatorPolicy,
    last_sequence: Option<u64>,
}

impl UnixMiningControlServer {
    pub fn bind(
        path: impl AsRef<Path>,
        key: OperatorKey,
        policy: UnixOperatorPolicy,
    ) -> Result<Self, UnixOperatorError> {
        let policy = policy.validate().map_err(UnixOperatorError::Policy)?;
        let path = path.as_ref().to_path_buf();
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(UnixOperatorError::PathAlreadyExists(path)),
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(UnixOperatorError::Io(error));
            }
            Err(_) => {}
        }
        let listener = UnixListener::bind(&path).map_err(UnixOperatorError::Io)?;
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            drop(listener);
            let _ = fs::remove_file(&path);
            return Err(UnixOperatorError::Io(error));
        }
        let metadata = fs::symlink_metadata(&path).map_err(UnixOperatorError::Io)?;
        let identity = SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        Ok(Self {
            listener,
            path,
            identity,
            key,
            policy,
            last_sequence: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    /// Accepts, authenticates, executes, and responds to exactly one command.
    pub fn serve_once<S, D>(
        &mut self,
        dispatcher: &mut ApplicationDispatcher<S, D>,
    ) -> Result<OperatorServeOutcome, UnixOperatorError>
    where
        S: RecoverableConsensusStorage,
        D: TransportDriver,
    {
        let (mut stream, _) = self.listener.accept().map_err(UnixOperatorError::Io)?;
        stream
            .set_read_timeout(Some(Duration::from_millis(self.policy.read_timeout_millis)))
            .map_err(UnixOperatorError::Io)?;
        stream
            .set_write_timeout(Some(Duration::from_millis(
                self.policy.write_timeout_millis,
            )))
            .map_err(UnixOperatorError::Io)?;
        let frame = read_framed_operator_message(&mut stream)?;
        let request =
            decode_operator_request(&frame, &self.key).map_err(UnixOperatorError::Frame)?;
        let command_tag = command_tag(&request.command);
        if self
            .last_sequence
            .is_some_and(|last| request.sequence <= last)
        {
            let reply = OperatorReply::Rejected(OperatorRejectCode::Replay);
            let response =
                encode_operator_response(request.sequence, command_tag, &reply, &self.key)
                    .map_err(UnixOperatorError::Frame)?;
            write_framed_operator_message(&mut stream, &response)?;
            return Ok(OperatorServeOutcome {
                sequence: request.sequence,
                command_tag,
                reply,
            });
        }
        self.last_sequence = Some(request.sequence);
        let reply = match request.command {
            OperatorCommand::Mining(command) => match dispatcher.control_mining(command) {
                Ok(outcome) => reply_from_outcome(outcome),
                Err(error) => OperatorReply::Rejected(reject_code(&error)),
            },
            OperatorCommand::Shutdown => match dispatcher.request_shutdown() {
                Ok(()) => OperatorReply::ShutdownRequested,
                Err(error) => OperatorReply::Rejected(reject_code(&error)),
            },
            OperatorCommand::Account(recipient) => {
                match dispatcher.canonical_account_status(recipient) {
                    Ok(status) => OperatorReply::Account(status),
                    Err(error) => OperatorReply::Rejected(reject_code(&error)),
                }
            }
            OperatorCommand::SubmitTransaction(canonical_bytes) => {
                match dispatcher.submit_canonical_transaction(&canonical_bytes) {
                    Ok(admission) => OperatorReply::Transaction(admission),
                    Err(error) => OperatorReply::Rejected(reject_code(&error)),
                }
            }
        };
        let response = encode_operator_response(request.sequence, command_tag, &reply, &self.key)
            .map_err(UnixOperatorError::Frame)?;
        write_framed_operator_message(&mut stream, &response)?;
        Ok(OperatorServeOutcome {
            sequence: request.sequence,
            command_tag,
            reply,
        })
    }
}

impl Drop for UnixMiningControlServer {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.identity.device
            && metadata.ino() == self.identity.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn encode_operator_request(
    sequence: u64,
    command: &OperatorCommand,
    key: &OperatorKey,
) -> Result<Vec<u8>, OperatorFrameError> {
    if sequence == 0 {
        return Err(OperatorFrameError::ZeroSequence);
    }
    let mut payload = Vec::new();
    match command {
        OperatorCommand::Mining(MiningControlCommand::Inspect)
        | OperatorCommand::Mining(MiningControlCommand::Cancel)
        | OperatorCommand::Shutdown => {}
        OperatorCommand::Mining(MiningControlCommand::Start {
            request,
            first_nonce,
        })
        | OperatorCommand::Mining(MiningControlCommand::Refresh {
            request,
            first_nonce,
        }) => encode_candidate_request(&mut payload, request, *first_nonce)?,
        OperatorCommand::Mining(MiningControlCommand::Step { local_now }) => {
            put_u64(&mut payload, *local_now);
        }
        OperatorCommand::Account(recipient) => {
            payload.extend_from_slice(recipient.as_bytes());
        }
        OperatorCommand::SubmitTransaction(canonical_bytes) => {
            let maximum =
                usize::try_from(MAX_TX_BYTES).map_err(|_| OperatorFrameError::InvalidLength)?;
            if canonical_bytes.len() > maximum {
                return Err(OperatorFrameError::TransactionTooLarge {
                    actual: canonical_bytes.len(),
                    maximum: MAX_TX_BYTES,
                });
            }
            put_u16(
                &mut payload,
                u16::try_from(canonical_bytes.len())
                    .map_err(|_| OperatorFrameError::InvalidLength)?,
            );
            payload.extend_from_slice(canonical_bytes);
        }
    }
    encode_frame(
        REQUEST_DIRECTION,
        command_tag(command),
        sequence,
        &payload,
        key,
    )
}

pub fn decode_operator_request(
    bytes: &[u8],
    key: &OperatorKey,
) -> Result<AuthenticatedOperatorRequest, OperatorFrameError> {
    let decoded = decode_frame(bytes, REQUEST_DIRECTION, key)?;
    let mut cursor = Cursor::new(decoded.payload);
    let command = match decoded.kind {
        1 => OperatorCommand::Mining(MiningControlCommand::Inspect),
        2 | 3 => {
            let request = decode_candidate_request(&mut cursor)?;
            let first_nonce = cursor.u64()?;
            if decoded.kind == 2 {
                OperatorCommand::Mining(MiningControlCommand::Start {
                    request,
                    first_nonce,
                })
            } else {
                OperatorCommand::Mining(MiningControlCommand::Refresh {
                    request,
                    first_nonce,
                })
            }
        }
        4 => OperatorCommand::Mining(MiningControlCommand::Step {
            local_now: cursor.u64()?,
        }),
        5 => OperatorCommand::Mining(MiningControlCommand::Cancel),
        6 => OperatorCommand::Shutdown,
        7 => OperatorCommand::Account(
            Recipient::from_bytes(cursor.array()?)
                .map_err(|_| OperatorFrameError::InvalidRecipient)?,
        ),
        8 => {
            let length = usize::from(cursor.u16()?);
            let maximum =
                usize::try_from(MAX_TX_BYTES).map_err(|_| OperatorFrameError::InvalidLength)?;
            if length > maximum {
                return Err(OperatorFrameError::TransactionTooLarge {
                    actual: length,
                    maximum: MAX_TX_BYTES,
                });
            }
            OperatorCommand::SubmitTransaction(cursor.bytes(length)?.to_vec())
        }
        other => return Err(OperatorFrameError::UnknownCommand(other)),
    };
    cursor.finish()?;
    Ok(AuthenticatedOperatorRequest {
        sequence: decoded.sequence,
        command,
    })
}

pub fn encode_operator_response(
    sequence: u64,
    command_tag: u8,
    reply: &OperatorReply,
    key: &OperatorKey,
) -> Result<Vec<u8>, OperatorFrameError> {
    if sequence == 0 {
        return Err(OperatorFrameError::ZeroSequence);
    }
    let mut payload = Vec::new();
    encode_reply(&mut payload, reply)?;
    encode_frame(RESPONSE_DIRECTION, command_tag, sequence, &payload, key)
}

pub fn decode_operator_response(
    bytes: &[u8],
    key: &OperatorKey,
) -> Result<AuthenticatedOperatorResponse, OperatorFrameError> {
    let decoded = decode_frame(bytes, RESPONSE_DIRECTION, key)?;
    let mut cursor = Cursor::new(decoded.payload);
    let reply = decode_reply(&mut cursor)?;
    cursor.finish()?;
    Ok(AuthenticatedOperatorResponse {
        sequence: decoded.sequence,
        command_tag: decoded.kind,
        reply,
    })
}

pub fn read_framed_operator_message(reader: &mut impl Read) -> Result<Vec<u8>, UnixOperatorError> {
    let mut length = [0_u8; 2];
    reader
        .read_exact(&mut length)
        .map_err(UnixOperatorError::Io)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length > usize::from(MAX_OPERATOR_FRAME_BYTES) {
        return Err(UnixOperatorError::Frame(OperatorFrameError::TooLarge {
            actual: length,
            maximum: MAX_OPERATOR_FRAME_BYTES,
        }));
    }
    if length < HEADER_BYTES + TAG_BYTES {
        return Err(UnixOperatorError::Frame(OperatorFrameError::TooShort));
    }
    let mut bytes = vec![0_u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(UnixOperatorError::Io)?;
    Ok(bytes)
}

pub fn write_framed_operator_message(
    writer: &mut impl Write,
    bytes: &[u8],
) -> Result<(), UnixOperatorError> {
    if bytes.len() > usize::from(MAX_OPERATOR_FRAME_BYTES) {
        return Err(UnixOperatorError::Frame(OperatorFrameError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_OPERATOR_FRAME_BYTES,
        }));
    }
    let length = u16::try_from(bytes.len())
        .map_err(|_| UnixOperatorError::Frame(OperatorFrameError::InvalidLength))?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(bytes))
        .and_then(|()| writer.flush())
        .map_err(UnixOperatorError::Io)
}

fn command_tag(command: &OperatorCommand) -> u8 {
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

fn encode_candidate_request(
    output: &mut Vec<u8>,
    request: &CandidateRequest,
    first_nonce: u64,
) -> Result<(), OperatorFrameError> {
    if request.reward_extra.len() > usize::from(MAX_REWARD_EXTRA_BYTES) {
        return Err(OperatorFrameError::RewardExtraTooLarge {
            actual: request.reward_extra.len(),
            maximum: MAX_REWARD_EXTRA_BYTES,
        });
    }
    put_u64(output, request.timestamp);
    put_u64(output, request.local_now);
    output.extend_from_slice(request.reward_recipient.as_bytes());
    put_u16(
        output,
        u16::try_from(request.reward_extra.len()).map_err(|_| OperatorFrameError::InvalidLength)?,
    );
    output.extend_from_slice(&request.reward_extra);
    put_u64(output, first_nonce);
    Ok(())
}

fn decode_candidate_request(
    cursor: &mut Cursor<'_>,
) -> Result<CandidateRequest, OperatorFrameError> {
    let timestamp = cursor.u64()?;
    let local_now = cursor.u64()?;
    let recipient =
        Recipient::from_bytes(cursor.array()?).map_err(|_| OperatorFrameError::InvalidRecipient)?;
    let extra_length = usize::from(cursor.u16()?);
    if extra_length > usize::from(MAX_REWARD_EXTRA_BYTES) {
        return Err(OperatorFrameError::RewardExtraTooLarge {
            actual: extra_length,
            maximum: MAX_REWARD_EXTRA_BYTES,
        });
    }
    let reward_extra = cursor.bytes(extra_length)?.to_vec();
    Ok(CandidateRequest {
        timestamp,
        local_now,
        reward_recipient: recipient,
        reward_extra,
    })
}

struct DecodedFrame<'a> {
    kind: u8,
    sequence: u64,
    payload: &'a [u8],
}

fn encode_frame(
    direction: u8,
    kind: u8,
    sequence: u64,
    payload: &[u8],
    key: &OperatorKey,
) -> Result<Vec<u8>, OperatorFrameError> {
    let payload_length =
        u16::try_from(payload.len()).map_err(|_| OperatorFrameError::InvalidLength)?;
    let total = HEADER_BYTES
        .checked_add(payload.len())
        .and_then(|value| value.checked_add(TAG_BYTES))
        .ok_or(OperatorFrameError::InvalidLength)?;
    if total > usize::from(MAX_OPERATOR_FRAME_BYTES) {
        return Err(OperatorFrameError::TooLarge {
            actual: total,
            maximum: MAX_OPERATOR_FRAME_BYTES,
        });
    }
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&MAGIC);
    output.push(OPERATOR_PROTOCOL_VERSION_V0);
    output.push(direction);
    output.push(kind);
    output.push(0);
    put_u64(&mut output, sequence);
    put_u16(&mut output, payload_length);
    let domain = if direction == REQUEST_DIRECTION {
        REQUEST_MAC_DOMAIN
    } else {
        RESPONSE_MAC_DOMAIN
    };
    output.extend_from_slice(payload);
    let tag = keyed_tag(key, domain, &output);
    output.extend_from_slice(&tag);
    Ok(output)
}

fn decode_frame<'a>(
    bytes: &'a [u8],
    direction: u8,
    key: &OperatorKey,
) -> Result<DecodedFrame<'a>, OperatorFrameError> {
    if bytes.len() < HEADER_BYTES + TAG_BYTES {
        return Err(OperatorFrameError::TooShort);
    }
    if bytes.len() > usize::from(MAX_OPERATOR_FRAME_BYTES) {
        return Err(OperatorFrameError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_OPERATOR_FRAME_BYTES,
        });
    }
    if bytes[..4] != MAGIC {
        return Err(OperatorFrameError::WrongMagic);
    }
    if bytes[4] != OPERATOR_PROTOCOL_VERSION_V0 {
        return Err(OperatorFrameError::WrongVersion(bytes[4]));
    }
    if bytes[5] != direction {
        return Err(OperatorFrameError::WrongDirection {
            expected: direction,
            actual: bytes[5],
        });
    }
    if bytes[7] != 0 {
        return Err(OperatorFrameError::NonzeroFlags(bytes[7]));
    }
    let sequence = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| OperatorFrameError::TooShort)?,
    );
    if sequence == 0 {
        return Err(OperatorFrameError::ZeroSequence);
    }
    let payload_length = usize::from(u16::from_be_bytes(
        bytes[16..18]
            .try_into()
            .map_err(|_| OperatorFrameError::TooShort)?,
    ));
    let expected = HEADER_BYTES
        .checked_add(payload_length)
        .and_then(|value| value.checked_add(TAG_BYTES))
        .ok_or(OperatorFrameError::InvalidLength)?;
    if expected != bytes.len() {
        return Err(OperatorFrameError::PayloadLengthMismatch);
    }
    let tag_start = bytes.len() - TAG_BYTES;
    let domain = if direction == REQUEST_DIRECTION {
        REQUEST_MAC_DOMAIN
    } else {
        RESPONSE_MAC_DOMAIN
    };
    let expected_tag = keyed_tag(key, domain, &bytes[..tag_start]);
    if !constant_time_equal(&expected_tag, &bytes[tag_start..]) {
        return Err(OperatorFrameError::AuthenticationFailed);
    }
    Ok(DecodedFrame {
        kind: bytes[6],
        sequence,
        payload: &bytes[HEADER_BYTES..tag_start],
    })
}

fn keyed_tag(key: &OperatorKey, domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key.bytes());
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn constant_time_equal(expected: &[u8; 32], actual: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in expected.iter().zip(actual) {
        difference |= left ^ right;
    }
    difference == 0
}

fn reply_from_outcome(outcome: MiningControlOutcome) -> OperatorReply {
    match outcome {
        MiningControlOutcome::Inspected(status) => OperatorReply::Inspected(status),
        MiningControlOutcome::Started(job) => OperatorReply::Started(job),
        MiningControlOutcome::Refreshed { current, .. } => OperatorReply::Refreshed(current),
        MiningControlOutcome::Stepped(step) => OperatorReply::Stepped(step_summary(*step)),
        MiningControlOutcome::Cancelled(job) => OperatorReply::Cancelled(job),
    }
}

fn step_summary(step: LocalMiningStep) -> OperatorStepSummary {
    OperatorStepSummary {
        work: step.work,
        submission_block_id: step.submission.map(|submission| submission.stored.block_id),
        relay_cached: step.relay_cached,
        announcements_queued: step.announcements_queued,
        announcement_backpressure: step.announcement_backpressure,
    }
}

fn reject_code<ReadError, MutationError, RecoveryError, TransportError>(
    error: &DispatcherError<ReadError, MutationError, RecoveryError, TransportError>,
) -> OperatorRejectCode {
    match error {
        DispatcherError::MiningJobAlreadyActive(_) => OperatorRejectCode::JobAlreadyActive,
        DispatcherError::MiningJobNotActive => OperatorRejectCode::JobNotActive,
        DispatcherError::MempoolUnavailable => OperatorRejectCode::ControlUnavailable,
        DispatcherError::Candidate(_) => OperatorRejectCode::CandidateRejected,
        DispatcherError::Mining(_) => OperatorRejectCode::MiningFailed,
        DispatcherError::CanonicalTransactionDecode(_) => OperatorRejectCode::InvalidTransaction,
        DispatcherError::Mempool(error) => match error {
            MempoolError::Invalid(_)
            | MempoolError::RewardTransaction
            | MempoolError::CanonicalEncoding(_)
            | MempoolError::CanonicalLength { .. } => OperatorRejectCode::InvalidTransaction,
            MempoolError::TransactionCapacity { .. }
            | MempoolError::SenderCapacity { .. }
            | MempoolError::ByteCapacity { .. } => OperatorRejectCode::TransactionPolicy,
            _ => OperatorRejectCode::LocalFailure,
        },
        DispatcherError::AccountTipRead(_)
        | DispatcherError::AccountStateRead(_)
        | DispatcherError::MissingCanonicalAccountState(_)
        | DispatcherError::AccountStateAnchorMismatch { .. }
        | DispatcherError::DuplicateCanonicalAccount(_) => OperatorRejectCode::AccountUnavailable,
        _ => OperatorRejectCode::LocalFailure,
    }
}

fn encode_reply(output: &mut Vec<u8>, reply: &OperatorReply) -> Result<(), OperatorFrameError> {
    match reply {
        OperatorReply::Inspected(status) => {
            output.push(1);
            encode_status(output, status);
        }
        OperatorReply::Started(job) => {
            output.push(2);
            encode_job(output, job);
        }
        OperatorReply::Refreshed(job) => {
            output.push(3);
            encode_job(output, job);
        }
        OperatorReply::Stepped(step) => {
            output.push(4);
            encode_work(output, &step.work);
            encode_optional_block_id(output, step.submission_block_id);
            put_bool(output, step.relay_cached);
            put_u16(output, step.announcements_queued);
            match step.announcement_backpressure {
                Some(backpressure) => {
                    output.push(1);
                    put_u16(output, backpressure.required);
                    put_u16(output, backpressure.available);
                }
                None => output.push(0),
            }
        }
        OperatorReply::Cancelled(job) => {
            output.push(5);
            encode_optional_job(output, job.as_ref());
        }
        OperatorReply::ShutdownRequested => output.push(6),
        OperatorReply::Account(status) => {
            output.push(7);
            encode_tip(output, status.canonical_tip);
            output.extend_from_slice(status.recipient.as_bytes());
            put_bool(output, status.exists);
            put_u64(output, status.balance.get());
            put_u64(output, status.nonce.get());
        }
        OperatorReply::Transaction(admission) => {
            output.push(8);
            match admission {
                MempoolAdmission::Accepted {
                    transaction_id,
                    bytes,
                } => {
                    output.push(1);
                    output.extend_from_slice(transaction_id.as_bytes());
                    put_u32(output, *bytes);
                }
                MempoolAdmission::AlreadyPresent { transaction_id } => {
                    output.push(2);
                    output.extend_from_slice(transaction_id.as_bytes());
                }
                MempoolAdmission::AlreadyConfirmed { transaction_id } => {
                    output.push(3);
                    output.extend_from_slice(transaction_id.as_bytes());
                }
            }
        }
        OperatorReply::Rejected(code) => {
            output.push(255);
            put_u16(output, *code as u16);
        }
    }
    Ok(())
}

fn decode_reply(cursor: &mut Cursor<'_>) -> Result<OperatorReply, OperatorFrameError> {
    match cursor.u8()? {
        1 => Ok(OperatorReply::Inspected(decode_status(cursor)?)),
        2 => Ok(OperatorReply::Started(decode_job(cursor)?)),
        3 => Ok(OperatorReply::Refreshed(decode_job(cursor)?)),
        4 => {
            let work = decode_work(cursor)?;
            let submission_block_id = decode_optional_block_id(cursor)?;
            let relay_cached = cursor.boolean()?;
            let announcements_queued = cursor.u16()?;
            let announcement_backpressure = match cursor.u8()? {
                0 => None,
                1 => Some(MiningAnnouncementBackpressure {
                    required: cursor.u16()?,
                    available: cursor.u16()?,
                }),
                other => return Err(OperatorFrameError::InvalidBoolean(other)),
            };
            Ok(OperatorReply::Stepped(OperatorStepSummary {
                work,
                submission_block_id,
                relay_cached,
                announcements_queued,
                announcement_backpressure,
            }))
        }
        5 => Ok(OperatorReply::Cancelled(decode_optional_job(cursor)?)),
        6 => Ok(OperatorReply::ShutdownRequested),
        7 => {
            let canonical_tip = decode_tip(cursor)?;
            let recipient = Recipient::from_bytes(cursor.array()?)
                .map_err(|_| OperatorFrameError::InvalidRecipient)?;
            let exists = cursor.boolean()?;
            let balance = out_primitives::Amount::new(cursor.u64()?);
            let nonce = out_primitives::Nonce::new(cursor.u64()?);
            Ok(OperatorReply::Account(CanonicalAccountStatus {
                canonical_tip,
                recipient,
                exists,
                balance,
                nonce,
            }))
        }
        8 => {
            let admission_tag = cursor.u8()?;
            let transaction_id = out_primitives::TransactionId::new(cursor.array()?);
            let admission = match admission_tag {
                1 => MempoolAdmission::Accepted {
                    transaction_id,
                    bytes: cursor.u32()?,
                },
                2 => MempoolAdmission::AlreadyPresent { transaction_id },
                3 => MempoolAdmission::AlreadyConfirmed { transaction_id },
                other => return Err(OperatorFrameError::UnknownReply(other)),
            };
            Ok(OperatorReply::Transaction(admission))
        }
        255 => Ok(OperatorReply::Rejected(decode_reject_code(cursor.u16()?)?)),
        other => Err(OperatorFrameError::UnknownReply(other)),
    }
}

fn encode_status(output: &mut Vec<u8>, status: &MiningControlStatus) {
    output.push(match status.network {
        SupportedNetwork::Testnet => 1,
        SupportedNetwork::Devnet => 2,
    });
    encode_tip(output, status.canonical_tip);
    put_u64(output, status.mempool_revision);
    encode_optional_job(output, status.job.as_ref());
}

fn decode_status(cursor: &mut Cursor<'_>) -> Result<MiningControlStatus, OperatorFrameError> {
    let network = match cursor.u8()? {
        1 => SupportedNetwork::Testnet,
        2 => SupportedNetwork::Devnet,
        other => return Err(OperatorFrameError::InvalidNetwork(other)),
    };
    Ok(MiningControlStatus {
        network,
        canonical_tip: decode_tip(cursor)?,
        mempool_revision: cursor.u64()?,
        job: decode_optional_job(cursor)?,
    })
}

fn encode_optional_job(output: &mut Vec<u8>, job: Option<&MiningJobSnapshot>) {
    match job {
        Some(job) => {
            output.push(1);
            encode_job(output, job);
        }
        None => output.push(0),
    }
}

fn decode_optional_job(
    cursor: &mut Cursor<'_>,
) -> Result<Option<MiningJobSnapshot>, OperatorFrameError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => decode_job(cursor).map(Some),
        other => Err(OperatorFrameError::InvalidBoolean(other)),
    }
}

fn encode_job(output: &mut Vec<u8>, job: &MiningJobSnapshot) {
    encode_tip(output, job.parent_tip);
    put_u64(output, job.height);
    put_u64(output, job.mempool_revision);
    put_u64(output, job.next_nonce);
    output.extend_from_slice(&job.total_attempts.to_be_bytes());
    encode_optional_block_id(output, job.solution_block_id);
}

fn decode_job(cursor: &mut Cursor<'_>) -> Result<MiningJobSnapshot, OperatorFrameError> {
    Ok(MiningJobSnapshot {
        parent_tip: decode_tip(cursor)?,
        height: cursor.u64()?,
        mempool_revision: cursor.u64()?,
        next_nonce: cursor.u64()?,
        total_attempts: cursor.u128()?,
        solution_block_id: decode_optional_block_id(cursor)?,
    })
}

fn encode_tip(output: &mut Vec<u8>, tip: ChainTip) {
    output.extend_from_slice(tip.block_id.as_bytes());
    put_u64(output, tip.height);
    output.extend_from_slice(tip.cumulative_work.as_bytes());
}

fn decode_tip(cursor: &mut Cursor<'_>) -> Result<ChainTip, OperatorFrameError> {
    Ok(ChainTip {
        block_id: BlockId::new(cursor.array()?),
        height: cursor.u64()?,
        cumulative_work: U256Be::new(cursor.array()?),
    })
}

fn encode_optional_block_id(output: &mut Vec<u8>, block_id: Option<BlockId>) {
    match block_id {
        Some(block_id) => {
            output.push(1);
            output.extend_from_slice(block_id.as_bytes());
        }
        None => output.push(0),
    }
}

fn decode_optional_block_id(
    cursor: &mut Cursor<'_>,
) -> Result<Option<BlockId>, OperatorFrameError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(BlockId::new(cursor.array()?))),
        other => Err(OperatorFrameError::InvalidBoolean(other)),
    }
}

fn encode_work(output: &mut Vec<u8>, work: &MiningWorkOutcome) {
    match work {
        MiningWorkOutcome::Idle => output.push(0),
        MiningWorkOutcome::Stale(MiningStaleReason::CanonicalTipChanged(change)) => {
            output.push(1);
            encode_tip(output, change.0);
            encode_tip(output, change.1);
        }
        MiningWorkOutcome::Stale(MiningStaleReason::MempoolChanged { expected, actual }) => {
            output.push(2);
            put_u64(output, *expected);
            put_u64(output, *actual);
        }
        MiningWorkOutcome::Progress {
            attempts,
            total_attempts,
            next_nonce,
        } => {
            output.push(3);
            put_u64(output, *attempts);
            output.extend_from_slice(&total_attempts.to_be_bytes());
            put_u64(output, *next_nonce);
        }
        MiningWorkOutcome::SolutionFound {
            attempts,
            total_attempts,
            block_id,
        } => {
            output.push(4);
            put_u64(output, *attempts);
            output.extend_from_slice(&total_attempts.to_be_bytes());
            output.extend_from_slice(block_id.as_bytes());
        }
        MiningWorkOutcome::SolutionPending {
            total_attempts,
            block_id,
        } => {
            output.push(5);
            output.extend_from_slice(&total_attempts.to_be_bytes());
            output.extend_from_slice(block_id.as_bytes());
        }
        MiningWorkOutcome::NonceSpaceExhausted {
            attempts,
            total_attempts,
        } => {
            output.push(6);
            put_u64(output, *attempts);
            output.extend_from_slice(&total_attempts.to_be_bytes());
        }
    }
}

fn decode_work(cursor: &mut Cursor<'_>) -> Result<MiningWorkOutcome, OperatorFrameError> {
    match cursor.u8()? {
        0 => Ok(MiningWorkOutcome::Idle),
        1 => Ok(MiningWorkOutcome::Stale(
            MiningStaleReason::CanonicalTipChanged(Box::new((
                decode_tip(cursor)?,
                decode_tip(cursor)?,
            ))),
        )),
        2 => Ok(MiningWorkOutcome::Stale(
            MiningStaleReason::MempoolChanged {
                expected: cursor.u64()?,
                actual: cursor.u64()?,
            },
        )),
        3 => Ok(MiningWorkOutcome::Progress {
            attempts: cursor.u64()?,
            total_attempts: cursor.u128()?,
            next_nonce: cursor.u64()?,
        }),
        4 => Ok(MiningWorkOutcome::SolutionFound {
            attempts: cursor.u64()?,
            total_attempts: cursor.u128()?,
            block_id: BlockId::new(cursor.array()?),
        }),
        5 => Ok(MiningWorkOutcome::SolutionPending {
            total_attempts: cursor.u128()?,
            block_id: BlockId::new(cursor.array()?),
        }),
        6 => Ok(MiningWorkOutcome::NonceSpaceExhausted {
            attempts: cursor.u64()?,
            total_attempts: cursor.u128()?,
        }),
        other => Err(OperatorFrameError::UnknownReply(other)),
    }
}

fn decode_reject_code(value: u16) -> Result<OperatorRejectCode, OperatorFrameError> {
    match value {
        1 => Ok(OperatorRejectCode::Replay),
        2 => Ok(OperatorRejectCode::JobAlreadyActive),
        3 => Ok(OperatorRejectCode::JobNotActive),
        4 => Ok(OperatorRejectCode::ControlUnavailable),
        5 => Ok(OperatorRejectCode::CandidateRejected),
        6 => Ok(OperatorRejectCode::MiningFailed),
        7 => Ok(OperatorRejectCode::LocalFailure),
        8 => Ok(OperatorRejectCode::InvalidTransaction),
        9 => Ok(OperatorRejectCode::TransactionPolicy),
        10 => Ok(OperatorRejectCode::AccountUnavailable),
        other => Err(OperatorFrameError::UnknownRejectCode(other)),
    }
}

fn put_bool(output: &mut Vec<u8>, value: bool) {
    output.push(u8::from(value));
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], OperatorFrameError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(OperatorFrameError::InvalidLength)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(OperatorFrameError::InvalidLength)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], OperatorFrameError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| OperatorFrameError::InvalidLength)
    }

    fn u8(&mut self) -> Result<u8, OperatorFrameError> {
        self.bytes(1)?
            .first()
            .copied()
            .ok_or(OperatorFrameError::InvalidLength)
    }

    fn boolean(&mut self) -> Result<bool, OperatorFrameError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(OperatorFrameError::InvalidBoolean(other)),
        }
    }

    fn u16(&mut self) -> Result<u16, OperatorFrameError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, OperatorFrameError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, OperatorFrameError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u128(&mut self) -> Result<u128, OperatorFrameError> {
        Ok(u128::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), OperatorFrameError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(OperatorFrameError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor as IoCursor;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};

    use out_codec::Transaction;
    use out_consensus::chain::ValidatedHeaderView;
    use out_storage::conformance::validated_reward_commit;
    use out_storage::InMemoryConsensusStore;

    use super::*;
    use crate::bootstrap::NodeBootstrap;
    use crate::dispatcher::{ApplicationDispatcher, DispatcherPolicy};
    use crate::driver::{BoundedMemoryDriver, DaemonHarness, DaemonPolicy, MemoryDriverPolicy};
    use crate::mempool::MempoolPolicy;
    use crate::mining::CpuMiningPolicy;
    use crate::peers::{MemoryTransportPolicy, MultiPeerPolicy};
    use crate::runtime::{NodeRuntime, RuntimePolicy};
    use crate::serving::ServingPolicy;
    use crate::sync::SyncPolicy;
    use crate::Node;

    const KEY_BYTES: [u8; 32] = [0x5a; 32];
    const VECTOR_TRANSACTION_HEX: &str = "0000000000bc0000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a70003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b800000000000000000029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000075bcd1500000000000003e8000000000000000100000000000003e8000a4f555420766563746f720062000003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b84db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b";

    fn key() -> OperatorKey {
        OperatorKey::from_bytes(KEY_BYTES).unwrap()
    }

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

    fn socket_path(label: &str) -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "out-operator-{label}-{}-{sequence}.sock",
            std::process::id()
        ))
    }

    fn dispatcher() -> ApplicationDispatcher<InMemoryConsensusStore, BoundedMemoryDriver> {
        let node = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        }
        .create_in_memory()
        .unwrap();
        dispatcher_for_node(node)
    }

    fn funded_dispatcher() -> (
        ApplicationDispatcher<InMemoryConsensusStore, BoundedMemoryDriver>,
        Recipient,
        out_primitives::Amount,
    ) {
        let mut node = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        }
        .create_in_memory()
        .unwrap();
        let genesis = node.canonical_tip().unwrap().block_id;
        let commit = validated_reward_commit(node.storage(), genesis, b"mempool-funding");
        let Transaction::Reward(reward) = &commit.block().body.transactions[0] else {
            panic!("reward transaction");
        };
        let recipient = reward.body.recipient;
        let balance = reward.body.subsidy.checked_add(reward.body.fees).unwrap();
        let local_now = commit.header().header().timestamp;
        node.process_block(commit.canonical_block_bytes(), local_now)
            .unwrap();
        (dispatcher_for_node(node), recipient, balance)
    }

    fn dispatcher_for_node(
        node: Node<InMemoryConsensusStore>,
    ) -> ApplicationDispatcher<InMemoryConsensusStore, BoundedMemoryDriver> {
        let runtime = NodeRuntime::new(
            node,
            RuntimePolicy {
                maximum_peers: 2,
                maximum_inbound_events: 4,
                maximum_inbound_bytes: 1_000_000,
                maximum_frame_bytes: 1_000_000,
                maximum_output_events: 4,
                maximum_inbound_events_per_step: 4,
                maximum_peer_polls_per_step: 2,
            },
        )
        .unwrap();
        let queue = MemoryTransportPolicy {
            maximum_queued_frames: 4,
            maximum_queued_bytes: 1_000_000,
            maximum_frame_bytes: 1_000_000,
        };
        let driver = BoundedMemoryDriver::new(MemoryDriverPolicy {
            inbound: queue,
            outbound: queue,
        })
        .unwrap();
        let daemon = DaemonHarness::new(
            runtime,
            driver,
            DaemonPolicy {
                maximum_transport_receives_per_step: 4,
                maximum_transport_sends_per_step: 4,
                maximum_runtime_outputs_per_step: 4,
                maximum_pending_outbound_frames: 4,
                maximum_pending_outbound_bytes: 1_000_000,
                maximum_local_events: 8,
            },
        )
        .unwrap();
        ApplicationDispatcher::new(
            daemon,
            SyncPolicy {
                maximum_overlay_headers: 4,
                maximum_blocks_per_request: 2,
                maximum_locator_entries: 4,
                linear_locator_entries: 2,
                maximum_locator_walk: 100,
            },
            MultiPeerPolicy {
                maximum_peers: 2,
                maximum_announcements_per_peer: 4,
                maximum_total_announcements: 8,
                maximum_pending_objects: 4,
                maximum_in_flight_per_peer: 2,
                maximum_retry_attempts: 2,
                request_timeout_ticks: 20,
                base_retry_backoff_ticks: 1,
                maximum_retry_backoff_ticks: 4,
                first_request_id: 100,
                maximum_orphans: 4,
                maximum_orphans_per_peer: 4,
                maximum_orphans_per_parent: 2,
                maximum_orphan_bytes: 1_000_000,
            },
            DispatcherPolicy {
                maximum_events_per_step: 8,
                maximum_commands_per_step: 4,
                first_orphan_replay_request_id: 10_000,
            },
            ServingPolicy {
                maximum_pending_requests: 4,
                maximum_responses_per_step: 2,
                maximum_pending_announcements: 4,
                maximum_announcements_per_step: 2,
                maximum_inventory_entries_per_announcement: 4,
                maximum_headers_per_response: 2,
                maximum_ancestry_records: 100,
                maximum_relay_blocks: 4,
                maximum_relay_bytes: 1_000_000,
            },
            MempoolPolicy {
                maximum_transactions: 8,
                maximum_total_bytes: 100_000,
                maximum_transactions_per_sender: 4,
                maximum_template_transactions: 4,
                maximum_template_bytes: 50_000,
            },
            CpuMiningPolicy {
                maximum_nonce_attempts: 8,
            },
        )
        .unwrap()
    }

    fn start_command(
        dispatcher: &ApplicationDispatcher<InMemoryConsensusStore, BoundedMemoryDriver>,
    ) -> OperatorCommand {
        let node = dispatcher.daemon().runtime().node();
        let genesis = node.canonical_tip().unwrap().block_id;
        let probe = validated_reward_commit(node.storage(), genesis, b"operator-recipient");
        let Transaction::Reward(reward) = &probe.block().body.transactions[0] else {
            panic!("reward probe");
        };
        let parent = node
            .storage()
            .get_validated_header(genesis)
            .unwrap()
            .unwrap();
        let timestamp = parent.header().timestamp + 1;
        OperatorCommand::Mining(MiningControlCommand::Start {
            request: CandidateRequest {
                timestamp,
                local_now: timestamp,
                reward_recipient: reward.body.recipient,
                reward_extra: b"unix-operator".to_vec(),
            },
            first_nonce: 7,
        })
    }

    fn exchange(
        server: &mut UnixMiningControlServer,
        dispatcher: &mut ApplicationDispatcher<InMemoryConsensusStore, BoundedMemoryDriver>,
        sequence: u64,
        command: &OperatorCommand,
    ) -> AuthenticatedOperatorResponse {
        let request = encode_operator_request(sequence, command, &key()).unwrap();
        let mut client = UnixStream::connect(server.path()).unwrap();
        write_framed_operator_message(&mut client, &request).unwrap();
        let served = server.serve_once(dispatcher).unwrap();
        assert_eq!(served.sequence, sequence);
        let response = read_framed_operator_message(&mut client).unwrap();
        decode_operator_response(&response, &key()).unwrap()
    }

    #[test]
    fn request_codec_is_canonical_authenticated_and_bounded() {
        let dispatcher = dispatcher();
        let mut recipient_bytes = [0x11; 33];
        recipient_bytes[0] = 0;
        let recipient = Recipient::from_bytes(recipient_bytes).unwrap();
        let commands = [
            OperatorCommand::Mining(MiningControlCommand::Inspect),
            start_command(&dispatcher),
            OperatorCommand::Mining(MiningControlCommand::Step { local_now: 123 }),
            OperatorCommand::Mining(MiningControlCommand::Cancel),
            OperatorCommand::Shutdown,
            OperatorCommand::Account(recipient),
            OperatorCommand::SubmitTransaction(vec![0, 1, 2]),
        ];
        for (index, command) in commands.iter().enumerate() {
            let sequence = u64::try_from(index).unwrap() + 1;
            let encoded = encode_operator_request(sequence, command, &key()).unwrap();
            assert!(encoded.len() <= usize::from(MAX_OPERATOR_FRAME_BYTES));
            assert_eq!(
                decode_operator_request(&encoded, &key()).unwrap(),
                AuthenticatedOperatorRequest {
                    sequence,
                    command: command.clone(),
                }
            );
            let mut tampered = encoded.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            assert_eq!(
                decode_operator_request(&tampered, &key()),
                Err(OperatorFrameError::AuthenticationFailed)
            );
            let wrong_key = OperatorKey::from_bytes([0x33; 32]).unwrap();
            assert_eq!(
                decode_operator_request(&encoded, &wrong_key),
                Err(OperatorFrameError::AuthenticationFailed)
            );
        }
        assert!(matches!(
            OperatorKey::from_bytes([0; 32]),
            Err(OperatorKeyError::AllZero)
        ));
        assert_eq!(format!("{:?}", key()), "OperatorKey([REDACTED])");

        let mut oversized = IoCursor::new((MAX_OPERATOR_FRAME_BYTES + 1).to_be_bytes());
        assert!(matches!(
            read_framed_operator_message(&mut oversized),
            Err(UnixOperatorError::Frame(OperatorFrameError::TooLarge {
                actual,
                maximum: MAX_OPERATOR_FRAME_BYTES,
            })) if actual == usize::from(MAX_OPERATOR_FRAME_BYTES) + 1
        ));
        let maximum_transaction =
            OperatorCommand::SubmitTransaction(vec![0xaa; MAX_TX_BYTES as usize]);
        assert!(
            encode_operator_request(100, &maximum_transaction, &key())
                .unwrap()
                .len()
                <= usize::from(MAX_OPERATOR_FRAME_BYTES)
        );
        assert!(matches!(
            encode_operator_request(
                101,
                &OperatorCommand::SubmitTransaction(vec![0xaa; MAX_TX_BYTES as usize + 1]),
                &key(),
            ),
            Err(OperatorFrameError::TransactionTooLarge {
                actual,
                maximum: MAX_TX_BYTES,
            }) if actual == MAX_TX_BYTES as usize + 1
        ));
        assert!(dispatcher.mining().snapshot().is_none());
    }

    #[test]
    fn response_codec_round_trips_status_work_and_rejection() {
        let tip = ChainTip {
            block_id: BlockId::new([1; 32]),
            height: 9,
            cumulative_work: U256Be::new([2; 32]),
        };
        let job = MiningJobSnapshot {
            parent_tip: tip,
            height: 10,
            mempool_revision: 3,
            next_nonce: 44,
            total_attempts: 55,
            solution_block_id: Some(BlockId::new([3; 32])),
        };
        let replies = [
            OperatorReply::Inspected(MiningControlStatus {
                network: SupportedNetwork::Devnet,
                canonical_tip: tip,
                mempool_revision: 3,
                job: Some(job.clone()),
            }),
            OperatorReply::Stepped(OperatorStepSummary {
                work: MiningWorkOutcome::Progress {
                    attempts: 8,
                    total_attempts: 55,
                    next_nonce: 44,
                },
                submission_block_id: None,
                relay_cached: false,
                announcements_queued: 0,
                announcement_backpressure: Some(MiningAnnouncementBackpressure {
                    required: 2,
                    available: 1,
                }),
            }),
            OperatorReply::Cancelled(Some(job)),
            OperatorReply::Account(CanonicalAccountStatus {
                canonical_tip: tip,
                recipient: Recipient::from_bytes([0; 33]).unwrap(),
                exists: false,
                balance: out_primitives::Amount::ZERO,
                nonce: out_primitives::Nonce::ZERO,
            }),
            OperatorReply::Transaction(MempoolAdmission::Accepted {
                transaction_id: out_primitives::TransactionId::new([4; 32]),
                bytes: 291,
            }),
            OperatorReply::Rejected(OperatorRejectCode::CandidateRejected),
        ];
        for reply in replies {
            let encoded = encode_operator_response(7, 4, &reply, &key()).unwrap();
            assert_eq!(
                decode_operator_response(&encoded, &key()).unwrap(),
                AuthenticatedOperatorResponse {
                    sequence: 7,
                    command_tag: 4,
                    reply,
                }
            );
        }
    }

    #[test]
    fn unix_server_queries_canonical_accounts_and_submits_signed_transactions() {
        let path = socket_path("account-submit");
        let mut server = UnixMiningControlServer::bind(
            &path,
            key(),
            UnixOperatorPolicy {
                read_timeout_millis: 1_000,
                write_timeout_millis: 1_000,
            },
        )
        .unwrap();
        let (mut dispatcher, funded_recipient, expected_balance) = funded_dispatcher();

        let funded = exchange(
            &mut server,
            &mut dispatcher,
            1,
            &OperatorCommand::Account(funded_recipient),
        );
        assert!(matches!(
            funded.reply,
            OperatorReply::Account(CanonicalAccountStatus {
                recipient,
                exists: true,
                balance,
                nonce: out_primitives::Nonce::ZERO,
                ..
            }) if recipient == funded_recipient && balance == expected_balance
        ));

        let mut absent_bytes = [0x77; 33];
        absent_bytes[0] = 0;
        let absent_recipient = Recipient::from_bytes(absent_bytes).unwrap();
        let absent = exchange(
            &mut server,
            &mut dispatcher,
            2,
            &OperatorCommand::Account(absent_recipient),
        );
        assert!(matches!(
            absent.reply,
            OperatorReply::Account(CanonicalAccountStatus {
                recipient,
                exists: false,
                balance: out_primitives::Amount::ZERO,
                nonce: out_primitives::Nonce::ZERO,
                ..
            }) if recipient == absent_recipient
        ));

        let canonical_transaction = hex(VECTOR_TRANSACTION_HEX);
        let accepted = exchange(
            &mut server,
            &mut dispatcher,
            3,
            &OperatorCommand::SubmitTransaction(canonical_transaction.clone()),
        );
        let OperatorReply::Transaction(MempoolAdmission::Accepted {
            transaction_id,
            bytes,
        }) = accepted.reply
        else {
            panic!("accepted transaction");
        };
        assert_eq!(usize::try_from(bytes).unwrap(), canonical_transaction.len());
        let duplicate = exchange(
            &mut server,
            &mut dispatcher,
            4,
            &OperatorCommand::SubmitTransaction(canonical_transaction),
        );
        assert_eq!(
            duplicate.reply,
            OperatorReply::Transaction(MempoolAdmission::AlreadyPresent { transaction_id })
        );
        let malformed = exchange(
            &mut server,
            &mut dispatcher,
            5,
            &OperatorCommand::SubmitTransaction(vec![0]),
        );
        assert_eq!(
            malformed.reply,
            OperatorReply::Rejected(OperatorRejectCode::InvalidTransaction)
        );
    }

    #[test]
    fn unix_server_executes_commands_rejects_replay_and_cleans_up() {
        let path = socket_path("lifecycle");
        let policy = UnixOperatorPolicy {
            read_timeout_millis: 1_000,
            write_timeout_millis: 1_000,
        };
        let mut server = UnixMiningControlServer::bind(&path, key(), policy).unwrap();
        assert_eq!(
            fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut dispatcher = dispatcher();

        let inspected = exchange(
            &mut server,
            &mut dispatcher,
            1,
            &OperatorCommand::Mining(MiningControlCommand::Inspect),
        );
        assert!(matches!(
            inspected.reply,
            OperatorReply::Inspected(MiningControlStatus { job: None, .. })
        ));
        let replay = exchange(
            &mut server,
            &mut dispatcher,
            1,
            &OperatorCommand::Mining(MiningControlCommand::Cancel),
        );
        assert_eq!(
            replay.reply,
            OperatorReply::Rejected(OperatorRejectCode::Replay)
        );
        assert_eq!(server.last_sequence(), Some(1));

        let start = start_command(&dispatcher);
        let started = exchange(&mut server, &mut dispatcher, 2, &start);
        assert!(matches!(started.reply, OperatorReply::Started(_)));
        assert!(dispatcher.mining().snapshot().is_some());
        let duplicate = exchange(&mut server, &mut dispatcher, 3, &start);
        assert_eq!(
            duplicate.reply,
            OperatorReply::Rejected(OperatorRejectCode::JobAlreadyActive)
        );
        let cancelled = exchange(
            &mut server,
            &mut dispatcher,
            4,
            &OperatorCommand::Mining(MiningControlCommand::Cancel),
        );
        assert!(matches!(cancelled.reply, OperatorReply::Cancelled(Some(_))));
        assert!(dispatcher.mining().snapshot().is_none());

        drop(server);
        assert!(!path.exists());
    }

    #[test]
    fn authentication_failure_never_executes_and_cleanup_preserves_replacement() {
        let path = socket_path("auth-failure");
        let mut server = UnixMiningControlServer::bind(
            &path,
            key(),
            UnixOperatorPolicy {
                read_timeout_millis: 1_000,
                write_timeout_millis: 1_000,
            },
        )
        .unwrap();
        let mut dispatcher = dispatcher();
        let mut request = encode_operator_request(1, &start_command(&dispatcher), &key()).unwrap();
        let last = request.len() - 1;
        request[last] ^= 1;
        let mut client = UnixStream::connect(server.path()).unwrap();
        write_framed_operator_message(&mut client, &request).unwrap();
        assert!(matches!(
            server.serve_once(&mut dispatcher),
            Err(UnixOperatorError::Frame(
                OperatorFrameError::AuthenticationFailed
            ))
        ));
        assert_eq!(server.last_sequence(), None);
        assert!(dispatcher.mining().snapshot().is_none());

        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement").unwrap();
        drop(server);
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        fs::remove_file(path).unwrap();
    }
}
