//! Pure peer-session and header-synchronization policy state machines.
//!
//! Time values are caller-supplied monotonic ticks. This module performs no I/O,
//! reads no wall clock, and treats decoded consensus objects as untrusted data.

use std::collections::BTreeMap;

use out_codec::BlockHeader;
use out_primitives::BlockId;

use crate::{
    select_protocol_version, Frame, Hello, HelloIdentityError, InventoryEntry, Message, P2pNetwork,
    MAX_INV_ENTRIES, MAX_LOCATOR_ENTRIES, PROTOCOL_VERSION_V0,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRole {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionPolicy {
    pub handshake_timeout_ticks: u64,
    pub response_timeout_ticks: u64,
    pub maximum_outstanding_requests: u16,
    pub disconnect_score: u32,
    pub protocol_violation_score: u32,
    pub unexpected_response_score: u32,
    pub timeout_score: u32,
}

impl SessionPolicy {
    pub fn validate(self) -> Result<Self, SessionError> {
        if self.handshake_timeout_ticks == 0 {
            return Err(SessionError::InvalidPolicy("handshake_timeout_ticks"));
        }
        if self.response_timeout_ticks == 0 {
            return Err(SessionError::InvalidPolicy("response_timeout_ticks"));
        }
        if self.maximum_outstanding_requests == 0 {
            return Err(SessionError::InvalidPolicy("maximum_outstanding_requests"));
        }
        if self.disconnect_score == 0 {
            return Err(SessionError::InvalidPolicy("disconnect_score"));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    AwaitingHello,
    AwaitingHelloAck,
    Established,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
    Ping,
    Headers,
    Object,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViolationKind {
    HandshakeAfterEstablished,
    ZeroRequestId,
    UnexpectedRequestId,
    UnexpectedResponse,
    ResponseKindMismatch,
    PongTokenMismatch,
    InvalidHeaderBatch,
    InvalidTransaction,
    RequestTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectReason {
    HandshakeTimeout,
    HandshakeOrder,
    Identity(HelloIdentityError),
    NoProtocolOverlap,
    NoConsensusOverlap,
    ScoreThreshold,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionAction {
    Send {
        request_id: u64,
        message: Message,
    },
    Established {
        peer: Hello,
        protocol_version: u16,
        consensus_version: u16,
    },
    Deliver {
        request_id: u64,
        message: Message,
    },
    HeadersResponse {
        request_id: u64,
        headers: Vec<BlockHeader>,
    },
    RequestRejected {
        request_id: u64,
        rejected_type: u16,
        code: u16,
        detail: Vec<u8>,
    },
    RequestTimedOut {
        request_id: u64,
        kind: RequestKind,
    },
    IgnoredExtension {
        message_type: u16,
    },
    Misbehavior {
        violation: ViolationKind,
        added_score: u32,
        total_score: u32,
    },
    Disconnect {
        reason: DisconnectReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    InvalidPolicy(&'static str),
    InvalidLocalHello(&'static str),
    ClockOverflow,
    SessionClosed,
    NotEstablished,
    OutstandingRequestLimit,
    RequestIdExhausted,
    EmptyLocator,
    LocatorTooLarge,
    EmptyInventory,
    InventoryTooLarge,
    DuplicateInventory,
    InvalidResponseType,
    ZeroRequestId,
    DuplicateRequestId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestExpectation {
    Pong(u64),
    Headers,
    Object,
}

impl RequestExpectation {
    const fn kind(self) -> RequestKind {
        match self {
            Self::Pong(_) => RequestKind::Ping,
            Self::Headers => RequestKind::Headers,
            Self::Object => RequestKind::Object,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutstandingRequest {
    expectation: RequestExpectation,
    deadline: u64,
}

#[derive(Clone, Debug)]
pub struct PeerSession {
    network: P2pNetwork,
    local_hello: Hello,
    policy: SessionPolicy,
    phase: SessionPhase,
    handshake_deadline: u64,
    negotiated_protocol_version: Option<u16>,
    negotiated_consensus_version: Option<u16>,
    peer_hello: Option<Hello>,
    next_request_id: u64,
    outstanding: BTreeMap<u64, OutstandingRequest>,
    misbehavior_score: u32,
}

impl PeerSession {
    pub fn new(
        role: SessionRole,
        network: P2pNetwork,
        local_hello: Hello,
        now: u64,
        policy: SessionPolicy,
    ) -> Result<(Self, Vec<SessionAction>), SessionError> {
        let policy = policy.validate()?;
        validate_local_hello(&local_hello)?;
        let handshake_deadline = now
            .checked_add(policy.handshake_timeout_ticks)
            .ok_or(SessionError::ClockOverflow)?;
        let phase = match role {
            SessionRole::Inbound => SessionPhase::AwaitingHello,
            SessionRole::Outbound => SessionPhase::AwaitingHelloAck,
        };
        let initial_actions = match role {
            SessionRole::Inbound => Vec::new(),
            SessionRole::Outbound => vec![SessionAction::Send {
                request_id: 0,
                message: Message::Hello(local_hello.clone()),
            }],
        };
        Ok((
            Self {
                network,
                local_hello,
                policy,
                phase,
                handshake_deadline,
                negotiated_protocol_version: None,
                negotiated_consensus_version: None,
                peer_hello: None,
                next_request_id: 1,
                outstanding: BTreeMap::new(),
                misbehavior_score: 0,
            },
            initial_actions,
        ))
    }

    pub const fn network(&self) -> P2pNetwork {
        self.network
    }

    pub const fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub const fn misbehavior_score(&self) -> u32 {
        self.misbehavior_score
    }

    pub const fn negotiated_protocol_version(&self) -> Option<u16> {
        self.negotiated_protocol_version
    }

    pub const fn negotiated_consensus_version(&self) -> Option<u16> {
        self.negotiated_consensus_version
    }

    pub fn peer_hello(&self) -> Option<&Hello> {
        self.peer_hello.as_ref()
    }

    pub fn outstanding_request_count(&self) -> usize {
        self.outstanding.len()
    }

    pub fn handle_inbound(
        &mut self,
        now: u64,
        frame: Frame,
    ) -> Result<Vec<SessionAction>, SessionError> {
        if self.phase == SessionPhase::Closed {
            return Err(SessionError::SessionClosed);
        }
        if self.phase != SessionPhase::Established && now >= self.handshake_deadline {
            self.phase = SessionPhase::Closed;
            return Ok(vec![SessionAction::Disconnect {
                reason: DisconnectReason::HandshakeTimeout,
            }]);
        }
        match self.phase {
            SessionPhase::AwaitingHello => self.handle_hello(frame),
            SessionPhase::AwaitingHelloAck => self.handle_hello_ack(frame),
            SessionPhase::Established => self.handle_established(frame),
            SessionPhase::Closed => Err(SessionError::SessionClosed),
        }
    }

    pub fn begin_ping(&mut self, now: u64, token: u64) -> Result<SessionAction, SessionError> {
        let request_id = self.begin_request(now, RequestExpectation::Pong(token))?;
        Ok(SessionAction::Send {
            request_id,
            message: Message::Ping(token),
        })
    }

    pub fn begin_headers_request(
        &mut self,
        now: u64,
        locator: Vec<BlockId>,
        stop_id: BlockId,
    ) -> Result<SessionAction, SessionError> {
        if locator.is_empty() {
            return Err(SessionError::EmptyLocator);
        }
        if locator.len() > usize::from(MAX_LOCATOR_ENTRIES) {
            return Err(SessionError::LocatorTooLarge);
        }
        let request_id = self.begin_request(now, RequestExpectation::Headers)?;
        Ok(SessionAction::Send {
            request_id,
            message: Message::GetHeaders { locator, stop_id },
        })
    }

    /// Starts one exactly correlated object request. P2P v0 has no terminal
    /// marker for multi-object retrieval, so node policy intentionally emits
    /// one object per request ID.
    pub fn begin_object_request(
        &mut self,
        now: u64,
        request_id: u64,
        object: InventoryEntry,
    ) -> Result<SessionAction, SessionError> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::NotEstablished);
        }
        if request_id == 0 {
            return Err(SessionError::ZeroRequestId);
        }
        if self.outstanding.contains_key(&request_id) {
            return Err(SessionError::DuplicateRequestId);
        }
        if self.outstanding.len() >= usize::from(self.policy.maximum_outstanding_requests) {
            return Err(SessionError::OutstandingRequestLimit);
        }
        let deadline = now
            .checked_add(self.policy.response_timeout_ticks)
            .ok_or(SessionError::ClockOverflow)?;
        self.outstanding.insert(
            request_id,
            OutstandingRequest {
                expectation: RequestExpectation::Object,
                deadline,
            },
        );
        Ok(SessionAction::Send {
            request_id,
            message: Message::GetObjects(vec![object]),
        })
    }

    /// Creates one bounded, unsolicited inventory notification. Notifications
    /// use request ID zero and never allocate outstanding-request state.
    pub fn announce_inventory(
        &self,
        entries: Vec<InventoryEntry>,
    ) -> Result<SessionAction, SessionError> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::NotEstablished);
        }
        if entries.is_empty() {
            return Err(SessionError::EmptyInventory);
        }
        if entries.len() > usize::from(MAX_INV_ENTRIES) {
            return Err(SessionError::InventoryTooLarge);
        }
        let mut unique = std::collections::BTreeSet::new();
        if entries.iter().any(|entry| !unique.insert(*entry)) {
            return Err(SessionError::DuplicateInventory);
        }
        Ok(SessionAction::Send {
            request_id: 0,
            message: Message::Inventory(entries),
        })
    }

    pub fn make_response(
        &self,
        request_id: u64,
        message: Message,
    ) -> Result<SessionAction, SessionError> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::NotEstablished);
        }
        if request_id == 0 {
            return Err(SessionError::InvalidResponseType);
        }
        if !matches!(
            message,
            Message::Pong(_)
                | Message::Transaction(_)
                | Message::Block(_)
                | Message::Headers(_)
                | Message::Reject { .. }
        ) {
            return Err(SessionError::InvalidResponseType);
        }
        Ok(SessionAction::Send {
            request_id,
            message,
        })
    }

    pub fn poll_timeouts(&mut self, now: u64) -> Result<Vec<SessionAction>, SessionError> {
        if self.phase == SessionPhase::Closed {
            return Err(SessionError::SessionClosed);
        }
        if self.phase != SessionPhase::Established {
            if now >= self.handshake_deadline {
                self.phase = SessionPhase::Closed;
                return Ok(vec![SessionAction::Disconnect {
                    reason: DisconnectReason::HandshakeTimeout,
                }]);
            }
            return Ok(Vec::new());
        }

        let expired: Vec<(u64, RequestKind)> = self
            .outstanding
            .iter()
            .filter(|(_, request)| now >= request.deadline)
            .map(|(request_id, request)| (*request_id, request.expectation.kind()))
            .collect();
        let mut actions = Vec::with_capacity(expired.len().saturating_mul(2));
        for (request_id, kind) in expired {
            self.outstanding.remove(&request_id);
            actions.push(SessionAction::RequestTimedOut { request_id, kind });
            self.add_score(
                ViolationKind::RequestTimeout,
                self.policy.timeout_score,
                &mut actions,
            );
            if self.phase == SessionPhase::Closed {
                break;
            }
        }
        Ok(actions)
    }

    pub fn report_invalid_header_batch(&mut self) -> Result<Vec<SessionAction>, SessionError> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::NotEstablished);
        }
        let mut actions = Vec::new();
        self.add_score(
            ViolationKind::InvalidHeaderBatch,
            self.policy.protocol_violation_score,
            &mut actions,
        );
        Ok(actions)
    }

    pub fn report_invalid_transaction(&mut self) -> Result<Vec<SessionAction>, SessionError> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::NotEstablished);
        }
        let mut actions = Vec::new();
        self.add_score(
            ViolationKind::InvalidTransaction,
            self.policy.protocol_violation_score,
            &mut actions,
        );
        Ok(actions)
    }

    fn handle_hello(&mut self, frame: Frame) -> Result<Vec<SessionAction>, SessionError> {
        if frame.header.request_id != 0 {
            return Ok(self.fatal_handshake(DisconnectReason::HandshakeOrder));
        }
        let Message::Hello(peer) = frame.message else {
            return Ok(self.fatal_handshake(DisconnectReason::HandshakeOrder));
        };
        let (protocol_version, consensus_version) = match self.negotiate(&peer) {
            Ok(selected) => selected,
            Err(reason) => return Ok(self.fatal_handshake(reason)),
        };
        self.phase = SessionPhase::Established;
        self.negotiated_protocol_version = Some(protocol_version);
        self.negotiated_consensus_version = Some(consensus_version);
        self.peer_hello = Some(peer.clone());
        Ok(vec![
            SessionAction::Send {
                request_id: 0,
                message: Message::HelloAck(self.local_hello.clone()),
            },
            SessionAction::Established {
                peer,
                protocol_version,
                consensus_version,
            },
        ])
    }

    fn handle_hello_ack(&mut self, frame: Frame) -> Result<Vec<SessionAction>, SessionError> {
        if frame.header.request_id != 0 {
            return Ok(self.fatal_handshake(DisconnectReason::HandshakeOrder));
        }
        let Message::HelloAck(peer) = frame.message else {
            return Ok(self.fatal_handshake(DisconnectReason::HandshakeOrder));
        };
        let (protocol_version, consensus_version) = match self.negotiate(&peer) {
            Ok(selected) => selected,
            Err(reason) => return Ok(self.fatal_handshake(reason)),
        };
        self.phase = SessionPhase::Established;
        self.negotiated_protocol_version = Some(protocol_version);
        self.negotiated_consensus_version = Some(consensus_version);
        self.peer_hello = Some(peer.clone());
        Ok(vec![SessionAction::Established {
            peer,
            protocol_version,
            consensus_version,
        }])
    }

    fn handle_established(&mut self, frame: Frame) -> Result<Vec<SessionAction>, SessionError> {
        let request_id = frame.header.request_id;
        let mut actions = Vec::new();
        match frame.message {
            Message::Hello(_) | Message::HelloAck(_) => self.add_score(
                ViolationKind::HandshakeAfterEstablished,
                self.policy.protocol_violation_score,
                &mut actions,
            ),
            Message::Ping(token) => {
                if request_id == 0 {
                    self.add_score(
                        ViolationKind::ZeroRequestId,
                        self.policy.protocol_violation_score,
                        &mut actions,
                    );
                } else {
                    actions.push(SessionAction::Send {
                        request_id,
                        message: Message::Pong(token),
                    });
                }
            }
            Message::Pong(token) => self.handle_pong(request_id, token, &mut actions),
            Message::Headers(headers) => self.handle_headers(request_id, headers, &mut actions),
            Message::Reject {
                rejected_type,
                code,
                detail,
            } => {
                if request_id == 0 || self.outstanding.remove(&request_id).is_none() {
                    self.add_score(
                        ViolationKind::UnexpectedResponse,
                        self.policy.unexpected_response_score,
                        &mut actions,
                    );
                } else {
                    actions.push(SessionAction::RequestRejected {
                        request_id,
                        rejected_type,
                        code,
                        detail,
                    });
                }
            }
            Message::GetHeaders { .. } | Message::GetObjects(_) => {
                if request_id == 0 {
                    self.add_score(
                        ViolationKind::ZeroRequestId,
                        self.policy.protocol_violation_score,
                        &mut actions,
                    );
                } else {
                    actions.push(SessionAction::Deliver {
                        request_id,
                        message: frame.message,
                    });
                }
            }
            Message::Inventory(_) => {
                if request_id != 0 {
                    self.add_score(
                        ViolationKind::UnexpectedRequestId,
                        self.policy.protocol_violation_score,
                        &mut actions,
                    );
                } else {
                    actions.push(SessionAction::Deliver {
                        request_id,
                        message: frame.message,
                    });
                }
            }
            Message::Transaction(_) | Message::Block(_) => {
                let deliver = match self.outstanding.get(&request_id).copied() {
                    Some(OutstandingRequest {
                        expectation: RequestExpectation::Object,
                        ..
                    }) => {
                        self.outstanding.remove(&request_id);
                        true
                    }
                    Some(_) => {
                        self.add_score(
                            ViolationKind::ResponseKindMismatch,
                            self.policy.unexpected_response_score,
                            &mut actions,
                        );
                        false
                    }
                    None => true,
                };
                if deliver {
                    actions.push(SessionAction::Deliver {
                        request_id,
                        message: frame.message,
                    });
                }
            }
            Message::IgnorableExtension { message_type, .. } => {
                actions.push(SessionAction::IgnoredExtension { message_type });
            }
        }
        Ok(actions)
    }

    fn handle_pong(&mut self, request_id: u64, token: u64, actions: &mut Vec<SessionAction>) {
        let Some(request) = self.outstanding.get(&request_id).copied() else {
            self.add_score(
                ViolationKind::UnexpectedResponse,
                self.policy.unexpected_response_score,
                actions,
            );
            return;
        };
        match request.expectation {
            RequestExpectation::Pong(expected) if expected == token => {
                self.outstanding.remove(&request_id);
            }
            RequestExpectation::Pong(_) => self.add_score(
                ViolationKind::PongTokenMismatch,
                self.policy.unexpected_response_score,
                actions,
            ),
            RequestExpectation::Headers => self.add_score(
                ViolationKind::ResponseKindMismatch,
                self.policy.unexpected_response_score,
                actions,
            ),
            RequestExpectation::Object => self.add_score(
                ViolationKind::ResponseKindMismatch,
                self.policy.unexpected_response_score,
                actions,
            ),
        }
    }

    fn handle_headers(
        &mut self,
        request_id: u64,
        headers: Vec<BlockHeader>,
        actions: &mut Vec<SessionAction>,
    ) {
        let Some(request) = self.outstanding.get(&request_id).copied() else {
            self.add_score(
                ViolationKind::UnexpectedResponse,
                self.policy.unexpected_response_score,
                actions,
            );
            return;
        };
        if request.expectation != RequestExpectation::Headers {
            self.add_score(
                ViolationKind::ResponseKindMismatch,
                self.policy.unexpected_response_score,
                actions,
            );
            return;
        }
        self.outstanding.remove(&request_id);
        actions.push(SessionAction::HeadersResponse {
            request_id,
            headers,
        });
    }

    fn begin_request(
        &mut self,
        now: u64,
        expectation: RequestExpectation,
    ) -> Result<u64, SessionError> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::NotEstablished);
        }
        if self.outstanding.len() >= usize::from(self.policy.maximum_outstanding_requests) {
            return Err(SessionError::OutstandingRequestLimit);
        }
        let deadline = now
            .checked_add(self.policy.response_timeout_ticks)
            .ok_or(SessionError::ClockOverflow)?;
        let request_id = self.next_request_id;
        if request_id == 0 || self.outstanding.contains_key(&request_id) {
            return Err(SessionError::RequestIdExhausted);
        }
        self.next_request_id = request_id
            .checked_add(1)
            .ok_or(SessionError::RequestIdExhausted)?;
        self.outstanding.insert(
            request_id,
            OutstandingRequest {
                expectation,
                deadline,
            },
        );
        Ok(request_id)
    }

    fn negotiate(&self, peer: &Hello) -> Result<(u16, u16), DisconnectReason> {
        peer.require_identity(
            self.local_hello.chain_id,
            self.local_hello.network_id,
            self.local_hello.genesis_commitment,
        )
        .map_err(DisconnectReason::Identity)?;
        let protocol_version = select_protocol_version(
            self.local_hello.min_protocol_version,
            self.local_hello.max_protocol_version,
            peer.min_protocol_version,
            peer.max_protocol_version,
        )
        .ok_or(DisconnectReason::NoProtocolOverlap)?;
        let consensus_version = select_protocol_version(
            self.local_hello.min_consensus_version,
            self.local_hello.max_consensus_version,
            peer.min_consensus_version,
            peer.max_consensus_version,
        )
        .ok_or(DisconnectReason::NoConsensusOverlap)?;
        Ok((protocol_version, consensus_version))
    }

    fn fatal_handshake(&mut self, reason: DisconnectReason) -> Vec<SessionAction> {
        self.phase = SessionPhase::Closed;
        vec![SessionAction::Disconnect { reason }]
    }

    fn add_score(
        &mut self,
        violation: ViolationKind,
        points: u32,
        actions: &mut Vec<SessionAction>,
    ) {
        if points == 0 {
            return;
        }
        self.misbehavior_score = self.misbehavior_score.saturating_add(points);
        actions.push(SessionAction::Misbehavior {
            violation,
            added_score: points,
            total_score: self.misbehavior_score,
        });
        if self.misbehavior_score >= self.policy.disconnect_score {
            self.phase = SessionPhase::Closed;
            self.outstanding.clear();
            actions.push(SessionAction::Disconnect {
                reason: DisconnectReason::ScoreThreshold,
            });
        }
    }
}

fn validate_local_hello(hello: &Hello) -> Result<(), SessionError> {
    if hello.min_protocol_version != PROTOCOL_VERSION_V0
        || hello.max_protocol_version != PROTOCOL_VERSION_V0
    {
        return Err(SessionError::InvalidLocalHello("protocol_version_range"));
    }
    if hello.min_consensus_version != 0 || hello.max_consensus_version != 0 {
        return Err(SessionError::InvalidLocalHello("consensus_version_range"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderSyncPhase {
    Idle,
    Awaiting { request_id: u64 },
    Validating { request_id: u64, header_count: u16 },
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderBatch {
    Complete,
    Validate(Vec<BlockHeader>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderSyncError {
    WrongPhase,
    WrongRequestId,
    UnexpectedAction,
    HeaderCountWidth,
    EmptyLocator,
    LocatorTooLarge,
    Session(SessionError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderSync {
    phase: HeaderSyncPhase,
}

impl HeaderSync {
    pub const fn new() -> Self {
        Self {
            phase: HeaderSyncPhase::Idle,
        }
    }

    pub const fn phase(self) -> HeaderSyncPhase {
        self.phase
    }

    pub fn begin(
        &mut self,
        session: &mut PeerSession,
        now: u64,
        locator: Vec<BlockId>,
        stop_id: BlockId,
    ) -> Result<SessionAction, HeaderSyncError> {
        if self.phase != HeaderSyncPhase::Idle {
            return Err(HeaderSyncError::WrongPhase);
        }
        if locator.is_empty() {
            return Err(HeaderSyncError::EmptyLocator);
        }
        if locator.len() > usize::from(MAX_LOCATOR_ENTRIES) {
            return Err(HeaderSyncError::LocatorTooLarge);
        }
        let action = session
            .begin_headers_request(now, locator, stop_id)
            .map_err(HeaderSyncError::Session)?;
        let SessionAction::Send { request_id, .. } = action else {
            return Err(HeaderSyncError::WrongPhase);
        };
        self.phase = HeaderSyncPhase::Awaiting { request_id };
        Ok(action)
    }

    pub fn accept_response(
        &mut self,
        action: SessionAction,
    ) -> Result<HeaderBatch, HeaderSyncError> {
        let SessionAction::HeadersResponse {
            request_id,
            headers,
        } = action
        else {
            return Err(HeaderSyncError::UnexpectedAction);
        };
        let HeaderSyncPhase::Awaiting {
            request_id: expected,
        } = self.phase
        else {
            return Err(HeaderSyncError::WrongPhase);
        };
        if request_id != expected {
            return Err(HeaderSyncError::WrongRequestId);
        }
        if headers.is_empty() {
            self.phase = HeaderSyncPhase::Complete;
            return Ok(HeaderBatch::Complete);
        }
        let header_count =
            u16::try_from(headers.len()).map_err(|_| HeaderSyncError::HeaderCountWidth)?;
        self.phase = HeaderSyncPhase::Validating {
            request_id,
            header_count,
        };
        Ok(HeaderBatch::Validate(headers))
    }

    pub fn validation_accepted(&mut self, reached_stop: bool) -> Result<(), HeaderSyncError> {
        if !matches!(self.phase, HeaderSyncPhase::Validating { .. }) {
            return Err(HeaderSyncError::WrongPhase);
        }
        self.phase = if reached_stop {
            HeaderSyncPhase::Complete
        } else {
            HeaderSyncPhase::Idle
        };
        Ok(())
    }

    pub fn validation_failed(&mut self) -> Result<(), HeaderSyncError> {
        if !matches!(self.phase, HeaderSyncPhase::Validating { .. }) {
            return Err(HeaderSyncError::WrongPhase);
        }
        self.phase = HeaderSyncPhase::Idle;
        Ok(())
    }

    pub fn observe_terminal_action(&mut self, action: &SessionAction) -> bool {
        let HeaderSyncPhase::Awaiting { request_id } = self.phase else {
            return false;
        };
        let matches = match action {
            SessionAction::RequestTimedOut {
                request_id: actual,
                kind: RequestKind::Headers,
            }
            | SessionAction::RequestRejected {
                request_id: actual, ..
            } => *actual == request_id,
            _ => false,
        };
        if matches {
            self.phase = HeaderSyncPhase::Idle;
        }
        matches
    }
}

impl Default for HeaderSync {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use out_codec::BlockHeader;
    use out_primitives::{
        ChainId, GenesisCommitment, Hash32, NetworkId, StateRoot, TransactionRoot, U256Be,
    };

    use super::*;
    use crate::{FrameHeader, TYPE_HEADERS, TYPE_HELLO, TYPE_HELLO_ACK, TYPE_PONG};

    fn policy() -> SessionPolicy {
        SessionPolicy {
            handshake_timeout_ticks: 10,
            response_timeout_ticks: 20,
            maximum_outstanding_requests: 2,
            disconnect_score: 10,
            protocol_violation_score: 5,
            unexpected_response_score: 3,
            timeout_score: 1,
        }
    }

    fn hello() -> Hello {
        Hello {
            min_protocol_version: 0,
            max_protocol_version: 0,
            min_consensus_version: 0,
            max_consensus_version: 0,
            chain_id: ChainId::new([1; 32]),
            network_id: NetworkId::new(2),
            genesis_commitment: GenesisCommitment::new([2; 32]),
            best_height: 7,
            best_block_id: BlockId::new([3; 32]),
        }
    }

    fn frame(request_id: u64, message_type: u16, message: Message) -> Frame {
        Frame {
            header: FrameHeader {
                network_magic: P2pNetwork::Testnet.magic(),
                protocol_version: 0,
                message_type,
                flags: 0,
                request_id,
                payload_len: 0,
                payload_checksum: Hash32::new([0; 32]),
            },
            message,
        }
    }

    fn header(height: u64) -> BlockHeader {
        BlockHeader {
            consensus_version: 0,
            chain_id: hello().chain_id,
            network_id: hello().network_id,
            genesis_commitment: hello().genesis_commitment,
            height,
            parent_block_id: BlockId::new([4; 32]),
            timestamp: 1,
            target: U256Be::new([0xff; 32]),
            transaction_root: TransactionRoot::new([5; 32]),
            state_root: StateRoot::new([6; 32]),
            nonce: 0,
        }
    }

    fn established_session() -> PeerSession {
        let (mut session, initial) = PeerSession::new(
            SessionRole::Outbound,
            P2pNetwork::Testnet,
            hello(),
            0,
            policy(),
        )
        .unwrap();
        assert_eq!(initial.len(), 1);
        let actions = session
            .handle_inbound(1, frame(0, TYPE_HELLO_ACK, Message::HelloAck(hello())))
            .unwrap();
        assert!(matches!(actions[0], SessionAction::Established { .. }));
        session
    }

    #[test]
    fn single_object_request_has_exact_external_id_and_timeout() {
        let mut session = established_session();
        let object = InventoryEntry::Block(BlockId::new([9; 32]));
        let action = session.begin_object_request(5, 99, object).unwrap();
        assert_eq!(
            action,
            SessionAction::Send {
                request_id: 99,
                message: Message::GetObjects(vec![object]),
            }
        );
        assert_eq!(session.outstanding_request_count(), 1);
        assert_eq!(
            session.begin_object_request(5, 99, object),
            Err(SessionError::DuplicateRequestId)
        );
        assert_eq!(
            session.poll_timeouts(25).unwrap(),
            vec![
                SessionAction::RequestTimedOut {
                    request_id: 99,
                    kind: RequestKind::Object,
                },
                SessionAction::Misbehavior {
                    violation: ViolationKind::RequestTimeout,
                    added_score: 1,
                    total_score: 1,
                },
            ]
        );
        assert_eq!(session.outstanding_request_count(), 0);
        assert_eq!(
            session.begin_object_request(26, 0, object),
            Err(SessionError::ZeroRequestId)
        );
    }

    #[test]
    fn inventory_notification_is_zero_id_bounded_and_unique() {
        let session = established_session();
        let first = InventoryEntry::Block(BlockId::new([8; 32]));
        let second = InventoryEntry::Block(BlockId::new([9; 32]));
        assert_eq!(
            session.announce_inventory(vec![first, second]).unwrap(),
            SessionAction::Send {
                request_id: 0,
                message: Message::Inventory(vec![first, second]),
            }
        );
        assert_eq!(
            session.announce_inventory(Vec::new()),
            Err(SessionError::EmptyInventory)
        );
        assert_eq!(
            session.announce_inventory(vec![first, first]),
            Err(SessionError::DuplicateInventory)
        );
        assert_eq!(
            session.announce_inventory(vec![first; usize::from(MAX_INV_ENTRIES) + 1]),
            Err(SessionError::InventoryTooLarge)
        );
    }

    #[test]
    fn outbound_and_inbound_handshakes_are_exactly_ordered() {
        let (outbound, actions) = PeerSession::new(
            SessionRole::Outbound,
            P2pNetwork::Testnet,
            hello(),
            100,
            policy(),
        )
        .unwrap();
        assert_eq!(outbound.phase(), SessionPhase::AwaitingHelloAck);
        assert!(matches!(
            &actions[0],
            SessionAction::Send {
                request_id: 0,
                message: Message::Hello(_)
            }
        ));

        let (mut inbound, actions) = PeerSession::new(
            SessionRole::Inbound,
            P2pNetwork::Testnet,
            hello(),
            100,
            policy(),
        )
        .unwrap();
        assert!(actions.is_empty());
        let actions = inbound
            .handle_inbound(101, frame(0, TYPE_HELLO, Message::Hello(hello())))
            .unwrap();
        assert_eq!(inbound.phase(), SessionPhase::Established);
        assert!(matches!(
            &actions[0],
            SessionAction::Send {
                request_id: 0,
                message: Message::HelloAck(_)
            }
        ));
        assert!(matches!(actions[1], SessionAction::Established { .. }));
    }

    #[test]
    fn handshake_identity_and_order_fail_closed() {
        let (mut session, _) = PeerSession::new(
            SessionRole::Inbound,
            P2pNetwork::Testnet,
            hello(),
            0,
            policy(),
        )
        .unwrap();
        let mut wrong = hello();
        wrong.network_id = NetworkId::new(3);
        let actions = session
            .handle_inbound(1, frame(0, TYPE_HELLO, Message::Hello(wrong)))
            .unwrap();
        assert_eq!(session.phase(), SessionPhase::Closed);
        assert_eq!(
            actions,
            vec![SessionAction::Disconnect {
                reason: DisconnectReason::Identity(HelloIdentityError::NetworkId)
            }]
        );

        let (mut session, _) = PeerSession::new(
            SessionRole::Inbound,
            P2pNetwork::Testnet,
            hello(),
            0,
            policy(),
        )
        .unwrap();
        let actions = session
            .handle_inbound(1, frame(9, TYPE_HELLO, Message::Hello(hello())))
            .unwrap();
        assert_eq!(
            actions[0],
            SessionAction::Disconnect {
                reason: DisconnectReason::HandshakeOrder
            }
        );
    }

    #[test]
    fn handshake_version_ranges_must_overlap_v0() {
        let (mut session, _) = PeerSession::new(
            SessionRole::Inbound,
            P2pNetwork::Testnet,
            hello(),
            0,
            policy(),
        )
        .unwrap();
        let mut peer = hello();
        peer.min_protocol_version = 1;
        peer.max_protocol_version = 1;
        assert_eq!(
            session
                .handle_inbound(1, frame(0, TYPE_HELLO, Message::Hello(peer)))
                .unwrap(),
            vec![SessionAction::Disconnect {
                reason: DisconnectReason::NoProtocolOverlap
            }]
        );

        let (mut session, _) = PeerSession::new(
            SessionRole::Inbound,
            P2pNetwork::Testnet,
            hello(),
            0,
            policy(),
        )
        .unwrap();
        let mut peer = hello();
        peer.min_consensus_version = 1;
        peer.max_consensus_version = 1;
        assert_eq!(
            session
                .handle_inbound(1, frame(0, TYPE_HELLO, Message::Hello(peer)))
                .unwrap(),
            vec![SessionAction::Disconnect {
                reason: DisconnectReason::NoConsensusOverlap
            }]
        );
    }

    #[test]
    fn handshake_timeout_uses_caller_monotonic_ticks() {
        let (mut session, _) = PeerSession::new(
            SessionRole::Inbound,
            P2pNetwork::Testnet,
            hello(),
            50,
            policy(),
        )
        .unwrap();
        assert!(session.poll_timeouts(59).unwrap().is_empty());
        assert_eq!(
            session.poll_timeouts(60).unwrap(),
            vec![SessionAction::Disconnect {
                reason: DisconnectReason::HandshakeTimeout
            }]
        );
    }

    #[test]
    fn ping_is_correlated_by_request_and_token() {
        let mut session = established_session();
        let action = session.begin_ping(10, 77).unwrap();
        let SessionAction::Send { request_id, .. } = action else {
            panic!("expected send");
        };
        assert_eq!(session.outstanding_request_count(), 1);
        assert!(session
            .handle_inbound(11, frame(request_id, TYPE_PONG, Message::Pong(77)))
            .unwrap()
            .is_empty());
        assert_eq!(session.outstanding_request_count(), 0);
    }

    #[test]
    fn wrong_pong_accumulates_bounded_score_without_completing_request() {
        let mut session = established_session();
        let action = session.begin_ping(10, 77).unwrap();
        let SessionAction::Send { request_id, .. } = action else {
            panic!("expected send");
        };
        let actions = session
            .handle_inbound(11, frame(request_id, TYPE_PONG, Message::Pong(78)))
            .unwrap();
        assert_eq!(session.outstanding_request_count(), 1);
        assert_eq!(session.misbehavior_score(), 3);
        assert!(matches!(
            actions[0],
            SessionAction::Misbehavior {
                violation: ViolationKind::PongTokenMismatch,
                ..
            }
        ));
    }

    #[test]
    fn request_capacity_and_exact_deadline_are_enforced() {
        let mut session = established_session();
        session.begin_ping(10, 1).unwrap();
        session.begin_ping(10, 2).unwrap();
        assert_eq!(
            session.begin_ping(10, 3),
            Err(SessionError::OutstandingRequestLimit)
        );
        assert!(session.poll_timeouts(29).unwrap().is_empty());
        let actions = session.poll_timeouts(30).unwrap();
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, SessionAction::RequestTimedOut { .. }))
                .count(),
            2
        );
        assert_eq!(session.outstanding_request_count(), 0);
    }

    #[test]
    fn invalid_locator_does_not_reserve_request_capacity() {
        let mut session = established_session();
        assert_eq!(
            session.begin_headers_request(10, Vec::new(), BlockId::new([0; 32])),
            Err(SessionError::EmptyLocator)
        );
        assert_eq!(session.outstanding_request_count(), 0);
        assert_eq!(
            session.begin_headers_request(
                10,
                vec![BlockId::new([1; 32]); usize::from(MAX_LOCATOR_ENTRIES) + 1],
                BlockId::new([0; 32])
            ),
            Err(SessionError::LocatorTooLarge)
        );
        assert_eq!(session.outstanding_request_count(), 0);
    }

    #[test]
    fn response_builder_rejects_unsolicited_and_request_messages() {
        let session = established_session();
        assert_eq!(
            session.make_response(0, Message::Pong(1)),
            Err(SessionError::InvalidResponseType)
        );
        assert_eq!(
            session.make_response(1, Message::Inventory(Vec::new())),
            Err(SessionError::InvalidResponseType)
        );
        assert!(matches!(
            session.make_response(1, Message::Headers(Vec::new())),
            Ok(SessionAction::Send {
                request_id: 1,
                message: Message::Headers(_)
            })
        ));
    }

    #[test]
    fn score_threshold_closes_and_clears_requests() {
        let mut session = established_session();
        session.begin_ping(10, 1).unwrap();
        let first = session
            .handle_inbound(11, frame(0, TYPE_PONG, Message::Pong(1)))
            .unwrap();
        assert_eq!(session.misbehavior_score(), 3);
        assert_eq!(first.len(), 1);
        let second = session
            .handle_inbound(12, frame(0, TYPE_PONG, Message::Pong(1)))
            .unwrap();
        assert_eq!(second.len(), 1);
        let third = session
            .handle_inbound(13, frame(0, TYPE_PONG, Message::Pong(1)))
            .unwrap();
        assert_eq!(third.len(), 1);
        let fourth = session
            .handle_inbound(14, frame(0, TYPE_PONG, Message::Pong(1)))
            .unwrap();
        assert!(matches!(
            fourth.last(),
            Some(SessionAction::Disconnect {
                reason: DisconnectReason::ScoreThreshold
            })
        ));
        assert_eq!(session.phase(), SessionPhase::Closed);
        assert_eq!(session.outstanding_request_count(), 0);
    }

    #[test]
    fn header_sync_waits_for_correlation_and_consensus_validation() {
        let mut session = established_session();
        let mut sync = HeaderSync::new();
        let action = sync
            .begin(
                &mut session,
                10,
                vec![BlockId::new([9; 32])],
                BlockId::new([0; 32]),
            )
            .unwrap();
        let SessionAction::Send { request_id, .. } = action else {
            panic!("expected send");
        };
        assert_eq!(
            sync.accept_response(SessionAction::HeadersResponse {
                request_id: request_id + 1,
                headers: vec![header(1)]
            }),
            Err(HeaderSyncError::WrongRequestId)
        );

        let actions = session
            .handle_inbound(
                11,
                frame(request_id, TYPE_HEADERS, Message::Headers(vec![header(1)])),
            )
            .unwrap();
        assert!(matches!(
            sync.accept_response(actions.into_iter().next().unwrap())
                .unwrap(),
            HeaderBatch::Validate(_)
        ));
        assert!(matches!(
            sync.phase(),
            HeaderSyncPhase::Validating {
                header_count: 1,
                ..
            }
        ));
        sync.validation_accepted(false).unwrap();
        assert_eq!(sync.phase(), HeaderSyncPhase::Idle);
    }

    #[test]
    fn empty_headers_complete_sync_and_timeout_returns_to_idle() {
        let mut session = established_session();
        let mut sync = HeaderSync::new();
        let action = sync
            .begin(
                &mut session,
                10,
                vec![BlockId::new([9; 32])],
                BlockId::new([0; 32]),
            )
            .unwrap();
        let SessionAction::Send { request_id, .. } = action else {
            panic!("expected send");
        };
        let actions = session
            .handle_inbound(
                11,
                frame(request_id, TYPE_HEADERS, Message::Headers(Vec::new())),
            )
            .unwrap();
        assert_eq!(
            sync.accept_response(actions.into_iter().next().unwrap())
                .unwrap(),
            HeaderBatch::Complete
        );
        assert_eq!(sync.phase(), HeaderSyncPhase::Complete);

        let mut sync = HeaderSync::new();
        let action = sync
            .begin(
                &mut session,
                40,
                vec![BlockId::new([9; 32])],
                BlockId::new([0; 32]),
            )
            .unwrap();
        let SessionAction::Send { request_id, .. } = action else {
            panic!("expected send");
        };
        let timeout = SessionAction::RequestTimedOut {
            request_id,
            kind: RequestKind::Headers,
        };
        assert!(sync.observe_terminal_action(&timeout));
        assert_eq!(sync.phase(), HeaderSyncPhase::Idle);
    }

    #[test]
    fn policy_and_clock_overflow_fail_without_wraparound() {
        let mut invalid = policy();
        invalid.response_timeout_ticks = 0;
        assert_eq!(
            PeerSession::new(
                SessionRole::Inbound,
                P2pNetwork::Testnet,
                hello(),
                0,
                invalid
            )
            .unwrap_err(),
            SessionError::InvalidPolicy("response_timeout_ticks")
        );
        assert_eq!(
            PeerSession::new(
                SessionRole::Inbound,
                P2pNetwork::Testnet,
                hello(),
                u64::MAX,
                policy()
            )
            .unwrap_err(),
            SessionError::ClockOverflow
        );
    }

    #[test]
    fn zero_timeout_weight_emits_only_timeout_action() {
        let mut no_timeout_score = policy();
        no_timeout_score.timeout_score = 0;
        let (mut session, _) = PeerSession::new(
            SessionRole::Outbound,
            P2pNetwork::Testnet,
            hello(),
            0,
            no_timeout_score,
        )
        .unwrap();
        session
            .handle_inbound(1, frame(0, TYPE_HELLO_ACK, Message::HelloAck(hello())))
            .unwrap();
        session.begin_ping(2, 9).unwrap();
        let actions = session.poll_timeouts(22).unwrap();
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            SessionAction::RequestTimedOut {
                kind: RequestKind::Ping,
                ..
            }
        ));
        assert_eq!(session.misbehavior_score(), 0);
    }

    #[test]
    fn invalid_header_report_is_policy_only_and_can_disconnect() {
        let mut session = established_session();
        let first = session.report_invalid_header_batch().unwrap();
        assert_eq!(session.misbehavior_score(), 5);
        assert_eq!(first.len(), 1);
        let second = session.report_invalid_header_batch().unwrap();
        assert_eq!(session.phase(), SessionPhase::Closed);
        assert!(matches!(
            second.last(),
            Some(SessionAction::Disconnect {
                reason: DisconnectReason::ScoreThreshold
            })
        ));
    }

    #[test]
    fn invalid_transaction_report_uses_protocol_policy_and_can_disconnect() {
        let mut session = established_session();
        let first = session.report_invalid_transaction().unwrap();
        assert_eq!(session.misbehavior_score(), 5);
        assert_eq!(
            first,
            vec![SessionAction::Misbehavior {
                violation: ViolationKind::InvalidTransaction,
                added_score: 5,
                total_score: 5,
            }]
        );
        let second = session.report_invalid_transaction().unwrap();
        assert_eq!(session.phase(), SessionPhase::Closed);
        assert!(matches!(
            second.last(),
            Some(SessionAction::Disconnect {
                reason: DisconnectReason::ScoreThreshold
            })
        ));
    }

    #[test]
    fn ignorable_extension_never_reaches_application_or_consensus() {
        let mut session = established_session();
        let actions = session
            .handle_inbound(
                2,
                frame(
                    0,
                    0x8001,
                    Message::IgnorableExtension {
                        message_type: 0x8001,
                        payload: vec![1, 2, 3],
                    },
                ),
            )
            .unwrap();
        assert_eq!(
            actions,
            vec![SessionAction::IgnoredExtension {
                message_type: 0x8001
            }]
        );
    }
}
