//! Socket-free transport-driver contract and deterministic daemon lifecycle harness.
//!
//! The abstractions in this module perform no host I/O. A real transport may
//! implement `TransportDriver` later, but it must preserve the ownership,
//! ordering, and backpressure rules exercised by the bounded memory driver.

use std::collections::VecDeque;

use out_p2p::session::{PeerSession, SessionAction, SessionError};
use out_p2p::{encode_frame, DecodeError, EncodeError, P2pNetwork};
use out_storage::{RecoverableConsensusStorage, RecoveryOutcome};

use crate::peers::{
    BoundedMemoryTransport, MemoryTransportError, MemoryTransportPolicy,
    MemoryTransportPolicyError, PeerId,
};
use crate::runtime::{
    NodeRuntime, RuntimeError, RuntimeOutput, RuntimePeerRemoval, RuntimePhase, RuntimeStep,
};
use crate::SupportedNetwork;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportFrame {
    pub peer_id: PeerId,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportSend<Error> {
    Accepted,
    Backpressured(TransportFrame),
    Failed { frame: TransportFrame, error: Error },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportPeerRemoval {
    pub discarded_inbound_frames: u16,
    pub discarded_inbound_bytes: u64,
    pub discarded_outbound_frames: u16,
    pub discarded_outbound_bytes: u64,
}

/// Narrow, ownership-preserving transport boundary.
///
/// `try_send` MUST return the exact input frame unchanged when it reports
/// `Backpressured` or `Failed`. `receive` MUST return complete frame bytes and
/// MUST bound allocation before buffering an attacker-controlled declared
/// length. None of these methods may define consensus validity.
pub trait TransportDriver {
    type Error;

    fn start(&mut self) -> Result<(), Self::Error>;
    fn receive(&mut self) -> Result<Option<TransportFrame>, Self::Error>;
    fn try_send(&mut self, frame: TransportFrame) -> TransportSend<Self::Error>;
    /// Closes one peer and atomically removes its transport-owned queued
    /// frames. An error MUST leave transport ownership unchanged.
    fn remove_peer(&mut self, peer_id: PeerId) -> Result<TransportPeerRemoval, Self::Error>;
    fn begin_shutdown(&mut self) -> Result<(), Self::Error>;
    fn poll_shutdown(&mut self) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryDriverPolicy {
    pub inbound: MemoryTransportPolicy,
    pub outbound: MemoryTransportPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryDriverPolicyError {
    Inbound(MemoryTransportPolicyError),
    Outbound(MemoryTransportPolicyError),
}

impl MemoryDriverPolicy {
    pub fn validate(self) -> Result<Self, MemoryDriverPolicyError> {
        self.inbound
            .validate()
            .map_err(MemoryDriverPolicyError::Inbound)?;
        self.outbound
            .validate()
            .map_err(MemoryDriverPolicyError::Outbound)?;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryDriverPhase {
    Created,
    Started,
    Draining,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryDriverFault {
    Start,
    Receive,
    Send,
    BeginShutdown,
    PollShutdown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryDriverError {
    Policy(MemoryDriverPolicyError),
    WrongPhase {
        expected: &'static str,
        actual: MemoryDriverPhase,
    },
    Queue(MemoryTransportError),
    Injected(MemoryDriverFault),
}

/// Bounded, deterministic test driver with independent inbound and outbound
/// queues. It opens no sockets and performs no asynchronous work.
pub struct BoundedMemoryDriver {
    inbound: BoundedMemoryTransport,
    outbound: BoundedMemoryTransport,
    phase: MemoryDriverPhase,
    fault_once: Option<MemoryDriverFault>,
}

impl BoundedMemoryDriver {
    pub fn new(policy: MemoryDriverPolicy) -> Result<Self, MemoryDriverError> {
        let policy = policy.validate().map_err(MemoryDriverError::Policy)?;
        let inbound =
            BoundedMemoryTransport::new(policy.inbound).map_err(MemoryDriverError::Queue)?;
        let outbound =
            BoundedMemoryTransport::new(policy.outbound).map_err(MemoryDriverError::Queue)?;
        Ok(Self {
            inbound,
            outbound,
            phase: MemoryDriverPhase::Created,
            fault_once: None,
        })
    }

    pub const fn phase(&self) -> MemoryDriverPhase {
        self.phase
    }

    pub fn inbound_frame_count(&self) -> usize {
        self.inbound.queued_frame_count()
    }

    pub fn outbound_frame_count(&self) -> usize {
        self.outbound.queued_frame_count()
    }

    pub fn inject_fault_once(&mut self, fault: MemoryDriverFault) {
        self.fault_once = Some(fault);
    }

    pub fn inject_inbound(&mut self, frame: TransportFrame) -> Result<(), MemoryDriverError> {
        if self.phase != MemoryDriverPhase::Started {
            return Err(MemoryDriverError::WrongPhase {
                expected: "started",
                actual: self.phase,
            });
        }
        self.inbound
            .send(frame.peer_id, frame.bytes)
            .map_err(MemoryDriverError::Queue)
    }

    pub fn take_outbound(&mut self) -> Result<Option<TransportFrame>, MemoryDriverError> {
        if self.phase == MemoryDriverPhase::Created {
            return Err(MemoryDriverError::WrongPhase {
                expected: "started, draining, or stopped",
                actual: self.phase,
            });
        }
        self.outbound
            .receive()
            .map(|frame| {
                frame.map(|frame| TransportFrame {
                    peer_id: frame.peer_id,
                    bytes: frame.bytes,
                })
            })
            .map_err(MemoryDriverError::Queue)
    }

    fn take_fault(&mut self, expected: MemoryDriverFault) -> bool {
        if self.fault_once == Some(expected) {
            self.fault_once = None;
            true
        } else {
            false
        }
    }
}

impl TransportDriver for BoundedMemoryDriver {
    type Error = MemoryDriverError;

    fn start(&mut self) -> Result<(), Self::Error> {
        if self.phase != MemoryDriverPhase::Created {
            return Err(MemoryDriverError::WrongPhase {
                expected: "created",
                actual: self.phase,
            });
        }
        if self.take_fault(MemoryDriverFault::Start) {
            return Err(MemoryDriverError::Injected(MemoryDriverFault::Start));
        }
        self.phase = MemoryDriverPhase::Started;
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<TransportFrame>, Self::Error> {
        if self.phase != MemoryDriverPhase::Started {
            return Err(MemoryDriverError::WrongPhase {
                expected: "started",
                actual: self.phase,
            });
        }
        if self.take_fault(MemoryDriverFault::Receive) {
            return Err(MemoryDriverError::Injected(MemoryDriverFault::Receive));
        }
        self.inbound
            .receive()
            .map(|frame| {
                frame.map(|frame| TransportFrame {
                    peer_id: frame.peer_id,
                    bytes: frame.bytes,
                })
            })
            .map_err(MemoryDriverError::Queue)
    }

    fn try_send(&mut self, frame: TransportFrame) -> TransportSend<Self::Error> {
        if !matches!(
            self.phase,
            MemoryDriverPhase::Started | MemoryDriverPhase::Draining
        ) {
            return TransportSend::Failed {
                frame,
                error: MemoryDriverError::WrongPhase {
                    expected: "started or draining",
                    actual: self.phase,
                },
            };
        }
        if self.take_fault(MemoryDriverFault::Send) {
            return TransportSend::Failed {
                frame,
                error: MemoryDriverError::Injected(MemoryDriverFault::Send),
            };
        }
        match self.outbound.send(frame.peer_id, frame.bytes.clone()) {
            Ok(()) => TransportSend::Accepted,
            Err(
                MemoryTransportError::FrameCapacity { .. }
                | MemoryTransportError::ByteCapacity { .. },
            ) => TransportSend::Backpressured(frame),
            Err(error) => TransportSend::Failed {
                frame,
                error: MemoryDriverError::Queue(error),
            },
        }
    }

    fn remove_peer(&mut self, peer_id: PeerId) -> Result<TransportPeerRemoval, Self::Error> {
        if self.phase != MemoryDriverPhase::Started {
            return Err(MemoryDriverError::WrongPhase {
                expected: "started",
                actual: self.phase,
            });
        }
        let (inbound, inbound_remaining) = self
            .inbound
            .peer_removal_plan(peer_id)
            .map_err(MemoryDriverError::Queue)?;
        let (outbound, outbound_remaining) = self
            .outbound
            .peer_removal_plan(peer_id)
            .map_err(MemoryDriverError::Queue)?;
        self.inbound.apply_peer_removal(peer_id, inbound_remaining);
        self.outbound
            .apply_peer_removal(peer_id, outbound_remaining);
        Ok(TransportPeerRemoval {
            discarded_inbound_frames: inbound.frames,
            discarded_inbound_bytes: inbound.bytes,
            discarded_outbound_frames: outbound.frames,
            discarded_outbound_bytes: outbound.bytes,
        })
    }

    fn begin_shutdown(&mut self) -> Result<(), Self::Error> {
        if self.phase != MemoryDriverPhase::Started {
            return Err(MemoryDriverError::WrongPhase {
                expected: "started",
                actual: self.phase,
            });
        }
        if self.take_fault(MemoryDriverFault::BeginShutdown) {
            return Err(MemoryDriverError::Injected(
                MemoryDriverFault::BeginShutdown,
            ));
        }
        self.phase = MemoryDriverPhase::Draining;
        Ok(())
    }

    fn poll_shutdown(&mut self) -> Result<bool, Self::Error> {
        if self.phase == MemoryDriverPhase::Stopped {
            return Ok(true);
        }
        if self.phase != MemoryDriverPhase::Draining {
            return Err(MemoryDriverError::WrongPhase {
                expected: "draining",
                actual: self.phase,
            });
        }
        if self.take_fault(MemoryDriverFault::PollShutdown) {
            return Err(MemoryDriverError::Injected(MemoryDriverFault::PollShutdown));
        }
        if self.outbound.queued_frame_count() == 0 {
            self.phase = MemoryDriverPhase::Stopped;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonPolicy {
    pub maximum_transport_receives_per_step: u16,
    pub maximum_transport_sends_per_step: u16,
    pub maximum_runtime_outputs_per_step: u16,
    pub maximum_pending_outbound_frames: u16,
    pub maximum_pending_outbound_bytes: u64,
    pub maximum_local_events: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonPolicyError {
    Zero(&'static str),
    SendsPerStepAbovePending,
}

impl DaemonPolicy {
    pub fn validate(self) -> Result<Self, DaemonPolicyError> {
        let nonzero = [
            (
                u64::from(self.maximum_transport_receives_per_step),
                "maximum_transport_receives_per_step",
            ),
            (
                u64::from(self.maximum_transport_sends_per_step),
                "maximum_transport_sends_per_step",
            ),
            (
                u64::from(self.maximum_runtime_outputs_per_step),
                "maximum_runtime_outputs_per_step",
            ),
            (
                u64::from(self.maximum_pending_outbound_frames),
                "maximum_pending_outbound_frames",
            ),
            (
                self.maximum_pending_outbound_bytes,
                "maximum_pending_outbound_bytes",
            ),
            (u64::from(self.maximum_local_events), "maximum_local_events"),
        ];
        if let Some((_, field)) = nonzero.into_iter().find(|(value, _)| *value == 0) {
            return Err(DaemonPolicyError::Zero(field));
        }
        if self.maximum_transport_sends_per_step > self.maximum_pending_outbound_frames {
            return Err(DaemonPolicyError::SendsPerStepAbovePending);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonPhase {
    Created,
    Recovering,
    Running,
    Draining,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DaemonPeerRemoval {
    pub runtime: RuntimePeerRemoval,
    pub transport: TransportPeerRemoval,
    pub discarded_held_inbound: bool,
    pub discarded_pending_outbound_frames: u16,
    pub discarded_pending_outbound_bytes: u64,
    pub discarded_local_events: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonEvent {
    SessionAction {
        peer_id: PeerId,
        action: Box<SessionAction>,
    },
    FrameRejected {
        peer_id: PeerId,
        error: DecodeError,
    },
    SessionFailed {
        peer_id: PeerId,
        error: SessionError,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonError<RecoveryError, TransportError> {
    Policy(DaemonPolicyError),
    WrongPhase {
        expected: &'static str,
        actual: DaemonPhase,
    },
    Runtime(RuntimeError<RecoveryError>),
    Transport(TransportError),
    Encode(EncodeError),
    OutboundBatchFrames {
        actual: usize,
        maximum: u16,
    },
    OutboundBatchBytes {
        actual: u64,
        maximum: u64,
    },
    LocalEventBatch {
        actual: usize,
        maximum: u16,
    },
    DriverReturnedChangedFrame,
    ResourceAccounting,
    RuntimeOutputDisappeared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonStep {
    pub transport_frames_received: u16,
    pub runtime_frames_admitted: u16,
    pub runtime_step: Option<RuntimeStep>,
    pub runtime_outputs_routed: u16,
    pub transport_frames_sent: u16,
    pub phase: DaemonPhase,
}

struct PreparedOutput {
    outbound: Vec<TransportFrame>,
    outbound_bytes: u64,
    events: Vec<DaemonEvent>,
}

/// Deterministic lifecycle coordinator for `NodeRuntime` and a transport
/// driver. Despite its name, this is not a process daemon and owns no threads,
/// clocks, signals, files, sockets, or services.
pub struct DaemonHarness<S, D>
where
    S: RecoverableConsensusStorage,
    D: TransportDriver,
{
    runtime: NodeRuntime<S>,
    driver: D,
    network: P2pNetwork,
    policy: DaemonPolicy,
    phase: DaemonPhase,
    held_inbound: Option<TransportFrame>,
    pending_outbound: VecDeque<TransportFrame>,
    pending_outbound_bytes: u64,
    events: VecDeque<DaemonEvent>,
}

impl<S, D> DaemonHarness<S, D>
where
    S: RecoverableConsensusStorage,
    D: TransportDriver,
{
    pub fn new(
        runtime: NodeRuntime<S>,
        driver: D,
        policy: DaemonPolicy,
    ) -> Result<Self, DaemonError<S::RecoveryError, D::Error>> {
        let policy = policy.validate().map_err(DaemonError::Policy)?;
        let network = match runtime.node().config().network {
            SupportedNetwork::Testnet => P2pNetwork::Testnet,
            SupportedNetwork::Devnet => P2pNetwork::Devnet,
        };
        Ok(Self {
            runtime,
            driver,
            network,
            policy,
            phase: DaemonPhase::Created,
            held_inbound: None,
            pending_outbound: VecDeque::new(),
            pending_outbound_bytes: 0,
            events: VecDeque::new(),
        })
    }

    pub const fn phase(&self) -> DaemonPhase {
        self.phase
    }

    pub const fn runtime(&self) -> &NodeRuntime<S> {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut NodeRuntime<S> {
        &mut self.runtime
    }

    pub const fn driver(&self) -> &D {
        &self.driver
    }

    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    pub fn pending_outbound_count(&self) -> usize {
        self.pending_outbound.len()
    }

    pub const fn pending_outbound_bytes(&self) -> u64 {
        self.pending_outbound_bytes
    }

    pub const fn has_held_inbound(&self) -> bool {
        self.held_inbound.is_some()
    }

    /// Returns a transport-owned frame that could not be admitted. This makes
    /// quarantine or explicit discard a caller decision; the harness never
    /// silently loses it.
    pub fn take_held_inbound(&mut self) -> Option<TransportFrame> {
        self.held_inbound.take()
    }

    pub fn local_event_count(&self) -> usize {
        self.events.len()
    }

    pub fn pop_event(&mut self) -> Option<DaemonEvent> {
        self.events.pop_front()
    }

    pub fn start(&mut self) -> Result<DaemonPhase, DaemonError<S::RecoveryError, D::Error>> {
        self.require_phase(DaemonPhase::Created, "created")?;
        let runtime_phase = self.runtime.start().map_err(DaemonError::Runtime)?;
        match runtime_phase {
            RuntimePhase::Recovering => {
                self.phase = DaemonPhase::Recovering;
            }
            RuntimePhase::Running => {
                if let Err(error) = self.driver.start() {
                    self.phase = DaemonPhase::Failed;
                    return Err(DaemonError::Transport(error));
                }
                self.phase = DaemonPhase::Running;
            }
            _ => {
                self.phase = DaemonPhase::Failed;
                return Err(DaemonError::Runtime(RuntimeError::WrongPhase {
                    expected: "running or recovering after start",
                    actual: runtime_phase,
                }));
            }
        }
        Ok(self.phase)
    }

    pub fn recover_storage(
        &mut self,
    ) -> Result<RecoveryOutcome, DaemonError<S::RecoveryError, D::Error>> {
        self.require_phase(DaemonPhase::Recovering, "recovering")?;
        let outcome = self
            .runtime
            .recover_storage()
            .map_err(DaemonError::Runtime)?;
        if let Err(error) = self.driver.start() {
            self.phase = DaemonPhase::Failed;
            return Err(DaemonError::Transport(error));
        }
        self.phase = DaemonPhase::Running;
        Ok(outcome)
    }

    pub fn register_peer(
        &mut self,
        peer_id: PeerId,
        session: PeerSession,
        initial_actions: Vec<SessionAction>,
    ) -> Result<(), DaemonError<S::RecoveryError, D::Error>> {
        self.require_phase(DaemonPhase::Running, "running")?;
        self.runtime
            .register_peer(peer_id, session, initial_actions)
            .map_err(DaemonError::Runtime)
    }

    /// Removes one peer across transport, runtime, and daemon-owned queues.
    /// No authoritative storage or consensus state is touched.
    pub fn unregister_peer(
        &mut self,
        peer_id: PeerId,
    ) -> Result<DaemonPeerRemoval, DaemonError<S::RecoveryError, D::Error>> {
        self.require_phase(DaemonPhase::Running, "running")?;
        if !self.runtime.contains_peer(peer_id) {
            return Err(DaemonError::Runtime(RuntimeError::UnknownPeer(peer_id)));
        }
        let mut pending_frames = 0_u16;
        let mut pending_bytes = 0_u64;
        for frame in self
            .pending_outbound
            .iter()
            .filter(|frame| frame.peer_id == peer_id)
        {
            pending_frames = pending_frames
                .checked_add(1)
                .ok_or(DaemonError::ResourceAccounting)?;
            let length =
                u64::try_from(frame.bytes.len()).map_err(|_| DaemonError::ResourceAccounting)?;
            pending_bytes = pending_bytes
                .checked_add(length)
                .ok_or(DaemonError::ResourceAccounting)?;
        }
        let mut local_events = 0_u16;
        for event in &self.events {
            let event_peer = match event {
                DaemonEvent::SessionAction { peer_id, .. }
                | DaemonEvent::FrameRejected { peer_id, .. }
                | DaemonEvent::SessionFailed { peer_id, .. } => *peer_id,
            };
            if event_peer == peer_id {
                local_events = local_events
                    .checked_add(1)
                    .ok_or(DaemonError::ResourceAccounting)?;
            }
        }
        let transport = self
            .driver
            .remove_peer(peer_id)
            .map_err(DaemonError::Transport)?;
        let runtime = self
            .runtime
            .unregister_peer(peer_id)
            .map_err(DaemonError::Runtime)?;
        let discarded_held_inbound = self
            .held_inbound
            .as_ref()
            .is_some_and(|frame| frame.peer_id == peer_id);
        if discarded_held_inbound {
            self.held_inbound = None;
        }
        self.pending_outbound
            .retain(|frame| frame.peer_id != peer_id);
        self.pending_outbound_bytes = self
            .pending_outbound_bytes
            .checked_sub(pending_bytes)
            .ok_or(DaemonError::ResourceAccounting)?;
        self.events.retain(|event| match event {
            DaemonEvent::SessionAction {
                peer_id: event_peer,
                ..
            }
            | DaemonEvent::FrameRejected {
                peer_id: event_peer,
                ..
            }
            | DaemonEvent::SessionFailed {
                peer_id: event_peer,
                ..
            } => *event_peer != peer_id,
        });
        Ok(DaemonPeerRemoval {
            runtime,
            transport,
            discarded_held_inbound,
            discarded_pending_outbound_frames: pending_frames,
            discarded_pending_outbound_bytes: pending_bytes,
            discarded_local_events: local_events,
        })
    }

    pub fn request_shutdown(&mut self) -> Result<(), DaemonError<S::RecoveryError, D::Error>> {
        self.require_phase(DaemonPhase::Running, "running")?;
        self.runtime
            .request_shutdown()
            .map_err(DaemonError::Runtime)?;
        if let Err(error) = self.driver.begin_shutdown() {
            self.phase = DaemonPhase::Failed;
            return Err(DaemonError::Transport(error));
        }
        self.phase = DaemonPhase::Draining;
        Ok(())
    }

    pub fn step(
        &mut self,
        now: u64,
    ) -> Result<DaemonStep, DaemonError<S::RecoveryError, D::Error>> {
        if !matches!(self.phase, DaemonPhase::Running | DaemonPhase::Draining) {
            return Err(DaemonError::WrongPhase {
                expected: "running or draining",
                actual: self.phase,
            });
        }
        let mut transport_frames_sent =
            self.flush_outbound(self.policy.maximum_transport_sends_per_step)?;
        let mut transport_frames_received = 0_u16;
        let mut runtime_frames_admitted = 0_u16;

        if self.phase == DaemonPhase::Running {
            if let Some(frame) = self.held_inbound.take() {
                if self.admit_or_hold(frame)? {
                    runtime_frames_admitted = runtime_frames_admitted.saturating_add(1);
                }
            }
            while self.held_inbound.is_none()
                && transport_frames_received < self.policy.maximum_transport_receives_per_step
            {
                let frame = match self.driver.receive() {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(error) => {
                        self.phase = DaemonPhase::Failed;
                        return Err(DaemonError::Transport(error));
                    }
                };
                transport_frames_received = transport_frames_received.saturating_add(1);
                if self.admit_or_hold(frame)? {
                    runtime_frames_admitted = runtime_frames_admitted.saturating_add(1);
                }
            }
        }

        let runtime_step = if matches!(
            self.runtime.phase(),
            RuntimePhase::Running | RuntimePhase::Draining
        ) {
            Some(self.runtime.step(now).map_err(DaemonError::Runtime)?)
        } else {
            None
        };
        let runtime_outputs_routed = self.route_runtime_outputs()?;
        let send_budget = self
            .policy
            .maximum_transport_sends_per_step
            .saturating_sub(transport_frames_sent);
        transport_frames_sent =
            transport_frames_sent.saturating_add(self.flush_outbound(send_budget)?);

        if self.phase == DaemonPhase::Draining
            && self.runtime.phase() == RuntimePhase::Stopped
            && self.pending_outbound.is_empty()
        {
            match self.driver.poll_shutdown() {
                Ok(true) => self.phase = DaemonPhase::Stopped,
                Ok(false) => {}
                Err(error) => {
                    self.phase = DaemonPhase::Failed;
                    return Err(DaemonError::Transport(error));
                }
            }
        }

        Ok(DaemonStep {
            transport_frames_received,
            runtime_frames_admitted,
            runtime_step,
            runtime_outputs_routed,
            transport_frames_sent,
            phase: self.phase,
        })
    }

    fn admit_or_hold(
        &mut self,
        frame: TransportFrame,
    ) -> Result<bool, DaemonError<S::RecoveryError, D::Error>> {
        match self
            .runtime
            .check_frame_admission(frame.peer_id, frame.bytes.len())
        {
            Ok(()) => {
                let retained = frame.clone();
                if let Err(error) = self.runtime.enqueue_frame(frame.peer_id, frame.bytes) {
                    self.held_inbound = Some(retained);
                    return Err(DaemonError::Runtime(error));
                }
                Ok(true)
            }
            Err(
                RuntimeError::InboundEventCapacity { .. }
                | RuntimeError::InboundByteCapacity { .. },
            ) => {
                self.held_inbound = Some(frame);
                Ok(false)
            }
            Err(error) => {
                self.held_inbound = Some(frame);
                Err(DaemonError::Runtime(error))
            }
        }
    }

    fn route_runtime_outputs(&mut self) -> Result<u16, DaemonError<S::RecoveryError, D::Error>> {
        let mut routed = 0_u16;
        while routed < self.policy.maximum_runtime_outputs_per_step {
            let Some(output) = self.runtime.front_output().cloned() else {
                break;
            };
            let prepared = self.prepare_output(output)?;
            if prepared.outbound.len() > usize::from(self.policy.maximum_pending_outbound_frames) {
                return Err(DaemonError::OutboundBatchFrames {
                    actual: prepared.outbound.len(),
                    maximum: self.policy.maximum_pending_outbound_frames,
                });
            }
            if prepared.outbound_bytes > self.policy.maximum_pending_outbound_bytes {
                return Err(DaemonError::OutboundBatchBytes {
                    actual: prepared.outbound_bytes,
                    maximum: self.policy.maximum_pending_outbound_bytes,
                });
            }
            if prepared.events.len() > usize::from(self.policy.maximum_local_events) {
                return Err(DaemonError::LocalEventBatch {
                    actual: prepared.events.len(),
                    maximum: self.policy.maximum_local_events,
                });
            }
            let outbound_total = self
                .pending_outbound
                .len()
                .checked_add(prepared.outbound.len())
                .ok_or(DaemonError::ResourceAccounting)?;
            let outbound_bytes = self
                .pending_outbound_bytes
                .checked_add(prepared.outbound_bytes)
                .ok_or(DaemonError::ResourceAccounting)?;
            let event_total = self
                .events
                .len()
                .checked_add(prepared.events.len())
                .ok_or(DaemonError::ResourceAccounting)?;
            if outbound_total > usize::from(self.policy.maximum_pending_outbound_frames)
                || outbound_bytes > self.policy.maximum_pending_outbound_bytes
                || event_total > usize::from(self.policy.maximum_local_events)
            {
                break;
            }
            self.runtime
                .pop_output()
                .ok_or(DaemonError::RuntimeOutputDisappeared)?;
            self.pending_outbound.extend(prepared.outbound);
            self.pending_outbound_bytes = outbound_bytes;
            self.events.extend(prepared.events);
            routed = routed.saturating_add(1);
        }
        Ok(routed)
    }

    fn prepare_output(
        &self,
        output: RuntimeOutput,
    ) -> Result<PreparedOutput, DaemonError<S::RecoveryError, D::Error>> {
        let mut outbound = Vec::new();
        let mut outbound_bytes = 0_u64;
        let mut events = Vec::new();
        match output {
            RuntimeOutput::SessionActions { peer_id, actions } => {
                for action in actions {
                    match action {
                        SessionAction::Send {
                            request_id,
                            message,
                        } => {
                            let bytes = encode_frame(self.network, request_id, &message)
                                .map_err(DaemonError::Encode)?;
                            let length = u64::try_from(bytes.len())
                                .map_err(|_| DaemonError::ResourceAccounting)?;
                            outbound_bytes = outbound_bytes
                                .checked_add(length)
                                .ok_or(DaemonError::ResourceAccounting)?;
                            outbound.push(TransportFrame { peer_id, bytes });
                        }
                        action => events.push(DaemonEvent::SessionAction {
                            peer_id,
                            action: Box::new(action),
                        }),
                    }
                }
            }
            RuntimeOutput::FrameRejected { peer_id, error } => {
                events.push(DaemonEvent::FrameRejected { peer_id, error });
            }
            RuntimeOutput::SessionFailed { peer_id, error } => {
                events.push(DaemonEvent::SessionFailed { peer_id, error });
            }
        }
        Ok(PreparedOutput {
            outbound,
            outbound_bytes,
            events,
        })
    }

    fn flush_outbound(
        &mut self,
        maximum: u16,
    ) -> Result<u16, DaemonError<S::RecoveryError, D::Error>> {
        let mut sent = 0_u16;
        while sent < maximum {
            let Some(frame) = self.pending_outbound.pop_front() else {
                break;
            };
            let retained = frame.clone();
            let length =
                u64::try_from(frame.bytes.len()).map_err(|_| DaemonError::ResourceAccounting)?;
            let remaining_bytes = self
                .pending_outbound_bytes
                .checked_sub(length)
                .ok_or(DaemonError::ResourceAccounting)?;
            match self.driver.try_send(frame) {
                TransportSend::Accepted => {
                    self.pending_outbound_bytes = remaining_bytes;
                    sent = sent.saturating_add(1);
                }
                TransportSend::Backpressured(returned) => {
                    if returned != retained {
                        self.pending_outbound.push_front(retained);
                        self.phase = DaemonPhase::Failed;
                        return Err(DaemonError::DriverReturnedChangedFrame);
                    }
                    self.pending_outbound.push_front(returned);
                    break;
                }
                TransportSend::Failed { frame, error } => {
                    if frame != retained {
                        self.pending_outbound.push_front(retained);
                        self.phase = DaemonPhase::Failed;
                        return Err(DaemonError::DriverReturnedChangedFrame);
                    }
                    self.pending_outbound.push_front(frame);
                    self.phase = DaemonPhase::Failed;
                    return Err(DaemonError::Transport(error));
                }
            }
        }
        Ok(sent)
    }

    fn require_phase(
        &self,
        expected: DaemonPhase,
        name: &'static str,
    ) -> Result<(), DaemonError<S::RecoveryError, D::Error>> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(DaemonError::WrongPhase {
                expected: name,
                actual: self.phase,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use out_codec::Block;
    use out_p2p::session::{SessionPhase, SessionPolicy, SessionRole};
    use out_p2p::{decode_frame_exact, Hello, Message, PROTOCOL_VERSION_V0};
    use out_storage::conformance::validated_reward_commit;
    use out_storage::{FaultPoint, InMemoryConsensusStore, RecoveryOutcome};

    use super::*;
    use crate::bootstrap::NodeBootstrap;
    use crate::runtime::{RuntimePolicy, RuntimePolicyError};
    use crate::{Node, SupportedNetwork};

    fn peer(value: u64) -> PeerId {
        PeerId::new(value).expect("peer")
    }

    fn node() -> Node<InMemoryConsensusStore> {
        NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        }
        .create_in_memory()
        .expect("node")
    }

    fn hello() -> Hello {
        let node = node();
        let tip = node.canonical_tip().expect("tip");
        let identity = SupportedNetwork::Devnet.identity();
        Hello {
            min_protocol_version: 0,
            max_protocol_version: 0,
            min_consensus_version: 0,
            max_consensus_version: 0,
            chain_id: identity.chain_id,
            network_id: identity.network_id,
            genesis_commitment: identity.genesis_commitment,
            best_height: tip.height,
            best_block_id: tip.block_id,
        }
    }

    fn session_policy() -> SessionPolicy {
        SessionPolicy {
            handshake_timeout_ticks: 10,
            response_timeout_ticks: 10,
            maximum_outstanding_requests: 4,
            disconnect_score: 100,
            protocol_violation_score: 20,
            unexpected_response_score: 10,
            timeout_score: 5,
        }
    }

    fn session(role: SessionRole) -> (PeerSession, Vec<SessionAction>) {
        PeerSession::new(role, P2pNetwork::Devnet, hello(), 0, session_policy()).expect("session")
    }

    fn runtime_policy() -> crate::runtime::RuntimePolicy {
        crate::runtime::RuntimePolicy {
            maximum_peers: 4,
            maximum_inbound_events: 4,
            maximum_inbound_bytes: 1_000_000,
            maximum_frame_bytes: 100_000,
            maximum_output_events: 4,
            maximum_inbound_events_per_step: 4,
            maximum_peer_polls_per_step: 4,
        }
    }

    fn memory_policy(outbound_frames: u16) -> MemoryDriverPolicy {
        let queue = MemoryTransportPolicy {
            maximum_queued_frames: 8,
            maximum_queued_bytes: 1_000_000,
            maximum_frame_bytes: 100_000,
        };
        MemoryDriverPolicy {
            inbound: queue,
            outbound: MemoryTransportPolicy {
                maximum_queued_frames: outbound_frames,
                ..queue
            },
        }
    }

    fn daemon_policy() -> DaemonPolicy {
        DaemonPolicy {
            maximum_transport_receives_per_step: 4,
            maximum_transport_sends_per_step: 4,
            maximum_runtime_outputs_per_step: 4,
            maximum_pending_outbound_frames: 8,
            maximum_pending_outbound_bytes: 1_000_000,
            maximum_local_events: 8,
        }
    }

    fn created_daemon(
        runtime_policy: RuntimePolicy,
        memory_policy: MemoryDriverPolicy,
    ) -> DaemonHarness<InMemoryConsensusStore, BoundedMemoryDriver> {
        let runtime = NodeRuntime::new(node(), runtime_policy).expect("runtime");
        let driver = BoundedMemoryDriver::new(memory_policy).expect("driver");
        DaemonHarness::new(runtime, driver, daemon_policy()).expect("daemon")
    }

    #[test]
    fn clean_start_routes_initial_hello_as_exact_frame() {
        let mut daemon = created_daemon(runtime_policy(), memory_policy(8));
        assert_eq!(daemon.start(), Ok(DaemonPhase::Running));
        let (session, initial) = session(SessionRole::Outbound);
        daemon.register_peer(peer(1), session, initial).unwrap();
        let step = daemon.step(1).unwrap();
        assert_eq!(step.runtime_outputs_routed, 1);
        assert_eq!(step.transport_frames_sent, 1);
        let frame = daemon.driver_mut().take_outbound().unwrap().unwrap();
        assert_eq!(frame.peer_id, peer(1));
        let decoded =
            decode_frame_exact(&frame.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0).unwrap();
        assert!(matches!(decoded.message, Message::Hello(_)));
        assert_eq!(decoded.header.request_id, 0);
    }

    #[test]
    fn recovery_finishes_before_driver_start_and_peer_admission() {
        let mut damaged = node();
        let genesis = damaged.canonical_tip().unwrap().block_id;
        let commit = validated_reward_commit(damaged.storage(), genesis, b"daemon-recovery");
        let raw = commit.canonical_block_bytes().to_vec();
        let block = Block::decode_non_genesis_exact(&raw).unwrap();
        damaged
            .storage_mut()
            .inject_fault_once(FaultPoint::AfterPrepare)
            .unwrap();
        assert!(damaged.process_block(&raw, block.header.timestamp).is_err());
        let runtime = NodeRuntime::new(damaged, runtime_policy()).unwrap();
        let driver = BoundedMemoryDriver::new(memory_policy(8)).unwrap();
        let mut daemon = DaemonHarness::new(runtime, driver, daemon_policy()).unwrap();
        assert_eq!(daemon.start(), Ok(DaemonPhase::Recovering));
        assert_eq!(daemon.driver().phase(), MemoryDriverPhase::Created);
        let (session, initial) = session(SessionRole::Inbound);
        assert!(matches!(
            daemon.register_peer(peer(1), session, initial),
            Err(DaemonError::WrongPhase {
                actual: DaemonPhase::Recovering,
                ..
            })
        ));
        assert_eq!(
            daemon.recover_storage(),
            Ok(RecoveryOutcome::RolledBackPrepared)
        );
        assert_eq!(daemon.driver().phase(), MemoryDriverPhase::Started);
    }

    #[test]
    fn inbound_handshake_routes_send_and_local_event_separately() {
        let mut daemon = created_daemon(runtime_policy(), memory_policy(8));
        daemon.start().unwrap();
        let (session, initial) = session(SessionRole::Inbound);
        daemon.register_peer(peer(1), session, initial).unwrap();
        let bytes = encode_frame(P2pNetwork::Devnet, 0, &Message::Hello(hello())).unwrap();
        daemon
            .driver_mut()
            .inject_inbound(TransportFrame {
                peer_id: peer(1),
                bytes,
            })
            .unwrap();
        daemon.step(1).unwrap();
        let response = daemon.driver_mut().take_outbound().unwrap().unwrap();
        let decoded =
            decode_frame_exact(&response.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0).unwrap();
        assert!(matches!(decoded.message, Message::HelloAck(_)));
        let Some(DaemonEvent::SessionAction { peer_id, action }) = daemon.pop_event() else {
            panic!("established event");
        };
        assert_eq!(peer_id, peer(1));
        assert!(matches!(*action, SessionAction::Established { .. }));
        assert_eq!(daemon.runtime().peer_count(), 1);
    }

    #[test]
    fn transport_backpressure_retains_exact_fifo_frames() {
        let mut daemon = created_daemon(runtime_policy(), memory_policy(1));
        daemon.start().unwrap();
        for peer_id in [peer(1), peer(2)] {
            let (session, initial) = session(SessionRole::Outbound);
            daemon.register_peer(peer_id, session, initial).unwrap();
        }
        let first = daemon.step(1).unwrap();
        assert_eq!(first.transport_frames_sent, 1);
        assert_eq!(daemon.pending_outbound_count(), 1);
        let first_frame = daemon.driver_mut().take_outbound().unwrap().unwrap();
        assert_eq!(first_frame.peer_id, peer(1));
        let second = daemon.step(1).unwrap();
        assert_eq!(second.transport_frames_sent, 1);
        assert_eq!(daemon.pending_outbound_count(), 0);
        let second_frame = daemon.driver_mut().take_outbound().unwrap().unwrap();
        assert_eq!(second_frame.peer_id, peer(2));
    }

    #[test]
    fn runtime_backpressure_holds_one_transport_frame_without_reordering() {
        let mut bounded = runtime_policy();
        bounded.maximum_inbound_events = 1;
        bounded.maximum_inbound_events_per_step = 1;
        bounded.maximum_output_events = 1;
        let mut daemon = created_daemon(bounded, memory_policy(8));
        daemon.start().unwrap();
        for peer_id in [peer(1), peer(2)] {
            let (session, initial) = session(SessionRole::Inbound);
            daemon.register_peer(peer_id, session, initial).unwrap();
        }
        let hello_bytes = encode_frame(P2pNetwork::Devnet, 0, &Message::Hello(hello())).unwrap();
        for peer_id in [peer(2), peer(1)] {
            daemon
                .driver_mut()
                .inject_inbound(TransportFrame {
                    peer_id,
                    bytes: hello_bytes.clone(),
                })
                .unwrap();
        }
        let first = daemon.step(1).unwrap();
        assert_eq!(first.transport_frames_received, 2);
        assert_eq!(first.runtime_frames_admitted, 1);
        assert!(daemon.has_held_inbound());
        assert!(matches!(
            daemon.pop_event(),
            Some(DaemonEvent::SessionAction { peer_id, .. }) if peer_id == peer(2)
        ));
        let second = daemon.step(1).unwrap();
        assert_eq!(second.runtime_frames_admitted, 1);
        assert!(!daemon.has_held_inbound());
        assert!(matches!(
            daemon.pop_event(),
            Some(DaemonEvent::SessionAction { peer_id, .. }) if peer_id == peer(1)
        ));
    }

    #[test]
    fn transport_failure_is_local_and_retains_unsent_frame() {
        let mut daemon = created_daemon(runtime_policy(), memory_policy(8));
        daemon.start().unwrap();
        let (session, initial) = session(SessionRole::Outbound);
        daemon.register_peer(peer(1), session, initial).unwrap();
        daemon
            .driver_mut()
            .inject_fault_once(MemoryDriverFault::Send);
        assert!(matches!(
            daemon.step(1),
            Err(DaemonError::Transport(MemoryDriverError::Injected(
                MemoryDriverFault::Send
            )))
        ));
        assert_eq!(daemon.phase(), DaemonPhase::Failed);
        assert_eq!(daemon.pending_outbound_count(), 1);
        assert_eq!(daemon.runtime().node().canonical_tip().unwrap().height, 0);
    }

    #[test]
    fn graceful_shutdown_waits_for_accepted_transport_output_to_drain() {
        let mut daemon = created_daemon(runtime_policy(), memory_policy(8));
        daemon.start().unwrap();
        let (session, initial) = session(SessionRole::Outbound);
        daemon.register_peer(peer(1), session, initial).unwrap();
        daemon.step(1).unwrap();
        daemon.request_shutdown().unwrap();
        assert_eq!(daemon.driver().phase(), MemoryDriverPhase::Draining);
        assert_eq!(daemon.step(2).unwrap().phase, DaemonPhase::Draining);
        assert!(daemon.driver_mut().take_outbound().unwrap().is_some());
        assert_eq!(daemon.step(2).unwrap().phase, DaemonPhase::Stopped);
        assert_eq!(daemon.driver().phase(), MemoryDriverPhase::Stopped);
    }

    #[test]
    fn policies_reject_zero_and_incoherent_send_budget() {
        let mut invalid = daemon_policy();
        invalid.maximum_local_events = 0;
        assert_eq!(
            invalid.validate(),
            Err(DaemonPolicyError::Zero("maximum_local_events"))
        );
        invalid = daemon_policy();
        invalid.maximum_transport_sends_per_step = 9;
        assert_eq!(
            invalid.validate(),
            Err(DaemonPolicyError::SendsPerStepAbovePending)
        );
        let mut invalid_runtime = runtime_policy();
        invalid_runtime.maximum_peers = 0;
        assert_eq!(
            invalid_runtime.validate(),
            Err(RuntimePolicyError::Zero("maximum_peers"))
        );
    }

    #[test]
    fn inbound_session_fixture_starts_before_hello() {
        let (session, initial) = session(SessionRole::Inbound);
        assert!(initial.is_empty());
        assert_eq!(session.phase(), SessionPhase::AwaitingHello);
    }
}
