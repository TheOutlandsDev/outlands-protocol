//! Deterministic multi-peer scheduling and bounded in-memory transport policy.
//!
//! Peer announcements, advertised tips, retry timing, and orphan retention are
//! operational hints only. They never participate in consensus validation or
//! chain selection. All time values are caller-supplied monotonic ticks.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use out_codec::{Block, EncodeError as ConsensusEncodeError};
use out_consensus::block_id_from_header_bytes;
use out_p2p::{InventoryEntry, FRAME_HEADER_BYTES, MAX_INV_ENTRIES, MAX_P2P_PAYLOAD_BYTES};
use out_primitives::BlockId;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PeerId(u64);

impl PeerId {
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiPeerPolicy {
    pub maximum_peers: u16,
    pub maximum_announcements_per_peer: u16,
    pub maximum_total_announcements: u32,
    pub maximum_pending_objects: u16,
    pub maximum_in_flight_per_peer: u16,
    pub maximum_retry_attempts: u16,
    pub request_timeout_ticks: u64,
    pub base_retry_backoff_ticks: u64,
    pub maximum_retry_backoff_ticks: u64,
    pub first_request_id: u64,
    pub maximum_orphans: u16,
    pub maximum_orphans_per_peer: u16,
    pub maximum_orphans_per_parent: u16,
    pub maximum_orphan_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultiPeerPolicyError {
    Zero(&'static str),
    AnnouncementPerPeerAboveTotal,
    PendingAboveTotalAnnouncements,
    RetryBackoffOrder,
}

impl MultiPeerPolicy {
    pub fn validate(self) -> Result<Self, MultiPeerPolicyError> {
        let nonzero = [
            (u64::from(self.maximum_peers), "maximum_peers"),
            (
                u64::from(self.maximum_announcements_per_peer),
                "maximum_announcements_per_peer",
            ),
            (
                u64::from(self.maximum_total_announcements),
                "maximum_total_announcements",
            ),
            (
                u64::from(self.maximum_pending_objects),
                "maximum_pending_objects",
            ),
            (
                u64::from(self.maximum_in_flight_per_peer),
                "maximum_in_flight_per_peer",
            ),
            (
                u64::from(self.maximum_retry_attempts),
                "maximum_retry_attempts",
            ),
            (self.request_timeout_ticks, "request_timeout_ticks"),
            (self.base_retry_backoff_ticks, "base_retry_backoff_ticks"),
            (
                self.maximum_retry_backoff_ticks,
                "maximum_retry_backoff_ticks",
            ),
            (self.first_request_id, "first_request_id"),
            (u64::from(self.maximum_orphans), "maximum_orphans"),
            (
                u64::from(self.maximum_orphans_per_peer),
                "maximum_orphans_per_peer",
            ),
            (
                u64::from(self.maximum_orphans_per_parent),
                "maximum_orphans_per_parent",
            ),
            (self.maximum_orphan_bytes, "maximum_orphan_bytes"),
        ];
        if let Some((_, field)) = nonzero.into_iter().find(|(value, _)| *value == 0) {
            return Err(MultiPeerPolicyError::Zero(field));
        }
        if u32::from(self.maximum_announcements_per_peer) > self.maximum_total_announcements {
            return Err(MultiPeerPolicyError::AnnouncementPerPeerAboveTotal);
        }
        if u32::from(self.maximum_pending_objects) > self.maximum_total_announcements {
            return Err(MultiPeerPolicyError::PendingAboveTotalAnnouncements);
        }
        if self.base_retry_backoff_ticks > self.maximum_retry_backoff_ticks {
            return Err(MultiPeerPolicyError::RetryBackoffOrder);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestAssignment {
    pub request_id: u64,
    pub peer_id: PeerId,
    pub object: InventoryEntry,
    pub attempt: u16,
    pub deadline_tick: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryReason {
    Timeout,
    Rejected,
    InvalidResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryOutcome {
    Retrying {
        object: InventoryEntry,
        failed_peer: PeerId,
        reason: RetryReason,
        delay_ticks: u64,
        peer_available_at: u64,
    },
    Exhausted {
        object: InventoryEntry,
        attempts: u16,
        last_peer: PeerId,
        reason: RetryReason,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultiPeerError {
    Policy(MultiPeerPolicyError),
    PeerCapacity { maximum: u16 },
    DuplicatePeer(PeerId),
    UnknownPeer(PeerId),
    PeerHasOrphans { peer_id: PeerId, count: u16 },
    InventoryMessageTooLarge { actual: usize, maximum: u16 },
    DuplicateInventory(InventoryEntry),
    PeerAnnouncementCapacity { peer_id: PeerId, maximum: u16 },
    TotalAnnouncementCapacity { maximum: u32 },
    PendingObjectCapacity { maximum: u16 },
    DuplicateScheduledObject(InventoryEntry),
    RequestIdExhausted,
    ClockOverflow,
    UnknownRequest(u64),
    RequestMismatch,
    PeerCounterCorrupt(PeerId),
    ObjectNotScheduled(InventoryEntry),
    ObjectNotExhausted(InventoryEntry),
    OrphanGenesis,
    OrphanEncode(ConsensusEncodeError),
    ConflictingOrphan(BlockId),
    OrphanCapacity { maximum: u16 },
    OrphanPeerCapacity { peer_id: PeerId, maximum: u16 },
    OrphanParentCapacity { parent: BlockId, maximum: u16 },
    OrphanByteCapacity { maximum: u64 },
    OrphanByteAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeerState {
    announcements: BTreeSet<InventoryEntry>,
    in_flight: u16,
    failures: u32,
    available_at: u64,
    orphan_count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanBlock {
    pub peer_id: PeerId,
    pub block_id: BlockId,
    pub parent_block_id: BlockId,
    pub received_tick: u64,
    pub canonical_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrphanAdmission {
    Stored { block_id: BlockId },
    AlreadyStored { block_id: BlockId },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerDisconnectCleanup {
    /// In-flight objects returned to the pending scheduler in request-ID order.
    pub requeued_objects: Vec<InventoryEntry>,
    /// Retained orphan records detached from live peer accounting in ascending
    /// block-ID order. They remain globally bounded and require full replay.
    pub detached_orphans: Vec<BlockId>,
}

pub struct MultiPeerCoordinator {
    policy: MultiPeerPolicy,
    peers: BTreeMap<PeerId, PeerState>,
    total_announcements: u32,
    pending_order: VecDeque<InventoryEntry>,
    pending: BTreeSet<InventoryEntry>,
    attempts: BTreeMap<InventoryEntry, u16>,
    exhausted: BTreeSet<InventoryEntry>,
    in_flight: BTreeMap<u64, RequestAssignment>,
    in_flight_objects: BTreeMap<InventoryEntry, u64>,
    next_request_id: u64,
    orphans: BTreeMap<BlockId, OrphanBlock>,
    orphan_owners: BTreeMap<BlockId, PeerId>,
    orphans_by_parent: BTreeMap<BlockId, BTreeSet<BlockId>>,
    orphan_bytes: u64,
}

impl MultiPeerCoordinator {
    pub fn new(policy: MultiPeerPolicy) -> Result<Self, MultiPeerError> {
        let policy = policy.validate().map_err(MultiPeerError::Policy)?;
        Ok(Self {
            policy,
            peers: BTreeMap::new(),
            total_announcements: 0,
            pending_order: VecDeque::new(),
            pending: BTreeSet::new(),
            attempts: BTreeMap::new(),
            exhausted: BTreeSet::new(),
            in_flight: BTreeMap::new(),
            in_flight_objects: BTreeMap::new(),
            next_request_id: policy.first_request_id,
            orphans: BTreeMap::new(),
            orphan_owners: BTreeMap::new(),
            orphans_by_parent: BTreeMap::new(),
            orphan_bytes: 0,
        })
    }

    pub const fn policy(&self) -> MultiPeerPolicy {
        self.policy
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn contains_peer(&self, peer_id: PeerId) -> bool {
        self.peers.contains_key(&peer_id)
    }

    pub const fn total_announcement_count(&self) -> u32 {
        self.total_announcements
    }

    pub fn pending_object_count(&self) -> usize {
        self.pending.len()
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    pub fn assignment(&self, request_id: u64) -> Option<RequestAssignment> {
        self.in_flight.get(&request_id).copied()
    }

    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    pub const fn orphan_bytes(&self) -> u64 {
        self.orphan_bytes
    }

    pub fn register_peer(&mut self, peer_id: PeerId) -> Result<(), MultiPeerError> {
        if self.peers.contains_key(&peer_id) {
            return Err(MultiPeerError::DuplicatePeer(peer_id));
        }
        if self.peers.len() >= usize::from(self.policy.maximum_peers) {
            return Err(MultiPeerError::PeerCapacity {
                maximum: self.policy.maximum_peers,
            });
        }
        self.peers.insert(
            peer_id,
            PeerState {
                announcements: BTreeSet::new(),
                in_flight: 0,
                failures: 0,
                available_at: 0,
                orphan_count: 0,
            },
        );
        Ok(())
    }

    /// Removes operational peer state and returns its in-flight objects in
    /// request-ID order. Those objects remain scheduled for other peers.
    pub fn unregister_peer(
        &mut self,
        peer_id: PeerId,
    ) -> Result<Vec<InventoryEntry>, MultiPeerError> {
        let peer = self
            .peers
            .get(&peer_id)
            .ok_or(MultiPeerError::UnknownPeer(peer_id))?;
        if peer.orphan_count != 0 {
            return Err(MultiPeerError::PeerHasOrphans {
                peer_id,
                count: peer.orphan_count,
            });
        }
        let announcement_count = u32::try_from(peer.announcements.len()).map_err(|_| {
            MultiPeerError::TotalAnnouncementCapacity {
                maximum: self.policy.maximum_total_announcements,
            }
        })?;
        let remaining_announcements = self
            .total_announcements
            .checked_sub(announcement_count)
            .ok_or(MultiPeerError::TotalAnnouncementCapacity {
                maximum: self.policy.maximum_total_announcements,
            })?;
        let request_ids: Vec<u64> = self
            .in_flight
            .iter()
            .filter_map(|(request_id, assignment)| {
                (assignment.peer_id == peer_id).then_some(*request_id)
            })
            .collect();
        self.peers.remove(&peer_id);
        self.total_announcements = remaining_announcements;
        let mut requeued = Vec::with_capacity(request_ids.len());
        for request_id in request_ids {
            if let Some(assignment) = self.in_flight.remove(&request_id) {
                self.in_flight_objects.remove(&assignment.object);
                requeued.push(assignment.object);
            }
        }
        Ok(requeued)
    }

    /// Detaches globally bounded orphan records from live per-peer accounting,
    /// then removes the peer. Retained orphans keep source attribution but
    /// still require complete consensus replay after their parent is stored.
    /// In-flight objects remain scheduled for other peers.
    pub fn disconnect_peer(
        &mut self,
        peer_id: PeerId,
    ) -> Result<PeerDisconnectCleanup, MultiPeerError> {
        if !self.peers.contains_key(&peer_id) {
            return Err(MultiPeerError::UnknownPeer(peer_id));
        }
        let detached_orphans: Vec<BlockId> = self
            .orphan_owners
            .iter()
            .filter_map(|(block_id, owner)| (*owner == peer_id).then_some(*block_id))
            .collect();
        let detached_count = u16::try_from(detached_orphans.len())
            .map_err(|_| MultiPeerError::PeerCounterCorrupt(peer_id))?;
        if self
            .peers
            .get(&peer_id)
            .ok_or(MultiPeerError::UnknownPeer(peer_id))?
            .orphan_count
            != detached_count
        {
            return Err(MultiPeerError::PeerCounterCorrupt(peer_id));
        }
        for block_id in &detached_orphans {
            self.orphan_owners.remove(block_id);
        }
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(MultiPeerError::UnknownPeer(peer_id))?;
        peer.orphan_count = peer
            .orphan_count
            .checked_sub(detached_count)
            .ok_or(MultiPeerError::PeerCounterCorrupt(peer_id))?;
        let requeued_objects = self.unregister_peer(peer_id)?;
        Ok(PeerDisconnectCleanup {
            requeued_objects,
            detached_orphans,
        })
    }

    /// Returns expired assignments in request-ID order without mutating them.
    /// The caller classifies and retries each result explicitly.
    pub fn expired_assignments(&self, now: u64) -> Vec<RequestAssignment> {
        self.in_flight
            .values()
            .filter(|assignment| now >= assignment.deadline_tick)
            .copied()
            .collect()
    }

    /// Records one already-decoded, canonically bounded inventory message.
    /// Capacity checks are atomic: failure records no partial announcement.
    pub fn observe_inventory(
        &mut self,
        peer_id: PeerId,
        entries: &[InventoryEntry],
    ) -> Result<Vec<InventoryEntry>, MultiPeerError> {
        if entries.len() > usize::from(MAX_INV_ENTRIES) {
            return Err(MultiPeerError::InventoryMessageTooLarge {
                actual: entries.len(),
                maximum: MAX_INV_ENTRIES,
            });
        }
        let peer = self
            .peers
            .get(&peer_id)
            .ok_or(MultiPeerError::UnknownPeer(peer_id))?;
        let mut message_seen = BTreeSet::new();
        let mut additions = Vec::new();
        for entry in entries.iter().copied() {
            if !message_seen.insert(entry) {
                return Err(MultiPeerError::DuplicateInventory(entry));
            }
            if !peer.announcements.contains(&entry) {
                additions.push(entry);
            }
        }
        let peer_total = peer
            .announcements
            .len()
            .checked_add(additions.len())
            .ok_or(MultiPeerError::PeerAnnouncementCapacity {
                peer_id,
                maximum: self.policy.maximum_announcements_per_peer,
            })?;
        if peer_total > usize::from(self.policy.maximum_announcements_per_peer) {
            return Err(MultiPeerError::PeerAnnouncementCapacity {
                peer_id,
                maximum: self.policy.maximum_announcements_per_peer,
            });
        }
        let addition_count = u32::try_from(additions.len()).map_err(|_| {
            MultiPeerError::TotalAnnouncementCapacity {
                maximum: self.policy.maximum_total_announcements,
            }
        })?;
        let total = self.total_announcements.checked_add(addition_count).ok_or(
            MultiPeerError::TotalAnnouncementCapacity {
                maximum: self.policy.maximum_total_announcements,
            },
        )?;
        if total > self.policy.maximum_total_announcements {
            return Err(MultiPeerError::TotalAnnouncementCapacity {
                maximum: self.policy.maximum_total_announcements,
            });
        }
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(MultiPeerError::UnknownPeer(peer_id))?;
        for entry in additions.iter().copied() {
            peer.announcements.insert(entry);
        }
        self.total_announcements = total;
        Ok(additions)
    }

    /// Adds caller-prioritized objects. The given order is retained exactly;
    /// peer selection never changes consensus block ordering.
    pub fn schedule_objects(&mut self, objects: &[InventoryEntry]) -> Result<(), MultiPeerError> {
        let mut additions = Vec::new();
        let mut seen = BTreeSet::new();
        for object in objects.iter().copied() {
            if !seen.insert(object) {
                return Err(MultiPeerError::DuplicateScheduledObject(object));
            }
            if !self.pending.contains(&object) {
                additions.push(object);
            }
        }
        let total = self.pending.len().checked_add(additions.len()).ok_or(
            MultiPeerError::PendingObjectCapacity {
                maximum: self.policy.maximum_pending_objects,
            },
        )?;
        if total > usize::from(self.policy.maximum_pending_objects) {
            return Err(MultiPeerError::PendingObjectCapacity {
                maximum: self.policy.maximum_pending_objects,
            });
        }
        for object in additions {
            self.pending.insert(object);
            self.pending_order.push_back(object);
        }
        Ok(())
    }

    pub fn next_assignment(
        &mut self,
        now: u64,
    ) -> Result<Option<RequestAssignment>, MultiPeerError> {
        let mut selected = None;
        for object in self.pending_order.iter().copied() {
            if self.in_flight_objects.contains_key(&object) || self.exhausted.contains(&object) {
                continue;
            }
            let candidate = self
                .peers
                .iter()
                .filter(|(_, peer)| {
                    peer.announcements.contains(&object)
                        && peer.available_at <= now
                        && peer.in_flight < self.policy.maximum_in_flight_per_peer
                })
                .map(|(peer_id, peer)| (peer.failures, peer.in_flight, *peer_id))
                .min();
            if let Some((_, _, peer_id)) = candidate {
                selected = Some((object, peer_id));
                break;
            }
        }
        let Some((object, peer_id)) = selected else {
            return Ok(None);
        };
        let previous_attempts = self.attempts.get(&object).copied().unwrap_or(0);
        let attempt = previous_attempts
            .checked_add(1)
            .ok_or(MultiPeerError::RequestIdExhausted)?;
        if attempt > self.policy.maximum_retry_attempts {
            self.exhausted.insert(object);
            return Ok(None);
        }
        let deadline_tick = now
            .checked_add(self.policy.request_timeout_ticks)
            .ok_or(MultiPeerError::ClockOverflow)?;
        let request_id = self.next_request_id;
        let next_request_id = request_id
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(MultiPeerError::RequestIdExhausted)?;
        let assignment = RequestAssignment {
            request_id,
            peer_id,
            object,
            attempt,
            deadline_tick,
        };
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(MultiPeerError::UnknownPeer(peer_id))?;
        peer.in_flight = peer
            .in_flight
            .checked_add(1)
            .ok_or(MultiPeerError::PeerCounterCorrupt(peer_id))?;
        self.next_request_id = next_request_id;
        self.attempts.insert(object, attempt);
        self.in_flight.insert(request_id, assignment);
        self.in_flight_objects.insert(object, request_id);
        Ok(Some(assignment))
    }

    pub fn complete_request(
        &mut self,
        assignment: RequestAssignment,
    ) -> Result<(), MultiPeerError> {
        self.require_assignment(assignment)?;
        self.remove_in_flight(assignment)?;
        self.remove_scheduled_object(assignment.object);
        for peer in self.peers.values_mut() {
            if peer.announcements.remove(&assignment.object) {
                self.total_announcements = self.total_announcements.checked_sub(1).ok_or(
                    MultiPeerError::TotalAnnouncementCapacity {
                        maximum: self.policy.maximum_total_announcements,
                    },
                )?;
            }
        }
        Ok(())
    }

    /// Rolls back a locally undispatched assignment without penalizing its
    /// peer or consuming a retry attempt.
    pub fn cancel_request(&mut self, assignment: RequestAssignment) -> Result<(), MultiPeerError> {
        self.require_assignment(assignment)?;
        self.remove_in_flight(assignment)?;
        match assignment.attempt.checked_sub(1) {
            Some(0) | None => {
                self.attempts.remove(&assignment.object);
            }
            Some(previous) => {
                self.attempts.insert(assignment.object, previous);
            }
        }
        Ok(())
    }

    pub fn retry_request(
        &mut self,
        assignment: RequestAssignment,
        now: u64,
        reason: RetryReason,
    ) -> Result<RetryOutcome, MultiPeerError> {
        self.require_assignment(assignment)?;
        let delay_ticks = retry_delay(
            self.policy.base_retry_backoff_ticks,
            self.policy.maximum_retry_backoff_ticks,
            assignment.attempt,
        );
        let peer_available_at = now
            .checked_add(delay_ticks)
            .ok_or(MultiPeerError::ClockOverflow)?;
        self.remove_in_flight(assignment)?;
        let peer = self
            .peers
            .get_mut(&assignment.peer_id)
            .ok_or(MultiPeerError::UnknownPeer(assignment.peer_id))?;
        peer.failures = peer.failures.saturating_add(1);
        peer.available_at = peer.available_at.max(peer_available_at);
        if assignment.attempt >= self.policy.maximum_retry_attempts {
            self.exhausted.insert(assignment.object);
            Ok(RetryOutcome::Exhausted {
                object: assignment.object,
                attempts: assignment.attempt,
                last_peer: assignment.peer_id,
                reason,
            })
        } else {
            Ok(RetryOutcome::Retrying {
                object: assignment.object,
                failed_peer: assignment.peer_id,
                reason,
                delay_ticks,
                peer_available_at,
            })
        }
    }

    pub fn reset_exhausted(&mut self, object: InventoryEntry) -> Result<(), MultiPeerError> {
        if !self.pending.contains(&object) {
            return Err(MultiPeerError::ObjectNotScheduled(object));
        }
        if !self.exhausted.remove(&object) {
            return Err(MultiPeerError::ObjectNotExhausted(object));
        }
        self.attempts.remove(&object);
        Ok(())
    }

    pub fn admit_orphan(
        &mut self,
        peer_id: PeerId,
        block: Block,
        received_tick: u64,
    ) -> Result<OrphanAdmission, MultiPeerError> {
        let peer = self
            .peers
            .get(&peer_id)
            .ok_or(MultiPeerError::UnknownPeer(peer_id))?;
        if block.header.height == 0 {
            return Err(MultiPeerError::OrphanGenesis);
        }
        let canonical_bytes = block
            .encode_non_genesis()
            .map_err(MultiPeerError::OrphanEncode)?;
        let block_id = block_id_from_header_bytes(&block.header.encode());
        if let Some(existing) = self.orphans.get(&block_id) {
            return if existing.canonical_bytes == canonical_bytes {
                Ok(OrphanAdmission::AlreadyStored { block_id })
            } else {
                Err(MultiPeerError::ConflictingOrphan(block_id))
            };
        }
        if self.orphans.len() >= usize::from(self.policy.maximum_orphans) {
            return Err(MultiPeerError::OrphanCapacity {
                maximum: self.policy.maximum_orphans,
            });
        }
        if peer.orphan_count >= self.policy.maximum_orphans_per_peer {
            return Err(MultiPeerError::OrphanPeerCapacity {
                peer_id,
                maximum: self.policy.maximum_orphans_per_peer,
            });
        }
        let parent_block_id = block.header.parent_block_id;
        let sibling_count = self
            .orphans_by_parent
            .get(&parent_block_id)
            .map_or(0, BTreeSet::len);
        if sibling_count >= usize::from(self.policy.maximum_orphans_per_parent) {
            return Err(MultiPeerError::OrphanParentCapacity {
                parent: parent_block_id,
                maximum: self.policy.maximum_orphans_per_parent,
            });
        }
        let encoded_len = u64::try_from(canonical_bytes.len()).map_err(|_| {
            MultiPeerError::OrphanByteCapacity {
                maximum: self.policy.maximum_orphan_bytes,
            }
        })?;
        let byte_total = self.orphan_bytes.checked_add(encoded_len).ok_or(
            MultiPeerError::OrphanByteCapacity {
                maximum: self.policy.maximum_orphan_bytes,
            },
        )?;
        if byte_total > self.policy.maximum_orphan_bytes {
            return Err(MultiPeerError::OrphanByteCapacity {
                maximum: self.policy.maximum_orphan_bytes,
            });
        }
        let record = OrphanBlock {
            peer_id,
            block_id,
            parent_block_id,
            received_tick,
            canonical_bytes,
        };
        self.orphans.insert(block_id, record);
        self.orphan_owners.insert(block_id, peer_id);
        self.orphans_by_parent
            .entry(parent_block_id)
            .or_default()
            .insert(block_id);
        self.orphan_bytes = byte_total;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(MultiPeerError::UnknownPeer(peer_id))?;
        peer.orphan_count = peer
            .orphan_count
            .checked_add(1)
            .ok_or(MultiPeerError::PeerCounterCorrupt(peer_id))?;
        Ok(OrphanAdmission::Stored { block_id })
    }

    /// Releases children in ascending block-ID order after their parent becomes
    /// authoritative. Returned blocks still require complete consensus checks.
    pub fn take_orphan_children(
        &mut self,
        parent: BlockId,
    ) -> Result<Vec<OrphanBlock>, MultiPeerError> {
        let child_ids = self.orphans_by_parent.remove(&parent).unwrap_or_default();
        let mut children = Vec::with_capacity(child_ids.len());
        for block_id in child_ids {
            if let Some(orphan) = self.remove_orphan_record(block_id)? {
                children.push(orphan);
            }
        }
        Ok(children)
    }

    /// Removes records received at or before the caller-selected tick, ordered
    /// by `(received_tick, block_id)` for reproducible resource reclamation.
    pub fn expire_orphans(
        &mut self,
        through_tick: u64,
    ) -> Result<Vec<OrphanBlock>, MultiPeerError> {
        let mut expired: Vec<(u64, BlockId)> = self
            .orphans
            .iter()
            .filter_map(|(block_id, orphan)| {
                (orphan.received_tick <= through_tick).then_some((orphan.received_tick, *block_id))
            })
            .collect();
        expired.sort_unstable();
        let mut removed = Vec::with_capacity(expired.len());
        for (_, block_id) in expired {
            if let Some(orphan) = self.remove_orphan_record(block_id)? {
                removed.push(orphan);
            }
        }
        Ok(removed)
    }

    fn require_assignment(&self, assignment: RequestAssignment) -> Result<(), MultiPeerError> {
        let stored = self
            .in_flight
            .get(&assignment.request_id)
            .ok_or(MultiPeerError::UnknownRequest(assignment.request_id))?;
        if *stored != assignment {
            return Err(MultiPeerError::RequestMismatch);
        }
        Ok(())
    }

    fn remove_in_flight(&mut self, assignment: RequestAssignment) -> Result<(), MultiPeerError> {
        self.in_flight.remove(&assignment.request_id);
        self.in_flight_objects.remove(&assignment.object);
        let peer = self
            .peers
            .get_mut(&assignment.peer_id)
            .ok_or(MultiPeerError::UnknownPeer(assignment.peer_id))?;
        peer.in_flight = peer
            .in_flight
            .checked_sub(1)
            .ok_or(MultiPeerError::PeerCounterCorrupt(assignment.peer_id))?;
        Ok(())
    }

    fn remove_scheduled_object(&mut self, object: InventoryEntry) {
        self.pending.remove(&object);
        self.pending_order.retain(|queued| *queued != object);
        self.attempts.remove(&object);
        self.exhausted.remove(&object);
    }

    fn remove_orphan_record(
        &mut self,
        block_id: BlockId,
    ) -> Result<Option<OrphanBlock>, MultiPeerError> {
        let Some(orphan) = self.orphans.remove(&block_id) else {
            return Ok(None);
        };
        if let Some(children) = self.orphans_by_parent.get_mut(&orphan.parent_block_id) {
            children.remove(&block_id);
            if children.is_empty() {
                self.orphans_by_parent.remove(&orphan.parent_block_id);
            }
        }
        let length = u64::try_from(orphan.canonical_bytes.len())
            .map_err(|_| MultiPeerError::OrphanByteAccounting)?;
        self.orphan_bytes = self
            .orphan_bytes
            .checked_sub(length)
            .ok_or(MultiPeerError::OrphanByteAccounting)?;
        if let Some(owner) = self.orphan_owners.remove(&block_id) {
            let peer = self
                .peers
                .get_mut(&owner)
                .ok_or(MultiPeerError::UnknownPeer(owner))?;
            peer.orphan_count = peer
                .orphan_count
                .checked_sub(1)
                .ok_or(MultiPeerError::PeerCounterCorrupt(owner))?;
        }
        Ok(Some(orphan))
    }
}

fn retry_delay(base: u64, maximum: u64, attempt: u16) -> u64 {
    let exponent = u32::from(attempt.saturating_sub(1));
    if exponent >= u64::BITS {
        return maximum;
    }
    base.checked_mul(1_u64 << exponent)
        .unwrap_or(maximum)
        .min(maximum)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryTransportPolicy {
    pub maximum_queued_frames: u16,
    pub maximum_queued_bytes: u64,
    pub maximum_frame_bytes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryTransportPolicyError {
    Zero(&'static str),
    FrameAboveProtocolMaximum { actual: u32, maximum: u32 },
}

impl MemoryTransportPolicy {
    pub fn validate(self) -> Result<Self, MemoryTransportPolicyError> {
        if self.maximum_queued_frames == 0 {
            return Err(MemoryTransportPolicyError::Zero("maximum_queued_frames"));
        }
        if self.maximum_queued_bytes == 0 {
            return Err(MemoryTransportPolicyError::Zero("maximum_queued_bytes"));
        }
        if self.maximum_frame_bytes == 0 {
            return Err(MemoryTransportPolicyError::Zero("maximum_frame_bytes"));
        }
        let protocol_maximum = u32::try_from(FRAME_HEADER_BYTES)
            .unwrap_or(u32::MAX)
            .saturating_add(MAX_P2P_PAYLOAD_BYTES);
        if self.maximum_frame_bytes > protocol_maximum {
            return Err(MemoryTransportPolicyError::FrameAboveProtocolMaximum {
                actual: self.maximum_frame_bytes,
                maximum: protocol_maximum,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryFrame {
    pub peer_id: PeerId,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryPeerRemoval {
    pub frames: u16,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryTransportError {
    Policy(MemoryTransportPolicyError),
    FrameTooLarge { actual: usize, maximum: u32 },
    FrameCapacity { maximum: u16 },
    ByteCapacity { maximum: u64 },
    ByteAccounting,
}

pub struct BoundedMemoryTransport {
    policy: MemoryTransportPolicy,
    queue: VecDeque<MemoryFrame>,
    queued_bytes: u64,
}

impl BoundedMemoryTransport {
    pub fn new(policy: MemoryTransportPolicy) -> Result<Self, MemoryTransportError> {
        let policy = policy.validate().map_err(MemoryTransportError::Policy)?;
        Ok(Self {
            policy,
            queue: VecDeque::new(),
            queued_bytes: 0,
        })
    }

    pub fn queued_frame_count(&self) -> usize {
        self.queue.len()
    }

    pub const fn queued_bytes(&self) -> u64 {
        self.queued_bytes
    }

    pub fn send(&mut self, peer_id: PeerId, bytes: Vec<u8>) -> Result<(), MemoryTransportError> {
        if bytes.len() > usize::try_from(self.policy.maximum_frame_bytes).unwrap_or(usize::MAX) {
            return Err(MemoryTransportError::FrameTooLarge {
                actual: bytes.len(),
                maximum: self.policy.maximum_frame_bytes,
            });
        }
        if self.queue.len() >= usize::from(self.policy.maximum_queued_frames) {
            return Err(MemoryTransportError::FrameCapacity {
                maximum: self.policy.maximum_queued_frames,
            });
        }
        let length =
            u64::try_from(bytes.len()).map_err(|_| MemoryTransportError::ByteCapacity {
                maximum: self.policy.maximum_queued_bytes,
            })?;
        let total =
            self.queued_bytes
                .checked_add(length)
                .ok_or(MemoryTransportError::ByteCapacity {
                    maximum: self.policy.maximum_queued_bytes,
                })?;
        if total > self.policy.maximum_queued_bytes {
            return Err(MemoryTransportError::ByteCapacity {
                maximum: self.policy.maximum_queued_bytes,
            });
        }
        self.queue.push_back(MemoryFrame { peer_id, bytes });
        self.queued_bytes = total;
        Ok(())
    }

    /// Removes one peer's queued frames while retaining every other frame in
    /// exact FIFO order.
    pub fn remove_peer(
        &mut self,
        peer_id: PeerId,
    ) -> Result<MemoryPeerRemoval, MemoryTransportError> {
        let (removal, remaining_bytes) = self.peer_removal_plan(peer_id)?;
        self.apply_peer_removal(peer_id, remaining_bytes);
        Ok(removal)
    }

    pub(crate) fn peer_removal_plan(
        &self,
        peer_id: PeerId,
    ) -> Result<(MemoryPeerRemoval, u64), MemoryTransportError> {
        let mut removal = MemoryPeerRemoval::default();
        for frame in &self.queue {
            if frame.peer_id == peer_id {
                removal.frames = removal
                    .frames
                    .checked_add(1)
                    .ok_or(MemoryTransportError::ByteAccounting)?;
                let length = u64::try_from(frame.bytes.len())
                    .map_err(|_| MemoryTransportError::ByteAccounting)?;
                removal.bytes = removal
                    .bytes
                    .checked_add(length)
                    .ok_or(MemoryTransportError::ByteAccounting)?;
            }
        }
        let remaining_bytes = self
            .queued_bytes
            .checked_sub(removal.bytes)
            .ok_or(MemoryTransportError::ByteAccounting)?;
        Ok((removal, remaining_bytes))
    }

    pub(crate) fn apply_peer_removal(&mut self, peer_id: PeerId, remaining_bytes: u64) {
        self.queue.retain(|frame| frame.peer_id != peer_id);
        self.queued_bytes = remaining_bytes;
    }

    pub fn receive(&mut self) -> Result<Option<MemoryFrame>, MemoryTransportError> {
        let Some(frame) = self.queue.pop_front() else {
            return Ok(None);
        };
        let length =
            u64::try_from(frame.bytes.len()).map_err(|_| MemoryTransportError::ByteAccounting)?;
        self.queued_bytes = self
            .queued_bytes
            .checked_sub(length)
            .ok_or(MemoryTransportError::ByteAccounting)?;
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use out_codec::Block;
    use out_p2p::{decode_frame_exact, encode_frame, Message, P2pNetwork, PROTOCOL_VERSION_V0};
    use out_storage::conformance::validated_reward_commit;

    use super::*;
    use crate::bootstrap::NodeBootstrap;
    use crate::SupportedNetwork;

    fn peer(value: u64) -> PeerId {
        PeerId::new(value).expect("nonzero peer")
    }

    fn policy() -> MultiPeerPolicy {
        MultiPeerPolicy {
            maximum_peers: 4,
            maximum_announcements_per_peer: 8,
            maximum_total_announcements: 24,
            maximum_pending_objects: 8,
            maximum_in_flight_per_peer: 2,
            maximum_retry_attempts: 3,
            request_timeout_ticks: 10,
            base_retry_backoff_ticks: 3,
            maximum_retry_backoff_ticks: 5,
            first_request_id: 500,
            maximum_orphans: 4,
            maximum_orphans_per_peer: 3,
            maximum_orphans_per_parent: 2,
            maximum_orphan_bytes: 1_000_000,
        }
    }

    fn transport() -> BoundedMemoryTransport {
        BoundedMemoryTransport::new(MemoryTransportPolicy {
            maximum_queued_frames: 4,
            maximum_queued_bytes: 1_000_000,
            maximum_frame_bytes: 100_000,
        })
        .expect("transport")
    }

    fn inventory_frame(peer_id: PeerId, entries: Vec<InventoryEntry>) -> MemoryFrame {
        let bytes = encode_frame(P2pNetwork::Devnet, 0, &Message::Inventory(entries))
            .expect("inventory frame");
        MemoryFrame { peer_id, bytes }
    }

    fn devnet_siblings() -> (Block, Block) {
        let node = NodeBootstrap {
            network: SupportedNetwork::Devnet,
            maximum_reorganization_blocks: 100,
        }
        .create_in_memory()
        .expect("node");
        let genesis = node.canonical_tip().expect("tip").block_id;
        let first = validated_reward_commit(node.storage(), genesis, b"orphan-a")
            .block()
            .clone();
        let second = validated_reward_commit(node.storage(), genesis, b"orphan-b")
            .block()
            .clone();
        (first, second)
    }

    #[test]
    fn coordinator_policy_rejects_zero_and_incoherent_budgets() {
        let mut invalid = policy();
        invalid.maximum_peers = 0;
        assert_eq!(
            invalid.validate(),
            Err(MultiPeerPolicyError::Zero("maximum_peers"))
        );

        invalid = policy();
        invalid.maximum_announcements_per_peer = 25;
        assert_eq!(
            invalid.validate(),
            Err(MultiPeerPolicyError::AnnouncementPerPeerAboveTotal)
        );

        invalid = policy();
        invalid.base_retry_backoff_ticks = 6;
        assert_eq!(
            invalid.validate(),
            Err(MultiPeerPolicyError::RetryBackoffOrder)
        );
    }

    #[test]
    fn encoded_inventory_selects_peers_deterministically_and_sends_real_request() {
        let mut coordinator = MultiPeerCoordinator::new(policy()).expect("coordinator");
        coordinator.register_peer(peer(2)).expect("peer 2");
        coordinator.register_peer(peer(1)).expect("peer 1");
        let object = InventoryEntry::Block(BlockId::new([0x33; 32]));
        let mut wire = transport();
        wire.send(peer(2), inventory_frame(peer(2), vec![object]).bytes)
            .expect("send inventory 2");
        wire.send(peer(1), inventory_frame(peer(1), vec![object]).bytes)
            .expect("send inventory 1");
        while let Some(frame) = wire.receive().expect("receive") {
            let decoded = decode_frame_exact(&frame.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0)
                .expect("decode inventory");
            let Message::Inventory(entries) = decoded.message else {
                panic!("inventory message");
            };
            coordinator
                .observe_inventory(frame.peer_id, &entries)
                .expect("observe inventory");
        }
        coordinator.schedule_objects(&[object]).expect("schedule");
        let assignment = coordinator
            .next_assignment(100)
            .expect("assignment")
            .expect("available");
        assert_eq!(assignment.peer_id, peer(1));
        let bytes = encode_frame(
            P2pNetwork::Devnet,
            assignment.request_id,
            &Message::GetObjects(vec![assignment.object]),
        )
        .expect("request frame");
        wire.send(assignment.peer_id, bytes).expect("send request");
        let request = wire.receive().expect("receive").expect("request");
        assert_eq!(request.peer_id, peer(1));
        assert!(matches!(
            decode_frame_exact(&request.bytes, P2pNetwork::Devnet, PROTOCOL_VERSION_V0)
                .expect("decode request")
                .message,
            Message::GetObjects(entries) if entries == vec![object]
        ));
        coordinator.complete_request(assignment).expect("complete");
        assert_eq!(coordinator.pending_object_count(), 0);
        assert_eq!(coordinator.total_announcement_count(), 0);
    }

    #[test]
    fn retry_backoff_is_capped_and_uses_an_eligible_alternate_peer() {
        let mut coordinator = MultiPeerCoordinator::new(policy()).expect("coordinator");
        coordinator.register_peer(peer(1)).expect("peer 1");
        coordinator.register_peer(peer(2)).expect("peer 2");
        let object = InventoryEntry::Block(BlockId::new([0x44; 32]));
        coordinator
            .observe_inventory(peer(1), &[object])
            .expect("inventory 1");
        coordinator
            .observe_inventory(peer(2), &[object])
            .expect("inventory 2");
        coordinator.schedule_objects(&[object]).expect("schedule");

        let first = coordinator.next_assignment(10).unwrap().unwrap();
        assert_eq!(first.peer_id, peer(1));
        assert!(coordinator.expired_assignments(19).is_empty());
        assert_eq!(coordinator.expired_assignments(20), vec![first]);
        assert_eq!(
            coordinator
                .retry_request(first, 20, RetryReason::Timeout)
                .expect("retry 1"),
            RetryOutcome::Retrying {
                object,
                failed_peer: peer(1),
                reason: RetryReason::Timeout,
                delay_ticks: 3,
                peer_available_at: 23,
            }
        );
        let second = coordinator.next_assignment(20).unwrap().unwrap();
        assert_eq!(second.peer_id, peer(2));
        assert_eq!(
            coordinator
                .retry_request(second, 20, RetryReason::Rejected)
                .expect("retry 2"),
            RetryOutcome::Retrying {
                object,
                failed_peer: peer(2),
                reason: RetryReason::Rejected,
                delay_ticks: 5,
                peer_available_at: 25,
            }
        );
        assert_eq!(coordinator.next_assignment(22), Ok(None));
        let third = coordinator.next_assignment(23).unwrap().unwrap();
        assert_eq!(third.peer_id, peer(1));
        assert!(matches!(
            coordinator.retry_request(third, 23, RetryReason::InvalidResponse),
            Ok(RetryOutcome::Exhausted { attempts: 3, .. })
        ));
        assert_eq!(coordinator.next_assignment(100), Ok(None));
        coordinator.reset_exhausted(object).expect("reset");
        assert!(coordinator.next_assignment(100).unwrap().is_some());
    }

    #[test]
    fn failed_inventory_capacity_check_is_atomic() {
        let mut bounded = policy();
        bounded.maximum_announcements_per_peer = 1;
        let mut coordinator = MultiPeerCoordinator::new(bounded).expect("coordinator");
        coordinator.register_peer(peer(1)).expect("peer");
        let first = InventoryEntry::Block(BlockId::new([1; 32]));
        let second = InventoryEntry::Block(BlockId::new([2; 32]));
        assert!(matches!(
            coordinator.observe_inventory(peer(1), &[first, second]),
            Err(MultiPeerError::PeerAnnouncementCapacity { .. })
        ));
        assert_eq!(coordinator.total_announcement_count(), 0);
        assert_eq!(
            coordinator.observe_inventory(peer(1), &[first]),
            Ok(vec![first])
        );
        assert_eq!(coordinator.total_announcement_count(), 1);
    }

    #[test]
    fn unregister_requeues_in_flight_objects_without_counting_a_failure() {
        let mut coordinator = MultiPeerCoordinator::new(policy()).expect("coordinator");
        coordinator.register_peer(peer(1)).expect("peer 1");
        coordinator.register_peer(peer(2)).expect("peer 2");
        let object = InventoryEntry::Block(BlockId::new([7; 32]));
        coordinator.observe_inventory(peer(1), &[object]).unwrap();
        coordinator.observe_inventory(peer(2), &[object]).unwrap();
        coordinator.schedule_objects(&[object]).unwrap();
        let assignment = coordinator.next_assignment(0).unwrap().unwrap();
        assert_eq!(assignment.peer_id, peer(1));
        assert_eq!(coordinator.unregister_peer(peer(1)), Ok(vec![object]));
        let reassigned = coordinator.next_assignment(0).unwrap().unwrap();
        assert_eq!(reassigned.peer_id, peer(2));
        assert_eq!(reassigned.attempt, 2);
    }

    #[test]
    fn disconnect_detaches_orphans_and_requeues_work_in_stable_order() {
        let (first, _) = devnet_siblings();
        let orphan_id = block_id_from_header_bytes(&first.header.encode());
        let object = InventoryEntry::Block(BlockId::new([7; 32]));
        let mut coordinator = MultiPeerCoordinator::new(policy()).expect("coordinator");
        coordinator.register_peer(peer(1)).expect("peer 1");
        coordinator.register_peer(peer(2)).expect("peer 2");
        coordinator.observe_inventory(peer(1), &[object]).unwrap();
        coordinator.observe_inventory(peer(2), &[object]).unwrap();
        coordinator.schedule_objects(&[object]).unwrap();
        let assignment = coordinator.next_assignment(0).unwrap().unwrap();
        assert_eq!(assignment.peer_id, peer(1));
        coordinator
            .admit_orphan(peer(1), first, 10)
            .expect("orphan");

        let cleanup = coordinator.disconnect_peer(peer(1)).expect("disconnect");
        assert_eq!(cleanup.requeued_objects, vec![object]);
        assert_eq!(cleanup.detached_orphans, vec![orphan_id]);
        assert_eq!(coordinator.peer_count(), 1);
        assert_eq!(coordinator.orphan_count(), 1);
        let reassigned = coordinator.next_assignment(0).unwrap().unwrap();
        assert_eq!(reassigned.peer_id, peer(2));
        assert_eq!(reassigned.attempt, 2);
        let retained = coordinator
            .take_orphan_children(
                coordinator
                    .orphans
                    .get(&orphan_id)
                    .expect("retained orphan")
                    .parent_block_id,
            )
            .expect("take detached orphan");
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].block_id, orphan_id);
        assert_eq!(coordinator.orphan_count(), 0);
    }

    #[test]
    fn orphan_siblings_are_bounded_and_released_by_block_id() {
        let (first, second) = devnet_siblings();
        let parent = first.header.parent_block_id;
        let first_id = block_id_from_header_bytes(&first.header.encode());
        let second_id = block_id_from_header_bytes(&second.header.encode());
        let mut coordinator = MultiPeerCoordinator::new(policy()).expect("coordinator");
        coordinator.register_peer(peer(1)).expect("peer");
        coordinator
            .admit_orphan(peer(1), second.clone(), 20)
            .expect("second orphan");
        coordinator
            .admit_orphan(peer(1), first.clone(), 10)
            .expect("first orphan");
        assert_eq!(
            coordinator.unregister_peer(peer(1)),
            Err(MultiPeerError::PeerHasOrphans {
                peer_id: peer(1),
                count: 2,
            })
        );
        assert_eq!(
            coordinator.admit_orphan(peer(1), first, 30),
            Ok(OrphanAdmission::AlreadyStored { block_id: first_id })
        );
        let children = coordinator
            .take_orphan_children(parent)
            .expect("take children");
        let expected = if first_id < second_id {
            vec![first_id, second_id]
        } else {
            vec![second_id, first_id]
        };
        assert_eq!(
            children
                .iter()
                .map(|orphan| orphan.block_id)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(coordinator.orphan_count(), 0);
        assert_eq!(coordinator.orphan_bytes(), 0);
        assert_eq!(coordinator.unregister_peer(peer(1)), Ok(Vec::new()));
    }

    #[test]
    fn orphan_capacity_and_expiration_are_atomic_and_deterministic() {
        let (first, second) = devnet_siblings();
        let first_len = first.encode_non_genesis().expect("encode").len() as u64;
        let mut bounded = policy();
        bounded.maximum_orphan_bytes = first_len;
        let mut coordinator = MultiPeerCoordinator::new(bounded).expect("coordinator");
        coordinator.register_peer(peer(1)).expect("peer");
        coordinator
            .admit_orphan(peer(1), first, 11)
            .expect("first orphan");
        assert!(matches!(
            coordinator.admit_orphan(peer(1), second, 10),
            Err(MultiPeerError::OrphanByteCapacity { .. })
        ));
        assert_eq!(coordinator.orphan_count(), 1);
        assert_eq!(coordinator.orphan_bytes(), first_len);
        let expired = coordinator.expire_orphans(11).expect("expire");
        assert_eq!(expired.len(), 1);
        assert_eq!(coordinator.orphan_bytes(), 0);
    }

    #[test]
    fn memory_transport_peer_removal_preserves_other_fifo_frames() {
        let mut transport = BoundedMemoryTransport::new(MemoryTransportPolicy {
            maximum_queued_frames: 4,
            maximum_queued_bytes: 100,
            maximum_frame_bytes: 50,
        })
        .expect("transport");
        transport.send(peer(1), vec![1, 1]).unwrap();
        transport.send(peer(2), vec![2]).unwrap();
        transport.send(peer(1), vec![3, 3, 3]).unwrap();
        transport.send(peer(2), vec![4, 4]).unwrap();
        assert_eq!(
            transport.remove_peer(peer(1)),
            Ok(MemoryPeerRemoval {
                frames: 2,
                bytes: 5,
            })
        );
        assert_eq!(transport.queued_frame_count(), 2);
        assert_eq!(transport.queued_bytes(), 3);
        assert_eq!(transport.receive().unwrap().unwrap().bytes, vec![2]);
        assert_eq!(transport.receive().unwrap().unwrap().bytes, vec![4, 4]);
    }

    #[test]
    fn memory_transport_enforces_frame_and_byte_budgets_without_partial_enqueue() {
        let mut wire = BoundedMemoryTransport::new(MemoryTransportPolicy {
            maximum_queued_frames: 1,
            maximum_queued_bytes: 4,
            maximum_frame_bytes: 4,
        })
        .expect("transport");
        wire.send(peer(1), vec![1, 2, 3, 4]).expect("first");
        assert_eq!(
            wire.send(peer(2), vec![5]),
            Err(MemoryTransportError::FrameCapacity { maximum: 1 })
        );
        assert_eq!(wire.queued_frame_count(), 1);
        assert_eq!(wire.queued_bytes(), 4);
        assert_eq!(
            wire.receive().expect("receive"),
            Some(MemoryFrame {
                peer_id: peer(1),
                bytes: vec![1, 2, 3, 4],
            })
        );
        assert_eq!(wire.queued_bytes(), 0);
        assert_eq!(
            wire.send(peer(1), vec![0; 5]),
            Err(MemoryTransportError::FrameTooLarge {
                actual: 5,
                maximum: 4,
            })
        );
        assert_eq!(wire.queued_frame_count(), 0);
    }
}
