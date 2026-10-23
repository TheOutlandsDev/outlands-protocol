> Export scope: dated verification statements below are historical. See [current export scope](../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT Consensus v0

Status: normative implementation draft with explicit owner-ratification gates in `open-decisions.md`.

## 1. Scope and definitions

OUT is an account-based proof-of-work chain. Consensus is the set of rules by which canonical bytes, a parent state, and an owner-ratified network parameter manifest produce exactly one validity result, post-state root, block ID, per-block work, cumulative work, and best-chain ordering.

“Invalid” means no conforming implementation may accept the object under the same chain history and parameters. “Local failure” means validation could not complete because of unavailable data, storage/I/O failure, memory/resource policy, shutdown, or internal fault; local failure MUST NOT be cached, relayed, or reported as proof that the block is consensus-invalid.

Network/mempool/RPC/wallet/mining-pool/operational policy is non-consensus unless a rule explicitly says otherwise.

## 2. Network identity and replay boundary

Each network is identified by the tuple:

```text
(chain_id[32], network_id:u32, genesis_commitment[32])
```

- `chain_id` identifies the OUT chain family. `OUT-ID-v0` fixes it to raw bytes `fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c4`.
- `network_id` distinguishes mainnet (`1`), testnet (`2`), and devnet (`3`).
- `genesis_commitment` binds all ratified parameters and initial accounts.
- Operator-facing network names are not consensus identifiers.
- Each transaction body and block header contains all three fields. Exact equality is required.
- The transaction signing digest includes the body, therefore all three fields. A valid signature from one network MUST fail identity validation on another even if keys, nonce, and payment fields match.
- P2P additionally uses a distinct 4-byte network magic. Magic is routing defense, not a substitute for consensus identity validation.

`OUT-ID-v0` fixes P2P magic to mainnet `a2f22921`, testnet `b1e4aa74`, and devnet `6bb49c33`; HRPs are `out`, `tout`, and `dout`. Each network MUST still receive a distinct complete genesis descriptor and commitment.

## 3. BLAKE3 domain separation

### 3.1 OUT_HASH

For every consensus hash below:

```text
OUT_HASH(context, material) = first 32 output octets of
                              BLAKE3 derive_key(context, material)
```

`context` is the exact case-sensitive ASCII byte string shown, passed as the BLAKE3 derive-key context with no NUL terminator, BOM, normalization, length prefix, or surrounding quotes. `material` is the exact concatenation below. BLAKE3 `derive_key` mode—not ordinary hash mode and not keyed-hash mode—MUST be used. Output bytes are retained in BLAKE3 order. Hex is lowercase display only and never hashed as text.

### 3.2 Context registry and exact materials

| Purpose | Exact context ASCII | Exact material |
|---|---|---|
| Transaction signing digest | `OUT Consensus v0 2026-08-30 transaction signing digest` | `0x00 || envelope_codec:u8 || regular_kind:u8 || BE32(body_len) || canonical_regular_body` |
| Transaction ID | `OUT Consensus v0 2026-08-30 transaction identifier` | complete canonical transaction envelope |
| Block ID | `OUT Consensus v0 2026-08-30 block identifier` | canonical 223-byte block header |
| Header PoW | `OUT Consensus v0 2026-08-30 proof of work header` | canonical 223-byte block header |
| Account key | `OUT Consensus v0 2026-08-30 account key` | `0x00 || recipient[33]` |
| State leaf | `OUT Consensus v0 2026-08-30 state leaf` | empty/occupied material in `state-model-v0.md` |
| State internal node | `OUT Consensus v0 2026-08-30 state internal node` | `0x00 || BE16(height) || left[32] || right[32]` |
| Transaction Merkle leaf | `OUT Consensus v0 2026-08-30 transaction Merkle leaf` | exact occupied/padding/empty-genesis material in `wire-format-v0.md` |
| Transaction Merkle node | `OUT Consensus v0 2026-08-30 transaction Merkle internal node` | `0x00 || BE16(level) || left[32] || right[32]` |
| Genesis commitment | `OUT Consensus v0 2026-08-30 genesis commitment` | complete canonical genesis descriptor |
| Snapshot commitment | `OUT Consensus v0 2026-08-30 snapshot commitment` | exact metadata and body in `state-model-v0.md` |
| P2P frame checksum | `OUT Protocol v0 2026-08-30 P2P message checksum` | exact fields and payload in `wire-format-v0.md` |

`BE16/32/64` always means fixed-width unsigned big-endian. Fixed-size fields have no length. Variable bytes include their specified length field in the material. The version/tag octets shown are mandatory even when zero. Concatenation never inserts delimiters or text. A purpose MUST NOT use another purpose's context, and an unlabeled generic consensus hash is forbidden.

Any future hash purpose MUST receive a new globally unique hard-coded context and an activated format version. Dynamic network values MUST be material, never part of the context string.

## 4. Ed25519 authorization

OUT uses pure Ed25519 as standardized by RFC 8032. It does not define a signature algorithm. The Ed25519 message `M` is exactly the 32-octet OUT signing digest from section 3; implementations MUST NOT use Ed25519ph, Ed25519ctx, an application context parameter, or hash the digest again outside Ed25519's specified internal SHA-512 operations.

### 4.1 Strict decoding

For public key `A[32]` and signature `R[32] || S[32]`, validation MUST:

1. Require exact lengths 32 and 64.
2. Decode Edwards25519 compressed `A` and `R` canonically: the encoded `y` (after clearing the sign bit) MUST be `< p = 2^255 - 19`; the point MUST satisfy the curve equation; re-encoding the decoded point MUST reproduce the input; and the sign bit MUST be zero when recovered `x = 0` (“negative zero” is invalid).
3. Interpret `S` in Ed25519's standard little-endian scalar encoding and require `0 <= S < L`, where `L = 2^252 + 27742317777372353535851937790883648493`.
4. Require both `A` and `R` to be non-identity points in the prime-order subgroup: `[L]A = identity`, `[L]R = identity`, `A != identity`, and `R != identity`. This rejects small-order, mixed-order, weak, and malformed points.
5. Compute `k = SHA-512(R_encoding || A_encoding || M) mod L` exactly as pure Ed25519.
6. Accept only if the uncofactored group equation `[S]B = R + [k]A` holds exactly.

Any failure is an invalid signature. A library is conforming only if configured/wrapped to implement every condition. ZIP-215-like permissive decoding, reduction of noncanonical `S`, accepting noncanonical points, cofactored-only compatibility equations, legacy malleability workarounds, and fallback verification modes are prohibited.

Batch verification is forbidden in consensus v0. Implementations MUST verify transactions individually in block order. A future batch optimization requires proof that its accept/reject set is identical, deterministic fallback to identify invalid inputs, and an activated specification change. CPU architecture, library version, vectorization, and thread schedule MUST NOT alter results.

After strict key decoding, a v0 sender is valid only when `sender == 0x00 || A_encoding`, as ratified in `OUT-ID-v0`.

## 5. Canonical genesis descriptor

The genesis descriptor is the network's ratified parameter manifest. Fields occur exactly in this order; all integers use the canonical big-endian codec. Lists are counted and have no per-entry length because their entries are fixed width.

| Order | Width | Field / constraint |
|---:|---:|---|
| 1 | 1 | descriptor codec `0x00` |
| 2 | 32 | `chain_id` |
| 3 | 4 | `network_id` |
| 4 | 2 | initial `consensus_version` |
| 5 | 8 | `genesis_timestamp` Unix seconds |
| 6 | 4 | P2P network magic |
| 7 | 1 + N | HRP length `u8` + lowercase ASCII HRP, `1..=30` |
| 8 | 1 | recipient version, candidate `0x00` |
| 9 | 2 | recipient payload length, candidate 32 |
| 10 | 1 | recipient semantics, candidate `0x00` raw strict Ed25519 key |
| 11 | 8 | `P_MAX_MONEY` |
| 12 | 2 | `P_MAX_MEMO_BYTES` |
| 13 | 2 | `P_MAX_REWARD_EXTRA_BYTES` |
| 14 | 4 | `P_MAX_TX_BYTES` |
| 15 | 4 | `P_MAX_TXS_PER_BLOCK` |
| 16 | 4 | `P_MAX_BLOCK_BODY_BYTES` |
| 17 | 4 | `P_MAX_P2P_PAYLOAD_BYTES` |
| 18 | 8 | `P_MAX_SNAPSHOT_BODY_BYTES` |
| 19 | 4 | `P_MAX_GENESIS_DESCRIPTOR_BYTES` |
| 20 | 4 | `P_MAX_GENESIS_ACCOUNTS` |
| 21 | 2 | `P_MAX_REWARD_SEGMENTS` |
| 22 | 2 | `P_MAX_UPGRADE_ENTRIES` |
| 23 | 2 each | `P_MAX_INV_ENTRIES`, `P_MAX_LOCATOR_ENTRIES`, `P_MAX_HEADERS` |
| 24 | 8 | `P_TARGET_SPACING`, nonzero |
| 25 | 4 | `P_RETARGET_WINDOW`, `>= 2` |
| 26 | 4 each | down numerator/denominator, up numerator/denominator; denominators nonzero |
| 27 | 2 | `P_MEDIAN_TIME_WINDOW`, odd and `>= 3` |
| 28 | 8 | `P_MAX_FUTURE_DRIFT` |
| 29 | 32 | `P_POW_LIMIT`, nonzero U256 |
| 30 | 32 | `P_GENESIS_TARGET`, nonzero and `<= P_POW_LIMIT` |
| 31 | 1 | fee semantics; candidate `0x00` means full explicit fee, no burn/refund |
| 32 | 8 | consensus minimum fee; ratified zero (mempool may require more) |
| 33 | 2 + entries | reward segment count, then `(start_height:u64, subsidy:u64)` |
| 34 | 2 + entries | upgrade count, then `(activation_height:u64, consensus_version:u16, tx_version:u16)` |
| 35 | 2 | network exception flags; bit 0 dev fixed-target, bit 1 delayed test minimum; all other bits zero |
| 36 | 8 | delayed-minimum threshold seconds; zero unless flag bit 1 set |
| 37 | 4 + entries | initial account count, then `(recipient[33], balance:u64)` |

Reward segment and upgrade counts MUST respectively be `<= P_MAX_REWARD_SEGMENTS` and `<= P_MAX_UPGRADE_ENTRIES`. Reward entries MUST exactly materialize `OUT-ECON-v0`: first start height 1, 29 positive eras of 2,102,400 blocks using floor-halving from 500,000,000 base units, then zero at height 60,969,601. Upgrade entries MUST be strictly ascending by activation height and begin at height 0. Neither list may contain duplicate heights or redundant consecutive values. Under `OUT-ECON-v0`, initial account count MUST be zero. The complete descriptor MUST be `<= P_MAX_GENESIS_DESCRIPTOR_BYTES`. The bootstrap parser obtains these outer caps from the reviewed local network profile, enforces them before allocation, then requires the decoded fields to match. Exact lifetime issuance is 2,102,399,972,668,800 base units and MUST remain `<= P_MAX_MONEY = 2,102,400,000,000,000 <= u64::MAX` under checked `u128` arithmetic.

`genesis_commitment = OUT_HASH(GENESIS_CONTEXT, descriptor_bytes)`. A network configuration MUST pin the exact descriptor bytes, commitment, genesis header bytes, and resulting genesis block ID. A parsed local configuration whose recomputed commitment differs MUST fail closed.

### 5.1 Genesis block

The genesis header has height 0, zero parent ID, descriptor timestamp, genesis target, descriptor identities/initial consensus version, the canonical empty state root `E[256]`, and the ratified zero-transaction genesis Merkle root. Its body is exactly `body_codec=0x00 || tx_count:u32=0`. It has no allocations, reward transaction, or subsidy. Its nonce MUST satisfy genesis target unless the network descriptor explicitly activates the dev fixed-target flag; even then the same hash/compare algorithm applies. Genesis's state root, PoW nonce, header, block ID, and descriptor commitment MUST have independently checked golden vectors before launch.

## 6. Versions and upgrades

Consensus version and transaction version are explicit `u16` values, initially ratified as `0`. The eventual ratified upgrade schedule selects exact versions by height:

```text
active_entry(h) = last entry with activation_height <= h
```

The header version and every transaction version MUST equal the active entry. Gaps are impossible because the schedule begins at 0. Unknown versions, premature versions, and old versions after activation are invalid. Activation is based only on block height, never wall clock, miner signaling, peer count, software version, or database state.

`OUT-TECH-v0` ratifies the initial schedule as exactly `(activation_height=0, consensus_version=0, tx_version=0)`. Because v0 has no on-chain governance or miner voting, any post-launch change is an explicit coordinated height-activated hard fork distributed in updated software. Its activation height and new versions MUST be public and fixed before activation; nodes without it remain on the old rules. A contentious change SHOULD use a new network identity. No wall-clock, signaling threshold, or automatic behavior can activate an upgrade.

P2P protocol negotiation is independent. Supporting a P2P version does not imply accepting an unknown consensus version.

## 7. Required block-validation pipeline

Implementations MAY parallelize pure preliminary checks, but acceptance MUST be equivalent to this order and all stateful evaluation is in transaction order.

```text
validate_block(raw, selected_network, local_now):
  1. if raw length > P_MAX_BLOCK_BYTES: INVALID(SIZE)
  2. canonical-decode envelope/header/body with pre-allocation bounds
     reject truncation, unknown tags, noncanonical form, trailing bytes
  3. check fixed header structure and body structure/count/kinds
  4. check chain_id, network_id, genesis_commitment and active versions
  5. if height==0: validate against pinned genesis and stop ordinary path
  6. lookup parent by exact block ID
     if unavailable: LOCAL_MISSING_PARENT (not invalid)
  7. check height == parent.height + 1 with checked arithmetic
  8. check timestamp > median_time_past(parent) and
           timestamp <= local_now + P_MAX_FUTURE_DRIFT
     future failure is TEMPORARILY_UNACCEPTABLE, not permanent invalid cache
  9. compute required target from parent branch; require exact header target;
     validate target range/encoding
 10. compute PoW digest, U256 value, and compare to target
 11. canonical-decode each bounded transaction; compute IDs; reject duplicate
     IDs in block or in the same ancestor branch
 12. recompute indexed transaction Merkle root and require exact header root
 13. for every transaction: structural fields, identity, height interval,
     supported recipient/auth kinds, canonical strict key/signature encodings
 14. individually verify every regular signature in transaction order
 15. load the exact parent state/root; if unavailable: LOCAL_STATE_UNAVAILABLE
 16. execute regular transactions at indices 1..n-1 in order:
     validate sender nonce, checked amount+fee, balance, and all money bounds;
     debit/increment then credit; accumulate fees in checked u128
 17. validate sole reward at index 0 against height, scheduled subsidy,
     exact accumulated fees, and supply bounds; then credit reward last
 18. compute post-state root with canonical state tree
 19. require computed root == header.state_root
 20. compute checked per-block work and cumulative work
 21. atomically persist header/body, validated metadata, state changes/root,
     undo/branch data, tx index, and chain-work record
 22. only after durable success expose the block as locally accepted and
     evaluate deterministic best-chain selection
```

Cheap checks SHOULD precede expensive signature/state work as shown. Merkle verification precedes signatures. The state transition MUST be pure with respect to `(parent_state, canonical_block, ratified_params)`; logging, Redis, PostgreSQL, RPC calls, thread timing, and local clock (apart from the explicit future-bound admission check) MUST NOT enter it.

### 7.1 Duplicate rules

- Duplicate transaction IDs within a block are invalid.
- A regular transaction ID already confirmed in an ancestor of the candidate parent is invalid on that branch. The nonce rule would ordinarily also reject it, but the explicit rule avoids ambiguity.
- The same transaction may exist on competing branches; a reorg may confirm it on the new branch if it is valid against that branch state.
- Duplicate P2P announcements and mempool copies are policy, not block validity.

### 7.2 Failure taxonomy

Consensus-invalid includes malformed/noncanonical bytes, wrong identity/version, impossible height, timestamp not greater than MTP, wrong target, failed PoW, wrong Merkle root, invalid signature, duplicate branch transaction, nonce/balance/money failure, wrong reward/fees, wrong state root, and arithmetic overflow required by consensus.

Local/non-consensus failure includes missing parent not yet received, pruned required state, database I/O/corruption, disk full, interrupted atomic batch, memory/CPU policy, unavailable worker thread, shutdown, or internal exception. Such a block remains unclassified locally. A far-future timestamp is temporarily unacceptable and MAY be retried when time advances; local wall clock MUST NOT make the block permanently invalid.

No malformed input may panic the node. An internal panic/exception is a node fault and MUST NOT be translated to “invalid block.”

## 8. Chain selection, reorganization, and finality

### 8.1 Best chain

For every valid block:

```text
cumulative_work(genesis) = work(genesis)
cumulative_work(block)   = checked_U256_add(cumulative_work(parent), work(block))
```

Among fully validated tips with locally available ancestry/state, select the maximum tuple:

```text
(cumulative_work, height, inverse_lexicographic_block_id)
```

That means higher cumulative work wins; if equal, greater height wins; if both equal, the lexicographically smaller raw 32-byte block ID wins. The tie rule is deterministic and has no claim of extra security. Header arrival order, peer score, database order, filesystem order, and current selected tip MUST NOT break ties.

### 8.2 Reorganization

To switch tips, find the common ancestor, verify the complete winning branch before exposure, roll back old-branch blocks in reverse height order, and apply new-branch blocks in increasing height order. The visible canonical tip/state/index set MUST change atomically or via a crash-recoverable journal whose recovery has one deterministic result. Intermediate mixed-branch state MUST never be exposed as canonical.

Nodes MUST retain enough undo data, historical roots, or reconstructible snapshots to perform any reorg they claim to support. A locally configured “maximum reorg depth” MAY pause and require operator action as safety policy, but MUST NOT label a deeper otherwise-valid higher-work chain consensus-invalid. Hard checkpoints would alter consensus/trust and are absent from v0.

Transactions removed from the old branch MAY be reconsidered for mempool insertion in original old-branch order after removing transactions confirmed on the new branch. They MUST be revalidated against the new tip. Reinsertion, ordering, fee filters, and relay are non-consensus.

### 8.3 Finality and unavailable history

Proof of work provides probabilistic, not absolute, finality. Confirmation counts are risk policy. No block after genesis has deterministic finality in v0.

A pruned node lacking required historical state/undo data MUST report local state unavailable, fetch and verify the required data, reconstruct from a verified snapshot plus subsequent blocks, or decline the reorg. It MUST NOT keep an inferior chain by declaring the candidate invalid. Pruning depth is operational policy constrained by the promised reorg/snapshot capabilities.

A snapshot is an availability optimization. It is accepted only after verifying its commitment/body/root and the header chain/cumulative work through its anchor as specified in `state-model-v0.md`. A catalog signature MAY identify a publisher but MUST NOT replace cryptographic root and chain verification. A trusted hard-coded snapshot/checkpoint is not part of v0 and would change the trust model.

## 9. Storage and service boundary

The consensus storage interface SHOULD expose only atomic operations such as:

```text
get_header(block_id)
get_body(block_id)
get_state(root, account_key)
begin_atomic_branch_commit(parent_id, block_id)
put_content_addressed_nodes(...)
put_block_and_metadata(...)
set_best_tip_and_indices(...)
commit() / abort()
recover()
```

Keys/values stored by RocksDB or redb MAY differ, but canonical object bytes, account semantics, roots, work, and selected tip MUST match. Consensus MUST never depend on database iteration order; sorting is by specified raw bytes before hashing/applying. Backend errors are local failures.

PostgreSQL MAY index or mirror blocks for analytics/control-plane use. Redis MAY cache/queue/announce transient data. Neither may be queried to decide balances, nonces, validity, roots, targets, chain work, or best tip. Complete loss of PostgreSQL and Redis MUST leave consensus results unchanged. Python, Docker, and operational services are outside the consensus trust boundary.
