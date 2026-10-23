> Export scope: dated verification statements below are historical. See [current export scope](../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT Consensus v0 open decisions

Status: owner-ratification register. No recommended value in this file is final merely because it is numeric.

## 1. Decision classes

| Class | Meaning |
|---|---|
| Fixed working decision | Required by the workshop objective and used normatively throughout the draft. |
| Recommended default | A concrete candidate that makes review and vector generation possible; not active until owner approval. |
| Owner approval required | Must be decided and recorded in the genesis parameter manifest. |
| Blocks implementation | Independent implementations cannot produce final compatible bytes or validation results until resolved. |
| Safely deferrable | Can be omitted from consensus v0 without ambiguity. |

Changing a ratified consensus parameter after genesis requires the upgrade rules in `consensus-v0.md`; editing this document is not an upgrade.

## 2. Fixed working decisions

- The chain is an original, account-based, proof-of-work native Layer 1.
- Consensus hashes use 32-byte BLAKE3 `derive_key` output with the exact fixed contexts in `consensus-v0.md`; an unlabeled generic consensus hash is forbidden.
- Signatures are pure Ed25519 over the 32-byte OUT signing digest, with strict point/scalar decoding, prime-subgroup checks, and no batch verification in v0.
- Human-readable addresses use Bech32m; transactions store a binary recipient, never address text.
- Stored money fields are unsigned 64-bit integers; aggregate and intermediate monetary arithmetic uses checked unsigned arithmetic at least 128 bits wide.
- PoW target and cumulative work use a tested unsigned 256-bit type. Retarget multiplication/division requires an exact wider intermediate.
- Canonical consensus encoding is positional and language-neutral. It is independent of Serde, bincode, JSON, Protobuf, Rust layout/discriminants, `usize`, floats, and maps.
- Account transitions and the authenticated state commitment are deterministic and database-independent.
- The P2P protocol is custom and versioned.
- RocksDB and redb are interchangeable beneath a narrow interface. PostgreSQL and Redis are never authoritative consensus stores.
- CPU defines the reference PoW behavior; CUDA must reproduce it bit-for-bit. CUDA performance does not shape consensus.

### 2.1 Ratified owner decisions: `OUT-ID-v0`

Approved by the project owner on 2026-08-30:

| Field | Mainnet | Testnet | Devnet |
|---|---|---|---|
| Network label | `mainnet` | `testnet` | `devnet` |
| Network ID (`u32`) | `1` | `2` | `3` |
| P2P magic | `a2f22921` | `b1e4aa74` | `6bb49c33` |
| Address HRP | `out` | `tout` | `dout` |

Shared OUT chain-family ID (32 raw bytes, displayed as lowercase hex):

```text
fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c4
```

Recipient version 0 is exactly `0x00 || canonical Ed25519 public_key[32]`. Initial consensus version, transaction version, and P2P protocol version are all unsigned value `0`. Each network will have a distinct genesis commitment derived later from its complete ratified descriptor. These decisions are fixed for v0; changing them requires a new network identity/activated protocol as applicable.

### 2.2 Ratified owner decisions: `OUT-ECON-v0`

Approved by the project owner on 2026-08-30 and identical on mainnet, testnet, and devnet:

| Field | Ratified value |
|---|---|
| Display precision | 8 decimal places; display-only, non-consensus |
| Base units per displayed OUT | 100,000,000 |
| `P_MAX_MONEY` | 2,102,400,000,000,000 base units (21,024,000 OUT) |
| Genesis allocations | none; initial account count and supply are zero |
| First rewarded height | 1 |
| Initial subsidy | 500,000,000 base units (5 OUT) |
| Subsidy era length | 2,102,400 rewarded blocks |
| Era rule | for height `h>=1`, `era=floor((h-1)/2,102,400)` and `subsidy=floor(500,000,000/2^era)` |
| Positive eras | 0 through 28 |
| First zero-subsidy height | 60,969,601 |
| Exact lifetime subsidy | 2,102,399,972,668,800 base units (21,023,999.726688 OUT) |
| Unissued cap headroom | 27,331,200 base units (0.273312 OUT) |
| Regular amount | strictly greater than zero |
| Fee semantics | explicit `u64`, paid in full, no burn/refund/base fee |
| Minimum consensus fee | 0; mempool policy MAY require more |
| Fee destination | credited exactly once to the reward recipient after regular transitions |

The terminal zero subsidy continues forever. Testnet/devnet funds are obtained by mining under their easier network-specific PoW rules, not by genesis faucet allocations. The era is measured only in block heights; any calendar duration is an estimate based on a separately ratified target spacing.

### 2.3 Ratified owner decisions: `OUT-LIMITS-v0`

Approved by the project owner on 2026-08-30:

| Parameter | Ratified value |
|---|---:|
| `P_MAX_MEMO_BYTES` | 256 |
| `P_MAX_REWARD_EXTRA_BYTES` | 100 |
| `P_MAX_TX_BYTES` | 16,384 |
| `P_MAX_TXS_PER_BLOCK` | 8,192 |
| `P_MAX_BLOCK_BODY_BYTES` | 2,097,152 |
| derived `P_MAX_BLOCK_BYTES` | 2,097,382 |
| `P_MAX_P2P_PAYLOAD_BYTES` | 4,194,304 |
| `P_MAX_INV_ENTRIES` | 2,048 |
| `P_MAX_LOCATOR_ENTRIES` | 128 |
| `P_MAX_HEADERS` | 2,000 |
| `P_MAX_GENESIS_DESCRIPTOR_BYTES` | 65,536 |
| `P_MAX_GENESIS_ACCOUNTS` | 0 |
| `P_MAX_REWARD_SEGMENTS` | 30 |
| `P_MAX_UPGRADE_ENTRIES` | 256 |
| `P_MAX_SNAPSHOT_BODY_BYTES` | 68,719,476,736 (64 GiB), streaming only |
| `P_TARGET_SPACING` | 60 seconds |
| `P_MEDIAN_TIME_WINDOW` | 11 blocks |
| `P_MAX_FUTURE_DRIFT` | 7,200 seconds |

The block byte cap makes the 8,192 count cap a conservative pre-allocation bound; canonical v0 minimum transaction sizes permit fewer actual entries. Snapshot readers MUST stream and enforce the decompressed bound without allocating it as one buffer.

### 2.4 Ratified owner decisions: `OUT-TECH-v0`

Approved by the project owner on 2026-08-30:

- State commitment is the specified version-0 fixed-depth 256-level binary sparse Merkle tree, MSB-first, with exact empty/occupied/node hashes. State proof wire format remains deferred.
- Targets are full 32-byte big-endian U256 values; no compact target exists.
- `P_RETARGET_WINDOW = 720`; expected span is `(720-1)*60 = 43,140` seconds.
- Retarget actual span is clamped to `[ceil(expected/4), floor(expected*4)]`, then the exact previous target is multiplied/divided with a >=512-bit intermediate and floor rounding.
- Mainnet uses ordinary epoch retarget and no minimum-difficulty exception. Its PoW limit/genesis target remain benchmark-gated.
- Testnet sets exception flag bit 1, delayed-minimum threshold 1,200 seconds, and both genesis target and PoW limit to `00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`.
- Devnet sets exception flag bit 0 and fixed genesis target/PoW limit to `000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`.
- Upgrade activation is height-based. The initial schedule contains only `(height=0, consensus_version=0, tx_version=0)`; no miner voting exists in v0. Later changes require explicit coordinated activation.
- There are no hard checkpoints beyond pinned genesis. Initial nodes are archival. A local deep-reorg safety pause cannot make valid higher-work history consensus-invalid.

Exact test/dev targets correspond approximately to `2^20` and `2^12` expected hashes respectively. The mainnet target MUST be selected from a documented reference-PoW benchmark and launch-hashrate assumption, not copied from another network or invented.

### 2.5 Ratified owner decision: genesis timestamp policy

Approved by the project owner on 2026-08-30:

- Testnet genesis timestamp is Unix `1788048000` (`2026-08-30T00:00:00Z`).
- Devnet genesis timestamp is Unix `1788048000` (`2026-08-30T00:00:00Z`).
- Mainnet genesis timestamp is the UTC start of the eventual public launch date. Its exact `u64` value MUST be approved and frozen together with the benchmark-derived mainnet targets before commitment/nonce generation.

Sharing a timestamp does not merge testnet/devnet identity: their network IDs, magic, HRPs, target/exception profiles, descriptors, and commitments differ.

Testnet/devnet genesis artifacts were subsequently generated and independently reproduced by the Python and C reference paths. Their commitments/nonces/PoW hashes/block IDs are recorded under `genesis/generated/`; mainnet remains gated.

### 2.6 Ratified owner decision: `OUT-LAUNCH-GATE-v0`

Approved by the project owner on 2026-08-31:

- Rust consensus implementation MAY begin against the frozen language-neutral specification and independently verified testnet/devnet manifests and vectors. Mainnet-only parameter fields MUST remain explicitly unset and MUST NOT be replaced by testnet/devnet or provisional values.
- This approval does not begin Rust implementation inside the present documentation/reference-tooling task.
- The mainnet launch mining profile and integer `H_LAUNCH` MUST be approved after sustained measurements of the intended launch miner or controlled fleet, including CPU/CUDA differential agreement where CUDA is used.
- An exact mainnet calendar date MUST NOT be selected merely to unblock development.
- Before the date is frozen, a public release-candidate testnet MUST complete at least 60 stable days; 90 stable days is the target. Consensus divergence, unresolved critical security defects, or invalid CPU/CUDA differential results prevent the interval from satisfying the gate.
- After the testnet and release gates pass, the owner SHOULD freeze the UTC launch date and complete mainnet descriptor 14 to 28 days before launch. The descriptor timestamp remains the UTC start of that approved date.

This is a release policy and implementation authorization, not a consensus field. Mainnet interoperability remains impossible until its exact descriptor and derived artifacts are frozen.

## 3. Recommended defaults requiring approval

The identifiers `P_*` are fields in the ratified genesis parameter manifest.

| Symbol / decision | Recommended default | Alternatives and tradeoffs | Approval / blocker |
|---|---|---|---|
| Network identity profile | Ratified as `OUT-ID-v0`; see section 2.1 | A new profile requires an explicit network/protocol decision | **Approved** |
| Monetary/economic profile | Ratified as `OUT-ECON-v0`; see section 2.2 | Changing supply, issuance, allocations, or fee semantics requires a new explicit consensus decision | **Approved** |
| Limits and timing profile | Ratified as `OUT-LIMITS-v0`; see section 2.3 | Changing a consensus bound/timestamp parameter requires an activated version or new network | **Approved** |
| State/PoW/upgrade profile | Ratified as `OUT-TECH-v0`; see section 2.4 | Mainnet target values remain benchmark-gated, not conceptually undecided | **Approved except exact mainnet targets** |
| `P_POW_LIMIT` | Owner-selected easiest 256-bit target, based on benchmark/security study | Any value without benchmark is arbitrary | **Blocks genesis and PoW** |
| `P_GENESIS_TARGET` | Equal to `P_POW_LIMIT` only for devnet; separately selected for public networks | Easier launch target reduces launch friction but may weaken early chain | **Blocks genesis** |
| Reorg/pruning/upgrade posture | Ratified in `OUT-TECH-v0`: archive-first, no hard checkpoints, local pause only, height activation | Proof format and later pruning implementation remain safely deferrable | **Approved** |
| Snapshot trust | Verify chain header/work to snapshot height plus snapshot body commitment and computed state root; optional signed catalogs are discovery hints only | Trusted checkpoint speeds bootstrap but changes trust assumptions | Owner approval before snapshot bootstrap |

## 4. Exact parameter manifest proposal

Owner approval SHOULD produce one reviewed manifest per network containing at least:

```text
chain_id[32]
network_id:u32
p2p_magic[4]
address_hrp:lowercase ASCII
initial_consensus_version:u16
recipient_v0_version:u8
recipient_v0_payload_len:u16
recipient_v0_semantics:u8
max_money:u64
max_memo_bytes:u16
max_reward_extra_bytes:u16
max_tx_bytes:u32
max_txs_per_block:u32
max_block_body_bytes:u32
max_p2p_payload_bytes:u32
max_snapshot_body_bytes:u64
max_genesis_descriptor_bytes:u32
max_genesis_accounts:u32
max_reward_segments:u16
max_upgrade_entries:u16
max_inv_entries:u16
max_locator_entries:u16
max_headers:u16
target_spacing:u64
retarget_window:u32
retarget_clamp_down_num:u32 / denominator:u32
retarget_clamp_up_num:u32 / denominator:u32
median_time_window:u16
max_future_drift:u64
pow_limit[32]
genesis_target[32]
reward_schedule:canonical height/rate segments
fee_semantics:u8
minimum_consensus_fee:u64
upgrade_schedule:canonical activation-height/version entries
network_exception_flags:u16
delayed_minimum_threshold:u64
genesis_timestamp:u64
initial_accounts:canonical sorted recipient/amount entries
```

Each network's final manifest encoding and commitment vector MUST be frozen before an implementation is called interoperable on that network. Testnet and devnet meet this gate. Mainnet final vector bytes cannot exist until its benchmark-gated values are approved.

## 5. Decisions that block mainnet activation

`OUT-LAUNCH-GATE-v0` authorizes Rust work against testnet/devnet while keeping mainnet fields unset. The remaining mainnet activation blockers are:

1. Mainnet PoW limit and genesis target selected from the documented reference benchmark and launch-hashrate assumption.
2. Exact mainnet launch timestamp.
3. The resulting complete mainnet descriptor, genesis commitment, PoW nonce/hash, block ID, and independent verification record.

## 6. Safely deferrable decisions

- State inclusion/non-inclusion proof wire format; the root algorithm itself is not deferrable.
- Mempool fee minimum, replacement, eviction, and reinsertion policies.
- RPC/JSON schema, wallet UI, display decimals, aliases, QR metadata, and mining-pool protocols.
- RocksDB versus redb selection, provided both satisfy the atomic interface.
- Snapshot transport, catalog discovery, signatures, and compression. Snapshot verification semantics are not deferrable if snapshot bootstrap is shipped.
- Pruned-node mode, provided the first release is archival and can service required reorgs.
- CUDA kernel organization and optimization.
- Peer discovery, reputation, and connection limits, except the hard frame/message bounds.

## 7. Required ratification record

Each approval MUST record: decision identifier, exact value/algorithm revision, approving owner, UTC date as human metadata, rationale, affected documents/vectors, and a content hash of the reviewed specification tree. Human dates and names are audit metadata and MUST NOT enter consensus unless explicitly included in the genesis descriptor.
