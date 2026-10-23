> Export scope: dated verification statements below are historical. See [current export scope](../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT proof of work v0

Status: normative and ratified by `OUT-LIMITS-v0` and `OUT-TECH-v0`, except the exact mainnet PoW limit and genesis target, which remain benchmark-gated.

Ratified shared parameters are `P_TARGET_SPACING=60`, `P_RETARGET_WINDOW=720`, proportional span clamps `1/4` and `4/1`, `P_MEDIAN_TIME_WINDOW=11`, and `P_MAX_FUTURE_DRIFT=7,200`, all in seconds/blocks as their field names specify.

## 1. PoW function

OUT PoW v0 is intentionally the independently specified BLAKE3 construction below. It is not defined by a CUDA kernel.

```text
header_bytes = canonical 223-byte block header, including nonce
pow_hash[32] = OUT_HASH(
  "OUT Consensus v0 2026-08-30 proof of work header",
  header_bytes)
pow_value = unsigned_integer_from_32_bytes_big_endian(pow_hash)
valid_pow = (pow_value <= target)
```

The context is passed to BLAKE3 `derive_key` exactly as specified in `consensus-v0.md`. There is no additional prefix, double hash, salt, per-device seed, endian reversal, memory-hard phase, compact target, floating-point difficulty, or hidden nonce transform.

Header nonce is a `u64` encoded big-endian at header offsets 215–222. Miners iterate any nonce order they choose, but validation hashes the exact header bytes. On nonce-space exhaustion miners MAY change reward `extra`, reward recipient, timestamp subject to rules, transaction set/order, or another committed header field by reconstructing a valid block; none changes the PoW definition.

## 2. Target representation and comparison

Target is exactly the 32-byte header field interpreted as an unsigned 256-bit big-endian integer. Leading zero bytes are required where numerically applicable; because width is fixed, there is exactly one encoding for every target. No compact representation exists in v0.

A target is structurally valid only when:

```text
1 <= target <= P_POW_LIMIT < 2^256
target == required_target(candidate_height, candidate_timestamp, parent_branch)
```

`P_POW_LIMIT` is the easiest permitted target (largest integer) and MUST be nonzero. Target zero, target above the limit, or any target other than the exact required value makes the block invalid before PoW comparison. Implementations MUST compare unsigned U256 values, not lexicographic hex text, signed integers, floats, or host limbs. Raw 32-byte lexicographic comparison is equivalent only if both arrays are fixed-size big-endian and MUST be tested against numeric comparison.

The validity comparison is inclusive (`pow_value <= target`). A hash exactly equal to target is valid.

## 3. Exact per-block work and cumulative work

Using mathematical integers with an intermediate capable of representing `2^256`:

```text
work(target) = floor((2^256 - 1) / (target + 1)) + 1
```

This yields at least 1. Division is unsigned Euclidean floor division. An implementation MAY use an algebraically equivalent tested U256 routine, but golden/boundary vectors MUST prove equivalence at target 1, `P_POW_LIMIT`, powers of two ±1, and limb boundaries. Floating-point/logarithmic “difficulty” MUST NOT be used for work.

```text
cumulative_work(genesis) = work(genesis.target)
cumulative_work(block) = checked_U256_add(cumulative_work(parent), work(block.target))
```

Cumulative-work addition MUST use checked unsigned 256-bit arithmetic. Overflow makes the candidate block consensus-invalid; it MUST NOT wrap, saturate, truncate, switch to float, or depend on build mode. Before launch, owners MUST prove from minimum work, target schedule bounds, and intended protocol lifetime that overflow is unreachable in practice. A later migration to a wider committed type requires an activated consensus version.

## 4. Timestamp rules

Header timestamp is unsigned Unix time in whole seconds. It has no time zone, locale, leap-second table, or subsecond component.

For a non-genesis candidate, collect up to `P_MEDIAN_TIME_WINDOW` timestamps by starting at the parent and following parents, including the parent. Sort the unsigned `u64` values ascending. With `n` collected values, median-time-past (`MTP`) is `sorted[floor(n/2)]` using zero-based indexing; for the early even-sized history this is the upper median. `OUT-LIMITS-v0` ratifies the odd full window as 11.

The candidate MUST satisfy:

```text
candidate.timestamp > MTP(parent)
candidate.timestamp <= local_now_unix_seconds + P_MAX_FUTURE_DRIFT
```

The future-bound addition is checked in a wider unsigned integer. If it exceeds `u64::MAX`, the upper bound is mathematically above every encodable timestamp; implementations MUST NOT wrap. `local_now` is sampled as Unix seconds from the node clock. A block failing only the future bound is temporarily unacceptable and MUST NOT be permanently cached as invalid; it may become acceptable as time advances. Different clock skew may change when a block is admitted, but never its eventual historical validity once below the bound. Operators SHOULD monitor clock synchronization.

Failure of `timestamp > MTP` is permanently consensus-invalid. Individual timestamps need not strictly increase relative to the direct parent, which is why retarget span handles nonpositive endpoint deltas explicitly.

Genesis timestamp is exactly the descriptor value.

## 5. Ratified epoch retarget algorithm

This section is exact and ratified in `OUT-TECH-v0`.

Let:

```text
W = P_RETARGET_WINDOW, W >= 2
S = P_TARGET_SPACING, S >= 1
epoch(h) = floor(h / W)
```

All ordinary blocks in an epoch share one computed `epoch_target`, except a precisely enabled delayed-testnet special block in section 6.

```text
epoch_target(0) = P_GENESIS_TARGET

epoch_target(e), e >= 1:
  first_height = (e - 1) * W              # checked u64
  last_height  = e * W - 1                # checked u64
  first_ts = timestamp(block[first_height])
  last_ts  = timestamp(block[last_height])

  expected = (W - 1) * S                  # exact checked wide integer
  raw_actual = (last_ts > first_ts) ? (last_ts - first_ts) : 1

  lower = ceil(expected * DOWN_NUM / DOWN_DEN)
  upper = floor(expected * UP_NUM / UP_DEN)
  require denominators != 0 and 1 <= lower <= upper
  actual = min(max(raw_actual, lower), upper)

  previous = epoch_target(e - 1)
  candidate = floor(previous * actual / expected)
               # exact nonnegative integer; multiplication uses >=512 bits
  if candidate < 1: candidate = 1
  if candidate > P_POW_LIMIT: candidate = P_POW_LIMIT
  return U256(candidate)
```

Ratified clamps are `DOWN_NUM/DOWN_DEN = 1/4` and `UP_NUM/UP_DEN = 4/1`. `ceil(a/b)` is `(a + b - 1)/b` using checked wide arithmetic; floor is Euclidean integer division. The descriptor MUST be rejected if any parameter calculation overflows its specified representation, yields zero expected span, produces invalid clamp order, or if `P_GENESIS_TARGET > P_POW_LIMIT`.

For a normal network:

```text
required_target(h) = epoch_target(epoch(h))
```

The candidate at height `e*W` computes epoch `e` solely from already-valid prior-epoch blocks, so no circular timestamp/target dependency exists. Retarget uses actual header timestamps after their MTP validation, including any prior testnet special blocks, but uses the previous epoch's computed base target—not whichever special target appeared in a header.

All height/time/window arithmetic is checked. Missing historical headers is a local failure, not an invalid target. Implementations MAY cache epoch targets only after recomputing/verifying them; cache loss cannot change results.

## 6. Network-specific exceptions

The genesis descriptor has mutually exclusive exception flags. A descriptor setting both is invalid.

### 6.1 Mainnet: no exception

Mainnet exception flags are zero and it uses the epoch algorithm exactly. Mainnet `P_POW_LIMIT` and `P_GENESIS_TARGET` MUST remain unset until the reference benchmark and launch-hashrate assumption are approved.

### 6.2 Development fixed target (flag bit 0)

Devnet fixes both `P_GENESIS_TARGET` and `P_POW_LIMIT` to big-endian hex `000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`. For every height, `required_target = P_GENESIS_TARGET`. Timestamp and PoW comparison still apply. Retarget parameters remain encoded/validated for descriptor stability but are not used. A dev block cannot replay on another network.

### 6.3 Delayed test minimum difficulty (flag bit 1)

Testnet fixes both genesis target and PoW limit to big-endian hex `00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` and `P_DELAYED_MINIMUM_THRESHOLD=1,200`. First compute `base = epoch_target(epoch(h))`. Then:

```text
if candidate.timestamp > parent.timestamp + P_DELAYED_MINIMUM_THRESHOLD:
    required_target = P_POW_LIMIT
else:
    required_target = base
```

The parent addition uses checked wide arithmetic. Equality at the threshold does not trigger the exception. The exception applies only to that candidate block; a following timely block returns to its epoch base without scanning header targets. Epoch retarget endpoint timestamps still include special blocks. `P_DELAYED_MINIMUM_THRESHOLD` MUST be positive when enabled and zero when disabled.

These exceptions are ratified only for the distinct `OUT-ID-v0` testnet/devnet identities. No node may infer a network from a name or silently enable an exception from a command-line convenience flag.

## 7. Validation pseudocode

```text
verify_pow_header(header, parent_branch, local_now, params):
  require canonical 223-byte encoding
  require exact network identity and active consensus version

  if header.height == 0:
    require header bytes equal pinned genesis header bytes
    required = params.genesis_target
  else:
    require parent exists and header.height == checked(parent.height + 1)
    require header.timestamp > median_time_past(parent_branch)
    require header.timestamp <= wide(local_now) + params.future_drift
    required = compute_required_target(header.height,
                                       header.timestamp,
                                       parent_branch,
                                       params)

  require 1 <= header.target <= params.pow_limit
  require header.target == required

  digest = blake3_derive_key_exact(POW_CONTEXT, header.bytes, output=32)
  value = U256_from_big_endian(digest)
  require value <= header.target

  w = exact_work(header.target)
  cw = (height == 0) ? w : checked_U256_add(parent.cumulative_work, w)
  require no overflow
  return (digest, w, cw)
```

Target/difficulty failure and failed hash comparison are consensus-invalid. Missing parent/window header, corrupted local chain metadata, or resource/I/O failure is local/unclassified.

## 8. CPU reference and CUDA equivalence

The CPU reference implementation MUST be a straightforward implementation of canonical header encoding, BLAKE3 `derive_key`, big-endian U256 conversion, exact target comparison, work, and retarget arithmetic. It MUST publish intermediate test vectors: header bytes, context bytes, derive-key output, numeric hash limbs in a specified diagnostic order, target, compare result, work, and cumulative work.

Any CUDA implementation MUST, for every 223-byte header, return exactly the same 32 digest octets and valid/invalid comparison as CPU. CUDA MUST NOT substitute ordinary BLAKE3 hash/keyed mode, reverse digest words, change chunk/finalization flags, prehash a partial header differently, omit derive-key context processing, use device floating point, truncate target limbs, or rely on undefined overflow.

Required differential testing includes:

- zero/all-ones/alternating nonce and every single-byte nonce position;
- headers spanning BLAKE3 block/chunk boundaries as exercised by the fixed 223-byte size;
- target equality and one below/above;
- digest leading zeros and high-bit set;
- U256 limb boundaries and retarget products near maximum;
- randomized headers on every supported CPU/GPU path;
- multiple CUDA grid/block sizes and batch orderings;
- release/debug and endian-emulated reference checks.

If CPU and CUDA disagree, the candidate result MUST be rejected by the node/miner integration and the implementation treated as faulty. CPU is the reference behavior only because it is simpler to audit; the normative behavior remains this document.
