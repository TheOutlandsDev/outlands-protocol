> Export scope: dated verification statements below are historical. See [current export scope](../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT canonical and wire format v0

Status: normative draft. Parameter symbols are exact once their owner-approved values are inserted; recommended unratified values are listed in `open-decisions.md`.

## 1. Primitive canonical codec

OUT v0 uses a positional binary codec. A decoder MUST receive both an input slice and an outer maximum before allocation. The specification defines bytes; Rust/C++/Python object layouts do not.

| Primitive | Encoding |
|---|---|
| `u8` | one unsigned octet |
| `u16` | exactly 2 octets, unsigned, big-endian |
| `u32` | exactly 4 octets, unsigned, big-endian |
| `u64` | exactly 8 octets, unsigned, big-endian |
| `U256` | exactly 32 octets, unsigned, big-endian, including leading zero octets |
| fixed bytes `[N]` | exactly `N` octets, no prefix |
| variable bytes `bytes16` | `u16` byte length followed by exactly that many octets |
| variable bytes `bytes32` | `u32` byte length followed by exactly that many octets |
| count vector | fixed-width count followed by exactly that many canonically encoded elements; no capacity/padding |
| boolean | absent from consensus v0; if later introduced, one octet `0x00` or `0x01` only |
| enum/tag | explicitly assigned unsigned integer of the documented width; never a language discriminant |

All multibyte OUT codec integers are big-endian. Ed25519's internal point/scalar encoding remains the standard's little-endian encoding and MUST NOT be byte-swapped by the OUT codec.

The following are forbidden in a consensus encoder or decoder: variable-width integers; signed integers for nonnegative fields; `usize`; native-endian values; floating point; Rust/C/C++ struct memory images; implicit padding; Serde, bincode, JSON, Protobuf, or ABI output; iteration over an unordered map/set; locale-sensitive text/number conversion; and implicit enum discriminants.

### 1.1 Canonicality and failure

- Every object MUST use exactly the field order shown. Fields are not self-describing.
- There are no optional fields in a v0 object unless a tagged variant explicitly says so. A sender MUST NOT append an absent/default field.
- Lengths and counts MUST use their specified fixed width. A parser MUST check the length/count against its limit and remaining input before allocating or iterating.
- A shorter input is `TRUNCATED` and invalid. A declared length greater than remaining bytes is `TRUNCATED`, even if it is also above a maximum; implementations SHOULD report the limit error first after safely reading the prefix, but validity is identical.
- A longer input is invalid: every object decoder MUST consume exactly the delimited bytes and reject trailing bytes.
- Positional objects cannot contain duplicate fields. A future tagged-field extension MUST sort tags ascending, reject duplicate tags, and follow the upgrade rule in section 8; no such extension is valid in v0.
- Reserved values and unknown mandatory tags are invalid. There is no “best effort” consensus decoding.
- Re-encoding any accepted object MUST reproduce byte-for-byte the accepted input.
- Malformed input MUST return an error and MUST NOT panic, abort, read out of bounds, exhaust memory based only on an asserted length, or create a partially accepted object.

### 1.2 Ratified v0 bounds (`OUT-LIMITS-v0`)

These symbols and values are ratified and MUST appear exactly in each v0 genesis parameter manifest.

| Bound | Candidate value | Applied before allocation |
|---|---:|---|
| `P_MAX_MEMO_BYTES` | 256 | regular transaction memo |
| `P_MAX_REWARD_EXTRA_BYTES` | 100 | reward extra data |
| `P_MAX_TX_BYTES` | 16,384 | complete transaction envelope |
| `P_MAX_TXS_PER_BLOCK` | 8,192 | transaction count; conservative pre-allocation cap |
| `P_MAX_BLOCK_BODY_BYTES` | 2,097,152 | canonical block body |
| `P_MAX_BLOCK_BYTES` | `230 + P_MAX_BLOCK_BODY_BYTES` | complete block envelope |
| `P_MAX_P2P_PAYLOAD_BYTES` | 4,194,304 | frame payload; MUST be at least `P_MAX_BLOCK_BYTES` |
| `P_MAX_GENESIS_DESCRIPTOR_BYTES` | 65,536 | complete descriptor; bootstrap parser obtains this cap from reviewed local network profile |
| `P_MAX_GENESIS_ACCOUNTS` | 0 | no-allocation genesis |
| `P_MAX_REWARD_SEGMENTS` | 30 | exact ratified reward schedule entries |
| `P_MAX_UPGRADE_ENTRIES` | 256 | activation schedule entries |
| `P_MAX_SNAPSHOT_BODY_BYTES` | 68,719,476,736 | optional canonical snapshot body; streaming required |
| `P_MAX_INV_ENTRIES` | 2,048 | inventory message |
| `P_MAX_LOCATOR_ENTRIES` | 128 | locator request |
| `P_MAX_HEADERS` | 2,000 | headers response |
| Bech32m text | 90 ASCII characters | address decoder |

Every individual P2P message also has the smaller semantic maximum stated in section 7.

## 2. Binary recipients and Bech32m addresses

Human address text is never present in a transaction, block, state leaf, signature preimage, or account key.

### 2.1 Binary recipient

The ratified v0 recipient is exactly 33 octets:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | `address_version`; v0 value `0x00` |
| 1 | 32 | `payload`; strict canonical Ed25519 verification-key encoding |

The payload size/meaning was ratified in `OUT-ID-v0`. An unknown address version in a consensus recipient is invalid, not an anyone-can-spend account. A display-only decoder MAY identify an unknown version, but MUST NOT present it as spendable or create a v0 transaction to it.

For v0 raw-key recipients, a regular transaction's sender recipient MUST equal `0x00 || auth.public_key[32]`. The strict public-key rules apply before this comparison.

### 2.2 Text address

The ratified lowercase HRPs are mainnet `out`, testnet `tout`, and devnet `dout`. An HRP has length 1 through 30 and contains only characters `33..126`, excluding `1` and uppercase letters. The total address MUST be at most 90 ASCII characters.

Encoding is:

```text
recipient = address_version:u8 || payload[32]
data5 = convert_bits(recipient, from=8, to=5, pad=true)
address = lowercase_hrp || "1" || bech32_charset(data5 || checksum6)
checksum variant = Bech32m, constant 0x2bc830a3
```

`convert_bits` reads a left-to-right bit stream, most-significant bit first within each input octet, emits consecutive 5-bit values, and zero-pads only the final incomplete 5-bit group. Decoding MUST verify that the reconstructed final padding has fewer than 5 bits and all padding bits are zero; it MUST reconstruct exactly 33 octets. Nonzero or excess padding is noncanonical.

Decoders MUST reject: wrong HRP for the selected network; missing/multiple separator; invalid character; checksum other than Bech32m; uppercase or mixed-case input; length over 90; wrong reconstructed size; noncanonical padding; unsupported version; or a v0 payload that is not a strict acceptable Ed25519 public key. Canonical rendering is lowercase only. The checksum functions and alphabet are exactly those of Bech32m; OUT does not copy the witness-version rules of the source protocol.

Conversion to consensus is deterministic: decode and validate text, then return the 33-byte recipient. Conversion to text takes a selected network HRP plus the 33-byte recipient. HRP is not part of the account identifier, but the selected network identity is already committed in transactions and signatures.

## 3. Transaction formats

### 3.1 Transaction envelope

| Order / offset | Size | Field | Rule |
|---|---:|---|---|
| 1 / 0 | 1 | `envelope_codec` | MUST be `0x00` |
| 2 / 1 | 1 | `tx_kind` | `0x00` regular, `0x01` reward; other invalid |
| 3 / 2 | 4 | `body_len` | big-endian; exact remaining body length |
| 4 / 6 | `body_len` | `body` | exact kind-specific canonical body |
| 5 | 2 | `auth_len` | exact authorization-section length |
| 6 | `auth_len` | `auth` | regular: exactly 98; reward: exactly 0 |

The total from offset 0 through auth MUST be `<= P_MAX_TX_BYTES`. Before allocating the body, a decoder MUST require `body_len <= P_MAX_TX_BYTES - 8` and `body_len <= remaining - 2` using checked arithmetic. It then reads `auth_len`, checks the kind-specific exact value and total, and rejects trailing bytes.

### 3.2 Regular transaction body (`tx_kind = 0x00`)

| Order | Size | Field | Rule |
|---:|---:|---|---|
| 1 | 2 | `tx_version` | MUST be version active at containing height; initial `0x0000` |
| 2 | 32 | `chain_id` | exact selected network parameter |
| 3 | 4 | `network_id` | exact selected network parameter |
| 4 | 32 | `genesis_commitment` | exact selected network commitment |
| 5 | 33 | `sender` | supported binary recipient |
| 6 | 8 | `nonce` | exact next account nonce |
| 7 | 33 | `recipient` | supported binary recipient |
| 8 | 8 | `amount` | base units, `u64`; MUST be `> 0` under `OUT-ECON-v0` |
| 9 | 8 | `fee` | base units, `u64`; paid in full under `OUT-ECON-v0` |
| 10 | 8 | `valid_from_height` | first valid height, inclusive |
| 11 | 8 | `expires_at_height` | last valid height, inclusive |
| 12 | 2 | `memo_len` | `<= P_MAX_MEMO_BYTES` |
| 13 | `memo_len` | `memo` | uninterpreted bytes; no Unicode normalization |

The fixed portion is 178 octets. `valid_from_height <= expires_at_height` MUST hold. A containing block height MUST lie in that closed interval. Empty memo is canonical as `memo_len = 0` and no bytes. Amount and fee semantics are ratified in `OUT-ECON-v0` and `state-model-v0.md`.

### 3.3 Regular authorization section

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | `auth_version` | MUST be `0x00` |
| 1 | 1 | `signature_scheme` | MUST be `0x00` (strict Ed25519) |
| 2 | 32 | `public_key` | strict canonical Ed25519 key |
| 34 | 64 | `signature` | strict canonical Ed25519 signature |

The section is exactly 98 octets. No multisignature, recovery ID, context string, or extra bytes exist in v0.

### 3.4 Reward body (`tx_kind = 0x01`)

| Order | Size | Field | Rule |
|---:|---:|---|---|
| 1 | 2 | `tx_version` | active version; initial `0x0000` |
| 2 | 32 | `chain_id` | selected network |
| 3 | 4 | `network_id` | selected network |
| 4 | 32 | `genesis_commitment` | selected network |
| 5 | 8 | `height` | equals containing block height |
| 6 | 33 | `recipient` | miner/reward recipient |
| 7 | 8 | `subsidy` | exactly scheduled subsidy |
| 8 | 8 | `fees` | exact checked sum of regular fees |
| 9 | 2 | `extra_len` | `<= P_MAX_REWARD_EXTRA_BYTES` |
| 10 | `extra_len` | `extra` | uninterpreted miner bytes |

The fixed portion is 129 octets. The envelope `auth_len` MUST be zero. A reward transaction is not signed, is invalid outside index 0 of a non-genesis block, and MUST occur exactly once. Its transaction ID commits to its complete envelope.

### 3.5 Signing and transaction identity

Let `body` be the exact regular body bytes and `BE32(n)` the 4-byte big-endian encoding. The signing key material is:

```text
0x00                         signing-preimage version
|| 0x00                     envelope_codec
|| 0x00                     regular tx_kind
|| BE32(len(body))
|| body
```

`signing_digest = OUT_HASH(TX_SIGN_CONTEXT, signing_key_material)` and pure Ed25519 signs exactly those 32 digest octets. The body contains chain ID, network ID, and genesis commitment, so signatures cannot replay across correctly configured networks. Neither `auth_len` nor authorization bytes are signed.

For every kind, `tx_id = OUT_HASH(TX_ID_CONTEXT, complete_canonical_transaction_envelope)`. Thus malleating an authorization would change the ID, but strict/canonical authorization rules admit no alternate accepted representation for the same signed body.

## 4. Block formats

### 4.1 Fixed block header

The canonical header is exactly 223 octets:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | `header_codec` | `0x00` |
| 1 | 2 | `consensus_version` | active at `height` |
| 3 | 32 | `chain_id` | selected network |
| 35 | 4 | `network_id` | selected network |
| 39 | 32 | `genesis_commitment` | selected network |
| 71 | 8 | `height` | genesis 0; otherwise parent height + 1 checked |
| 79 | 32 | `parent_block_id` | genesis all zero; otherwise exact parent ID |
| 111 | 8 | `timestamp` | unsigned Unix seconds, UTC semantics |
| 119 | 32 | `target` | full big-endian U256; no compact form |
| 151 | 32 | `tx_root` | transaction Merkle root |
| 183 | 32 | `state_root` | post-block account-state root |
| 215 | 8 | `nonce` | PoW nonce, big-endian in bytes |

Unix seconds are an integer count; leap seconds, time zones, locale, and calendar rendering never affect validation. Target is always a full 32-byte integer, deliberately avoiding noncanonical compact target encodings.

`block_id = OUT_HASH(BLOCK_ID_CONTEXT, header[223])`. `pow_hash` uses a different domain context over the same exact header bytes as specified in `pow-v0.md`.

### 4.2 Block body

| Order | Size | Field | Rule |
|---:|---:|---|---|
| 1 | 1 | `body_codec` | `0x00` |
| 2 | 4 | `tx_count` | `1..=P_MAX_TXS_PER_BLOCK` for non-genesis |
| 3 | repeated | entries | `tx_len:u32 || transaction[tx_len]` |

Each `tx_len` MUST be between 1 and `P_MAX_TX_BYTES`, fit in the remaining body, and equal the bytes consumed by exactly one canonical envelope. The entire body MUST be `<= P_MAX_BLOCK_BODY_BYTES`. The first transaction MUST be the sole reward transaction; all others MUST be regular. Genesis-body rules are in `consensus-v0.md` and may use zero transactions only if the ratified genesis descriptor explicitly selects that form.

### 4.3 Complete block envelope

| Offset/order | Size | Field | Rule |
|---|---:|---|---|
| 0 | 1 | `block_codec` | `0x00` |
| 1 | 2 | `header_len` | MUST equal 223 |
| 3 | 223 | `header` | exact header above |
| 226 | 4 | `body_len` | `<= P_MAX_BLOCK_BODY_BYTES` |
| 230 | `body_len` | `body` | exact canonical body |

The envelope MUST consume all delimited bytes and be `<= P_MAX_BLOCK_BYTES = 230 + P_MAX_BLOCK_BODY_BYTES`.

## 5. Transaction Merkle commitment

For `n` transactions, non-genesis blocks require `1 <= n <= P_MAX_TXS_PER_BLOCK`. Let `m` be the smallest power of two `>= n`; checked calculation MUST reject overflow.

For leaf position `i` (`u32`, zero based):

```text
if i < n:
  L[i] = OUT_HASH(TX_MERKLE_LEAF_CONTEXT,
                  0x00 || 0x01 || BE32(i) || tx_id[i])
else:
  L[i] = OUT_HASH(TX_MERKLE_LEAF_CONTEXT,
                  0x00 || 0x00 || BE32(i))
```

The first byte is the Merkle format version; the second is occupied (`1`) or padding (`0`). Padding leaves do not duplicate a transaction. At level `level = 1` above leaves and upward:

```text
N[level,j] = OUT_HASH(TX_MERKLE_NODE_CONTEXT,
                      0x00 || BE16(level) || left[32] || right[32])
```

Pair consecutive nodes left then right. The single result is `tx_root`. For `n=1`, the root is the occupied leaf itself. A ratified zero-transaction genesis uses `OUT_HASH(TX_MERKLE_LEAF_CONTEXT, 0x00 || 0x02 || BE32(0))`; tag `0x02` is reserved solely for that empty-genesis root. Duplicate transaction IDs within one block are consensus-invalid even though their indexed leaves differ.

## 6. Canonical genesis/snapshot record encodings

The exact genesis descriptor and snapshot hashing preimages are specified in `consensus-v0.md` and `state-model-v0.md`. Their variable lists use `u32` count, fixed-size entries, ascending bytewise key order, a checked total maximum determined before launch, and no maps.

## 7. Custom P2P protocol v0

P2P transport is non-consensus, but framing is exact to prevent cross-network confusion and parser disagreement. A peer MUST complete `HELLO`/`HELLO_ACK` before other messages. Encryption/authentication and peer discovery are deferred; deployment SHOULD add a reviewed secure transport without changing inner frames.

### 7.1 Frame header

Every frame starts with exactly 54 octets:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | `network_magic` | owner-approved exact network value |
| 4 | 2 | `protocol_version` | sender's selected P2P version; v0=`0x0000` candidate |
| 6 | 2 | `message_type` | explicit values below |
| 8 | 2 | `flags` | MUST be zero in v0 |
| 10 | 8 | `request_id` | zero for unsolicited; echoed by response |
| 18 | 4 | `payload_len` | checked before allocation |
| 22 | 32 | `payload_checksum` | P2P checksum hash of payload |

`payload_checksum = OUT_HASH(P2P_MESSAGE_CONTEXT, BE16(protocol_version) || BE16(message_type) || BE64(request_id) || BE32(payload_len) || payload)`. Frame bytes are header then exactly `payload_len` octets. No compression, multiplexing, or trailing bytes exist in v0. Receivers MUST reject wrong magic, unsupported negotiated version, nonzero flags, oversize/type-oversize payload, checksum mismatch, truncated payload, or trailing bytes in the typed payload. Length limits MUST be enforced before buffering the complete payload.

Types `0x0000..0x7fff` are mandatory semantics: an unknown value terminates the protocol session. Types `0x8000..0xffff` are ignorable extensions: a receiver MAY discard an unknown frame after its safely bounded checksum is validated. An ignorable type can never carry consensus objects whose processing is required for synchronization.

### 7.2 Message types and payload layouts

| Type | Name | Payload and semantic maximum |
|---:|---|---|
| `0x0001` | `HELLO` | exact fixed layout below, 116 bytes |
| `0x0002` | `HELLO_ACK` | same 116-byte layout |
| `0x0003` | `PING` | `token:u64`, exactly 8 |
| `0x0004` | `PONG` | echoed `token:u64`, exactly 8 |
| `0x0010` | `INV` | `count:u16` then `count` entries `(kind:u8, id[32])`; count `<= P_MAX_INV_ENTRIES`; kind 0 tx, 1 block |
| `0x0011` | `GET_OBJECTS` | same entry layout/bound as `INV` |
| `0x0012` | `TX` | exactly one canonical transaction, `<= P_MAX_TX_BYTES` |
| `0x0013` | `BLOCK` | exactly one canonical block, `<= P_MAX_BLOCK_BYTES` |
| `0x0020` | `GET_HEADERS` | `count:u16` (`1..=P_MAX_LOCATOR_ENTRIES`) + block IDs + `stop_id[32]` (zero means none) |
| `0x0021` | `HEADERS` | `count:u16` (`<=P_MAX_HEADERS`) + exactly `count * 223` header bytes |
| `0x007f` | `REJECT` | `rejected_type:u16 || code:u16 || detail_len:u16 || detail`; detail max 256 and operational only |

`HELLO` layout:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 2 | `min_protocol_version` |
| 2 | 2 | `max_protocol_version` |
| 4 | 2 | `min_consensus_version` |
| 6 | 2 | `max_consensus_version` |
| 8 | 32 | `chain_id` |
| 40 | 4 | `network_id` |
| 44 | 32 | `genesis_commitment` |
| 76 | 8 | `best_height` |
| 84 | 32 | `best_block_id` |

Peers select the greatest mutually supported P2P version. A mismatch in any identity field is fatal. Advertised height/work is untrusted. Text user-agent strings, ports, wall-clock time, and database details are intentionally absent.

Inventory duplication, ordering, request timeouts, peer scoring, mempool admission, and unsolicited transaction relay are non-consensus policy. Typed payload decoders still MUST reject duplicate inventory entries and trailing bytes to maintain one canonical message representation.

## 8. Versioning and extensions

- Codec/header/envelope version changes alter parsing and require an activated consensus version.
- Consensus version is selected solely by the owner-ratified height schedule committed at genesis or by a prior valid upgrade. Unknown or inactive consensus versions make a block invalid.
- A decoder MUST NOT infer a format from length, attempt legacy fallbacks, or reinterpret failed v0 bytes as another version.
- New mandatory fields require a new object codec or tagged variant. They MUST NOT be appended to a v0 object.
- New transaction kinds or authorization schemes require consensus activation. Unknown kinds/schemes are invalid.
- P2P versions are negotiated independently and cannot make an invalid consensus object valid.
- An implementation MAY preserve unknown ignorable P2P extension frames for diagnostics, but MUST NOT pass them into consensus.
