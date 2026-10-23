> Export scope: dated verification statements below are historical. See [current export scope](../../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT local operator protocol v0

This document specifies an operational Unix-domain IPC format implemented by `out-node`. It is not a consensus protocol, P2P protocol, wallet format, or mainnet parameter decision.

## Security and lifecycle

- The server binds a caller-selected Unix-domain socket path and MUST refuse any path that already exists.
- The created socket mode MUST be `0600`. The caller MUST place it in a directory writable only by the intended operator account.
- The authentication key is exactly 32 bytes and MUST NOT be all zero. It MUST be produced by a cryptographically secure random generator, provisioned through an already trusted local channel, never logged, and rotated for every server lifetime.
- The server keeps only the greatest authenticated request sequence in memory. A request sequence MUST be nonzero and strictly greater than the last accepted sequence. Restart resets this state, which is why key rotation at every restart is mandatory.
- Authentication MUST succeed before replay state changes or any command executes.
- A server call accepts exactly one connection, reads exactly one request, writes at most one response, and closes the connection. There is no implicit accept loop, retry, mining loop, clock sampling, or background task.
- Request and response tags MUST be compared in constant time.

## Stream envelope

The Unix byte stream prefixes each authenticated frame with one unsigned 16-bit big-endian frame length. The length does not include the two-byte prefix and MUST be between 50 and 16,512 inclusive. The receiver MUST reject a value above 16,512 before allocating the frame buffer. This ceiling accommodates one maximum-size 16,384-byte consensus transaction plus its operational envelope; it does not change the consensus transaction limit.

## Authenticated frame

All integers are unsigned and big-endian.

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `OUTO` |
| 4 | 1 | version | `0x00` |
| 5 | 1 | direction | request `0x00`; response `0x01` |
| 6 | 1 | command | inspect `1`, start `2`, refresh `3`, step `4`, cancel `5`, shutdown `6`, account `7`, submit transaction `8` |
| 7 | 1 | flags | MUST be zero |
| 8 | 8 | sequence | nonzero `u64` |
| 16 | 2 | payload length | exact payload byte count |
| 18 | variable | payload | command or reply payload |
| final 32 | 32 | authentication tag | BLAKE3 keyed hash |

The total frame length MUST equal `18 + payload_length + 32`; truncation, trailing bytes, unknown versions, wrong direction, nonzero flags, and mismatched lengths are rejected.

For a request, the tag is:

`BLAKE3_KEYED(key, ASCII("OUT/operator/request/v0") || frame_without_tag)`

For a response, the tag is:

`BLAKE3_KEYED(key, ASCII("OUT/operator/response/v0") || frame_without_tag)`

The domain bytes have no terminator or implicit length. `frame_without_tag` begins at the `OUTO` magic and ends at the final payload byte. The two-byte stream-envelope length is not part of the tag.

## Request payloads

Inspect, cancel, and shutdown have an empty payload. Step contains one `local_now: u64`.

Account contains exactly one 33-byte binary recipient (`0x00` plus a 32-byte Ed25519 public key). It is not Bech32m text. Unknown recipient versions and trailing bytes are rejected.

Submit transaction uses this exact layout:

| Order | Width | Field |
|---:|---:|---|
| 1 | 2 | transaction length |
| 2 | 0..16,384 | canonical signed regular-transaction bytes |

The transaction length MUST be at most the consensus `MAX_TX_BYTES` value of 16,384 and MUST equal the bytes present. The server decodes these bytes with the consensus exact decoder, which rejects truncation, trailing bytes, noncanonical forms, reward transactions, unknown mandatory fields, wrong network identity, and invalid signatures through the ordinary mempool admission path. The request never contains or accepts a private key.

Start and refresh use this exact layout:

| Order | Width | Field |
|---:|---:|---|
| 1 | 8 | candidate timestamp |
| 2 | 8 | caller local Unix time |
| 3 | 33 | binary recipient (`0x00` plus 32-byte Ed25519 public key) |
| 4 | 2 | reward-extra length |
| 5 | 0..100 | reward-extra bytes |
| 6 | 8 | first nonce |

The reward-extra length MUST be at most 100 and MUST equal the bytes present. The recipient version MUST be `0x00`. Unknown command tags are mandatory and rejected after successful authentication.

## Response payloads

The first response-payload byte is a reply tag:

| Tag | Meaning | Remaining payload |
|---:|---|---|
| 1 | inspected | mining-control status |
| 2 | started | job snapshot |
| 3 | refreshed | current replacement job snapshot |
| 4 | stepped | work outcome and submission summary |
| 5 | cancelled | optional removed job snapshot |
| 6 | shutdown requested | empty |
| 7 | account | canonical account status |
| 8 | transaction | mempool admission result |
| 255 | rejected | `u16` rejection code |

All optional values use a one-byte tag: absent `0`, present `1` followed by the value. Other option or boolean values are rejected.

A chain tip is `block_id[32] || height:u64 || cumulative_work[32]`. A job snapshot is `parent_tip || candidate_height:u64 || mempool_revision:u64 || next_nonce:u64 || total_attempts:u128 || optional_solution_block_id`. A status is `network:u8 || canonical_tip || mempool_revision:u64 || optional_job`, where testnet is `1` and devnet is `2`; mainnet has no value.

The step work tag and fields are:

| Tag | Outcome | Fields after tag |
|---:|---|---|
| 0 | idle | none |
| 1 | stale tip | expected tip, actual tip |
| 2 | stale mempool | expected revision `u64`, actual revision `u64` |
| 3 | progress | attempts `u64`, total attempts `u128`, next nonce `u64` |
| 4 | solution found | attempts `u64`, total attempts `u128`, block ID `[32]` |
| 5 | solution pending | total attempts `u128`, block ID `[32]` |
| 6 | nonce space exhausted | attempts `u64`, total attempts `u128` |

The work value is followed by optional submitted block ID, relay-cached boolean, announcements-queued `u16`, then optional backpressure. Present backpressure contains required `u16` and available `u16` announcement slots.

An account status is `canonical_tip || recipient[33] || exists:u8 || balance:u64 || nonce:u64`. The `exists` byte is exactly `0` or `1`. The status is read from the authoritative snapshot anchored at the returned canonical tip and never includes a mempool overlay. A nonexistent account returns `exists=0`, zero balance, and zero nonce. Duplicate account records or a missing/mismatched authoritative snapshot produce account-unavailable rather than a fabricated result.

A transaction admission begins with an admission tag followed by its transaction ID: accepted `1 || transaction_id[32] || canonical_bytes:u32`, already present `2 || transaction_id[32]`, or already confirmed `3 || transaction_id[32]`. Admission is non-consensus mempool state. Accepted bytes remain subject to ordinary full consensus validation if later included in a block, and mempool loss cannot affect balances or chain state.

Rejection codes are replay `1`, job already active `2`, job not active `3`, control unavailable `4`, candidate rejected `5`, mining failed `6`, undisclosed local failure `7`, invalid transaction `8`, transaction policy/capacity `9`, and account unavailable `10`. Internal storage or transport error details MUST NOT be serialized.

Every response MUST use the same sequence and command tag as its authenticated request. Unknown reply, work, network, option, boolean, and rejection tags are rejected. No field permits trailing bytes.

## Consensus separation

Mining commands request one operation from the already typed mining-control boundary. Account inspection reads only the authoritative canonical snapshot. Transaction submission invokes the frozen exact decoder and strict consensus admission routines, but the resulting mempool remains disposable and non-authoritative. Shutdown requests the existing bounded daemon drain path and does not bypass durable storage recovery. The protocol cannot define a block, transaction, signature, address, target, state transition, state root, cumulative-work value, or chain-selection rule. A mined solution still passes through ordinary full consensus validation and atomic storage. PostgreSQL, Redis, JSON, Serde, database iteration order, filesystem order, locale, and platform word size do not participate.
