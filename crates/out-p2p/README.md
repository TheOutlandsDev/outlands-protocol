> Export scope: dated verification statements below are historical. See [current export scope](../../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT P2P codec v0

`out-p2p` implements the exact inner frame and typed message bytes from `docs/wire-format-v0.md`. It is a pure, synchronous byte codec. It contains no sockets, ports, DNS, peer discovery, async runtime, daemon, transport encryption, service integration, or host-network configuration.

The decoder is deliberately two-stage. `decode_frame_header` consumes exactly the 54-byte header, validates network magic, protocol version, flags, mandatory type recognition, the global payload bound, and the smaller type-specific bound. A transport can therefore reject an attacker-controlled length before allocating or buffering the complete payload. `decode_frame_exact` then requires the exact declared payload length, validates the domain-separated checksum, and performs canonical typed decoding with complete consumption.

`Hello::require_identity` compares the chain ID, network ID, and genesis commitment independently so a session layer can treat any mismatch as fatal. `select_protocol_version` selects the greatest overlap and rejects invalid or disjoint ranges. Session ordering and timeouts remain transport policy; a transport MUST still require `HELLO`/`HELLO_ACK` completion before forwarding other decoded messages.

`session` provides that pure policy layer without performing transport I/O. It has explicit inbound/outbound handshake states, fatal identity and version checks, caller-supplied monotonic timeout and scoring parameters, bounded outstanding `PING`, `GET_HEADERS`, and exact single-object `GET_OBJECTS` correlation, deterministic timeout actions, and a header-sync gate that requires the caller to validate every nonempty batch through consensus before requesting the next batch. P2P v0 has no terminal marker for a multi-object response, so node policy deliberately emits exactly one object per request ID. Reject and timeout correlation is exact, while the application dispatcher still verifies the returned object identity and complete consensus validity. Invalid-header scoring occurs only after the caller reports a consensus failure; missing local history or storage failure MUST NOT be reported as peer misbehavior.

Only testnet and devnet magic are constructible in this implementation phase. Mainnet remains unavailable until its complete benchmark-gated genesis profile is ratified and added to the node.
