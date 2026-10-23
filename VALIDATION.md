# Fresh export validation — 2026-10-23

| Suite | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| out-primitives | 7 | 0 | 0 |
| out-codec | 12 | 0 | 0 |
| out-crypto | 7 | 0 | 0 |
| out-state | 6 | 0 | 0 |
| out-consensus | 43 | 0 | 0 |
| out-p2p | 31 | 0 | 0 |
| Total | 106 | 0 | 0 |

Executed against the staged original-source selection using Rust 1.98.0 (`rustc 1.98.0 (88d9e12ae 2026-08-18)`), locked offline Cargo resolution, cached dependencies, two build jobs and a 180-second command bound. No packages were installed or downloaded. Build artifacts stayed outside the source export. All exported Rust files passed an explicit `rustfmt --check --edition 2021` with the same installed toolchain.

```sh
cargo test --offline --locked --lib \
  -p out-primitives -p out-codec -p out-crypto \
  -p out-state -p out-consensus -p out-p2p -j 2
```

The first locked attempt stopped before compilation because excluding the wallet member required updating the lockfile. An offline refresh removed only unused packages. No new package/version or changed registry checksum was introduced. The subsequent locked run exited successfully with the results above. This is recorded as a packaging adjustment, not a passing first attempt.

The tests execute original codec, arithmetic, cryptography-integration, state, consensus and pure P2P/session code with synthetic fixtures. They are not mocks standing in for those routines. They do not establish exhaustive conformance, independent cryptographic review, full consensus correctness, financial safety or economic properties. No coverage percentage, benchmark or deployment result was measured.

Not freshly executed: storage/native-backend builds/tests, node/process/Unix-socket tests, standalone C/Python reference comparisons, CUDA work, wallet/keystore work, real-device qualification, peer networking, any HTTP/UI flow, live services or a blockchain deployment. The testnet/devnet fixtures describe development profiles, not evidence of a deployed testnet. Mainnet remains gated. Historical statements in retained documents remain historical; the source-only exclusions cannot be used to reproduce omitted private acceptance packets.
