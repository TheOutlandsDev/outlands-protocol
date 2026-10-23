# Provenance and attribution

The original project was commissioned as an original account-based proof-of-work specification and subsequently developed into this Rust implementation with AI assistance. The review examined the owner-controlled workspace and the original development records, rather than treating the earlier public overview as implemented software. Creation/update calls for every exported crate file were found in those records. Some historical byte-for-byte patch reconstructions are incomplete because formatting and other edits occurred between recorded patches; the review does not claim a complete per-line authorship reconstruction.

The owner reports originating the ideas, using AI for faster coding/testing/debugging, and owning the files. That attestation, the file-level source/development review and retained attribution support this selected release. They are not an independent legal originality guarantee or a claim of unaided implementation. Private session records, personal Git identities and original source history remain outside this export.

[SOURCE-MAP.json](SOURCE-MAP.json) records each selected original path, original/export SHA-256, byte count and transformation. Rust implementation bytes are unchanged. New export documentation explains the selection and fresh validation. The private owner review packet separately records a disposition for every original file, including exclusions; it is not included here.

OUT does not claim authorship of the cryptographic primitives, database engines, arithmetic libraries or standards it uses. Relevant foundations include:

- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3): upstream hash implementation, used through the `blake3` dependency.
- [Ed25519 / RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): signature algorithm, used through the Dalek libraries with OUT-specific validation checks.
- [Bech32m / BIP 350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki): referenced by the broader OUT address specification; the wallet implementation is excluded.
- redb, RocksDB, crypto-bigint, Dalek and their transitive dependencies: see [dependency inventory](DEPENDENCIES.md). Their code and binaries are not bundled in this source export.

The original standalone reference tooling contains official BLAKE3 C files and license/notice material. That entire tooling/vendor subtree is excluded rather than relabeled as original OUT code; its originals and notices remain intact privately. No third-party implementation was rewritten to conceal its origin. No employer/client, paid/restricted, game/recipe or unrelated project material was selected.

Existing `MIT OR Apache-2.0` package metadata remains unchanged. No new license file or repository-wide license grant is assigned by this export. Dependency license expressions are informational upstream metadata, not a relicense of those packages. Before distributing dependency code or compiled binaries, satisfy the actual upstream notice/license requirements for that distribution; the present review covers this source-only selection.
