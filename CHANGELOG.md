# Changelog

## [Unreleased]

## [0.3.0] — 2026-07-14

### Changed

- **Curve abstraction**: the entire crypto backend is now generic over an `EcOperation` trait, so any curve with a compatible `eccoxide` implementation can be used. ([3c4a3ff](https://github.com/vincenthz/rust-pvss/commit/3c4a3ff), [902e3b4](https://github.com/vincenthz/rust-pvss/commit/902e3b4))
- **Hash-to-curve**: generators are now produced via hash-to-curve so their discrete logarithms are unknown, improving security assumptions. ([698e362](https://github.com/vincenthz/rust-pvss/commit/698e362))
- **Fiat–Shamir strengthening**: both DLEQ and PDLEQ now hash g1/g2 into the challenge and use a domain separator. ([e217aa5](https://github.com/vincenthz/rust-pvss/commit/e217aa5), [2915bee](https://github.com/vincenthz/rust-pvss/commit/2915bee))
- **Dependency update**: `eccoxide` bumped to 0.4; OpenSSL backend removed entirely. ([1975b02](https://github.com/vincenthz/rust-pvss/commit/1975b02), [1536a96](https://github.com/vincenthz/rust-pvss/commit/1536a96))
- **Edition**: moved to Rust 2024 edition. ([e3cdeb2](https://github.com/vincenthz/rust-pvss/commit/e3cdeb2))
- **Performance**: test suite reduced to a smaller set of share sizes for faster CI. ([843db8a](https://github.com/vincenthz/rust-pvss/commit/843db8a))
- **CI**: migrated to newer GitHub Actions (checkout@v6). ([3035575](https://github.com/vincenthz/rust-pvss/commit/3035575), [b04b74f](https://github.com/vincenthz/rust-pvss/commit/b04b74f))
- **Copyright** line updated. ([64b0d72](https://github.com/vincenthz/rust-pvss/commit/64b0d72))

## [0.2.0] — 2023-08-12

### Added

- **`eccoxide` as primary crypto backend**, replacing the earlier dual OpenSSL / Rust backend. ([3f8a85e](https://github.com/vincenthz/rust-pvss/commit/3f8a85e))
- Explicit `Drg` parameter throughout the API (instead of implicit system randomness sourcing). ([69c2a9c](https://github.com/vincenthz/rust-pvss/commit/69c2a9c))
- Generator regeneration so its DL is unknown via hash-to-curve. ([698e362](https://github.com/vincenthz/rust-pvss/commit/698e362))

### Changed

- Migrated to Rust 2021 edition. ([f88afaf](https://github.com/vincenthz/rust-pvss/commit/f88afaf))
- Various arithmetic and cloning optimizations in `dleq` and `pdleq`. ([8104b5f](https://github.com/vincenthz/rust-pvss/commit/8104b5f), [8a852c8](https://github.com/vincenthz/rust-pvss/commit/8a852c8), [64495bc](https://github.com/vincenthz/rust-pvss/commit/64495bc))
- Removed commented-out code and stale Clone impls. ([2ee64d7](https://github.com/vincenthz/rust-pvss/commit/2ee64d7), [5417067](https://github.com/vincenthz/rust-pvss/commit/5417067))
- Travis CI removed in favour of GitHub Actions. ([8fb2533](https://github.com/vincenthz/rust-pvss/commit/8fb2533))
- License metadata cleaned up (Apache license reference removed). ([1622ec0](https://github.com/vincenthz/rust-pvss/commit/1622ec0))

## [0.1.1] — 2020-11-10

### Changed

- Refreshed dependencies, removed compiler warnings and lints. ([7d997e8](https://github.com/vincenthz/rust-pvss/commit/7d997e8))
- Updated `LICENSE` and project metadata. ([6b3cce0](https://github.com/vincenthz/rust-pvss/commit/6b3cce0), [31c6433](https://github.com/vincenthz/rust-pvss/commit/31c6433))

## [0.1.0] — 2017-07-07

Initial release.

### Added

- **Schoenmaker PVSS scheme** (`simple` module): public escrow, per-share DLEQ proofs, share recovery via Lagrange interpolation, and secret verification.
- **SCRAPE PVSS scheme** (`scrape` module): public shares with parallel DLEQ proofs (PDLEQ), Reed–Solomon verification, and public verifiability.
- **Curve-agnostic crypto primitives** built on OpenSSL at the time:
  - Scalar and point types with basic arithmetic.
  - DLEQ (Discrete Log Equality) proofs with Fiat–Shamir.
  - PDLEQ (Parallel DLEQ) proofs for the SCRAPE scheme.
- Key pair creation and byte (de)serialization for public and private keys.
- `ShareId` with a `ShareIdsSequence` iterator (1-based).
- Example binary demonstrating a full escrow → share → decrypt → recover round-trip with 100 participants.
- Basic test suite exercising keygen, DLEQ, PVSS, and SCRAPE.
