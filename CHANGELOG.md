# Changelog

## [0.1.1] - 2020-03-18

### Added

- Added basic CLI wallet commands:
  - `nomic deposit`: Generates a Bitcoin address associated with an on-chain SECP256k1 account, spendable by the current signatory set. Deposits to this address are credited on-chain with an equivalent amount of NBTC.
  - `nomic balance`: Shows your balance.
- Created CLI process management commands (`nomic start`, `nomic relayer`, `nomic worker`) in a single consolidated binary. ([#12](https://github.com/nomic-io/nomic/pull/12))
- Node now automatically installs and spawns Tendermint. ([#12](https://github.com/nomic-io/nomic/pull/12))
- Logging output. ([#12](https://github.com/nomic-io/nomic/pull/12))
- Relayer now creates and broadcasts deposit proofs.
- Added deposit proof transactions and NBTC minting.
- Added on-chain signatory set transitions (weekly).

### Changed

- Nomic node no longer requires running a Bitcoin full node. ([#16](https://github.com/nomic-io/nomic/pull/16))

### Bug Fixes

- Fixed issue which caused non-determinism on some arm64 machines. ([#10](https://github.com/nomic-io/nomic/pull/10))

## [0.1.0] - 2020-02-12

After running a network based on the previous pre-releases, this version has proven stable. It is now moving from release candidate status to become the official Nomic v0.1.0 release.

This is also the first bugfix release, resulting in an upgrade which does not fork the chain.

### Added

- Validator setup guide.

### Bug Fixes

- Fixed issue that caused inconsistent databases in the event of a crash.

## [0.1.0-rc.1] - 2019-12-17

This is the first release of our testnet node.

### Added

- Initial implementation of full node, ready for building a first testnet. Peg is not functional yet, but the state machine does maintain a SPV state of the Bitcoin Testnet chain.
