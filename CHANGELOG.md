# Changelog

## [0.2.0] - 2020-05-06

### Added

- Added full Bitcoin peg system - the validators of the network now coordinate to sign Bitcoin transactions and manage reserves of BTC.
  - Nodes now run a signatory process which automatically signs Bitcoin transactions.
  - Relayers now scan Nomic for checkpoint transactions to relay to the Bitcoin network.
- Added `nomic withdraw` CLI command, which deducts NBTC from the wallet and pays out BTC on the Bitcoin mainchain.
- Added `nomic send` CLI command, which transfers coins from one account to another.

### Changed

- Nomic CLI commands now use the `--dev` flag for testing against a local network.
- CLI commands now denominate amounts in Bitcoin rather than Satoshis.
- Voting power units are now scaled down by the minimum work amount (`2^20`).

### Bug Fixes

- Changed encoding of voting power in the Bitcoin reserve script to prevent overflowing 32-bit values. ([#47](https://github.com/nomic-io/nomic/pull/47))

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
