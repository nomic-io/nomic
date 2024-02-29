#!/bin/bash

# stop on error & display the running command
set -xe

# only required features
cargo test --verbose --no-default-features --features=full,feat-ibc,testnet

# all features
cargo test --verbose --features full,feat-ibc,testnet,faucet-test,devnet

# check rest
cargo check --manifest-path rest/Cargo.toml --verbose

<<<<<<< HEAD
=======
# run code coverage
cargo llvm-cov --no-default-features --features=full,feat-ibc,testnet --workspace --lcov --no-cfg-coverage-nightly

# run code coverage
cargo llvm-cov --no-default-features --features=full,feat-ibc,testnet --workspace --lcov --no-cfg-coverage-nightly

>>>>>>> 1c3351b (chore: add llvm html for visualizing test coverage)
# formatter
cargo fmt --all -- --check

# clippy
cargo clippy --no-default-features --features=full,feat-ibc,testnet -- -D warnings

# test bitcoin
RUST_LOG=info cargo test --verbose --features full,feat-ibc,testnet,faucet-test,devnet --test bitcoin -- --ignored
RUST_LOG=info cargo test --verbose --features full,feat-ibc,testnet,faucet-test,devnet --test header_queue -- --ignored
RUST_LOG=info cargo test --verbose --features full,feat-ibc,testnet,faucet-test,devnet --test node -- --ignored
RUST_LOG=info cargo test --verbose --features full,feat-ibc,testnet,faucet-test,devnet --test relayer -- --ignored