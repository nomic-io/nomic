<h1 align="center">
<img src="./logo.png" width="60%">
</h1>

[![Rust](https://github.com/nomic-io/nomic/workflows/Rust/badge.svg)](https://github.com/nomic-io/nomic/actions?query=workflow%3ARust)
[![Telegram](https://img.shields.io/static/v1?label=chat&message=Telegram&color=blue&logo=telegram)](https://t.me/nomicbtc)

Rust implementation of the [Nomic Bitcoin sidechain](https://github.com/nomic-io/bitcoin-peg).

## Validator setup guide

This guide will walk you through setting up a validator for the Nomic Bitcoin sidechain testnet.

If you need any help getting your node running, join the [Telegram channel](https://t.me/nomicbtc).

### Requirements

- &gt;= 1GB RAM
- &gt;= 5GB of storage
- Linux or macOS _(Windows support coming soon)_

### 1. Download or compile Nomic

You may either download a prebuilt binary, or compile it youself.

**Prebuilt Binaries:**

Download the binary from Github with wget, then give it executable permissions.

```bash
# on Linux (x86_64)
wget https://github.com/nomic-io/rust-bitcoin-peg/releases/download/v0.2.2/nomic-x86_64-linux-0.2.2.tar.gz
tar -xf ./nomic-x86_64-linux-0.2.2.tar.gz

# on Linux (arm64)
wget https://github.com/nomic-io/rust-bitcoin-peg/releases/download/v0.2.2/nomic-arm64-linux-0.2.2.tar.gz
tar -xf ./nomic-arm64-linux-0.2.2.tar.gz

# on macOS
wget https://github.com/nomic-io/rust-bitcoin-peg/releases/download/v0.2.2/nomic-x86_64-macos-0.2.2.tar.gz
tar -xf ./nomic-x86_64-macos-0.2.2.tar.gz
```

Or you can [build from source](#self-build-instructions)

### 2. Start your full node

You can start your node by running:

```bash
./nomic start
```

This will run the Nomic state machine and a consensus process (powered by [Tendermint](https://github.com/tendermint/tendermint)), and will automatically connect to other nodes in the network.

Once connected, your node will sync through history and catch up to the current state of the network. Welcome to the testnet! Your node is now verifying incoming transactions and blocks.

### 3. Mining for voting power

At this point, you are now running a _full node_, but since your node does not have any voting power it is not yet a _validator_.

To gain voting power on the Nomic sidechain, full nodes must mine [hashcash](https://en.wikipedia.org/wiki/Hashcash) proofs-of-work. This process lets participation in the network remain open and permissionless.

To mine, run:

```bash
./nomic worker
```

You can watch your voting power increase at [http://localhost:26657/status](http://localhost:26657/status). You're now a validator on the Nomic sidechain! Keep your node running to help ensure stability of the network.

### 4. (Optional) Run a relayer

Since the Nomic network is separate from the Bitcoin network, some nodes must connect to both and run _relayers_ to move data between them.

#### 4a. Download Bitcoin Core

If you'd like to run a relayer, you'll first need to download Bitcoin Core.

```bash
# on Linux (x86_64)
wget https://bitcoin.org/bin/bitcoin-core-0.19.1/bitcoin-0.19.1-x86_64-linux-gnu.tar.gz
tar -xzf bitcoin-0.19.1-x86_64-linux-gnu.tar.gz

# on Linux (arm64)
wget https://bitcoin.org/bin/bitcoin-core-0.19.1/bitcoin-0.19.1-aarch64-linux-gnu.tar.gz
tar -xzf bitcoin-0.19.1-aarch64-linux-gnu.tar.gz

# on macOS
wget https://bitcoin.org/bin/bitcoin-core-0.19.1/bitcoin-0.19.1-osx64.tar.gz
tar -xzf bitcoin-0.19.1-osx64.tar.gz
```

#### 4b. Start your Bitcoin Testnet full node

Now you can sync your full node:

```bash
./bitcoin-0.19.1/bin/bitcoind -testnet -rpcuser=user -rpcpassword=pass
```

Note that this will use ~30GB of disk space, and will take a few hours (the speed depends on your CPU and bandwidth). Enjoy a cup of tea while you wait.

#### 4c. Start your Nomic relayer

Once Bitcoin is synced, you can run the relayer:

```bash
./nomic relayer
```

Now any time a new Bitcoin block gets mined, your node will broadcast it to the sidechain. Your node will also relay relevant Bitcoin transactions.

## Node Management

### Backing up your private key

Your validator is signing blocks with a unique private key stored at `~/.nomic-testnet/config/priv_validator_key.json`. Remember to keep this safe since losing it would mean you lose the voting power you worked hard to get. Also, keep it safe since if an attacker got a hold of it they would be able to attack the network, also resulting in the loss of your voting power.

However, as the network is still just an early testnet and security is not critical yet, it probably is sufficient to just copy the file to another folder:

```bash
cp ~/.nomic-testnet/config/priv_validator_key.json ~/nomic-key-backup.json
```

### Hard-resetting your node

Since Nomic is in the early stages, we may end up resetting the network after making a backwards-incompatible change or introducing a bug which results in corrupt data. If you need to hard reset your node, simply make sure you've backed up the key as in the above section, then remove all the data:

```bash
rm -rf ~/.nomic-testnet
```

Then start your node again to initialize the data, kill the process, and replace the key with your backup:

```bash
cp nomic-key-backup.json ~/.nomic-testnet/config/priv_validator_key.json
```

### Self-Build Instructions

If you'd like to build Nomic yourself instead of downloading the pre-built binary, you'll first need to install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Now clone the repo and compile:

```bash
rustup default nightly # nomic requires rust nightly
git clone https://github.com/nomic-io/nomic.git && cd nomic
cargo install --path cli
```

This will take a few minutes. Once it's done, you'll have a `nomic` command.

## Deposits, Withdrawals, and Transfers

After your full node is running, try depositing some testnet Bitcoin with:

```bash
./nomic deposit
```

The funds will show up in your sidechain account after your Bitcoin transaction has 2 confirmations.

After depositing some Bitcoin, check your balance with:
```bash
./nomic balance
```

Now send some coins to another address with:

```bash
./nomic send <nomic-address> <amount>
```

Finally, withdraw some coins back to a testnet Bitcoin address with:

```bash
./nomic withdraw <btc-address> <amount>
```

## Join the Telegram Chat

Stay tuned as the Nomic sidechain develops, and join the discussion in the [Telegram channel](https://t.me/nomicbtc)!
