<h1 align="center">
<img src="./logo.svg" width="40%">
</h1>

Nomic Bitcoin Bridge testnet v0.3.0 (codename "gucci")

## Guccinet

In this testnet, we've added two core featues: staking and Bitcoin integration.

### Full staking

Nomic now uses Orga's new high-performance staking module, which provides a staking experience similar to what you'd expect from a Cosmos SDK chain.

Our implementation carefully avoids iteration where possible, so paying block rewards or slashing a million delegators is an O(1) operation.

Offline validators are now automatically jailed.

The following commands are now available via the CLI:

```
$ nomic claim        # Claim all available rewards from your delegations          
$ nomic declare      # Declare your node as a validator
$ nomic delegate     # Delegate coins to a validator     
$ nomic delegations  # List your delegations
$ nomic unbond       # Unbond coins from a validator
```

### Bitcoin integration

Bitcoin block headers are now tracked by our on-chain Bitcoin SPV module.

All full nodes will verify Bitcoin headers, but full nodes may optionally also run a relayer to report new Bitcoin block headers to the network:

```
$ nomic relayer
```

In the near future, we'll enable Bitcoin deposits and withdrawals in this module.


## Validator setup guide

This guide will walk you through setting up a validator for the Nomic Bitcoin Bridge testnet.

If you need any help getting your node running, join the [Telegram channel](https://t.me/joinchat/b0iv3MHgH5phYjkx).

### Requirements

- &gt;= 1GB RAM
- &gt;= 5GB of storage
- Linux or macOS _(Windows support coming soon)_

### 1. Build Nomic

Start by building Nomic - for now this requires Rust nightly.

```bash
# install rustup if you haven't already
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# nomic currently requires rust nightly
rustup default nightly

# install required dependencies (ubuntu)
sudo apt install build-essential libssl-dev pkg-config clang

# clone
git clone https://github.com/nomic-io/nomic.git nomic && cd nomic

# build and install, adding a `nomic` command to your PATH
cargo install --path .
```

### 2. Initialize and configure your node

Initialize your data directory (`~/.guccinet`) by running:

```bash
nomic init
```

Next, add a seed so your node will be able to connect to the network by editing
`~/.guccinet/tendermint/config/config.toml`:

```toml
# Comma separated list of seed nodes to connect to
seeds = "f41974e22dd0be5f1e797b00aab73875a55a8943@68.183.121.60:26656,debb05b3f152a63116a0e66fbaf27e2673caf4a9@159.89.232.28:26656"
```

### 3. Run your node

```bash
nomic start
```

This will run the Nomic state machine and a Tendermint process.

### 4. Acquiring coins and staking for voting power

First, find your address by running `nomic balance` (for now this must be run on a machine
which has an active full node).

Ask the Nomic team for some coins in the Telegram and include your address.

Once you have received coins, you can declare your node as a validator and
delegate to yourself with:

```
nomic declare <validator_address> <amount>
```

The validator address is the base64 pubkey value
found under `"validator_info"` in the output of http://localhost:26657/status.
Amount is how many coins to delegate to yourself.

### 5. Run the relayer (optional)

To run the Bitcoin relayer, you must first [run a Bitcoin full node](https://bitcoin.org/en/full-node).

Locate your `bitcoin.conf` (`~/.bitcoin/bitcoin.conf` on Linux, or
`~/Library/Application\ Support/Bitcoin/bitcoin.conf` on Mac), and configure it
with:

```
server=1
rpcuser=<PICK_A_USERNAME>
rpcpassword=<PICK_A_PASSWORD>
rpcbind=127.0.0.1
rpcport=8332
```

Then start your relayer:

```bash
nomic relayer <rpc_username> <rpc_pass>
```

Your node will now start relaying Bitcoin block headers to Nomic.
