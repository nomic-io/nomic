<h1 align="center">
<img src="./logo.svg" width="40%">
</h1>

Nomic Bitcoin Bridge testnet v0.4.0 (Stakenet Release Candidate)

## Stakenet

This testnet includes everything required for the upcoming Stakenet launch
(Nomic's first production network). This network does not include the Bitcoin
bridge functionality and token transfers are disabled - only staking is
supported. This is our last test to make sure everything is in order for launch.

You'll notice many differences between Nomic and a typical Cosmos SDK chain,
this is because Nomic is built with an entirely [custom
stack](https://github.com/nomic-io/orga).

## Validator setup guide

This guide will walk you through setting up a validator for the Nomic Bitcoin
Bridge testnet.

If you need any help getting your node running, join the [Telegram
channel](https://t.me/joinchat/b0iv3MHgH5phYjkx).

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

Initialize your data directory (`~/.nomic-stakenet-rc`) by running:

```bash
nomic init
```

Next, add a seed so your node will be able to connect to the network by editing
`~/.nomic-stakenet-rc/tendermint/config/config.toml`:

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

First, find your address by running `nomic balance` (for now this must be run on
a machine which has an active full node).

Ask the Nomic team for some coins in the Telegram and include your address.

Once you have received coins, you can declare your node as a validator and
delegate to yourself with:

```
nomic declare \
  <validator_consensus_key> \
  <amount> \
  <commission_rate> \
  <moniker> \
  <website> \
  <identity> \
  <details>
```

- The `validator_consensus_key` field is the base64 pubkey `value` field found
under `"validator_info"` in the output of http://localhost:26657/status.
- The `identity` field is the 64-bit hex key suffix found on your Keybase
  profile, used to get your profile picture in wallets and block explorers.

For example:
```
nomic declare \
  ohFOw5u9LGq1ZRMTYZD1Y/WrFtg7xfyBaEB4lSgfeC8= \
  10000000 \
  0.123 \
  "Foo's Validator" \
  "https://foovalidator.com" \
  37AA68F6AA20B7A8 \
  "Please delegate to me!"
```

Thanks for participating in the Nomic network! We'll be updating the network
often so stay tuned in [Telegram](https://t.me/joinchat/b0iv3MHgH5phYjkx) for
updates.
