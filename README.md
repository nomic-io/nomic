<h1 align="center">
<img src="./logo.svg" width="40%">
</h1>

Nomic Bitcoin Bridge v0.5.0 (Stakenet Release)

## Stakenet

This is the release for the Nomic Stakenet (Nomic's first production network).
This network does not include the Bitcoin bridge functionality and token
transfers are disabled - only staking is supported.

You'll notice many differences between Nomic and a typical Cosmos SDK chain,
this is because Nomic is built with an entirely [custom
stack](https://github.com/nomic-io/orga).

## Validator setup guide

This guide will walk you through setting up a validator for the Nomic Stakenet.

If you need any help getting your node running, join the [Discord](https://discord.gg/DJ2f2YtfpJ) and request the validator role.

### Requirements

- &gt;= 4GB RAM
- &gt;= 50GB of storage
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
# or for systems running fedora
sudo dnf install clang openssl-devel && sudo dnf group install "C Development Tools and Libraries" 

# clone
git clone https://github.com/nomic-io/nomic.git nomic && cd nomic

# build and install, adding a `nomic` command to your PATH
cargo install --path .
```

### 2. Initialize and configure your node

Initialize your data directory (`~/.nomic-stakenet`) by running:

```bash
nomic init
```

Next, configure your node by editing
`~/.nomic-stakenet/tendermint/config/config.toml`.

Add the external ip and port where your node can be reached so that other
nodes will connect to you:

```toml
# Address to advertise to peers for them to dial
# If empty, will use the same port as the laddr,
# and will introspect on the listener or use UPnP
# to figure out the address. ip and port are required
# example: 159.89.10.97:26656
external_address = "123.45.67.89:26656"
```

Add a seed so your node will be able to connect to the network:

```toml
# Comma separated list of seed nodes to connect to
seeds = "238120dfe716082754048057c1fdc3d6f09609b5@161.35.51.124:26656,a67d7a4d90f84d5c67bfc196aac68441ba9484a6@167.99.119.196:26659"
```

### 3. Run your node

```bash
nomic start
```

This will run the Nomic state machine and a Tendermint process.

### 4. Acquiring coins and staking for voting power

First, find your address by running `nomic balance` (for now this must be run on
a machine which has an active full node).

Ask the Nomic team for some coins in Discord and include your address.

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

**IMPORTANT NOTE:** Carefully double-check all the fields since you will not be able to modify them after declaring. If you make a mistake, you will have to declare a new validator instead.

- The `validator_consensus_key` field is the base64 pubkey `value` field found
under `"validator_info"` in the output of http://localhost:26657/status.
- The `identity` field is the 64-bit hex key suffix found on your Keybase
  profile, used to get your profile picture in wallets and block explorers.

For example:
```
nomic declare \
  ohFOw5u9LGq1ZRMTYZD1Y/WrFtg7xfyBaEB4lSgfeC8= \
  100000 \
  0.042 \
  "Foo's Validator" \
  "https://foovalidator.com" \
  37AA68F6AA20B7A8 \
  "Please delegate to me!"
```

Visit https://app.nomic.io to claim the airdrop if you are an eligible ATOM holder/staker, so you can delegate more NOM to yourself.

Thanks for participating in the Nomic network! We'll be updating the network
often so stay tuned in [Discord](https://discord.gg/DJ2f2YtfpJ) for
updates.
