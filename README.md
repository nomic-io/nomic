<h1 align="center">
<img src="./logo.png" width="60%">
</h1>

Rust implementation of the [Nomic Bitcoin sidechain](https://github.com/nomic-io/bitcoin-peg).

## Validator setup guide

This guide will walk you through setting up a validator for the Nomic Bitcoin sidechain testnet.

Note: the examples below assume you're using 64-bit Linux.

If you need any help getting your node running, join the [Telegram channel](https://t.me/nomicvalidators).

### Requirements

- At least 1GB RAM
- A few hours (to sync your Bitcoin Testnet full node and Nomic full node)
- At least 30GB of available storage (for the Bitcoin Testnet blockchain), or 1GB if your run the Bitcoin node in pruned mode

### 1. Run a Bitcoin testnet full node

Download the Bitcoin core binary with wget, and start a full node in testnet mode:

```bash
wget https://bitcoin.org/bin/bitcoin-core-0.19.0.1/bitcoin-0.19.0.1-x86_64-linux-gnu.tar.gz
tar -xzf bitcoin-0.19.0.1-x86_64-linux-gnu.tar.gz
./bitcoin-0.19.0.1/bin/bitcoind -testnet -rpcuser=foo -rpcpassword=bar
```

Syncing your Bitcoin testnet full node will take a few hours, depending on your CPU and bandwidth. Enjoy a cup of tea while you wait.

If you'd like to reduce the amount of storage required, you can instead run the node in pruned mode by adding the `-prune=N` option where N is the amount of storage to use in MB. Example, limiting to 1000MB:
```bash
./bitcoin-0.19.0.1/bin/bitcoind -testnet -prune=1000 -rpcuser=foo -rpcpassword=bar
```

### 2. Run the Nomic ABCI server

Download and run the Nomic ABCI server binary.

```bash
wget https://github.com/nomic-io/rust-bitcoin-peg/releases/download/v0.1.0-rc.2/nomic-x86_64-linux
chmod +x ./nomic-x86_64-linux
BTC_RPC_USER=foo BTC_RPC_PASS=bar ./nomic-x86_64-linux
```

The ABCI server will wait for a connection from the local Tendermint node, and you won't see any output. Leave this running while you set up your Tendermint node in the next step.

This server is where the Nomic full node's application logic happens, e.g. validating sidechain transactions and keeping track of account balances. It will talk to a Tendermint consensus process which you will run in the next step.

### 3. Run a Tendermint full node

Download and unzip Tendermint v0.32.8.

```bash
wget https://github.com/tendermint/tendermint/releases/download/v0.32.8/tendermint_v0.32.8_linux_amd64.zip
unzip tendermint_v0.32.8_linux_amd64.zip
```

Now configure your Tendermint home directory and start your full node:

```bash
./tendermint init --home ~/.nomic-testnet
curl https://raw.githubusercontent.com/nomic-io/rust-bitcoin-peg/master/config/genesis.json > ~/.nomic-testnet/config/genesis.json
./tendermint node --home ~/.nomic-testnet --p2p.persistent_peers "117930eb8451ae368ba07c18e14cd497ef59f33e@kep.io:26656"
```

You'll see a bunch of output while your node catches up with the rest of the network. This would be a good time for another cup of tea.

This is the consensus process, which is responsible for connecting to the peer-to-peer network, syncing the blockchain, creating new blocks, etc.

### 4. Run the relayer

The relayer scans Bitcoin for new block headers and broadcasts them to the sidechain. It's what bridges the Bitcoin network and the Nomic sidechain network.

Download and run the latest version of the relayer:

```bash
wget https://github.com/nomic-io/rust-bitcoin-peg/releases/download/v0.1.0-rc.1/relayer-x86_64-linux
chmod +x relayer-x86_64-linux
BTC_RPC_USER=foo BTC_RPC_PASS=bar ./relayer-x86_64-linux
```

You'll see the latest Bitcoin block hash printed whenever a new block is mined.

### 5. Run the work generator

At this point, you are now running a *full node*, but since your node does not have any voting power it is not yet a *validator*.

To gain voting power on the Nomic sidechain, full nodes must create [hashcash](https://en.wikipedia.org/wiki/Hashcash) proofs-of-work. This process lets participation in the network remain open and permissionless.

Download and run the single-CPU work generation script:

```bash
wget https://github.com/nomic-io/rust-bitcoin-peg/releases/download/v0.1.0-rc.1/worker-x86_64-linux
chmod +x worker-x86_64-linux
./worker-x86_64-linux
```

You won't see any output, but you can watch your voting power increase at [http://localhost:26657/status](http://localhost:26657/status). You're now a validator on the Nomic sidechain! Keep your node running to help ensure stability of the network.

### Next Steps

In the future, validator nodes like yours will also be responsible for helping manage the network's Bitcoin reserves. Stay tuned as the Nomic sidechain develops, and join the discussion in the [Telegram channel](https://t.me/nomicvalidators)!
