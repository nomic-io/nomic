<h1 align="center">
<img src="./logo.svg" width="40%">
</h1>

Nomic Bitcoin Bridge

## Testnet Interchain Upgrade

This testnet version is the release candidate for the upcoming Stakenet upgrade.

## Run test cases

```bash
./run-tests.sh

# for bitcoin e2e testing, if you want to test individual unit tests, you can use the following command:
cargo test --verbose --features full,feat-ibc,testnet,faucet-test,devnet --test bitcoin recover_expired_deposit -- --ignored --exact
```

## Upgrading existing nodes

If you're upgrading your existing testnet node:

1. Rebuild from this branch with:

```bash
git pull

cargo install --locked --path .
```

2. Shut down your running node.

3. Restart your node with `nomic start`.

Your node will automatically perform the upgrade on Friday, October 7 at 17:00 UTC.

4. Run tests

```bash
cargo test --all
```

## Node setup guide

This guide will walk you through setting up a node for the Nomic testnet.

If you need any help getting your node running, join the [Discord](https://discord.gg/jH7U2NRJKn) and ask for the Validator role.

### Requirements

- &gt;= 4GB RAM
- &gt;= 100GB of storage
- Linux or macOS _(Windows support coming soon)_

### 1. Build Nomic

Start by building Nomic - for now this requires Rust nightly.
Install rustup if you haven't already:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install nightly as well (nomic currently requires rust nightly):

```bash
rustup default nightly
```

Install required dependencies (ubuntu):

```bash
sudo apt install build-essential libssl-dev pkg-config clang
```

Install required dependencies (macOS):

```bash
brew install llvm
```

For systems running fedora:

```bash
sudo dnf install clang openssl-devel && sudo dnf group install "C Development Tools and Libraries"
```

Clone the github folder and switch to the correct folder:

```bash
git clone https://github.com/oraichain/bitcoin-bridge.git && cd bitcoin-bridge
git checkout {latest_release}
```

Build and install, adding a `nomic` command to your PATH:

```bash
cargo install --locked --path .
```

### 2. Run your node

Start your Nomic node:

```bash
# the FUNDED_ADDRESS will have lots of test NOM & NBTC to test
# your-wanted-chain-id is the chain id you want your local network to be. If it does not exist => auto create new, else reuse the existing one

# the env variables will only apply to the first node of the network when the chain initializes => the below command is only for the first node.
FUNDED_ADDRESS=<your-nomic-address-for-funding> FUNDED_ORAIBTC_AMOUNT=<your-oraibtc-for-funding> FUNDED_USAT_AMOUNT=<your-usat-for-funding> FUNDED_ORAIBTC_AMOUNT=<amount> FUNDED_USAT_AMOUNT=<amount> nomic start --chain-id <your-wanted-chain-id>

# Run the below command to join the network as a full node
nomic start \
  --genesis /root/.oraibtc-mainnet-1/tendermint/config/genesis.json \
  --state-sync-rpc http://<other-node-ip>:26657 \
  --tendermint-logs \
  -- --p2p.seeds <other-node-id>@<other-node-ip>:26656

# eg:
FUNDED_ADDRESS=oraibtc1ehmhqcn8erf3dgavrca69zgp4rtxj5kqzpga4j FUNDED_ORAIBTC_AMOUNT=1000000000000 FUNDED_USAT_AMOUNT=0 nomic start --chain-id oraibtc-subnet-1
```

This will run the Nomic state machine and a Tendermint process. For new nodes the statesync process will run automatically to get the node up to speed with the current chain.

Start your GRPC:

```bash
nomic grpc --chain-id <your-chain-id> -g 0.0.0.0 -- 9001
```

This will start and expose your local grpc to the world through port 9090. You can choose a different port if you prefer

Start Hermes IBC relayer (assuming the config.toml file is located at /root/.hermes/. You can use the example config.toml file located at `hermes-ibc/config.toml`):

```bash
./hermes-ibc/hermes-setup-and-run.sh
```

### 3. Acquiring coins and staking for voting power

First, find your address by running `nomic balance` (for now this must be run on
the same machine as your active full node).

Ask the Nomic team for some coins in the Discord and include your address.

Once you have received coins, you can declare your node as a validator and
delegate to yourself with:

```bash
nomic declare \
  <validator_consensus_key> \
  <amount> \
  <commission_rate> \
  <max_commission_rate> \
  <max_commission_rate_change_per_day> \
  <min_self_delegation> \
  <moniker> \
  <website> \
  <identity> \
  <details>
```

**IMPORTANT NOTE:** Carefully double-check all the fields since you will not be
able to modify the `commission_max` or `commission_max_change` after declaring. If you make a mistake, you will have to
declare a new validator instead.

- The `validator_consensus_key` field is the base64 pubkey `value` field found
  under `"validator_info"` in the output of http://localhost:26657/status.
- The `identity` field is the 64-bit hex key suffix found on your Keybase
  profile, used to get your profile picture in wallets and block explorers.

For example:

```bash
nomic declare "1e1oIYAQkOcNP504VKFVtrqWx6bdaORShxC4s4st3Mo=" 100000 0.042 0.1 0.01 100000 "Foo's Validator" "https://foovalidator.com" 37AA68F6AA20B7A8 "Please delegate to me!" --chain-id oraibtc-testnet-2
```

### 4. Run your Bitcoin signer

The funds in the Bitcoin bridge are held in a large multisig controlled by the Nomic validators. If you are a validator with a significant amount of voting power, it is very important that you run a signer.

#### i. Set your signatory key

This will submit your public key to the network so you can be added to the multisig. If you do not have a key stored at `~/.nomic-testnet-4c/signer/xpriv`, this will automatically generate a Bitcoin extended private key for you. **KEEP THIS KEY SAFE** - similar to your validator private key, it is important to be mindful of this key so that it is never lost or stolen.

**Note:** Setting your signatory key is only required if you are starting a fresh node. Migrating nodes can move on to the next step.

```
nomic set-signatory-key
```

If you have your extended private key stored in a different location than the default, you may pass a path.

```
nomic set-signatory-key <path-to-your-key>
```

#### ii. Run your Bitcoin signer

You can run the signer with:

```
nomic signer
```

If you have stored your xpriv in a different location, you can pass the path to the signer.

```
nomic signer xpriv_paths=[<path_to_your_xpriv>]
```

Leave this process running, it will automatically sign Bitcoin transactions that the network wants to create.

In the future, we hope for the community to come up with alternative types of signers which provide for extra security, by e.g. airgapping keys, using HSMs, or prompting the user for an encryption key.

### 5. (Optional) Run a relayer

Relayer nodes carry data between the Bitcoin blockchain and the Nomic blockchain. You can help support the health of the network by running a Bitcoin node alongside your Nomic node and running the relayer process.

#### i. Sync a Bitcoin node

Download Bitcoin Core: https://bitcoin.org/en/download

Run it with for testnet:

```bash
bitcoind -server -testnet -rpcuser=satoshi -rpcpassword=nakamoto
```

For mainnet, run this:

```bash
bitcoind -rpcuser=satoshi -rpcpassword=nakamoto
```

(The RPC server only listens on localhost, so the user and password are not critically important.)

**NOTE:** To save on disk space, you may want to configure your Bitcoin node to prune block storage. For instance, add `-prune=5000` to only keep a maximum of 5000 MB of blocks. You may also want to use the `-daemon` option to keep the node running in the background.

#### ii. Run the relayer process

```bash
// testnet
nomic relayer --rpc-port=18332 --rpc-user=satoshi --rpc-pass=nakamoto

// mainnet
nomic relayer --rpc-port=8332 --rpc-user=satoshi --rpc-pass=nakamoto
```

Leave this running - the relayer will constantly scan the Bitcoin and Nomic chains and broadcast relevant data.

The relayer will also create a server which listens on port 8999 for clients to announce their deposit addresses. To help make the network more reliable, if you run a relayer please open this port and let us know your node's address in Discord or a Github issue so we can have clients make use of your node. If you're going to make this service public, putting the server behind an HTTP reverse proxy is recommended for extra safety.

---

Thanks for participating in the Nomic Testnet! We'll be updating the network
often so stay tuned in [Discord](https://discord.gg/jH7U2NRJKn) for updates.

### 6. How to run lcd server

For running lcd server, you only need to change directory to rest folder. Then run the command below:

```
// make sure to change home directory to rest by: cd rest
cargo run
```

### 7. Running a validator node syncing with seed node

Firstly, you have to copy the genesis file of your seed node.

```bash
nano {home_directory}/genesis.json

// Paste the content of genesis file to genesis.json, remember to make the validators field to []
eg:
{
  "app_hash": "",
  "chain_id": "oraibtc-subnet-1",
  "consensus_params": {
    "block": {
      "max_bytes": "22020096",
      "max_gas": "-1",
      "time_iota_ms": "1000"
    },
    "evidence": {
      "max_age_duration": "172800000000000",
      "max_age_num_blocks": "100000",
      "max_bytes": "1048576"
    },
    "validator": {
      "pub_key_types": [
        "ed25519"
      ]
    },
    "version": {}
  },
  "genesis_time": "2024-01-05T04:30:01.70325218Z",
  "initial_height": "0",
  "validators": []
}
```

Secondly, you have to get the node_id from rpc of seed node. Assume seed_node_url is ip address, all port are public, the full steps for running validator node are below:

```bash
curl {seed_node_url}:26657/status

eg:
{
  "jsonrpc": "2.0",
  "id": -1,
  "result": {
    "node_info": {
      "protocol_version": {
        "p2p": "8",
        "block": "11",
        "app": "0"
      },
      "id": "c1ed727e36b0d7452c03513a87f77dc4766e2b38", // node_id
      "listen_addr": "tcp://0.0.0.0:26656",
      "network": "oraibtc-subnet-1",
      "version": "0.34.26",
      "channels": "40202122233038606100",
      "moniker": "oraibtc-test-mainnet",
      "other": {
        "tx_index": "on",
        "rpc_address": "tcp://0.0.0.0:26657"
      }
    },
    "sync_info": {
      "latest_block_hash": "0DFF9A1251E33F425543DEAB1795F4CB2878A3F60B36F3F280E28CDEAF979545",
      "latest_app_hash": "CFE5FC014798559E5BFED0414B83324B1F7D15A6CB7ACFA83493FDBF7AD85383",
      "latest_block_height": "10760",
      "latest_block_time": "2024-01-05T14:23:05.981270195Z",
      "earliest_block_hash": "D15DBF99D61C6A5515FBF28254079DED94C80B350F8C15D2D6A36A192B65AD54",
      "earliest_app_hash": "",
      "earliest_block_height": "1",
      "earliest_block_time": "2024-01-05T04:30:01.70325218Z",
      "catching_up": false
    },
    "validator_info": {
      "address": "C50A1D024DBBA97B40EF53AE4511C2D5F593EAC9",
      "pub_key": {
        "type": "tendermint/PubKeyEd25519",
        "value": "PFGMB8wARZ5BRmO/8CmtY8em/G9LVix/4h5B9NwKlaY=" // This is validator key will
         use for nomic declare
      },
      "voting_power": "1000000000"
    }
  }
}

Example of running full validator node:
nomic start \
  --genesis {home_directory}/genesis.json \
  --state-sync-rpc {seed_node_url}:26657 \
  --state-sync-rpc {seed_node_url}:26657 \
  -- --p2p-peers c1ed727e36b0d7452c03513a87f77dc4766e2b38@{seed_node_url}:26656

nomic declare \
  PFGMB8wARZ5BRmO/8CmtY8em/G9LVix/4h5B9NwKlaY= \
  1000000 \
  0.042 \
  0.1 \
  0.01 \
  1000000 \
  "Sample Moniker" \
  "perfogic@gmail.com" \
  ALKSDHNLKASD \ // random string
  "Please delegate to me"

nomic grpc \
  -g 0.0.0.0 \
  --chain-id oraibtc-subnet-1

nomic signer \
  --chain-id oraibtc-subnet-1

nomic relayer  \
  --rpc-port=18332 --rpc-user=satoshi --rpc-pass=nakamoto \
  --chain-id oraibtc-subnet-1
```
