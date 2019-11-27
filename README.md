# rust-bitcoin-peg

Rust implementation of the [Nomic Bitcoin sidechain](https://github.com/nomic-io/bitcoin-peg).


## Usage

```bash
git clone https://github.com/nomic-io/rust-bitcoin-peg
cd rust-bitcoin-peg

# Start a bitcoin testnet full node
export BTC_RPC_USER=foo
export BTC_RPC_PASS=bar
npm i -g bitcoind 
./scripts/start-bitcoin-testnet.sh

# Start peg chain ABCI server
cargo run chain/chain

# Start Tendermint
npm i -g tendermint-node
export TM_HOME=~/.nomic-sidechain
tendermint init --home $TM_HOME
rm $TM_HOME/config/genesis.json
cp config/genesis.json $TM_HOME
tendermint node --home $TM_HOME

# Start bitcoin header relayer
cargo run relayer
```

