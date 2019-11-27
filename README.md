# rust-bitcoin-peg

Rust implementation of the [Nomic Bitcoin sidechain](https://github.com/nomic-io/bitcoin-peg).


## Usage

```
$ git clone https://github.com/nomic-io/rust-bitcoin-peg
$ cd rust-bitcoin-peg

# Start a bitcoin testnet full node
$ export BTC_RPC_USER=foo
$ export BTC_RPC_PASS=bar
$ npm i -g bitcoind 
$ ./scripts/start-bitcoin-testnet.sh

# Start peg chain full node
$ cargo run chain/chain

# Start bitcoin header relayer
$ cargo run relayer
```

