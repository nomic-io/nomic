use bitcoincore_rpc::{Auth, Client, Error as RpcError, RpcApi};
use nomic_bitcoin::{bitcoin, bitcoincore_rpc, EnrichedHeader};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

const BITCOIN_START_HEIGHT: usize = 1667232;
fn make_rpc_client() -> Result<Client, RpcError> {
    let rpc_user = env::var("BTC_RPC_USER").unwrap();
    let rpc_pass = env::var("BTC_RPC_PASS").unwrap();
    let rpc_auth = Auth::UserPass(rpc_user, rpc_pass);
    let rpc_url = "http://localhost:18332";
    Client::new(rpc_url.to_string(), rpc_auth)
}
/// Get the latest checkpoint header from rpc
fn get_checkpoint_header() -> EnrichedHeader {
    let rpc = make_rpc_client().unwrap();
    let best_block_hash = rpc.get_best_block_hash().unwrap();
    let mut header = rpc.get_block_header_verbose(&best_block_hash).unwrap();
    if header.height < BITCOIN_START_HEIGHT {
        panic!("Start and sync a Bitcoin testnet full node before starting the peg ABCI state machine.");
    }
    loop {
        if header.height == BITCOIN_START_HEIGHT {
            return EnrichedHeader {
                header: rpc.get_block_header_raw(&header.hash).unwrap(),
                height: header.height as u32,
            };
        }
        header = rpc
            .get_block_header_verbose(&header.previousblockhash.unwrap())
            .unwrap();
    }
}

fn main() {
    let header_info = get_checkpoint_header();
    let header_info_encoded: Vec<u8> =
        bincode::serialize(&header_info).expect("Failed to serialize checkpoint header info");
    let header_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("config")
        .join("header");

    fs::write(header_path, header_info_encoded)
        .expect("Failed to write serialized checkpoint header");
}
