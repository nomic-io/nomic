use bitcoin::blockdata::block::BlockHeader;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoincore_rpc::{Auth, Client, Error as RpcError, RpcApi};
use nomic_bitcoin::{bitcoin, bitcoincore_rpc};
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
fn get_checkpoint_header() -> CheckpointHeader {
    let rpc = make_rpc_client().unwrap();
    let best_block_hash = rpc.get_best_block_hash().unwrap();
    let mut header = rpc.get_block_header_verbose(&best_block_hash).unwrap();
    if header.height < BITCOIN_START_HEIGHT {
        panic!("Start and sync a Bitcoin testnet full node before starting the peg ABCI state machine.");
    }
    loop {
        if header.height == BITCOIN_START_HEIGHT {
            return CheckpointHeader {
                header: rpc.get_block_header_raw(&header.hash).unwrap(),
                height: header.height as u32,
            };
        }
        header = rpc
            .get_block_header_verbose(&header.previousblockhash.unwrap())
            .unwrap();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(remote = "BlockHeader")]
pub struct BlockHeaderDef {
    /// The protocol version. Should always be 1.
    pub version: u32,
    /// Reference to the previous block in the chain
    pub prev_blockhash: Sha256dHash,
    /// The root hash of the merkle tree of transactions in the block
    pub merkle_root: Sha256dHash,
    /// The timestamp of the block, as claimed by the miner
    pub time: u32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course)
    pub bits: u32,
    /// The nonce, selected to obtain a low enough blockhash
    pub nonce: u32,
}
#[derive(Serialize, Deserialize)]
struct CheckpointHeader {
    pub height: u32,
    #[serde(with = "BlockHeaderDef")]
    pub header: BlockHeader,
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
