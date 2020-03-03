use crate::spv::headercache::HeaderCache;
use crate::Action;
use bitcoin::network::constants::Network::Testnet as bitcoin_network;
use nomic_primitives::transaction::Transaction;
use nomic_work::work;
use orga::{StateMachine, Store};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MIN_WORK: u64 = 1 << 20;
/// Main entrypoint to the core bitcoin peg state machine.
///
/// This function implements the conventions set by Orga, though this may change as our core
/// framework design settles.
pub fn run(
    store: &mut dyn Store,
    action: Action,
    validators: &mut BTreeMap<Vec<u8>, u64>,
) -> Result<(), StateMachineError> {
    match action {
        Action::Transaction(transaction) => match transaction {
            Transaction::WorkProof(work_transaction) => {
                let mut hasher = Sha256::new();
                hasher.input(&work_transaction.public_key);
                let nonce_bytes = work_transaction.nonce.to_be_bytes();
                hasher.input(&nonce_bytes);
                let hash = hasher.result().to_vec();
                let work_proof_value = work(&hash);

                if work_proof_value >= MIN_WORK {
                    // Make sure this proof hasn't been redeemed yet
                    let value_at_work_proof_hash = store.get(&hash).unwrap_or(None);
                    if let None = value_at_work_proof_hash {
                        // Grant voting power
                        let current_voting_power = *validators
                            .get(&work_transaction.public_key)
                            .unwrap_or(&(0 as u64));

                        validators.insert(
                            work_transaction.public_key,
                            current_voting_power + work_proof_value,
                        );
                        // Write the redeemed hash to the store so it can't be replayed
                        store.put(hash.to_vec(), vec![0]);
                    } else {
                        println!("duplicate work proof: {:?},\n\nHash: {:?}, \n\nValue stored at hash on store: {:?}", work_transaction, hash, value_at_work_proof_hash);
                    }
                }
            }
            Transaction::Header(header_transaction) => {
                let mut header_cache = HeaderCache::new(bitcoin_network, store);
                for header in header_transaction.block_headers {
                    match header_cache.add_header(&header) {
                        Ok(_) => {}
                        Err(e) => {
                            println!("header add err: {:?}", e);
                            return Err(StateMachineError::new());
                        }
                    }
                }
            }
            _ => (),
        },
        _ => (),
    };

    Ok(())
}

/// Called once at genesis to write some data to the store.
pub fn initialize(store: &mut dyn Store) {
    let mut header_cache = HeaderCache::new(bitcoin_network, store);
    let genesis_header = bitcoin::blockdata::constants::genesis_block(bitcoin_network).header;
    let (checkpoint, height) = utils::get_latest_checkpoint_header();

    header_cache.add_header_raw(checkpoint, height);
}

mod utils {

    use bitcoincore_rpc::{Auth, Client, Error as RpcError, RpcApi};
    use std::env;
    const BITCOIN_START_HEIGHT: usize = 1667232;
    pub fn make_rpc_client() -> Result<Client, RpcError> {
        let rpc_user = env::var("BTC_RPC_USER").unwrap();
        let rpc_pass = env::var("BTC_RPC_PASS").unwrap();
        let rpc_auth = Auth::UserPass(rpc_user, rpc_pass);
        let rpc_url = "http://localhost:18332";
        Client::new(rpc_url.to_string(), rpc_auth)
    }
    /// Get the latest checkpoint header from rpc
    pub fn get_latest_checkpoint_header() -> (bitcoin::blockdata::block::BlockHeader, u32) {
        let rpc = make_rpc_client().unwrap();
        let best_block_hash = rpc.get_best_block_hash().unwrap();
        let mut header = rpc.get_block_header_verbose(&best_block_hash).unwrap();
        if header.height < BITCOIN_START_HEIGHT {
            panic!("Start and sync a Bitcoin testnet full node before starting the peg ABCI state machine.");
        }
        loop {
            if header.height == BITCOIN_START_HEIGHT {
                return (
                    rpc.get_block_header_raw(&header.hash).unwrap(),
                    header.height as u32,
                );
            }
            header = rpc
                .get_block_header_verbose(&header.previousblockhash.unwrap())
                .unwrap();
        }
    }
}

#[derive(Debug)]
pub struct StateMachineError {}

impl StateMachineError {
    fn new() -> Self {
        StateMachineError {}
    }
}
