use crate::spv::headercache::HeaderCache;
use crate::Action;
use bitcoin::network::constants::Network::Testnet as bitcoin_network;
use nomic_primitives::transaction::Transaction;
use orga::{StateMachine, Store};

/// Main entrypoint to the core bitcoin peg state machine.
///
/// This function implements the conventions set by Orga, though this may change as our core
/// framework design settles.
pub fn run(store: &mut dyn Store, action: Action) -> Result<(), StateMachineError> {
    match action {
        Action::Transaction(transaction) => match transaction {
            Transaction::Header(header_transaction) => {
                let mut header_cache = HeaderCache::new(bitcoin_network, store);
                for header in header_transaction.block_headers {
                    println!("header to add: {:?}", header);

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
    //   header_cache.add_header(&genesis_header);
}

mod utils {

    use bitcoincore_rpc::{Auth, Client, Error as RpcError, RpcApi};
    use std::env;

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
        loop {
            if header.height % 2016 == 0 {
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
