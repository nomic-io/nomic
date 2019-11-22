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
    println!("Got action: {:?}", action);
    match action {
        Action::Transaction(transaction) => match transaction {
            Transaction::Header(header_transaction) => {
                let mut header_cache = HeaderCache::new(bitcoin_network, store);
                for header in header_transaction.block_headers {
                    match header_cache.add_header(&header) {
                        Ok(_) => {}
                        Err(_) => return Err(StateMachineError::new()),
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
    header_cache.add_header(&genesis_header);
}

#[derive(Debug)]
pub struct StateMachineError {}

impl StateMachineError {
    fn new() -> Self {
        StateMachineError {}
    }
}
