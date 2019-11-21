use crate::spv::headercache::HeaderCache;
use crate::Action;
use bitcoin::network::constants::Network::Testnet as bitcoin_network;
use orga::{StateMachine, Store};

/// Main entrypoint to the core bitcoin peg state machine.
///
/// This function implements the conventions set by Orga, though this may change as our core
/// framework design settles.
pub fn run(store: &mut dyn Store, action: Action) -> Result<(), StateMachineError> {
    println!("Got action: {:?}", action);
    match action {
        Action::Transaction(transaction) => {
            println!("got transaction: {:?}", transaction);
        }
        _ => (),
    }

    Ok(())
}

/// Called once at genesis to write some data to the store.
pub fn initialize(store: &mut dyn Store) {
    let mut header_cache = HeaderCache::new(bitcoin_network, store);
    let genesis_header = bitcoin::blockdata::constants::genesis_block(bitcoin_network).header;
    header_cache.add_header(&genesis_header);
    println!("initialized header cache.");
}

#[derive(Debug)]
pub struct StateMachineError {}

impl StateMachineError {
    fn new() -> Self {
        StateMachineError {}
    }
}
