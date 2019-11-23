use bitcoin::hashes::sha256d::Hash;
use bitcoin::network::constants::Network::Testnet as bitcoin_network;
use nomic_chain::state_machine::{initialize, run};
use nomic_chain::{orga, spv, Action};
use nomic_primitives::transaction::{HeaderTransaction, Transaction};
use orga::{Read, Write};

pub struct Client {
    bitcoin_block_hashes: Vec<Hash>,
    pub store: orga::MapStore,
}

impl Client {
    pub fn new() -> Result<Self, ClientError> {
        let mut mem_store = orga::MapStore::new();
        initialize(&mut mem_store);

        Ok(Client {
            bitcoin_block_hashes: Vec::new(),
            store: mem_store,
        })
    }

    /// Transmit a transaction the peg state machine.
    ///
    /// In this mock implementation, the transaction is wrapped in a peg action and then
    /// immediately evaluated against the client's store.
    ///
    /// In the future, the transaction will be serialized and broadcasted to the network, and the
    /// state machine abci host will be responsible for wrapping the transaction in the appropriate Action
    /// enum variant.
    pub fn send(&mut self, transaction: Transaction) -> Result<(), ClientError> {
        let action = Action::Transaction(transaction);
        let execution_result = run(&mut self.store, action);
        match execution_result {
            Ok(()) => Ok(()),
            Err(_) => Err(ClientError::new("error executing transaction")),
        }
    }

    /// Get the Bitcoin headers currently used by the peg zone's on-chain SPV client.
    pub fn get_bitcoin_block_hashes(&mut self) -> Result<Vec<Hash>, ClientError> {
        let store = &mut self.store;
        let mut header_cache = spv::headercache::HeaderCache::new(bitcoin_network, store);
        let trunk = header_cache.load_trunk();
        match trunk {
            Some(trunk) => Ok(trunk.clone()),
            None => Err(ClientError::new("unable to get trunk")),
        }
    }

    /// Set the peg's headers. This is only for use in testing since this is currently a mock
    /// client.
    pub fn set_bitcoin_block_hashes(&mut self, bitcoin_block_hashes: Vec<Hash>) {
        self.bitcoin_block_hashes = bitcoin_block_hashes;
    }

    /// Execute the raw action on the peg state machine.
    /// For debugging only -- this won't exist in the non-mock version of the peg client.
    pub fn do_raw_action(&mut self, action: Action) {
        run(&mut self.store, action);
    }
}

#[derive(Debug)]
pub struct ClientError {
    message: String,
}

impl ClientError {
    fn new(message: &str) -> Self {
        ClientError {
            message: String::from(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orga::{Read, Write};
    #[test]
    fn sanity() {
        let mut client = Client::new().unwrap();
        let action = Action::Foo;
        client.do_raw_action(action);
    }
}
