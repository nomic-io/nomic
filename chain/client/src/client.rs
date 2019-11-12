use bitcoin::hashes::sha256d::Hash;
use nomic_primitives::transaction::HeaderTransaction;

pub struct Client {
    bitcoin_block_hashes: Vec<Hash>,
}

impl Client {
    pub fn new() -> Result<Self, ClientError> {
        Ok(Client {
            bitcoin_block_hashes: Vec::new(),
        })
    }

    pub fn send(&self, transaction: &HeaderTransaction) -> Result<(), ClientError> {
        Ok(())
    }

    /// Get the Bitcoin headers currently used by the peg zone's on-chain SPV client.
    pub fn get_bitcoin_block_hashes(&self) -> Result<Vec<Hash>, ClientError> {
        Ok(self.bitcoin_block_hashes.clone())
    }

    /// Set the peg's headers. This is only for use in testing since this is currently a mock
    /// client.
    pub fn set_bitcoin_block_hashes(&mut self, bitcoin_block_hashes: Vec<Hash>) {
        self.bitcoin_block_hashes = bitcoin_block_hashes;
    }
}

pub struct ClientError {}

impl ClientError {
    fn new() -> Self {
        ClientError {}
    }
}
