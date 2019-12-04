use bitcoin::hashes::sha256d::Hash;
use bitcoin::network::constants::Network::Testnet as bitcoin_network;
use error_chain::bail;
use nomic_chain::{orga, spv, Action};
use nomic_primitives::transaction::{HeaderTransaction, Transaction, WorkProofTransaction};
use orga::{Read, Write};
use std::collections::HashMap;
use std::str::FromStr;
use tendermint::rpc::Client as TendermintRpcClient;

struct RemoteStore<'a> {
    pub rpc: &'a TendermintRpcClient,
}

impl<'a> Read for RemoteStore<'a> {
    fn get(&self, key: &[u8]) -> orga::Result<Option<Vec<u8>>> {
        let rpc = &self.rpc;
        let query_response = reqwest::blocking::get(
            &format!(
                "http://localhost:26657/abci_query?data=0x{}",
                hex::encode(key)
            )[..],
        );
        if let Ok(res) = query_response {
            if let Ok(query_response_json) = res.json::<serde_json::Value>() {
                // TODO: error handling if response json isn't what we expect
                let query_response_value = &query_response_json["result"]["response"]["value"]
                    .as_str()
                    .unwrap();
                let query_response_value_bytes = base64::decode(query_response_value).unwrap();
                return Ok(Some(query_response_value_bytes));
            }
        }

        //        match abci_result {}
        Ok(None)
    }
}

impl<'a> Write for RemoteStore<'a> {
    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> orga::Result<()> {
        panic!("Write method should not be called on a RemoteStore");
    }

    fn delete(&mut self, key: &[u8]) -> orga::Result<()> {
        panic!("Delete method should not be called on a RemoteStore");
    }
}

pub struct Client {
    tendermint_rpc: TendermintRpcClient,
}

impl Client {
    pub fn new(tendermint_rpc_address: &str) -> Result<Self, ClientError> {
        let address = tendermint::net::Address::from_str(tendermint_rpc_address).unwrap();
        let tendermint_rpc = TendermintRpcClient::new(&address).unwrap();

        Ok(Client { tendermint_rpc })
    }

    fn store(&self) -> RemoteStore {
        RemoteStore {
            rpc: &self.tendermint_rpc,
        }
    }

    /// Transmit a transaction the peg state machine.
    ///
    /// In this mock implementation, the transaction is wrapped in a peg action and then
    /// immediately evaluated against the client's store.
    ///
    /// In the future, the transaction will be serialized and broadcasted to the network, and the
    /// state machine abci host will be responsible for wrapping the transaction in the appropriate Action
    /// enum variant.
    pub fn send(
        &mut self,
        transaction: Transaction,
    ) -> Result<tendermint::rpc::endpoint::broadcast::tx_commit::Response, tendermint::rpc::Error>
    {
        let tx_bytes = serde_json::to_vec(&transaction).unwrap();

        let rpc = &self.tendermint_rpc;
        let tx = tendermint::abci::Transaction::new(tx_bytes);
        let broadcast_result = rpc.broadcast_tx_commit(tx);
        broadcast_result
    }

    /// Get the Bitcoin headers currently used by the peg zone's on-chain SPV client.
    pub fn get_bitcoin_block_hashes(&mut self) -> Result<Vec<Hash>, ClientError> {
        let mut store = self.store();
        let mut header_cache = spv::headercache::HeaderCache::new(bitcoin_network, &mut store);
        let trunk = header_cache.load_trunk();
        match trunk {
            Some(trunk) => Ok(trunk.clone()),
            None => Err(ClientError::new("unable to get trunk")),
        }
    }

    /// Create and broadcast a transaction which reedems a golden nonce, granting voting power to
    /// the provided validator public key.
    pub fn submit_work_proof(
        &mut self,
        public_key: &[u8],
        nonce: u64,
    ) -> Result<tendermint::rpc::endpoint::broadcast::tx_commit::Response, tendermint::rpc::Error>
    {
        let work_transaction = Transaction::WorkProof(WorkProofTransaction {
            public_key: public_key.to_vec(),
            nonce,
        });
        self.send(work_transaction)
    }

    pub fn get_bitcoin_tip(&mut self) -> bitcoin::BlockHeader {
        let mut store = self.store();
        let mut header_cache = spv::headercache::HeaderCache::new(bitcoin_network, &mut store);
        header_cache.tip().unwrap().stored.header
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
