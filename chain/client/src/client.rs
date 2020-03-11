use bitcoin::hash_types::BlockHash as Hash;
use bitcoin::Network::Testnet as bitcoin_network;

use nomic_bitcoin::bitcoin;
use nomic_chain::{orga, spv};
use nomic_primitives::transaction::{Transaction, WorkProofTransaction};
use orga::{
    abci::TendermintClient, merkstore::Client as MerkStoreClient, Read, Result as OrgaResult, Write,
};

use std::str::FromStr;
use tendermint::rpc::Client as TendermintRpcClient;

struct RemoteStore {
    merk_store_client: MerkStoreClient<TendermintClient>,
}

impl RemoteStore {
    fn new(address: &str) -> Self {
        let tendermint_client = TendermintClient::new(address).expect("Failed to initialize tendermint client in RemoteStore. Is a local Tendermint full node running?");
        let merk_store_client = MerkStoreClient::new(tendermint_client);
        RemoteStore { merk_store_client }
    }
}

impl Read for RemoteStore {
    fn get(&self, key: &[u8]) -> orga::Result<Option<Vec<u8>>> {
        let result = self.merk_store_client.get(key);
        result
    }
}

impl Write for RemoteStore {
    fn put(&mut self, _key: Vec<u8>, _value: Vec<u8>) -> orga::Result<()> {
        panic!("Write method should not be called on a RemoteStore");
    }

    fn delete(&mut self, _key: &[u8]) -> orga::Result<()> {
        panic!("Delete method should not be called on a RemoteStore");
    }
}

pub struct Client {
    pub tendermint_rpc: TendermintRpcClient,
    remote_store: RemoteStore,
}

impl Client {
    pub fn new(tendermint_rpc_address: &str) -> Result<Self, ClientError> {
        let address = tendermint::net::Address::from_str(tendermint_rpc_address).unwrap();
        let tendermint_rpc = TendermintRpcClient::new(&address).unwrap();
        let remote_store = RemoteStore::new(tendermint_rpc_address);

        Ok(Client {
            tendermint_rpc,
            remote_store,
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
        let store = &mut self.remote_store;
        let mut header_cache = spv::headercache::HeaderCache::new(bitcoin_network, store);
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

    pub fn get_bitcoin_tip(&mut self) -> OrgaResult<bitcoin::BlockHeader> {
        let store = &mut self.remote_store;
        let mut header_cache = spv::headercache::HeaderCache::new(bitcoin_network, store);
        let maybe_tip = header_cache.tip()?;
        if let Some(tip) = maybe_tip {
            Ok(tip.stored.header)
        } else {
            panic!("Unable to fetch Bitcoin tip header");
        }
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
