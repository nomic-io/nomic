use crate::Result;
use bitcoin::hash_types::BlockHash as Hash;
use bitcoin::Network::Testnet as bitcoin_network;
use failure::bail;
use nomic_bitcoin::bitcoin;
use nomic_chain::{orga, spv, State};
use nomic_primitives::transaction::{Transaction, WorkProofTransaction};
use nomic_primitives::Account;
use nomic_signatory_set::{SignatorySet, SignatorySetSnapshot};
use orga::{
    abci::TendermintClient, merkstore::Client as MerkStoreClient, Read, Result as OrgaResult,
    WrapStore, Write,
};

use std::cell::{RefCell, RefMut};
use std::ops::DerefMut;
use std::str::FromStr;
use tendermint::rpc::Client as TendermintRpcClient;

pub struct RemoteStore {
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
    store: RefCell<RemoteStore>,
}

impl Client {
    pub fn new(tendermint_rpc_address: &str) -> Result<Self> {
        let address = tendermint::net::Address::from_str(tendermint_rpc_address)?;
        let tendermint_rpc = TendermintRpcClient::new(&address)?;
        let store = RemoteStore::new(tendermint_rpc_address);

        Ok(Client {
            tendermint_rpc,
            store: RefCell::new(store),
        })
    }

    pub fn state<'a>(&'a self) -> OrgaResult<State<RefMut<'a, RemoteStore>>> {
        State::wrap_store(self.store.borrow_mut())
    }

    /// Transmit a transaction the peg state machine.
    pub fn send(
        &self,
        transaction: Transaction,
    ) -> Result<tendermint::rpc::endpoint::broadcast::tx_commit::Response> {
        let tx_bytes = serde_json::to_vec(&transaction).unwrap();

        let rpc = &self.tendermint_rpc;
        let tx = tendermint::abci::Transaction::new(tx_bytes);
        Ok(rpc.broadcast_tx_commit(tx)?)
    }

    /// Get the Bitcoin headers currently used by the peg zone's on-chain SPV client.
    pub fn get_bitcoin_block_hashes(&self) -> Result<Vec<Hash>> {
        let mut store = self.store.borrow_mut();
        let mut header_cache =
            spv::headercache::HeaderCache::new(bitcoin_network, store.deref_mut());
        let trunk = header_cache.load_trunk();

        match trunk {
            Some(trunk) => Ok(trunk.clone()),
            None => bail!("Unable to get header trunk"),
        }
    }

    /// Create and broadcast a transaction which reedems a golden nonce, granting voting power to
    /// the provided validator public key.
    pub fn submit_work_proof(
        &self,
        public_key: &[u8],
        nonce: u64,
    ) -> Result<tendermint::rpc::endpoint::broadcast::tx_commit::Response> {
        let work_transaction = Transaction::WorkProof(WorkProofTransaction {
            public_key: public_key.to_vec(),
            nonce,
        });
        self.send(work_transaction)
    }

    pub fn get_bitcoin_tip(&self) -> OrgaResult<bitcoin::BlockHeader> {
        let mut store = self.store.borrow_mut();
        let mut header_cache =
            spv::headercache::HeaderCache::new(bitcoin_network, store.deref_mut());
        let maybe_tip = header_cache.tip()?;
        if let Some(tip) = maybe_tip {
            Ok(tip.stored.header)
        } else {
            panic!("Unable to fetch Bitcoin tip header");
        }
    }

    pub fn get_signatory_sets(&self) -> OrgaResult<Vec<SignatorySet>> {
        self.state()?
            .peg
            .signatory_sets
            .iter()
            .map(|snapshot| snapshot.map(|snapshot| snapshot.signatories))
            .collect()
    }

    pub fn get_signatory_set_snapshot(&self) -> OrgaResult<SignatorySetSnapshot> {
        self.state()?.peg.current_signatory_set()
    }

    pub fn get_balance(&self, address: &[u8]) -> OrgaResult<u64> {
        let account = self.get_account(address)?;
        Ok(account.balance)
    }

    pub fn get_account(&self, address: &[u8]) -> OrgaResult<Account> {
        Ok(self
            .state()?
            .accounts
            .get(unsafe_slice_to_address(address))?
            .unwrap_or_default())
    }

    pub fn get_finalized_checkpoint_tx(&self) -> OrgaResult<Option<bitcoin::Transaction>> {
        let state = self.state()?;
        if state.peg.has_finalized_checkpoint() {
            Ok(Some(state.peg.finalized_checkpoint_tx()?))
        } else {
            Ok(None)
        }
    }

    pub fn get_active_checkpoint_tx(&self) -> OrgaResult<Option<bitcoin::Transaction>> {
        let state = self.state()?;
        if state.peg.active_checkpoint.is_active.get_or_default()? {
            Ok(Some(state.peg.active_checkpoint_tx()?))
        } else {
            Ok(None)
        }
    }
}

type Address = [u8; 33];
fn unsafe_slice_to_address(slice: &[u8]) -> Address {
    // warning: only call this with a slice of length 32
    let mut buf = [0; 33];
    buf.copy_from_slice(slice);
    buf
}
