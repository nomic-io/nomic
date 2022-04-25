use adapter::Adapter;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use orga::call::Call;
use orga::client::Client;
use orga::coins::{Accounts, Symbol};
use orga::collections::{map::{Ref, ChildMut}, Deque, Map};
use orga::encoding::{Decode, Encode};
#[cfg(feature = "full")]
use orga::abci::InitChain;
#[cfg(feature = "full")]
use orga::plugins::InitChainCtx;
use orga::query::Query;
use orga::state::State;
use orga::{Error, Result};
use threshold_sig::{ThresholdSig, Pubkey, Signature};
use signatory::SignatorySet;
use header_queue::HeaderQueue;
use checkpoint::CheckpointQueue;
use txid_set::TxidSet;

pub mod adapter;
pub mod checkpoint;
pub mod header_queue;
pub mod txid_set;
#[cfg(feature = "full")]
pub mod relayer;
pub mod signatory;
pub mod threshold_sig; 

#[derive(State, Debug, Clone)]
pub struct Nbtc(());
impl Symbol for Nbtc {}

#[derive(State, Call, Query, Client)]
pub struct Bitcoin {
    pub headers: HeaderQueue,
    pub relayed_txs: TxidSet,
    pub checkpoints: CheckpointQueue,
    pub accounts: Accounts<Nbtc>,
}

impl Bitcoin {
    // #[call]
    // pub fn deposit(&mut self, tx: Adapter<Transaction>, expiration: u64) -> Result<()> {
    //     self.relayed_txs.insert(tx.txid(), expiration)
    // }
}

#[cfg(feature = "full")]
impl InitChain for Bitcoin {
    fn init_chain(&mut self, ctx: &InitChainCtx) -> Result<()> {
        self.checkpoints.push_building()?;

        Ok(())
    }
}
