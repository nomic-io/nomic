use adapter::Adapter;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use orga::call::Call;
use orga::client::Client;
use orga::collections::Map;
use orga::query::Query;
use orga::state::State;
use orga::Result;

pub mod adapter;
pub mod header_queue;
pub mod threshold_sig;

#[derive(State, Call, Query, Client)]
pub struct Bitcoin {
    pub headers: header_queue::HeaderQueue,
    relayed_txs: RelayedTxs,
}

impl Bitcoin {
    #[query]
    pub fn was_relayed(&self, txid: Adapter<Txid>) -> Result<bool> {
        self.relayed_txs.contains(txid)
    }

    // #[call]
    // pub fn deposit(&mut self, tx: Adapter<Transaction>, expiration: u64) -> Result<()> {
    //     self.relayed_txs.insert(tx.txid(), expiration)
    // }
}

#[derive(State, Call, Query, Client)]
pub struct RelayedTxs {
    expiration_queue: Map<(u64, [u8; 32]), ()>,
    txids: Map<Adapter<Txid>, ()>,
}

impl RelayedTxs {
    #[query]
    pub fn contains(&self, txid: Adapter<Txid>) -> Result<bool> {
        self.txids.contains_key(txid)
    }

    pub fn insert(&mut self, txid: Txid, expiration: u64) -> Result<()> {
        let txid = Adapter::new(txid);
        self.txids.insert(txid, ())?;
        self.expiration_queue
            .insert((expiration, txid.into_inner()), ())?;
        Ok(())
    }

    pub fn remove_expired(&mut self, now: u64) -> Result<()> {
        let mut expired = vec![];
        for entry in self.expiration_queue.iter()? {
            let (entry, _) = entry?;
            let (expiration, txid) = *entry;
            if expiration > now {
                break;
            }
            expired.push((expiration, txid));
        }

        for (expiration, txid) in expired {
            let adapter_txid = Adapter::new(Txid::from_inner(txid));
            self.txids.remove(adapter_txid)?;
            self.expiration_queue.remove((expiration, txid))?;
        }

        Ok(())
    }
}
