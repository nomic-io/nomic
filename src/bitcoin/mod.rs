use crate::error::{Error, Result};
use adapter::Adapter;
use bitcoin::hashes::Hash;
use bitcoin::{util::merkleblock::PartialMerkleTree, Transaction, Txid};
use checkpoint::CheckpointQueue;
use header_queue::HeaderQueue;
#[cfg(feature = "full")]
use orga::abci::InitChain;
use orga::call::Call;
use orga::client::Client;
use orga::coins::{Accounts, Address, Coin, Symbol};
use orga::collections::{
    map::{ChildMut, Ref},
    Deque, Map,
};
use orga::context::GetContext;
use orga::encoding::{Decode, Encode};
#[cfg(feature = "full")]
use orga::plugins::InitChainCtx;
use orga::plugins::Time;
use orga::query::Query;
use orga::state::State;
use orga::{Error as OrgaError, Result as OrgaResult};
use signatory::SignatorySet;
use threshold_sig::{Pubkey, Signature, ThresholdSig};
use txid_set::{Outpoint, OutpointSet};

pub mod adapter;
pub mod checkpoint;
pub mod header_queue;
#[cfg(feature = "full")]
pub mod relayer;
pub mod signatory;
pub mod threshold_sig;
pub mod txid_set;

#[derive(State, Debug, Clone)]
pub struct Nbtc(());
impl Symbol for Nbtc {}

#[derive(State, Call, Query, Client)]
pub struct Bitcoin {
    pub headers: HeaderQueue,
    pub processed_outpoints: OutpointSet,
    pub checkpoints: CheckpointQueue,
    pub accounts: Accounts<Nbtc>,
}

impl Bitcoin {
    #[call]
    pub fn relay_deposit(
        &mut self,
        btc_tx: Adapter<Transaction>,
        btc_height: u32,
        btc_proof: Adapter<PartialMerkleTree>,
        btc_vout: u32,
        sigset_index: u64,
        dest: Address,
    ) -> Result<()> {
        let btc_header = self
            .headers
            .get_by_height(btc_height)?
            .ok_or_else(|| OrgaError::App("Invalid bitcoin block height".to_string()))?;

        let mut txids = vec![];
        let mut block_indexes = vec![];
        let proof_merkle_root = btc_proof
            .extract_matches(&mut txids, &mut block_indexes)
            .map_err(|_| Error::BitcoinMerkleBlockError)?;
        if proof_merkle_root != btc_header.merkle_root() {
            return Err(OrgaError::App(
                "Bitcoin merkle proof does not match header".to_string(),
            ))?;
        }
        if txids.len() != 1 {
            return Err(OrgaError::App(
                "Bitcoin merkle proof contains an invalid number of txids".to_string(),
            ))?;
        }
        if txids[0] != btc_tx.txid() {
            return Err(OrgaError::App(
                "Bitcoin merkle proof does not match transaction".to_string(),
            ))?;
        }

        if btc_vout as usize >= btc_tx.output.len() {
            return Err(OrgaError::App("Output index is out of bounds".to_string()))?;
        }
        let output = &btc_tx.output[btc_vout as usize];

        let now = self
            .context::<Time>()
            .ok_or_else(|| Error::Orga(OrgaError::App("No time context available".to_string())))?
            .seconds as u64;
        let sigset = &self.checkpoints.get(sigset_index)?.sig_set;
        if now > sigset.deposit_timeout() {
            return Err(OrgaError::App("Deposit timeout has expired".to_string()))?;
        }

        let expected_script = sigset.output_script(dest.bytes().to_vec());
        if output.script_pubkey != expected_script {
            return Err(OrgaError::App(
                "Output script does not match signature set".to_string(),
            ))?;
        }

        let outpoint = (btc_tx.txid().into_inner(), btc_vout);
        if self.processed_outpoints.contains(outpoint)? {
            return Err(OrgaError::App(
                "Output has already been relayed".to_string(),
            ))?;
        }

        self.processed_outpoints
            .insert(outpoint, sigset.deposit_timeout())?;

        // TODO: subtract deposit fee
        self.accounts.deposit(dest, Nbtc::mint(output.value))?;

        Ok(())
    }
}

#[cfg(feature = "full")]
impl InitChain for Bitcoin {
    fn init_chain(&mut self, ctx: &InitChainCtx) -> OrgaResult<()> {
        self.checkpoints.push_building()?;

        Ok(())
    }
}
