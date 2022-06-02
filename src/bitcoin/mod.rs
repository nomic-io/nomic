use std::ops::Deref;

use crate::error::{Error, Result};
use adapter::Adapter;
use bitcoin::hashes::Hash;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::Script;
use bitcoin::{util::merkleblock::PartialMerkleTree, Transaction, Txid};
use checkpoint::{Checkpoint, CheckpointQueue, CheckpointStatus, Input, FEE_RATE};
use header_queue::HeaderQueue;
#[cfg(feature = "full")]
use orga::abci::{BeginBlock, InitChain};
use orga::call::Call;
use orga::client::Client;
use orga::coins::{Accounts, Address, Amount, Coin, Symbol};
use orga::context::{GetContext, Context};
use orga::plugins::Paid;
use orga::collections::{
    map::{ChildMut, Ref},
    Deque, Map,
};
use orga::encoding::{Decode, Encode, Terminated};
#[cfg(feature = "full")]
use orga::plugins::{BeginBlockCtx, InitChainCtx, Validators};
use orga::plugins::{Signer, Time};
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
#[cfg(feature = "full")]
pub mod signer;
pub mod threshold_sig;
pub mod txid_set;

#[derive(State, Debug, Clone)]
pub struct Nbtc(());
impl Symbol for Nbtc {}

pub const MIN_DEPOSIT_AMOUNT: u64 = 600;
pub const MAX_WITHDRAWAL_SCRIPT_LENGTH: u64 = 64;

#[derive(State, Call, Query, Client)]
pub struct Bitcoin {
    pub headers: HeaderQueue,
    pub processed_outpoints: OutpointSet,
    pub checkpoints: CheckpointQueue,
    pub accounts: Accounts<Nbtc>,
    pub signatory_keys: SignatoryKeys,
}

pub type ConsensusKey = [u8; 32];

#[derive(Call, Query, Client, Clone)]
pub struct Xpub(ExtendedPubKey);

pub const XPUB_LENGTH: usize = 78;

impl Xpub {
    pub fn new(key: ExtendedPubKey) -> Self {
        Xpub(key)
    }
}

impl State for Xpub {
    type Encoding = Self;

    fn create(_: orga::store::Store, data: Self) -> OrgaResult<Self> {
        Ok(data)
    }

    fn flush(self) -> OrgaResult<Self> {
        Ok(self)
    }
}

impl Deref for Xpub {
    type Target = ExtendedPubKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Encode for Xpub {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        let bytes = self.0.encode();
        dest.write_all(&bytes)?;
        Ok(())
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        Ok(XPUB_LENGTH)
    }
}

impl Decode for Xpub {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let mut bytes = [0; XPUB_LENGTH];
        input.read_exact(&mut bytes)?;
        let key = ExtendedPubKey::decode(&bytes).map_err(|_| ed::Error::UnexpectedByte(32))?;
        Ok(Xpub(key))
    }
}

impl Terminated for Xpub {}

impl From<ExtendedPubKey> for Xpub {
    fn from(key: ExtendedPubKey) -> Self {
        Xpub(key)
    }
}

fn exempt_from_fee() -> Result<()> {
    let paid = Context::resolve::<Paid>()
        .ok_or_else(|| OrgaError::Coins("No Paid context found".into()))?;

    paid.give::<crate::app::Nom, _>(orga::plugins::MIN_FEE)?;

    Ok(())
}

impl Bitcoin {
    #[call]
    pub fn set_signatory_key(&mut self, signatory_key: Xpub) -> Result<()> {
        #[cfg(feature = "full")]
        {
            exempt_from_fee()?;

            let signer = self
                .context::<Signer>()
                .ok_or_else(|| Error::Orga(OrgaError::App("No Signer context available".into())))?
                .signer
                .ok_or_else(|| Error::Orga(OrgaError::App("Call must be signed".into())))?;

            let validators: &mut Validators = self.context().ok_or_else(|| {
                Error::Orga(orga::Error::App("No validator context found".to_string()))
            })?;

            let consensus_key = validators.consensus_key(signer)?.ok_or_else(|| {
                Error::Orga(orga::Error::App(
                    "Signer does not have a consensus key".to_string(),
                ))
            })?;

            if signatory_key.network != self.network() {
                return Err(Error::Orga(orga::Error::App(
                    "Signatory key network does not match network".to_string(),
                )));
            }

            self.signatory_keys.insert(consensus_key, signatory_key)?;
        }

        Ok(())
    }

    #[call]
    pub fn relay_deposit(
        &mut self,
        btc_tx: Adapter<Transaction>,
        btc_height: u32,
        btc_proof: Adapter<PartialMerkleTree>,
        btc_vout: u32,
        sigset_index: u32,
        dest: Address,
    ) -> Result<()> {
        exempt_from_fee()?;

        if dest.is_null() {
            return Err(OrgaError::App("Cannot deposit to null address".to_string()).into());
        }

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

        if output.value < MIN_DEPOSIT_AMOUNT {
            return Err(OrgaError::App(
                "Deposit amount is below minimum".to_string(),
            ))?;
        }

        let sigset = self.checkpoints.get(sigset_index)?.sigset.clone();

        let now = self
            .context::<Time>()
            .ok_or_else(|| Error::Orga(OrgaError::App("No time context available".to_string())))?
            .seconds as u64;
        if now > sigset.deposit_timeout() {
            return Err(OrgaError::App("Deposit timeout has expired".to_string()))?;
        }

        let expected_script = sigset.output_script(dest)?;
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

        let prevout = bitcoin::OutPoint {
            txid: btc_tx.txid(),
            vout: btc_vout,
        };
        let est_vsize =
            self.checkpoints
                .building_mut()?
                .push_input(prevout, &sigset, dest, output.value)?;

        // TODO: don't credit account until we're done signing including tx
        let value = output.value.checked_sub(est_vsize * FEE_RATE);

        match value {
            None => {
                return Err(OrgaError::App(
                    "Deposit amount is too small to pay its spending fee".to_string(),
                )
                .into())
            }
            Some(value) => self.accounts.deposit(dest, Nbtc::mint(value))?,
        };

        Ok(())
    }

    #[call]
    pub fn withdraw(&mut self, script_pubkey: Adapter<Script>, amount: Amount) -> Result<()> {
        exempt_from_fee()?;

        if script_pubkey.len() as u64 > MAX_WITHDRAWAL_SCRIPT_LENGTH {
            return Err(OrgaError::App("Script exceeds maximum length".to_string()).into());
        }

        let signer = self
            .context::<Signer>()
            .ok_or_else(|| Error::Orga(OrgaError::App("No Signer context available".into())))?
            .signer
            .ok_or_else(|| Error::Orga(OrgaError::App("Call must be signed".into())))?;

        self.accounts.withdraw(signer, amount)?.burn();

        let fee = (9 + script_pubkey.len() as u64) * FEE_RATE;
        let value: u64 = amount.into();
        let value = match value.checked_sub(fee) {
            None => {
                return Err(OrgaError::App(
                    "Withdrawal is too small to pay its miner fee".to_string(),
                )
                .into())
            }
            Some(value) => value,
        };

        let output = bitcoin::TxOut {
            script_pubkey: script_pubkey.into_inner(),
            value,
        };

        let mut checkpoint = self.checkpoints.building_mut()?;
        checkpoint.outputs.push_back(Adapter::new(output))?;

        Ok(())
    }

    #[query]
    pub fn value_locked(&self) -> Result<u64> {
        if let Some(checkpoint) = self.checkpoints.back()? {
            checkpoint.get_tvl()
        } else {
            Ok(0)
        }
    }

    pub fn network(&self) -> bitcoin::Network {
        self.headers.network()
    }
}

#[cfg(feature = "full")]
impl BeginBlock for Bitcoin {
    fn begin_block(&mut self, ctx: &BeginBlockCtx) -> OrgaResult<()> {
        self.checkpoints
            .maybe_step(self.signatory_keys.map())
            .map_err(|err| OrgaError::App(err.to_string()))?;

        Ok(())
    }
}

#[derive(State, Call, Query, Client)]
pub struct SignatoryKeys {
    by_cons: Map<ConsensusKey, Xpub>,
    xpubs: Map<Xpub, ()>,
}

impl SignatoryKeys {
    pub fn map(&self) -> &Map<ConsensusKey, Xpub> {
        &self.by_cons
    }

    pub fn insert(&mut self, consensus_key: ConsensusKey, xpub: Xpub) -> Result<()> {
        let mut normalized_xpub = xpub.clone();
        normalized_xpub.0.child_number = 0.into();
        normalized_xpub.0.depth = 0;
        normalized_xpub.0.parent_fingerprint = Default::default();

        if self.xpubs.contains_key(normalized_xpub.clone())? {
            return Err(OrgaError::App("Duplicate signatory key".to_string()).into());
        }

        if self.by_cons.contains_key(consensus_key)? {
            return Err(OrgaError::App("Validator already has a signatory key".to_string()).into());
        }

        self.by_cons.insert(consensus_key, xpub)?;
        self.xpubs.insert(normalized_xpub, ())?;

        Ok(())
    }
}
