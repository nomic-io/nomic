#[cfg(feature = "full")]
use super::ConsensusKey;
use super::{
    adapter::Adapter,
    signatory::SignatorySet,
    threshold_sig::{Signature, ThresholdSig},
    Xpub,
};
use crate::bitcoin::{signatory::derive_pubkey, Nbtc};
use crate::error::{Error, Result};
use bitcoin::hashes::Hash;
use bitcoin::{
    blockdata::transaction::EcdsaSighashType, hashes::hex::ToHex, PackedLockTime, Sequence,
    Transaction, TxIn, TxOut,
};
use derive_more::{Deref, DerefMut};

use log::info;
#[cfg(feature = "full")]
use orga::collections::Map;
#[cfg(feature = "full")]
use orga::context::GetContext;
use orga::encoding::Terminated;
#[cfg(feature = "full")]
use orga::plugins::Time;
use orga::prelude::Accounts;
use orga::store::Store;
use orga::{
    call::Call,
    client::Client,
    collections::{map::ReadOnly, ChildMut, Deque, Ref},
    encoding::{Decode, Encode, LengthVec},
    migrate::MigrateFrom,
    orga,
    prelude::Context,
    query::Query,
    state::State,
    Error as OrgaError, Result as OrgaResult,
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, str::FromStr};

pub const EMERGENCY_DISBURSAL_MIN_TX_AMT: u64 = 1000;
pub const EMERGENCY_DISBURSAL_LOCK_TIME_INTERVAL: u32 = 30; //one week

pub const EMERGENCY_DISBURSAL_MAX_TX_SIZE: u64 = 50_000; //50kB

#[derive(Debug, Encode, Decode, Default, Serialize, Deserialize)]
pub enum CheckpointStatus {
    #[default]
    Building,
    Signing,
    Complete,
}

impl MigrateFrom for CheckpointStatus {
    fn migrate_from(other: Self) -> orga::Result<Self> {
        Ok(other)
    }
}

// TODO: make it easy to derive State for simple types like this
impl State for CheckpointStatus {
    #[inline]
    fn attach(&mut self, _: Store) -> OrgaResult<()> {
        Ok(())
    }

    #[inline]
    fn flush<W: std::io::Write>(self, out: &mut W) -> OrgaResult<()> {
        Ok(self.encode_into(out)?)
    }

    fn load(_store: Store, bytes: &mut &[u8]) -> OrgaResult<Self> {
        Ok(Self::decode(bytes)?)
    }
}

impl Query for CheckpointStatus {
    type Query = ();

    fn query(&self, _: ()) -> OrgaResult<()> {
        Ok(())
    }
}

impl Call for CheckpointStatus {
    type Call = ();

    fn call(&mut self, _: ()) -> OrgaResult<()> {
        Ok(())
    }
}

impl<U: Send + Clone> Client<U> for CheckpointStatus {
    type Client = orga::client::PrimitiveClient<Self, U>;

    fn create_client(parent: U) -> Self::Client {
        orga::client::PrimitiveClient::new(parent)
    }
}

// impl Describe for CheckpointStatus {
//     fn describe() -> orga::describe::Descriptor {
//         orga::describe::Builder::new::<Self>().build()
//     }
// }

#[orga(skip(Client), version = 1)]
#[derive(Debug)]
pub struct Input {
    pub prevout: Adapter<bitcoin::OutPoint>,
    pub script_pubkey: Adapter<bitcoin::Script>,
    pub redeem_script: Adapter<bitcoin::Script>,
    pub sigset_index: u32,
    #[cfg(not(feature = "testnet"))]
    #[orga(version(V0))]
    pub dest: orga::coins::Address,
    #[cfg(feature = "testnet")]
    #[orga(version(V0))]
    pub dest: LengthVec<u16, u8>,
    #[orga(version(V1))]
    pub dest: LengthVec<u16, u8>,
    pub amount: u64,
    pub est_witness_vsize: u64,
    pub signatures: ThresholdSig,
}

impl Input {
    pub fn to_txin(&self) -> Result<TxIn> {
        let mut witness = self.signatures.to_witness()?;
        if self.signatures.done() {
            witness.push(self.redeem_script.to_bytes());
        }

        Ok(bitcoin::TxIn {
            previous_output: *self.prevout,
            script_sig: bitcoin::Script::new(),
            sequence: Sequence(u32::MAX),
            witness: bitcoin::Witness::from_vec(witness),
        })
    }

    pub fn new(
        prevout: bitcoin::OutPoint,
        sigset: &SignatorySet,
        dest: &[u8],
        amount: u64,
    ) -> Result<Self> {
        let script_pubkey = sigset.output_script(dest)?;
        let redeem_script = sigset.redeem_script(dest)?;

        Ok(Input {
            prevout: Adapter::new(prevout),
            script_pubkey: Adapter::new(script_pubkey),
            redeem_script: Adapter::new(redeem_script),
            sigset_index: sigset.index(),
            dest: dest.encode()?.try_into()?,
            amount,
            est_witness_vsize: sigset.est_witness_vsize(),
            signatures: ThresholdSig::from_sigset(sigset)?,
        })
    }

    pub fn est_vsize(&self) -> u64 {
        self.est_witness_vsize + 40
    }
}

impl MigrateFrom<InputV0> for InputV1 {
    fn migrate_from(other: InputV0) -> OrgaResult<Self> {
        Ok(Self {
            prevout: other.prevout,
            script_pubkey: other.script_pubkey,
            redeem_script: other.redeem_script,
            sigset_index: other.sigset_index,
            #[cfg(not(feature = "testnet"))]
            dest: other.dest.encode()?.try_into()?,
            #[cfg(feature = "testnet")]
            dest: other.dest,
            amount: other.amount,
            est_witness_vsize: other.est_witness_vsize,
            signatures: other.signatures,
        })
    }
}

pub type Output = Adapter<bitcoin::TxOut>;

#[orga]
#[derive(Debug)]
pub struct BitcoinTx {
    pub lock_time: u32,
    pub signed_inputs: u16,
    pub input: Deque<Input>,
    pub output: Deque<Output>,
}

impl BitcoinTx {
    pub fn to_bitcoin_tx(&self) -> Result<Transaction> {
        Ok(bitcoin::Transaction {
            version: 1,
            lock_time: PackedLockTime(self.lock_time),
            input: self
                .input
                .iter()?
                .map(|input| input?.to_txin())
                .collect::<Result<Vec<TxIn>>>()?,
            output: self
                .output
                .iter()?
                .map(|output| Ok((**output?).clone()))
                .collect::<Result<Vec<TxOut>>>()?,
        })
    }

    fn with_lock_time(lock_time: u32) -> Self {
        BitcoinTx {
            lock_time,
            ..Default::default()
        }
    }

    pub fn done(&self) -> bool {
        self.signed_inputs as u64 == self.input.len()
    }

    pub fn size(&self) -> Result<u64> {
        Ok(self.to_bitcoin_tx()?.vsize().try_into()?)
    }

    pub fn txid(&self) -> Result<bitcoin::Txid> {
        let bitcoin_tx = self.to_bitcoin_tx()?;
        Ok(bitcoin_tx.txid())
    }

    pub fn value(&self) -> Result<u64> {
        self.output
            .iter()?
            .fold(Ok(0), |sum: Result<u64>, out| Ok(sum? + out?.value))
    }

    pub fn populate_input_sig_message(&mut self, input_index: usize) -> Result<()> {
        let bitcoin_tx = self.to_bitcoin_tx()?;
        let mut sc = bitcoin::util::sighash::SighashCache::new(&bitcoin_tx);
        let mut input = self
            .input
            .get_mut(input_index as u64)?
            .ok_or(Error::InputIndexOutOfBounds(input_index))?;

        let sighash = sc.segwit_signature_hash(
            input_index,
            &input.redeem_script,
            input.amount,
            EcdsaSighashType::All,
        )?;

        input.signatures.set_message(sighash.into_inner());

        Ok(())
    }
}

pub enum BatchType {
    Disbursal,
    IntermediateTx,
    Checkpoint,
}

#[orga(skip(Default))]
#[derive(Debug)]
pub struct Checkpoint {
    pub status: CheckpointStatus,
    pub batches: Deque<Deque<BitcoinTx>>,
    signed_batches: u16,
    pub sigset: SignatorySet,
}

impl Checkpoint {
    pub fn new(sigset: SignatorySet) -> Result<Self> {
        let mut checkpoint = Checkpoint {
            status: CheckpointStatus::default(),
            batches: Deque::default(),
            signed_batches: 0,
            sigset,
        };

        let disbursal_batch = Deque::default();
        checkpoint.batches.push_front(disbursal_batch)?;

        let intermediate_tx = BitcoinTx::default();
        let mut intermediate_tx_batch = Deque::default();
        intermediate_tx_batch.push_back(intermediate_tx)?;
        checkpoint.batches.push_back(intermediate_tx_batch)?;

        let checkpoint_tx = BitcoinTx::default();
        let mut checkpoint_batch = Deque::default();
        checkpoint_batch.push_back(checkpoint_tx)?;
        checkpoint.batches.push_back(checkpoint_batch)?;

        Ok(checkpoint)
    }

    pub fn checkpoint_tx(&self) -> Result<bitcoin::Transaction> {
        self.batches
            .back()?
            .unwrap()
            .back()?
            .unwrap()
            .to_bitcoin_tx()
    }

    pub fn reserve_output(&self) -> Result<Option<TxOut>> {
        let checkpoint_tx = self.checkpoint_tx()?;
        if let Some(output) = checkpoint_tx.output.get(0) {
            Ok(Some(output.clone()))
        } else {
            Ok(None)
        }
    }

    //TODO: thread local secpk256k1 context
    #[query]
    pub fn to_sign(&self, xpub: Xpub) -> Result<Vec<([u8; 32], u32)>> {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        let mut msgs = vec![];

        let batch = self.current_batch()?;
        if batch.is_none() {
            return Ok(msgs);
        }

        for tx in batch.unwrap().iter()? {
            for input in tx?.input.iter()? {
                let input = input?;

                let pubkey = derive_pubkey(&secp, xpub.clone(), input.sigset_index)?;
                if input.signatures.needs_sig(pubkey.into())? {
                    msgs.push((input.signatures.message(), input.sigset_index));
                }
            }
        }

        Ok(msgs)
    }

    pub fn current_batch(&self) -> Result<Option<Ref<Deque<BitcoinTx>>>> {
        if self.signed() {
            return Ok(None);
        }

        Ok(Some(self.batches.get(self.signed_batches as u64)?.unwrap()))
    }

    pub fn create_time(&self) -> u64 {
        self.sigset.create_time()
    }

    #[query]
    pub fn get_tvl(&self) -> Result<u64> {
        let checkpoint_tx = self.checkpoint_tx()?;
        Ok(checkpoint_tx.input.iter().fold(0, |mut acc, input| {
            acc += input.previous_output.vout as u64 * 1_000_000;
            acc
        }))
    }

    pub fn signed(&self) -> bool {
        self.signed_batches as u64 == self.batches.len()
    }
}

#[derive(Clone, Serialize)]
pub struct Config {
    pub min_checkpoint_interval: u64,
    pub max_checkpoint_interval: u64,
    pub max_inputs: u64,
    pub max_outputs: u64,
    pub fee_rate: u64,
    pub max_age: u64,
}

impl Config {
    fn regtest() -> Self {
        Self {
            min_checkpoint_interval: 1,
            max_checkpoint_interval: 60 * 60 * 8,
            max_inputs: 40,
            max_outputs: 200,
            fee_rate: 102,
            max_age: 60 * 60 * 24 * 7 * 3,
        }
    }

    fn bitcoin() -> Self {
        Self {
            min_checkpoint_interval: 60 * 5,
            max_checkpoint_interval: 60 * 60 * 8,
            max_inputs: 40,
            max_outputs: 200,
            fee_rate: 102,
            max_age: 60 * 60 * 24 * 7 * 3,
        }
    }
}

impl Terminated for Config {}

impl Default for Config {
    fn default() -> Self {
        match super::NETWORK {
            bitcoin::Network::Regtest => Config::regtest(),
            bitcoin::Network::Testnet | bitcoin::Network::Bitcoin => Config::bitcoin(),
            _ => unimplemented!(),
        }
    }
}

impl MigrateFrom for Config {
    fn migrate_from(other: Self) -> orga::Result<Self> {
        Ok(other)
    }
}

#[orga]
pub struct CheckpointQueue {
    pub(super) queue: Deque<Checkpoint>,
    pub(super) index: u32,
    #[state(skip)]
    config: Config,
}

#[derive(Deref)]
pub struct CompletedCheckpoint<'a>(Ref<'a, Checkpoint>);

#[derive(Deref, Debug)]
pub struct SigningCheckpoint<'a>(Ref<'a, Checkpoint>);

impl<'a, U: Clone> Client<U> for SigningCheckpoint<'a> {
    type Client = ();

    fn create_client(_: U) {}
}

impl<'a> Query for SigningCheckpoint<'a> {
    type Query = ();

    fn query(&self, _: ()) -> OrgaResult<()> {
        Ok(())
    }
}

impl<'a> SigningCheckpoint<'a> {
    pub fn current_batch(&self) -> Result<Option<Ref<Deque<BitcoinTx>>>> {
        if self.signed() {
            return Ok(None);
        }

        Ok(Some(self.batches.get(self.signed_batches as u64)?.unwrap()))
    }
}

#[derive(Deref, DerefMut)]
pub struct SigningCheckpointMut<'a>(ChildMut<'a, u64, Checkpoint>);

impl<'a> SigningCheckpointMut<'a> {
    pub fn sign(&mut self, xpub: Xpub, sigs: LengthVec<u16, Signature>) -> Result<()> {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        let batch = self.current_batch_mut()?;
        if batch.is_none() {
            return Err(OrgaError::App("No batch to sign".to_string()).into());
        }

        let mut sig_index = 0;
        let mut batch = batch.unwrap();

        for i in 0..batch.len() {
            let mut tx = batch.get_mut(i)?.unwrap();
            if tx.done() {
                continue;
            }

            for j in 0..tx.input.len() {
                let mut input = tx.input.get_mut(j)?.unwrap();
                let pubkey = derive_pubkey(&secp, xpub.clone(), input.sigset_index)?;

                if !input.signatures.contains_key(pubkey.into())? {
                    continue;
                }

                if input.signatures.done() {
                    sig_index += 1;
                    continue;
                }

                if sig_index > sigs.len() {
                    return Err(OrgaError::App("Not enough signatures supplied".to_string()).into());
                }

                let sig = sigs[sig_index];
                sig_index += 1;

                input.signatures.sign(pubkey.into(), sig)?;

                if input.signatures.done() {
                    tx.signed_inputs += 1;
                }
            }
        }

        if sig_index != sigs.len() {
            return Err(OrgaError::App("Excess signatures supplied".to_string()).into());
        }

        self.signed_batches += 1;

        Ok(())
    }

    pub fn done(&self) -> bool {
        self.batches.len() == self.signed_batches as u64
    }

    pub fn advance(self) -> Result<()> {
        let mut checkpoint = self.0;

        checkpoint.status = CheckpointStatus::Complete;

        Ok(())
    }

    pub fn current_batch_mut(&mut self) -> Result<Option<ChildMut<u64, Deque<BitcoinTx>>>> {
        if self.done() {
            return Ok(None);
        }
        let signed_batches = self.signed_batches as u64;
        let batch = self.batches.get_mut(signed_batches)?.unwrap();

        Ok(Some(batch))
    }
}

#[derive(Deref)]
pub struct BuildingCheckpoint<'a>(Ref<'a, Checkpoint>);

#[derive(Deref, DerefMut)]
pub struct BuildingCheckpointMut<'a>(ChildMut<'a, u64, Checkpoint>);

type BuildingAdvanceRes = (
    bitcoin::OutPoint,
    u64,
    Vec<ReadOnly<Input>>,
    Vec<ReadOnly<Output>>,
);

impl<'a> BuildingCheckpointMut<'a> {
    fn link_intermediate_tx(&mut self, tx: &mut BitcoinTx) -> Result<()> {
        let sigset = self.sigset.clone();
        let output_script = sigset.output_script(&[0u8])?;
        let tx_value = tx.value()?;

        let mut intermediate_tx_batch = self
            .batches
            .get_mut(BatchType::IntermediateTx as u64)?
            .unwrap();
        let mut intermediate_tx = intermediate_tx_batch.get_mut(0)?.unwrap();
        let num_outputs = u32::try_from(intermediate_tx.output.len())?;

        let final_tx_input = Input::new(
            bitcoin::OutPoint::new(intermediate_tx.txid()?, num_outputs + 1),
            &sigset,
            &[0u8],
            tx_value,
        )?;

        let intermediate_tx_output = bitcoin::TxOut {
            value: tx_value,
            script_pubkey: output_script,
        };

        intermediate_tx
            .output
            .push_back(intermediate_tx_output.into())?;

        tx.input.push_back(final_tx_input)?;

        Ok(())
    }

    //TODO: Generalize emergency disbursal to dynamic tree structure for intermediate tx overflow
    fn generate_emergency_disbursal_txs(
        &mut self,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::prelude::Address, Adapter<bitcoin::Script>>,
        reserve_outpoint: bitcoin::OutPoint,
    ) -> Result<()> {
        let time = Context::resolve::<Time>()
            .ok_or_else(|| OrgaError::Coins("No Time context found".into()))?;

        let sigset = self.sigset.clone();

        let lock_time = time.seconds as u32 + EMERGENCY_DISBURSAL_LOCK_TIME_INTERVAL;

        if nbtc_accounts.iter()?.last().is_none() {
            return Err(Error::Account("No Bitcoin accounts present".to_string()));
        }
        let mut final_txs = vec![BitcoinTx::with_lock_time(lock_time)];
        for account in nbtc_accounts.iter()? {
            let (address, coins) = account?;
            if coins.amount < EMERGENCY_DISBURSAL_MIN_TX_AMT {
                continue;
            }

            let mut curr_tx = final_txs.pop().unwrap();
            if curr_tx.size()? >= EMERGENCY_DISBURSAL_MAX_TX_SIZE {
                self.link_intermediate_tx(&mut curr_tx)?;
                final_txs.push(curr_tx);
                curr_tx = BitcoinTx::with_lock_time(lock_time);
            }

            //TODO: Move address to script logic to a function
            let hash = bitcoin::hashes::hash160::Hash::from_str(address.bytes().to_hex().as_str())
                .map_err(|err| Error::BitcoinPubkeyHash(err.to_string()))?;
            let pubkey_hash = bitcoin::PubkeyHash::from(hash);
            let dest_script = match recovery_scripts.get(*address)? {
                Some(script) => script.clone(),
                None => Adapter::new(bitcoin::Script::new_p2pkh(&pubkey_hash)),
            };

            let tx_out = bitcoin::TxOut {
                value: u64::from(coins.amount) / 1_000_000,
                script_pubkey: dest_script.into_inner(),
            };

            curr_tx.output.push_back(Adapter::new(tx_out))?;
            final_txs.push(curr_tx);
        }

        let intermediate_tx_len = self
            .batches
            .get(BatchType::IntermediateTx as u64)?
            .unwrap()
            .get(0)?
            .unwrap()
            .output
            .len();

        let disbursal_batch = self.batches.get(BatchType::Disbursal as u64)?.unwrap();
        if intermediate_tx_len < disbursal_batch.len() {
            self.link_intermediate_tx(final_txs.last_mut().unwrap())?;
        }

        let tx_in = Input::new(
            reserve_outpoint,
            &sigset,
            &[0u8],
            reserve_outpoint.vout as u64,
        )?;

        let mut intermediate_tx_batch = self
            .batches
            .get_mut(BatchType::IntermediateTx as u64)?
            .unwrap();
        let mut intermediate_tx = intermediate_tx_batch.get_mut(0)?.unwrap();

        intermediate_tx.input.push_back(tx_in)?;

        let mut disbursal_batch = self.batches.get_mut(BatchType::Disbursal as u64)?.unwrap();
        for tx in final_txs {
            disbursal_batch.push_back(tx)?;
        }

        Ok(())
    }

    pub fn advance(
        mut self,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::prelude::Address, Adapter<bitcoin::Script>>,
        config: &Config,
    ) -> Result<BuildingAdvanceRes> {
        self.0.status = CheckpointStatus::Signing;

        let reserve_out = bitcoin::TxOut {
            value: 0, // will be updated after counting ins/outs and fees
            script_pubkey: self.0.sigset.output_script(&[0u8])?, // TODO: double-check safety
        };

        let mut checkpoint_batch = self
            .0
            .batches
            .get_mut(BatchType::Checkpoint as u64)?
            .unwrap();
        let mut checkpoint_tx = checkpoint_batch.get_mut(0)?.unwrap();

        checkpoint_tx.output.push_front(Adapter::new(reserve_out))?;

        let mut excess_inputs = vec![];
        while checkpoint_tx.input.len() > config.max_inputs {
            let removed_input = checkpoint_tx.input.pop_back()?.unwrap();
            excess_inputs.push(removed_input);
        }

        let mut excess_outputs = vec![];
        while checkpoint_tx.output.len() > config.max_outputs {
            let removed_output = checkpoint_tx.output.pop_back()?.unwrap();
            excess_outputs.push(removed_output);
        }

        //TODO: Input/Output sum functions
        let mut in_amount = 0;
        for i in 0..checkpoint_tx.input.len() {
            let input = checkpoint_tx.input.get(i)?.unwrap();
            in_amount += input.amount;
        }

        let mut out_amount = 0;
        for i in 0..checkpoint_tx.output.len() {
            let output = checkpoint_tx.output.get(i)?.unwrap();
            out_amount += output.value;
        }

        let est_vsize: u64 = checkpoint_tx.to_bitcoin_tx()?.vsize().try_into()?;
        let fee = est_vsize * config.fee_rate;
        let reserve_value = in_amount - out_amount - fee;
        let mut reserve_out = checkpoint_tx.output.get_mut(0)?.unwrap();
        reserve_out.value = reserve_value;

        let bitcoin_tx = checkpoint_tx.to_bitcoin_tx()?;
        let mut sc = bitcoin::util::sighash::SighashCache::new(&bitcoin_tx);
        for i in 0..checkpoint_tx.input.len() {
            let mut input = checkpoint_tx.input.get_mut(i)?.unwrap();
            let sighash = sc.segwit_signature_hash(
                i as usize,
                &input.redeem_script,
                input.amount,
                EcdsaSighashType::All,
            )?;
            input.signatures.set_message(sighash.into_inner());
        }

        let reserve_outpoint = bitcoin::OutPoint {
            txid: checkpoint_tx.txid()?,
            vout: 0,
        };

        self.generate_emergency_disbursal_txs(nbtc_accounts, recovery_scripts, reserve_outpoint)?;

        Ok((
            reserve_outpoint,
            reserve_value,
            excess_inputs,
            excess_outputs,
        ))
    }
}

impl CheckpointQueue {
    pub fn configure(&mut self, config: Config) {
        self.config = config;
    }

    pub fn config(&self) -> Config {
        self.config.clone()
    }

    pub fn reset(&mut self) -> OrgaResult<()> {
        self.index = 0;
        super::clear_deque(&mut self.queue)?;

        Ok(())
    }

    #[query]
    pub fn get(&self, index: u32) -> Result<Ref<'_, Checkpoint>> {
        let index = self.get_deque_index(index)?;
        Ok(self.queue.get(index as u64)?.unwrap())
    }

    pub fn get_mut(&mut self, index: u32) -> Result<ChildMut<'_, u64, Checkpoint>> {
        let index = self.get_deque_index(index)?;
        Ok(self.queue.get_mut(index as u64)?.unwrap())
    }

    fn get_deque_index(&self, index: u32) -> Result<u32> {
        let start = self.index + 1 - (self.queue.len() as u32);
        if index > self.index || index < start {
            Err(OrgaError::App("Index out of bounds".to_string()).into())
        } else {
            Ok(index - start)
        }
    }

    // TODO: remove this attribute, not sure why clippy is complaining when is_empty is defined
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> Result<u32> {
        Ok(u32::try_from(self.queue.len())?)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    #[query]
    pub fn index(&self) -> u32 {
        self.index
    }

    #[query]
    pub fn all(&self) -> Result<Vec<(u32, Ref<'_, Checkpoint>)>> {
        // TODO: return iterator
        // TODO: use Deque iterator

        let mut out = Vec::with_capacity(self.queue.len() as usize);

        for i in 0..self.queue.len() {
            let checkpoint = self.queue.get(i)?.unwrap();
            out.push((
                (self.index + 1 - (self.queue.len() as u32 - i as u32)),
                checkpoint,
            ));
        }

        Ok(out)
    }

    #[query]
    pub fn completed(&self) -> Result<Vec<CompletedCheckpoint<'_>>> {
        // TODO: return iterator
        // TODO: use Deque iterator

        let mut out = vec![];

        for i in 0..self.queue.len() {
            let checkpoint = self.queue.get(i)?.unwrap();

            if !matches!(checkpoint.status, CheckpointStatus::Complete) {
                break;
            }

            out.push(CompletedCheckpoint(checkpoint));
        }

        Ok(out)
    }

    #[query]
    pub fn last_completed_tx(&self) -> Result<Adapter<bitcoin::Transaction>> {
        let index = if self.signing()?.is_some() {
            self.index.checked_sub(2)
        } else {
            self.index.checked_sub(1)
        }
        .ok_or_else(|| Error::Orga(OrgaError::App("No completed checkpoints yet".to_string())))?;

        let bitcoin_tx = self.get(index)?.checkpoint_tx()?;
        Ok(Adapter::new(bitcoin_tx))
    }

    #[query]
    pub fn completed_txs(&self) -> Result<Vec<Adapter<bitcoin::Transaction>>> {
        self.completed()?
            .into_iter()
            .map(|c| Ok(Adapter::new(c.checkpoint_tx()?)))
            .collect()
    }

    #[query]
    pub fn emergency_disbursal_txs(&self) -> Result<Vec<Adapter<bitcoin::Transaction>>> {
        let mut vec = vec![];

        if let Some(completed) = self.completed()?.last() {
            let disbursal_batch = completed.batches.get(BatchType::Disbursal as u64)?.unwrap();
            for tx in disbursal_batch.iter()? {
                vec.push(Adapter::new(tx?.to_bitcoin_tx()?));
            }
        }

        Ok(vec)
    }

    #[query]
    pub fn signing(&self) -> Result<Option<SigningCheckpoint<'_>>> {
        if self.queue.len() < 2 {
            return Ok(None);
        }

        let second = self.get(self.index - 1)?;
        if !matches!(second.status, CheckpointStatus::Signing) {
            return Ok(None);
        }

        Ok(Some(SigningCheckpoint(second)))
    }

    pub fn signing_mut(&mut self) -> Result<Option<SigningCheckpointMut>> {
        if self.queue.len() < 2 {
            return Ok(None);
        }

        let second = self.get_mut(self.index - 1)?;
        if !matches!(second.status, CheckpointStatus::Signing) {
            return Ok(None);
        }

        Ok(Some(SigningCheckpointMut(second)))
    }

    pub fn building(&self) -> Result<BuildingCheckpoint> {
        let last = self.get(self.index)?;
        Ok(BuildingCheckpoint(last))
    }

    pub fn building_mut(&mut self) -> Result<BuildingCheckpointMut> {
        let last = self.get_mut(self.index)?;
        Ok(BuildingCheckpointMut(last))
    }

    pub fn prune(&mut self) -> Result<()> {
        let latest = self.building()?.create_time();

        while let Some(oldest) = self.queue.front()? {
            if latest - oldest.create_time() <= self.config.max_age {
                break;
            }

            self.queue.pop_front()?;
        }

        Ok(())
    }

    #[cfg(feature = "full")]
    pub fn maybe_step(
        &mut self,
        sig_keys: &Map<ConsensusKey, Xpub>,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::prelude::Address, Adapter<bitcoin::Script>>,
    ) -> Result<()> {
        if self.signing()?.is_some() {
            return Ok(());
        }

        if !self.queue.is_empty() {
            let now = self
                .context::<Time>()
                .ok_or_else(|| OrgaError::App("No time context".to_string()))?
                .seconds as u64;
            let elapsed = now - self.building()?.create_time();
            if elapsed < self.config.min_checkpoint_interval {
                return Ok(());
            }

            if elapsed < self.config.max_checkpoint_interval || self.index == 0 {
                let building = self.building()?;
                let checkpoint_tx = building.checkpoint_tx()?;

                let has_pending_deposit = if self.index == 0 {
                    !checkpoint_tx.input.is_empty()
                } else {
                    checkpoint_tx.input.len() > 1
                };

                let has_pending_withdrawal = !checkpoint_tx.output.is_empty();

                if !has_pending_deposit && !has_pending_withdrawal {
                    return Ok(());
                }
            }

            let config = self.config();
            while let Some(first) = self.queue.front()? {
                if now - first.create_time() <= config.max_age {
                    break;
                }

                self.queue.pop_front()?;
            }
        }

        if self.maybe_push(sig_keys)?.is_none() {
            return Ok(());
        }

        self.prune()?;

        if self.index > 0 {
            let config = self.config();
            let second = self.get_mut(self.index - 1)?;
            let sigset = second.sigset.clone();
            let (reserve_outpoint, reserve_value, excess_inputs, excess_outputs) =
                BuildingCheckpointMut(second).advance(nbtc_accounts, recovery_scripts, &config)?;

            let mut building = self.building_mut()?;
            let mut building_checkpoint_batch = building
                .batches
                .get_mut(BatchType::Checkpoint as u64)?
                .unwrap();
            let mut checkpoint_tx = building_checkpoint_batch.get_mut(0)?.unwrap();

            let input = Input::new(
                reserve_outpoint,
                &sigset,
                &[0u8], // TODO: double-check safety
                reserve_value,
            )?;

            checkpoint_tx.input.push_back(input)?;

            for input in excess_inputs {
                let shares = input.signatures.shares()?;
                let mut data = input.into_inner();
                data.signatures = ThresholdSig::from_shares(shares)?;
                checkpoint_tx.input.push_back(data)?;
            }

            for output in excess_outputs {
                let data = output.into_inner();
                checkpoint_tx.output.push_back(data)?;
            }
        }

        Ok(())
    }

    #[cfg(test)]
    fn push(&mut self, checkpoint: Checkpoint) -> Result<()> {
        self.index += 1;
        Ok(self.queue.push_back(checkpoint)?)
    }

    #[cfg(feature = "full")]
    fn maybe_push(
        &mut self,
        sig_keys: &Map<ConsensusKey, Xpub>,
    ) -> Result<Option<BuildingCheckpointMut>> {
        let mut index = self.index;
        if !self.queue.is_empty() {
            index += 1;
        }

        let sigset = SignatorySet::from_validator_ctx(index, sig_keys)?;

        if sigset.possible_vp() == 0 {
            return Ok(None);
        }

        if !sigset.has_quorum() {
            return Ok(None);
        }

        self.index = index;

        self.queue.push_back(Checkpoint::new(sigset)?)?;

        let building = self.building_mut()?;

        Ok(Some(building))
    }

    #[query]
    pub fn active_sigset(&self) -> Result<SignatorySet> {
        Ok(self.building()?.sigset.clone())
    }

    #[call]
    pub fn sign(&mut self, xpub: Xpub, sigs: LengthVec<u16, Signature>) -> Result<()> {
        super::exempt_from_fee()?;

        let mut signing = self
            .signing_mut()?
            .ok_or_else(|| Error::Orga(OrgaError::App("No checkpoint to be signed".to_string())))?;

        signing.sign(xpub, sigs)?;

        if signing.done() {
            let checkpoint_tx = signing.checkpoint_tx()?;
            info!("Checkpoint signing complete {:?}", checkpoint_tx);
            signing.advance()?;
        }

        Ok(())
    }

    #[query]
    pub fn to_sign(&self, xpub: Xpub) -> Result<Vec<([u8; 32], u32)>> {
        self.signing()?
            .ok_or_else(|| OrgaError::App("No checkpoint to be signed".to_string()))?
            .to_sign(xpub)
    }

    #[query]
    pub fn sigset(&self, index: u32) -> Result<SignatorySet> {
        Ok(self.get(index)?.sigset.clone())
    }
}

#[cfg(test)]
mod test {}
