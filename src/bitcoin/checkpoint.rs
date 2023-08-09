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
use bitcoin::{blockdata::transaction::EcdsaSighashType, Sequence, Transaction, TxIn, TxOut};
use derive_more::{Deref, DerefMut};
use log::info;
use orga::coins::Accounts;
#[cfg(feature = "full")]
use orga::context::GetContext;
#[cfg(feature = "full")]
use orga::plugins::Time;
use orga::{
    call::Call,
    collections::{map::ReadOnly, ChildMut, Deque, Map, Ref},
    encoding::{Decode, Encode, LengthVec},
    migrate::{Migrate, MigrateFrom},
    orga,
    query::Query,
    state::State,
    Error as OrgaError, Result as OrgaResult,
};

use orga::{describe::Describe, store::Store};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Encode, Decode, Default, Serialize, Deserialize)]
pub enum CheckpointStatus {
    #[default]
    Building,
    Signing,
    Complete,
}

impl Migrate for CheckpointStatus {}

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

impl Describe for CheckpointStatus {
    fn describe() -> orga::describe::Descriptor {
        orga::describe::Builder::new::<Self>().build()
    }
}

#[orga(version = 1)]
#[derive(Debug)]
pub struct Input {
    pub prevout: Adapter<bitcoin::OutPoint>,
    pub script_pubkey: Adapter<bitcoin::Script>,
    pub redeem_script: Adapter<bitcoin::Script>,
    pub sigset_index: u32,
    #[cfg(not(feature = "testnet"))]
    #[orga(version(V0))]
    pub dest: orga::coins::VersionedAddress,
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
    fn migrate_from(value: InputV0) -> OrgaResult<Self> {
        Ok(Self {
            prevout: value.prevout,
            script_pubkey: value.script_pubkey,
            redeem_script: value.redeem_script,
            sigset_index: value.sigset_index,
            #[cfg(not(feature = "testnet"))]
            dest: value.dest.encode()?.try_into()?,
            #[cfg(feature = "testnet")]
            dest: value.dest,
            amount: value.amount,
            est_witness_vsize: value.est_witness_vsize,
            signatures: value.signatures,
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
            lock_time: bitcoin::PackedLockTime(self.lock_time),
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

    pub fn with_lock_time(lock_time: u32) -> Self {
        BitcoinTx {
            lock_time,
            ..Default::default()
        }
    }

    pub fn signed(&self) -> bool {
        self.signed_inputs as u64 == self.input.len()
    }

    pub fn vsize(&self) -> Result<u64> {
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

    pub fn deduct_fee(&mut self, fee: u64) -> Result<()> {
        if fee == 0 {
            return Ok(());
        }

        if self.output.is_empty() {
            //TODO: Bitcoin error module
            return Err(Error::BitcoinFee(fee));
        }

        let threshold = loop {
            let threshold = fee / self.output.len();
            let mut min_output = u64::MAX;
            self.output.retain_unordered(|output| {
                if output.value < min_output {
                    min_output = output.value;
                }
                Ok(output.value >= threshold)
            })?;
            if self.output.is_empty() {
                break threshold;
            }
            let threshold = fee / self.output.len();
            if min_output >= threshold {
                break threshold;
            }
        };

        for i in 0..self.output.len() {
            let mut output = self.output.get_mut(i)?.unwrap();
            output.value -= threshold;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum BatchType {
    Disbursal,
    IntermediateTx,
    Checkpoint,
}

#[orga]
pub struct Batch {
    batch: Deque<BitcoinTx>,
    signed_txs: u16,
}

impl Deref for Batch {
    type Target = Deque<BitcoinTx>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl DerefMut for Batch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.batch
    }
}

impl Batch {
    fn signed(&self) -> bool {
        self.signed_txs as u64 == self.batch.len()
    }
}

#[orga(skip(Default), version = 1)]
#[derive(Debug)]
pub struct Checkpoint {
    pub status: CheckpointStatus,

    #[orga(version(V0))]
    pub inputs: Deque<Input>,
    #[orga(version(V0))]
    signed_inputs: u16,
    #[orga(version(V0))]
    pub outputs: Deque<Output>,

    #[orga(version(V1))]
    pub batches: Deque<Batch>,

    pub sigset: SignatorySet,
}

impl MigrateFrom<CheckpointV0> for CheckpointV1 {
    fn migrate_from(value: CheckpointV0) -> OrgaResult<Self> {
        let bitcoin_tx = BitcoinTx {
            input: value.inputs,
            output: value.outputs,
            signed_inputs: value.signed_inputs,
            lock_time: 0,
        };

        let mut batches = Deque::default();
        batches.push_back(Batch::default())?;
        batches.push_back(Batch::default())?;

        let mut batch = Batch::default();
        if bitcoin_tx.signed() {
            batch.signed_txs = 1;
        }
        batch.push_back(bitcoin_tx)?;

        batches.push_back(batch)?;
        Ok(Self {
            status: value.status,
            sigset: value.sigset,
            batches,
        })
    }
}

#[orga]
impl Checkpoint {
    pub fn new(sigset: SignatorySet) -> Result<Self> {
        let mut checkpoint = Checkpoint {
            status: CheckpointStatus::default(),
            batches: Deque::default(),
            sigset,
        };

        let disbursal_batch = Batch::default();
        checkpoint.batches.push_front(disbursal_batch)?;

        #[allow(unused_mut)]
        let mut intermediate_tx_batch = Batch::default();
        #[cfg(feature = "emergency-disbursal")]
        intermediate_tx_batch.push_back(BitcoinTx::default())?;
        checkpoint.batches.push_back(intermediate_tx_batch)?;

        let checkpoint_tx = BitcoinTx::default();
        let mut checkpoint_batch = Batch::default();
        checkpoint_batch.push_back(checkpoint_tx)?;
        checkpoint.batches.push_back(checkpoint_batch)?;

        Ok(checkpoint)
    }

    pub fn checkpoint_tx(&self) -> Result<bitcoin::Transaction> {
        self.batches
            .get(BatchType::Checkpoint as u64)?
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

    fn signed_batches(&self) -> Result<u64> {
        let mut signed_batches = 0;
        for batch in self.batches.iter()? {
            if batch?.signed() {
                signed_batches += 1;
            } else {
                break;
            }
        }

        Ok(signed_batches)
    }

    pub fn current_batch(&self) -> Result<Option<Ref<Batch>>> {
        if self.signed()? {
            return Ok(None);
        }

        Ok(Some(self.batches.get(self.signed_batches()?)?.unwrap()))
    }

    pub fn create_time(&self) -> u64 {
        self.sigset.create_time()
    }

    pub fn signed(&self) -> Result<bool> {
        Ok(self.signed_batches()? == self.batches.len())
    }
}

#[orga(skip(Default))]
#[derive(Clone)]
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
            min_checkpoint_interval: 15,
            ..Config::bitcoin()
        }
    }

    fn bitcoin() -> Self {
        Self {
            min_checkpoint_interval: 60 * 5,
            max_checkpoint_interval: 60 * 60 * 8,
            max_inputs: 40,
            max_outputs: 200,
            fee_rate: 2,
            max_age: 60 * 60 * 24 * 7 * 3,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        match super::NETWORK {
            bitcoin::Network::Regtest => Config::regtest(),
            bitcoin::Network::Testnet | bitcoin::Network::Bitcoin => Config::bitcoin(),
            _ => unimplemented!(),
        }
    }
}

#[orga(version = 1)]
pub struct CheckpointQueue {
    pub(super) queue: Deque<Checkpoint>,
    pub(super) index: u32,
    #[orga(version(V1))]
    config: Config,
}

impl MigrateFrom<CheckpointQueueV0> for CheckpointQueueV1 {
    fn migrate_from(value: CheckpointQueueV0) -> OrgaResult<Self> {
        Ok(Self {
            queue: value.queue,
            index: value.index,
            config: Config::default(),
        })
    }
}

#[derive(Deref)]
pub struct CompletedCheckpoint<'a>(Ref<'a, Checkpoint>);

#[derive(Deref, Debug)]
pub struct SigningCheckpoint<'a>(Ref<'a, Checkpoint>);

impl<'a> Query for SigningCheckpoint<'a> {
    type Query = ();

    fn query(&self, _: ()) -> OrgaResult<()> {
        Ok(())
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
            if tx.signed() {
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

            if tx.signed() {
                batch.signed_txs += 1;
            }
        }

        if sig_index != sigs.len() {
            return Err(OrgaError::App("Excess signatures supplied".to_string()).into());
        }

        Ok(())
    }

    pub fn signed(&self) -> Result<bool> {
        Ok(self.batches.len() == self.signed_batches()?)
    }

    pub fn advance(self) -> Result<()> {
        let mut checkpoint = self.0;

        checkpoint.status = CheckpointStatus::Complete;

        Ok(())
    }

    pub fn current_batch_mut(&mut self) -> Result<Option<ChildMut<u64, Batch>>> {
        if self.signed()? {
            return Ok(None);
        }
        let signed_batches = self.signed_batches()?;
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
    #[cfg(feature = "emergency-disbursal")]
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
            bitcoin::OutPoint::new(intermediate_tx.txid()?, num_outputs),
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

    //TODO: Unit tests
    #[cfg(feature = "emergency-disbursal")]
    fn deduct_emergency_disbursal_fees(&mut self, fee_rate: u64) -> Result<()> {
        let intermediate_tx_fee = {
            let mut intermediate_tx_batch = self
                .batches
                .get_mut(BatchType::IntermediateTx as u64)?
                .unwrap();
            let mut intermediate_tx = intermediate_tx_batch.get_mut(0)?.unwrap();
            let fee = intermediate_tx.vsize()? * fee_rate;
            intermediate_tx.deduct_fee(fee)?;
            fee
        };

        let intermediate_tx_batch = self.batches.get(BatchType::IntermediateTx as u64)?.unwrap();
        let intermediate_tx = intermediate_tx_batch.get(0)?.unwrap();
        let intermediate_tx_id = intermediate_tx.txid()?;
        let intermediate_tx_len = intermediate_tx.output.len();
        let mut intermediate_tx_outputs: Vec<(usize, u64)> = intermediate_tx
            .output
            .iter()?
            .enumerate()
            .map(|(i, output)| Ok((i, output?.value)))
            .collect::<Result<_>>()?;

        let mut disbursal_batch = self.batches.get_mut(BatchType::Disbursal as u64)?.unwrap();
        disbursal_batch.retain_unordered(|mut tx| {
            let mut input = tx.input.get_mut(0)?.unwrap();
            input.amount -= intermediate_tx_fee / intermediate_tx_len;
            for (i, output) in intermediate_tx_outputs.iter() {
                if output == &(input.amount) {
                    input.prevout = Adapter::new(bitcoin::OutPoint {
                        txid: intermediate_tx_id,
                        vout: *i as u32,
                    });
                    intermediate_tx_outputs.remove(*i);
                    let tx_size = tx.vsize().map_err(|err| OrgaError::App(err.to_string()))?;
                    let fee = intermediate_tx_fee / intermediate_tx_len + tx_size * fee_rate;
                    tx.deduct_fee(fee)
                        .map_err(|err| OrgaError::App(err.to_string()))?;
                    return Ok(true);
                }
            }
            Ok(false)
        })?;

        Ok(())
    }

    //TODO: Generalize emergency disbursal to dynamic tree structure for intermediate tx overflow
    #[cfg(feature = "emergency-disbursal")]
    fn generate_emergency_disbursal_txs(
        &mut self,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::coins::Address, Adapter<bitcoin::Script>>,
        reserve_outpoint: bitcoin::OutPoint,
        external_outputs: impl Iterator<Item = Result<bitcoin::TxOut>>,
        fee_rate: u64,
        reserve_value: u64,
    ) -> Result<()> {
        {
            //TODO: Pull bitcoin config from state
            let bitcoin_config = super::Bitcoin::config();
            use orga::context::Context;
            let time = Context::resolve::<Time>()
                .ok_or_else(|| OrgaError::Coins("No Time context found".into()))?;

            let sigset = self.sigset.clone();

            let lock_time =
                time.seconds as u32 + bitcoin_config.emergency_disbursal_lock_time_interval;

            let outputs: Vec<_> = nbtc_accounts
                .iter()?
                .map(|entry| {
                    let (address, coins) = entry?;
                    use bitcoin::hashes::hex::ToHex;
                    use std::str::FromStr;
                    let hash =
                        bitcoin::hashes::hash160::Hash::from_str(address.bytes().to_hex().as_str())
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

                    Ok::<_, crate::error::Error>(tx_out)
                })
                .chain(external_outputs)
                .collect();

            let mut final_txs = vec![BitcoinTx::with_lock_time(lock_time)];

            let num_outputs = outputs.len();
            for (i, output) in outputs.into_iter().enumerate() {
                let output = output?;

                if output.value < bitcoin_config.emergency_disbursal_min_tx_amt {
                    continue;
                }

                let mut curr_tx = final_txs.pop().unwrap();
                if curr_tx.vsize()? >= bitcoin_config.emergency_disbursal_max_tx_size {
                    self.link_intermediate_tx(&mut curr_tx)?;
                    final_txs.push(curr_tx);
                    curr_tx = BitcoinTx::with_lock_time(lock_time);
                }

                curr_tx.output.push_back(Adapter::new(output))?;

                if i == num_outputs - 1 {
                    self.link_intermediate_tx(&mut curr_tx)?;
                }

                final_txs.push(curr_tx);
            }

            let tx_in = Input::new(reserve_outpoint, &sigset, &[0u8], reserve_value)?;
            let output_script = self.sigset.output_script(&[0u8])?;
            let mut intermediate_tx_batch = self
                .batches
                .get_mut(BatchType::IntermediateTx as u64)?
                .unwrap();
            let mut intermediate_tx = intermediate_tx_batch.get_mut(0)?.unwrap();
            intermediate_tx.lock_time = lock_time;
            intermediate_tx.input.push_back(tx_in)?;

            let intermediate_tx_out_value = intermediate_tx.value()?;
            let excess_value = reserve_value - intermediate_tx_out_value;
            let excess_tx_out = bitcoin::TxOut {
                value: excess_value,
                script_pubkey: output_script,
            };
            intermediate_tx
                .output
                .push_back(Adapter::new(excess_tx_out))?;

            let mut disbursal_batch = self.batches.get_mut(BatchType::Disbursal as u64)?.unwrap();
            for tx in final_txs {
                disbursal_batch.push_back(tx)?;
            }
        }

        self.deduct_emergency_disbursal_fees(fee_rate)?;

        let mut disbursal_batch = self.batches.get_mut(BatchType::Disbursal as u64)?.unwrap();
        for i in 0..disbursal_batch.len() {
            let mut tx = disbursal_batch.get_mut(i)?.unwrap();
            for j in 0..tx.input.len() {
                tx.populate_input_sig_message(j.try_into()?)?;
            }
        }

        let mut intermediate_tx_batch = self
            .batches
            .get_mut(BatchType::IntermediateTx as u64)?
            .unwrap();
        let mut intermediate_tx = intermediate_tx_batch.get_mut(0)?.unwrap();
        intermediate_tx.populate_input_sig_message(0)?;

        Ok(())
    }

    #[allow(unused_variables)]
    pub fn advance(
        mut self,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::coins::Address, Adapter<bitcoin::Script>>,
        external_outputs: impl Iterator<Item = Result<bitcoin::TxOut>>,
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

        let est_vsize = checkpoint_tx.vsize()?
            + checkpoint_tx
                .input
                .iter()?
                .fold(Ok(0), |sum: Result<u64>, input| {
                    Ok(sum? + input?.est_witness_vsize)
                })?;

        let fee = est_vsize * config.fee_rate;
        let reserve_value = in_amount
            .checked_sub(out_amount + fee)
            .ok_or_else(|| OrgaError::App("Insufficient funds to cover fees".to_string()))?;
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

        #[cfg(feature = "emergency-disbursal")]
        self.generate_emergency_disbursal_txs(
            nbtc_accounts,
            recovery_scripts,
            reserve_outpoint,
            external_outputs,
            config.fee_rate,
            reserve_value,
        )?;

        Ok((
            reserve_outpoint,
            reserve_value,
            excess_inputs,
            excess_outputs,
        ))
    }
}

#[orga]
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

    pub fn rewind(&mut self, to_index: u32) -> Result<()> {
        if to_index > self.index || self.index - to_index > self.queue.len() as u32 {
            return Err(OrgaError::App("Invalid index".to_string()).into());
        }

        let mut inputs = vec![];
        let mut outputs = vec![];
        let mut checkpoint = loop {
            let mut removed = self.queue.pop_back()?.unwrap().into_inner();

            let mut checkpoint_batch = removed
                .batches
                .get_mut(BatchType::Checkpoint as u64)?
                .unwrap();
            let mut checkpoint_tx = checkpoint_batch.back_mut()?.unwrap();

            while let Some(input) = checkpoint_tx.input.pop_back()? {
                if checkpoint_tx.input.len() == 0 && self.index != to_index {
                    // skip reserve input (except on target index)
                    continue;
                }
                let mut input = input.into_inner();
                input.signatures = ThresholdSig::new();
                inputs.push(input);
            }

            while let Some(output) = checkpoint_tx.output.pop_back()? {
                if checkpoint_tx.output.len() == 0 {
                    // skip reserve output
                    continue;
                }
                if output.value < output.script_pubkey.dust_value().to_sat() {
                    // skip dust outputs
                    continue;
                }
                outputs.push(output.into_inner());
            }

            if self.index == to_index {
                break removed;
            }
            self.index -= 1;
        };

        checkpoint.status = CheckpointStatus::Building;

        let mut checkpoint_batch = checkpoint
            .batches
            .get_mut(BatchType::Checkpoint as u64)?
            .unwrap();
        let mut checkpoint_tx = checkpoint_batch.back_mut()?.unwrap();
        checkpoint_tx.input.push_back(inputs.pop().unwrap())?;
        for input in inputs {
            checkpoint_tx.input.push_back(input)?;
        }
        for output in outputs {
            checkpoint_tx.output.push_back(output)?;
        }

        self.queue.push_back(checkpoint)?;

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
        #[cfg(not(feature = "emergency-disbursal"))]
        unimplemented!();

        #[cfg(feature = "emergency-disbursal")]
        {
            let mut vec = vec![];

            if let Some(completed) = self.completed()?.last() {
                let intermediate_tx_batch = completed
                    .batches
                    .get(BatchType::IntermediateTx as u64)?
                    .unwrap();
                let intermediate_tx = intermediate_tx_batch.get(0)?.unwrap();
                vec.push(Adapter::new(intermediate_tx.to_bitcoin_tx()?));

                let disbursal_batch = completed.batches.get(BatchType::Disbursal as u64)?.unwrap();
                for tx in disbursal_batch.iter()? {
                    vec.push(Adapter::new(tx?.to_bitcoin_tx()?));
                }
            }

            Ok(vec)
        }
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
        recovery_scripts: &Map<orga::coins::Address, Adapter<bitcoin::Script>>,
        external_outputs: impl Iterator<Item = Result<bitcoin::TxOut>>,
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
        }

        if self.maybe_push(sig_keys)?.is_none() {
            return Ok(());
        }

        #[cfg(feature = "testnet")]
        self.prune()?;

        if self.index > 0 {
            let config = self.config();
            let second = self.get_mut(self.index - 1)?;
            let sigset = second.sigset.clone();
            let (reserve_outpoint, reserve_value, excess_inputs, excess_outputs) =
                BuildingCheckpointMut(second).advance(
                    nbtc_accounts,
                    recovery_scripts,
                    external_outputs,
                    &config,
                )?;

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

        if signing.signed()? {
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
mod test {
    use super::*;

    fn push_bitcoin_tx_output(tx: &mut BitcoinTx, value: u64) {
        let tx_out = bitcoin::TxOut {
            value,
            script_pubkey: bitcoin::Script::new(),
        };
        tx.output.push_back(Output::new(tx_out)).unwrap();
    }

    #[test]
    fn deduct_fee() {
        let mut bitcoin_tx = BitcoinTx::default();
        push_bitcoin_tx_output(&mut bitcoin_tx, 0);
        push_bitcoin_tx_output(&mut bitcoin_tx, 10000);

        bitcoin_tx.deduct_fee(100).unwrap();

        assert_eq!(bitcoin_tx.output.len(), 1);
        assert_eq!(bitcoin_tx.output.get(0).unwrap().unwrap().value, 9900);
    }

    #[test]
    fn deduct_fee_multi_pass() {
        let mut bitcoin_tx = BitcoinTx::default();
        push_bitcoin_tx_output(&mut bitcoin_tx, 60);
        push_bitcoin_tx_output(&mut bitcoin_tx, 70);
        push_bitcoin_tx_output(&mut bitcoin_tx, 300);

        bitcoin_tx.deduct_fee(200).unwrap();

        assert_eq!(bitcoin_tx.output.len(), 1);
        assert_eq!(bitcoin_tx.output.get(0).unwrap().unwrap().value, 100);
    }

    #[test]
    fn deduct_fee_multi_pass_empty_result() {
        let mut bitcoin_tx = BitcoinTx::default();
        push_bitcoin_tx_output(&mut bitcoin_tx, 60);
        push_bitcoin_tx_output(&mut bitcoin_tx, 70);
        push_bitcoin_tx_output(&mut bitcoin_tx, 100);

        bitcoin_tx.deduct_fee(200).unwrap();
    }

    //TODO: More fee deduction tests
}
