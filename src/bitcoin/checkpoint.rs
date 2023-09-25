#[cfg(feature = "full")]
use super::ConsensusKey;
use super::{
    adapter::Adapter,
    signatory::SignatorySet,
    threshold_sig::{Signature, ThresholdSig},
    Xpub,
};
use crate::error::{Error, Result};
use crate::{
    app::Dest,
    bitcoin::{signatory::derive_pubkey, Nbtc},
};
use bitcoin::hashes::Hash;
use bitcoin::{blockdata::transaction::EcdsaSighashType, Sequence, Transaction, TxIn, TxOut};
use derive_more::{Deref, DerefMut};
use log::info;
use orga::coins::{Accounts, Coin};
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

#[derive(
    Debug,
    Encode,
    Decode,
    Default,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
)]
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
    pub dest: LengthVec<u16, u8>,
    pub amount: u64,
    pub est_witness_vsize: u64,
    pub signatures: ThresholdSig,
}

impl Input {
    pub fn to_txin(&self) -> Result<TxIn> {
        let mut witness = self.signatures.to_witness()?;
        if self.signatures.signed() {
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
    fn migrate_from(_value: InputV0) -> OrgaResult<Self> {
        unreachable!()
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
                let dust_value = output.script_pubkey.dust_value().to_sat();
                let adjusted_output = output.value.saturating_sub(dust_value);
                if adjusted_output < min_output {
                    min_output = adjusted_output;
                }
                Ok(adjusted_output > threshold)
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

pub const DEFAULT_FEE_RATE: u64 = 10;

#[orga(skip(Default), version = 3)]
#[derive(Debug)]
pub struct Checkpoint {
    pub status: CheckpointStatus,
    pub batches: Deque<Batch>,
    #[orga(version(V2, V3))]
    pub pending: Map<Dest, Coin<Nbtc>>,
    #[orga(version(V3))]
    pub fee_rate: u64,
    #[orga(version(V3))]
    pub signed_at_btc_height: Option<u32>,
    pub sigset: SignatorySet,
}

impl MigrateFrom<CheckpointV0> for CheckpointV1 {
    fn migrate_from(_value: CheckpointV0) -> OrgaResult<Self> {
        unreachable!()
    }
}

impl MigrateFrom<CheckpointV1> for CheckpointV2 {
    fn migrate_from(value: CheckpointV1) -> OrgaResult<Self> {
        Ok(Self {
            status: value.status,
            batches: value.batches,
            pending: Map::new(),
            sigset: value.sigset,
        })
    }
}

impl MigrateFrom<CheckpointV2> for CheckpointV3 {
    fn migrate_from(value: CheckpointV2) -> OrgaResult<Self> {
        Ok(Self {
            status: value.status,
            batches: value.batches,
            pending: value.pending,
            fee_rate: DEFAULT_FEE_RATE,
            signed_at_btc_height: None,
            sigset: value.sigset,
        })
    }
}

#[orga]
impl Checkpoint {
    pub fn new(sigset: SignatorySet) -> Result<Self> {
        let mut checkpoint = Checkpoint {
            status: CheckpointStatus::default(),
            batches: Deque::default(),
            pending: Map::new(),
            fee_rate: DEFAULT_FEE_RATE,
            signed_at_btc_height: None,
            sigset,
        };

        let disbursal_batch = Batch::default();
        checkpoint.batches.push_front(disbursal_batch)?;

        #[allow(unused_mut)]
        let mut intermediate_tx_batch = Batch::default();
        intermediate_tx_batch.push_back(BitcoinTx::default())?;
        checkpoint.batches.push_back(intermediate_tx_batch)?;

        let checkpoint_tx = BitcoinTx::default();
        let mut checkpoint_batch = Batch::default();
        checkpoint_batch.push_back(checkpoint_tx)?;
        checkpoint.batches.push_back(checkpoint_batch)?;

        Ok(checkpoint)
    }

    fn sign(&mut self, xpub: Xpub, sigs: LengthVec<u16, Signature>, btc_height: u32) -> Result<()> {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        let cp_was_signed = self.signed()?;
        let mut sig_index = 0;
        for i in 0..self.batches.len() {
            let mut batch = self.batches.get_mut(i)?.unwrap();
            let batch_was_signed = batch.signed();

            for j in 0..batch.len() {
                let mut tx = batch.get_mut(j)?.unwrap();
                let tx_was_signed = tx.signed();

                for k in 0..tx.input.len() {
                    let mut input = tx.input.get_mut(k)?.unwrap();
                    let pubkey = derive_pubkey(&secp, xpub, input.sigset_index)?;

                    if !input.signatures.needs_sig(pubkey.into())? {
                        continue;
                    }

                    if sig_index >= sigs.len() {
                        return Err(
                            OrgaError::App("Not enough signatures supplied".to_string()).into()
                        );
                    }

                    let sig = sigs[sig_index];
                    sig_index += 1;

                    let input_was_signed = input.signatures.signed();
                    input.signatures.sign(pubkey.into(), sig)?;

                    if !input_was_signed && input.signatures.signed() {
                        tx.signed_inputs += 1;
                    }
                }

                if !tx_was_signed && tx.signed() {
                    batch.signed_txs += 1;
                }
            }

            if !batch_was_signed {
                break;
            }
        }

        if sig_index != sigs.len() {
            return Err(OrgaError::App("Excess signatures supplied".to_string()).into());
        }

        if self.signed()? && !cp_was_signed {
            self.signed_at_btc_height = Some(btc_height);
        }

        Ok(())
    }

    #[query]
    pub fn checkpoint_tx(&self) -> Result<Adapter<bitcoin::Transaction>> {
        Ok(Adapter::new(
            self.batches
                .get(BatchType::Checkpoint as u64)?
                .unwrap()
                .back()?
                .unwrap()
                .to_bitcoin_tx()?,
        ))
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

        for batch in self.batches.iter()? {
            let batch = batch?;
            for tx in batch.iter()? {
                for input in tx?.input.iter()? {
                    let input = input?;

                    let pubkey = derive_pubkey(&secp, xpub, input.sigset_index)?;
                    if input.signatures.needs_sig(pubkey.into())? {
                        msgs.push((input.signatures.message(), input.sigset_index));
                    }
                }
            }
            if !batch.signed() {
                break;
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

#[orga(skip(Default), version = 1)]
#[derive(Clone)]
pub struct Config {
    pub min_checkpoint_interval: u64,
    pub max_checkpoint_interval: u64,
    pub max_inputs: u64,
    pub max_outputs: u64,
    #[orga(version(V0))]
    pub fee_rate: u64,
    pub max_age: u64,
    #[orga(version(V1))]
    pub target_checkpoint_inclusion: u64,
    #[orga(version(V1))]
    pub min_fee_rate: u64,
    #[orga(version(V1))]
    pub max_fee_rate: u64,
}

impl MigrateFrom<ConfigV0> for ConfigV1 {
    fn migrate_from(value: ConfigV0) -> OrgaResult<Self> {
        Ok(Self {
            min_checkpoint_interval: value.min_checkpoint_interval,
            max_checkpoint_interval: value.max_checkpoint_interval,
            max_inputs: value.max_inputs,
            max_outputs: value.max_outputs,
            max_age: value.max_age,
            ..Self::default()
        })
    }
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
            max_age: 60 * 60 * 24 * 7 * 3,
            target_checkpoint_inclusion: 2,
            min_fee_rate: 2, // relay threshold is 1 sat/vbyte
            max_fee_rate: 200,
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

#[orga(version = 2)]
pub struct CheckpointQueue {
    pub queue: Deque<Checkpoint>,
    pub index: u32,
    #[orga(version(V2))]
    pub confirmed_index: Option<u32>,
    pub config: Config,
}

impl MigrateFrom<CheckpointQueueV0> for CheckpointQueueV1 {
    fn migrate_from(_value: CheckpointQueueV0) -> OrgaResult<Self> {
        unreachable!()
    }
}

impl MigrateFrom<CheckpointQueueV1> for CheckpointQueueV2 {
    fn migrate_from(value: CheckpointQueueV1) -> OrgaResult<Self> {
        Ok(Self {
            queue: value.queue,
            index: value.index,
            confirmed_index: None,
            config: value.config,
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
    pub fn sign(
        &mut self,
        xpub: Xpub,
        sigs: LengthVec<u16, Signature>,
        btc_height: u32,
    ) -> Result<()> {
        self.0.sign(xpub, sigs, btc_height)
    }

    pub fn advance(self) -> Result<()> {
        let mut checkpoint = self.0;

        checkpoint.status = CheckpointStatus::Complete;

        Ok(())
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

        if intermediate_tx_len == 0 {
            log::warn!("Generated empty emergency disbursal");
            return Ok(());
        }

        let mut intermediate_tx_outputs: Vec<(usize, u64)> = intermediate_tx
            .output
            .iter()?
            .enumerate()
            .map(|(i, output)| Ok((i, output?.value)))
            .collect::<Result<_>>()?;

        let mut disbursal_batch = self.batches.get_mut(BatchType::Disbursal as u64)?.unwrap();
        disbursal_batch.retain_unordered(|mut tx| {
            let mut input = match tx.input.get_mut(0)? {
                Some(input) => input,
                None => return Ok(false),
            };
            if input.amount < intermediate_tx_fee / intermediate_tx_len {
                return Ok(false);
            }
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
    fn generate_emergency_disbursal_txs(
        &mut self,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::coins::Address, Adapter<bitcoin::Script>>,
        reserve_outpoint: bitcoin::OutPoint,
        external_outputs: impl Iterator<Item = Result<bitcoin::TxOut>>,
        fee_rate: u64,
        reserve_value: u64,
    ) -> Result<()> {
        #[cfg(not(feature = "full"))]
        unimplemented!();

        #[cfg(feature = "full")]
        {
            let intermediate_tx_batch = self
                .batches
                .get_mut(BatchType::IntermediateTx as u64)?
                .unwrap();
            if intermediate_tx_batch.is_empty() {
                return Ok(());
            }

            //TODO: Pull bitcoin config from state
            let bitcoin_config = super::Bitcoin::config();
            use orga::context::Context;
            let time = Context::resolve::<Time>()
                .ok_or_else(|| OrgaError::Coins("No Time context found".into()))?;

            let sigset = self.sigset.clone();

            let lock_time =
                time.seconds as u32 + bitcoin_config.emergency_disbursal_lock_time_interval;

            let mut outputs = Vec::new();
            for entry in nbtc_accounts.iter()? {
                let (address, coins) = entry?;
                if let Some(dest_script) = recovery_scripts.get(*address)? {
                    let tx_out = bitcoin::TxOut {
                        value: u64::from(coins.amount) / 1_000_000,
                        script_pubkey: dest_script.clone().into_inner(),
                    };

                    outputs.push(Ok(tx_out));
                }
            }

            // // TODO: combine pending transfer outputs into other outputs by adding to amount
            let pending_outputs: Vec<_> = self
                .pending
                .iter()?
                .filter_map(|entry| {
                    let (dest, coins) = match entry {
                        Err(err) => return Some(Err(err.into())),
                        Ok(entry) => entry,
                    };
                    let script_pubkey = match dest.to_output_script(recovery_scripts) {
                        Err(err) => return Some(Err(err.into())),
                        Ok(maybe_script) => maybe_script,
                    }?;
                    Some(Ok::<_, Error>(TxOut {
                        value: u64::from(coins.amount) / 1_000_000,
                        script_pubkey,
                    }))
                })
                .collect();

            let mut final_txs = vec![BitcoinTx::with_lock_time(lock_time)];
            for output in outputs
                .into_iter()
                .chain(pending_outputs.into_iter())
                .chain(external_outputs)
            {
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

                final_txs.push(curr_tx);
            }

            let mut last_tx = final_txs.pop().unwrap();
            self.link_intermediate_tx(&mut last_tx)?;
            final_txs.push(last_tx);

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

        let fee_rate = self.fee_rate;

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

        let fee = est_vsize * fee_rate;
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

        self.generate_emergency_disbursal_txs(
            nbtc_accounts,
            recovery_scripts,
            reserve_outpoint,
            external_outputs,
            self.fee_rate,
            reserve_value,
        )?;

        Ok((
            reserve_outpoint,
            reserve_value,
            excess_inputs,
            excess_outputs,
        ))
    }

    pub fn insert_pending(&mut self, dest: Dest, coins: Coin<Nbtc>) -> Result<()> {
        let mut amount = self
            .pending
            .remove(dest.clone())?
            .map_or(0.into(), |c| c.amount);
        amount = (amount + coins.amount).result()?;
        self.pending.insert(dest, Coin::mint(amount))?;
        Ok(())
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
    pub fn completed(&self, limit: u32) -> Result<Vec<CompletedCheckpoint<'_>>> {
        // TODO: return iterator
        // TODO: use Deque iterator

        let mut out = vec![];

        let length = self.len()?;
        if length == 0 {
            return Ok(out);
        }

        let skip = if self.signing()?.is_some() { 2 } else { 1 };
        let end = self.index.saturating_sub(skip - 1);

        let start = end - limit.min(length - skip);

        for i in start..end {
            let checkpoint = self.get(i)?;
            out.push(CompletedCheckpoint(checkpoint));
        }

        Ok(out)
    }

    #[query]
    pub fn last_completed_index(&self) -> Result<u32> {
        if self.signing()?.is_some() {
            self.index.checked_sub(2)
        } else {
            self.index.checked_sub(1)
        }
        .ok_or_else(|| Error::Orga(OrgaError::App("No completed checkpoints yet".to_string())))
    }

    #[query]
    pub fn last_completed(&self) -> Result<Ref<Checkpoint>> {
        self.get(self.last_completed_index()?)
    }

    pub fn last_completed_mut(&mut self) -> Result<ChildMut<u64, Checkpoint>> {
        self.get_mut(self.last_completed_index()?)
    }

    #[query]
    pub fn last_completed_tx(&self) -> Result<Adapter<bitcoin::Transaction>> {
        self.last_completed()?.checkpoint_tx()
    }

    #[query]
    pub fn completed_txs(&self, limit: u32) -> Result<Vec<Adapter<bitcoin::Transaction>>> {
        self.completed(limit)?
            .into_iter()
            .map(|c| c.checkpoint_tx())
            .collect()
    }

    #[query]
    pub fn emergency_disbursal_txs(&self) -> Result<Vec<Adapter<bitcoin::Transaction>>> {
        let mut txs = vec![];

        if let Some(completed) = self.completed(1)?.last() {
            let intermediate_tx_batch = completed
                .batches
                .get(BatchType::IntermediateTx as u64)?
                .unwrap();
            let intermediate_tx = intermediate_tx_batch.get(0)?.unwrap();
            txs.push(Adapter::new(intermediate_tx.to_bitcoin_tx()?));

            let disbursal_batch = completed.batches.get(BatchType::Disbursal as u64)?.unwrap();
            for tx in disbursal_batch.iter()? {
                txs.push(Adapter::new(tx?.to_bitcoin_tx()?));
            }
        }

        Ok(txs)
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
            // TODO: move to min_checkpoints field in config
            if self.queue.len() <= 10 {
                break;
            }

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
    ) -> Result<bool> {
        if !self.should_push(sig_keys)? {
            return Ok(false);
        }

        if self.maybe_push(sig_keys)?.is_none() {
            return Ok(false);
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

        Ok(true)
    }

    #[cfg(feature = "full")]
    pub fn should_push(&mut self, sig_keys: &Map<ConsensusKey, Xpub>) -> Result<bool> {
        if self.signing()?.is_some() {
            return Ok(false);
        }

        if !self.queue.is_empty() {
            let now = self
                .context::<Time>()
                .ok_or_else(|| OrgaError::App("No time context".to_string()))?
                .seconds as u64;
            let elapsed = now - self.building()?.create_time();
            if elapsed < self.config.min_checkpoint_interval {
                return Ok(false);
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
                let has_pending_transfers = building.pending.iter()?.next().transpose()?.is_some();

                if !has_pending_deposit && !has_pending_withdrawal && !has_pending_transfers {
                    return Ok(false);
                }
            }
        }

        let mut index = self.index;
        if !self.queue.is_empty() {
            index += 1;
        }

        let sigset = SignatorySet::from_validator_ctx(index, sig_keys)?;

        if sigset.possible_vp() == 0 {
            return Ok(false);
        }

        if !sigset.has_quorum() {
            return Ok(false);
        }

        Ok(true)
    }

    #[cfg(feature = "full")]
    pub fn maybe_push(
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

    pub fn sign(
        &mut self,
        xpub: Xpub,
        sigs: LengthVec<u16, Signature>,
        index: u32,
        btc_height: u32,
    ) -> Result<()> {
        super::exempt_from_fee()?;

        let mut checkpoint = self.get_mut(index)?;
        let status = checkpoint.status;
        if matches!(status, CheckpointStatus::Building) {
            return Err(OrgaError::App("Checkpoint is still building".to_string()).into());
        }

        checkpoint.sign(xpub, sigs, btc_height)?;

        if matches!(status, CheckpointStatus::Signing) && checkpoint.signed()? {
            let checkpoint_tx = checkpoint.checkpoint_tx()?;
            info!("Checkpoint signing complete {:?}", checkpoint_tx);
            SigningCheckpointMut(checkpoint).advance()?;
        }

        Ok(())
    }

    #[query]
    pub fn sigset(&self, index: u32) -> Result<SignatorySet> {
        Ok(self.get(index)?.sigset.clone())
    }

    #[query]
    pub fn num_unconfirmed(&self) -> Result<u32> {
        let has_signing = self.signing()?.is_some();
        let signing_offset = has_signing as u32;

        let last_completed_index = self.index.checked_sub(1 + signing_offset);
        let last_completed_index = match last_completed_index {
            None => return Ok(0),
            Some(index) => index,
        };

        let confirmed_index = match self.confirmed_index {
            None => return Ok(self.len()? - 1 - signing_offset),
            Some(index) => index,
        };

        Ok(last_completed_index - confirmed_index)
    }

    #[query]
    pub fn first_unconfirmed_index(&self) -> Result<Option<u32>> {
        let num_unconf = self.num_unconfirmed()?;
        if num_unconf == 0 {
            return Ok(None);
        }

        let has_signing = self.signing()?.is_some();
        let signing_offset = has_signing as u32;

        Ok(Some(self.index - num_unconf - signing_offset))
    }
}

pub fn adjust_fee_rate(prev_fee_rate: u64, up: bool, config: &Config) -> u64 {
    if up {
        (prev_fee_rate * 5 / 4)
            .max(prev_fee_rate + 1)
            .min(config.max_fee_rate)
    } else {
        (prev_fee_rate * 3 / 4)
            .min(prev_fee_rate - 1)
            .max(config.min_fee_rate)
    }
}

#[cfg(test)]
mod test {
    #[cfg(all(feature = "full"))]
    use bitcoin::{
        util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey},
        OutPoint, PubkeyHash, Script, Txid,
    };
    #[cfg(all(feature = "full"))]
    use rand::Rng;

    #[cfg(all(feature = "full"))]
    use crate::bitcoin::{signatory::Signatory, threshold_sig::Share};

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
        push_bitcoin_tx_output(&mut bitcoin_tx, 502);
        push_bitcoin_tx_output(&mut bitcoin_tx, 482);
        push_bitcoin_tx_output(&mut bitcoin_tx, 300);

        bitcoin_tx.deduct_fee(30).unwrap();

        assert_eq!(bitcoin_tx.output.len(), 1);
        assert_eq!(bitcoin_tx.output.get(0).unwrap().unwrap().value, 472);
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

    fn create_queue_with_statuses(complete: u32, signing: bool) -> CheckpointQueue {
        let mut queue = CheckpointQueue::default();
        let mut push = |status| {
            let mut cp = Checkpoint {
                status,
                batches: Deque::new(),
                pending: Map::new(),
                fee_rate: DEFAULT_FEE_RATE,
                signed_at_btc_height: None,
                sigset: SignatorySet::default(),
            };
            cp.status = status;
            queue.queue.push_back(cp).unwrap();
        };

        queue.index = complete;

        for _ in 0..complete {
            push(CheckpointStatus::Complete);
        }
        if signing {
            push(CheckpointStatus::Signing);
            queue.index += 1;
        }
        push(CheckpointStatus::Building);

        queue
    }

    #[test]
    fn completed_with_signing() {
        let queue = create_queue_with_statuses(10, true);
        let cp = queue.completed(1).unwrap();
        assert_eq!(cp.len(), 1);
        assert_eq!(cp[0].status, CheckpointStatus::Complete);
    }

    #[test]
    fn completed_without_signing() {
        let queue = create_queue_with_statuses(10, false);
        let cp = queue.completed(1).unwrap();
        assert_eq!(cp.len(), 1);
        assert_eq!(cp[0].status, CheckpointStatus::Complete);
    }

    #[test]
    fn completed_no_complete() {
        let queue = create_queue_with_statuses(0, false);
        let cp = queue.completed(10).unwrap();
        assert_eq!(cp.len(), 0);
    }

    #[test]
    fn completed_zero_limit() {
        let queue = create_queue_with_statuses(10, false);
        let cp = queue.completed(0).unwrap();
        assert_eq!(cp.len(), 0);
    }

    #[test]
    fn completed_oversized_limit() {
        let queue = create_queue_with_statuses(10, false);
        let cp = queue.completed(100).unwrap();
        assert_eq!(cp.len(), 10);
    }

    #[test]
    fn completed_pruned() {
        let mut queue = create_queue_with_statuses(10, false);
        queue.index += 10;
        let cp = queue.completed(2).unwrap();
        assert_eq!(cp.len(), 2);
        assert_eq!(cp[1].status, CheckpointStatus::Complete);
    }

    #[test]
    fn num_unconfirmed() {
        let mut queue = create_queue_with_statuses(10, false);
        queue.confirmed_index = Some(5);
        assert_eq!(queue.num_unconfirmed().unwrap(), 4);

        let mut queue = create_queue_with_statuses(10, true);
        queue.confirmed_index = Some(5);
        assert_eq!(queue.num_unconfirmed().unwrap(), 4);

        let mut queue = create_queue_with_statuses(0, false);
        queue.confirmed_index = None;
        assert_eq!(queue.num_unconfirmed().unwrap(), 0);

        let mut queue = create_queue_with_statuses(0, true);
        queue.confirmed_index = None;
        assert_eq!(queue.num_unconfirmed().unwrap(), 0);

        let mut queue = create_queue_with_statuses(10, false);
        queue.confirmed_index = None;
        assert_eq!(queue.num_unconfirmed().unwrap(), 10);

        let mut queue = create_queue_with_statuses(10, true);
        queue.confirmed_index = None;
        assert_eq!(queue.num_unconfirmed().unwrap(), 10);
    }

    #[test]
    fn first_unconfirmed_index() {
        let mut queue = create_queue_with_statuses(10, false);
        queue.confirmed_index = Some(5);
        assert_eq!(queue.first_unconfirmed_index().unwrap(), Some(6));

        let mut queue = create_queue_with_statuses(10, true);
        queue.confirmed_index = Some(5);
        assert_eq!(queue.first_unconfirmed_index().unwrap(), Some(6));

        let mut queue = create_queue_with_statuses(0, false);
        queue.confirmed_index = None;
        assert_eq!(queue.first_unconfirmed_index().unwrap(), None);

        let mut queue = create_queue_with_statuses(0, true);
        queue.confirmed_index = None;
        assert_eq!(queue.first_unconfirmed_index().unwrap(), None);

        let mut queue = create_queue_with_statuses(10, false);
        queue.confirmed_index = None;
        assert_eq!(queue.first_unconfirmed_index().unwrap(), Some(0));

        let mut queue = create_queue_with_statuses(10, true);
        queue.confirmed_index = None;
        assert_eq!(queue.first_unconfirmed_index().unwrap(), Some(0));
    }
}
