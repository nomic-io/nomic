#[cfg(feature = "full")]
use super::ConsensusKey;
use super::{
    adapter::Adapter,
    signatory::SignatorySet,
    threshold_sig::{Signature, ThresholdSig},
    Xpub,
};
use crate::bitcoin::Nbtc;
use crate::error::{Error, Result};
use bitcoin::hashes::Hash;
use bitcoin::{
    blockdata::transaction::EcdsaSighashType, hashes::hex::ToHex, PackedLockTime, Sequence,
};
// use bitcoin_hashes::Hash;
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

//TODO: Find actual amount for this
pub const EMERGENCY_DISBURSAL_MIN_TX_AMT: u64 = 0;
pub const EMERGENCY_DISBURSAL_LOCK_TIME_INTERVAL: u32 = 60 * 24 * 7; //one week
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

#[orga(skip(Default))]
#[derive(Debug)]
pub struct Checkpoint {
    pub status: CheckpointStatus,
    pub inputs: Deque<Input>,
    pub emergency_disbursal_txs: Deque<Adapter<bitcoin::Transaction>>,
    signed_inputs: u16,
    pub outputs: Deque<Output>,
    pub sig_queue: SignatureQueue,
    pub sigset: SignatorySet,
}

impl Checkpoint {
    pub fn get_to_sign_msgs(
        &self,
        sigs: &Deque<ThresholdSig>,
        xpub: &Xpub,
        msgs: &mut Vec<([u8; 32], u32)>,
    ) -> Result<()> {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        for i in 0..self.inputs.len() {
            let input = self.inputs.get(i)?.unwrap();
            let pubkey = xpub
                .derive_pub(
                    &secp,
                    &[bitcoin::util::bip32::ChildNumber::from_normal_idx(
                        input.sigset_index,
                    )?],
                )?
                .public_key;
            let sigs = sigs.get(i)?.unwrap();
            if sigs.needs_sig(pubkey.into())? {
                msgs.push((sigs.message(), input.sigset_index));
            }
        }

        Ok(())
    }

    #[query]
    pub fn to_sign(&self, xpub: Xpub) -> Result<Vec<([u8; 32], u32)>> {
        let mut msgs = vec![];

        // TODO: get signatures for active group in signature queue
        self.get_to_sign_msgs(&self.sig_queue.emergency_disbursal, &xpub, &mut msgs)?;
        self.get_to_sign_msgs(&self.sig_queue.inputs, &xpub, &mut msgs)?;

        Ok(msgs)
    }

    pub fn create_time(&self) -> u64 {
        self.sigset.create_time()
    }

    pub fn tx(&self) -> Result<(bitcoin::Transaction, u64)> {
        let mut tx = bitcoin::Transaction {
            version: 1,
            lock_time: PackedLockTime(0),
            input: vec![],
            output: vec![],
        };

        let mut est_vsize = 0;

        // TODO: use deque iterator
        for i in 0..self.inputs.len() {
            let input = self.inputs.get(i)?.unwrap();
            let sigs = &*self.sig_queue.inputs.get(i)?.unwrap();
            tx.input.push(input.to_txin(sigs)?);
            est_vsize += input.est_witness_vsize;
        }

        // TODO: use deque iterator
        for i in 0..self.outputs.len() {
            let output = self.outputs.get(i)?.unwrap();
            tx.output.push((**output).clone());
        }

        est_vsize += tx.size() as u64;

        Ok((tx, est_vsize))
    }

    #[query]
    pub fn get_tvl(&self) -> Result<u64> {
        let mut tvl = 0;
        for i in 0..self.inputs.len() {
            if let Some(input) = self.inputs.get(i)? {
                tvl += input.amount;
            }
        }

        Ok(tvl)
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
            fee_rate: 1,
            max_age: 60 * 60 * 24 * 7 * 3,
        }
    }

    fn bitcoin() -> Self {
        Self {
            min_checkpoint_interval: 60 * 5,
            max_checkpoint_interval: 60 * 60 * 8,
            max_inputs: 40,
            max_outputs: 200,
            fee_rate: 1,
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

#[derive(Deref, DerefMut)]
pub struct SigningCheckpointMut<'a>(ChildMut<'a, u64, Checkpoint>);

impl<'a> SigningCheckpointMut<'a> {
    pub fn sign(&mut self, xpub: Xpub, sigs: LengthVec<u16, Signature>) -> Result<()> {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        let mut sig_index = 0;
        for i in 0..self.inputs.len() {
            let input = self.inputs.get_mut(i)?.unwrap();

            let pubkey = xpub
                .derive_pub(
                    &secp,
                    &[bitcoin::util::bip32::ChildNumber::from_normal_idx(
                        input.sigset_index,
                    )?],
                )?
                .public_key
                .into();

            let mut input_sigs = self.sig_queue.inputs.get_mut(i)?.unwrap();
            if !input_sigs.contains_key(pubkey)? {
                continue;
            }

            if input_sigs.done() {
                sig_index += 1;
                continue;
            }

            if sig_index > sigs.len() {
                return Err(OrgaError::App("Not enough signatures supplied".to_string()).into());
            }

            let sig = sigs[sig_index];
            sig_index += 1;

            input_sigs.sign(pubkey, sig)?;

            if input_sigs.done() {
                self.signed_inputs += 1;
            }
        }

        if sig_index != sigs.len() {
            return Err(OrgaError::App("Excess signatures supplied".to_string()).into());
        }

        Ok(())
    }

    pub fn done(&self) -> bool {
        self.signed_inputs as u64 == self.inputs.len()
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
    Vec<(ReadOnly<Input>, ReadOnly<ThresholdSig>)>,
    Vec<ReadOnly<Output>>,
);

impl<'a> BuildingCheckpointMut<'a> {
    pub fn push_input(
        &mut self,
        prevout: bitcoin::OutPoint,
        sigset: &SignatorySet,
        dest: &[u8],
        amount: u64,
    ) -> Result<u64> {
        let script_pubkey = sigset.output_script(dest)?;
        let redeem_script = sigset.redeem_script(dest)?;

        let input = Input {
            prevout: Adapter::new(prevout),
            script_pubkey: Adapter::new(script_pubkey),
            redeem_script: Adapter::new(redeem_script),
            sigset_index: sigset.index(),
            dest: dest.encode()?.try_into()?,
            amount,
            est_witness_vsize: sigset.est_witness_vsize(),
        };
        let est_vsize = input.est_vsize();
        self.inputs.push_back(input)?;

        // TODO: make it possible to populate instance in memory then push,
        // rather than push then access and modify
        self.sig_queue.inputs.push_back(ThresholdSig::new())?;
        let inputs_len = self.inputs.len();
        let mut sigs = self.sig_queue.inputs.get_mut(inputs_len - 1)?.unwrap();
        sigs.from_sigset(sigset)?;

        Ok(est_vsize)
    }

    fn provide_empty_tx(lock_time: u32) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: 1,
            lock_time: PackedLockTime(lock_time),
            input: Vec::new(),
            output: Vec::new(),
        }
    }

    fn get_raw_emergency_disbursal_txs(
        &self,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::prelude::Address, Adapter<bitcoin::Script>>,
        lock_time: u32,
    ) -> Result<Vec<bitcoin::Transaction>> {
        let mut txs: Vec<bitcoin::Transaction> = Vec::new();

        for account in nbtc_accounts.iter()? {
            let mut curr_tx = txs
                .pop()
                .unwrap_or_else(|| Self::provide_empty_tx(lock_time));
            if curr_tx.size() as u64 > EMERGENCY_DISBURSAL_MAX_TX_SIZE {
                txs.push(curr_tx);
                curr_tx = Self::provide_empty_tx(lock_time)
            }

            let (address, coins) = account?;

            if coins.amount < EMERGENCY_DISBURSAL_MIN_TX_AMT {
                continue;
            }

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

            curr_tx.output.push(tx_out);
            txs.push(curr_tx);
        }

        Ok(txs)
    }

    fn generate_intermediate_tx(
        &self,
        txs: &[bitcoin::Transaction],
        lock_time: u32,
        reserve_outpoint: bitcoin::OutPoint,
    ) -> Result<bitcoin::Transaction> {
        let mut intermediate_tx = Self::provide_empty_tx(lock_time);

        let tx_in = bitcoin::TxIn {
            previous_output: reserve_outpoint,
            script_sig: vec![].into(),
            sequence: Sequence(u32::MAX),
            witness: bitcoin::Witness::new(),
        };
        intermediate_tx.input.push(tx_in);

        for tx in txs.iter() {
            let intermediate_tx_out = bitcoin::TxOut {
                value: tx.output.iter().fold(0, |sum, out| sum + out.value),
                script_pubkey: self.0.sigset.output_script(&[])?,
            };

            intermediate_tx.output.push(intermediate_tx_out);
        }

        Ok(intermediate_tx)
    }

    fn link_intermediate_tx(
        &self,
        intermediate_tx: &bitcoin::Transaction,
        txs: &mut [bitcoin::Transaction],
    ) -> Result<()> {
        for (i, tx) in txs.iter_mut().enumerate() {
            let intermediate_tx_in = bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(intermediate_tx.txid(), i as u32),
                script_sig: vec![].into(),
                sequence: Sequence(u32::MAX),
                witness: bitcoin::Witness::new(),
            };

            tx.input.push(intermediate_tx_in);
        }

        Ok(())
    }

    fn generate_emergency_disbursal_sigs(
        &self,
        txs: &[bitcoin::Transaction],
        intermediate_tx: &bitcoin::Transaction,
    ) -> Result<Vec<ThresholdSig>> {
        let mut sigs = Vec::new();
        for (i, tx) in txs.iter().enumerate() {
            let mut sig = ThresholdSig::new();
            let owned_tx = tx.to_owned();
            let mut sc = bitcoin::util::sighash::SighashCache::new(&owned_tx);
            let spending_output = intermediate_tx.output.get(i).unwrap();
            let sighash = sc.segwit_signature_hash(
                0,
                &self.0.sigset.redeem_script(&[])?,
                spending_output.value,
                EcdsaSighashType::All,
            )?;
            sig.set_message(sighash.into_inner());
            sigs.push(sig);
        }
        Ok(sigs)
    }

    fn generate_emergency_disbursal_txs(
        &mut self,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::prelude::Address, Adapter<bitcoin::Script>>,
        reserve_outpoint: bitcoin::OutPoint,
    ) -> Result<bitcoin::Transaction> {
        let time = Context::resolve::<Time>()
            .ok_or_else(|| OrgaError::Coins("No Time context found".into()))?;
        //TODO: Use std::time::Duration to safely convert time
        let lock_time = time.seconds as u32 + EMERGENCY_DISBURSAL_LOCK_TIME_INTERVAL;

        let mut txs =
            self.get_raw_emergency_disbursal_txs(nbtc_accounts, recovery_scripts, lock_time)?;

        let intermediate_tx = self.generate_intermediate_tx(&txs, lock_time, reserve_outpoint)?;
        self.link_intermediate_tx(&intermediate_tx, &mut txs)?;

        self.emergency_disbursal_txs
            .push_back(Adapter::new(intermediate_tx.clone()))?;
        for tx in txs.iter() {
            self.emergency_disbursal_txs
                .push_back(Adapter::new(tx.to_owned()))?;
        }

        let sigs = self.generate_emergency_disbursal_sigs(&txs, &intermediate_tx)?;
        for sig in sigs {
            self.sig_queue.emergency_disbursal.push_back(sig)?;
        }

        Ok(intermediate_tx)
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
        self.0.outputs.push_front(Adapter::new(reserve_out))?;

        let mut excess_inputs = vec![];
        while self.0.inputs.len() > config.max_inputs {
            let removed_input = self.0.inputs.pop_back()?.unwrap();
            let removed_sigs = self.0.sig_queue.inputs.pop_back()?.unwrap();
            excess_inputs.push((removed_input, removed_sigs));
        }

        let mut excess_outputs = vec![];
        while self.0.outputs.len() > config.max_outputs {
            let removed_output = self.0.outputs.pop_back()?.unwrap();
            excess_outputs.push(removed_output);
        }

        let mut in_amount = 0;
        for i in 0..self.0.inputs.len() {
            let input = self.0.inputs.get(i)?.unwrap();
            in_amount += input.amount;
        }

        let mut out_amount = 0;
        for i in 0..self.0.outputs.len() {
            let output = self.0.outputs.get(i)?.unwrap();
            out_amount += output.value;
        }

        let (mut tx, est_vsize) = self.0.tx()?;
        let fee = est_vsize * config.fee_rate;
        let reserve_value = in_amount - out_amount - fee;
        let mut reserve_out = self.0.outputs.get_mut(0)?.unwrap();
        reserve_out.value = reserve_value;
        tx.output[0].value = reserve_value;

        let mut sc = bitcoin::util::sighash::SighashCache::new(&tx);
        for i in 0..self.0.inputs.len() {
            let input = self.0.inputs.get_mut(i)?.unwrap();
            let sighash_type = EcdsaSighashType::All;
            let sighash = sc.segwit_signature_hash(
                i as usize,
                &input.redeem_script,
                input.amount,
                sighash_type,
            )?;
            let mut sigs = self.0.sig_queue.inputs.get_mut(i)?.unwrap();
            sigs.set_message(sighash.into_inner());
        }

        let reserve_outpoint = bitcoin::OutPoint {
            txid: tx.txid(),
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

        Ok(Adapter::new(self.get(index)?.tx()?.0))
    }

    #[query]
    pub fn completed_txs(&self) -> Result<Vec<Adapter<bitcoin::Transaction>>> {
        self.completed()?
            .into_iter()
            .map(|c| Ok(Adapter::new(c.tx()?.0)))
            .collect()
    }

    #[query]
    pub fn emergency_disbursal_txs(&self) -> Result<Vec<Adapter<bitcoin::Transaction>>> {
        let mut vec = vec![];
        if let Some(completed) = self.completed()?.last() {
            for tx in completed.emergency_disbursal_txs.iter()? {
                vec.push(tx?.clone());
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
                let has_pending_deposit = if self.index == 0 {
                    !building.inputs.is_empty()
                } else {
                    building.inputs.len() > 1
                };

                let has_pending_withdrawal = !building.outputs.is_empty();

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

            building.push_input(
                reserve_outpoint,
                &sigset,
                &[0u8], // TODO: double-check safety
                reserve_value,
            )?;

            for (input, sigs) in excess_inputs {
                let shares = sigs.shares()?;
                let data = input.into_inner();
                building.inputs.push_back(data)?;
                building.sig_queue.inputs.push_back(ThresholdSig::new())?;
                building
                    .sig_queue
                    .inputs
                    .back_mut()?
                    .unwrap()
                    .from_shares(shares)?;
            }

            for output in excess_outputs {
                let data = output.into_inner();
                building.outputs.push_back(data)?;
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

        self.queue.push_back(Checkpoint {
            sigset,
            ..Default::default()
        })?;

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
            info!("Checkpoint signing complete {:?}", signing.tx()?);
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
