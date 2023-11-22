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

use super::SIGSET_THRESHOLD;
use orga::{describe::Describe, store::Store};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};

/// The status of a checkpoint. Checkpoints start as `Building`, and eventually
/// advance through the three states.
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
    /// The checkpoint is being constructed. It can still be mutated by adding
    /// bitcoin inputs and outputs, pending actions, etc.
    #[default]
    Building,

    /// The inputs in the checkpoint are being signed. The checkpoint's
    /// structure is frozen in this stage, and it is no longer valid to add or
    /// remove inputs or outputs.
    Signing,

    /// All inputs in the the checkpoint are fully signed and the contained
    /// checkpoint transaction is valid and ready to be broadcast on the bitcoin
    /// network.
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

/// An input to a Bitcoin transaction - possibly in an unsigned state.
///
/// This structure contains the necessary data for signing an input, and once
/// signed can be turned into a `bitcoin::TxIn` for inclusion in a Bitcoin
/// transaction.
#[orga(version = 1)]
#[derive(Debug)]
pub struct Input {
    /// The outpoint being spent by this input.
    pub prevout: Adapter<bitcoin::OutPoint>,

    /// The script of the output being spent by this input. In practice, this
    /// will be a pay-to-witness-script-hash (P2WSH) script, containing the hash
    /// of the script in the `redeem_script` field.
    pub script_pubkey: Adapter<bitcoin::Script>,

    /// The redeem script which `script_pubkey` contains the hash of, supplied
    /// in the witness of the input when spending. In practice, this will
    /// represent a multisig tied to the associated signatory set.
    pub redeem_script: Adapter<bitcoin::Script>,

    /// The index of the signatory set which this input is associated with.
    pub sigset_index: u32,

    /// Bytes representing a commitment to a destination (e.g. a native nomic
    /// account address, an IBC transfer destination, or a 0-byte for the
    /// reserve output owned by the network). These bytes are included in the
    /// redeem script to tie the funds to the destination.
    pub dest: LengthVec<u16, u8>,

    /// The amount of the input being spent, in satoshis.
    pub amount: u64,

    /// An estimate of the size of the witness for this input, in virtual bytes.
    /// This size is used for fee calculations.
    pub est_witness_vsize: u64,

    /// The signatures for this input. This structure is where the signatories
    /// coordinate to submit their signatures, and starts out with no
    /// signatures.
    pub signatures: ThresholdSig,
}

impl Input {
    /// Converts the `Input` to a `bitcoin::TxIn`, useful when constructing an
    /// actual Bitcoin transaction to be broadcast.
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

    /// Creates an `Input` which spends the given Bitcoin outpoint, populating
    /// it with an empty signing state to be signed by the given signatory set.
    pub fn new(
        prevout: bitcoin::OutPoint,
        sigset: &SignatorySet,
        dest: &[u8],
        amount: u64,
        threshold: (u64, u64),
    ) -> Result<Self> {
        let script_pubkey = sigset.output_script(dest, threshold)?;
        let redeem_script = sigset.redeem_script(dest, threshold)?;

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

    /// The estimated size of the input, including the worst-case size of the
    /// witness once fully signed, in virtual bytes.
    pub fn est_vsize(&self) -> u64 {
        self.est_witness_vsize + 40
    }
}

impl MigrateFrom<InputV0> for InputV1 {
    fn migrate_from(_value: InputV0) -> OrgaResult<Self> {
        unreachable!()
    }
}

/// A bitcoin transaction output, wrapped to implement the core `orga` traits.
pub type Output = Adapter<bitcoin::TxOut>;

/// A bitcoin transaction, as a native `orga` data structure.
#[orga]
#[derive(Debug)]
pub struct BitcoinTx {
    /// The locktime field included in the bitcoin transaction, representing
    /// either a block height or timestamp.
    pub lock_time: u32,

    /// A counter representing how many inputs have been fully-signed so far.
    /// The transaction is valid and ready to be broadcast to the bitcoin
    /// network once all inputs have been signed.
    pub signed_inputs: u16,

    /// The inputs to the transaction.
    pub input: Deque<Input>,

    /// The outputs to the transaction.
    pub output: Deque<Output>,
}

impl BitcoinTx {
    /// Converts the `BitcoinTx` to a `bitcoin::Transaction`.
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

    /// Creates a new `BitcoinTx` with the given locktime, and no inputs or
    /// outputs.
    pub fn with_lock_time(lock_time: u32) -> Self {
        BitcoinTx {
            lock_time,
            ..Default::default()
        }
    }

    /// Returns `true` if all inputs in the transaction are fully signed,
    /// otherwise returns `false`.
    pub fn signed(&self) -> bool {
        self.signed_inputs as u64 == self.input.len()
    }

    /// The estimated size of the transaction, including the worst-case sizes of
    /// all input witnesses once fully signed, in virtual bytes.
    pub fn vsize(&self) -> Result<u64> {
        Ok(self.to_bitcoin_tx()?.vsize().try_into()?)
    }

    /// The hash of the transaction. Note that this will change if any inputs or
    /// outputs are added, removed, or modified, so should only be used once the
    /// transaction is known to be final.
    pub fn txid(&self) -> Result<bitcoin::Txid> {
        let bitcoin_tx = self.to_bitcoin_tx()?;
        Ok(bitcoin_tx.txid())
    }

    /// The total value of the outputs in the transaction, in satoshis.
    pub fn value(&self) -> Result<u64> {
        self.output
            .iter()?
            .fold(Ok(0), |sum: Result<u64>, out| Ok(sum? + out?.value))
    }

    /// Calculates the sighash to be signed for the given input index, and
    /// populates the input's signing state with it. This should be used when a
    /// transaction is finalized and its structure will not change, and
    /// coordination of signing will begin.
    fn populate_input_sig_message(&mut self, input_index: usize) -> Result<()> {
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

    /// Deducts the given amount of satoshis evenly from all outputs in the
    /// transaction, leaving the difference as the amount to be paid to miners
    /// as a fee.
    ///
    /// This function will fail if the fee is greater than the value of the
    /// outputs in the transaction. Any inputs which are not large enough to pay
    /// their share of the fee will be removed.
    pub fn deduct_fee(&mut self, fee: u64) -> Result<()> {
        if fee == 0 {
            return Ok(());
        }

        if self.output.is_empty() {
            // TODO: Bitcoin module error
            return Err(Error::BitcoinFee(fee));
        }

        // This algorithm calculates the amount to attempt to deduct from each
        // output (`threshold`), and then removes any outputs which are too
        // small to pay this. Since removing outputs changes the threshold,
        // additional iterations will be required until all remaining outputs
        // are large enough.
        let threshold = loop {
            // The threshold is the fee divided by the number of outputs (each
            // output pays an equal share of the fee).
            let threshold = fee / self.output.len();

            // Remove any outputs which are too small to pay the threshold.
            let mut min_output = u64::MAX;
            self.output.retain_unordered(|output| {
                let dust_value = output.script_pubkey.dust_value().to_sat();
                let adjusted_output = output.value.saturating_sub(dust_value);
                if adjusted_output < min_output {
                    min_output = adjusted_output;
                }
                Ok(adjusted_output > threshold)
            })?;

            // Handle the case where no outputs remain.
            if self.output.is_empty() {
                break threshold;
            }

            // If the threshold is less than the smallest output, we can stop
            // here.
            let threshold = fee / self.output.len();
            if min_output >= threshold {
                break threshold;
            }
        };

        // Deduct the final fee share from each remaining output.
        for i in 0..self.output.len() {
            let mut output = self.output.get_mut(i)?.unwrap();
            output.value -= threshold;
        }

        Ok(())
    }
}

/// `BatchType` represents one of the three types of transaction batches in a
/// checkpoint.
#[derive(Debug)]
pub enum BatchType {
    /// The batch containing the "final emergency disbursal transactions".
    ///
    /// This batch will contain at least one and potentially many transactions,
    /// paying out to the recipients of the emergency disbursal (e.g. recovery
    /// wallets of nBTC holders).
    Disbursal,

    /// The batch containing the intermediate transaction.
    ///
    /// This batch will always contain exactly one transaction, the
    /// "intermediate emergency disbursal transaction", which spends the reserve
    /// output of a stuck checkpoint transaction, and pays out to inputs which
    /// will be spent by the final emergency disbursal transactions.
    IntermediateTx,

    /// The batch containing the checkpoint transaction. This batch will always
    /// contain exactly one transaction, the "checkpoint transaction".
    ///
    /// This transaction spends the reserve output of the previous checkpoint
    /// transaction and the outputs of any incoming deposits. It pays out to the
    /// the latest signatory set (in the "reserve output") and to destinations
    /// of any requested withdrawals.
    Checkpoint,
}

/// A batch of transactions in a checkpoint.
///
/// A batch is a collection of transactions which are atomically signed
/// together. Signatories submit signatures for all inputs in all transactions
/// in the batch at once. Once the batch is fully signed, the checkpoint can
/// advance to signing of the next batch, if any.
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

/// The default fee rate to be used to pay miner fees, in satoshis per virtual byte.
pub const DEFAULT_FEE_RATE: u64 = 10;

/// `Checkpoint` is the main structure which coordinates the network's
/// management of funds on the Bitcoin blockchain.
///
/// The network periodically creates checkpoints, which are Bitcoin transactions
/// that move the funds held in reserve. There is a singular sequential chain of
/// checkpoints, and each checkpoint has an associated signatory set. The
/// signatory set is a list of public keys of the signers performing the
/// decentralized custody of the funds held in reserve.
///
/// Checkpoints are each associated with a main transaction, the "checkpoint
/// transaction", which spends the reserve output of the previous checkpoint
/// transaction and the outputs of any incoming deposits. It pays out to the the
/// latest signatory set (in the "reserve output") and to destinations of any
/// requested withdrawals. This transaction is included in the third batch of
/// the `batches` deque.
///
/// Checkpoints are also associated with a set of transactions which pay out to
/// the recipients of the emergency disbursal (e.g. recovery wallets of nBTC
/// holders), if the checkpoint transaction is not spent after a given amount of
/// time (e.g. two weeks). These transactions are broken up into a single
/// "intermediate emergency disbursal transaction" (in the second batch of the
/// `batches` deque), and one or more "final emergency disbursal transactions"
/// (in the first batch of the `batches` deque).
#[orga(skip(Default), version = 3)]
#[derive(Debug)]
pub struct Checkpoint {
    /// The status of the checkpoint, either `Building`, `Signing`, or
    /// `Complete`.
    pub status: CheckpointStatus,

    /// The batches of transactions in the checkpoint, to each be signed
    /// atomically, in order. The first batch contains the "final emergency
    /// disbursal transactions", the second batch contains the "intermediate
    /// emergency disbursal transaction", and the third batch contains the
    /// "checkpoint transaction".
    pub batches: Deque<Batch>,

    /// Pending transfers of nBTC to be processed once the checkpoint is fully
    /// signed. These transfers are processed in lockstep with the checkpointing
    /// process in order to keep nBTC balances in sync with the emergency
    /// disbursal.
    ///
    /// These transfers can be initiated by a simple nBTC send or by a deposit.
    #[orga(version(V2, V3))]
    pub pending: Map<Dest, Coin<Nbtc>>,

    /// The fee rate to use when calculating the miner fee for the transactions
    /// in the checkpoint, in satoshis per virtual byte.
    ///
    /// This rate is automatically adjusted per-checkpoint, being increased when
    /// completed checkpoints are not being confirmed on the Bitcoin network
    /// faster than the target confirmation speed (implying the network is
    /// paying too low of a fee), and being decreased if checkpoints are
    /// confirmed faster than the target confirmation speed.
    #[orga(version(V3))]
    pub fee_rate: u64,

    /// The height of the Bitcoin block at which the checkpoint was fully signed
    /// and ready to be broadcast to the Bitcoin network, used by the fee
    /// adjustment algorithm to determine if the checkpoint was confirmed too
    /// fast or too slow.
    #[orga(version(V3))]
    pub signed_at_btc_height: Option<u32>,

    /// Whether or not to honor relayed deposits made against this signatory
    /// set. This can be used, for example, to enforce a cap on deposits into
    /// the system.
    #[orga(version(V3))]
    pub deposits_enabled: bool,

    /// The signatory set associated with the checkpoint. Note that deposits to
    /// slightly older signatory sets can still be processed in this checkpoint,
    /// but the reserve output will be paid to the latest signatory set.
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
            deposits_enabled: true,
        })
    }
}

#[orga]
impl Checkpoint {
    /// Creates a new checkpoint with the given signatory set.
    ///
    /// The checkpoint will be initialized with a single empty checkpoint
    /// transaction, a single empty intermediate emergency disbursal
    /// transaction, and an empty batch of final emergency disbursal
    /// transactions.
    pub fn new(sigset: SignatorySet) -> Result<Self> {
        let mut checkpoint = Checkpoint {
            status: CheckpointStatus::default(),
            batches: Deque::default(),
            pending: Map::new(),
            fee_rate: DEFAULT_FEE_RATE,
            signed_at_btc_height: None,
            deposits_enabled: true,
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

    /// Processes a batch of signatures from a signatory, applying them to the
    /// inputs of transaction batches which are ready to be signed.
    ///
    /// Transaction batches are ready to be signed if they are either already
    /// signed (all inputs of all transactions in the batch are above the
    /// signing threshold), in which case any newly-submitted signatures will
    /// "over-sign" the inputs, or if the batch is the first non-signed batch
    /// (the "active" batch). This prevents signatories from submitting
    /// signatures to a batch beyond the active batch, so that batches are
    /// always finished signing serially, in order.
    ///
    /// A signatory must submit all signatures for all inputs in which they are
    /// present in the signatory set, for all transactions of all batches ready
    /// to be signed. If the signatory provides more or less signatures than
    /// expected, `sign()` will return an error.
    fn sign(&mut self, xpub: Xpub, sigs: LengthVec<u16, Signature>, btc_height: u32) -> Result<()> {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        let cp_was_signed = self.signed()?;
        let mut sig_index = 0;

        // Iterate over all batches in the checkpoint, breaking once iterating
        // to a batch which is not ready to be signed.
        for i in 0..self.batches.len() {
            let mut batch = self.batches.get_mut(i)?.unwrap();
            let batch_was_signed = batch.signed();

            // Iterate over all transactions in the batch.
            for j in 0..batch.len() {
                let mut tx = batch.get_mut(j)?.unwrap();
                let tx_was_signed = tx.signed();

                // Iterate over all inputs in the transaction.
                for k in 0..tx.input.len() {
                    let mut input = tx.input.get_mut(k)?.unwrap();
                    let pubkey = derive_pubkey(&secp, xpub, input.sigset_index)?;

                    // Skip input if either the signatory is not part of this
                    // input's signatory set, or the signatory has already
                    // submitted a signature for this input.
                    if !input.signatures.needs_sig(pubkey.into())? {
                        continue;
                    }

                    // Error if there are no remaining supplied signatures - the
                    // signatory supplied less signatures than we require from
                    // them.
                    if sig_index >= sigs.len() {
                        return Err(
                            OrgaError::App("Not enough signatures supplied".to_string()).into()
                        );
                    }
                    let sig = sigs[sig_index];
                    sig_index += 1;

                    // Apply the signature.
                    let input_was_signed = input.signatures.signed();
                    input.signatures.sign(pubkey.into(), sig)?;

                    // If this signature made the input fully signed, increase
                    // the counter of fully-signed inputs in the containing
                    // transaction.
                    if !input_was_signed && input.signatures.signed() {
                        tx.signed_inputs += 1;
                    }
                }

                // If these signatures made the transaction fully signed,
                // increase the counter of fully-signed transactions in the
                // containing batch.
                if !tx_was_signed && tx.signed() {
                    batch.signed_txs += 1;
                }
            }

            // If this was the last batch ready to be signed, stop here.
            if !batch_was_signed {
                break;
            }
        }

        // Error if there are remaining supplied signatures - the signatory
        // supplied more signatures than we require from them.
        if sig_index != sigs.len() {
            return Err(OrgaError::App("Excess signatures supplied".to_string()).into());
        }

        // If these signatures made the checkpoint fully signed, record the
        // height at which it was signed.
        if self.signed()? && !cp_was_signed {
            self.signed_at_btc_height = Some(btc_height);
        }

        Ok(())
    }

    /// Gets the checkpoint transaction as a `bitcoin::Transaction`.
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

    /// Gets the output containing the reserve funds for the checkpoint, the
    /// "reserve output". This output is owned by the latest signatory set, and
    /// is spent by the suceeding checkpoint transaction.
    ///
    /// This output is not created until the checkpoint advances to `Signing`
    /// status.
    pub fn reserve_output(&self) -> Result<Option<TxOut>> {
        // TODO: should return None for Building checkpoints? otherwise this
        // might return a withdrawal
        let checkpoint_tx = self.checkpoint_tx()?;
        if let Some(output) = checkpoint_tx.output.get(0) {
            Ok(Some(output.clone()))
        } else {
            Ok(None)
        }
    }

    /// Returns a list of all inputs in the checkpoint which the signatory with
    /// the given extended public key should sign.
    ///
    /// The return value is a list of tuples, each containing `(sighash,
    /// sigset_index)` - the sighash to be signed and the index of the signatory
    /// set associated with the input.
    #[query]
    pub fn to_sign(&self, xpub: Xpub) -> Result<Vec<([u8; 32], u32)>> {
        // TODO: thread local secpk256k1 context
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

    /// Returns the number of fully-signed batches in the checkpoint.
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

    /// Returns the current batch being signed, or `None` if all batches are
    /// signed.
    pub fn current_batch(&self) -> Result<Option<Ref<Batch>>> {
        if self.signed()? {
            return Ok(None);
        }

        Ok(Some(self.batches.get(self.signed_batches()?)?.unwrap()))
    }

    /// Returns the timestamp at which the checkpoint was created (when it was
    /// first constructed in the `Building` status).
    pub fn create_time(&self) -> u64 {
        self.sigset.create_time()
    }

    /// Returns `true` if all batches in the checkpoint are fully signed,
    /// otherwise returns `false`.
    pub fn signed(&self) -> Result<bool> {
        Ok(self.signed_batches()? == self.batches.len())
    }

    /// The emergency disbursal transactions for checkpoint.
    ///
    /// The first element of the returned vector is the intermediate
    /// transaction, and the remaining elements are the final transactions.
    pub fn emergency_disbursal_txs(&self) -> Result<Vec<Adapter<bitcoin::Transaction>>> {
        let mut txs = vec![];

        let intermediate_tx_batch = self.batches.get(BatchType::IntermediateTx as u64)?.unwrap();
        let Some(intermediate_tx) = intermediate_tx_batch.get(0)? else {
            return Ok(txs);
        };
        txs.push(Adapter::new(intermediate_tx.to_bitcoin_tx()?));

        let disbursal_batch = self.batches.get(BatchType::Disbursal as u64)?.unwrap();
        for tx in disbursal_batch.iter()? {
            txs.push(Adapter::new(tx?.to_bitcoin_tx()?));
        }

        Ok(txs)
    }
}

/// Configuration parameters used in processing checkpoints.
#[orga(skip(Default), version = 2)]
#[derive(Clone)]
pub struct Config {
    /// The minimum amount of time between the creation of checkpoints, in
    /// seconds.
    ///
    /// If a checkpoint is to be created, but less than this time has passed
    /// since the last checkpoint was created (in the `Building` state), the
    /// current `Building` checkpoint will be delayed in advancing to `Signing`.
    pub min_checkpoint_interval: u64,

    /// The maximum amount of time between the creation of checkpoints, in
    /// seconds.
    ///
    /// If a checkpoint would otherwise not be created, but this amount of time
    /// has passed since the last checkpoint was created (in the `Building`
    /// state), the current `Building` checkpoint will be advanced to `Signing`
    /// and a new `Building` checkpoint will be added.
    pub max_checkpoint_interval: u64,

    /// The maximum number of inputs allowed in a checkpoint transaction.
    ///
    /// This is used to prevent the checkpoint transaction from being too large
    /// to be accepted by the Bitcoin network.
    ///
    /// If a checkpoint has more inputs than this when advancing from `Building`
    /// to `Signing`, the excess inputs will be moved to the suceeding,
    /// newly-created `Building` checkpoint.
    pub max_inputs: u64,

    /// The maximum number of outputs allowed in a checkpoint transaction.
    ///
    /// This is used to prevent the checkpoint transaction from being too large
    /// to be accepted by the Bitcoin network.
    ///
    /// If a checkpoint has more outputs than this when advancing from `Building`
    /// to `Signing`, the excess outputs will be moved to the suceeding,
    /// newly-created `Building` checkpoint.∑
    pub max_outputs: u64,

    /// The default fee rate to use when creating the first checkpoint of the
    /// network, in satoshis per virtual byte.
    #[orga(version(V0))]
    pub fee_rate: u64,

    /// The maximum age of a checkpoint to retain, in seconds.
    ///
    /// Checkpoints older than this will be pruned from the state, down to a
    /// minimum of 10 checkpoints in the checkpoint queue.
    pub max_age: u64,

    /// The number of blocks to target for confirmation of the checkpoint
    /// transaction.
    ///
    /// This is used to adjust the fee rate of the checkpoint transaction, to
    /// ensure it is confirmed within the target number of blocks. The fee rate
    /// will be adjusted up if the checkpoint transaction is not confirmed
    /// within the target number of blocks, and will be adjusted down if the
    /// checkpoint transaction faster than the target.
    #[orga(version(V1, V2))]
    pub target_checkpoint_inclusion: u32,

    /// The lower bound to use when adjusting the fee rate of the checkpoint
    /// transaction, in satoshis per virtual byte.
    #[orga(version(V1, V2))]
    pub min_fee_rate: u64,

    /// The upper bound to use when adjusting the fee rate of the checkpoint
    /// transaction, in satoshis per virtual byte.
    #[orga(version(V1, V2))]
    pub max_fee_rate: u64,

    /// The threshold of signatures required to spend reserve scripts, as a
    /// ratio represented by a tuple, `(numerator, denominator)`.
    ///
    /// For example, `(9, 10)` means the threshold is 90% of the signatory set.
    #[orga(version(V1, V2))]
    pub sigset_threshold: (u64, u64),

    /// The minimum amount of nBTC an account must hold to be eligible for an
    /// output in the emergency disbursal.
    #[orga(version(V1, V2))]
    pub emergency_disbursal_min_tx_amt: u64,

    /// The amount of time between the creation of a checkpoint and when the
    /// associated emergency disbursal transactions can be spent, in seconds.
    #[orga(version(V1, V2))]
    pub emergency_disbursal_lock_time_interval: u32,

    /// The maximum size of a final emergency disbursal transaction, in virtual
    /// bytes.
    ///
    /// The outputs to be included in final emergency disbursal transactions
    /// will be distributed across multiple transactions around this size.
    #[orga(version(V1, V2))]
    pub emergency_disbursal_max_tx_size: u64,

    /// The maximum number of unconfirmed checkpoints before the network will
    /// stop creating new checkpoints.
    ///
    /// If there is a long chain of unconfirmed checkpoints, there is possibly
    /// an issue causing the transactions to not be included on Bitcoin (e.g. an
    /// invalid transaction was created, the fee rate is too low even after
    /// adjustments, Bitcoin miners are censoring the transactions, etc.), in
    /// which case the network should evaluate and fix the issue before creating
    /// more checkpoints.
    ///
    /// This will also stop the fee rate from being adjusted too high if the
    /// issue is simply with relayers failing to report the confirmation of the
    /// checkpoint transactions.
    #[orga(version(V2))]
    pub max_unconfirmed_checkpoints: u32,
}

impl MigrateFrom<ConfigV0> for ConfigV1 {
    fn migrate_from(value: ConfigV0) -> OrgaResult<Self> {
        Ok(Self {
            min_checkpoint_interval: value.min_checkpoint_interval,
            max_checkpoint_interval: value.max_checkpoint_interval,
            max_inputs: value.max_inputs,
            max_outputs: value.max_outputs,
            max_age: value.max_age,
            target_checkpoint_inclusion: ConfigV2::default().target_checkpoint_inclusion,
            min_fee_rate: ConfigV2::default().min_fee_rate,
            max_fee_rate: ConfigV2::default().max_fee_rate,
            sigset_threshold: ConfigV2::default().sigset_threshold,
            emergency_disbursal_min_tx_amt: ConfigV2::default().emergency_disbursal_min_tx_amt,
            emergency_disbursal_lock_time_interval: ConfigV2::default()
                .emergency_disbursal_lock_time_interval,
            emergency_disbursal_max_tx_size: ConfigV2::default().emergency_disbursal_max_tx_size,
        })
    }
}

impl MigrateFrom<ConfigV1> for ConfigV2 {
    fn migrate_from(value: ConfigV1) -> OrgaResult<Self> {
        Ok(Self {
            min_checkpoint_interval: value.min_checkpoint_interval,
            max_checkpoint_interval: value.max_checkpoint_interval,
            max_inputs: value.max_inputs,
            max_outputs: value.max_outputs,
            max_age: value.max_age,
            target_checkpoint_inclusion: value.target_checkpoint_inclusion,
            min_fee_rate: value.min_fee_rate,
            max_fee_rate: value.max_fee_rate,
            sigset_threshold: value.sigset_threshold,
            emergency_disbursal_min_tx_amt: value.emergency_disbursal_min_tx_amt,
            emergency_disbursal_lock_time_interval: value.emergency_disbursal_lock_time_interval,
            emergency_disbursal_max_tx_size: value.emergency_disbursal_max_tx_size,
            ..Default::default()
        })
    }
}

impl Config {
    fn regtest() -> Self {
        Self {
            min_checkpoint_interval: 15,
            emergency_disbursal_lock_time_interval: 60,
            emergency_disbursal_max_tx_size: 11,
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
            sigset_threshold: SIGSET_THRESHOLD,
            emergency_disbursal_min_tx_amt: 1000,
            #[cfg(feature = "testnet")]
            emergency_disbursal_lock_time_interval: 60 * 60 * 24 * 7, // one week
            #[cfg(not(feature = "testnet"))]
            emergency_disbursal_lock_time_interval: 60 * 60 * 24 * 7 * 2, // two weeks
            emergency_disbursal_max_tx_size: 50_000,
            max_unconfirmed_checkpoints: 15,
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

/// `CheckpointQueue` is the main collection for the checkpointing process,
/// containing a sequential chain of checkpoints.
///
/// Once the network has processed its first deposit, the checkpoint queue will
/// always contain at least one checkpoint, in the `Building` state, at the
/// highest index in the queue.
///
/// The queue will only contain at most one checkpoint in the `Signing` state,
/// at the second-highest index in the queue if it exists. When this checkpoint
/// is stil being signed, progress will block and no new checkpoints will be
/// created since the checkpoints are in a sequential chain.
///
/// The queue may contain any number of checkpoints in the `Complete` state,
/// which are the checkpoints which have been fully signed and are ready to be
/// broadcast to the Bitcoin network. The queue also maintains a counter
/// (`confirmed_index`) to track which of these completed checkpoints have been
/// confirmed in a Bitcoin block.
#[orga(version = 2)]
pub struct CheckpointQueue {
    /// The checkpoints in the queue, in order from oldest to newest. The last
    /// checkpoint is the checkpoint currently being built, and has the index
    /// contained in the `index` field.
    pub queue: Deque<Checkpoint>,

    /// The index of the checkpoint currently being built.
    pub index: u32,

    /// The index of the last checkpoint which has been confirmed in a Bitcoin
    /// block. Since checkpoints are a sequential cahin, each spending an output
    /// from the previous, all checkpoints with an index lower than this must
    /// have also been confirmed.
    #[orga(version(V2))]
    pub confirmed_index: Option<u32>,

    /// Configuration parameters used in processing checkpoints.
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

/// A wrapper around  an immutable reference to a `Checkpoint` which adds type
/// information guaranteeing that the checkpoint is in the `Complete` state.
#[derive(Deref)]
pub struct CompletedCheckpoint<'a>(Ref<'a, Checkpoint>);

/// A wrapper around an immutable reference to a `Checkpoint` which adds type
/// information guaranteeing that the checkpoint is in the `Signing` state.
#[derive(Deref, Debug)]
pub struct SigningCheckpoint<'a>(Ref<'a, Checkpoint>);

impl<'a> Query for SigningCheckpoint<'a> {
    type Query = ();

    fn query(&self, _: ()) -> OrgaResult<()> {
        Ok(())
    }
}

/// A wrapper around a mutable reference to a `Checkpoint` which adds type
/// information guaranteeing that the checkpoint is in the `Complete` state.
#[derive(Deref, DerefMut)]
pub struct SigningCheckpointMut<'a>(ChildMut<'a, u64, Checkpoint>);

impl<'a> SigningCheckpointMut<'a> {
    /// Adds a batch of signatures to the checkpoint for the signatory with the
    /// given extended public key (`xpub`).
    ///
    /// The signatures must be provided in the same order as the inputs in the
    /// checkpoint transaction, and must be provided for all inputs in which the
    /// signatory is present in the signatory set.
    pub fn sign(
        &mut self,
        xpub: Xpub,
        sigs: LengthVec<u16, Signature>,
        btc_height: u32,
    ) -> Result<()> {
        self.0.sign(xpub, sigs, btc_height)
    }

    /// Changes the status of the checkpoint to `Complete`.
    pub fn advance(self) -> Result<()> {
        let mut checkpoint = self.0;

        checkpoint.status = CheckpointStatus::Complete;

        Ok(())
    }
}

/// A wrapper around an immutable reference to a `Checkpoint` which adds type
/// information guaranteeing that the checkpoint is in the `Building` state.
#[derive(Deref)]
pub struct BuildingCheckpoint<'a>(Ref<'a, Checkpoint>);

/// A wrapper around a mutable reference to a `Checkpoint` which adds type
/// information guaranteeing that the checkpoint is in the `Building` state.
#[derive(Deref, DerefMut)]
pub struct BuildingCheckpointMut<'a>(ChildMut<'a, u64, Checkpoint>);

/// The data returned by the `advance()` method of `BuildingCheckpointMut`.
type BuildingAdvanceRes = (
    bitcoin::OutPoint,
    u64,
    Vec<ReadOnly<Input>>,
    Vec<ReadOnly<Output>>,
);

impl<'a> BuildingCheckpointMut<'a> {
    /// Adds an output to the intermediate emergency disbursal transaction of
    /// the checkpoint, to be spent by the given final emergency disbursal
    /// transaction. The corresponding input is also added to the final
    /// emergency disbursal transaction.
    fn link_intermediate_tx(&mut self, tx: &mut BitcoinTx, threshold: (u64, u64)) -> Result<()> {
        let sigset = self.sigset.clone();
        let output_script = sigset.output_script(&[0u8], threshold)?;
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
            threshold,
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

    /// Deducts satoshis from the outputs of all emergency disbursal
    /// transactions (the intermediate transaction and all final transactions)
    /// to make them pay the miner fee at the given fee rate.
    ///
    /// Any outputs which are too small to pay their share of the required fees
    /// will be removed.
    ///
    /// It is possible for this process to remove outputs from the intermediate
    /// transaction, leaving an orphaned final transaction which spends from a
    /// non-existent output. for simplicity the unconnected final transaction is
    /// left in the state (it can be skipped by relayers when broadcasting the
    /// remaining valid emergency disbursal transactions).
    fn deduct_emergency_disbursal_fees(&mut self, fee_rate: u64) -> Result<()> {
        // TODO: Unit tests

        // Deduct fees from intermediate emergency disbursal transaction.
        // Let-binds the amount deducted so we can ensure to deduct the same
        // amount from the final emergency disbursal transactions since the
        // outputs they spend are now worth less than before.
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

        // Collect a list of the outputs of the intermediate emergency
        // disbursal, so later on we can ensure there is a 1-to-1 mapping
        // between final transactions and intermediate outputs, matched by
        // amount.
        let mut intermediate_tx_outputs: Vec<(usize, u64)> = intermediate_tx
            .output
            .iter()?
            .enumerate()
            .map(|(i, output)| Ok((i, output?.value)))
            .collect::<Result<_>>()?;

        // Deduct fees from final emergency disbursal transactions. Only retain
        // transactions which have enough value to pay the fee.
        let mut disbursal_batch = self.batches.get_mut(BatchType::Disbursal as u64)?.unwrap();
        disbursal_batch.retain_unordered(|mut tx| {
            // Do not retain transactions which were never linked to the
            // intermediate tx.
            // TODO: is this even possible?
            let mut input = match tx.input.get_mut(0)? {
                Some(input) => input,
                None => return Ok(false),
            };

            // Do not retain transactions which are smaller than the amount of
            // fee applied to the intermediate tx output which they spend. If
            // large enough, deduct the fee from the input to match what was
            // already deducted for the intermediate tx output.
            if input.amount < intermediate_tx_fee / intermediate_tx_len {
                return Ok(false);
            }
            input.amount -= intermediate_tx_fee / intermediate_tx_len;

            // Find the first remaining output of the intermediate tx which
            // matches the amount being spent by this final tx's input.
            for (i, (vout, output)) in intermediate_tx_outputs.iter().enumerate() {
                if output == &(input.amount) {
                    // Once found, link the final tx's input to the vout index
                    // of the the matching output from the intermediate tx, and
                    // remove it from the matching list.

                    input.prevout = Adapter::new(bitcoin::OutPoint {
                        txid: intermediate_tx_id,
                        vout: *vout as u32,
                    });
                    intermediate_tx_outputs.remove(i);
                    // Deduct the final tx's miner fee from its outputs,
                    // removing any outputs which are too small to pay their
                    // share of the fee.
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

    /// Generates the emergency disbursal transactions for the checkpoint,
    /// populating the first and second transaction batches in the checkpoint.
    ///
    /// The emergency disbursal transactions are generated from a list of
    /// outputs representing the holders of nBTC: one for every nBTC account
    /// which has an associated recovery script, one for every pending transfer
    /// in the checkpoint, and one for every output passed in by the consumer
    /// via the `external_outputs` iterator.
    #[allow(clippy::too_many_arguments)]
    fn generate_emergency_disbursal_txs(
        &mut self,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::coins::Address, Adapter<bitcoin::Script>>,
        reserve_outpoint: bitcoin::OutPoint,
        external_outputs: impl Iterator<Item = Result<bitcoin::TxOut>>,
        fee_rate: u64,
        reserve_value: u64,
        config: &Config,
    ) -> Result<()> {
        // TODO: Use tree structure instead of single-intermediate, many-final,
        // since the intermediate tx may grow too large

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

            use orga::context::Context;
            let time = Context::resolve::<Time>()
                .ok_or_else(|| OrgaError::Coins("No Time context found".into()))?;

            let sigset = self.sigset.clone();

            let lock_time = time.seconds as u32 + config.emergency_disbursal_lock_time_interval;

            let mut outputs = Vec::new();

            // Create an output for every nBTC account with an associated
            // recovery script.
            for entry in recovery_scripts.iter()? {
                let (address, dest_script) = entry?;
                let balance = nbtc_accounts.balance(*address)?;
                let tx_out = bitcoin::TxOut {
                    value: u64::from(balance) / 1_000_000,
                    script_pubkey: dest_script.clone().into_inner(),
                };

                outputs.push(Ok(tx_out))
            }

            // Create an output for every pending nBTC transfer in the checkpoint.
            // TODO: combine pending transfer outputs into other outputs by adding to amount
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

            // Iterate through outputs and batch them into final txs, adding
            // outputs to the intermediate tx and linking inputs to them as we
            // go.
            let mut final_txs = vec![BitcoinTx::with_lock_time(lock_time)];
            for output in outputs
                .into_iter()
                .chain(pending_outputs.into_iter())
                .chain(external_outputs)
            {
                let output = output?;

                // Skip outputs under the configured minimum amount.
                if output.value < config.emergency_disbursal_min_tx_amt {
                    continue;
                }

                // If the last final tx is too large, create a new, empty one
                // and add our output there instead.
                // TODO: don't pop and repush, just get a mutable reference
                let mut curr_tx = final_txs.pop().unwrap();
                if curr_tx.vsize()? >= config.emergency_disbursal_max_tx_size {
                    self.link_intermediate_tx(&mut curr_tx, config.sigset_threshold)?;
                    final_txs.push(curr_tx);
                    curr_tx = BitcoinTx::with_lock_time(lock_time);
                }

                // Add output to final tx.
                curr_tx.output.push_back(Adapter::new(output))?;

                final_txs.push(curr_tx);
            }

            // We are done adding outputs, so link the last final tx to the
            // intermediate tx.
            let mut last_tx = final_txs.pop().unwrap();
            self.link_intermediate_tx(&mut last_tx, config.sigset_threshold)?;
            final_txs.push(last_tx);

            // Add the reserve output as an input to the intermediate tx, and
            // set its locktime to the desired value.
            let tx_in = Input::new(
                reserve_outpoint,
                &sigset,
                &[0u8],
                reserve_value,
                config.sigset_threshold,
            )?;
            let output_script = self.sigset.output_script(&[0u8], config.sigset_threshold)?;
            let mut intermediate_tx_batch = self
                .batches
                .get_mut(BatchType::IntermediateTx as u64)?
                .unwrap();
            let mut intermediate_tx = intermediate_tx_batch.get_mut(0)?.unwrap();
            intermediate_tx.lock_time = lock_time;
            intermediate_tx.input.push_back(tx_in)?;

            // For any excess value not accounted for by emergency disbursal
            // outputs, add an output to the intermediate tx which pays the
            // excess back to the signatory set. The signatory set will need to
            // coordinate out-of-band to figure out how to deal with these
            // unaccounted-for funds to return them to the rightful nBTC
            // holders.
            let intermediate_tx_out_value = intermediate_tx.value()?;
            let excess_value = reserve_value - intermediate_tx_out_value;
            let excess_tx_out = bitcoin::TxOut {
                value: excess_value,
                script_pubkey: output_script,
            };
            intermediate_tx
                .output
                .push_back(Adapter::new(excess_tx_out))?;

            // Push the newly created final txs into the checkpoint batch to
            // save them in the state.
            let mut disbursal_batch = self.batches.get_mut(BatchType::Disbursal as u64)?.unwrap();
            for tx in final_txs {
                disbursal_batch.push_back(tx)?;
            }
        }

        // Deduct Bitcoin miner fees from the intermediate tx and all final txs.
        self.deduct_emergency_disbursal_fees(fee_rate)?;

        // Populate the sighashes to be signed for each final tx's input.
        let mut disbursal_batch = self.batches.get_mut(BatchType::Disbursal as u64)?.unwrap();
        for i in 0..disbursal_batch.len() {
            let mut tx = disbursal_batch.get_mut(i)?.unwrap();
            for j in 0..tx.input.len() {
                tx.populate_input_sig_message(j.try_into()?)?;
            }
        }

        // Populate the sighashes to be signed for the intermediate tx's input.
        let mut intermediate_tx_batch = self
            .batches
            .get_mut(BatchType::IntermediateTx as u64)?
            .unwrap();
        let mut intermediate_tx = intermediate_tx_batch.get_mut(0)?.unwrap();
        intermediate_tx.populate_input_sig_message(0)?;

        Ok(())
    }

    /// Advances the checkpoint to the `Signing` state.
    ///
    /// This will generate the emergency disbursal transactions representing the
    /// ownership of nBTC at this point in time. It will also prepare all inputs
    /// to be signed, across the three transaction batches.
    ///
    /// This step freezes the checkpoint, and no further changes can be made to
    /// it other than adding signatures. This means at this point all
    /// transactions contained within have a known transaction id which will not
    /// change.
    #[allow(unused_variables)]
    pub fn advance(
        mut self,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::coins::Address, Adapter<bitcoin::Script>>,
        external_outputs: impl Iterator<Item = Result<bitcoin::TxOut>>,
        timestamping_commitment: Vec<u8>,
        config: &Config,
    ) -> Result<BuildingAdvanceRes> {
        self.0.status = CheckpointStatus::Signing;

        // The reserve output is the first output of the checkpoint tx, and
        // contains all funds held in reserve by the network.
        let reserve_out = bitcoin::TxOut {
            value: 0, // will be updated after counting ins/outs and fees
            script_pubkey: self
                .0
                .sigset
                .output_script(&[0u8], config.sigset_threshold)?,
        };

        // The timestamping commitment output is the second output of the
        // checkpoint tx, and contains a commitment to some given data, which
        // will be included on the Bitcoin blockchain as `OP_RETURN` data, now
        // timestamped by Bitcoin's proof-of-work security.
        let timestamping_commitment_out = bitcoin::TxOut {
            value: 0,
            script_pubkey: bitcoin::Script::new_op_return(&timestamping_commitment),
        };

        let fee_rate = self.fee_rate;

        let mut checkpoint_batch = self
            .0
            .batches
            .get_mut(BatchType::Checkpoint as u64)?
            .unwrap();
        let mut checkpoint_tx = checkpoint_batch.get_mut(0)?.unwrap();
        checkpoint_tx
            .output
            .push_front(Adapter::new(timestamping_commitment_out))?;
        checkpoint_tx.output.push_front(Adapter::new(reserve_out))?;

        // Remove excess inputs and outputs from the checkpoint tx, to be pushed
        // onto the suceeding checkpoint while in its `Building` state.
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

        // Sum the total input and output amounts.
        // TODO: Input/Output sum functions
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

        // Deduct the outgoing amount and calculated fee amount from the reserve
        // input amount, to set the resulting reserve output value.
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

        // Prepare the checkpoint tx's inputs to be signed by calculating their
        // sighashes.
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

        // Generate the emergency disbursal transactions, spending from the
        // reserve output.
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
            config,
        )?;

        Ok((
            reserve_outpoint,
            reserve_value,
            excess_inputs,
            excess_outputs,
        ))
    }

    /// Insert a transfer to the pending transfer queue.
    ///
    /// Transfers will be processed once the containing checkpoint is finished
    /// being signed, but will be represented in this checkpoint's emergency
    /// disbursal before they are processed.
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
    /// Set the queue's configuration parameters.
    pub fn configure(&mut self, config: Config) {
        self.config = config;
    }

    /// The queue's current configuration parameters.
    pub fn config(&self) -> Config {
        self.config.clone()
    }

    /// Removes all checkpoints from the queue and resets the index to zero.
    pub fn reset(&mut self) -> OrgaResult<()> {
        self.index = 0;
        super::clear_deque(&mut self.queue)?;

        Ok(())
    }

    /// Gets a refernce to the checkpoint at the given index.
    ///
    /// If the index is out of bounds or was pruned, an error is returned.
    #[query]
    pub fn get(&self, index: u32) -> Result<Ref<'_, Checkpoint>> {
        let index = self.get_deque_index(index)?;
        Ok(self.queue.get(index as u64)?.unwrap())
    }

    /// Gets a mutable reference to the checkpoint at the given index.
    ///
    /// If the index is out of bounds or was pruned, an error is returned.
    pub fn get_mut(&mut self, index: u32) -> Result<ChildMut<'_, u64, Checkpoint>> {
        let index = self.get_deque_index(index)?;
        Ok(self.queue.get_mut(index as u64)?.unwrap())
    }

    /// Calculates the index within the deque based on the given checkpoint
    /// index.
    ///
    /// This is necessary because the values can differ for queues which have
    /// been pruned. For example, a queue may contain 5 checkpoints,
    /// representing indexes 30 to 34. Checkpoint index 30 is at deque index 0,
    /// checkpoint 34 is at deque index 4, and checkpoint index 29 is now
    /// out-of-bounds.
    fn get_deque_index(&self, index: u32) -> Result<u32> {
        let start = self.index + 1 - (self.queue.len() as u32);
        if index > self.index || index < start {
            Err(OrgaError::App("Index out of bounds".to_string()).into())
        } else {
            Ok(index - start)
        }
    }

    /// The number of checkpoints in the queue.
    ///
    /// This will likely be different from `index` since checkpoints can be
    /// pruned. After receiving the first deposit, the network will always have
    /// at least one checkpoint in the queue.
    // TODO: remove this attribute, not sure why clippy is complaining when
    // is_empty is defined
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> Result<u32> {
        Ok(u32::try_from(self.queue.len())?)
    }

    /// Returns `true` if there are no checkpoints in the queue.
    ///
    /// This will only be `true` before the first deposit has been processed.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// The index of the last checkpoint in the queue (aka the `Building`
    /// checkpoint).
    #[query]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// All checkpoints in the queue, in order from oldest to newest.
    ///
    /// The return value is a vector of tuples, where the first element is the
    /// checkpoint's index, and the second element is a reference to the
    /// checkpoint.
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

    /// All checkpoints in the queue which are in the `Complete` state, in order
    /// from oldest to newest.
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

    /// The index of the last completed checkpoint.
    #[query]
    pub fn last_completed_index(&self) -> Result<u32> {
        if self.signing()?.is_some() {
            self.index.checked_sub(2)
        } else {
            self.index.checked_sub(1)
        }
        .ok_or_else(|| Error::Orga(OrgaError::App("No completed checkpoints yet".to_string())))
    }

    /// A reference to the last completed checkpoint.
    #[query]
    pub fn last_completed(&self) -> Result<Ref<Checkpoint>> {
        self.get(self.last_completed_index()?)
    }

    /// A mutable reference to the last completed checkpoint.
    pub fn last_completed_mut(&mut self) -> Result<ChildMut<u64, Checkpoint>> {
        self.get_mut(self.last_completed_index()?)
    }

    /// The last completed checkpoint, converted to a Bitcoin transaction.
    #[query]
    pub fn last_completed_tx(&self) -> Result<Adapter<bitcoin::Transaction>> {
        self.last_completed()?.checkpoint_tx()
    }

    /// All completed checkpoints, converted to Bitcoin transactions.
    #[query]
    pub fn completed_txs(&self, limit: u32) -> Result<Vec<Adapter<bitcoin::Transaction>>> {
        self.completed(limit)?
            .into_iter()
            .map(|c| c.checkpoint_tx())
            .collect()
    }

    /// The emergency disbursal transactions for the last completed checkpoint.
    ///
    /// The first element of the returned vector is the intermediate
    /// transaction, and the remaining elements are the final transactions.
    #[query]
    pub fn emergency_disbursal_txs(&self) -> Result<Vec<Adapter<bitcoin::Transaction>>> {
        if let Some(completed) = self.completed(1)?.last() {
            completed.emergency_disbursal_txs()
        } else {
            Ok(vec![])
        }
    }

    /// A reference to the checkpoint in the `Signing` state, if there is one.
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

    /// A mutable reference to the checkpoint in the `Signing` state, if there
    /// is one.
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

    /// A reference to the checkpoint in the `Building` state.
    ///
    /// This is the checkpoint which is currently being built, and is not yet
    /// being signed. Other than at the start of the network, before the first
    /// deposit has been received, there will always be a checkpoint in this
    /// state.
    pub fn building(&self) -> Result<BuildingCheckpoint> {
        let last = self.get(self.index)?;
        Ok(BuildingCheckpoint(last))
    }

    /// A mutable reference to the checkpoint in the `Building` state.
    ///
    /// This is the checkpoint which is currently being built, and is not yet
    /// being signed. Other than at the start of the network, before the first
    /// deposit has been received, there will always be a checkpoint in this
    /// state.
    pub fn building_mut(&mut self) -> Result<BuildingCheckpointMut> {
        let last = self.get_mut(self.index)?;
        Ok(BuildingCheckpointMut(last))
    }

    /// Prunes old checkpoints from the queue.
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

    /// Advances the checkpoint queue state machine.
    ///
    /// This method is called once per sidechain block, and will handle adding
    /// new checkpoints to the queue, advancing the `Building` checkpoint to
    /// `Signing`, and adjusting the checkpoint fee rates.
    ///
    /// If the `Building` checkpoint was advanced to `Signing` and a new
    /// `Building` checkpoint was created, this method will return `Ok(true)`.
    /// Otherwise, it will return `Ok(false)`.
    ///
    /// **Parameters:**
    ///
    /// - `sig_keys`: a map of consensus keys to their corresponding xpubs. This
    /// is used to determine which keys should be used in the signatory set,
    /// getting the set participation from the current validator set.
    /// - `nbtc_accounts`: a map of nBTC accounts to their corresponding
    /// balances. This is used along with to create outputs for the emergency
    /// disbursal transactions by getting the recovery script for each account
    /// from the `recovery_scripts` parameter.
    /// - `recovery_scripts`: a map of nBTC account addresses to their
    /// corresponding recovery scripts (account holders' desired destinations
    /// for the emergency disbursal).
    /// - `external_outputs`: an iterator of Bitcoin transaction outputs which
    /// should be included in the emergency disbursal transactions. This allows
    /// higher level modules the ability to create outputs for their own
    /// purposes.
    /// - `btc_height`: the current Bitcoin block height.
    /// - `should_allow_deposits`: whether or not deposits should be allowed in
    ///   any newly-created checkpoints.
    /// - `timestamping_commitment`: the data to be timestamped by the
    ///  checkpoint's timestamping commitment output (included as `OP_RETURN`
    ///  data in the checkpoint transaction to timestamp on the Bitcoin
    ///  blockchain for proof-of-work security).
    #[cfg(feature = "full")]
    #[allow(clippy::too_many_arguments)]
    pub fn maybe_step(
        &mut self,
        sig_keys: &Map<ConsensusKey, Xpub>,
        nbtc_accounts: &Accounts<Nbtc>,
        recovery_scripts: &Map<orga::coins::Address, Adapter<bitcoin::Script>>,
        external_outputs: impl Iterator<Item = Result<bitcoin::TxOut>>,
        btc_height: u32,
        should_allow_deposits: bool,
        timestamping_commitment: Vec<u8>,
    ) -> Result<bool> {
        if !self.should_push(sig_keys)? {
            return Ok(false);
        }

        if self.maybe_push(sig_keys, should_allow_deposits)?.is_none() {
            return Ok(false);
        }

        self.prune()?;

        if self.index > 0 {
            let config = self.config();
            let second = self.get_mut(self.index - 1)?;
            let sigset = second.sigset.clone();
            let prev_fee_rate = second.fee_rate;
            let (reserve_outpoint, reserve_value, excess_inputs, excess_outputs) =
                BuildingCheckpointMut(second).advance(
                    nbtc_accounts,
                    recovery_scripts,
                    external_outputs,
                    timestamping_commitment,
                    &config,
                )?;

            // Adjust the fee rate for the next checkpoint based on whether past
            // checkpoints have been confirmed in greater or less than the
            // target number of Bitcoin blocks.
            let fee_rate = if let Some(first_unconf_index) = self.first_unconfirmed_index()? {
                // There are unconfirmed checkpoints.

                let first_unconf = self.get(first_unconf_index)?;
                let btc_blocks_since_first =
                    btc_height - first_unconf.signed_at_btc_height.unwrap_or(0);
                let miners_excluded_cps =
                    btc_blocks_since_first >= config.target_checkpoint_inclusion;

                let last_unconf_index = self.last_completed_index()?;
                let last_unconf = self.get(last_unconf_index)?;
                let btc_blocks_since_last =
                    btc_height - last_unconf.signed_at_btc_height.unwrap_or(0);
                let block_was_mined = btc_blocks_since_last > 0;

                if miners_excluded_cps && block_was_mined {
                    // Blocks were mined since a signed checkpoint, but it was
                    // not included.
                    adjust_fee_rate(prev_fee_rate, true, &config)
                } else {
                    prev_fee_rate
                }
            } else {
                let has_completed = self.last_completed_index().is_ok();
                if has_completed {
                    // No unconfirmed checkpoints.
                    adjust_fee_rate(prev_fee_rate, false, &config)
                } else {
                    // This case only happens at start of chain - having no
                    // unconfs doesn't mean anything.
                    prev_fee_rate
                }
            };

            let mut building = self.building_mut()?;
            building.fee_rate = fee_rate;
            let mut building_checkpoint_batch = building
                .batches
                .get_mut(BatchType::Checkpoint as u64)?
                .unwrap();
            let mut checkpoint_tx = building_checkpoint_batch.get_mut(0)?.unwrap();

            // The new checkpoint tx's first input is the reserve output from
            // the previous checkpoint.
            let input = Input::new(
                reserve_outpoint,
                &sigset,
                &[0u8], // TODO: double-check safety
                reserve_value,
                config.sigset_threshold,
            )?;
            checkpoint_tx.input.push_back(input)?;

            // Add any excess inputs and outputs from the previous checkpoint to
            // the new checkpoint.
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

    /// Returns `true` if a new checkpoint will be pushed to the queue in the
    /// next call to `maybe_step`. Otherwise, returns `false`.
    ///
    /// Note that a new checkpoint being pushed also necessarily means that the
    /// `Building` checkpoint will be advanced to `Signing`.
    #[cfg(feature = "full")]
    pub fn should_push(&mut self, sig_keys: &Map<ConsensusKey, Xpub>) -> Result<bool> {
        // Do not push if there is a checkpoint in the `Signing` state. There
        // should only ever be at most one checkpoint in this state.
        if self.signing()?.is_some() {
            return Ok(false);
        }

        if !self.queue.is_empty() {
            let now = self
                .context::<Time>()
                .ok_or_else(|| OrgaError::App("No time context".to_string()))?
                .seconds as u64;
            let elapsed = now - self.building()?.create_time();

            // Do not push if the minimum checkpoint interval has not elapsed
            // since creating the current `Building` checkpoint.
            if elapsed < self.config.min_checkpoint_interval {
                return Ok(false);
            }

            // Don't push if there are no pending deposits, withdrawals, or
            // transfers, unless the maximum checkpoint interval has elapsed
            // since creating the current `Building` checkpoint.
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

        // Do not push if there are too many unconfirmed checkpoints.
        //
        // If there is a long chain of unconfirmed checkpoints, there is possibly an
        // issue causing the transactions to not be included on Bitcoin (e.g. an
        // invalid transaction was created, the fee rate is too low even after
        // adjustments, Bitcoin miners are censoring the transactions, etc.), in
        // which case the network should evaluate and fix the issue before creating
        // more checkpoints.
        //
        // This will also stop the fee rate from being adjusted too high if the
        // issue is simply with relayers failing to report the confirmation of the
        // checkpoint transactions.
        let unconfs = self.num_unconfirmed()?;
        if unconfs >= self.config.max_unconfirmed_checkpoints {
            return Ok(false);
        }

        // Increment the index. For the first checkpoint, leave the index at
        // zero.
        let mut index = self.index;
        if !self.queue.is_empty() {
            index += 1;
        }

        // Build the signatory set for the new checkpoint based on the current
        // validator set.
        let sigset = SignatorySet::from_validator_ctx(index, sig_keys)?;

        // Do not push if there are no validators in the signatory set.
        if sigset.possible_vp() == 0 {
            return Ok(false);
        }

        // Do not push if the signatory set does not have a quorum.
        if !sigset.has_quorum() {
            return Ok(false);
        }

        // Otherwise, push a new checkpoint.
        Ok(true)
    }

    /// Pushes a new checkpoint to the queue, if the conditions are met.
    ///
    /// Returns `Ok(None)` if no checkpoint was pushed, or `Ok(Some(cp))` if a
    /// checkpoint was pushed. The returned checkpoint is the new `Building`
    /// checkpoint.
    #[cfg(feature = "full")]
    pub fn maybe_push(
        &mut self,
        sig_keys: &Map<ConsensusKey, Xpub>,
        deposits_enabled: bool,
    ) -> Result<Option<BuildingCheckpointMut>> {
        // Increment the index. For the first checkpoint, leave the index at
        // zero.
        let mut index = self.index;
        if !self.queue.is_empty() {
            index += 1;
        }

        // Build the signatory set for the new checkpoint based on the current
        // validator set.
        let sigset = SignatorySet::from_validator_ctx(index, sig_keys)?;

        // Do not push if there are no validators in the signatory set.
        if sigset.possible_vp() == 0 {
            return Ok(None);
        }

        // Do not push if the signatory set does not have a quorum.
        if !sigset.has_quorum() {
            return Ok(None);
        }

        self.index = index;
        self.queue.push_back(Checkpoint::new(sigset)?)?;

        let mut building = self.building_mut()?;
        building.deposits_enabled = deposits_enabled;

        Ok(Some(building))
    }

    /// The active signatory set, which is the signatory set for the `Building`
    /// checkpoint.
    #[query]
    pub fn active_sigset(&self) -> Result<SignatorySet> {
        Ok(self.building()?.sigset.clone())
    }

    /// Process a batch of signatures, applying them to the checkpoint with the
    /// given index.
    ///
    /// Note that signatures can be sumitted to checkpoints which are already
    /// complete, causing them to be over-signed (which does not affect their
    /// validity). This is useful for letting all signers submit, regardless of
    /// whether they are faster or slower than the other signers. This is
    /// useful, for example, in being able to check if a signer is offline.
    ///
    /// If the batch of signatures causes the checkpoint to be fully signed, it
    /// will be advanced to the `Complete` state.
    ///
    /// This method is exempt from paying transaction fees since the amount of
    /// signatures that can be submitted is capped and this type of transaction
    /// cannot be used to DoS the network.
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

    /// The signatory set for the checkpoint with the given index.
    #[query]
    pub fn sigset(&self, index: u32) -> Result<SignatorySet> {
        Ok(self.get(index)?.sigset.clone())
    }

    /// The number of completed checkpoints which have not yet been confirmed on
    /// the Bitcoin network.
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

    /// The index of the first checkpoint which is not confirmed on the Bitcoin
    /// network, if there is one.
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

/// Takes a previous fee rate and returns a new fee rate, adjusted up or down by
/// 25%. The new fee rate is capped at the maximum and minimum fee rates
/// specified in the given config.
pub fn adjust_fee_rate(prev_fee_rate: u64, up: bool, config: &Config) -> u64 {
    if up {
        (prev_fee_rate * 5 / 4).max(prev_fee_rate + 1)
    } else {
        (prev_fee_rate * 3 / 4).min(prev_fee_rate - 1)
    }
    .min(config.max_fee_rate)
    .max(config.min_fee_rate)
}

#[cfg(test)]
mod test {
    #[cfg(feature = "full")]
    use crate::utils::set_time;

    use std::{cell::RefCell, rc::Rc};

    #[cfg(all(feature = "full"))]
    use bitcoin::{
        secp256k1::Secp256k1,
        util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey},
        OutPoint, PubkeyHash, Script, Txid,
    };
    use orga::{collections::EntryMap, context::Context};
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
                deposits_enabled: true,
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

    #[test]
    fn adjust_fee_rate() {
        let config = Config::default();
        assert_eq!(super::adjust_fee_rate(100, true, &config), 125);
        assert_eq!(super::adjust_fee_rate(100, false, &config), 75);
        assert_eq!(super::adjust_fee_rate(2, true, &config), 3);
        assert_eq!(super::adjust_fee_rate(0, true, &config), 2);
        assert_eq!(super::adjust_fee_rate(2, false, &config), 2);
        assert_eq!(super::adjust_fee_rate(200, true, &config), 200);
        assert_eq!(super::adjust_fee_rate(300, true, &config), 200);
    }

    #[cfg(feature = "full")]
    #[test]
    #[serial_test::serial]
    fn fee_adjustments() {
        // TODO: extract pieces into util functions, test more cases

        let paid = orga::plugins::Paid::default();
        Context::add(paid);

        let mut vals = orga::plugins::Validators::new(
            Rc::new(RefCell::new(Some(EntryMap::new()))),
            Rc::new(RefCell::new(None)),
        );
        vals.set_voting_power([0; 32], 100);
        Context::add(vals);

        let secp = Secp256k1::new();
        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Regtest, &[0]).unwrap();
        let xpub = ExtendedPubKey::from_priv(&secp, &xpriv);

        let mut sig_keys = Map::new();
        sig_keys.insert([0; 32], Xpub::new(xpub));

        let queue = Rc::new(RefCell::new(CheckpointQueue::default()));
        queue.borrow_mut().config = Config {
            min_fee_rate: 2,
            max_fee_rate: 200,
            target_checkpoint_inclusion: 2,
            min_checkpoint_interval: 100,
            ..Default::default()
        };

        let maybe_step = |btc_height| {
            queue
                .borrow_mut()
                .maybe_step(
                    &sig_keys,
                    &Accounts::default(),
                    &Map::new(),
                    vec![Ok(bitcoin::TxOut {
                        script_pubkey: Script::new(),
                        value: 1_000_000,
                    })]
                    .into_iter(),
                    btc_height,
                    true,
                    vec![1, 2, 3],
                )
                .unwrap();
        };
        let push_deposit = || {
            let mut input = Input::new(
                OutPoint {
                    txid: Txid::from_slice(&[0; 32]).unwrap(),
                    vout: 0,
                },
                &queue.borrow().building().unwrap().sigset,
                &[0u8],
                100_000_000,
                (9, 10),
            )
            .unwrap();
            let mut queue = queue.borrow_mut();
            let mut building_mut = queue.building_mut().unwrap();
            let mut building_checkpoint_batch = building_mut
                .batches
                .get_mut(BatchType::Checkpoint as u64)
                .unwrap()
                .unwrap();
            let mut checkpoint_tx = building_checkpoint_batch.get_mut(0).unwrap().unwrap();
            checkpoint_tx.input.push_back(input).unwrap();
        };
        let sign_batch = |btc_height| {
            let mut queue = queue.borrow_mut();
            let cp = queue.signing().unwrap().unwrap();
            let sigset_index = cp.sigset.index;
            let to_sign = cp.to_sign(Xpub::new(xpub.clone())).unwrap();
            let secp2 = Secp256k1::signing_only();
            let sigs = crate::bitcoin::signer::sign(&secp2, &xpriv, &to_sign).unwrap();
            drop(cp);
            queue
                .sign(Xpub::new(xpub), sigs, sigset_index, btc_height)
                .unwrap();
        };
        let sign_cp = |btc_height| {
            sign_batch(btc_height);
            sign_batch(btc_height);
            if queue.borrow().signing().unwrap().is_some() {
                sign_batch(btc_height);
            }
        };
        let confirm_cp = |index, btc_height| {
            let mut queue = queue.borrow_mut();
            queue.confirmed_index = Some(index);
        };

        assert_eq!(queue.borrow().len().unwrap(), 0);

        set_time(0);
        maybe_step(10);

        assert_eq!(queue.borrow().len().unwrap(), 1);
        assert_eq!(queue.borrow().building().unwrap().create_time(), 0);

        push_deposit();
        maybe_step(10);

        assert_eq!(queue.borrow().len().unwrap(), 1);
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 10);

        set_time(1_000);
        maybe_step(10);

        assert_eq!(queue.borrow().len().unwrap(), 2);
        assert!(queue.borrow().last_completed_index().is_err());
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 10);

        sign_cp(11);

        assert_eq!(queue.borrow().len().unwrap(), 2);
        assert_eq!(queue.borrow().last_completed_index().unwrap(), 0);
        assert_eq!(
            queue
                .borrow()
                .last_completed()
                .unwrap()
                .signed_at_btc_height
                .unwrap(),
            11
        );

        set_time(2_000);
        push_deposit();
        maybe_step(11);
        sign_cp(11);

        assert_eq!(queue.borrow().len().unwrap(), 3);
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 10);

        set_time(3_000);
        push_deposit();
        maybe_step(11);
        sign_cp(11);

        assert_eq!(queue.borrow().len().unwrap(), 4);
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 10);

        set_time(4_000);
        push_deposit();
        maybe_step(12);
        sign_cp(12);

        assert_eq!(queue.borrow().len().unwrap(), 5);
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 10);

        set_time(5_000);
        push_deposit();
        maybe_step(13);
        sign_cp(13);

        assert_eq!(queue.borrow().len().unwrap(), 6);
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 12);

        set_time(6_000);
        push_deposit();
        maybe_step(13);
        sign_cp(13);

        assert_eq!(queue.borrow().len().unwrap(), 7);
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 12);

        set_time(7_000);
        push_deposit();
        maybe_step(14);
        sign_cp(14);

        assert_eq!(queue.borrow().len().unwrap(), 8);
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 15);

        confirm_cp(5, 14);
        set_time(8_000);
        push_deposit();
        maybe_step(15);
        sign_cp(15);

        assert_eq!(queue.borrow().len().unwrap(), 9);
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 15);

        confirm_cp(7, 15);
        set_time(9_000);
        push_deposit();
        maybe_step(16);
        sign_cp(16);

        assert_eq!(queue.borrow().len().unwrap(), 10);
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 11);

        set_time(10_000);
        push_deposit();
        maybe_step(17);
        sign_cp(17);

        assert_eq!(queue.borrow().len().unwrap(), 11);
        assert_eq!(queue.borrow().building().unwrap().fee_rate, 11);
    }

    #[cfg(feature = "full")]
    #[test]
    #[serial_test::serial]
    fn max_unconfirmed_checkpoints() {
        // TODO: extract pieces into util functions, test more cases

        let paid = orga::plugins::Paid::default();
        Context::add(paid);

        let mut vals = orga::plugins::Validators::new(
            Rc::new(RefCell::new(Some(EntryMap::new()))),
            Rc::new(RefCell::new(None)),
        );
        vals.set_voting_power([0; 32], 100);
        Context::add(vals);

        let secp = Secp256k1::new();
        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Regtest, &[0]).unwrap();
        let xpub = ExtendedPubKey::from_priv(&secp, &xpriv);

        let mut sig_keys = Map::new();
        sig_keys.insert([0; 32], Xpub::new(xpub));

        let queue = Rc::new(RefCell::new(CheckpointQueue::default()));
        queue.borrow_mut().config = Config {
            min_fee_rate: 2,
            max_fee_rate: 200,
            target_checkpoint_inclusion: 2,
            min_checkpoint_interval: 100,
            max_unconfirmed_checkpoints: 2,
            ..Default::default()
        };

        let set_time = |time| {
            let time = orga::plugins::Time::from_seconds(time);
            Context::add(time);
        };
        let maybe_step = |btc_height| {
            queue
                .borrow_mut()
                .maybe_step(
                    &sig_keys,
                    &Accounts::default(),
                    &Map::new(),
                    vec![Ok(bitcoin::TxOut {
                        script_pubkey: Script::new(),
                        value: 1_000_000,
                    })]
                    .into_iter(),
                    btc_height,
                    true,
                    vec![1, 2, 3],
                )
                .unwrap();
        };
        let push_deposit = || {
            let mut input = Input::new(
                OutPoint {
                    txid: Txid::from_slice(&[0; 32]).unwrap(),
                    vout: 0,
                },
                &queue.borrow().building().unwrap().sigset,
                &[0u8],
                100_000_000,
                (9, 10),
            )
            .unwrap();
            let mut queue = queue.borrow_mut();
            let mut building_mut = queue.building_mut().unwrap();
            let mut building_checkpoint_batch = building_mut
                .batches
                .get_mut(BatchType::Checkpoint as u64)
                .unwrap()
                .unwrap();
            let mut checkpoint_tx = building_checkpoint_batch.get_mut(0).unwrap().unwrap();
            checkpoint_tx.input.push_back(input).unwrap();
        };
        let sign_batch = |btc_height| {
            let mut queue = queue.borrow_mut();
            let cp = queue.signing().unwrap().unwrap();
            let sigset_index = cp.sigset.index;
            let to_sign = cp.to_sign(Xpub::new(xpub.clone())).unwrap();
            let secp2 = Secp256k1::signing_only();
            let sigs = crate::bitcoin::signer::sign(&secp2, &xpriv, &to_sign).unwrap();
            drop(cp);
            queue
                .sign(Xpub::new(xpub), sigs, sigset_index, btc_height)
                .unwrap();
        };
        let sign_cp = |btc_height| {
            sign_batch(btc_height);
            sign_batch(btc_height);
            if queue.borrow().signing().unwrap().is_some() {
                sign_batch(btc_height);
            }
        };
        let confirm_cp = |index, btc_height| {
            let mut queue = queue.borrow_mut();
            queue.confirmed_index = Some(index);
        };

        assert_eq!(queue.borrow().len().unwrap(), 0);

        set_time(0);
        maybe_step(8);
        push_deposit();
        maybe_step(8);

        set_time(1_000);
        maybe_step(8);
        sign_cp(8);
        confirm_cp(0, 9);

        set_time(2_000);
        push_deposit();
        maybe_step(10);
        sign_cp(10);

        set_time(3_000);
        push_deposit();
        maybe_step(10);
        sign_cp(10);

        assert_eq!(queue.borrow().len().unwrap(), 4);

        set_time(4_000);
        push_deposit();
        maybe_step(10);

        assert_eq!(queue.borrow().len().unwrap(), 4);

        set_time(5_000);
        push_deposit();
        maybe_step(10);

        assert_eq!(queue.borrow().len().unwrap(), 4);

        confirm_cp(2, 11);
        set_time(6_000);
        maybe_step(11);

        assert_eq!(queue.borrow().len().unwrap(), 5);
    }
}
