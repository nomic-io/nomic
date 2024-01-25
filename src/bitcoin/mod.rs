use std::collections::HashMap;
use std::ops::Deref;

use self::checkpoint::Input;
use self::threshold_sig::Signature;
use crate::app::Dest;
use crate::bitcoin::checkpoint::BatchType;
use crate::constants::{
    BTC_NATIVE_TOKEN_DENOM, MIN_DEPOSIT_AMOUNT, MIN_WITHDRAWAL_AMOUNT, TRANSFER_FEE,
};
use crate::error::{Error, Result};
use adapter::Adapter;
use bitcoin::hashes::Hash;
use bitcoin::util::bip32::ChildNumber;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::Script;
use bitcoin::{util::merkleblock::PartialMerkleTree, Transaction};
use checkpoint::CheckpointQueue;
use header_queue::HeaderQueue;
use orga::coins::{Accounts, Address, Amount, Coin, Give, Symbol};
use orga::collections::Map;
use orga::collections::{Deque, Next};
use orga::context::{Context, GetContext};
use orga::describe::Describe;
use orga::encoding::{Decode, Encode, LengthVec, Terminated};
use orga::migrate::{Migrate, MigrateFrom};
use orga::orga;
use orga::plugins::Paid;
#[cfg(feature = "full")]
use orga::plugins::Validators;
use orga::plugins::{Signer, Time};
use orga::prelude::FieldCall;
use orga::query::FieldQuery;
use orga::state::State;
use orga::store::Store;
use orga::{Error as OrgaError, Result as OrgaResult};
use outpoint_set::OutpointSet;
use serde::Serialize;
use signatory::SignatorySet;

pub mod adapter;
pub mod checkpoint;
#[cfg(feature = "full")]
pub mod deposit_index;
pub mod header_queue;
pub mod outpoint_set;
#[cfg(feature = "full")]
pub mod relayer;
pub mod signatory;
#[cfg(feature = "full")]
pub mod signer;
pub mod threshold_sig;

/// The symbol for nBTC, the network's native BTC token.
#[derive(State, Debug, Clone, Encode, Decode, Default, Migrate, Serialize)]
pub struct Nbtc(());
impl Symbol for Nbtc {
    const INDEX: u8 = 21;
    const NAME: &'static str = BTC_NATIVE_TOKEN_DENOM;
}

#[cfg(all(not(feature = "testnet"), not(feature = "devnet")))]
pub const NETWORK: ::bitcoin::Network = ::bitcoin::Network::Bitcoin;
#[cfg(all(feature = "testnet", not(feature = "devnet")))]
pub const NETWORK: ::bitcoin::Network = ::bitcoin::Network::Testnet;
#[cfg(all(feature = "devnet", feature = "testnet"))]
pub const NETWORK: ::bitcoin::Network = ::bitcoin::Network::Regtest;

// TODO: move to config
#[cfg(feature = "testnet")]
pub const SIGSET_THRESHOLD: (u64, u64) = (9, 10);
#[cfg(not(feature = "testnet"))]
pub const SIGSET_THRESHOLD: (u64, u64) = (2, 3);

/// The configuration parameters for the Bitcoin module.
#[orga(skip(Default), version = 5)]
pub struct Config {
    /// The minimum number of checkpoints that must be produced before
    /// withdrawals are enabled.
    pub min_withdrawal_checkpoints: u32,
    /// The minimum amount of BTC a deposit must send to be honored, in
    /// satoshis.
    pub min_deposit_amount: u64,
    /// The minimum amount of BTC a withdrawal must withdraw, in satoshis.
    pub min_withdrawal_amount: u64,
    /// TODO: remove this, not used
    pub max_withdrawal_amount: u64,
    /// The maximum length of a withdrawal output script, in bytes.
    pub max_withdrawal_script_length: u64,
    /// The fee charged for an nBTC transfer, in micro-satoshis.
    pub transfer_fee: u64,
    /// The minimum number of confirmations a Bitcoin block must have before it
    /// is considered finalized. Note that in the current implementation, the
    /// actual number of confirmations required is `min_confirmations + 1`.
    pub min_confirmations: u32,
    /// The number which amounts in satoshis are multiplied by to get the number
    /// of units held in nBTC accounts. In other words, the amount of
    /// subdivisions of satoshis which nBTC accounting uses.
    pub units_per_sat: u64,

    // (These fields were moved to `checkpoint::Config`)
    #[orga(version(V0, V1))]
    pub emergency_disbursal_min_tx_amt: u64,
    #[orga(version(V0, V1))]
    pub emergency_disbursal_lock_time_interval: u32,
    #[orga(version(V0, V1))]
    pub emergency_disbursal_max_tx_size: u64,

    /// If a signer does not submit signatures for this many consecutive
    /// checkpoints, they are considered offline and are removed from the
    /// signatory set (jailed) and slashed.
    #[orga(version(V1, V2, V3, V4, V5))]
    pub max_offline_checkpoints: u32,
    /// The minimum number of confirmations a checkpoint must have on the
    /// Bitcoin network before it is considered confirmed. Note that in the
    /// current implementation, the actual number of confirmations required is
    /// `min_checkpoint_confirmations + 1`.
    #[orga(version(V2, V3, V4, V5))]
    pub min_checkpoint_confirmations: u32,
    /// The maximum amount of BTC that can be held in the network, in satoshis.
    #[orga(version(V2, V3, V4, V5))]
    pub capacity_limit: u64,
}

impl MigrateFrom<ConfigV0> for ConfigV1 {
    fn migrate_from(value: ConfigV0) -> OrgaResult<Self> {
        Ok(Self {
            min_withdrawal_checkpoints: value.min_withdrawal_checkpoints,
            min_deposit_amount: value.min_deposit_amount,
            min_withdrawal_amount: value.min_withdrawal_amount,
            max_withdrawal_amount: value.max_withdrawal_amount,
            max_withdrawal_script_length: value.max_withdrawal_script_length,
            transfer_fee: value.transfer_fee,
            min_confirmations: value.min_confirmations,
            units_per_sat: value.units_per_sat,
            emergency_disbursal_min_tx_amt: value.emergency_disbursal_min_tx_amt,
            emergency_disbursal_lock_time_interval: value.emergency_disbursal_lock_time_interval,
            emergency_disbursal_max_tx_size: value.emergency_disbursal_max_tx_size,
            max_offline_checkpoints: Config::default().max_offline_checkpoints,
        })
    }
}

impl MigrateFrom<ConfigV1> for ConfigV2 {
    fn migrate_from(value: ConfigV1) -> OrgaResult<Self> {
        Ok(Self {
            min_withdrawal_checkpoints: value.min_withdrawal_checkpoints,
            min_deposit_amount: value.min_deposit_amount,
            min_withdrawal_amount: value.min_withdrawal_amount,
            max_withdrawal_amount: value.max_withdrawal_amount,
            max_withdrawal_script_length: value.max_withdrawal_script_length,
            transfer_fee: value.transfer_fee,
            min_confirmations: value.min_confirmations,
            units_per_sat: value.units_per_sat,
            max_offline_checkpoints: value.max_offline_checkpoints,
            min_checkpoint_confirmations: Config::default().min_checkpoint_confirmations,
            capacity_limit: Config::bitcoin().capacity_limit,
        })
    }
}

impl MigrateFrom<ConfigV2> for ConfigV3 {
    fn migrate_from(value: ConfigV2) -> OrgaResult<Self> {
        // Migrating to set min_checkpoint_confirmations to 0 and testnet
        // capacity limit to 100 BTC
        Ok(Self {
            min_withdrawal_checkpoints: value.min_withdrawal_checkpoints,
            min_deposit_amount: value.min_deposit_amount,
            min_withdrawal_amount: value.min_withdrawal_amount,
            max_withdrawal_amount: value.max_withdrawal_amount,
            max_withdrawal_script_length: value.max_withdrawal_script_length,
            transfer_fee: value.transfer_fee,
            min_confirmations: value.min_confirmations,
            units_per_sat: value.units_per_sat,
            max_offline_checkpoints: value.max_offline_checkpoints,
            min_checkpoint_confirmations: 0,
            capacity_limit: Config::bitcoin().capacity_limit,
        })
    }
}

impl MigrateFrom<ConfigV3> for ConfigV4 {
    fn migrate_from(value: ConfigV3) -> OrgaResult<Self> {
        // Migrating to set min_checkpoint_confirmations to 0 and testnet
        // capacity limit to 100 BTC
        Ok(Self {
            min_withdrawal_checkpoints: value.min_withdrawal_checkpoints,
            min_deposit_amount: value.min_deposit_amount,
            min_withdrawal_amount: value.min_withdrawal_amount,
            max_withdrawal_amount: value.max_withdrawal_amount,
            max_withdrawal_script_length: value.max_withdrawal_script_length,
            transfer_fee: value.transfer_fee,
            min_confirmations: value.min_confirmations,
            units_per_sat: value.units_per_sat,
            max_offline_checkpoints: value.max_offline_checkpoints,
            min_checkpoint_confirmations: 0,
            capacity_limit: Config::default().capacity_limit,
        })
    }
}

impl MigrateFrom<ConfigV4> for ConfigV5 {
    fn migrate_from(value: ConfigV4) -> OrgaResult<Self> {
        // Migrating to set min_checkpoint_confirmations to 0 and testnet
        // capacity limit to 100 BTC
        Ok(Self {
            min_withdrawal_checkpoints: value.min_withdrawal_checkpoints,
            min_deposit_amount: Config::default().min_deposit_amount,
            min_withdrawal_amount: Config::default().min_withdrawal_amount,
            max_withdrawal_amount: value.max_withdrawal_amount,
            max_withdrawal_script_length: value.max_withdrawal_script_length,
            transfer_fee: Config::default().transfer_fee,
            min_confirmations: value.min_confirmations,
            units_per_sat: value.units_per_sat,
            max_offline_checkpoints: value.max_offline_checkpoints,
            min_checkpoint_confirmations: value.min_checkpoint_confirmations,
            capacity_limit: value.capacity_limit,
        })
    }
}

impl Config {
    fn bitcoin() -> Self {
        Self {
            min_withdrawal_checkpoints: 4,
            min_deposit_amount: MIN_DEPOSIT_AMOUNT,
            min_withdrawal_amount: MIN_WITHDRAWAL_AMOUNT,
            max_withdrawal_amount: 64,
            max_withdrawal_script_length: 64,
            transfer_fee: TRANSFER_FEE,
            #[cfg(feature = "testnet")]
            min_confirmations: 0,
            #[cfg(not(feature = "testnet"))]
            min_confirmations: 1,
            units_per_sat: 1_000_000,
            max_offline_checkpoints: 20,
            min_checkpoint_confirmations: 0,
            #[cfg(feature = "testnet")]
            capacity_limit: 100 * 100_000_000, // 100 BTC
            #[cfg(not(feature = "testnet"))]
            capacity_limit: 19 * 100_000_000, // 19 BTC
        }
    }

    fn regtest() -> Self {
        Self {
            min_withdrawal_checkpoints: 1,
            max_offline_checkpoints: 1,
            ..Self::bitcoin()
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        match NETWORK {
            bitcoin::Network::Regtest => Config::regtest(),
            bitcoin::Network::Testnet | bitcoin::Network::Bitcoin => Config::bitcoin(),
            _ => unimplemented!(),
        }
    }
}

/// Calculates the bridge fee for a deposit of the given amount of BTC, in
/// satoshis.
pub fn calc_deposit_fee(amount: u64) -> u64 {
    amount / 100
}

/// The main structure where Bitcoin bridge state is held.
///
/// This structure is the main entry point for interacting with the Bitcoin
/// bridge. It contains all of the state necessary to keep track of the Bitcoin
/// blockchain headers, relay deposit transactions, maintain nBTC accounts, and
/// coordinate the checkpointing process to manage the BTC reserve on the
/// Bitcoin blockchain.
#[orga(version = 1)]
pub struct Bitcoin {
    /// A light client of the Bitcoin blockchain, keeping track of the headers
    /// of the highest-work chain.
    #[call]
    pub headers: HeaderQueue,

    /// The set of outpoints which have been relayed to the bridge. This is used
    /// to prevent replay attacks of deposits.
    pub processed_outpoints: OutpointSet,

    /// The checkpoint queue, which manages the checkpointing process,
    /// periodically moving the reserve of BTC on the Bitcoin blockchain to
    /// collect incoming deposits, move the funds to the latest signatory set,
    /// and pay out requested withdrawals.
    #[call]
    pub checkpoints: CheckpointQueue,

    /// The map of nBTC accounts, which hold the nBTC balances of users.
    pub accounts: Accounts<Nbtc>,

    /// The public keys declared by signatories, which are used to sign Bitcoin
    /// transactions.
    // TODO: store recovery script data in account struct
    pub signatory_keys: SignatoryKeys,

    /// A pool of BTC where bridge fees are collected.
    pub(crate) reward_pool: Coin<Nbtc>,

    /// The recovery scripts for nBTC account holders, which are users' desired
    /// destinations for BTC to be paid out to in the emergency disbursal
    /// process if the network is halted.
    pub recovery_scripts: Map<Address, Adapter<Script>>,

    /// The configuration parameters for the Bitcoin module.
    pub config: Config,
}

impl MigrateFrom<BitcoinV0> for BitcoinV1 {
    fn migrate_from(_value: BitcoinV0) -> OrgaResult<Self> {
        unreachable!()
    }
}

/// A Tendermint/CometBFT public key.
pub type ConsensusKey = [u8; 32];

/// A Bitcoin extended public key, used to derive Bitcoin public keys which
/// signatories sign transactions with.
// #[derive(Call, Query, Clone, Debug, Client, PartialEq, Serialize)]
#[derive(Debug, PartialEq, Serialize, FieldCall, FieldQuery, Clone, Copy)]
pub struct Xpub {
    key: ExtendedPubKey,
}

impl Migrate for Xpub {}

impl Describe for Xpub {
    fn describe() -> orga::describe::Descriptor {
        orga::describe::Builder::new::<Self>().build()
    }
}

pub const XPUB_LENGTH: usize = 78;

impl Xpub {
    /// Creates a new `Xpub` from an `ExtendedPubKey`.
    pub fn new(key: ExtendedPubKey) -> Self {
        Xpub { key }
    }

    /// Gets the `ExtendedPubKey` from the `Xpub`.
    pub fn inner(&self) -> &ExtendedPubKey {
        &self.key
    }
}

impl State for Xpub {
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

impl Deref for Xpub {
    type Target = ExtendedPubKey;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl Encode for Xpub {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        let bytes = self.key.encode();
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
        Ok(Xpub { key })
    }
}

impl Terminated for Xpub {}

impl From<ExtendedPubKey> for Xpub {
    fn from(key: ExtendedPubKey) -> Self {
        Xpub { key }
    }
}

impl From<&ExtendedPubKey> for Xpub {
    fn from(key: &ExtendedPubKey) -> Self {
        Xpub { key: *key }
    }
}

/// Exempts a call from having to pay the transaction fee, by funding the fee
/// plugin with minted coins.
pub fn exempt_from_fee() -> Result<()> {
    let paid = Context::resolve::<Paid>()
        .ok_or_else(|| OrgaError::Coins("No Paid context found".into()))?;

    paid.give::<crate::app::Nom, _>(orga::plugins::MIN_FEE)?;

    Ok(())
}

#[orga]
impl Bitcoin {
    /// Sets the configuration parameters to the given values.
    pub fn configure(&mut self, config: Config) {
        self.config = config;
    }

    /// Gets the configuration parameters.
    pub fn config() -> Config {
        Config::default()
    }

    /// Called by validators to store their signatory public key, which will be
    /// used for their signing of Bitcoin transactions.
    ///
    /// Currently, validators may only set their signatory key once - key
    /// rotation is not yet supported.
    ///
    /// This call must be signed by an operator key associated with an account
    /// which has declared a validator.
    #[call]
    pub fn set_signatory_key(&mut self, _signatory_key: Xpub) -> Result<()> {
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
            let regtest_mode = self.network() == bitcoin::Network::Regtest
                && _signatory_key.network == bitcoin::Network::Testnet;

            println!("network: {:?}", self.network());
            println!("signatory key network: {:?}", _signatory_key.network);

            if !regtest_mode && _signatory_key.network != self.network() {
                return Err(Error::Orga(orga::Error::App(
                    "Signatory key network does not match network".to_string(),
                )));
            }

            self.signatory_keys.insert(consensus_key, _signatory_key)?;
        }

        Ok(())
    }

    /// Called by users to set their recovery script, which is their desired
    /// destination paid out to in the emergency disbursal process if the the
    /// account has sufficient balance.
    #[call]
    pub fn set_recovery_script(&mut self, signatory_script: Adapter<Script>) -> Result<()> {
        #[cfg(feature = "full")]
        {
            if signatory_script.len() as u64 > self.config.max_withdrawal_script_length {
                return Err(Error::Orga(orga::Error::App(
                    "Script exceeds maximum length".to_string(),
                )));
            }

            let signer = self
                .context::<Signer>()
                .ok_or_else(|| Error::Orga(OrgaError::App("No Signer context available".into())))?
                .signer
                .ok_or_else(|| Error::Orga(OrgaError::App("Call must be signed".into())))?;

            self.recovery_scripts.insert(signer, signatory_script)?;
        }

        Ok(())
    }

    /// Returns `true` if the next call to `self.checkpoints.maybe_step()` will
    /// push a new checkpoint (along with advancing the current `Building`
    /// checkpoint to `Signing`). Returns `false` otherwise.
    #[cfg(feature = "full")]
    pub fn should_push_checkpoint(&mut self) -> Result<bool> {
        self.checkpoints.should_push(self.signatory_keys.map())
    }

    /// Verifies and processes a deposit of BTC into the reserve.
    ///
    /// This will check that the Bitcoin transaction has been sufficiently
    /// confirmed on the Bitcoin blockchain, then will add the deposit to the
    /// current `Building` checkpoint to be spent as an input. The deposit's
    /// committed destination will be credited once the checkpoint is fully
    /// signed.
    pub fn relay_deposit(
        &mut self,
        btc_tx: Adapter<Transaction>,
        btc_height: u32,
        btc_proof: Adapter<PartialMerkleTree>,
        btc_vout: u32,
        sigset_index: u32,
        dest: super::app::Dest,
    ) -> Result<()> {
        exempt_from_fee()?;

        let now = self
            .context::<Time>()
            .ok_or_else(|| Error::Orga(OrgaError::App("No time context available".to_string())))?
            .seconds as u64;

        let btc_header = self
            .headers
            .get_by_height(btc_height)?
            .ok_or_else(|| OrgaError::App("Invalid bitcoin block height".to_string()))?;

        if self.headers.height()? - btc_height < self.config.min_confirmations {
            return Err(OrgaError::App("Block is not sufficiently confirmed".to_string()).into());
        }

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

        if output.value < self.config.min_deposit_amount {
            return Err(OrgaError::App(
                "Deposit amount is below minimum".to_string(),
            ))?;
        }

        let checkpoint = self.checkpoints.get(sigset_index)?;
        let sigset = checkpoint.sigset.clone();

        if now > sigset.deposit_timeout() {
            return Err(OrgaError::App("Deposit timeout has expired".to_string()))?;
        }

        let dest_bytes = dest.commitment_bytes()?;
        let expected_script =
            sigset.output_script(&dest_bytes, self.checkpoints.config.sigset_threshold)?;
        if output.script_pubkey != expected_script {
            return Err(OrgaError::App(
                "Output script does not match signature set".to_string(),
            ))?;
        }

        let prevout = bitcoin::OutPoint {
            txid: btc_tx.txid(),
            vout: btc_vout,
        };
        let input = Input::new(
            prevout,
            &sigset,
            &dest_bytes,
            output.value,
            self.checkpoints.config.sigset_threshold,
        )?;
        let input_size = input.est_vsize();

        let fee = input_size * checkpoint.fee_rate;
        let value = output.value.checked_sub(fee).ok_or_else(|| {
            OrgaError::App("Deposit amount is too small to pay its spending fee".to_string())
        })? * self.config.units_per_sat;
        log::info!(
            "Relay deposit with output value: {}, input size: {}, checkpoint fee rate: {}",
            output.value,
            input_size,
            checkpoint.fee_rate
        );

        println!(
            "Relay deposit with output value: {}, input size: {}, checkpoint fee rate: {}",
            output.value, input_size, checkpoint.fee_rate
        );

        let outpoint = (btc_tx.txid().into_inner(), btc_vout);
        if self.processed_outpoints.contains(outpoint)? {
            return Err(OrgaError::App(
                "Output has already been relayed".to_string(),
            ))?;
        }
        self.processed_outpoints
            .insert(outpoint, sigset.deposit_timeout())?;

        let mut building_mut = self.checkpoints.building_mut()?;
        if !building_mut.deposits_enabled {
            return Err(OrgaError::App(
                "Deposits are disabled for the given checkpoint".to_string(),
            ))?;
        }
        let mut building_checkpoint_batch = building_mut
            .batches
            .get_mut(BatchType::Checkpoint as u64)?
            .unwrap();
        let mut checkpoint_tx = building_checkpoint_batch.get_mut(0)?.unwrap();
        checkpoint_tx.input.push_back(input)?;

        let minted_nbtc = Nbtc::mint(value);
        // let deposit_fee = minted_nbtc.take(calc_deposit_fee(value))?;
        // self.reward_pool.give(deposit_fee)?;

        self.checkpoints
            .building_mut()?
            .insert_pending(dest, minted_nbtc)?;

        Ok(())
    }

    /// Records proof that a checkpoint produced by the network has been
    /// confirmed into a Bitcoin block.
    #[call]
    pub fn relay_checkpoint(
        &mut self,
        btc_height: u32,
        btc_proof: Adapter<PartialMerkleTree>,
        cp_index: u32,
    ) -> Result<()> {
        exempt_from_fee()?;

        if let Some(conf_index) = self.checkpoints.confirmed_index {
            if cp_index <= conf_index {
                return Err(OrgaError::App(
                    "Checkpoint has already been relayed".to_string(),
                ))?;
            }
        }

        let btc_header = self
            .headers
            .get_by_height(btc_height)?
            .ok_or_else(|| OrgaError::App("Invalid bitcoin block height".to_string()))?;

        if self.headers.height()? - btc_height < self.config.min_checkpoint_confirmations {
            return Err(OrgaError::App("Block is not sufficiently confirmed".to_string()).into());
        }

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

        let btc_tx = self.checkpoints.get(cp_index)?.checkpoint_tx()?;
        if txids[0] != btc_tx.txid() {
            return Err(OrgaError::App(
                "Bitcoin merkle proof does not match transaction".to_string(),
            ))?;
        }

        self.checkpoints.confirmed_index = Some(cp_index);
        log::info!(
            "Checkpoint {} confirmed at Bitcoin height {}",
            cp_index,
            btc_height
        );

        Ok(())
    }

    /// Initiates a withdrawal, adding an output to the current `Building`
    /// checkpoint to be paid out once the checkpoint is fully signed.
    pub fn withdraw(&mut self, script_pubkey: Adapter<Script>, amount: Amount) -> Result<()> {
        exempt_from_fee()?;

        let signer = self
            .context::<Signer>()
            .ok_or_else(|| Error::Orga(OrgaError::App("No Signer context available".into())))?
            .signer
            .ok_or_else(|| Error::Orga(OrgaError::App("Call must be signed".into())))?;

        self.accounts.withdraw(signer, amount)?.burn();

        self.add_withdrawal(script_pubkey, amount)
    }

    /// Adds an output to the current `Building` checkpoint to be paid out once
    /// the checkpoint is fully signed.
    pub fn add_withdrawal(&mut self, script_pubkey: Adapter<Script>, amount: Amount) -> Result<()> {
        if script_pubkey.len() as u64 > self.config.max_withdrawal_script_length {
            return Err(OrgaError::App("Script exceeds maximum length".to_string()).into());
        }

        if self.checkpoints.len()? < self.config.min_withdrawal_checkpoints {
            return Err(OrgaError::App(format!(
                "Withdrawals are disabled until the network has produced at least {} checkpoints",
                self.config.min_withdrawal_checkpoints
            ))
            .into());
        }

        let fee = (9 + script_pubkey.len() as u64) * self.checkpoints.building()?.fee_rate;
        let value: u64 = Into::<u64>::into(amount) / self.config.units_per_sat;
        let value = match value.checked_sub(fee) {
            None => {
                return Err(OrgaError::App(
                    "Withdrawal is too small to pay its miner fee".to_string(),
                )
                .into())
            }
            Some(value) => value,
        };

        if bitcoin::Amount::from_sat(value) <= script_pubkey.dust_value() {
            return Err(OrgaError::App(
                "Withdrawal is too small to pay its dust limit".to_string(),
            )
            .into());
        }

        if value < self.config.min_withdrawal_amount {
            return Err(OrgaError::App(
                "Withdrawal is smaller than than minimum amount".to_string(),
            )
            .into());
        }

        let output = bitcoin::TxOut {
            script_pubkey: script_pubkey.into_inner(),
            value,
        };

        let mut checkpoint = self.checkpoints.building_mut()?;
        let mut building_checkpoint_batch = checkpoint
            .batches
            .get_mut(BatchType::Checkpoint as u64)?
            .unwrap();
        let mut checkpoint_tx = building_checkpoint_batch.get_mut(0)?.unwrap();
        checkpoint_tx.output.push_back(Adapter::new(output))?;

        Ok(())
    }

    /// Transfers nBTC to another account.
    #[call]
    pub fn transfer(&mut self, to: Address, amount: Amount) -> Result<()> {
        exempt_from_fee()?;

        let signer = self
            .context::<Signer>()
            .ok_or_else(|| Error::Orga(OrgaError::App("No Signer context available".into())))?
            .signer
            .ok_or_else(|| Error::Orga(OrgaError::App("Call must be signed".into())))?;

        let transfer_fee = self
            .accounts
            .withdraw(signer, self.config.transfer_fee.into())?;
        self.reward_pool.give(transfer_fee)?;

        let dest = Dest::Address(to);
        let coins = self.accounts.withdraw(signer, amount)?;
        self.checkpoints
            .building_mut()?
            .insert_pending(dest, coins)?;

        Ok(())
    }

    /// Called by signatories to submit their signatures for the current
    /// `Signing` checkpoint.
    #[call]
    pub fn sign(
        &mut self,
        xpub: Xpub,
        sigs: LengthVec<u16, Signature>,
        cp_index: u32,
    ) -> Result<()> {
        self.checkpoints
            .sign(xpub, sigs, cp_index, self.headers.height()?)
    }

    /// The amount of BTC in the reserve output of the most recent fully-signed
    /// checkpoint.
    #[query]
    pub fn value_locked(&self) -> Result<u64> {
        let last_completed = self.checkpoints.last_completed()?;
        Ok(last_completed.reserve_output()?.unwrap().value)
    }

    /// The network (e.g. Bitcoin testnet vs mainnet) which is currently
    /// configured.
    pub fn network(&self) -> bitcoin::Network {
        self.headers.network()
    }

    /// Gets the rate of change of the reserve output and signatory set over the
    /// given interval, in basis points (1/100th of a percent).
    ///
    /// This is used by signers to implement a "circuit breaker" mechanism,
    /// temporarily halting signing if funds are leaving the reserve too quickly
    /// or if the signatory set is changing too quickly.
    #[query]
    pub fn change_rates(&self, interval: u64, now: u64, reset_index: u32) -> Result<ChangeRates> {
        let signing = self
            .checkpoints
            .signing()?
            .ok_or_else(|| OrgaError::App("No checkpoint to be signed".to_string()))?;

        if now > interval && now - interval > signing.create_time()
            || reset_index >= signing.sigset.index
        {
            return Ok(ChangeRates::default());
        }
        let now = signing.create_time().max(now);

        let completed = self
            .checkpoints
            .completed((interval / self.checkpoints.config.min_checkpoint_interval) as u32 + 1)?;
        if completed.is_empty() {
            return Ok(ChangeRates::default());
        }

        let prev_index = completed
            .iter()
            .rposition(|c| (now - c.create_time()) > interval || c.sigset.index <= reset_index)
            .unwrap_or(0);

        let prev_checkpoint = completed.get(prev_index).unwrap();

        let amount_prev = prev_checkpoint.reserve_output()?.unwrap().value;
        let amount_now = signing.reserve_output()?.unwrap().value;

        let reserve_decrease = amount_prev.saturating_sub(amount_now);

        let vp_shares = |sigset: &SignatorySet| -> Result<_> {
            let secp = bitcoin::secp256k1::Secp256k1::verification_only();
            let sigset_index = sigset.index();
            let total_vp = sigset.present_vp() as f64;
            let sigset_fractions: HashMap<_, _> = sigset
                .iter()
                .map(|v| (v.pubkey.as_slice(), v.voting_power as f64 / total_vp))
                .collect();
            let mut sigset: HashMap<_, _> = Default::default();
            for entry in self.signatory_keys.map().iter()? {
                let (_, xpub) = entry?;
                let derive_path = [ChildNumber::from_normal_idx(sigset_index)?];
                let pubkey: threshold_sig::Pubkey =
                    xpub.derive_pub(&secp, &derive_path)?.public_key.into();
                sigset.insert(
                    xpub.inner().encode(),
                    *sigset_fractions.get(pubkey.as_slice()).unwrap_or(&0.0),
                );
            }

            Ok(sigset)
        };

        let now_sigset = vp_shares(&signing.sigset)?;
        let prev_sigset = vp_shares(&prev_checkpoint.sigset)?;
        let sigset_change = now_sigset.iter().fold(0.0, |acc, (k, v)| {
            let prev_share = prev_sigset.get(k).unwrap_or(&0.0);
            if v > prev_share {
                acc + (v - prev_share)
            } else {
                acc
            }
        });
        let sigset_change = (sigset_change * 10_000.0) as u16;

        Ok(ChangeRates {
            withdrawal: (reserve_decrease * 10_000 / amount_prev) as u16,
            sigset_change,
        })
    }

    /// Called once per sidechain block to advance the checkpointing process.
    #[cfg(feature = "full")]
    pub fn begin_block_step(
        &mut self,
        external_outputs: impl Iterator<Item = Result<bitcoin::TxOut>>,
        timestamping_commitment: Vec<u8>,
    ) -> Result<Vec<ConsensusKey>> {
        let has_completed_cp = if let Err(Error::Orga(OrgaError::App(err))) =
            self.checkpoints.last_completed_index()
        {
            if err == "No completed checkpoints yet" {
                false
            } else {
                return Err(Error::Orga(OrgaError::App(err)));
            }
        } else {
            true
        };

        let reached_capacity_limit = if has_completed_cp {
            self.value_locked()? >= self.config.capacity_limit
        } else {
            false
        };

        let pushed = self
            .checkpoints
            .maybe_step(
                self.signatory_keys.map(),
                &self.accounts,
                &self.recovery_scripts,
                external_outputs,
                self.headers.height()?,
                !reached_capacity_limit,
                timestamping_commitment,
            )
            .map_err(|err| OrgaError::App(err.to_string()))?;

        // TODO: remove expired outpoints from processed_outpoints

        if pushed {
            self.offline_signers()
        } else {
            Ok(vec![])
        }
    }

    /// Returns the consensus keys of signers who have not submitted signatures
    /// for the last `max_offline_checkpoints` checkpoints.
    ///
    /// This should be used to punish offline signers, by e.g. removing them
    /// from the validator set and slashing their stake.
    #[cfg(feature = "full")]
    fn offline_signers(&mut self) -> Result<Vec<ConsensusKey>> {
        use orga::plugins::ValidatorEntry;

        let mut validators = self
            .context::<Validators>()
            .ok_or_else(|| OrgaError::App("No validator context found".to_string()))?
            .entries()?;
        validators.sort_by(|a, b| b.power.cmp(&a.power));

        let offline_threshold = self.config.max_offline_checkpoints;
        let sigset = self.checkpoints.active_sigset()?;
        let lowest_power = sigset.signatories.last().unwrap().voting_power;
        let completed = self.checkpoints.completed(offline_threshold)?;
        if completed.len() < offline_threshold as usize {
            return Ok(vec![]);
        }
        let mut offline_signers = vec![];
        for ValidatorEntry {
            power,
            pubkey: cons_key,
        } in validators
        {
            if power < lowest_power {
                break;
            }

            let xpub = if let Some(xpub) = self.signatory_keys.get(cons_key)? {
                xpub
            } else {
                continue;
            };

            let mut offline = true;
            for checkpoint in completed.iter().rev() {
                if checkpoint.to_sign(xpub)?.is_empty() {
                    offline = false;
                    break;
                }
            }

            if offline {
                offline_signers.push(cons_key);
            }
        }

        Ok(offline_signers)
    }

    /// Takes the pending nBTC transfers from the most recent fully-signed
    /// checkpoint, leaving the vector empty after calling.
    ///
    /// This should be used to process the pending transfers, crediting each of
    /// them now that the checkpoint has been fully signed.
    pub fn take_pending(&mut self) -> Result<Vec<(Dest, Coin<Nbtc>)>> {
        if let Err(Error::Orga(OrgaError::App(err))) = self.checkpoints.last_completed_index() {
            if err == "No completed checkpoints yet" {
                return Ok(vec![]);
            }
        }

        // TODO: drain iter
        let pending = &mut self.checkpoints.last_completed_mut()?.pending;
        let keys = pending
            .iter()?
            .map(|entry| entry.map(|(dest, _)| dest.clone()).map_err(Error::from))
            .collect::<Result<Vec<Dest>>>()?;
        let mut dests = vec![];
        for dest in keys {
            let coins = pending.remove(dest.clone())?.unwrap().into_inner();
            dests.push((dest, coins));
        }
        Ok(dests)
    }
}

/// The current rates of change of the reserve output and signatory set, in
/// basis points (1/100th of a percent).
#[orga]
#[derive(Debug, Clone)]
pub struct ChangeRates {
    pub withdrawal: u16,
    pub sigset_change: u16,
}

/// A collection storing the signatory extended public keys of each validator
/// who has submitted one.
///
/// The collection also includes an set of all signatory extended public keys,
/// which is used to prevent duplicate keys from being submitted.
#[orga]
pub struct SignatoryKeys {
    by_cons: Map<ConsensusKey, Xpub>,
    xpubs: Map<Xpub, ()>,
}

#[orga]
impl SignatoryKeys {
    /// Clears the collection.
    pub fn reset(&mut self) -> OrgaResult<()> {
        let mut xpubs = vec![];
        for entry in self.by_cons.iter()? {
            let (_k, v) = entry?;
            xpubs.push(v);
        }
        for xpub in xpubs {
            self.xpubs.remove(*xpub)?;
        }

        clear_map(&mut self.by_cons)?;

        Ok(())
    }

    /// Returns the map of consensus keys to signatory extended public keys.
    pub fn map(&self) -> &Map<ConsensusKey, Xpub> {
        &self.by_cons
    }

    /// Adds a signatory extended public key to the collection, associated with
    /// the given consensus key.
    pub fn insert(&mut self, consensus_key: ConsensusKey, xpub: Xpub) -> Result<()> {
        let mut normalized_xpub = xpub;
        normalized_xpub.key.child_number = 0.into();
        normalized_xpub.key.depth = 0;
        normalized_xpub.key.parent_fingerprint = Default::default();

        if self.by_cons.contains_key(consensus_key)? {
            return Err(OrgaError::App("Validator already has a signatory key".to_string()).into());
        }

        if self.xpubs.contains_key(normalized_xpub)? {
            return Err(OrgaError::App("Duplicate signatory key".to_string()).into());
        }

        self.by_cons.insert(consensus_key, xpub)?;
        self.xpubs.insert(normalized_xpub, ())?;

        Ok(())
    }

    /// Returns the signatory extended public key associated with the given
    /// consensus key, if one exists.
    #[query]
    pub fn get(&self, cons_key: ConsensusKey) -> Result<Option<Xpub>> {
        Ok(self.by_cons.get(cons_key)?.map(|x| *x))
    }
}

/// Iterates through the given map and removes all entries.
fn clear_map<K, V>(map: &mut Map<K, V>) -> OrgaResult<()>
where
    K: Encode + Decode + Terminated + Next + Clone + Send + Sync + 'static,
    V: State,
{
    let mut keys = vec![];
    for entry in map.iter()? {
        let (k, _v) = entry?;
        keys.push(k.clone());
    }

    for key in keys {
        map.remove(key)?;
    }

    Ok(())
}

/// Iterates through the given deque and removes all entries.
fn clear_deque<V>(deque: &mut Deque<V>) -> OrgaResult<()>
where
    V: State,
{
    while !deque.is_empty() {
        deque.pop_back()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use bitcoin::{
        secp256k1::Secp256k1, util::bip32::ExtendedPrivKey, BlockHash, BlockHeader, OutPoint,
        TxMerkleNode, Txid,
    };
    use orga::collections::EntryMap;

    use super::{
        header_queue::{WorkHeader, WrappedHeader},
        *,
    };

    #[serial_test::serial]
    #[test]
    fn relay_height_validity() {
        Context::add(Paid::default());
        Context::add(Time::from_seconds(0));

        let mut btc = Bitcoin::default();

        for _ in 0..10 {
            btc.headers
                .deque
                .push_back(WorkHeader::new(
                    WrappedHeader::new(
                        Adapter::new(BlockHeader {
                            bits: 0,
                            merkle_root: TxMerkleNode::all_zeros(),
                            nonce: 0,
                            prev_blockhash: BlockHash::all_zeros(),
                            time: 0,
                            version: 0,
                        }),
                        btc.headers.height().unwrap() + 1,
                    ),
                    bitcoin::util::uint::Uint256([0, 0, 0, 0]),
                ))
                .unwrap();
        }

        let h = btc.headers.height().unwrap();
        let mut try_relay = |height| {
            // TODO: make test cases not fail at irrelevant steps in relay_deposit
            // (either by passing in valid input, or by handling other error paths)
            btc.relay_deposit(
                Adapter::new(Transaction {
                    input: vec![],
                    lock_time: bitcoin::PackedLockTime(0),
                    output: vec![],
                    version: 0,
                }),
                height,
                Adapter::new(PartialMerkleTree::from_txids(&[Txid::all_zeros()], &[true])),
                0,
                0,
                Dest::Address(Address::NULL),
            )
        };

        assert_eq!(
            try_relay(h + 100).unwrap_err().to_string(),
            "App Error: Invalid bitcoin block height",
        );
        assert_eq!(
            try_relay(h - 100).unwrap_err().to_string(),
            "Passed index is greater than initial height. Referenced header does not exist on the Header Queue",
        );

        Context::remove::<Paid>();
    }

    #[test]
    #[serial_test::serial]
    fn check_change_rates() -> Result<()> {
        // use checkpoint::*;
        let paid = orga::plugins::Paid::default();
        Context::add(paid);

        let mut vals = orga::plugins::Validators::new(
            Rc::new(RefCell::new(Some(EntryMap::new()))),
            Rc::new(RefCell::new(Some(Map::new()))),
        );
        let addr = vec![Address::from_pubkey([0; 33]), Address::from_pubkey([1; 33])];
        vals.set_voting_power([0; 32], 100);
        vals.set_operator([0; 32], addr[0])?;
        vals.set_voting_power([1; 32], 10);
        vals.set_operator([1; 32], addr[1])?;
        Context::add(vals);

        let set_signer = |addr| {
            Context::add(Signer { signer: Some(addr) });
        };
        let set_time = |time| {
            let time = orga::plugins::Time::from_seconds(time);
            Context::add(time);
        };

        let btc = Rc::new(RefCell::new(Bitcoin::default()));
        let secp = Secp256k1::new();
        let network = btc.borrow().network();
        let xpriv = vec![
            ExtendedPrivKey::new_master(network, &[0]).unwrap(),
            ExtendedPrivKey::new_master(network, &[1]).unwrap(),
        ];
        let xpub = vec![
            ExtendedPubKey::from_priv(&secp, &xpriv[0]),
            ExtendedPubKey::from_priv(&secp, &xpriv[1]),
        ];

        let push_deposit = || {
            let input = Input::new(
                OutPoint {
                    txid: Txid::from_slice(&[0; 32]).unwrap(),
                    vout: 0,
                },
                &btc.borrow().checkpoints.building().unwrap().sigset,
                &[0u8],
                100_000_000,
                (9, 10),
            )
            .unwrap();
            let mut btc = btc.borrow_mut();
            let mut building_mut = btc.checkpoints.building_mut().unwrap();
            let mut building_checkpoint_batch = building_mut
                .batches
                .get_mut(BatchType::Checkpoint as u64)
                .unwrap()
                .unwrap();
            let mut checkpoint_tx = building_checkpoint_batch.get_mut(0).unwrap().unwrap();
            checkpoint_tx.input.push_back(input).unwrap();
        };

        let push_withdrawal = || {
            let mut btc = btc.borrow_mut();

            btc.add_withdrawal(Adapter::new(Script::new()), 459_459_927_000_000.into())
                .unwrap();
        };

        let sign_batch = |btc_height| {
            let mut btc = btc.borrow_mut();
            let queue = &mut btc.checkpoints;
            let cp = queue.signing().unwrap().unwrap();
            let sigset_index = cp.sigset.index;
            for i in 0..2 {
                if queue.signing().unwrap().is_none() {
                    break;
                }
                let cp = queue.signing().unwrap().unwrap();
                let to_sign = cp.to_sign(Xpub::new(xpub[i])).unwrap();
                let secp2 = Secp256k1::signing_only();
                let sigs = crate::bitcoin::signer::sign(&secp2, &xpriv[i], &to_sign).unwrap();
                queue
                    .sign(Xpub::new(xpub[i]), sigs, sigset_index, btc_height)
                    .unwrap();
            }
        };
        let sign_cp = |btc_height| {
            sign_batch(btc_height);
            sign_batch(btc_height);
            if btc.borrow().checkpoints.signing().unwrap().is_some() {
                sign_batch(btc_height);
            }
        };
        let maybe_step = || {
            let mut btc = btc.borrow_mut();

            btc.begin_block_step(vec![].into_iter(), vec![1, 2, 3])
                .unwrap();
        };

        set_time(0);
        for i in 0..2 {
            set_signer(addr[i]);
            btc.borrow_mut().set_signatory_key(Xpub::new(xpub[i]))?;
        }

        assert_eq!(btc.borrow().checkpoints.len()?, 0);
        maybe_step();
        assert_eq!(btc.borrow().checkpoints.len()?, 1);

        set_time(1000);
        push_deposit();
        maybe_step();
        sign_cp(10);

        assert_eq!(btc.borrow().checkpoints.len()?, 2);

        set_time(2000);
        push_deposit();
        maybe_step();
        let change_rates = btc.borrow().change_rates(2000, 2100, 0)?;
        assert_eq!(change_rates.withdrawal, 0);
        assert_eq!(change_rates.sigset_change, 0);
        sign_cp(10);

        assert_eq!(btc.borrow().checkpoints.len()?, 3);

        // Change the sigset
        let vals = Context::resolve::<Validators>().unwrap();
        vals.set_voting_power([1; 32], 100);

        set_time(3000);
        push_deposit();
        maybe_step();
        let change_rates = btc.borrow().change_rates(3000, 3100, 0)?;
        assert_eq!(change_rates.withdrawal, 0);
        assert_eq!(change_rates.sigset_change, 0);
        sign_cp(10);

        assert_eq!(btc.borrow().checkpoints.len()?, 4);

        set_time(4000);
        push_deposit();
        maybe_step();
        let change_rates = btc.borrow().change_rates(3000, 4100, 0)?;
        assert_eq!(change_rates.withdrawal, 0);
        assert_eq!(change_rates.sigset_change, 4090);
        assert_eq!(btc.borrow().checkpoints.len()?, 5);

        sign_cp(10);

        set_time(5000);
        push_deposit();
        maybe_step();
        let change_rates = btc.borrow().change_rates(3000, 5100, 0)?;
        assert_eq!(change_rates.withdrawal, 0);
        assert_eq!(change_rates.sigset_change, 4090);
        assert_eq!(btc.borrow().checkpoints.len()?, 6);
        sign_cp(10);

        set_time(6000);
        push_withdrawal();
        maybe_step();
        let change_rates = btc.borrow().change_rates(3000, 5100, 0)?;
        assert_eq!(change_rates.withdrawal, 8649);
        assert_eq!(change_rates.sigset_change, 4090);
        assert_eq!(btc.borrow().checkpoints.signing()?.unwrap().sigset.index, 5);
        let change_rates = btc.borrow().change_rates(3000, 5100, 5)?;
        assert_eq!(change_rates.withdrawal, 0);
        assert_eq!(change_rates.sigset_change, 0);

        Ok(())
    }
}
