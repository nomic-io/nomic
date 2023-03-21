use std::collections::HashMap;
use std::ops::Deref;

use crate::error::{Error, Result};
use ::bitcoin::util::bip32::ChildNumber;
use adapter::Adapter;
use bitcoin::hashes::Hash;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::Script;
use bitcoin::{util::merkleblock::PartialMerkleTree, Transaction};
use checkpoint::{CheckpointQueue, FEE_RATE};
use header_queue::HeaderQueue;
#[cfg(feature = "full")]
use orga::abci::BeginBlock;
use orga::call::Call;
use orga::coins::{Accounts, Address, Amount, Coin, Give, Symbol, Take};
use orga::collections::Map;
use orga::context::{Context, GetContext};
use orga::encoding::{Decode, Encode, Terminated};
use orga::migrate::MigrateFrom;
use orga::orga;
use orga::plugins::Paid;
#[cfg(feature = "full")]
use orga::plugins::{BeginBlockCtx, Validators};
use orga::plugins::{Signer, Time};
use orga::query::Query;
use orga::state::State;
use orga::store::Store;
use orga::{Error as OrgaError, Result as OrgaResult};
use signatory::SignatorySet;
use txid_set::OutpointSet;

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

#[derive(State, Debug, Clone, Encode, Decode, Default, MigrateFrom)]
pub struct Nbtc(());
impl Symbol for Nbtc {
    const INDEX: u8 = 21;
}

#[cfg(not(feature = "testnet"))]
pub const NETWORK: ::bitcoin::Network = ::bitcoin::Network::Bitcoin;
#[cfg(feature = "testnet")]
pub const NETWORK: ::bitcoin::Network = ::bitcoin::Network::Testnet;
pub const MIN_WITHDRAWAL_CHECKPOINTS: u32 = 4;
pub const MIN_DEPOSIT_AMOUNT: u64 = 600;
pub const MIN_WITHDRAWAL_AMOUNT: u64 = 600;
pub const MAX_WITHDRAWAL_SCRIPT_LENGTH: u64 = 64;
pub const TRANSFER_FEE: u64 = UNITS_PER_SAT;
pub const MIN_CONFIRMATIONS: u32 = 0;
pub const UNITS_PER_SAT: u64 = 1_000_000;

pub fn calc_deposit_fee(amount: u64) -> u64 {
    amount / 5
}

#[orga]
pub struct Bitcoin {
    #[call]
    pub headers: HeaderQueue,
    pub processed_outpoints: OutpointSet,
    #[call]
    pub checkpoints: CheckpointQueue,
    #[call]
    pub accounts: Accounts<Nbtc>,
    pub signatory_keys: SignatoryKeys,
    pub(crate) reward_pool: Coin<Nbtc>,
}

pub type ConsensusKey = [u8; 32];

#[derive(Call, Query, Clone, Debug, Client, PartialEq)]
pub struct Xpub(ExtendedPubKey);

impl MigrateFrom for Xpub {
    fn migrate_from(other: Self) -> OrgaResult<Self> {
        Ok(other)
    }
}

// impl Describe for Xpub {
//     fn describe() -> orga::describe::Descriptor {
//         orga::describe::Builder::new::<Self>().build()
//     }
// }

pub const XPUB_LENGTH: usize = 78;

impl Xpub {
    pub fn new(key: ExtendedPubKey) -> Self {
        Xpub(key)
    }

    pub fn inner(&self) -> &ExtendedPubKey {
        &self.0
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

impl From<&ExtendedPubKey> for Xpub {
    fn from(key: &ExtendedPubKey) -> Self {
        Xpub(*key)
    }
}

pub fn exempt_from_fee() -> Result<()> {
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

    pub fn relay_deposit(
        &mut self,
        btc_tx: Adapter<Transaction>,
        btc_height: u32,
        btc_proof: Adapter<PartialMerkleTree>,
        btc_vout: u32,
        sigset_index: u32,
        dest: &[u8],
    ) -> Result<Amount> {
        exempt_from_fee()?;

        let btc_header = self
            .headers
            .get_by_height(btc_height)?
            .ok_or_else(|| OrgaError::App("Invalid bitcoin block height".to_string()))?;

        // if self.headers.height()? - btc_height < MIN_CONFIRMATIONS {
        //     return Err(OrgaError::App("Block is not sufficiently confirmed".to_string()).into());
        // }

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

        // TODO: don't credit account until we're done signing including tx;

        let value = output
            .value
            .checked_sub(est_vsize * FEE_RATE)
            .ok_or_else(|| {
                OrgaError::App("Deposit amount is too small to pay its spending fee".to_string())
            })?
            * UNITS_PER_SAT;

        let mut minted_nbtc = Nbtc::mint(value);
        let deposit_fee = minted_nbtc.take(calc_deposit_fee(value))?;
        self.reward_pool.give(deposit_fee)?;

        Ok(minted_nbtc.amount)
    }

    pub fn withdraw(&mut self, script_pubkey: Adapter<Script>, amount: Amount) -> Result<()> {
        exempt_from_fee()?;

        if script_pubkey.len() as u64 > MAX_WITHDRAWAL_SCRIPT_LENGTH {
            return Err(OrgaError::App("Script exceeds maximum length".to_string()).into());
        }

        if self.checkpoints.len()? < MIN_WITHDRAWAL_CHECKPOINTS {
            return Err(OrgaError::App(format!(
                "Withdrawals are disabled until the network has produced at least {} checkpoints",
                MIN_WITHDRAWAL_CHECKPOINTS
            ))
            .into());
        }

        let signer = self
            .context::<Signer>()
            .ok_or_else(|| Error::Orga(OrgaError::App("No Signer context available".into())))?
            .signer
            .ok_or_else(|| Error::Orga(OrgaError::App("Call must be signed".into())))?;

        self.accounts.withdraw(signer, amount)?.burn();

        let fee = (9 + script_pubkey.len() as u64) * FEE_RATE;
        let value: u64 = Into::<u64>::into(amount) / UNITS_PER_SAT;
        let value = match value.checked_sub(fee) {
            None => {
                return Err(OrgaError::App(
                    "Withdrawal is too small to pay its miner fee".to_string(),
                )
                .into())
            }
            Some(value) => value,
        };

        if value < MIN_WITHDRAWAL_AMOUNT {
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
        checkpoint.outputs.push_back(Adapter::new(output))?;

        Ok(())
    }

    #[call]
    pub fn transfer(&mut self, to: Address, amount: Amount) -> Result<()> {
        exempt_from_fee()?;

        let signer = self
            .context::<Signer>()
            .ok_or_else(|| Error::Orga(OrgaError::App("No Signer context available".into())))?
            .signer
            .ok_or_else(|| Error::Orga(OrgaError::App("Call must be signed".into())))?;

        let transfer_fee = self.accounts.withdraw(signer, TRANSFER_FEE.into())?;
        self.reward_pool.give(transfer_fee)?;
        self.accounts.transfer(to, amount)?;

        Ok(())
    }

    #[query]
    pub fn value_locked(&self) -> Result<u64> {
        self.checkpoints.building()?.get_tvl()
    }

    pub fn network(&self) -> bitcoin::Network {
        self.headers.network()
    }

    #[query]
    pub fn change_rates(&self, interval: u64, now: u64) -> Result<ChangeRates> {
        let signing = self
            .checkpoints
            .signing()?
            .ok_or_else(|| OrgaError::App("No checkpoint to be signed".to_string()))?;
        if now > interval && now - interval > signing.create_time() {
            return Ok(ChangeRates::default());
        }
        let now = signing.create_time().max(now);

        let completed = self.checkpoints.completed()?;
        if completed.is_empty() {
            return Ok(ChangeRates::default());
        }
        let prev = completed
            .iter()
            .rev()
            .find(|c| (now - c.create_time()) > interval)
            .unwrap_or_else(|| completed.first().unwrap());

        let amount_now = signing.inputs.get(0)?.unwrap().amount;
        let amount_prev = prev.inputs.get(0)?.unwrap().amount;
        let decrease = if amount_now > amount_prev {
            0
        } else {
            amount_prev - amount_now
        };

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
        let prev_sigset = vp_shares(&prev.sigset)?;
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
            withdrawal: (decrease * 10_000 / amount_prev) as u16,
            sigset_change,
        })
    }
}

#[orga]
pub struct ChangeRates {
    pub withdrawal: u16,
    pub sigset_change: u16,
}

#[cfg(feature = "full")]
impl BeginBlock for Bitcoin {
    fn begin_block(&mut self, _ctx: &BeginBlockCtx) -> OrgaResult<()> {
        self.checkpoints
            .maybe_step(self.signatory_keys.map())
            .map_err(|err| OrgaError::App(err.to_string()))?;

        Ok(())
    }
}

#[orga]
pub struct SignatoryKeys {
    by_cons: Map<ConsensusKey, Xpub>,
    xpubs: Map<Xpub, ()>,
}

impl SignatoryKeys {
    pub fn reset(&mut self) -> OrgaResult<()> {
        let mut xpubs = vec![];
        for entry in self.by_cons.iter()? {
            let (_k, v) = entry?;
            xpubs.push(v.clone());
        }
        for xpub in xpubs {
            self.xpubs.remove(xpub)?;
        }

        clear_map(&mut self.by_cons)?;

        Ok(())
    }

    pub fn map(&self) -> &Map<ConsensusKey, Xpub> {
        &self.by_cons
    }

    pub fn insert(&mut self, consensus_key: ConsensusKey, xpub: Xpub) -> Result<()> {
        let mut normalized_xpub = xpub.clone();
        normalized_xpub.0.child_number = 0.into();
        normalized_xpub.0.depth = 0;
        normalized_xpub.0.parent_fingerprint = Default::default();

        if self.by_cons.contains_key(consensus_key)? {
            return Err(OrgaError::App("Validator already has a signatory key".to_string()).into());
        }

        if self.xpubs.contains_key(normalized_xpub.clone())? {
            return Err(OrgaError::App("Duplicate signatory key".to_string()).into());
        }

        self.by_cons.insert(consensus_key, xpub)?;
        self.xpubs.insert(normalized_xpub, ())?;

        Ok(())
    }

    #[query]
    pub fn get(&self, cons_key: ConsensusKey) -> Result<Option<Xpub>> {
        Ok(self.by_cons.get(cons_key)?.map(|x| x.clone()))
    }
}

use orga::collections::{Deque, Next};
fn clear_map<K, V>(map: &mut Map<K, V>) -> OrgaResult<()>
where
    K: Encode + Decode + Terminated + Next + Clone,
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

fn clear_deque<V>(deque: &mut Deque<V>) -> OrgaResult<()>
where
    V: State,
{
    while !deque.is_empty() {
        deque.pop_back()?;
    }

    Ok(())
}
