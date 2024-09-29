use bitcoin::{
    hashes::Hash,
    psbt::Prevouts,
    secp256k1::{schnorr, PublicKey, Secp256k1},
    util::{
        merkleblock::PartialMerkleTree,
        sighash::SighashCache,
        taproot::{TapLeafHash, TapSighashHash, TaprootBuilder, TaprootSpendInfo},
    },
    OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use bitcoin_script::bitcoin_script as script;
use ed::{Decode, Encode};
use orga::{
    coins::{Coin, Symbol, Take},
    collections::{Deque, Map},
    encoding::LengthVec,
    macros::Migrate,
    orga,
    state::State,
};
use serde::Serialize;

use crate::{
    app::{Dest, Identity},
    bitcoin::{
        checkpoint::{BatchType, BitcoinTx, Input},
        header_queue::HeaderQueue,
        Adapter, Bitcoin, Nbtc, SIGSET_THRESHOLD,
    },
    error::{Error, Result},
    frost::Frost,
};

use crate::bitcoin::threshold_sig::Signature;

#[cfg(feature = "full")]
pub mod proto;
#[cfg(feature = "full")]
pub mod relayer;

/// The symbol for staked nBTC.
#[derive(State, Debug, Clone, Encode, Decode, Default, Migrate, Serialize)]
pub struct StakedNbtc(());
impl Symbol for StakedNbtc {
    const INDEX: u8 = 22;
    const NAME: &'static str = "stusat";
}

#[orga]
pub struct Babylon {
    pub delegations: Map<Identity, Deque<Delegation>>,
    pub staked: DelegationQueue,
    pub unbonding: DelegationQueue,
    pub params: Params,
}

pub type DelegationQueue = Map<(u32, Identity, u64), ()>;

#[orga]
impl Babylon {
    pub fn step(&mut self, frost: &mut Frost, btc: &mut Bitcoin) -> Result<()> {
        type QueueHandler = fn(&mut Delegation, &mut Frost, &mut Bitcoin, &Params) -> Result<()>;
        let mut process_queue = |queue: &mut DelegationQueue,
                                 condition: fn(u32, u32, &Params) -> bool,
                                 handler: QueueHandler| {
            let mut remove_keys = vec![];
            let mut iter = queue.iter()?;
            loop {
                let Some(entry) = iter.next() else {
                    break;
                };

                let key = entry?.0;
                let (height, owner, index) = *key;
                if !condition(btc.headers.height()?, height, &self.params) {
                    break;
                }

                let mut owner_dels = self.delegations.get_mut(owner)?.ok_or_else(|| {
                    Error::Orga(orga::Error::App("Delegation not found".to_string()))
                })?;
                let mut del = owner_dels.get_mut(index)?.ok_or_else(|| {
                    Error::Orga(orga::Error::App("Delegation not found".to_string()))
                })?;
                handler(&mut del, frost, btc, &self.params)?;
                remove_keys.push(*key);
            }

            for key in remove_keys {
                queue.remove(key)?;
            }

            Ok::<_, crate::error::Error>(())
        };

        // Process unbonding queue (once timelock has passed, withdraw from unbonding
        // transaction)
        process_queue(
            &mut self.unbonding,
            |btc_height, maturity_height, _| btc_height >= maturity_height,
            |del, _, btc, params| del.withdraw(btc, params),
        )?;

        // Process staked queue (once delegations are older than `max_age`, start
        // unbonding)
        process_queue(
            &mut self.staked,
            |btc_height, staking_height, params| btc_height >= staking_height + params.max_age,
            |del, frost, btc, params| del.unbond(frost, btc, params),
        )?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn stake(
        &mut self,
        btc: &mut crate::bitcoin::Bitcoin,
        frost: &mut crate::frost::Frost,
        owner: Identity,
        return_dest: Dest,
        finality_provider: [u8; 32],
        staking_time: u16,
        nbtc: Coin<Nbtc>,
    ) -> Result<u64> {
        let Some(frost_index) = frost.most_recent_with_key()? else {
            return Err(Error::Orga(orga::Error::App(
                "Frost not initialized".to_string(),
            )));
        };
        let group_pubkey = frost.group_pubkey(frost_index)?.unwrap();
        let index = self.delegations.get(owner)?.unwrap_or_default().len();

        let batch_index = btc
            .checkpoints
            .building()?
            .batches
            .get(BatchType::Checkpoint as u64)?
            .unwrap()
            .len();

        let del = Delegation::new(
            index,
            owner,
            return_dest,
            PublicKey::from_slice(&group_pubkey.inner.verifying_key().serialize())?.into(),
            frost_index,
            vec![XOnlyPublicKey::from_slice(&finality_provider)?],
            staking_time,
            (btc.checkpoints.index, batch_index),
            nbtc,
            &self.params,
        )?;

        // Push staking tx to checkpoint.
        let mut staking_tx = BitcoinTx::default();
        staking_tx
            .output
            .push_back(Adapter::new(del.staking_output(&self.params)?))?;
        staking_tx
            .output
            .push_back(Adapter::new(del.op_return_output()?))?;
        btc.checkpoints
            .building_mut()?
            .batches
            .get_mut(BatchType::Checkpoint as u64)?
            .unwrap()
            .push_back(staking_tx)?;

        self.delegations
            .entry(owner)?
            .or_insert_default()?
            .push_back(del)?;

        Ok(index)
    }

    pub fn unstake(
        &mut self,
        owner: Identity,
        index: u64,
        frost: &mut Frost,
        btc: &Bitcoin,
    ) -> Result<()> {
        self.delegations
            .get_mut(owner)?
            .ok_or_else(|| Error::Orga(orga::Error::App("Delegation not found".to_string())))?
            .get_mut(index)?
            .ok_or_else(|| Error::Orga(orga::Error::App("Delegation not found".to_string())))?
            .request_unbond(frost, btc, &self.params)
    }
}

pub fn multisig_script(pks: &[XOnlyPublicKey], threshold: u32, verify: bool) -> Result<Script> {
    if pks.is_empty() {
        return Err(Error::Orga(orga::Error::App(
            "No keys provided".to_string(),
        )));
    }

    if threshold > pks.len() as u32 {
        return Err(Error::Orga(orga::Error::App(
            "Required number of valid signers is greater than number of provided keys".to_string(),
        )));
    }

    if pks.len() == 1 {
        return Ok(single_key_script(pks[0], verify));
    }

    let pks = sort_keys(pks)?;

    let mut bytes = vec![];
    for (i, pk) in pks.iter().enumerate() {
        let pk = pk.serialize().to_vec();
        bytes.extend(
            if i == 0 {
                // TODO: put this allow in the bitcoin_script crate
                #[allow(clippy::redundant_closure_call)]
                {
                    script! { <pk> OP_CHECKSIG }
                }
            } else {
                // TODO: put this allow in the bitcoin_script crate
                #[allow(clippy::redundant_closure_call)]
                {
                    script! { <pk> OP_CHECKSIGADD }
                }
            }
            .into_bytes(),
        );
    }
    // TODO: put this allow in the bitcoin_script crate
    #[allow(clippy::redundant_closure_call)]
    {
        bytes.extend(script! { <threshold as i64> }.into_bytes());
    }
    if verify {
        // TODO: put this allow in the bitcoin_script crate
        #[allow(clippy::redundant_closure_call)]
        {
            bytes.extend(script! { OP_NUMEQUALVERIFY }.into_bytes());
        }
    } else {
        // TODO: put this allow in the bitcoin_script crate
        #[allow(clippy::redundant_closure_call)]
        {
            bytes.extend(script! { OP_NUMEQUAL }.into_bytes());
        }
    }

    Ok(bytes.into())
}

pub fn sort_keys(pks: &[XOnlyPublicKey]) -> Result<Vec<XOnlyPublicKey>> {
    if pks.len() < 2 {
        return Err(Error::Orga(orga::Error::App(
            "Cannot sort less than two keys".to_string(),
        )));
    }

    let mut pks = pks.to_vec();
    pks.sort_by_key(|pk| pk.serialize());

    for i in 0..pks.len() - 1 {
        if pks[i] == pks[i + 1] {
            return Err(Error::Orga(orga::Error::App(
                "Duplicate key in list of keys".to_string(),
            )));
        }
    }

    Ok(pks)
}

pub fn single_key_script(pk: XOnlyPublicKey, verify: bool) -> Script {
    let pk = pk.serialize().to_vec();
    if verify {
        // TODO: put this allow in the bitcoin_script crate
        #[allow(clippy::redundant_closure_call)]
        {
            script! { <pk> OP_CHECKSIGVERIFY }
        }
    } else {
        // TODO: put this allow in the bitcoin_script crate
        #[allow(clippy::redundant_closure_call)]
        {
            script! { <pk> OP_CHECKSIG }
        }
    }
}

pub fn timelock_script(pk: XOnlyPublicKey, timelock: u64) -> Script {
    let mut bytes = single_key_script(pk, true).into_bytes();
    // TODO: put this allow in the bitcoin_script crate
    #[allow(clippy::redundant_closure_call)]
    bytes.extend(script! { <timelock as i64> OP_CSV }.into_bytes());
    bytes.into()
}

pub fn aggregate_scripts(scripts: &[Script]) -> Script {
    let mut bytes = vec![];
    for script in scripts.iter() {
        bytes.extend(script.clone().into_bytes());
    }
    bytes.into()
}

#[orga(skip(Default))]
#[derive(Debug, Clone)]
pub struct Params {
    pub covenant_keys: LengthVec<u8, [u8; 32]>,
    pub covenant_quorum: u32,
    pub slashing_script: Adapter<Script>,
    pub slashing_min_fee: u64,
    pub op_return_tag: [u8; 4],
    pub slashing_rate: (u32, u32),
    pub max_age: u32,
    pub min_staking_time: u16,
    pub max_staking_time: u16,
    pub unbonding_time: u16,
    pub min_staking_amount: u64,
    pub max_staking_amount: u64,
    pub unbonding_fee: u64,
    pub confirmation_depth: u32,
}

impl Params {
    pub fn bbn_test_3() -> Self {
        let covenant_keys = [
            "ffeaec52a9b407b355ef6967a7ffc15fd6c3fe07de2844d61550475e7a5233e5",
            "a5c60c2188e833d39d0fa798ab3f69aa12ed3dd2f3bad659effa252782de3c31",
            "59d3532148a597a2d05c0395bf5f7176044b1cd312f37701a9b4d0aad70bc5a4",
            "57349e985e742d5131e1e2b227b5170f6350ac2e2feb72254fcc25b3cee21a18",
            "c8ccb03c379e452f10c81232b41a1ca8b63d0baf8387e57d302c987e5abb8527",
        ];
        let covenant_quorum = 3;

        let slashing_addr = "tb1qv03wm7hxhag6awldvwacy0z42edtt6kwljrhd9";
        let slashing_min_fee = 1_000;

        Self {
            covenant_keys: covenant_keys
                .iter()
                .map(|k| {
                    let mut key = [0; 32];
                    let v = hex::decode(k).unwrap();
                    key.copy_from_slice(&v);
                    key
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            covenant_quorum,
            slashing_script: slashing_addr
                .parse::<bitcoin::Address>()
                .unwrap()
                .script_pubkey()
                .into(),
            slashing_min_fee,
            op_return_tag: *b"bbb3",
            slashing_rate: (11, 100),
            max_age: 1_008,
            min_staking_time: u16::MAX,
            max_staking_time: 1,
            unbonding_time: 5,
            min_staking_amount: 50_000,
            max_staking_amount: 5_000_000,
            unbonding_fee: 1_000,
            confirmation_depth: 10,
        }
    }

    pub fn bbn_test_4() -> Self {
        let covenant_keys = [
            "a10a06bb3bae360db3aef0326413b55b9e46bf20b9a96fc8a806a99e644fe277",
            "6f13a6d104446520d1757caec13eaf6fbcf29f488c31e0107e7351d4994cd068",
            "a5e21514682b87e37fb5d3c9862055041d1e6f4cc4f3034ceaf3d90f86b230a6",
        ];
        let covenant_quorum = 2;

        let slashing_addr = "tb1qv03wm7hxhag6awldvwacy0z42edtt6kwljrhd9";
        let slashing_min_fee = 2_000;

        Self {
            covenant_keys: covenant_keys
                .iter()
                .map(|k| {
                    let mut key = [0; 32];
                    let v = hex::decode(k).unwrap();
                    key.copy_from_slice(&v);
                    key
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            covenant_quorum,
            slashing_script: slashing_addr
                .parse::<bitcoin::Address>()
                .unwrap()
                .script_pubkey()
                .into(),
            slashing_min_fee,
            op_return_tag: *b"bbb4",
            slashing_rate: (11, 100),
            max_age: 1_008,
            min_staking_time: 64_000,
            max_staking_time: 64_000,
            unbonding_time: 1_008,
            min_staking_amount: 50_000,
            max_staking_amount: 5_000_000,
            unbonding_fee: 10_000,
            confirmation_depth: 10,
        }
    }

    pub fn covenant_keys(&self) -> Vec<XOnlyPublicKey> {
        self.covenant_keys
            .iter()
            .map(|k| XOnlyPublicKey::from_slice(k).unwrap())
            .collect()
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::bbn_test_4()
    }
}

pub fn unbonding_script(staker_key: XOnlyPublicKey, params: &Params) -> Result<Script> {
    Ok(aggregate_scripts(&[
        single_key_script(staker_key, true),
        multisig_script(&params.covenant_keys(), params.covenant_quorum, false)?,
    ]))
}

pub fn slashing_script(
    staker_key: XOnlyPublicKey,
    fp_keys: &[XOnlyPublicKey],
    params: &Params,
) -> Result<Script> {
    Ok(aggregate_scripts(&[
        single_key_script(staker_key, true),
        multisig_script(fp_keys, 1, true)?,
        multisig_script(&params.covenant_keys(), params.covenant_quorum, false)?,
    ]))
}

const UNSPENDABLE_KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub fn staking_taproot(
    staker_key: XOnlyPublicKey,
    fp_keys: &[XOnlyPublicKey],
    staking_time: u16,
    params: &Params,
) -> Result<TaprootSpendInfo> {
    let timelock_script = timelock_script(staker_key, staking_time as u64);
    let unbonding_script = unbonding_script(staker_key, params)?;
    let slashing_script = slashing_script(staker_key, fp_keys, params)?;

    let internal_key = UNSPENDABLE_KEY.parse()?;
    TaprootBuilder::new()
        .add_leaf(2, timelock_script)?
        .add_leaf(2, unbonding_script)?
        .add_leaf(1, slashing_script)?
        .finalize(&Secp256k1::new(), internal_key)
        .map_err(|_| Error::Orga(orga::Error::App("Failed to finalize taproot".to_string())))
}

pub fn slashing_tx(
    staker_key: XOnlyPublicKey,
    stake_out: OutPoint,
    stake_value: u64,
    params: &Params,
) -> Result<Transaction> {
    let staking_in = TxIn {
        previous_output: stake_out,
        script_sig: Script::new(),
        sequence: Sequence(u32::MAX),
        witness: Witness::default(),
    };

    let slashing_rate = params.slashing_rate;
    let slashing_value =
        (stake_value as u128 * slashing_rate.0 as u128 / slashing_rate.1 as u128) as u64;
    let slashing_out = TxOut {
        value: slashing_value,
        script_pubkey: (*params.slashing_script).clone(),
    };

    let change_key = TaprootBuilder::new()
        .add_leaf(0, timelock_script(staker_key, params.unbonding_time as u64))?
        .finalize(&Secp256k1::new(), UNSPENDABLE_KEY.parse().unwrap())
        .unwrap()
        .output_key();
    let change_out = TxOut {
        value: stake_value - slashing_value - params.slashing_min_fee,
        script_pubkey: Script::new_v1_p2tr_tweaked(change_key),
    };

    Ok(Transaction {
        version: 2,
        lock_time: bitcoin::PackedLockTime(0),
        input: vec![staking_in],
        output: vec![slashing_out, change_out],
    })
}

pub fn unbonding_taproot(
    staker_key: XOnlyPublicKey,
    fp_keys: &[XOnlyPublicKey],
    params: &Params,
) -> Result<TaprootSpendInfo> {
    let timelock_script = timelock_script(staker_key, params.unbonding_time as u64);
    let slashing_script = slashing_script(staker_key, fp_keys, params)?;

    let internal_key = UNSPENDABLE_KEY.parse()?;
    TaprootBuilder::new()
        .add_leaf(1, timelock_script)?
        .add_leaf(1, slashing_script)?
        .finalize(&Secp256k1::new(), internal_key)
        .map_err(|_| Error::Orga(orga::Error::App("Failed to finalize taproot".to_string())))
}

pub fn unbonding_tx(
    staker_key: XOnlyPublicKey,
    fp_keys: &[XOnlyPublicKey],
    staking_outpoint: OutPoint,
    staking_value: u64,
    params: &Params,
) -> Result<Transaction> {
    let staking_in = TxIn {
        previous_output: staking_outpoint,
        script_sig: Script::new(),
        sequence: Sequence(u32::MAX),
        witness: Witness::default(),
    };

    let script_pubkey =
        Script::new_v1_p2tr_tweaked(unbonding_taproot(staker_key, fp_keys, params)?.output_key());
    let out = TxOut {
        value: staking_value - params.unbonding_fee,
        script_pubkey,
    };

    Ok(Transaction {
        version: 2,
        lock_time: bitcoin::PackedLockTime(0),
        input: vec![staking_in],
        output: vec![out],
    })
}

pub type XOnlyPubkey = [u8; 32];

fn bytes_to_pubkey(bytes: XOnlyPubkey) -> Result<XOnlyPublicKey> {
    Ok(XOnlyPublicKey::from_slice(&bytes)?)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DelegationStatus {
    Created,
    Staked,
    SigningUnbond,
    SignedUnbond,
    ConfirmedUnbond,
    Withdrawn,
}

#[orga]
#[derive(Debug)]
pub struct Delegation {
    pub index: u64,
    pub owner: Identity,
    pub return_dest: Dest,
    pub btc_key: XOnlyPubkey,
    pub frost_group: u64,
    pub fp_keys: LengthVec<u8, XOnlyPubkey>,
    pub staking_period: u16,
    pub unbonding_period: u16,
    pub checkpoint_batch_index: (u32, u64),
    pub stake: Coin<Nbtc>,

    pub staking_outpoint: Option<crate::bitcoin::adapter::Adapter<OutPoint>>,
    pub staking_height: Option<u32>,

    // TODO: handle different types of spends (timelock vs unbonding vs slashed)
    pub requested_unbond: bool,
    pub withdrawal_sigset_index: Option<u32>,
    pub withdrawal_script_pubkey: Option<crate::bitcoin::adapter::Adapter<Script>>,
    pub frost_sig_offset: Option<u64>,
    pub(crate) staking_unbonding_sig: Option<Signature>,
    pub(crate) unbonding_withdrawal_sig: Option<Signature>,

    pub unbonding_height: Option<u32>,

    pub withdraw_checkpoint_index: Option<u32>,
}

#[orga]
impl Delegation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        index: u64,
        owner: Identity,
        return_dest: Dest,
        btc_key: XOnlyPublicKey,
        frost_group: u64,
        fp_keys: Vec<XOnlyPublicKey>,
        staking_period: u16,
        checkpoint_batch_index: (u32, u64),
        stake: Coin<Nbtc>,
        params: &Params,
    ) -> Result<Self> {
        if staking_period < params.min_staking_time || staking_period > params.max_staking_time {
            return Err(Error::Orga(orga::Error::App(
                "Staking period out of bounds".to_string(),
            )));
        }

        Ok(Self {
            index,
            owner,
            return_dest,
            btc_key: btc_key.serialize(),
            frost_group,
            fp_keys: fp_keys
                .iter()
                .map(|k| k.serialize())
                .collect::<Vec<_>>()
                .try_into()?,
            staking_period,
            unbonding_period: params.unbonding_time,
            checkpoint_batch_index,
            stake,
            ..Default::default()
        })
    }

    // TODO: remove conversion methods once orga can transparently convert

    fn btc_key(&self) -> Result<XOnlyPublicKey> {
        bytes_to_pubkey(self.btc_key)
    }

    fn fp_keys(&self) -> Result<Vec<XOnlyPublicKey>> {
        self.fp_keys.iter().cloned().map(bytes_to_pubkey).collect()
    }

    pub fn stake_sats(&self) -> u64 {
        let stake_amount: u64 = self.stake.amount.into();
        stake_amount / 1_000_000 // TODO: get conversion from bitcoin config
    }

    #[allow(clippy::too_many_arguments)]
    pub fn relay_staking_tx(
        &mut self,
        headers: &HeaderQueue,
        height: u32,
        proof: PartialMerkleTree,
        tx: Transaction,
        vout: u32,
        params: &Params,
        stake_queue: &mut DelegationQueue,
        frost: &mut Frost,
        btc: &Bitcoin,
    ) -> Result<()> {
        if self.status() != DelegationStatus::Created {
            return Err(Error::Orga(orga::Error::App(
                "Staking tx already relayed".to_string(),
            )));
        }

        if headers.height()?.saturating_sub(height) < params.confirmation_depth {
            return Err(Error::Orga(orga::Error::App(
                "Staking tx is not confirmed".to_string(),
            )));
        }

        // TODO: dedupe this with other proof verification calls
        let header = headers
            .get_by_height(height)?
            .ok_or_else(|| Error::Orga(orga::Error::App("Header not found".to_string())))?;
        let mut txids = vec![];
        let mut block_indexes = vec![];
        let proof_merkle_root = proof
            .extract_matches(&mut txids, &mut block_indexes)
            .map_err(|_| Error::BitcoinMerkleBlockError)?;
        if proof_merkle_root != header.merkle_root() {
            return Err(orga::Error::App(
                "Bitcoin merkle proof does not match header".to_string(),
            ))?;
        }
        if txids.len() != 1 {
            return Err(orga::Error::App(
                "Bitcoin merkle proof contains an invalid number of txids".to_string(),
            ))?;
        }
        if txids[0] != tx.txid() {
            return Err(orga::Error::App(
                "Bitcoin merkle proof does not match transaction".to_string(),
            ))?;
        }

        if vout as usize >= tx.output.len() {
            return Err(orga::Error::App(
                "Output index is out of bounds".to_string(),
            ))?;
        }
        let output = &tx.output[vout as usize];

        if output.value != self.stake_sats() {
            // TODO: get conversion from config
            return Err(orga::Error::App(
                "Staking amount does not match".to_string(),
            ))?;
        }
        if output.script_pubkey != self.staking_script(params)? {
            return Err(orga::Error::App(
                "Staking script pubkey does not match".to_string(),
            ))?;
        }

        let outpoint = OutPoint {
            txid: tx.txid(),
            vout,
        };
        self.staking_outpoint = Some(outpoint.into());
        self.staking_height = Some(height);

        stake_queue.insert((height, self.owner, self.index), ())?;

        if self.requested_unbond {
            self.unbond(frost, btc, params)?;
        }

        Ok(())
    }

    pub fn request_unbond(
        &mut self,
        frost: &mut Frost,
        btc: &Bitcoin,
        params: &Params,
    ) -> Result<()> {
        if self.requested_unbond {
            return Err(Error::Orga(orga::Error::App(
                "Delegation already requested unbond".to_string(),
            )));
        }
        if self.status() == DelegationStatus::Withdrawn {
            return Err(Error::Orga(orga::Error::App(
                "Delegation already withdrawn".to_string(),
            )));
        }

        self.requested_unbond = true;

        match self.status() {
            DelegationStatus::Created => {}
            DelegationStatus::Staked => {
                self.unbond(frost, btc, params)?;
            }
            DelegationStatus::SigningUnbond => {}
            DelegationStatus::SignedUnbond => {}
            DelegationStatus::ConfirmedUnbond => {}
            DelegationStatus::Withdrawn => {
                return Err(Error::Orga(orga::Error::App(
                    "Delegation already withdrawn".to_string(),
                )));
            }
        }

        Ok(())
    }

    pub fn unbond(&mut self, frost: &mut Frost, btc: &Bitcoin, params: &Params) -> Result<()> {
        if self.status() != DelegationStatus::Staked {
            return Err(Error::Orga(orga::Error::App(
                "Delegation not in Staked state".to_string(),
            )));
        }

        let sigset = btc.checkpoints.active_sigset()?;
        let script = sigset.output_script(&[0], SIGSET_THRESHOLD)?;
        self.withdrawal_sigset_index = Some(sigset.index);
        self.withdrawal_script_pubkey = Some(script.into());

        let mut group = frost.groups.get_mut(self.frost_group)?.unwrap();
        self.frost_sig_offset.replace(group.signing.len());
        group.push_message(
            self.unbonding_withdrawal_sighash(params)?
                .to_vec()
                .try_into()?,
        )?;
        group.push_message(
            self.staking_unbonding_sighash(params)?
                .to_vec()
                .try_into()?,
        )?;

        Ok(())
    }

    pub fn sign_unbond(
        &mut self,
        staking_unbonding_sig: Signature,
        unbonding_withdrawal_sig: Signature,
        params: &Params,
    ) -> Result<()> {
        assert_eq!(self.status(), DelegationStatus::SigningUnbond);

        // TODO: reuse secp instance
        let secp = Secp256k1::verification_only();

        let key = self.btc_key()?;
        let verify = |msg: &[u8], sig: &Signature| -> Result<()> {
            let msg = bitcoin::secp256k1::Message::from_slice(msg)?;
            let sig = schnorr::Signature::from_slice(sig.as_slice())?;
            #[cfg(not(fuzzing))]
            secp.verify_schnorr(&sig, &msg, &key)?;
            Ok(())
        };

        let staking_unbonding_sighash = self.staking_unbonding_sighash(params)?;
        verify(
            &staking_unbonding_sighash.into_inner(),
            &staking_unbonding_sig,
        )?;
        self.staking_unbonding_sig = Some(staking_unbonding_sig);

        let unbonding_withdrawal_sighash = self.unbonding_withdrawal_sighash(params)?;
        verify(
            &unbonding_withdrawal_sighash.into_inner(),
            &unbonding_withdrawal_sig,
        )?;
        self.unbonding_withdrawal_sig = Some(unbonding_withdrawal_sig);

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn relay_unbonding_tx(
        &mut self,
        headers: &HeaderQueue,
        height: u32,
        proof: PartialMerkleTree,
        tx: Transaction,
        params: &Params,
        unbond_queue: &mut DelegationQueue,
        stake_queue: &mut DelegationQueue,
    ) -> Result<()> {
        if self.status() != DelegationStatus::SignedUnbond {
            return Err(Error::Orga(orga::Error::App(
                "Delegation not in SignedUnbond state".to_string(),
            )));
        }

        if headers.height()?.saturating_sub(height) < params.confirmation_depth {
            return Err(Error::Orga(orga::Error::App(
                "Unbonding tx is not confirmed".to_string(),
            )));
        }

        // TODO: dedupe this with other proof verification calls
        let header = headers
            .get_by_height(height)?
            .ok_or_else(|| Error::Orga(orga::Error::App("Header not found".to_string())))?;
        let mut txids = vec![];
        let mut block_indexes = vec![];
        let proof_merkle_root = proof
            .extract_matches(&mut txids, &mut block_indexes)
            .map_err(|_| Error::BitcoinMerkleBlockError)?;
        if proof_merkle_root != header.merkle_root() {
            return Err(orga::Error::App(
                "Bitcoin merkle proof does not match header".to_string(),
            ))?;
        }
        if txids.len() != 1 {
            return Err(orga::Error::App(
                "Bitcoin merkle proof contains an invalid number of txids".to_string(),
            ))?;
        }
        if txids[0] != tx.txid() {
            return Err(orga::Error::App(
                "Bitcoin merkle proof does not match transaction".to_string(),
            ))?;
        }
        if tx.txid() != self.unbonding_tx(params)?.txid() {
            return Err(Error::Orga(orga::Error::App(
                "Proven tx is not expected unbonding tx".to_string(),
            )));
        }

        self.unbonding_height = Some(height);

        let maturity_height = height + self.unbonding_period as u32;
        unbond_queue.insert((maturity_height, self.owner, self.index), ())?;
        stake_queue.remove((self.staking_height.unwrap(), self.owner, self.index))?;

        Ok(())
    }

    pub fn can_withdraw(&self, btc: &Bitcoin) -> Result<bool> {
        Ok(self.status() == DelegationStatus::ConfirmedUnbond
            && btc.headers.height()?
                < self.unbonding_height.unwrap() + self.unbonding_period as u32)
    }

    pub fn withdraw(&mut self, btc: &mut Bitcoin, params: &Params) -> Result<()> {
        if self.status() != DelegationStatus::ConfirmedUnbond {
            return Err(Error::Orga(orga::Error::App(
                "Delegation not in ConfirmedUnbond state".to_string(),
            )));
        }

        if !self.can_withdraw(btc)? {
            return Err(Error::Orga(orga::Error::App(
                "Unbonding period not over".to_string(),
            )));
        }

        let withdrawal_tx = self.unbonding_withdrawal_tx(params)?;
        let withdrawal_outpoint = OutPoint {
            txid: withdrawal_tx.txid(),
            vout: 0,
        };
        let sigset = btc.checkpoints.active_sigset()?;
        let input = Input::new(
            withdrawal_outpoint,
            &sigset,
            &[0],
            withdrawal_tx.output[0].value,
            SIGSET_THRESHOLD,
        )?;

        let mut building_cp = btc.checkpoints.building_mut()?;
        building_cp
            .batches
            .get_mut(BatchType::Checkpoint as u64)?
            .unwrap()
            .front_mut()?
            .unwrap()
            .input
            .push_back(input)?;

        let dest = if self.requested_unbond {
            // pay liquid funds to return dest
            self.return_dest.clone()
        } else {
            // renew delegation
            Dest::Stake {
                return_dest: self.return_dest.to_string().try_into()?,
                finality_provider: self.fp_keys[0],
                staking_period: self.staking_period,
            }
        };
        building_cp
            .pending
            .insert((dest, self.owner), self.stake.take(self.stake.amount)?)?;

        self.withdraw_checkpoint_index = Some(sigset.index);

        Ok(())
    }

    pub fn status(&self) -> DelegationStatus {
        assert_eq!(
            self.staking_outpoint.is_none(),
            self.staking_height.is_none()
        );

        if self.withdraw_checkpoint_index.is_some() {
            DelegationStatus::Withdrawn
        } else if self.unbonding_height.is_some() {
            DelegationStatus::ConfirmedUnbond
        } else if self.unbonding_withdrawal_sig.is_some() {
            DelegationStatus::SignedUnbond
        } else if self.withdrawal_script_pubkey.is_some() {
            DelegationStatus::SigningUnbond
        } else if self.staking_outpoint.is_some() {
            DelegationStatus::Staked
        } else {
            DelegationStatus::Created
        }
    }

    pub fn staking_output(&self, params: &Params) -> Result<TxOut> {
        Ok(TxOut {
            value: self.stake_sats(),
            script_pubkey: self.staking_script(params)?,
        })
    }

    pub fn op_return_output(&self) -> Result<TxOut> {
        Ok(TxOut {
            value: 0,
            script_pubkey: Script::new_op_return(self.op_return_bytes()?.as_slice()),
        })
    }

    pub fn staking_taproot(&self, params: &Params) -> Result<TaprootSpendInfo> {
        staking_taproot(
            self.btc_key()?,
            &self.fp_keys()?,
            self.staking_period,
            params,
        )
    }

    pub fn staking_script(&self, params: &Params) -> Result<Script> {
        let spend_info = self.staking_taproot(params)?;
        Ok(Script::new_v1_p2tr_tweaked(spend_info.output_key()))
    }

    pub fn unbonding_tx(&self, params: &Params) -> Result<Transaction> {
        unbonding_tx(
            self.btc_key()?,
            &self.fp_keys()?,
            *self.staking_outpoint.ok_or_else(|| {
                Error::Orga(orga::Error::App("Missing staking outpoint".to_string()))
            })?,
            self.stake_sats(),
            params,
        )
    }

    pub fn slashing_tx(&self) -> Result<Transaction> {
        slashing_tx(
            self.btc_key()?,
            *self.staking_outpoint.ok_or_else(|| {
                Error::Orga(orga::Error::App("Missing staking outpoint".to_string()))
            })?,
            self.stake_sats(),
            &Params::bbn_test_4(),
        )
    }

    pub fn unbonding_slashing_tx(&self, params: &Params) -> Result<Transaction> {
        let unbonding_tx = self.unbonding_tx(params)?;
        slashing_tx(
            self.btc_key()?,
            OutPoint {
                txid: unbonding_tx.txid(),
                vout: 0,
            },
            unbonding_tx.output[0].value,
            &Params::bbn_test_4(),
        )
    }

    pub fn staking_timelock_sighash(
        &self,
        spending_tx: &Transaction,
        input_index: u32,
        params: &Params,
    ) -> Result<TapSighashHash> {
        let mut sc = SighashCache::new(spending_tx);
        Ok(sc.taproot_script_spend_signature_hash(
            input_index as usize,
            &Prevouts::All(&[&TxOut {
                script_pubkey: self.staking_script(params)?,
                value: self.stake_sats(),
            }]),
            TapLeafHash::from_script(
                &timelock_script(self.btc_key()?, self.staking_period as u64),
                bitcoin::util::taproot::LeafVersion::TapScript,
            ),
            bitcoin::SchnorrSighashType::Default,
        )?)
    }

    pub fn staking_unbonding_sighash(&self, params: &Params) -> Result<TapSighashHash> {
        let unbonding_tx = self.unbonding_tx(params)?;
        let mut sc = SighashCache::new(&unbonding_tx);
        Ok(sc.taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&TxOut {
                script_pubkey: self.staking_script(params)?,
                value: self.stake_sats(),
            }]),
            TapLeafHash::from_script(
                &unbonding_script(self.btc_key()?, &Params::bbn_test_4())?,
                bitcoin::util::taproot::LeafVersion::TapScript,
            ),
            bitcoin::SchnorrSighashType::Default,
        )?)
    }

    pub fn staking_slashing_sighash(&self, params: &Params) -> Result<TapSighashHash> {
        let slashing_tx = self.slashing_tx()?;
        let mut sc = SighashCache::new(&slashing_tx);
        Ok(sc.taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&TxOut {
                script_pubkey: self.staking_script(params)?,
                value: self.stake_sats(),
            }]),
            TapLeafHash::from_script(
                &slashing_script(self.btc_key()?, &self.fp_keys()?, params)?,
                bitcoin::util::taproot::LeafVersion::TapScript,
            ),
            bitcoin::SchnorrSighashType::Default,
        )?)
    }

    pub fn unbonding_withdrawal_sighash(&self, params: &Params) -> Result<TapSighashHash> {
        let unbonding_tx = self.unbonding_tx(params)?;
        let withdrawal_tx = self.unbonding_withdrawal_tx(params)?;
        let mut sc = SighashCache::new(&withdrawal_tx);
        Ok(sc.taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&unbonding_tx.output[0]]),
            TapLeafHash::from_script(
                &timelock_script(self.btc_key()?, self.unbonding_period as u64),
                bitcoin::util::taproot::LeafVersion::TapScript,
            ),
            bitcoin::SchnorrSighashType::Default,
        )?)
    }

    pub fn op_return_bytes(&self) -> Result<Vec<u8>> {
        let data = OpReturnData {
            magic_byes: Params::bbn_test_4().op_return_tag,
            version: 0,
            staker_btc_pk: self.btc_key,
            fp_pk: *self
                .fp_keys
                .first()
                .ok_or_else(|| Error::Orga(orga::Error::App("Missing first FP key".to_string())))?,
            staking_time: self.staking_period,
        };

        Ok(data.encode()?)
    }

    pub fn unbonding_withdrawal_tx(&self, params: &Params) -> Result<Transaction> {
        let unbonding_tx = self.unbonding_tx(params)?;
        let unbonding_txid = unbonding_tx.txid();
        let unbonding_vout = 0;
        let unbonding_value = unbonding_tx.output[0].value;
        let unbonding_script = self.withdrawal_script_pubkey.clone().ok_or_else(|| {
            Error::Orga(orga::Error::App(
                "Missing withdrawal script pubkey".to_string(),
            ))
        })?;

        let unbonding_tx = Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: unbonding_txid,
                    vout: unbonding_vout,
                },
                script_sig: Script::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: unbonding_value - params.unbonding_fee,
                script_pubkey: unbonding_script.into_inner(),
            }],
        };

        Ok(unbonding_tx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct OpReturnData {
    pub magic_byes: [u8; 4],
    pub version: u8,
    pub staker_btc_pk: [u8; 32],
    pub fp_pk: [u8; 32],
    pub staking_time: u16,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        psbt::serialize::{Deserialize, Serialize},
        secp256k1::Message,
        util::bip32::ExtendedPrivKey,
        Network, PackedLockTime,
    };

    use super::*;

    #[test]
    fn staking_output_fixture() {
        let staker_btc_pk = "b3193611fc3fad7c35847dc98fb3bbc22f7c86fa87a5b5d3c64e06bf4e2ff54b";
        let fp_pk = "14102e9fedd4a93e0955c07ba06a598309e75371b7bb8645717abb37b5fde939";
        let staking_time = 1_008;
        let expected_staking_addr =
            "tb1pw3nfdjxrdy5u258m0tr9mggywc3avdpgaud7v3g06cx63wm3gjzs2glaz8";

        let staking_script = Script::new_v1_p2tr_tweaked(
            staking_taproot(
                staker_btc_pk.parse().unwrap(),
                &[fp_pk.parse().unwrap()],
                staking_time,
                &Params::bbn_test_3(),
            )
            .unwrap()
            .output_key(),
        );
        let staking_addr = bitcoin::Address::from_script(&staking_script, Network::Signet).unwrap();
        assert_eq!(staking_addr.to_string(), expected_staking_addr);
    }

    #[test]
    fn slashing_tx_fixture() {
        let staker_btc_pk = "b3193611fc3fad7c35847dc98fb3bbc22f7c86fa87a5b5d3c64e06bf4e2ff54b";
        let staking_outpoint = OutPoint {
            txid: "56f6d24069d3d8ef40f6dc7363d4acc1fde502610ad80ee3476aa5b8e8ad7a23"
                .parse()
                .unwrap(),
            vout: 0,
        };
        let staking_value = 20_000;
        let expected_slashing_tx = Transaction::deserialize(&hex::decode("0200000001237aade8b8a56a47e30ed80a6102e5fdc1acd46373dcf640efd8d36940d2f6560000000000ffffffff02980800000000000016001463e2edfae6bf51aebbed63bb823c55565ab5eacea041000000000000225120e9f60075bdb745bb352fee26ee981fd55573652a928c8e6b19db29e00f32646000000000").unwrap()).unwrap();

        let mut params = Params::bbn_test_3();
        params.unbonding_time = 101;

        let slashing_tx = slashing_tx(
            staker_btc_pk.parse().unwrap(),
            staking_outpoint,
            staking_value,
            &params,
        )
        .unwrap();
        assert_eq!(slashing_tx, expected_slashing_tx);
    }

    #[test]
    fn unbonding_tx_fixture() {
        let staker_btc_pk = "b3193611fc3fad7c35847dc98fb3bbc22f7c86fa87a5b5d3c64e06bf4e2ff54b";
        let fp_pk = "14102e9fedd4a93e0955c07ba06a598309e75371b7bb8645717abb37b5fde939";
        let staking_outpoint = OutPoint {
            txid: "56f6d24069d3d8ef40f6dc7363d4acc1fde502610ad80ee3476aa5b8e8ad7a23"
                .parse()
                .unwrap(),
            vout: 0,
        };
        let staking_value = 20_000;
        let expected_unbonding_tx = Transaction::deserialize(&hex::decode("0200000001237aade8b8a56a47e30ed80a6102e5fdc1acd46373dcf640efd8d36940d2f6560000000000ffffffff01384a000000000000225120c60d4710421700778d000fe5d618710b3c529aff1db293f9771a718207166b0800000000").unwrap()).unwrap();
        let expected_unbonding_slashing_tx = Transaction::deserialize(&hex::decode("0200000001a92722fb4e58cae7d03e2445ccb2a6201de1603773a5cb2e730136e95d6eabc60000000000ffffffff022a0800000000000016001463e2edfae6bf51aebbed63bb823c55565ab5eace263e000000000000225120e9f60075bdb745bb352fee26ee981fd55573652a928c8e6b19db29e00f32646000000000").unwrap()).unwrap();

        let mut params = Params::bbn_test_3();
        params.unbonding_time = 101;

        let unbonding_tx = unbonding_tx(
            staker_btc_pk.parse().unwrap(),
            &[fp_pk.parse().unwrap()],
            staking_outpoint,
            staking_value,
            &params,
        )
        .unwrap();
        assert_eq!(unbonding_tx, expected_unbonding_tx);

        let unbonding_slashing_tx = slashing_tx(
            staker_btc_pk.parse().unwrap(),
            OutPoint {
                txid: unbonding_tx.txid(),
                vout: 0,
            },
            unbonding_tx.output[0].value,
            &params,
        )
        .unwrap();
        assert_eq!(unbonding_slashing_tx, expected_unbonding_slashing_tx);
    }

    #[test]
    fn delegation() -> Result<()> {
        let secp = Secp256k1::new();
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, b"foo")?;
        let keypair = xpriv.to_keypair(&secp);
        let privkey = keypair.secret_key();

        // tb1p7aunqrcsrr0vrh7w9jcsm82w7c8xlrgererrfc5zae9ejxfupl3st6lal6
        let btc_pubkey = keypair.x_only_public_key().0;

        let params = Params::bbn_test_4();

        let mut del = Delegation::new(
            0,
            Identity::default(), // TODO
            Dest::default(),     // TODO
            btc_pubkey,
            0,
            vec![XOnlyPublicKey::from_keypair(&keypair).0],
            64_000,
            (0, 1),
            Nbtc::mint(50_000_000_000),
            &params,
        )?;
        assert_eq!(del.status(), DelegationStatus::Created);

        let script = del.staking_script(&params).unwrap();
        let addr = bitcoin::Address::from_script(&script, Network::Bitcoin).unwrap();
        dbg!(addr);

        let tx = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: "c5f1c4d0355eff69637efedb7ea62d10efcfe11a053728ac58a5b20d78913ccb"
                        .parse()
                        .unwrap(),
                    vout: 2,
                },
                script_sig: Script::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![
                del.staking_output(&params).unwrap(),
                del.op_return_output().unwrap(),
                TxOut {
                    value: 107_135 - 50_000 - (16 * 200),
                    // addr: bc1q7nqxt2rq0tqzt6x3h54hrvw8pfr4s0uuwyfgvq
                    script_pubkey: bitcoin::Address::from_str(
                        "bc1q7nqxt2rq0tqzt6x3h54hrvw8pfr4s0uuwyfgvq",
                    )
                    .unwrap()
                    .script_pubkey(),
                },
            ],
            lock_time: PackedLockTime::ZERO,
            version: 2,
        };
        println!("staking: {}", hex::encode(tx.serialize()));

        let spend_info = del.staking_taproot(&params).unwrap();
        let withdraw_script = timelock_script(del.btc_key()?, del.staking_period as u64);
        let leaf_ver = bitcoin::util::taproot::LeafVersion::TapScript;
        let witness = spend_info
            .control_block(&(withdraw_script.clone(), leaf_ver))
            .unwrap()
            .serialize();

        let mut tx = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: tx.txid(),
                    vout: 0,
                },
                script_sig: Script::default(),
                sequence: Sequence(150),
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: 50_000,
                script_pubkey: bitcoin::Address::from_str(
                    "bc1q7nqxt2rq0tqzt6x3h54hrvw8pfr4s0uuwyfgvq",
                )
                .unwrap()
                .script_pubkey(),
            }],
            lock_time: PackedLockTime::ZERO,
            version: 2,
        };
        tx.output[0].value -= tx.size() as u64 * 16;

        let sighash = del.staking_timelock_sighash(&tx, 0, &params).unwrap();
        let message = Message::from_slice(&sighash).unwrap();
        let sig = secp.sign_schnorr(&message, &keypair);
        let mut sig_bytes = [0; 64];
        sig_bytes.copy_from_slice(&sig.as_ref()[..]);
        tx.input[0].witness =
            Witness::from_vec(vec![sig_bytes.into(), withdraw_script.to_bytes(), witness]);
        println!("withdrawal: {}", hex::encode(tx.serialize()));
        println!("withdrawal txid: {}", tx.txid());

        // TODO: test verifying merkle proof
        del.staking_outpoint = Some(
            OutPoint {
                txid: "2d635625af2cfbe69f78f65865fa1fd948fd677deadc8b5a60039a08bbb1f3d0"
                    .parse()
                    .unwrap(),
                vout: 0,
            }
            .into(),
        );
        del.staking_height = Some(197_574);
        assert_eq!(del.status(), DelegationStatus::Staked);

        Ok(())
    }

    #[test]
    fn op_return_fixture() {
        let bytes = hex::decode("62626234008c0d21a8dd59a2a50f7ab8cb94d3034eb2b3d130589168bf7876a30b22c876d803d5a0bb72d71993e435d6c5a70e2aa4db500a62cfaae33c56050deefee64ec00096").unwrap();
        let data = OpReturnData::decode(bytes.as_slice()).unwrap();
        assert_eq!(&data.magic_byes, b"bbb4");
        assert_eq!(data.version, 0);
        assert_eq!(
            data.staker_btc_pk.as_slice(),
            hex::decode("8c0d21a8dd59a2a50f7ab8cb94d3034eb2b3d130589168bf7876a30b22c876d8")
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            data.fp_pk.as_slice(),
            hex::decode("03d5a0bb72d71993e435d6c5a70e2aa4db500a62cfaae33c56050deefee64ec0")
                .unwrap()
                .as_slice()
        );
        assert_eq!(data.staking_time, 150);
    }

    #[test]
    fn delegation_fixture() {
        let btc_key = XOnlyPublicKey::from_slice(
            &hex::decode("8c0d21a8dd59a2a50f7ab8cb94d3034eb2b3d130589168bf7876a30b22c876d8")
                .unwrap(),
        )
        .unwrap();
        let fp_keys = vec![XOnlyPublicKey::from_slice(
            &hex::decode("03d5a0bb72d71993e435d6c5a70e2aa4db500a62cfaae33c56050deefee64ec0")
                .unwrap(),
        )
        .unwrap()];

        let mut params = Params::bbn_test_4();
        params.min_staking_time = 0;

        let del = Delegation::new(
            0,
            Identity::default(),
            Dest::default(),
            btc_key,
            0,
            fp_keys,
            150,
            (0, 1),
            Coin::mint(50_000_000_000),
            &params,
        )
        .unwrap();

        assert_eq!(del.op_return_bytes().unwrap(), hex::decode("62626234008c0d21a8dd59a2a50f7ab8cb94d3034eb2b3d130589168bf7876a30b22c876d803d5a0bb72d71993e435d6c5a70e2aa4db500a62cfaae33c56050deefee64ec00096").unwrap());
        assert_eq!(
            del.staking_script(&params).unwrap().to_bytes(),
            hex::decode("51202552bc9fe84a0e05f156d127e7d2460bff26541ba56e9f761d2029ee09f3859f")
                .unwrap(),
        );
    }
}
