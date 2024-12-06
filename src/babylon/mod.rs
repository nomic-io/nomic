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
use serde_with::serde_as;
use serde_with::TryFromInto;

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

/// The main state struct which manages all delegations and their state
/// transitions.
#[orga]
pub struct Babylon {
    /// A map of all delegations, indexed by the owner's identity.
    pub delegations: Map<Identity, Deque<Delegation>>,
    /// A queue of all delegations which are currently staked, used to process
    /// delegations which reach maturity.
    pub staked: DelegationQueue,
    /// A queue of all delegations which are currently unbonding, used to
    /// process unbondings which reach maturity.
    pub unbonding: DelegationQueue,
    /// The parameters which define the Babylon network.
    pub params: Params,
}

pub type DelegationQueue = Map<(u32, Identity, u64), ()>;

#[orga]
impl Babylon {
    /// Called once per Nomic block to process delegation queues.
    pub fn step(&mut self, frost_sets: &mut [&mut Frost], btc: &mut Bitcoin) -> Result<()> {
        type QueueHandler =
            fn(&mut Delegation, &mut [&mut Frost], &mut Bitcoin, &Params) -> Result<()>;
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
                handler(&mut del, frost_sets, btc, &self.params)?;
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

        // TODO: don't iterate through all delegations
        // Process delegations which have started unbonding and have now been fully
        // signed by the FROST signers, adding their signatures from the Frost state to
        // the delegation struct.
        let mut to_advance = vec![];
        for entry in self.delegations.iter()? {
            let (_, owner_dels) = entry?;
            for del in owner_dels.iter()? {
                let del = del?;

                if del.status() != DelegationStatus::SigningUnbond {
                    continue;
                }

                let frost = &mut frost_sets[del.frost_group.0 as usize];

                let unbonding_withdrawal_sig =
                    frost.signature(del.frost_group.1, del.frost_sig_offset.unwrap())?;
                let staking_unbonding_sig =
                    frost.signature(del.frost_group.1, del.frost_sig_offset.unwrap() + 1)?;

                if let (Some(unbonding_withdrawal_sig), Some(staking_unbonding_sig)) =
                    (unbonding_withdrawal_sig, staking_unbonding_sig)
                {
                    to_advance.push((
                        del.owner,
                        del.index,
                        Signature(unbonding_withdrawal_sig.inner.serialize()),
                        Signature(staking_unbonding_sig.inner.serialize()),
                    ));
                }
            }
        }
        for (owner, index, unbonding_withdrawal_sig, staking_unbonding_sig) in to_advance {
            let mut owner_dels = self
                .delegations
                .get_mut(owner)?
                .ok_or_else(|| Error::Orga(orga::Error::App("Delegation not found".to_string())))?;
            let mut del = owner_dels
                .get_mut(index)?
                .ok_or_else(|| Error::Orga(orga::Error::App("Delegation not found".to_string())))?;
            del.sign_unbond(
                unbonding_withdrawal_sig,
                staking_unbonding_sig,
                &self.params,
            )?;
        }

        Ok(())
    }

    /// Stake nBTC via Babylon, creating a new delegation.
    #[allow(clippy::too_many_arguments)]
    pub fn stake(
        &mut self,
        btc: &mut crate::bitcoin::Bitcoin,
        frost_sets: &mut [&mut crate::frost::Frost],
        frost_group: Option<(u8, u64)>,
        owner: Identity,
        return_dest: Dest,
        finality_provider: [u8; 32],
        staking_time: u16,
        nbtc: Coin<Nbtc>,
    ) -> Result<u64> {
        let (frost_set, frost_group, group_pubkey) =
            if let Some((set_index, group_index)) = frost_group {
                // user specified a frost group
                if set_index as usize >= frost_sets.len() {
                    return Err(Error::Orga(orga::Error::App(
                        "Frost set not found".to_string(),
                    )));
                }
                let pubkey = frost_sets[set_index as usize]
                    .group_pubkey(group_index)?
                    .ok_or_else(|| {
                        Error::Orga(orga::Error::App("Frost group not found".to_string()))
                    })?;
                (set_index, group_index, pubkey)
            } else if let Some(group_index) = frost_sets[0].most_recent_with_key()? {
                // user did not specify a frost group, so we use the most recent main frost
                // group
                let pubkey = frost_sets[0].group_pubkey(group_index)?.unwrap();
                (0, group_index, pubkey)
            } else {
                // user did not specify a frost group, and there are no main frost groups
                return Err(Error::Orga(orga::Error::App(
                    "Frost not initialized".to_string(),
                )));
            };

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
            (frost_set, frost_group),
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

    /// Unstake nBTC from a delegation, starting the unbonding process.
    pub fn unstake(
        &mut self,
        owner: Identity,
        index: u64,
        frost_sets: &mut [&mut Frost],
        btc: &Bitcoin,
    ) -> Result<()> {
        self.delegations
            .get_mut(owner)?
            .ok_or_else(|| Error::Orga(orga::Error::App("Delegation not found".to_string())))?
            .get_mut(index)?
            .ok_or_else(|| Error::Orga(orga::Error::App("Delegation not found".to_string())))?
            .request_unbond(frost_sets, btc, &self.params)
    }

    /// Get all delegations owned by `owner`.
    #[query]
    pub fn owner_delegations(&self, owner: Identity) -> Result<Vec<Delegation>> {
        self.delegations
            .get(owner)?
            .unwrap_or_default()
            .iter()?
            .map(|entry| Ok(Delegation::decode(entry?.encode()?.as_slice())?))
            .collect()
    }
}

/// Construct a multisig Bitcoin script fragment, as defined by the Babylon
/// protocol.
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

/// Sort a list of public keys and ensure there are no duplicates.
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

/// Construct a single-key Bitcoin script fragment, as defined by the Babylon
/// protocol.
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

/// Construct a timelock Bitcoin script fragment, as defined by the Babylon
/// protocol.
pub fn timelock_script(pk: XOnlyPublicKey, timelock: u64) -> Script {
    let mut bytes = single_key_script(pk, true).into_bytes();
    // TODO: put this allow in the bitcoin_script crate
    #[allow(clippy::redundant_closure_call)]
    bytes.extend(script! { <timelock as i64> OP_CSV }.into_bytes());
    bytes.into()
}

/// Aggregate a list of Bitcoin scripts into a single script.
pub fn aggregate_scripts(scripts: &[Script]) -> Script {
    let mut bytes = vec![];
    for script in scripts.iter() {
        bytes.extend(script.clone().into_bytes());
    }
    bytes.into()
}

/// The parameters which define the Babylon network.
#[orga(skip(Default))]
#[derive(Debug, Clone)]
pub struct Params {
    /// The public keys of the covenant signers.
    pub covenant_keys: LengthVec<u8, [u8; 32]>,
    /// The quorum required to sign a covenant transaction.
    pub covenant_quorum: u32,
    /// The script pubkey of the slashing address.
    pub slashing_script: Adapter<Script>,
    /// The fee used in a delegation's slashing transactions.
    pub slashing_min_fee: u64,
    /// The tag used as the starting magic bytes of the OP_RETURN output in a
    /// staking transaction.
    pub op_return_tag: [u8; 4],
    /// The slashing rate used in a delegation's slashing transactions (a ratio
    /// as `(numerator, denominator)`).
    pub slashing_rate: (u32, u32),
    /// The maximum age of a staking transaction before Nomic will automatically
    /// start unbonding it before restaking it.
    pub max_age: u32,
    /// The minimum staking time allowed for a delegation.
    pub min_staking_time: u16,
    /// The maximum staking time allowed for a delegation.
    pub max_staking_time: u16,
    /// The time a delegation must wait before unbonding.
    pub unbonding_time: u16,
    /// The minimum amount of nBTC required to stake (in microsats).
    pub min_staking_amount: u64,
    /// The maximum amount of nBTC allowed to stake (in microsats).
    pub max_staking_amount: u64,
    /// The fee used in a delegation's unbonding transaction.
    pub unbonding_fee: u64,
    /// The number of Bitcoin block confirmations required for a staking
    /// transaction to be considered confirmed.
    pub confirmation_depth: u32,
}

impl Params {
    /// Parameters for Babylon testnet 3.
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
            op_return_tag: *b"bbn3",
            slashing_rate: (11, 100),
            max_age: u32::MAX,
            min_staking_time: u16::MAX,
            max_staking_time: 1,
            unbonding_time: 5,
            min_staking_amount: 50_000,
            max_staking_amount: 5_000_000,
            unbonding_fee: 1_000,
            confirmation_depth: 10,
        }
    }

    /// Parameters for the Babylon staging testnet.
    pub fn bbn_staging_testnet() -> Self {
        let covenant_keys = [
            "49766ccd9e3cd94343e2040474a77fb37cdfd30530d05f9f1e96ae1e2102c86e",
            "76d1ae01f8fb6bf30108731c884cddcf57ef6eef2d9d9559e130894e0e40c62c",
            "17921cf156ccb4e73d428f996ed11b245313e37e27c978ac4d2cc21eca4672e4",
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
            op_return_tag: *b"bbd4",
            slashing_rate: (11, 100),
            max_age: u32::MAX,
            min_staking_time: 150,
            max_staking_time: 64_000,
            unbonding_time: 5,
            min_staking_amount: 30_000,
            max_staking_amount: 100_000_000,
            unbonding_fee: 3_000,
            confirmation_depth: 2,
        }
    }

    /// Parameters for the Babylon mainnet (as of phase 1, cap 3).
    pub fn bbn_mainnet() -> Self {
        let covenant_keys = [
            "d45c70d28f169e1f0c7f4a78e2bc73497afe585b70aa897955989068f3350aaa",
            "4b15848e495a3a62283daaadb3f458a00859fe48e321f0121ebabbdd6698f9fa",
            "23b29f89b45f4af41588dcaf0ca572ada32872a88224f311373917f1b37d08d1",
            "d3c79b99ac4d265c2f97ac11e3232c07a598b020cf56c6f055472c893c0967ae",
            "8242640732773249312c47ca7bdb50ca79f15f2ecc32b9c83ceebba44fb74df7",
            "e36200aaa8dce9453567bba108bdc51f7f1174b97a65e4dc4402fc5de779d41c",
            "cbdd028cfe32c1c1f2d84bfec71e19f92df509bba7b8ad31ca6c1a134fe09204",
            "f178fcce82f95c524b53b077e6180bd2d779a9057fdff4255a0af95af918cee0",
            "de13fc96ea6899acbdc5db3afaa683f62fe35b60ff6eb723dad28a11d2b12f8c",
        ];
        let covenant_quorum = 6;

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
            op_return_tag: *b"bbn1",
            slashing_rate: (11, 100),
            max_age: u32::MAX,
            min_staking_time: 64_000,
            max_staking_time: 64_000,
            unbonding_time: 1_008,
            min_staking_amount: 500_000,
            max_staking_amount: 500_000_000_000,
            unbonding_fee: 32_000,
            confirmation_depth: 10,
        }
    }

    /// Gets the covenant keys as a list of `XOnlyPublicKey`s.
    pub fn covenant_keys(&self) -> Vec<XOnlyPublicKey> {
        self.covenant_keys
            .iter()
            .map(|k| XOnlyPublicKey::from_slice(k).unwrap())
            .collect()
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::bbn_mainnet()
    }
}

/// Constructs the script for the unbonding path of a delegation, as defined by
/// the Babylon protocol.
pub fn unbonding_script(staker_key: XOnlyPublicKey, params: &Params) -> Result<Script> {
    Ok(aggregate_scripts(&[
        single_key_script(staker_key, true),
        multisig_script(&params.covenant_keys(), params.covenant_quorum, false)?,
    ]))
}

/// Constructs the script for the slashing path of a delegation, as defined by
/// the Babylon protocol.
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

/// An unspendable key used as the internal key for Taproot scripts that have no
/// key path, as defined in BIP 341.
const UNSPENDABLE_KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Construct the Taproot for the staking output of a delegation, as defined by
/// the Babylon protocol.
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

/// Construct a slashing transaction of a delegation, as defined by the
/// Babylon protocol.
///
/// Note that there is used to construct 2 different slashing transactions: one
/// spending from the staking output, and one spending from the unbonding
/// output.
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

/// Construct the Taproot for the unbonding output of a delegation, as defined
/// by the Babylon protocol.
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

/// Construct the unbonding transaction of a delegation, as defined by the
/// Babylon protocol.
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

/// Raw bytes of a serialized `XOnlyPubkey`.
pub type XOnlyPubkey = [u8; 32];

/// Convert serialized `XOnlyPubkey` bytes to the `XOnlyPublicKey` type.
fn bytes_to_pubkey(bytes: XOnlyPubkey) -> Result<XOnlyPublicKey> {
    Ok(XOnlyPublicKey::from_slice(&bytes)?)
}

/// The status of a delegation.
///
/// This is derived in a stateful manner from the delegation's fields.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DelegationStatus {
    Created,
    Staked,
    SigningUnbond,
    SignedUnbond,
    ConfirmedUnbond,
    Withdrawn,
}

/// A delegation of nBTC to the Babylon network.
///
/// This type represents a state machine which transitions through various
/// states as the delegation is created, staked, unbonded, and withdrawn.

#[serde_as]
#[orga]
#[derive(Debug)]
pub struct Delegation {
    // Fields for `Created` state:
    /// The index of the delegation within the owner's list of delegations.
    ///
    /// Multiple delegations can have the same index but with different owners.
    pub index: u64,
    /// The owner of the delegation.
    pub owner: Identity,
    /// The destination where the nBTC should be returned once the delegation
    /// is withdrawn.
    pub return_dest: Dest,
    /// The public key used to create the staking output.
    ///
    /// In practice this is the aggregated public key of the FROST group.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub btc_key: XOnlyPubkey,
    /// The set (0 for `frost` and 1 for `aux_frost`) and index of the FROST
    /// group used to sign the delegation.
    pub frost_group: (u8, u64),
    /// The finality provider keys this delegation is being staked to.
    ///
    /// Note that as of Babylon mainnet cap 2, testnet 4, and the staging
    /// testnet, there is only one finality provider key.
    #[serde_as(as = "TryFromInto<Vec<XOnlyPubkey>>")]
    pub fp_keys: LengthVec<u8, XOnlyPubkey>,
    /// The amount of Bitcoin blocks the delegation is staked for.
    pub staking_period: u16,
    /// The amount of Bitcoin blocks the delegation must wait before unbonding.
    pub unbonding_period: u16,
    /// The index of the Nomic BTC checkpoint the delegation's staking
    /// transaction is included it, and the transaction index within its
    /// checkpoint batch.
    pub checkpoint_batch_index: (u32, u64),
    /// The staked nBTC held in the delegation.
    ///
    /// Since `Coin` has move-semantics for funds, this will be consumed and
    /// have an amount of 0 once the delegation has been withdrawn.
    pub stake: Coin<Nbtc>,
    /// The amount staked in the delegation, in microsats.
    ///
    /// Note that this will be equal to the amount in the `stake` field for most
    /// of the delegation's lifecycle. However, `stake` will be consumed when
    /// the delegation is withdrawn, so this field is used to keep track of the
    /// original amount staked.
    pub stake_amount: u64,

    // Fields for `Staked` state:
    /// The staking transaction's outpoint, set once the staking transaction has
    /// been proven to have confirmed on the Bitcoin blockchain.
    pub staking_outpoint: Option<crate::bitcoin::adapter::Adapter<OutPoint>>,
    /// The height of the Bitcoin block the staking transaction was included in.
    ///
    /// Set once the staking transaction has been proven to have confirmed on
    /// the Bitcoin blockchain.
    pub staking_height: Option<u32>,

    // Fields for `SigningUnbond` state:
    // TODO: handle different types of spends (timelock vs unbonding vs slashed)
    /// Whether the owner has requested to unbond the delegation.
    pub requested_unbond: bool,
    /// The index of the signatory set the delegation is paying to in its
    /// withdrawal, which will be used to collect the funds back into the Nomic
    /// reserve once the withdrawal transaction has confirmed.
    ///
    /// Set once the delegation has started unbonding.
    pub withdrawal_sigset_index: Option<u32>,
    /// The script pubkey of the withdrawal output, set once the delegation has
    /// started unbonding.
    pub withdrawal_script_pubkey: Option<crate::bitcoin::adapter::Adapter<Script>>,
    /// The index of the start of the relevant signatures within the FROST
    /// group.
    ///
    /// Set once the delegation has started unbonding.
    pub frost_sig_offset: Option<u64>,

    // Fields for `SignedUnbond` state:
    /// The signature of the unbonding transaction's spend of the staking
    /// output.
    ///
    /// Set once the delegation has been fully signed by the FROST group.
    pub(crate) staking_unbonding_sig: Option<Signature>,
    /// The signature of the withdrawal transaction's spend of the unbonding
    /// output.
    ///
    /// Set once the delegation has been fully signed by the FROST group.
    pub(crate) unbonding_withdrawal_sig: Option<Signature>,

    // Fields for `ConfirmedUnbond` state:
    /// The height of the Bitcoin block the unbonding transaction was included
    /// in.
    ///
    /// Set once the unbonding transaction has been proven to have confirmed on
    /// the Bitcoin blockchain.
    pub unbonding_height: Option<u32>,

    // Fields for `Withdrawn` state:
    /// The index of the checkpoint which included the withdrawal transaction.
    pub withdraw_checkpoint_index: Option<u32>,
}

#[orga]
impl Delegation {
    /// Construct a new delegation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        index: u64,
        owner: Identity,
        return_dest: Dest,
        btc_key: XOnlyPublicKey,
        frost_group: (u8, u64),
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
            stake_amount: stake.amount.into(),
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
        self.stake_amount / 1_000_000 // TODO: get conversion from bitcoin
                                      // config
    }

    /// Relays proof of the staking transaction's inclusion in a Bitcoin block.
    ///
    /// This advances the delegation's state from `Created` to `Staked`.
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
        frost_sets: &mut [&mut Frost],
        btc: &Bitcoin,
    ) -> Result<()> {
        if self.status() != DelegationStatus::Created {
            return Err(Error::Orga(orga::Error::App(
                "Staking tx already relayed".to_string(),
            )));
        }

        if headers.height()?.saturating_sub(height) < params.confirmation_depth - 1 {
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
            self.unbond(frost_sets, btc, params)?;
        }

        Ok(())
    }

    /// Requests to unbond the delegation.
    ///
    /// If the delegation is still being created, the unbonding will begin as
    /// soon as the staking transaction is confirmed. If the delegation is
    /// already staked, the unbonding will begin immediately.
    pub fn request_unbond(
        &mut self,
        frost_sets: &mut [&mut Frost],
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
                self.unbond(frost_sets, btc, params)?;
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

    /// Begin unbonding the delegation, transitioning it to the `SigningUnbond`
    /// state.
    ///
    /// This requests the FROST group to sign the unbonding transaction's spend
    /// of the staking output, and the withdrawal transaction's spend of the
    /// unbonding output.
    pub fn unbond(
        &mut self,
        frost_sets: &mut [&mut Frost],
        btc: &Bitcoin,
        params: &Params,
    ) -> Result<()> {
        if self.status() != DelegationStatus::Staked {
            return Err(Error::Orga(orga::Error::App(
                "Delegation not in Staked state".to_string(),
            )));
        }

        let sigset = btc.checkpoints.active_sigset()?;
        let script = sigset.output_script(&[0], SIGSET_THRESHOLD)?;
        self.withdrawal_sigset_index = Some(sigset.index);
        self.withdrawal_script_pubkey = Some(script.into());

        let frost = &mut frost_sets[self.frost_group.0 as usize];
        let mut group = frost.groups.get_mut(self.frost_group.1)?.unwrap();
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

    /// Add the unbonding signatures from the FROST group to the delegation.
    ///
    /// This transitions the delegation to the `SignedUnbond` state.
    pub fn sign_unbond(
        &mut self,
        unbonding_withdrawal_sig: Signature,
        staking_unbonding_sig: Signature,
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

    /// Relays proof of the unbonding transaction's inclusion in a Bitcoin
    /// block.
    ///
    /// This advances the delegation's state from `SignedUnbond` to
    /// `ConfirmedUnbond` and adds the unbond to the unbonding queue based on
    /// its confirmation height. Once the unbonding period has passed, the
    /// delegation will be withdrawn.
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

        if headers.height()?.saturating_sub(height) < params.confirmation_depth - 1 {
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

    /// Whether the delegation can be withdrawn.
    ///
    /// This is based on the current Bitcoin blockchain height, the height when
    /// the delegation's unbonding period began, and the length of the unbonding
    /// period.
    pub fn can_withdraw(&self, btc: &Bitcoin) -> Result<bool> {
        Ok(self.status() == DelegationStatus::ConfirmedUnbond
            && btc.headers.height()?
                >= self.unbonding_height.unwrap() + self.unbonding_period as u32)
    }

    /// Withdraw from the matured unbonding transaction of the delegation.
    ///
    /// This pushes the withdrawal transaction to the checkpoint batch, and
    /// pushes the input spending it to the building checkpoint transaction.
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
        let sigset = btc
            .checkpoints
            .get(self.withdrawal_sigset_index.unwrap())?
            .sigset
            .clone();
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

        // TODO: allow auto-renewal of stake by paying to updated stake dest
        let dest = self.return_dest.clone();
        let nbtc = self.stake.take(self.stake.amount)?;
        building_cp.pending.insert((dest, self.owner), nbtc)?;

        self.withdraw_checkpoint_index = Some(sigset.index);

        Ok(())
    }

    /// The status of the delegation.
    ///
    /// This is derived in a stateful manner from the delegation's fields. The
    /// status is sequential and can only advance from one state to the next.
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

    /// The staking output - the output of the staking transaction containing
    /// the Babylon protocol Taproot construction.
    pub fn staking_output(&self, params: &Params) -> Result<TxOut> {
        Ok(TxOut {
            value: self.stake_sats(),
            script_pubkey: self.staking_script(params)?,
        })
    }

    /// The OP_RETURN output - the output of the unbonding transaction
    /// containing the Babylon protocol OP_RETURN data (used by Babylon to
    /// identify the delegation).
    pub fn op_return_output(&self) -> Result<TxOut> {
        Ok(TxOut {
            value: 0,
            script_pubkey: Script::new_op_return(self.op_return_bytes()?.as_slice()),
        })
    }

    /// The staking Taproot construction for this delegation.
    pub fn staking_taproot(&self, params: &Params) -> Result<TaprootSpendInfo> {
        staking_taproot(
            self.btc_key()?,
            &self.fp_keys()?,
            self.staking_period,
            params,
        )
    }

    /// The script paying to the staking Taproot construction.
    pub fn staking_script(&self, params: &Params) -> Result<Script> {
        let spend_info = self.staking_taproot(params)?;
        Ok(Script::new_v1_p2tr_tweaked(spend_info.output_key()))
    }

    /// The unbonding transaction for the delegation.
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

    /// The slashing transaction for the delegation which spends the staking
    /// output.
    pub fn slashing_tx(&self) -> Result<Transaction> {
        slashing_tx(
            self.btc_key()?,
            *self.staking_outpoint.ok_or_else(|| {
                Error::Orga(orga::Error::App("Missing staking outpoint".to_string()))
            })?,
            self.stake_sats(),
            &Params::bbn_mainnet(),
        )
    }

    /// The slashing transaction for the delegation which spends the unbonding
    /// output.
    pub fn unbonding_slashing_tx(&self, params: &Params) -> Result<Transaction> {
        let unbonding_tx = self.unbonding_tx(params)?;
        slashing_tx(
            self.btc_key()?,
            OutPoint {
                txid: unbonding_tx.txid(),
                vout: 0,
            },
            unbonding_tx.output[0].value,
            &Params::bbn_mainnet(),
        )
    }

    /// The sighash for the staking transaction's spend of the staking output,
    /// for the path which becomes valid once the staking output has matured
    /// (its staking period has passed).
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

    /// The sighash for the unbonding transaction's spend of the staking output.
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
                &unbonding_script(self.btc_key()?, &Params::bbn_mainnet())?,
                bitcoin::util::taproot::LeafVersion::TapScript,
            ),
            bitcoin::SchnorrSighashType::Default,
        )?)
    }

    /// The sighash for the slashing transaction's spend of the staking output.
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

    /// The sighash for the withdrawal transaction's spend of the unbonding
    /// output.
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

    /// The OP_RETURN data for the delegation.
    ///
    /// This is used by Babylon to identify the delegation on the Bitcoin
    /// blockchain.
    pub fn op_return_bytes(&self) -> Result<Vec<u8>> {
        let data = OpReturnData {
            magic_byes: Params::bbn_mainnet().op_return_tag,
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

    /// The withdrawal transaction which spends the unbonding output.
    pub fn unbonding_withdrawal_tx(&self, params: &Params) -> Result<Transaction> {
        let unbonding_tx = self.unbonding_tx(params)?;
        let unbonding_txid = unbonding_tx.txid();
        let unbonding_vout = 0;
        let unbonding_value = unbonding_tx.output[0].value;
        let unbonding_script = timelock_script(self.btc_key()?, params.unbonding_time as u64);
        let withdrawal_script = self.withdrawal_script_pubkey.clone().ok_or_else(|| {
            Error::Orga(orga::Error::App(
                "Missing withdrawal script pubkey".to_string(),
            ))
        })?;

        let tr = unbonding_taproot(self.btc_key()?, &self.fp_keys()?, params)?;

        let leaf_ver = bitcoin::util::taproot::LeafVersion::TapScript;
        let cb = tr
            .control_block(&(unbonding_script.clone(), leaf_ver))
            .unwrap()
            .serialize();
        let witness = Witness::from_vec(vec![
            self.unbonding_withdrawal_sig
                .map(|b| b.to_vec())
                .unwrap_or_default(),
            unbonding_script.to_bytes(),
            cb,
        ]);

        let unbonding_tx = Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: unbonding_txid,
                    vout: unbonding_vout,
                },
                script_sig: Script::default(),
                sequence: Sequence(params.unbonding_time as u32),
                witness,
            }],
            output: vec![TxOut {
                value: unbonding_value - params.unbonding_fee,
                script_pubkey: withdrawal_script.into_inner(),
            }],
        };

        Ok(unbonding_tx)
    }
}

/// The data stored in the OP_RETURN output of a delegation's staking
/// transaction.
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

        let params = Params::bbn_staging_testnet();

        let mut del = Delegation::new(
            0,
            Identity::default(), // TODO
            Dest::default(),     // TODO
            btc_pubkey,
            (0, 0),
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

        let mut params = Params::bbn_staging_testnet();
        params.min_staking_time = 0;

        let del = Delegation::new(
            0,
            Identity::default(),
            Dest::default(),
            btc_key,
            (0, 0),
            fp_keys,
            150,
            (0, 1),
            Coin::mint(50_000_000_000),
            &params,
        )
        .unwrap();

        assert_eq!(hex::encode(del.op_return_bytes().unwrap()), "62626434008c0d21a8dd59a2a50f7ab8cb94d3034eb2b3d130589168bf7876a30b22c876d803d5a0bb72d71993e435d6c5a70e2aa4db500a62cfaae33c56050deefee64ec00096");
        assert_eq!(
            hex::encode(del.staking_script(&params).unwrap().to_bytes()),
            "512083f18ab40065c1bd5ab6616535e9af358df7640e935c16012d0df306a4c0e42f",
        );
    }
}
