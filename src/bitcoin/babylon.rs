use bitcoin::{
    secp256k1::Secp256k1, util::taproot::TaprootBuilder, Address, LockTime, OutPoint, Script,
    Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use bitcoin_script::bitcoin_script as script;
use orga::{coins::Coin, orga};

use crate::{
    bitcoin::Nbtc,
    error::{Error, Result},
};

const UNSPENDABLE_KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

#[orga]
pub struct Babylon {
    to_stake: Coin<Nbtc>,
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

    let pks = sort_keys(&pks)?;

    let mut bytes = vec![];
    for (i, pk) in pks.iter().enumerate() {
        let pk = pk.serialize().to_vec();
        bytes.extend(
            if i == 0 {
                script! { <pk> OP_CHECKSIG }
            } else {
                script! { <pk> OP_CHECKSIGADD }
            }
            .into_bytes(),
        );
    }
    bytes.extend(script! { <threshold as i64> OP_GREATERTHANOREQUAL }.into_bytes());
    if verify {
        bytes.extend(script! { OP_VERIFY }.into_bytes());
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
    // TODO: reverse sort order?
    pks.sort_by(|a, b| a.serialize().cmp(&b.serialize()));

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
        script! { <pk> OP_CHECKSIGVERIFY }
    } else {
        script! { <pk> OP_CHECKSIG }
    }
}

pub fn timelock_script(pk: XOnlyPublicKey, timelock: u64) -> Script {
    let mut bytes = single_key_script(pk, true).into_bytes();
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

pub struct Params {
    pub covenant_keys: Vec<XOnlyPublicKey>,
    pub covenant_quorum: u32,
    pub slashing_addr: Address,
    pub slashing_min_fee: u64,
}

impl Params {
    fn bbn_test_3() -> Self {
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
            covenant_keys: covenant_keys.iter().map(|k| k.parse().unwrap()).collect(),
            covenant_quorum,
            slashing_addr: slashing_addr.parse().unwrap(),
            slashing_min_fee,
        }
    }
}

pub fn unbonding_script(staker_key: XOnlyPublicKey, params: &Params) -> Result<Script> {
    Ok(aggregate_scripts(&[
        single_key_script(staker_key, true),
        multisig_script(&params.covenant_keys, params.covenant_quorum, false)?,
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
        multisig_script(&params.covenant_keys, params.covenant_quorum, false)?,
    ]))
}

pub fn staking_script(
    staker_key: XOnlyPublicKey,
    fp_keys: &[XOnlyPublicKey],
    staking_time: u16,
    params: &Params,
) -> Result<Script> {
    let timelock_script = timelock_script(staker_key, staking_time as u64);
    let unbonding_script = unbonding_script(staker_key, params)?;
    let slashing_script = slashing_script(staker_key, fp_keys, params)?;

    let internal_key = UNSPENDABLE_KEY.parse()?;
    let spend_info = TaprootBuilder::new()
        .add_leaf(2, timelock_script)?
        .add_leaf(2, unbonding_script)?
        .add_leaf(1, slashing_script)?
        .finalize(&Secp256k1::new(), internal_key)
        .map_err(|_| Error::Orga(orga::Error::App("Failed to finalize taproot".to_string())))?;

    Ok(Script::new_v1_p2tr_tweaked(spend_info.output_key()))
}

pub fn slashing_tx(
    staker_key: XOnlyPublicKey,
    stake_out: OutPoint,
    stake_value: u64,
    unbonding_time: u16,
    params: &Params,
) -> Result<Transaction> {
    let staking_in = TxIn {
        previous_output: stake_out,
        script_sig: Script::new(),
        sequence: Sequence(u32::MAX),
        witness: Witness::default(),
    };

    let slashing_rate = (9, 10); // TODO: parameterize
    let slashing_value = stake_value * slashing_rate.0 / slashing_rate.1;
    let slashing_out = TxOut {
        value: slashing_value,
        script_pubkey: params.slashing_addr.script_pubkey(),
    };

    let change_key = TaprootBuilder::new()
        .add_leaf(0, timelock_script(staker_key, unbonding_time as u64))?
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

pub fn unbonding_tx(
    staker_key: XOnlyPublicKey,
    fp_keys: &[XOnlyPublicKey],
    staking_outpoint: OutPoint,
    staking_value: u64,
    unbonding_time: u16,
    params: &Params,
) -> Result<Transaction> {
    let staking_in = TxIn {
        previous_output: staking_outpoint,
        script_sig: Script::new(),
        sequence: Sequence(u32::MAX),
        witness: Witness::default(),
    };

    let out_key = TaprootBuilder::new()
        .add_leaf(1, timelock_script(staker_key, unbonding_time as u64))?
        .add_leaf(1, slashing_script(staker_key, fp_keys, params)?)?
        .finalize(&Secp256k1::new(), UNSPENDABLE_KEY.parse().unwrap())
        .unwrap()
        .output_key();
    let out = TxOut {
        value: staking_value - 1_000, // TODO: parameterize
        script_pubkey: Script::new_v1_p2tr_tweaked(out_key),
    };

    Ok(Transaction {
        version: 2,
        lock_time: bitcoin::PackedLockTime(0),
        input: vec![staking_in],
        output: vec![out],
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::{psbt::serialize::Deserialize, Network};

    use super::*;

    #[test]
    fn staking_output_fixture() {
        let staker_btc_pk = "b3193611fc3fad7c35847dc98fb3bbc22f7c86fa87a5b5d3c64e06bf4e2ff54b";
        let fp_pk = "14102e9fedd4a93e0955c07ba06a598309e75371b7bb8645717abb37b5fde939";
        let staking_time = 1_008;
        let expected_staking_addr =
            "tb1p9e7vhkuskwfzyt8wz4v2769p9wd0et3gz78y39hawpm2ekeqjawqakm862";

        let staking_script = staking_script(
            staker_btc_pk.parse().unwrap(),
            &[fp_pk.parse().unwrap()],
            staking_time,
            &Params::bbn_test_3(),
        )
        .unwrap();
        let staking_addr = Address::from_script(&staking_script, Network::Signet).unwrap();
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
        let unbonding_time = 101;
        let expected_slashing_tx = Transaction::deserialize(&hex::decode("0200000001237aade8b8a56a47e30ed80a6102e5fdc1acd46373dcf640efd8d36940d2f6560000000000ffffffff02d00700000000000016001463e2edfae6bf51aebbed63bb823c55565ab5eace6842000000000000225120e9f60075bdb745bb352fee26ee981fd55573652a928c8e6b19db29e00f32646000000000").unwrap()).unwrap();

        let slashing_tx = slashing_tx(
            staker_btc_pk.parse().unwrap(),
            staking_outpoint,
            staking_value,
            unbonding_time,
            &Params::bbn_test_3(),
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
        let unbonding_time = 101;
        let expected_unbonding_tx = Transaction::deserialize(&hex::decode("0200000001237aade8b8a56a47e30ed80a6102e5fdc1acd46373dcf640efd8d36940d2f6560000000000ffffffff01384a00000000000022512019d293a8610a102e8d62c1ed6c054b759e4361d5352e268ad0c39582734ea50b00000000").unwrap()).unwrap();
        let expected_unbonding_slashing_tx = Transaction::deserialize(&hex::decode("02000000017285541c7b224b952f32eb16a815db378fc338502edcd64e09cf0eb9417f5deb0000000000ffffffff026c0700000000000016001463e2edfae6bf51aebbed63bb823c55565ab5eacee43e000000000000225120e9f60075bdb745bb352fee26ee981fd55573652a928c8e6b19db29e00f32646000000000").unwrap()).unwrap();

        let unbonding_tx = unbonding_tx(
            staker_btc_pk.parse().unwrap(),
            &[fp_pk.parse().unwrap()],
            staking_outpoint,
            staking_value,
            unbonding_time,
            &Params::bbn_test_3(),
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
            unbonding_time,
            &Params::bbn_test_3(),
        )
        .unwrap();
        assert_eq!(unbonding_slashing_tx, expected_unbonding_slashing_tx);
    }
}
