use lazy_static::lazy_static;
use log::info;
use nomic_bitcoin::bitcoin;
use nomic_client::Client;
use nomic_primitives::{transaction::Transaction, Result};
use secp256k1::{Secp256k1, SecretKey, SignOnly};
use std::fs;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

lazy_static! {
    static ref SECP: Secp256k1<SignOnly> = Secp256k1::signing_only();
}

pub fn start<P: AsRef<Path>>(nomic_home: P) -> Result<()> {
    let client = Client::new("localhost:26657")?;
    let key_path = nomic_home
        .as_ref()
        .join("config")
        .join("priv_validator_key.json");
    let priv_key_json = fs::read_to_string(key_path)?;
    let priv_key_json: serde_json::Value = serde_json::from_str(&priv_key_json)?;
    let priv_key_value = &priv_key_json["priv_key"]["value"];
    let priv_key_str = priv_key_value
        .as_str()
        .expect("Invalid Tendermint private key");
    let priv_key = SecretKey::from_slice(base64::decode(priv_key_str)?.as_slice())?;

    let pub_key = secp256k1::PublicKey::from_secret_key(&SECP, &priv_key);
    println!("signatory pub key: {:?}", &pub_key.serialize()[..]);

    loop {
        try_sign(&client, &priv_key)?;
        sleep(Duration::from_secs(60));
    }
}

fn try_sign(client: &Client, priv_key: &SecretKey) -> Result<()> {
    let btc_tx = match client.get_active_checkpoint_tx()? {
        None => return Ok(()),
        Some(tx) => tx,
    };

    let signatory_set_index = client
        .state()?
        .active_checkpoint
        .signatory_set_index
        .get()?;
    let signatories = client
        .state()?
        .signatory_sets
        .get_fixed(signatory_set_index)?
        .signatories;

    let pub_key = secp256k1::PublicKey::from_secret_key(&SECP, &priv_key);

    let mut signatory_index = None;
    for (i, signatory) in signatories.iter().enumerate() {
        if signatory.pubkey.key == pub_key {
            signatory_index = Some(i);
            break;
        }
    }
    let signatory_index = match signatory_index {
        None => return Ok(()),
        Some(index) => index,
    };

    info!("Signing active checkpoint tx: {:?}", &btc_tx);

    let signatures = client
        .state()?
        .active_utxos()?
        .iter()
        .enumerate()
        .map(|(i, utxo)| {
            let script = nomic_signatory_set::redeem_script(&signatories, utxo.data.clone());
            let sighash = bitcoin::util::bip143::SighashComponents::new(&btc_tx).sighash_all(
                &btc_tx.input[i],
                &script,
                utxo.value,
            );
            let message = secp256k1::Message::from_slice(&sighash[..])?;
            let sig = SECP.sign(&message, &priv_key);
            Ok(sig.serialize_compact().to_vec())
        })
        .collect::<Result<_>>()?;

    let tx = nomic_primitives::transaction::SignatureTransaction {
        signatures,
        signatory_index: signatory_index as u16,
    };

    if let Err(err) = client.send(Transaction::Signature(tx)) {
        log::debug!("error sending signature tx: {}", err);
    }

    Ok(())
}
