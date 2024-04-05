use bitcoin::{
    secp256k1::{self, hashes::Hash, KeyPair, Secp256k1},
    util::bip32::{ChildNumber, ExtendedPrivKey},
};
use orga::{
    call::build_call,
    client::{wallet::Unsigned, AppClient, Client},
    tendermint::client::HttpClient,
};

use crate::{
    app::{InnerApp, Nom},
    babylon::DelegationStatus,
    bitcoin::threshold_sig::Pubkey,
    error::Result,
};

use super::Delegation;

// TODO: scan loop
// TODO: sign and submit pops
// TODO: sign and submit slashing sigs

pub async fn maybe_sign(
    del_client: AppClient<InnerApp, Delegation, HttpClient, Nom, Unsigned>,
    app_client: AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    bbn_privkey: secp256k1::SecretKey,
    btc_xpriv: ExtendedPrivKey,
) -> Result<bool> {
    let secp = Secp256k1::new();

    let delegation = del_client.query(Ok).await?;
    dbg!(&delegation);

    if delegation.status()? == DelegationStatus::Created {
        log::debug!("Delegation not ready to sign yet");
        return Ok(false);
    } else if delegation.status()? == DelegationStatus::Signed {
        log::debug!("Delegation signed, continuing");
        return Ok(true);
    }

    let btc_privkey = btc_xpriv
        .derive_priv(
            &secp,
            &[ChildNumber::from_normal_idx(delegation.checkpoint_index)?],
        )?
        .to_keypair(&secp);
    let btc_pubkey = btc_privkey.x_only_public_key().0;
    assert_eq!(btc_pubkey.serialize(), delegation.btc_key);

    let bbn_pubkey = bbn_privkey.public_key(&secp);

    let bbn_msg = secp256k1::Message::from_slice(&btc_pubkey.serialize()).unwrap();
    let bbn_sig = secp.sign_ecdsa(&bbn_msg, &bbn_privkey);

    let bbn_sig_hex = hex::encode(bbn_sig.serialize_compact());
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&bbn_sig_hex);
    let hash = hasher.finalize().to_vec();
    let btc_msg = secp256k1::Message::from_slice(&hash).unwrap();
    let btc_sig = secp.sign_schnorr(&btc_msg, &btc_privkey);

    let slashing_sighash = delegation.slashing_sighash()?;
    let slashing_msg = bitcoin::secp256k1::Message::from_slice(&slashing_sighash.into_inner())?;
    let slashing_sig = secp.sign_schnorr(&slashing_msg, &btc_privkey);

    let unbonding_slashing_sighash = delegation.unbonding_slashing_sighash()?;
    let us_sig = bitcoin::secp256k1::Message::from_slice(&unbonding_slashing_sighash.into_inner())?;
    let us_sig = secp.sign_schnorr(&us_sig, &btc_privkey);

    let bbn_pubkey = Pubkey::new(bbn_pubkey.serialize())?;
    let bbn_sig = bbn_sig.serialize_compact().into();
    let mut btc_sig_bytes = [0; 64];
    btc_sig_bytes.copy_from_slice(&btc_sig.as_ref()[..]);
    let mut slashing_sig_bytes = [0; 64];
    slashing_sig_bytes.copy_from_slice(&slashing_sig.as_ref()[..]);
    let mut us_sig_bytes = [0; 64];
    us_sig_bytes.copy_from_slice(&us_sig.as_ref()[..]);

    log::info!("Submitting signatures...");
    app_client
        .call(
            |app| {
                build_call!(app.babylon.sign(
                    delegation.index,
                    bbn_pubkey,
                    btc_sig_bytes.into(),
                    bbn_sig,
                    slashing_sig_bytes.into(),
                    us_sig_bytes.into()
                ))
            },
            |app| build_call!(app.app_noop()),
        )
        .await?;

    Ok(false)
}

//
//
