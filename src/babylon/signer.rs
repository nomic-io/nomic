use bitcoin::secp256k1::{self, KeyPair, Secp256k1};
use orga::{
    call::build_call,
    client::{wallet::Unsigned, AppClient},
    tendermint::client::HttpClient,
};

use crate::{
    app::{InnerApp, Nom},
    babylon::DelegationStatus,
    bitcoin::threshold_sig::Signature,
    error::Result,
};

use super::Delegation;

// pub async fn step(address: Address) -> Result<()> {}
// TODO: scan loop
// TODO: sign and submit pops
// TODO: sign and submit slashing sigs

pub fn sign_bbn_pop(del: &Delegation, privkey: secp256k1::SecretKey) -> Signature {
    let secp = Secp256k1::new();
    let msg = secp256k1::Message::from_slice(&del.btc_key).unwrap();
    let sig = secp.sign_ecdsa(&msg, &privkey);
    sig.serialize_compact().into()
}

pub fn sign_btc(del: &Delegation, privkey: KeyPair) -> Result<(Signature, Signature, Signature)> {
    let secp = Secp256k1::new();

    let sign = |msg| {
        let msg = secp256k1::Message::from_slice(msg).unwrap();
        let sig = secp.sign_schnorr(&msg, &privkey);
        let mut sig_bytes = [0; 64];
        sig_bytes.copy_from_slice(&sig.as_ref()[..]);
        sig_bytes.into()
    };

    Ok((
        sign(&del.pop_btc_sighash()?),
        sign(&del.slashing_sighash()?),
        sign(&del.unbonding_slashing_sighash()?),
    ))
}

#[cfg(feature = "full")]
pub async fn maybe_sign(
    del_client: AppClient<InnerApp, Delegation, HttpClient, Nom, Unsigned>,
    app_client: AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    bbn_privkey: secp256k1::SecretKey,
) -> Result<bool> {
    let delegation = del_client.query(Ok).await?;
    dbg!(&delegation);

    if delegation.status()? == DelegationStatus::Created {
        log::debug!("Delegation not ready to sign yet");
        return Ok(false);
    } else if delegation.status()? == DelegationStatus::Signed {
        log::debug!("Delegation signed, continuing");
        return Ok(true);
    }

    let bbn_sig = sign_bbn_pop(&delegation, bbn_privkey);

    log::info!("Submitting signatures...");
    app_client
        .call(
            |app| build_call!(app.sign_bbn(delegation.index, bbn_sig)),
            |app| build_call!(app.app_noop()),
        )
        .await?;

    Ok(false)
}
