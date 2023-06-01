#![feature(async_closure)]

use bitcoin::secp256k1;
use bitcoind::bitcoincore_rpc::RpcApi;
use bitcoind::{BitcoinD, Conf};
use log::info;
use nomic::app::DepositCommitment;
use nomic::app_client;
use nomic::bitcoin::relayer::Config as RelayerConfig;
use nomic::bitcoin::relayer::DepositAddress;
use nomic::bitcoin::relayer::Relayer;
use nomic::error::{Error, Result};
use nomic::orga::prelude::Node;
use nomic::utils::{
    declare_validator, generate_sign_doc, make_std_tx, poll_for_blocks, populate_bitcoin_block,
    retry, setup_test_app, setup_test_signer, setup_time_context, test_bitcoin_client, KeyData,
};
use orga::cosmrs::crypto::secp256k1::SigningKey;
use orga::encoding::Encode;
use orga::plugins::sdk_compat::sdk::{PubKey as OrgaPubKey, Signature as OrgaSignature};
use orga::prelude::sdk_compat::sdk::{self, SignDoc};
use orga::prelude::{Address, Amount};
use reqwest::StatusCode;
use serial_test::serial;
use std::fs;
use std::str::FromStr;
use std::sync::Once;
use std::time::Duration;
use tempfile::tempdir;
use tendermint_rpc::{Client, HttpClient};

static INIT: Once = Once::new();

pub async fn withdraw(address: String, dest_addr: String, amount: u64) -> Result<SignDoc> {
    let mut value = serde_json::Map::new();
    value.insert("amount".to_string(), amount.to_string().into());
    value.insert("dst_address".to_string(), dest_addr.into());

    let address = address
        .parse()
        .map_err(|_| Error::Address("Failed to parse address".to_string()))?;
    let nonce = app_client().nonce(address).await?;

    Ok(generate_sign_doc(
        sdk::Msg {
            type_: "nomic/MsgWithdraw".to_string(),
            value: value.into(),
        },
        nonce,
    ))
}

async fn generate_deposit_address(address: &Address) -> Result<DepositAddress> {
    info!("Generating deposit address for {}...", address);
    let sigset = app_client().bitcoin.checkpoints.active_sigset().await??;
    let script = sigset.output_script(
        DepositCommitment::Address(*address)
            .commitment_bytes()?
            .as_slice(),
    )?;

    Ok(DepositAddress {
        deposit_addr: bitcoin::Address::from_script(&script, bitcoin::Network::Regtest)
            .unwrap()
            .to_string(),
        sigset_index: sigset.index(),
    })
}

pub async fn broadcast_deposit_addr(
    dest_addr: String,
    sigset_index: u32,
    relayer: String,
    deposit_addr: String,
) -> Result<()> {
    info!("Broadcasting deposit address to relayer...");
    let dest_addr = dest_addr.parse().unwrap();

    let commitment = DepositCommitment::Address(dest_addr).encode()?;

    let url = format!("{}/address", relayer,);
    let client = reqwest::Client::new();
    let res = client
        .post(url)
        .query(&[
            ("sigset_index", &sigset_index.to_string()),
            ("deposit_addr", &deposit_addr),
        ])
        .body(commitment)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::OK => Ok(()),
        _ => Err(Error::Relayer(format!(
            "Relayer response returned with error code: {}",
            res.status()
        ))),
    }
}

async fn poll_for_completed_checkpoint(num_checkpoints: u32) {
    info!("Scanning for signed checkpoints...");
    let client = app_client();

    let mut signed_checkpoint = client
        .bitcoin
        .checkpoints
        .completed()
        .await
        .unwrap()
        .unwrap();

    while signed_checkpoint.len() < num_checkpoints as usize {
        signed_checkpoint = client
            .bitcoin
            .checkpoints
            .completed()
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    info!("New signed checkpoint discovered")
}

async fn sign_and_broadcast(sign_doc: SignDoc, account: &KeyData) {
    info!("Signing transaction...");
    let sign_json = serde_json::to_vec(&sign_doc).unwrap();

    let signing_key = SigningKey::from_bytes(&account.privkey.secret_bytes()).unwrap();

    let pubkey = secp256k1::PublicKey::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &account.privkey,
    );

    let orga_pubkey = OrgaPubKey {
        type_: "tendermint/PubKeySecp256k1".to_string(),
        value: base64::encode(pubkey.serialize()),
    };

    let signature = signing_key.sign(&sign_json).unwrap();
    let orga_signature = OrgaSignature {
        pub_key: orga_pubkey,
        signature: base64::encode(signature),
        r#type: Some("sdk".to_string()),
    };

    let tx = make_std_tx(sign_doc, orga_signature);
    let tx_bytes = serde_json::to_string(&tx).unwrap();
    let tm_client = HttpClient::new("http://127.0.0.1:26657").unwrap();
    let transaction = orga::cosmrs::tendermint::abci::transaction::Transaction::from(
        tx_bytes.as_bytes().to_vec(),
    );

    info!("Broadcasting transaction...");
    tm_client.broadcast_tx_commit(transaction).await.unwrap();
}

#[tokio::test]
#[serial]
async fn bitcoin_test() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        setup_time_context();
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();

    let block_data = populate_bitcoin_block(&bitcoind);

    let home = tempdir().unwrap();
    let path = home.into_path();

    let node_path = path.clone();
    let signer_path = path.clone();
    let drop_path = path.clone();
    let header_relayer_path = path.clone();

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let funded_accounts = setup_test_app(&path, &block_data);

    std::thread::spawn(move || {
        info!("Starting Nomic node...");
        Node::<nomic::app::App>::new(&node_path, Default::default())
            .run()
            .unwrap();
    });

    let relayer_config = RelayerConfig {
        network: bitcoin::Network::Regtest,
    };

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind).await, app_client())
        .configure(relayer_config.clone());
    let headers = relayer.start_header_relay();

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind).await, app_client())
        .configure(relayer_config.clone());
    let deposits = relayer.start_deposit_relay(&header_relayer_path);

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind).await, app_client())
        .configure(relayer_config.clone());
    let checkpoints = relayer.start_checkpoint_relay();

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind).await, app_client())
        .configure(relayer_config.clone());
    let disbursal = relayer.start_emergency_disbursal_transaction_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(20)).await;
        setup_test_signer(&signer_path).start().await.unwrap();

        Ok(())
    };

    let test = async {
        poll_for_blocks().await;
        declare_validator(&path).await.unwrap();

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();

        retry(
            || bitcoind.client.generate_to_address(101, &wallet_address),
            10,
        )
        .unwrap();

        let mut retry_count = 0;
        let mut deposit_address = None;
        while deposit_address.is_none() && retry_count < 10 {
            deposit_address = generate_deposit_address(&funded_accounts[0].address)
                .await
                .ok();
            retry_count += 1;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        broadcast_deposit_addr(
            funded_accounts[0].address.to_string(),
            deposit_address.as_ref().unwrap().sigset_index,
            "http://localhost:8999".to_string(),
            deposit_address.as_ref().unwrap().deposit_addr.clone(),
        )
        .await
        .unwrap();

        retry(
            || {
                bitcoind.client.send_to_address(
                    &bitcoin::Address::from_str(&deposit_address.as_ref().unwrap().deposit_addr)
                        .unwrap(),
                    bitcoin::Amount::from_btc(10.0).unwrap(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            10,
        )
        .unwrap();

        retry(
            || bitcoind.client.generate_to_address(1, &wallet_address),
            10,
        )
        .unwrap();

        poll_for_completed_checkpoint(1).await;

        let balance = app_client()
            .bitcoin
            .accounts
            .balance(funded_accounts[0].address)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(balance, Amount::from(799999873600000));

        let withdraw_sign_doc = withdraw(
            funded_accounts[0].address.to_string(),
            wallet_address.to_string(),
            Amount::from(7000000000).into(),
        )
        .await
        .unwrap();

        sign_and_broadcast(withdraw_sign_doc, &funded_accounts[0]).await;

        retry(
            || bitcoind.client.generate_to_address(1, &wallet_address),
            10,
        )
        .unwrap();

        poll_for_completed_checkpoint(2).await;

        let balance = app_client()
            .bitcoin
            .accounts
            .balance(funded_accounts[0].address)
            .await
            .unwrap()
            .unwrap();
        dbg!(app_client().bitcoin.value_locked().await.unwrap().unwrap());

        assert_eq!(balance, Amount::from(799992873600000));

        tokio::time::sleep(Duration::from_secs(60 * 2)).await;

        let balance = app_client()
            .bitcoin
            .accounts
            .balance(funded_accounts[0].address)
            .await
            .unwrap()
            .unwrap();

        println!("Balance after disbursal: {}", balance);

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(headers, deposits, checkpoints, disbursal, signer, test) {
        Err(Error::Test(_)) => (),
        Ok(_) => (),
        other => {
            other.unwrap();
        }
    }
}
