#![feature(async_closure)]

use bitcoind::bitcoincore_rpc::json::{
    ImportMultiRequest, ImportMultiRequestScriptPubkey, ImportMultiRescanSince,
};
use bitcoind::bitcoincore_rpc::RpcApi;
use bitcoind::{BitcoinD, Conf};
use log::info;
use nomic::app::{DepositCommitment, InnerApp, Nom};
use nomic::app_client_testnet;
use nomic::bitcoin::relayer::DepositAddress;
use nomic::bitcoin::relayer::Relayer;
use nomic::error::{Error, Result};
use nomic::utils::*;
use orga::abci::Node;
use orga::client::wallet::DerivedKey;
use orga::client::AppClient;
use orga::coins::{Address, Amount};
use orga::encoding::Encode;
use orga::macros::build_call;
use orga::plugins::load_privkey;
use orga::tendermint::client::HttpClient;
use reqwest::StatusCode;
use serial_test::serial;
use std::str::FromStr;
use std::sync::Once;
use std::time::Duration;
use tempfile::tempdir;

static INIT: Once = Once::new();

async fn generate_deposit_address(address: &Address) -> Result<DepositAddress> {
    info!("Generating deposit address for {}...", address);
    let sigset = app_client_testnet()
        .query(|app| Ok(app.bitcoin.checkpoints.active_sigset()?))
        .await?;
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

async fn deposit_bitcoin(
    address: &Address,
    btc: bitcoin::Amount,
    wallet: &bitcoind::bitcoincore_rpc::Client,
) -> Result<()> {
    let deposit_address = generate_deposit_address(address).await.unwrap();

    broadcast_deposit_addr(
        address.to_string(),
        deposit_address.sigset_index,
        "http://localhost:8999".to_string(),
        deposit_address.deposit_addr.clone(),
    )
    .await
    .unwrap();

    wallet
        .send_to_address(
            &bitcoin::Address::from_str(&deposit_address.deposit_addr).unwrap(),
            btc,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    Ok(())
}

async fn withdraw_bitcoin(
    nomic_account: &KeyData,
    usats: u64,
    dest_address: &bitcoin::Address,
) -> Result<()> {
    let key_bytes = nomic_account.privkey.secret_bytes();
    let key = orga::secp256k1::SecretKey::from_slice(&key_bytes).unwrap();
    let wallet = DerivedKey::from_secret_key(key);

    let dest_script = nomic::bitcoin::adapter::Adapter::new(dest_address.script_pubkey());
    app_client_testnet()
        .with_wallet(wallet)
        .call(
            move |app| build_call!(app.withdraw_nbtc(dest_script, Amount::from(usats))),
            |app| build_call!(app.app_noop()),
        )
        .await?;
    Ok(())
}

fn client_provider() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, DerivedKey> {
    let val_priv_key = load_privkey().unwrap();
    let wallet = DerivedKey::from_secret_key(val_priv_key);
    app_client_testnet().with_wallet(wallet)
}

#[tokio::test]
#[serial]
#[ignore]
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
    let header_relayer_path = path.clone();

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let funded_accounts = setup_test_app(&path, &block_data);

    std::thread::spawn(move || {
        info!("Starting Nomic node...");
        Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default())
            .run()
            .unwrap();
    });

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind));
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(test_bitcoin_client(&bitcoind));
    let deposits = relayer.start_deposit_relay(&header_relayer_path);

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind));
    let checkpoints = relayer.start_checkpoint_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(20)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let test = async {
        let val_priv_key = load_privkey().unwrap();
        let wallet = DerivedKey::from_secret_key(val_priv_key);
        declare_validator(&path, wallet).await.unwrap();

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();

        let withdraw_address = wallet.get_new_address(None, None).unwrap();

        let mut labels = vec![];
        for i in 0..funded_accounts.len() {
            labels.push(format!("funded-account-{}", i));
        }

        let mut import_multi_reqest = vec![];
        for (i, account) in funded_accounts.iter().enumerate() {
            import_multi_reqest.push(ImportMultiRequest {
                timestamp: ImportMultiRescanSince::Now,
                descriptor: None,
                script_pubkey: Some(ImportMultiRequestScriptPubkey::Script(&account.script)),
                redeem_script: None,
                witness_script: None,
                pubkeys: &[],
                keys: &[],
                range: None,
                internal: None,
                watchonly: Some(true),
                label: Some(&labels[i]),
                keypool: None,
            });
        }

        wallet
            .import_multi(import_multi_reqest.as_slice(), None)
            .unwrap();

        retry(
            || bitcoind.client.generate_to_address(120, &wallet_address),
            10,
        )
        .unwrap();

        poll_for_bitcoin_header(1120).await.unwrap();

        let balance = app_client_testnet()
            .query(|app| app.bitcoin.accounts.balance(funded_accounts[0].address))
            .await
            .unwrap();
        assert_eq!(balance, Amount::from(0));

        poll_for_signatory_key().await;

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(10.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        retry(
            || bitcoind.client.generate_to_address(1, &wallet_address),
            10,
        )
        .unwrap();

        poll_for_bitcoin_header(1121).await.unwrap();
        poll_for_completed_checkpoint(1).await;

        let balance = app_client_testnet()
            .query(|app| app.bitcoin.accounts.balance(funded_accounts[0].address))
            .await
            .unwrap();

        assert_eq!(balance, Amount::from(799999747200000));

        deposit_bitcoin(
            &funded_accounts[1].address,
            bitcoin::Amount::from_btc(0.4).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        retry(
            || bitcoind.client.generate_to_address(1, &wallet_address),
            10,
        )
        .unwrap();

        poll_for_bitcoin_header(1122).await.unwrap();
        poll_for_completed_checkpoint(2).await;

        let balance = app_client_testnet()
            .query(|app| app.bitcoin.accounts.balance(funded_accounts[1].address))
            .await
            .unwrap();

        assert_eq!(balance, Amount::from(31999747200000));

        withdraw_bitcoin(&funded_accounts[0], 7000000000, &withdraw_address)
            .await
            .unwrap();

        retry(
            || bitcoind.client.generate_to_address(1, &wallet_address),
            10,
        )
        .unwrap();

        poll_for_bitcoin_header(1123).await.unwrap();
        poll_for_completed_checkpoint(3).await;

        let balance = app_client_testnet()
            .query(|app| app.bitcoin.accounts.balance(funded_accounts[0].address))
            .await
            .unwrap();

        assert_eq!(balance, Amount::from(799992747200000));

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(headers, deposits, checkpoints, signer, test) {
        Err(Error::Test(_)) => (),
        Ok(_) => (),
        other => {
            other.unwrap();
        }
    }
}
