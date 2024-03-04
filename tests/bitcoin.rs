#![feature(async_closure)]
use bitcoin::blockdata::transaction::EcdsaSighashType;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{secp256k1, Script};
use bitcoincore_rpc_async::RpcApi as AsyncRpcApi;
use bitcoind::bitcoincore_rpc::json::{
    ImportMultiRequest, ImportMultiRequestScriptPubkey, ImportMultiRescanSince,
};
use bitcoind::bitcoincore_rpc::RpcApi;
use bitcoind::{BitcoinD, Conf};
use chrono::TimeZone;
use chrono::Utc;
use futures::FutureExt;
use log::info;
use nomic::app::Dest;
use nomic::app::{InnerApp, Nom};
use nomic::bitcoin::adapter::Adapter;
use nomic::bitcoin::checkpoint::CheckpointStatus;
use nomic::bitcoin::checkpoint::Config as CheckpointConfig;
use nomic::bitcoin::deposit_index::{Deposit, DepositInfo};
use nomic::bitcoin::header_queue::Config as HeaderQueueConfig;
use nomic::bitcoin::relayer::DepositAddress;
use nomic::bitcoin::relayer::Relayer;
use nomic::bitcoin::signer::Signer;
use nomic::bitcoin::threshold_sig::Pubkey;
use nomic::bitcoin::Config as BitcoinConfig;
use nomic::error::{Error, Result};
use nomic::utils::*;
use nomic::utils::{
    declare_validator, poll_for_active_sigset, poll_for_blocks, poll_for_updated_balance,
    populate_bitcoin_block, retry, set_time, setup_test_app, setup_test_signer,
    test_bitcoin_client, NomicTestWallet,
};
use orga::abci::Node;
use orga::client::{
    wallet::{DerivedKey, Unsigned},
    AppClient,
};
use orga::coins::{Address, Amount};
use orga::encoding::Encode;
use orga::macros::build_call;
use orga::plugins::{load_privkey, Time, MIN_FEE};
use orga::tendermint::client::HttpClient;
use rand::Rng;
use reqwest::StatusCode;
use serial_test::serial;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::str::FromStr;
use std::sync::Once;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::mpsc;

static INIT: Once = Once::new();

fn app_client() -> AppClient<InnerApp, InnerApp, orga::tendermint::client::HttpClient, Nom, Unsigned>
{
    nomic::app_client("http://localhost:26657")
}

async fn generate_deposit_address(address: &Address) -> Result<DepositAddress> {
    info!("Generating deposit address for {}...", address);
    let (sigset, threshold) = app_client()
        .query(|app: InnerApp| {
            Ok((
                app.bitcoin.checkpoints.active_sigset()?,
                app.bitcoin.checkpoints.config.sigset_threshold,
            ))
        })
        .await?;
    let script = sigset.output_script(
        Dest::Address(*address).commitment_bytes()?.as_slice(),
        threshold,
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

    let commitment = Dest::Address(dest_addr).encode()?;

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
        _ => Err(Error::Relayer(format!("{}", res.text().await.unwrap()))),
    }
}

async fn set_recovery_address(nomic_account: NomicTestWallet) -> Result<()> {
    info!("Setting recovery address...");

    app_client()
        .with_wallet(nomic_account.wallet)
        .call(
            move |app| build_call!(app.accounts.take_as_funding((MIN_FEE).into())),
            move |app| {
                build_call!(app
                    .bitcoin
                    .set_recovery_script(Adapter::new(nomic_account.script.clone())))
            },
        )
        .await?;
    info!("Validator declared");
    Ok(())
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
    .await?;

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
    nomic_account: &NomicTestWallet,
    amount: bitcoin::Amount,
    dest_address: &bitcoin::Address,
) -> Result<()> {
    let dest_script = nomic::bitcoin::adapter::Adapter::new(dest_address.script_pubkey());
    let usats = amount.to_sat() * 1_000_000;
    app_client()
        .with_wallet(nomic_account.wallet.clone())
        .call(
            move |app| build_call!(app.withdraw_nbtc(dest_script, Amount::from(usats))),
            |app| build_call!(app.app_noop()),
        )
        .await?;
    Ok(())
}

async fn get_signatory_script() -> Result<Script> {
    Ok(app_client()
        .query(|app: InnerApp| {
            let tx = app.bitcoin.checkpoints.emergency_disbursal_txs()?;
            Ok(tx[0].output[1].script_pubkey.clone())
        })
        .await?)
}

fn client_provider() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, DerivedKey> {
    let val_priv_key = load_privkey().unwrap();
    let wallet = DerivedKey::from_secret_key(val_priv_key);
    app_client().with_wallet(wallet)
}

#[tokio::test]
#[serial]
#[ignore]
async fn bitcoin_test() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
        let time = Time::from_seconds(genesis_time.timestamp());
        set_time(time);
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
    let rpc_url = bitcoind.rpc_url();
    let cookie_file = bitcoind.params.cookie_file.clone();
    let btc_client = test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await;

    let block_data = populate_bitcoin_block(&btc_client).await;

    let home = tempdir().unwrap();
    let path = home.into_path();

    let node_path = path.clone();
    let signer_path = path.clone();
    let xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    fs::create_dir_all(signer_path.join("signer")).unwrap();
    fs::write(
        signer_path.join("signer/xpriv"),
        xpriv.to_string().as_bytes(),
    )
    .unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);
    let header_relayer_path = path.clone();

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let headers_config = HeaderQueueConfig {
        encoded_trusted_header: Adapter::new(block_data.block_header)
            .encode()
            .unwrap()
            .try_into()
            .unwrap(),
        trusted_height: block_data.height,
        retargeting: false,
        min_difficulty_blocks: true,
        max_length: 59,
        ..Default::default()
    };
    let funded_accounts = setup_test_app(&path, 4, Some(headers_config), None, None);

    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default());
    let _node_child = node.await.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let deposits = relayer.start_deposit_relay(&header_relayer_path, 60 * 60 * 12);

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let checkpoints = relayer.start_checkpoint_relay();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let disbursal = relayer.start_emergency_disbursal_transaction_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let (tx, mut rx) = mpsc::channel(100);
    let shutdown_listener = async {
        rx.recv().await;
        Err::<(), Error>(Error::Test("Signer shutdown initiated".to_string()))
    };

    let slashable_signer_xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    let slashable_signer_xpub = ExtendedPubKey::from_priv(
        &secp256k1::Secp256k1::new(),
        &slashable_signer_xpriv.clone(),
    );
    let slashable_signer = async {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        let signer = Signer::new(
            address_from_privkey(&funded_accounts[2].privkey),
            vec![slashable_signer_xpriv],
            0.1,
            1.0,
            0,
            None,
            || {
                let wallet = DerivedKey::from_secret_key(privkey);
                app_client().with_wallet(wallet)
            },
            None,
        )
        .start();

        match futures::try_join!(signer, shutdown_listener) {
            Err(Error::Test(_)) | Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    };

    let test = async {
        let val_priv_key = load_privkey().unwrap();
        let nomic_wallet = DerivedKey::from_secret_key(val_priv_key);
        let consensus_key = load_consensus_key(&path)?;
        declare_validator(consensus_key, nomic_wallet, 100_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(val_priv_key))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        declare_validator([0; 32], funded_accounts[2].wallet.clone(), 4_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(privkey))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(slashable_signer_xpub.into())),
            )
            .await?;

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();
        let async_wallet_address =
            bitcoincore_rpc_async::bitcoin::Address::from_str(&wallet_address.to_string()).unwrap();
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

        set_recovery_address(funded_accounts[0].clone())
            .await
            .unwrap();

        btc_client
            .generate_to_address(120, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1120).await.unwrap();

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        poll_for_active_sigset().await;
        poll_for_signatory_key(consensus_key).await;

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(10.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1124).await.unwrap();
        poll_for_signing_checkpoint().await;

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        let confirmed_index = app_client()
            .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.confirmed_index))
            .await
            .unwrap();
        assert_eq!(confirmed_index, None);

        // balance only gets updated after moving pass bitcoin header & checkpoint has completed
        poll_for_completed_checkpoint(1).await;

        // what does this do?
        tx.send(Some(())).await.unwrap();

        let expected_balance = 989996871600000;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, Amount::from(expected_balance));

        btc_client
            .generate_to_address(3, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1127).await.unwrap();

        deposit_bitcoin(
            &funded_accounts[1].address,
            bitcoin::Amount::from_btc(0.4).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1131).await.unwrap();
        poll_for_completed_checkpoint(2).await;

        let expected_balance = 39595307400000;
        let balance = poll_for_updated_balance(funded_accounts[1].address, expected_balance).await;
        assert_eq!(balance, Amount::from(expected_balance));

        println!("prepare withdrawing bitcoin");
        withdraw_bitcoin(
            &funded_accounts[0],
            bitcoin::Amount::from_sat(7000),
            &withdraw_address,
        )
        .await
        .unwrap();

        app_client()
            .with_wallet(funded_accounts[0].wallet.clone())
            .call(
                move |app| build_call!(app.accounts.take_as_funding((MIN_FEE).into())),
                move |app| build_call!(app.bitcoin.transfer_to_fee_pool(8000000000.into())),
            )
            .await?;

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1135).await.unwrap();
        poll_for_completed_checkpoint(3).await;

        let signer_jailed = app_client()
            .query(|app: InnerApp| {
                Ok(app
                    .staking
                    .all_validators()?
                    .iter()
                    .any(|val| val.address == funded_accounts[2].address.into() && val.jailed))
            })
            .await
            .unwrap();
        assert!(signer_jailed);

        let expected_balance = 989981871600000;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, Amount::from(expected_balance));

        let disbursal_txs = app_client()
            .query(|app: InnerApp| {
                Ok(app
                    .bitcoin
                    .checkpoints
                    .emergency_disbursal_txs()?
                    .iter()
                    .map(|tx| tx.txid())
                    .collect::<Vec<_>>())
            })
            .await?;

        for txid in disbursal_txs.iter() {
            let async_txid =
                bitcoincore_rpc_async::bitcoin::hash_types::Txid::from_str(&txid.to_string())
                    .unwrap();
            while btc_client
                .get_raw_transaction(&async_txid, None)
                .await
                .is_err()
            {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }

        btc_client
            .generate_to_address(1, &async_wallet_address)
            .await
            .unwrap();

        let signatory_script = get_signatory_script().await.unwrap();
        let last_header = wallet.get_best_block_hash().unwrap();
        let last_block = wallet.get_block(&last_header).unwrap();
        let txs = last_block.txdata;

        let mut signatory_balance = 0;
        for tx in txs {
            for output in tx.output.iter() {
                if output.script_pubkey == signatory_script {
                    signatory_balance = output.value;
                }
            }
        }
        assert_eq!(signatory_balance, 49994239);

        let funded_account_balances: Vec<_> = funded_accounts
            .iter()
            .map(|account| {
                let bitcoin_address =
                    &bitcoin::Address::from_script(&account.script, bitcoin::Network::Regtest)
                        .unwrap();
                match wallet.get_received_by_address(bitcoin_address, None) {
                    Ok(amount) => amount.to_sat(),
                    _ => 0,
                }
            })
            .collect();

        let expected_account_balances: Vec<u64> = vec![989980029, 0, 0, 0];
        assert_eq!(funded_account_balances, expected_account_balances);

        for (i, account) in funded_accounts[0..1].iter().enumerate() {
            let dump_address = wallet.get_new_address(None, None).unwrap();
            let disbursal_txs: Vec<Adapter<bitcoin::Transaction>> = app_client()
                .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.emergency_disbursal_txs()?))
                .await
                .unwrap();

            let spending_tx = disbursal_txs
                .iter()
                .find(|tx| {
                    tx.output
                        .iter()
                        .any(|output| output.script_pubkey == account.script)
                })
                .unwrap();

            let vout = spending_tx
                .output
                .iter()
                .position(|output| output.script_pubkey == account.script)
                .unwrap();

            let tx_in = bitcoind::bitcoincore_rpc::json::CreateRawTransactionInput {
                txid: spending_tx.txid(),
                vout: vout.try_into().unwrap(),
                sequence: None,
            };
            let mut outputs = HashMap::new();
            outputs.insert(
                dump_address.to_string(),
                bitcoin::Amount::from_sat(expected_account_balances[i] - 10000),
            );

            let tx = bitcoind
                .client
                .create_raw_transaction(&[tx_in], &outputs, None, None)
                .unwrap();

            let privkey = bitcoin::PrivateKey::new(account.privkey, bitcoin::Network::Regtest);
            let sign_res = bitcoind
                .client
                .sign_raw_transaction_with_key(
                    &tx,
                    &[privkey],
                    None,
                    Some(EcdsaSighashType::All.into()),
                )
                .unwrap();
            let signed_tx: bitcoin::Transaction = sign_res.transaction().unwrap();

            btc_client.send_raw_transaction(&signed_tx).await.unwrap();

            btc_client
                .generate_to_address(1, &async_wallet_address)
                .await
                .unwrap();

            let sent_amount = match wallet.get_received_by_address(&dump_address, None) {
                Ok(amount) => amount.to_sat(),
                _ => 0,
            };

            assert_eq!(sent_amount, expected_account_balances[i] - 10000);
        }

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(
        headers,
        deposits,
        checkpoints,
        disbursal,
        signer,
        slashable_signer,
        test
    ) {
        Err(Error::Test(_)) => (),
        Ok(_) => (),
        other => {
            other.unwrap();
        }
    }
}

#[tokio::test]
#[serial]
#[ignore]
async fn signing_completed_checkpoint_test() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
        let time = Time::from_seconds(genesis_time.timestamp());
        set_time(time);
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
    let rpc_url = bitcoind.rpc_url();
    let cookie_file = bitcoind.params.cookie_file.clone();
    let btc_client = test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await;

    let block_data = populate_bitcoin_block(&btc_client).await;

    let home = tempdir().unwrap();
    let path = home.into_path();

    let node_path = path.clone();
    let signer_path = path.clone();
    let xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    fs::create_dir_all(signer_path.join("signer")).unwrap();
    fs::write(
        signer_path.join("signer/xpriv"),
        xpriv.to_string().as_bytes(),
    )
    .unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);
    let header_relayer_path = path.clone();

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let headers_config = HeaderQueueConfig {
        encoded_trusted_header: Adapter::new(block_data.block_header)
            .encode()
            .unwrap()
            .try_into()
            .unwrap(),
        trusted_height: block_data.height,
        retargeting: false,
        min_difficulty_blocks: true,
        max_length: 59,
        ..Default::default()
    };
    let bitcoin_config = BitcoinConfig {
        max_offline_checkpoints: 20,
        ..Default::default()
    };
    let funded_accounts =
        setup_test_app(&path, 4, Some(headers_config), None, Some(bitcoin_config));

    info!("Starting Nomic node...");
    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default()).await;
    let node_child = node.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let deposits = relayer.start_deposit_relay(&header_relayer_path, 60 * 60 * 12);

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let checkpoints = relayer.start_checkpoint_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let (tx, mut rx) = mpsc::channel(100);
    let shutdown_listener = async {
        rx.recv().await;
        Err::<(), Error>(Error::Test("Signer shutdown initiated".to_string()))
    };

    let slashable_xpriv_seed: [u8; 32] = rand::thread_rng().gen();

    let slashable_signer = async {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let xpriv =
            ExtendedPrivKey::new_master(bitcoin::Network::Testnet, slashable_xpriv_seed.as_slice())
                .unwrap();
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        let signer = Signer::new(
            address_from_privkey(&funded_accounts[2].privkey),
            vec![xpriv],
            0.1,
            1.0,
            0,
            None,
            || {
                let wallet = DerivedKey::from_secret_key(privkey);
                app_client().with_wallet(wallet)
            },
            None,
        )
        .start();

        match futures::try_join!(signer, shutdown_listener) {
            Err(Error::Test(_)) | Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    };

    let slashable_signer_2 = {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let xpriv =
            ExtendedPrivKey::new_master(bitcoin::Network::Testnet, slashable_xpriv_seed.as_slice())
                .unwrap();
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        Signer::new(
            address_from_privkey(&funded_accounts[2].privkey),
            vec![xpriv],
            0.1,
            1.0,
            0,
            None,
            move || {
                let wallet = DerivedKey::from_secret_key(privkey);
                app_client().with_wallet(wallet)
            },
            None,
        )
        .start()
    };

    let test = async {
        let val_priv_key = load_privkey().unwrap();
        let nomic_wallet = DerivedKey::from_secret_key(val_priv_key);
        let consensus_key = load_consensus_key(&path)?;
        declare_validator(consensus_key, nomic_wallet, 100_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(val_priv_key))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let xpriv =
            ExtendedPrivKey::new_master(bitcoin::Network::Testnet, slashable_xpriv_seed.as_slice())
                .unwrap();
        let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        declare_validator([0; 32], funded_accounts[2].wallet.clone(), 4_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(privkey))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();
        let async_wallet_address =
            bitcoincore_rpc_async::bitcoin::Address::from_str(&wallet_address.to_string()).unwrap();

        btc_client
            .generate_to_address(120, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1120).await.unwrap();

        poll_for_signatory_key(consensus_key).await;
        poll_for_signatory_key([0; 32]).await;
        tx.send(Some(())).await.unwrap();

        for i in 0..3 {
            deposit_bitcoin(
                &funded_accounts[0].address,
                bitcoin::Amount::from_btc(1.0).unwrap(),
                &wallet,
            )
            .await
            .unwrap();

            btc_client
                .generate_to_address(4, &async_wallet_address)
                .await
                .unwrap();
            poll_for_bitcoin_header(1120 + (i + 1) * 4).await.unwrap();

            poll_for_completed_checkpoint(i + 1).await;
        }

        let checkpoint_txs = app_client()
            .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.completed_txs(20)?))
            .await
            .unwrap();
        let pre_tx_sizes = checkpoint_txs
            .iter()
            .map(|tx| tx.vsize())
            .collect::<Vec<_>>();

        tokio::spawn(slashable_signer_2);
        tokio::time::sleep(Duration::from_secs(30)).await;

        let checkpoint_txs = app_client()
            .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.completed_txs(20)?))
            .await
            .unwrap();
        let post_tx_sizes = checkpoint_txs
            .iter()
            .map(|tx| tx.vsize())
            .collect::<Vec<_>>();

        let signatory_lengths = app_client()
            .query(|app: InnerApp| {
                Ok(app
                    .bitcoin
                    .checkpoints
                    .all()?
                    .iter()
                    .filter_map(|checkpoint| {
                        if checkpoint.1.status != CheckpointStatus::Complete {
                            return None;
                        }
                        Some(checkpoint.1.sigset.signatories.len().clone())
                    })
                    .collect::<Vec<_>>())
            })
            .await
            .unwrap();

        for (i, length) in signatory_lengths.iter().enumerate() {
            if length == &(2 as usize) {
                assert!(post_tx_sizes[i] > pre_tx_sizes[i]);
            }
        }

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(
        headers,
        deposits,
        checkpoints,
        signer,
        slashable_signer,
        test
    ) {
        Err(Error::Test(_)) => (),
        Ok(_) => (),
        other => {
            other.unwrap();
        }
    }
}

#[tokio::test]
#[serial]
#[ignore]
async fn pending_deposits() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        set_time(0);
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
    let rpc_url = bitcoind.rpc_url();
    let cookie_file = bitcoind.params.cookie_file.clone();
    let btc_client = test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await;

    let block_data = populate_bitcoin_block(&btc_client).await;

    let home = tempdir().unwrap();
    let path = home.into_path();

    let node_path = path.clone();
    let signer_path = path.clone();
    let xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    fs::create_dir_all(signer_path.join("signer")).unwrap();
    fs::write(
        signer_path.join("signer/xpriv"),
        xpriv.to_string().as_bytes(),
    )
    .unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);
    let header_relayer_path = path.clone();

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let headers_config = HeaderQueueConfig {
        encoded_trusted_header: Adapter::new(block_data.block_header)
            .encode()
            .unwrap()
            .try_into()
            .unwrap(),
        trusted_height: block_data.height,
        retargeting: false,
        min_difficulty_blocks: true,
        max_length: 59,
        ..Default::default()
    };
    let bitcoin_config = BitcoinConfig {
        min_confirmations: 3,
        ..Default::default()
    };
    let funded_accounts =
        setup_test_app(&path, 4, Some(headers_config), None, Some(bitcoin_config));

    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default());
    let node_child = node.await.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let deposits = relayer.start_deposit_relay(&header_relayer_path, 60 * 60 * 12);

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let checkpoints = relayer.start_checkpoint_relay();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let disbursal = relayer.start_emergency_disbursal_transaction_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(15)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let test = async {
        let val_priv_key = load_privkey().unwrap();
        let nomic_wallet = DerivedKey::from_secret_key(val_priv_key);
        let consensus_key = load_consensus_key(&path)?;
        declare_validator(consensus_key, nomic_wallet, 100_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(val_priv_key))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();
        let async_wallet_address =
            bitcoincore_rpc_async::bitcoin::Address::from_str(&wallet_address.to_string()).unwrap();

        btc_client
            .generate_to_address(120, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1120).await.unwrap();

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        poll_for_active_sigset().await;
        poll_for_signatory_key(consensus_key).await;

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(10.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        loop {
            let deposits = reqwest::get(format!(
                "http://localhost:8999/pending_deposits?receiver={}",
                &funded_accounts[0].address
            ))
            .await
            .unwrap()
            .json::<Vec<DepositInfo>>()
            .await
            .unwrap();

            if !deposits.is_empty() {
                break;
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        for i in 0..=4 {
            let deposits = reqwest::get(format!(
                "http://localhost:8999/pending_deposits?receiver={}",
                &funded_accounts[0].address
            ))
            .await
            .unwrap()
            .json::<Vec<DepositInfo>>()
            .await
            .unwrap();

            let deposit_info = deposits.get(0).unwrap();

            assert_eq!(i, deposit_info.confirmations);

            btc_client
                .generate_to_address(1, &async_wallet_address)
                .await
                .unwrap();

            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        let deposits = reqwest::get(format!(
            "http://localhost:8999/pending_deposits?receiver={}",
            &funded_accounts[0].address
        ))
        .await
        .unwrap()
        .json::<Vec<DepositInfo>>()
        .await
        .unwrap();

        assert!(deposits.is_empty());

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

#[tokio::test]
#[serial]
#[ignore]
async fn signer_key_updating() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
        let time = Time::from_seconds(genesis_time.timestamp());
        set_time(time);
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
    let rpc_url = bitcoind.rpc_url();
    let cookie_file = bitcoind.params.cookie_file.clone();
    let btc_client = test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await;

    let block_data = populate_bitcoin_block(&btc_client).await;

    let home = tempdir().unwrap();
    let path = home.into_path();

    let node_path = path.clone();
    let signer_path = path.clone();
    let header_relayer_path = path.clone();

    let seed: [u8; 32] = rand::thread_rng().gen();
    let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Testnet, seed.as_slice()).unwrap();
    fs::create_dir_all(signer_path.join("signer")).unwrap();
    fs::write(
        signer_path.join("signer/xpriv"),
        xpriv.to_string().as_bytes(),
    )
    .unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let headers_config = HeaderQueueConfig {
        encoded_trusted_header: Adapter::new(block_data.block_header)
            .encode()
            .unwrap()
            .try_into()
            .unwrap(),
        trusted_height: block_data.height,
        retargeting: false,
        min_difficulty_blocks: true,
        max_length: 59,
        ..Default::default()
    };
    let funded_accounts = setup_test_app(&path, 4, Some(headers_config), None, None);

    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default());
    let _node_child = node.await.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let deposits = relayer.start_deposit_relay(&header_relayer_path, 60 * 60 * 12);

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let checkpoints = relayer.start_checkpoint_relay();

    let (tx, mut rx) = mpsc::channel(100);
    let shutdown_listener = async {
        rx.recv().await;
        Err::<(), Error>(Error::Test("Signer shutdown initiated".to_string()))
    };

    let signer = async {
        tokio::time::sleep(Duration::from_secs(15)).await;

        let tm_privkey_bytes = std::fs::read(signer_path.join(".orga-wallet/privkey")).unwrap();
        let tm_privkey =
            orga::secp256k1::SecretKey::from_slice(tm_privkey_bytes.as_slice()).unwrap();
        let pubkey = orga::secp256k1::PublicKey::from_secret_key(
            &orga::secp256k1::Secp256k1::new(),
            &tm_privkey,
        );

        let signer = Signer::new(
            Address::from_pubkey(pubkey.serialize()),
            vec![xpriv],
            0.1,
            1.0,
            0,
            None,
            client_provider,
            None,
        )
        .start();

        match futures::try_join!(signer, shutdown_listener) {
            Err(Error::Test(_)) | Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    };

    let test = async {
        let val_priv_key = load_privkey().unwrap();
        let nomic_wallet = DerivedKey::from_secret_key(val_priv_key);
        let consensus_key = load_consensus_key(&path)?;
        declare_validator(consensus_key, nomic_wallet, 100_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(val_priv_key))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();
        let async_wallet_address =
            bitcoincore_rpc_async::bitcoin::Address::from_str(&wallet_address.to_string()).unwrap();

        btc_client
            .generate_to_address(120, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1120).await.unwrap();

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        poll_for_active_sigset().await;
        poll_for_signatory_key(consensus_key).await;

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(10.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1124).await.unwrap();
        poll_for_signing_checkpoint().await;

        poll_for_completed_checkpoint(1).await;

        let completed_checkpoint_0_pubkey = app_client()
            .query(|app| {
                let last_completed = app.bitcoin.checkpoints.last_completed()?;
                assert!(last_completed.sigset.signatories.len() == 1);
                Ok(last_completed.sigset.signatories.get(0).unwrap().pubkey)
            })
            .await
            .unwrap();

        let derived_public_key_0 = xpub
            .derive_pub(
                &secp256k1::Secp256k1::new(),
                &[ChildNumber::from_normal_idx(0)?],
            )
            .unwrap()
            .public_key;

        assert_eq!(
            completed_checkpoint_0_pubkey,
            Pubkey::from(derived_public_key_0)
        );

        let building_checkpoint_1_pubkey = app_client()
            .query(|app| {
                let building = app.bitcoin.checkpoints.building()?;
                assert!(building.sigset.signatories.len() == 1);
                Ok(building.sigset.signatories.get(0).unwrap().pubkey)
            })
            .await
            .unwrap();

        let derived_public_key_1 = xpub
            .derive_pub(
                &secp256k1::Secp256k1::new(),
                &[ChildNumber::from_normal_idx(1)?],
            )
            .unwrap()
            .public_key;

        assert_eq!(
            building_checkpoint_1_pubkey,
            Pubkey::from(derived_public_key_1)
        );

        tx.send(Some(())).await.unwrap();

        let seed: [u8; 32] = rand::thread_rng().gen();
        let new_xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Testnet, seed.as_slice())?;
        fs::write(
            signer_path.join("signer/xpriv-new"),
            new_xpriv.to_string().as_bytes(),
        )?;
        let new_xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &new_xpriv);

        client_provider()
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(new_xpub.into())),
            )
            .await?;

        let new_key_signer = {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let tm_privkey_bytes = std::fs::read(signer_path.join(".orga-wallet/privkey"))?;
            let tm_privkey = secp256k1::SecretKey::from_slice(tm_privkey_bytes.as_slice()).unwrap();
            let tm_pubkey =
                secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &tm_privkey);

            Signer::new(
                Address::from_pubkey(tm_pubkey.serialize()),
                vec![new_xpriv, xpriv],
                0.1,
                1.0,
                0,
                None,
                client_provider,
                None,
            )
            .start()
        };

        tokio::spawn(new_key_signer);
        tokio::time::sleep(Duration::from_secs(30)).await;

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(0.1).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1128).await.unwrap();
        poll_for_signing_checkpoint().await;
        poll_for_completed_checkpoint(2).await;

        let completed_checkpoint_1_pubkey = app_client()
            .query(|app| {
                let last_completed = app.bitcoin.checkpoints.last_completed()?;
                assert!(last_completed.sigset.signatories.len() == 1);
                Ok(last_completed.sigset.signatories.get(0).unwrap().pubkey)
            })
            .await
            .unwrap();

        assert_eq!(
            completed_checkpoint_1_pubkey,
            Pubkey::from(derived_public_key_1)
        );

        let building_checkpoint_2_pubkey = app_client()
            .query(|app| {
                let building = app.bitcoin.checkpoints.building()?;
                assert!(building.sigset.signatories.len() == 1);
                Ok(building.sigset.signatories.get(0).unwrap().pubkey)
            })
            .await
            .unwrap();

        let derived_public_key_2 = new_xpub
            .derive_pub(
                &secp256k1::Secp256k1::new(),
                &[ChildNumber::from_normal_idx(2)?],
            )
            .unwrap()
            .public_key;

        assert_eq!(
            building_checkpoint_2_pubkey,
            Pubkey::from(derived_public_key_2)
        );

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(0.1).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1132).await.unwrap();
        poll_for_signing_checkpoint().await;
        poll_for_completed_checkpoint(3).await;

        let completed_checkpoint_2_pubkey = app_client()
            .query(|app| {
                let last_completed = app.bitcoin.checkpoints.last_completed()?;
                assert!(last_completed.sigset.signatories.len() == 1);
                Ok(last_completed.sigset.signatories.get(0).unwrap().pubkey)
            })
            .await
            .unwrap();

        assert_eq!(
            completed_checkpoint_2_pubkey,
            Pubkey::from(derived_public_key_2)
        );

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

#[tokio::test]
#[serial]
#[ignore]
async fn recover_expired_deposit() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
        let time = Time::from_seconds(genesis_time.timestamp());
        set_time(time);
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
    let rpc_url = bitcoind.rpc_url();
    let cookie_file = bitcoind.params.cookie_file.clone();
    let btc_client = test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await;

    let block_data = populate_bitcoin_block(&btc_client).await;

    let home = tempdir().unwrap();
    let path = home.into_path();

    let node_path = path.clone();
    let signer_path = path.clone();
    let header_relayer_path = path.clone();

    let xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    fs::create_dir_all(signer_path.join("signer")).unwrap();
    fs::write(
        signer_path.join("signer/xpriv"),
        xpriv.to_string().as_bytes(),
    )
    .unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let headers_config = HeaderQueueConfig {
        encoded_trusted_header: Adapter::new(block_data.block_header)
            .encode()
            .unwrap()
            .try_into()
            .unwrap(),
        trusted_height: block_data.height,
        retargeting: false,
        min_difficulty_blocks: true,
        max_length: 59,
        ..Default::default()
    };

    let checkpoint_config = CheckpointConfig {
        min_checkpoint_interval: 15,
        emergency_disbursal_lock_time_interval: 100 * 60,
        ..Default::default()
    };

    let funded_accounts = setup_test_app(
        &path,
        4,
        Some(headers_config),
        Some(checkpoint_config),
        None,
    );

    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default());
    let node_child = node.await.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let deposits = relayer.start_deposit_relay(&header_relayer_path, 60 * 60 * 12);

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let recovery_txs = relayer.start_recovery_tx_relay(&header_relayer_path);

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let checkpoints = relayer.start_checkpoint_relay();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let disbursal = relayer.start_emergency_disbursal_transaction_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let test = async {
        let val_priv_key = load_privkey().unwrap();
        let nomic_wallet = DerivedKey::from_secret_key(val_priv_key);
        let consensus_key = load_consensus_key(&path)?;
        declare_validator(consensus_key, nomic_wallet.clone(), 100_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(nomic_wallet.clone())
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();
        let async_wallet_address =
            bitcoincore_rpc_async::bitcoin::Address::from_str(&wallet_address.to_string()).unwrap();

        set_recovery_address(funded_accounts[0].clone())
            .await
            .unwrap();

        btc_client
            .generate_to_address(120, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1120).await.unwrap();

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        poll_for_active_sigset().await;
        poll_for_signatory_key(consensus_key).await;

        let expiring_deposit_address = generate_deposit_address(&funded_accounts[1].address)
            .await
            .unwrap();

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(5.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1124).await.unwrap();
        poll_for_completed_checkpoint(1).await;

        let sent_txid = wallet
            .send_to_address(
                &bitcoin::Address::from_str(&expiring_deposit_address.deposit_addr).unwrap(),
                bitcoin::Amount::from_btc(0.4).unwrap(),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        println!("sent_txid: {:?}", sent_txid);

        btc_client
            .generate_to_address(6, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1130).await.unwrap();

        tokio::time::sleep(Duration::from_secs(90)).await;
        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(5.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1134).await.unwrap();
        poll_for_completed_checkpoint(2).await;
        // tokio::time::sleep(Duration::from_secs(90)).await;

        broadcast_deposit_addr(
            funded_accounts[1].address.to_string(),
            expiring_deposit_address.sigset_index,
            "http://localhost:8999".to_string(),
            expiring_deposit_address.deposit_addr.clone(),
        )
        .await?;

        btc_client
            .generate_to_address(1, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1135).await.unwrap();

        btc_client
            .generate_to_address(50, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1185).await.unwrap();
        poll_for_completed_checkpoint(3).await;

        let expected_balance = 39596871600000;
        let balance = poll_for_updated_balance(funded_accounts[1].address, expected_balance).await;
        assert_eq!(balance, Amount::from(expected_balance));

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(
        headers,
        deposits,
        recovery_txs,
        checkpoints,
        disbursal,
        signer,
        test
    ) {
        Err(Error::Test(_)) => (),
        Ok(_) => (),
        other => {
            other.unwrap();
        }
    }
}

#[tokio::test]
#[serial]
#[ignore]
async fn generate_deposit_expired() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
        let time = Time::from_seconds(genesis_time.timestamp());
        set_time(time);
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
    let rpc_url = bitcoind.rpc_url();
    let cookie_file = bitcoind.params.cookie_file.clone();
    let btc_client = test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await;

    let block_data = populate_bitcoin_block(&btc_client).await;

    let home = tempdir().unwrap();
    let path = home.into_path();

    let node_path = path.clone();
    let signer_path = path.clone();
    let header_relayer_path = path.clone();

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let headers_config = HeaderQueueConfig {
        encoded_trusted_header: Adapter::new(block_data.block_header)
            .encode()
            .unwrap()
            .try_into()
            .unwrap(),
        trusted_height: block_data.height,
        retargeting: false,
        min_difficulty_blocks: true,
        max_length: 59,
        ..Default::default()
    };

    let bitcoin_config = BitcoinConfig {
        max_deposit_age: 60 * 5,
        ..Default::default()
    };

    let funded_accounts =
        setup_test_app(&path, 4, Some(headers_config), None, Some(bitcoin_config));

    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default());
    let node_child = node.await.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let deposits = relayer.start_deposit_relay(&header_relayer_path, 5 * 60);

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let checkpoints = relayer.start_checkpoint_relay();

    let xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    fs::create_dir_all(signer_path.join("signer")).unwrap();
    fs::write(
        signer_path.join("signer/xpriv"),
        xpriv.to_string().as_bytes(),
    )
    .unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);

    let signer = async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let test = async {
        let val_priv_key = load_privkey().unwrap();
        let nomic_wallet = DerivedKey::from_secret_key(val_priv_key);
        let consensus_key = load_consensus_key(&path)?;
        declare_validator(consensus_key, nomic_wallet.clone(), 100_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(nomic_wallet.clone())
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();
        let async_wallet_address =
            bitcoincore_rpc_async::bitcoin::Address::from_str(&wallet_address.to_string()).unwrap();

        btc_client
            .generate_to_address(120, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1120).await.unwrap();

        let balance = app_client()
            .query(|app| app.bitcoin.accounts.balance(funded_accounts[0].address))
            .await
            .unwrap();
        assert_eq!(balance, Amount::from(0));

        poll_for_active_sigset().await;
        poll_for_signatory_key(consensus_key).await;

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(10.0).unwrap(),
            &wallet,
        )
        .await?;

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(headers, deposits, checkpoints, signer, test) {
        Err(Error::Test(_)) => panic!("Test failed to fail on deposit address generation"),
        Err(Error::Relayer(e)) => {
            if !e.to_string().contains("Unable to generate deposit address") {
                panic!("Unexpected error: {}", e);
            }
        }
        Ok(_) => panic!("Expected error"),
        other => {
            other.unwrap();
        }
    }
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_emergency_disbursal() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
        let time = Time::from_seconds(genesis_time.timestamp());
        set_time(time);
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
    let rpc_url = bitcoind.rpc_url();
    let cookie_file = bitcoind.params.cookie_file.clone();
    let btc_client = test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await;

    let block_data = populate_bitcoin_block(&btc_client).await;

    let home = tempdir().unwrap();
    let path = home.into_path();

    let node_path = path.clone();
    let signer_path = path.clone();
    let xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    fs::create_dir_all(signer_path.join("signer")).unwrap();
    fs::write(
        signer_path.join("signer/xpriv"),
        xpriv.to_string().as_bytes(),
    )
    .unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);
    let header_relayer_path = path.clone();

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let headers_config = HeaderQueueConfig {
        encoded_trusted_header: Adapter::new(block_data.block_header)
            .encode()
            .unwrap()
            .try_into()
            .unwrap(),
        trusted_height: block_data.height,
        retargeting: false,
        min_difficulty_blocks: true,
        max_length: 59,
        ..Default::default()
    };
    let checkpoint_config = CheckpointConfig {
        min_checkpoint_interval: 5,
        emergency_disbursal_lock_time_interval: 10,
        ..Default::default()
    };
    let funded_accounts = setup_test_app(
        &path,
        4,
        Some(headers_config),
        Some(checkpoint_config),
        None,
    );

    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default());
    let _node_child = node.await.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let deposits = relayer.start_deposit_relay(&header_relayer_path, 60 * 60 * 12);

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let checkpoints = relayer.start_checkpoint_relay();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );

    let signer = async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let (tx, mut rx) = mpsc::channel(100);
    let shutdown_listener = async {
        rx.recv().await;
        Err::<(), Error>(Error::Test("Signer shutdown initiated".to_string()))
    };

    let slashable_signer_xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    let slashable_signer_xpub = ExtendedPubKey::from_priv(
        &secp256k1::Secp256k1::new(),
        &slashable_signer_xpriv.clone(),
    );
    let slashable_signer = async {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        let signer = Signer::new(
            address_from_privkey(&funded_accounts[2].privkey),
            vec![slashable_signer_xpriv],
            0.1,
            1.0,
            0,
            None,
            || {
                let wallet = DerivedKey::from_secret_key(privkey);
                app_client().with_wallet(wallet)
            },
            None,
        )
        .start();

        match futures::try_join!(signer, shutdown_listener) {
            Err(Error::Test(_)) | Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    };

    let test = async {
        let val_priv_key = load_privkey().unwrap();
        let nomic_wallet = DerivedKey::from_secret_key(val_priv_key);
        let consensus_key = load_consensus_key(&path)?;
        declare_validator(consensus_key, nomic_wallet, 100_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(val_priv_key))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        declare_validator([0; 32], funded_accounts[2].wallet.clone(), 4_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(privkey))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(slashable_signer_xpub.into())),
            )
            .await?;

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();
        let async_wallet_address =
            bitcoincore_rpc_async::bitcoin::Address::from_str(&wallet_address.to_string()).unwrap();
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

        set_recovery_address(funded_accounts[0].clone())
            .await
            .unwrap();

        btc_client
            .generate_to_address(120, &async_wallet_address)
            .await
            .unwrap();

        // populate_bitcoin_block populates 1000 blocks of bitcoin initially
        poll_for_bitcoin_header(1120).await.unwrap();

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        poll_for_active_sigset().await;
        poll_for_signatory_key(consensus_key).await;

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(10.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1124).await.unwrap();
        poll_for_signing_checkpoint().await;

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        let confirmed_index = app_client()
            .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.confirmed_index))
            .await
            .unwrap();
        assert_eq!(confirmed_index, None);

        // balance only gets updated after moving pass bitcoin header & checkpoint has completed
        poll_for_completed_checkpoint(1).await;

        // what does this do? => This will send some signal to recv to make the signer 2 stop
        // after enough time, the signer 2 will be slashed
        tx.send(Some(())).await.unwrap();

        let expected_balance = 989996871600000;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, Amount::from(expected_balance));

        // Now we need to mock a new signing checkpoint and don't let it complete before the emergency disbursal
        println!(
            "funded account bitcoin address: {:?}",
            funded_accounts[0].bitcoin_address()
        );
        println!(
            "address type: {:?}",
            funded_accounts[0].bitcoin_address().address_type()
        );

        btc_client
            .generate_to_address(130, &async_wallet_address)
            .await
            .unwrap();
        poll_for_bitcoin_header(1130).await.unwrap();
        tokio::time::sleep(Duration::from_secs(20)).await;
        let mut relayed = HashSet::new();
        let funded_bitcoin_address = funded_accounts[0].bitcoin_address();
        let funded_bitcoin_wallet =
            retry(|| bitcoind.create_wallet("nomic-funded-bitcoin-wallet"), 10).unwrap();
        funded_bitcoin_wallet
            .import_address(&funded_bitcoin_address, Some("funded"), None)
            .unwrap();
        let btc_balances = funded_bitcoin_wallet.get_balances().unwrap();
        println!(
            "my btc balances before emergency disbursal: {:?}",
            btc_balances.mine
        );
        // before emergency disbursal -> should be zero in balance
        assert_eq!(btc_balances.mine.immature, bitcoin::Amount::default());
        assert_eq!(btc_balances.mine.trusted, bitcoin::Amount::default());
        assert_eq!(
            btc_balances.mine.untrusted_pending,
            bitcoin::Amount::default()
        );
        let watch_only = btc_balances.watchonly.unwrap();
        assert_eq!(watch_only.clone().immature, bitcoin::Amount::default());
        assert_eq!(watch_only.clone().trusted, bitcoin::Amount::default());
        assert_eq!(
            watch_only.clone().untrusted_pending,
            bitcoin::Amount::default()
        );

        // fixture
        let mut disbursal_amount_sat: u64 = 0;
        let disbursal_txs: Vec<Adapter<bitcoin::Transaction>> = app_client()
            .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.emergency_disbursal_txs()?))
            .await
            .unwrap();

        for tx in disbursal_txs.clone() {
            let mut will_break = false;
            for output in tx.output.clone() {
                let address =
                    bitcoin::Address::from_script(&output.script_pubkey, bitcoin::Network::Regtest)
                        .unwrap();
                if address.eq(&funded_bitcoin_address) {
                    // collect disbursal amount of our funded account in the case of emergency disbursal.
                    // The amount should match with the btc balance after disbursal
                    disbursal_amount_sat = output.value;
                    will_break = true;
                    break;
                }
            }
            if will_break {
                break;
            }
        }

        // action
        relayer
            .relay_emergency_disbursal_transactions(&mut relayed)
            .await
            .unwrap();

        let btc_balances = funded_bitcoin_wallet.get_balances().unwrap();
        println!("btc balances after emergency disbursal: {:?}", btc_balances);
        assert_eq!(
            btc_balances.watchonly.unwrap().untrusted_pending.to_sat(),
            disbursal_amount_sat
        );

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(
        headers,
        deposits,
        checkpoints,
        signer,
        slashable_signer,
        test
    ) {
        Err(Error::Test(_)) => (),
        Ok(_) => (),
        other => {
            other.unwrap();
        }
    }
}

#[tokio::test]
#[serial]
#[ignore]
/***
 * Thís will test withdraw 2 times:
 * + Deposit 10 BTC => withdraw 3 BTC
 * + Deposit 5 BTC + 2 BTC => withdraw 13 BTC
 */
async fn test_withdraw() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
        let time = Time::from_seconds(genesis_time.timestamp());
        set_time(time);
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
    let rpc_url = bitcoind.rpc_url();
    let cookie_file = bitcoind.params.cookie_file.clone();
    let btc_client = test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await;

    let block_data = populate_bitcoin_block(&btc_client).await;

    let home = tempdir().unwrap();
    let path = home.into_path();

    let node_path = path.clone();
    let signer_path = path.clone();
    let xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    fs::create_dir_all(signer_path.join("signer")).unwrap();
    fs::write(
        signer_path.join("signer/xpriv"),
        xpriv.to_string().as_bytes(),
    )
    .unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);
    let header_relayer_path = path.clone();

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let headers_config = HeaderQueueConfig {
        encoded_trusted_header: Adapter::new(block_data.block_header)
            .encode()
            .unwrap()
            .try_into()
            .unwrap(),
        trusted_height: block_data.height,
        retargeting: false,
        min_difficulty_blocks: true,
        max_length: 59,
        ..Default::default()
    };
    let checkpoint_config = CheckpointConfig {
        emergency_disbursal_lock_time_interval: 10 * 60,
        ..Default::default()
    };
    let funded_accounts = setup_test_app(
        &path,
        4,
        Some(headers_config),
        Some(checkpoint_config),
        None,
    );

    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default());
    let _node_child = node.await.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let deposits = relayer.start_deposit_relay(&header_relayer_path, 60 * 60 * 12);

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let checkpoints = relayer.start_checkpoint_relay();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let disbursal = relayer.start_emergency_disbursal_transaction_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let (tx, mut rx) = mpsc::channel(100);
    let shutdown_listener = async {
        rx.recv().await;
        Err::<(), Error>(Error::Test("Signer shutdown initiated".to_string()))
    };

    let slashable_signer_xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    let slashable_signer_xpub = ExtendedPubKey::from_priv(
        &secp256k1::Secp256k1::new(),
        &slashable_signer_xpriv.clone(),
    );
    let slashable_signer = async {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        let signer = Signer::new(
            address_from_privkey(&funded_accounts[2].privkey),
            vec![slashable_signer_xpriv],
            0.1,
            1.0,
            0,
            None,
            || {
                let wallet = DerivedKey::from_secret_key(privkey);
                app_client().with_wallet(wallet)
            },
            None,
        )
        .start();

        match futures::try_join!(signer, shutdown_listener) {
            Err(Error::Test(_)) | Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    };

    let test = async {
        let val_priv_key = load_privkey().unwrap();
        let nomic_wallet = DerivedKey::from_secret_key(val_priv_key);
        let consensus_key = load_consensus_key(&path)?;
        declare_validator(consensus_key, nomic_wallet, 100_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(val_priv_key))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        declare_validator([0; 32], funded_accounts[2].wallet.clone(), 4_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(privkey))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(slashable_signer_xpub.into())),
            )
            .await?;

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();
        let async_wallet_address =
            bitcoincore_rpc_async::bitcoin::Address::from_str(&wallet_address.to_string()).unwrap();
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

        set_recovery_address(funded_accounts[0].clone())
            .await
            .unwrap();

        btc_client
            .generate_to_address(120, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1120).await.unwrap();

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        poll_for_active_sigset().await;
        poll_for_signatory_key(consensus_key).await;

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(10.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1124).await.unwrap();
        poll_for_signing_checkpoint().await;

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        let confirmed_index = app_client()
            .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.confirmed_index))
            .await
            .unwrap();
        assert_eq!(confirmed_index, None);

        poll_for_completed_checkpoint(1).await;
        tx.send(Some(())).await.unwrap();

        app_client()
            .with_wallet(funded_accounts[0].wallet.clone())
            .call(
                move |app| build_call!(app.accounts.take_as_funding((MIN_FEE).into())),
                move |app| build_call!(app.bitcoin.transfer_to_fee_pool(10000000000.into())),
            )
            .await?;
        let expected_balance = 989974200000000;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, Amount::from(expected_balance));

        btc_client
            .generate_to_address(3, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1127).await.unwrap();

        println!(
            "withdraw address to string: {:?}",
            withdraw_address.to_string()
        );
        let simulate_withdrawal_fee = app_client()
            .query(|app: InnerApp| {
                Ok(app.withdrawal_fees(Adapter::new(withdraw_address.to_string()), None)?)
            })
            .await
            .unwrap();
        withdraw_bitcoin(
            &funded_accounts[0],
            bitcoin::Amount::from_btc(3.0).unwrap(),
            &withdraw_address,
        )
        .await
        .unwrap();

        app_client()
            .with_wallet(funded_accounts[0].wallet.clone())
            .call(
                move |app| build_call!(app.accounts.take_as_funding((MIN_FEE).into())),
                move |app| build_call!(app.bitcoin.transfer_to_fee_pool(15350000000.into())),
            )
            .await?;

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1131).await.unwrap();
        poll_for_completed_checkpoint(2).await;

        match wallet.get_balances() {
            Ok(data) => {
                assert_eq!(simulate_withdrawal_fee, 3100000000);
                assert_eq!(
                    data.mine.untrusted_pending.to_sat() * 1000000,
                    299996900000000
                );
            }
            Err(e) => {
                info!("Error: {:?}", e);
            }
        }

        let expected_balance = 689958850000000;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, Amount::from(expected_balance));

        // After this, i will test two more deposit and withdraw all
        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(5.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();
        btc_client
            .generate_to_address(1, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1132).await.unwrap();
        poll_for_signing_checkpoint().await;
        poll_for_completed_checkpoint(3).await;

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(2.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();
        btc_client
            .generate_to_address(1, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1133).await.unwrap();

        // Lack of fee pool here, so i send more BTC to fee pool
        app_client()
            .with_wallet(funded_accounts[0].wallet.clone())
            .call(
                move |app| build_call!(app.accounts.take_as_funding((MIN_FEE).into())),
                move |app| build_call!(app.bitcoin.transfer_to_fee_pool(9000000000.into())),
            )
            .await?;

        poll_for_signing_checkpoint().await;
        poll_for_completed_checkpoint(4).await;

        let expected_balance = 1382883964000000;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, Amount::from(expected_balance));

        // Withdraw all
        withdraw_bitcoin(
            &funded_accounts[0],
            bitcoin::Amount::from_btc(13.00).unwrap(),
            &withdraw_address,
        )
        .await
        .unwrap();

        // Lack of fee pool here, so i send more BTC to fee pool
        app_client()
            .with_wallet(funded_accounts[0].wallet.clone())
            .call(
                move |app| build_call!(app.accounts.take_as_funding((MIN_FEE).into())),
                move |app| build_call!(app.bitcoin.transfer_to_fee_pool(90000000000.into())),
            )
            .await?;

        btc_client
            .generate_to_address(2, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1135).await.unwrap();
        poll_for_completed_checkpoint(5).await;

        let simulate_withdrawal_fee = app_client()
            .query(|app: InnerApp| {
                Ok(app.withdrawal_fees(Adapter::new(withdraw_address.to_string()), None)?)
            })
            .await
            .unwrap();
        match wallet.get_balances() {
            Ok(data) => {
                assert_eq!(simulate_withdrawal_fee, 5952000000);
                assert_eq!(
                    data.mine.untrusted_pending.to_sat() * 1000000,
                    1299994048000000
                );
            }
            Err(e) => {
                info!("Error: {:?}", e);
            }
        }

        let expected_balance = 82793964000000;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, Amount::from(expected_balance));

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(
        headers,
        deposits,
        checkpoints,
        disbursal,
        signer,
        slashable_signer,
        test
    ) {
        Err(Error::Test(_)) => (),
        Ok(_) => (),
        other => {
            other.unwrap();
        }
    }
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_minimum_deposit_fees() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
        let time = Time::from_seconds(genesis_time.timestamp());
        set_time(time);
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
    let rpc_url = bitcoind.rpc_url();
    let cookie_file = bitcoind.params.cookie_file.clone();
    let btc_client = test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await;

    let block_data = populate_bitcoin_block(&btc_client).await;

    let home = tempdir().unwrap();
    let path = home.into_path();

    let node_path = path.clone();
    let signer_path = path.clone();
    let xpriv = generate_bitcoin_key(bitcoin::Network::Regtest).unwrap();
    fs::create_dir_all(signer_path.join("signer")).unwrap();
    fs::write(
        signer_path.join("signer/xpriv"),
        xpriv.to_string().as_bytes(),
    )
    .unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);
    let header_relayer_path = path.clone();

    std::env::set_var("NOMIC_HOME_DIR", &path);

    let headers_config = HeaderQueueConfig {
        encoded_trusted_header: Adapter::new(block_data.block_header)
            .encode()
            .unwrap()
            .try_into()
            .unwrap(),
        trusted_height: block_data.height,
        retargeting: false,
        min_difficulty_blocks: true,
        max_length: 59,
        ..Default::default()
    };
    let bitcoin_config = BitcoinConfig {
        max_offline_checkpoints: 20,
        ..Default::default()
    };
    let checkpoint_config = CheckpointConfig {
        user_fee_factor: 10000,
        ..Default::default()
    };
    let funded_accounts = setup_test_app(
        &path,
        4,
        Some(headers_config),
        Some(checkpoint_config),
        Some(bitcoin_config),
    );

    info!("Starting Nomic node...");
    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default()).await;
    let node_child = node.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let deposits = relayer.start_deposit_relay(&header_relayer_path, 60 * 60 * 12);

    let mut relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );
    let checkpoints = relayer.start_checkpoint_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let (tx, mut rx) = mpsc::channel(100);
    let shutdown_listener = async {
        rx.recv().await;
        Err::<(), Error>(Error::Test("Signer shutdown initiated".to_string()))
    };

    let slashable_xpriv_seed: [u8; 32] = rand::thread_rng().gen();

    let slashable_signer = async {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let xpriv =
            ExtendedPrivKey::new_master(bitcoin::Network::Testnet, slashable_xpriv_seed.as_slice())
                .unwrap();
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        let signer = Signer::new(
            address_from_privkey(&funded_accounts[2].privkey),
            vec![xpriv],
            0.1,
            1.0,
            0,
            None,
            || {
                let wallet = DerivedKey::from_secret_key(privkey);
                app_client().with_wallet(wallet)
            },
            None,
        )
        .start();

        match futures::try_join!(signer, shutdown_listener) {
            Err(Error::Test(_)) | Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    };

    let test = async {
        let val_priv_key = load_privkey().unwrap();
        let nomic_wallet = DerivedKey::from_secret_key(val_priv_key);
        let consensus_key = load_consensus_key(&path)?;
        declare_validator(consensus_key, nomic_wallet, 100_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(val_priv_key))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let xpriv =
            ExtendedPrivKey::new_master(bitcoin::Network::Testnet, slashable_xpriv_seed.as_slice())
                .unwrap();
        let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        declare_validator([0; 32], funded_accounts[2].wallet.clone(), 4_000)
            .await
            .unwrap();
        app_client()
            .with_wallet(DerivedKey::from_secret_key(privkey))
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();
        let async_wallet_address =
            bitcoincore_rpc_async::bitcoin::Address::from_str(&wallet_address.to_string()).unwrap();

        btc_client
            .generate_to_address(120, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1120).await.unwrap();

        poll_for_signatory_key(consensus_key).await;
        poll_for_signatory_key([0; 32]).await;
        tx.send(Some(())).await.unwrap();

        // case 1: test query with current building checkpoint
        let deposit_fees = app_client()
            .query(|app: InnerApp| Ok(app.deposit_fees(None)?))
            .await
            .unwrap();

        // sigset len = 1 => deposit_fees = 158 (input vsize) * 50 (default fee rate) * 10000 (use fee factor config above) / 10000 * 10^6 (units per sat)
        assert_eq!(deposit_fees, 7900000000);

        // fixture: try creating some checkpoints and then we can query
        for i in 0..3 {
            deposit_bitcoin(
                &funded_accounts[0].address,
                bitcoin::Amount::from_btc(1.0).unwrap(),
                &wallet,
            )
            .await
            .unwrap();

            btc_client
                .generate_to_address(1, &async_wallet_address)
                .await
                .unwrap();
            poll_for_bitcoin_header(1120 + i).await.unwrap();
            poll_for_completed_checkpoint(i + 1).await;
        }

        let first_checkpoint_deposit_fees = app_client()
            .query(|app: InnerApp| Ok(app.deposit_fees(Some(0))?))
            .await
            .unwrap();
        // first checkpoint minimum deposit fees should stay the same
        assert_eq!(first_checkpoint_deposit_fees, 7900000000);

        // case 2:
        let second_checkpoint_deposit_fees = app_client()
            .query(|app: InnerApp| Ok(app.deposit_fees(Some(1))?))
            .await
            .unwrap();
        // in the 2nd checkpoint, the signatory length is 2 -> 237 * 50 * 10^6
        assert_eq!(second_checkpoint_deposit_fees, 11850000000);

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(
        headers,
        deposits,
        checkpoints,
        signer,
        slashable_signer,
        test
    ) {
        Err(Error::Test(_)) => (),
        Ok(_) => (),
        other => {
            other.unwrap();
        }
    }
}
