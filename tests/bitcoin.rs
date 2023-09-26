#![feature(async_closure)]
use bitcoin::blockdata::transaction::EcdsaSighashType;
use bitcoin::secp256k1::Message;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Script;
use bitcoincore_rpc_async::Auth;
use bitcoincore_rpc_async::RpcApi;
use bitcoind::bitcoincore_rpc::json::{
    ImportMultiRequest, ImportMultiRequestScriptPubkey, ImportMultiRescanSince,
};
use bitcoind::bitcoincore_rpc::RpcApi as AsyncRpcApi;
use bitcoind::{BitcoinD, Conf};
use log::info;
use nomic::app::Dest;
use nomic::app::{InnerApp, Nom};
use nomic::bitcoin::adapter::Adapter;
use nomic::bitcoin::checkpoint::CheckpointStatus;
use nomic::bitcoin::checkpoint::Config as CheckpointQueueConfig;
use nomic::bitcoin::header_queue::Config as HeaderQueueConfig;
use nomic::bitcoin::relayer::DepositAddress;
use nomic::bitcoin::relayer::Relayer;
use nomic::bitcoin::signer::Signer;
use nomic::bitcoin::threshold_sig::Signature;
use nomic::bitcoin::Config as BitcoinConfig;
use nomic::error::{Error, Result};
use nomic::utils::*;
use nomic::utils::{
    declare_validator, poll_for_active_sigset, poll_for_blocks, populate_bitcoin_block, retry,
    setup_test_app, setup_test_signer, setup_time_context, test_bitcoin_client, NomicTestWallet,
};
use orga::abci::Node;
use orga::client::{
    wallet::{DerivedKey, Unsigned},
    AppClient,
};
use orga::coins::{Address, Amount};
use orga::encoding::{Encode, LengthVec};
use orga::macros::build_call;
use orga::plugins::{load_privkey, MIN_FEE};
use orga::tendermint::client::HttpClient;
use rand::Rng;
use reqwest::StatusCode;
use serial_test::serial;
use std::collections::HashMap;
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
    let sigset = app_client()
        .query(|app| Ok(app.bitcoin.checkpoints.active_sigset()?))
        .await?;
    let script = sigset.output_script(Dest::Address(*address).commitment_bytes()?.as_slice())?;

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
        _ => Err(Error::Relayer(format!(
            "Relayer response returned with error code: {}",
            res.status()
        ))),
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
        setup_time_context();
    });

    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();

    let btc_client = bitcoincore_rpc_async::Client::new(
        bitcoind.rpc_url(),
        Auth::CookieFile(bitcoind.params.cookie_file.clone()),
    )
    .await
    .unwrap();
    let block_data = populate_bitcoin_block(&bitcoind);

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
        emergency_disbursal_lock_time_interval: 3 * 60,
        ..Default::default()
    };

    let funded_accounts =
        setup_test_app(&path, 4, Some(headers_config), None, Some(bitcoin_config));

    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default());
    let _node_child = node.await.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind), rpc_addr.clone());
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(test_bitcoin_client(&bitcoind), rpc_addr.clone());
    let deposits = relayer.start_deposit_relay(&header_relayer_path);

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind), rpc_addr.clone());
    let checkpoints = relayer.start_checkpoint_relay();

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind), rpc_addr.clone());
    let disbursal = relayer.start_emergency_disbursal_transaction_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(20)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let (tx, mut rx) = mpsc::channel(100);
    let shutdown_listener = async {
        rx.recv().await;
        Err::<(), Error>(Error::Test("Signer shutdown initiated".to_string()))
    };

    let slashable_signer = async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let seed: [u8; 32] = rand::thread_rng().gen();
        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Testnet, seed.as_slice())?;
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        let signer = Signer::new(
            address_from_privkey(&funded_accounts[2].privkey),
            xpriv,
            0.1,
            1.0,
            || {
                let wallet = DerivedKey::from_secret_key(privkey);
                app_client().with_wallet(wallet)
            },
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
        declare_validator([0; 32], funded_accounts[2].wallet.clone(), 4_000)
            .await
            .unwrap();

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();
        let withdraw_address = wallet.get_new_address(None, None).unwrap();
        let async_wallet_address =
            bitcoincore_rpc_async::bitcoin::Address::from_str(&wallet_address.to_string()).unwrap();

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
            .await?;

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
        .await
        .unwrap();

        let balance = app_client()
            .query(|app| app.bitcoin.accounts.balance(funded_accounts[0].address))
            .await
            .unwrap();
        assert_eq!(balance, Amount::from(0));

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await?;

        poll_for_bitcoin_header(1124).await.unwrap();
        poll_for_signing_checkpoint().await;

        let balance = app_client()
            .query(|app| app.bitcoin.accounts.balance(funded_accounts[0].address))
            .await
            .unwrap();
        assert_eq!(balance, Amount::from(0));

        poll_for_completed_checkpoint(1).await;

        tx.send(Some(())).await.unwrap();

        let balance = app_client()
            .query(|app| app.bitcoin.accounts.balance(funded_accounts[0].address))
            .await
            .unwrap();
        assert_eq!(balance, Amount::from(799998736000000));

        deposit_bitcoin(
            &funded_accounts[1].address,
            bitcoin::Amount::from_btc(0.4).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await?;

        poll_for_bitcoin_header(1128).await.unwrap();
        poll_for_completed_checkpoint(2).await;

        let balance = app_client()
            .query(|app| app.bitcoin.accounts.balance(funded_accounts[1].address))
            .await
            .unwrap();

        assert_eq!(balance, Amount::from(31998104000000));

        withdraw_bitcoin(
            &funded_accounts[0],
            bitcoin::Amount::from_sat(7000),
            &withdraw_address,
        )
        .await
        .unwrap();

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await?;

        poll_for_bitcoin_header(1132).await.unwrap();
        poll_for_completed_checkpoint(3).await;

        let signer_jailed = app_client()
            .query(|app| {
                Ok(app
                    .staking
                    .all_validators()?
                    .iter()
                    .any(|val| val.address == funded_accounts[2].address.into() && val.jailed))
            })
            .await
            .unwrap();
        assert!(signer_jailed);

        let balance = app_client()
            .query(|app| app.bitcoin.accounts.balance(funded_accounts[0].address))
            .await
            .unwrap();
        assert_eq!(balance, Amount::from(799991736000000));

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
            .await?;

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
        assert_eq!(signatory_balance, 239991049);

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

        let expected_account_balances: Vec<u64> = vec![799990201, 0, 0, 0];
        assert_eq!(funded_account_balances, expected_account_balances);

        for (i, account) in funded_accounts[0..1].iter().enumerate() {
            let dump_address = wallet.get_new_address(None, None).unwrap();
            let disbursal_txs = app_client()
                .query(|app| Ok(app.bitcoin.checkpoints.emergency_disbursal_txs()?))
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

            bitcoind.client.send_raw_transaction(&signed_tx).unwrap();

            btc_client
                .generate_to_address(1, &async_wallet_address)
                .await?;

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
        emergency_disbursal_lock_time_interval: 24 * 60 * 7,
        ..Default::default()
    };
    let funded_accounts =
        setup_test_app(&path, 4, Some(headers_config), None, Some(bitcoin_config));

    info!("Starting Nomic node...");
    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default()).await;
    let _node_child = node.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind), rpc_addr.clone());
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(test_bitcoin_client(&bitcoind), rpc_addr.clone());
    let deposits = relayer.start_deposit_relay(&header_relayer_path);

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind), rpc_addr.clone());
    let checkpoints = relayer.start_checkpoint_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(20)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let (tx, mut rx) = mpsc::channel(100);
    let shutdown_listener = async {
        rx.recv().await;
        Err::<(), Error>(Error::Test("Signer shutdown initiated".to_string()))
    };

    let seed: [u8; 32] = rand::thread_rng().gen();

    let slashable_signer = async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let xpriv =
            ExtendedPrivKey::new_master(bitcoin::Network::Testnet, seed.as_slice()).unwrap();
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        let signer = Signer::new(
            address_from_privkey(&funded_accounts[2].privkey),
            xpriv,
            0.1,
            1.0,
            || {
                let wallet = DerivedKey::from_secret_key(privkey);
                app_client().with_wallet(wallet)
            },
        )
        .start();

        match futures::try_join!(signer, shutdown_listener) {
            Err(Error::Test(_)) | Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    };

    let slashable_signer_2 = {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let xpriv =
            ExtendedPrivKey::new_master(bitcoin::Network::Testnet, seed.as_slice()).unwrap();
        let privkey_bytes = funded_accounts[2].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        Signer::new(
            address_from_privkey(&funded_accounts[2].privkey),
            xpriv,
            0.1,
            1.0,
            move || {
                let wallet = DerivedKey::from_secret_key(privkey);
                app_client().with_wallet(wallet)
            },
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
        declare_validator([0; 32], funded_accounts[2].wallet.clone(), 4_000)
            .await
            .unwrap();

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();

        retry(
            || bitcoind.client.generate_to_address(120, &wallet_address),
            10,
        )
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

            retry(
                || bitcoind.client.generate_to_address(4, &wallet_address),
                10,
            )
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
        tokio::time::sleep(Duration::from_secs(2 * 60)).await;

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
                        Some(checkpoint.1.sigset.signatories.len())
                    })
                    .collect::<Vec<_>>())
            })
            .await
            .unwrap();

        for (i, length) in signatory_lengths.iter().enumerate() {
            if length == &2 {
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
async fn signing_pruned_checkpoint_test() {
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

    let checkpoint_queue_config = CheckpointQueueConfig {
        min_checkpoints: 3,
        max_age: 0,
        ..Default::default()
    };

    let bitcoin_config = BitcoinConfig {
        max_offline_checkpoints: 20,
        emergency_disbursal_lock_time_interval: 24 * 60 * 7,
        ..Default::default()
    };

    let funded_accounts = setup_test_app(
        &path,
        2,
        Some(headers_config),
        Some(checkpoint_queue_config),
        Some(bitcoin_config),
    );

    info!("Starting Nomic node...");
    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default()).await;
    let _node_child = node.run().await.unwrap();

    let rpc_addr = "http://localhost:26657".to_string();

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind), rpc_addr.clone());
    let headers = relayer.start_header_relay();

    let relayer = Relayer::new(test_bitcoin_client(&bitcoind), rpc_addr.clone());
    let deposits = relayer.start_deposit_relay(&header_relayer_path);

    let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind), rpc_addr.clone());
    let checkpoints = relayer.start_checkpoint_relay();

    let signer = async {
        tokio::time::sleep(Duration::from_secs(20)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let (tx, mut rx) = mpsc::channel(100);
    let shutdown_listener = async {
        rx.recv().await;
        Err::<(), Error>(Error::Test("Signer shutdown initiated".to_string()))
    };

    let seed: [u8; 32] = rand::thread_rng().gen();

    let slashable_signer = async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let xpriv =
            ExtendedPrivKey::new_master(bitcoin::Network::Testnet, seed.as_slice()).unwrap();
        let privkey_bytes = funded_accounts[1].privkey.secret_bytes();
        let privkey = orga::secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
        let signer = Signer::new(
            address_from_privkey(&funded_accounts[1].privkey),
            xpriv,
            0.1,
            1.0,
            || {
                let wallet = DerivedKey::from_secret_key(privkey);
                app_client().with_wallet(wallet)
            },
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
        declare_validator([0; 32], funded_accounts[1].wallet.clone(), 4_000)
            .await
            .unwrap();

        let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
        let wallet_address = wallet.get_new_address(None, None).unwrap();

        retry(
            || bitcoind.client.generate_to_address(120, &wallet_address),
            10,
        )
        .unwrap();

        poll_for_bitcoin_header(1120).await.unwrap();

        poll_for_signatory_key(consensus_key).await;
        poll_for_signatory_key([0; 32]).await;
        let slashable_signer_xpub = app_client()
            .query(|app| Ok(app.bitcoin.signatory_keys.get([0; 32])?))
            .await
            .unwrap()
            .unwrap();

        tx.send(Some(())).await.unwrap();

        for i in 0..2 {
            deposit_bitcoin(
                &funded_accounts[0].address,
                bitcoin::Amount::from_btc(1.0).unwrap(),
                &wallet,
            )
            .await
            .unwrap();

            retry(
                || bitcoind.client.generate_to_address(4, &wallet_address),
                10,
            )
            .unwrap();
            poll_for_bitcoin_header(1120 + (i + 1) * 4).await.unwrap();

            poll_for_completed_checkpoint(i + 1).await;
        }

        let signer_wallet = DerivedKey::from_secret_key(
            orga::secp256k1::SecretKey::from_slice(&funded_accounts[1].privkey.secret_bytes())
                .unwrap(),
        );
        let secp = bitcoin::secp256k1::Secp256k1::signing_only();
        let sigs: LengthVec<u16, Signature> = app_client()
            .query(|app| {
                Ok(app
                    .bitcoin
                    .checkpoints
                    .get(0)?
                    .to_sign(slashable_signer_xpub)?
                    .iter()
                    .map(|(msg, _)| {
                        Ok(secp
                            .sign_ecdsa(
                                &Message::from_slice(&msg[..])?,
                                &funded_accounts[1].privkey.clone(),
                            )
                            .serialize_compact()
                            .into())
                    })
                    .collect::<Result<Vec<_>>>()?)
            })
            .await
            .unwrap()
            .try_into()
            .unwrap();

        deposit_bitcoin(
            &funded_accounts[0].address,
            bitcoin::Amount::from_btc(1.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        retry(
            || bitcoind.client.generate_to_address(4, &wallet_address),
            10,
        )
        .unwrap();
        poll_for_bitcoin_header(1132).await.unwrap();

        poll_for_completed_checkpoint(3).await;

        let _res = app_client()
            .with_wallet(signer_wallet)
            .call(
                move |app| {
                    build_call!(app.bitcoin.checkpoints.sign(
                        slashable_signer_xpub,
                        sigs.clone(),
                        0
                    ))
                },
                |app| build_call!(app.app_noop()),
            )
            .await;

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
