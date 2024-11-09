#![cfg(feature = "ethereum-full")]
#![feature(async_closure)]
use crate::utils::*;
use alloy_node_bindings::Anvil;
use alloy_provider::ext::AnvilApi;
use alloy_provider::network::EthereumWallet;
use alloy_provider::Provider;
use alloy_rpc_types::BlockId;
use bitcoin::secp256k1;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoincore_rpc_async::RpcApi as AsyncRpcApi;
use bitcoind::bitcoincore_rpc::json::{
    ImportMultiRequest, ImportMultiRequestScriptPubkey, ImportMultiRescanSince,
};
use bitcoind::bitcoincore_rpc::RpcApi;
use bitcoind::{BitcoinD, Conf};
use chrono::TimeZone;
use chrono::Utc;
use log::info;
use nomic::app::Dest;
use nomic::app::{InnerApp, Nom};
use nomic::app_client;
use nomic::bitcoin::adapter::Adapter;
use nomic::bitcoin::checkpoint::Config as CheckpointConfig;
use nomic::bitcoin::header_queue::Config as HeaderQueueConfig;
use nomic::bitcoin::relayer::DepositAddress;
use nomic::bitcoin::relayer::Relayer;
use nomic::error::{Error, Result};
use nomic::ethereum::relayer::Relayer as EthRelayer;
use nomic::ethereum::{bridge_contract, token_contract};
use nomic::utils::*;
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
use reqwest::StatusCode;
use serial_test::serial;
use std::fs;
use std::str::FromStr;
use std::sync::Once;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::mpsc;

pub mod utils;

static INIT: Once = Once::new();

#[tokio::test]
#[serial]
#[ignore]
async fn ethereum() {
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
    let cp_config = CheckpointConfig {
        min_checkpoint_interval: 1,
        emergency_disbursal_lock_time_interval: 1000000,
        wait_to_collect_fees: false,
        ..Default::default()
    };
    let funded_accounts =
        setup_test_app(&path, 4, Some(headers_config), Some(cp_config), None, None);

    let node = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default());
    let _node_child = node.await.run().await.unwrap();

    let anvil = Anvil::default().chain_id(0).port(8545u16);

    let eth_node = async { Ok(anvil.spawn()) };
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

    let eth_priv_key = alloy_signer_local::PrivateKeySigner::random();
    let async_eth_priv_key = eth_priv_key.clone();
    let eth_address = eth_priv_key.address();

    let val_priv_key = load_privkey().unwrap();
    let nomic_wallet = DerivedKey::from_secret_key(val_priv_key);
    let eth_nomic_wallet = nomic_wallet.clone();
    let eth_wallet = EthereumWallet::new(eth_priv_key.clone());

    let provider = alloy_provider::ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(eth_wallet)
        .on_anvil();
    provider.anvil_set_auto_mine(true).await.unwrap();
    provider.anvil_set_chain_id(0).await.unwrap();
    provider
        .anvil_set_balance(
            eth_address.0 .0.into(),
            alloy_core::primitives::U256::from(100000000000000000000u128), // 100 ETH
        )
        .await
        .unwrap();

    let test_provider = provider.clone();
    let (tx, mut rx) = mpsc::channel(100);
    let eth_relayer = async {
        let contract_address: String = rx.recv().await.unwrap();
        info!(
            "Starting eth relayer with contract address: {}",
            contract_address
        );

        loop {
            let relayer = EthRelayer::new(
                "http://localhost:26657".to_string(),
                eth_nomic_wallet.clone(),
                provider.clone(),
            );
            match relayer
                .start_eth_relay(
                    format!("0x{}", hex::encode(async_eth_priv_key.clone().to_bytes())),
                    "http://localhost:8545".to_string(),
                    "http://localhost:5052".to_string(),
                    0,
                    contract_address.clone(),
                )
                .await
            {
                Ok(_) => break,
                Err(e) => {
                    info!("Eth relayer error: {}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }

        Ok(())
    };

    let test = async {
        let consensus_key = load_consensus_key(&path)?;
        declare_validator(consensus_key, nomic_wallet, 100_000)
            .await
            .unwrap();
        app_client(DEFAULT_RPC)
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

        poll_for_finalized_query_data(
            DEFAULT_RPC.to_string(),
            Some("Polling for Bitcoin headers...".to_string()),
            None,
            1120,
            |app| Ok(app.bitcoin.headers.height()?),
        )
        .await
        .unwrap();
        poll_for_finalized_query_data(
            DEFAULT_RPC.to_string(),
            Some("Polling for signatory key...".to_string()),
            None,
            true,
            |app| Ok(app.bitcoin.signatory_keys.get(consensus_key)?.is_some()),
        )
        .await
        .unwrap();

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

        poll_for_finalized_query_data(
            DEFAULT_RPC.to_string(),
            Some("Polling for completed checkpoint...".to_string()),
            None,
            1,
            |app| Ok(app.bitcoin.checkpoints.completed(1_000)?.len()),
        )
        .await
        .unwrap();

        btc_client
            .generate_to_address(6, &async_wallet_address)
            .await
            .unwrap();

        poll_for_finalized_query_data(
            DEFAULT_RPC.to_string(),
            Some("Polling for Bitcoin headers...".to_string()),
            None,
            1130,
            |app| Ok(app.bitcoin.headers.height()?),
        )
        .await
        .unwrap();

        let mut current_valset = app_client(DEFAULT_RPC)
            .query(|app| Ok(app.bitcoin.checkpoints.get(0)?.sigset.clone()))
            .await
            .unwrap();
        current_valset.normalize_vp(u32::MAX as u64);

        let validator_eth_addresses = current_valset
            .eth_addresses()
            .iter()
            .map(|a| alloy_core::primitives::Address::from_slice(&a.bytes()))
            .collect::<Vec<_>>();
        let validator_voting_powers = current_valset
            .signatories
            .iter()
            .map(|s| alloy_core::primitives::U256::from(s.voting_power))
            .collect::<Vec<_>>();

        let bridge_contract = bridge_contract::deploy(
            test_provider.clone(),
            alloy_core::primitives::Address::from_slice(&[0; 20]),
            validator_eth_addresses,
            validator_voting_powers,
        )
        .await
        .unwrap();

        let bridge_contract_address = bridge_contract.address().0 .0;

        let token_contract = token_contract::deploy(
            test_provider.clone(),
            bridge_contract_address.into(),
            "nBTC".to_string(),
            "nBTC".to_string(),
            14,
        )
        .await
        .unwrap();

        let token_contract_address = token_contract.address().0 .0;

        app_client(DEFAULT_RPC)
            .with_wallet(funded_accounts[0].wallet.clone())
            .call(
                move |app| {
                    build_call!(app.eth_create_connection(
                        0,
                        bridge_contract_address.into(),
                        token_contract_address.into(),
                        current_valset.index
                    ))
                },
                |app| build_call!(app.app_noop()),
            )
            .await?;

        tx.send(bridge_contract.clone().address().to_string())
            .await
            .unwrap();

        app_client(DEFAULT_RPC)
            .with_wallet(funded_accounts[0].wallet.clone())
            .call(
                |app| {
                    build_call!(app.eth_transfer_nbtc(
                        0,
                        bridge_contract.address().0 .0.into(),
                        eth_address.0 .0.into(),
                        200_000_000_000.into()
                    ))
                },
                |app| build_call!(app.app_noop()),
            )
            .await
            .unwrap();

        btc_client
            .generate_to_address(6, &async_wallet_address)
            .await
            .unwrap();

        poll_for_finalized_query_data(
            DEFAULT_RPC.to_string(),
            Some("Polling for completed checkpoint...".to_string()),
            None,
            2,
            |app| Ok(app.bitcoin.checkpoints.completed(1_000)?.len()),
        )
        .await
        .unwrap();

        loop {
            let balance = token_contract
                .balanceOf(eth_address.0 .0.into())
                .call()
                .await
                .unwrap()
                ._0;

            if balance > alloy_core::primitives::U256::from(0u128) {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        token_contract
            .approve(
                bridge_contract.address().0 .0.into(),
                alloy_core::primitives::U256::from(u64::MAX),
            )
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        bridge_contract
            .sendToNomic(
                token_contract.address().0 .0.into(),
                Dest::NativeAccount {
                    address: funded_accounts[1].address,
                }
                .to_string(),
                alloy_core::primitives::U256::from(20_000_000_000u128),
            )
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        let block = provider
            .get_block(BlockId::latest(), Default::default())
            .await
            .unwrap()
            .expect("Block not found");
        let header = block.header;
        let state_root = header.state_root;
        let block_number = header.number;

        app_client(DEFAULT_RPC)
            .with_wallet(funded_accounts[0].wallet.clone())
            .call(
                |app| {
                    build_call!(app.ethereum.unsafe_update_consensus(
                        0,
                        state_root.into(),
                        block_number
                    ))
                },
                |app| build_call!(app.app_noop()),
            )
            .await
            .unwrap();

        btc_client
            .generate_to_address(6, &async_wallet_address)
            .await
            .unwrap();

        poll_for_finalized_query_data(
            DEFAULT_RPC.to_string(),
            Some("Polling for completed checkpoint...".to_string()),
            None,
            3,
            |app| Ok(app.bitcoin.checkpoints.completed(1_000)?.len()),
        )
        .await
        .unwrap();

        let expected_balance = 20_000_000_000;
        let balance = poll_for_updated_query_data(
            DEFAULT_RPC.to_string(),
            Some("Polling for updated balance...".to_string()),
            None,
            Amount::from(0),
            |app| app.bitcoin.accounts.balance(funded_accounts[1].address),
        )
        .await
        .unwrap();
        assert_eq!(balance, Amount::from(expected_balance));

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(
        headers,
        deposits,
        checkpoints,
        signer,
        eth_node,
        eth_relayer,
        test
    ) {
        Err(Error::Test(_)) => (),
        Ok(_) => (),
        other => {
            other.unwrap();
        }
    }
}
