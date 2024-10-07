#![feature(async_closure)]
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
use nomic::app::IbcDest;
use nomic::app::{InnerApp, Nom};
use nomic::bitcoin::adapter::Adapter;
use nomic::bitcoin::header_queue::Config as HeaderQueueConfig;
use nomic::bitcoin::relayer::DepositAddress;
use nomic::bitcoin::relayer::Relayer;
use nomic::error::{Error, Result};
use nomic::utils::*;
use nomic::utils::{
    declare_validator, poll_for_active_sigset, poll_for_blocks, poll_for_updated_balance,
    populate_bitcoin_block, retry, set_time, setup_test_app, setup_test_signer,
    test_bitcoin_client,
};
use orga::abci::Node;
use orga::client::{
    wallet::{DerivedKey, Unsigned},
    AppClient,
};
use orga::coins::{Address, Amount};
use orga::encoding::Encode;
use orga::ibc::GrpcOpts;
use orga::ibc::IbcTimestamp as Timestamp;
use orga::macros::build_call;
use orga::plugins::{load_privkey, Time, MIN_FEE};
use orga::tendermint::client::HttpClient;
use reqwest::StatusCode;
use serial_test::serial;
use std::fs;
use std::str::FromStr;
use std::sync::Once;
use std::time::Duration;
use std::time::SystemTime;
use tempfile::tempdir;
use tokio::process::Command;

static INIT: Once = Once::new();
const TEST_CHAIN_ID: &str = "nomic-e2e";

fn app_client() -> AppClient<InnerApp, InnerApp, orga::tendermint::client::HttpClient, Nom, Unsigned>
{
    nomic::app_client("http://localhost:26657")
}

async fn generate_deposit_address(address: &Address) -> Result<DepositAddress> {
    info!("Generating deposit address for {}...", address);
    let (sigset, threshold) = app_client()
        .query(|app| {
            Ok((
                app.bitcoin.checkpoints.active_sigset()?,
                app.bitcoin.checkpoints.config.sigset_threshold,
            ))
        })
        .await?;
    let script = sigset.output_script(
        Dest::NativeAccount { address: *address }
            .commitment_bytes()?
            .as_slice(),
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

    let commitment = Dest::NativeAccount { address: dest_addr }.encode()?;

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
        _ => Err(Error::Relayer(res.text().await.unwrap().to_string())),
    }
}

async fn direct_deposit_bitcoin(
    receiver: String,
    sender: String,
    btc: bitcoin::Amount,
    wallet: &bitcoind::bitcoincore_rpc::Client,
) -> Result<()> {
    let now_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        * 1_000_000_000;
    let dest = Dest::Ibc {
        data: nomic::app::IbcDest {
            source_port: "transfer".try_into().unwrap(),
            source_channel: "channel-0".try_into().unwrap(),
            sender: sender.try_into().unwrap(),
            receiver: receiver.try_into().unwrap(),
            timeout_timestamp: now_ns + 86400 * 1_000_000_000,
            memo: "".to_string().try_into().unwrap(),
        },
    };

    let (sigset, threshold) = app_client()
        .query(|app| {
            Ok((
                app.bitcoin.checkpoints.active_sigset()?,
                app.bitcoin.checkpoints.config.sigset_threshold,
            ))
        })
        .await?;
    let script = sigset.output_script(dest.commitment_bytes()?.as_slice(), threshold)?;
    let btc_addr = bitcoin::Address::from_script(&script, nomic::bitcoin::NETWORK).unwrap();

    let url = format!("{}/address", "http://localhost:8999",);
    let client = reqwest::Client::new();
    let res = client
        .post(url)
        .query(&[
            ("sigset_index", &sigset.index().to_string()),
            ("deposit_addr", &btc_addr.to_string()),
        ])
        .body(dest.encode()?)
        .send()
        .await
        .unwrap();

    wallet
        .send_to_address(
            &bitcoin::Address::from_str(&btc_addr.to_string()).unwrap(),
            btc,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    match res.status() {
        StatusCode::OK => Ok(()),
        _ => Err(Error::Relayer(res.text().await.unwrap().to_string())),
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

fn client_provider() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, DerivedKey> {
    let val_priv_key = load_privkey().unwrap();
    let wallet = DerivedKey::from_secret_key(val_priv_key);
    app_client().with_wallet(wallet)
}

struct GmHandler {}

impl GmHandler {
    async fn start(gm_path: String) -> Result<()> {
        Command::new(gm_path.clone())
            .args(["reset", "ibc-0"])
            .spawn()?;
        Command::new(gm_path.clone())
            .args(["reset", "node-0"])
            .spawn()?;
        Command::new(gm_path).arg("start").spawn()?;

        Ok(())
    }
}

#[tokio::test]
#[serial]
#[ignore]
async fn ibc_test() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
        let time = Time::from_seconds(genesis_time.timestamp());
        set_time(time);
    });

    let gm_path = std::env::var("GM_PATH").unwrap();

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
    let funded_accounts = setup_test_app(
        &path,
        4,
        Some(headers_config),
        None,
        None,
        Some(vec![Address::from_str(
            "nomic1vd0r7t04vnr36x6pydel9eacvn776psetwqndl",
        )
        .unwrap()]),
    );

    let node = Node::<nomic::app::App>::new(node_path, Some(TEST_CHAIN_ID), Default::default());
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

    let relayer = Relayer::new(
        test_bitcoin_client(rpc_url.clone(), cookie_file.clone()).await,
        rpc_addr.clone(),
    );

    let signer = async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        setup_test_signer(&signer_path, client_provider)
            .start()
            .await
    };

    let grpc = async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        dbg!("Starting gRPC server...");
        orga::ibc::start_grpc(
            || app_client().sub(|app| Ok(app.ibc.ctx)),
            &GrpcOpts {
                host: "127.0.0.1".to_string(),
                port: 9001,
                chain_id: TEST_CHAIN_ID.to_string(),
            },
        )
        .await;

        Ok(())
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

        let mut labels = vec![];
        for i in 0..funded_accounts.len() {
            labels.push(format!("funded-account-{}", i));
        }

        wallet
            .import_multi(import_multi_reqest.as_slice(), None)
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

        deposit_bitcoin(
            &Address::from_str("nomic1vd0r7t04vnr36x6pydel9eacvn776psetwqndl").unwrap(),
            bitcoin::Amount::from_btc(1.0).unwrap(),
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

        let expected_balance = 0;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, expected_balance);

        let confirmed_index = app_client()
            .query(|app| Ok(app.bitcoin.checkpoints.confirmed_index))
            .await
            .unwrap();
        assert_eq!(confirmed_index, None);

        poll_for_completed_checkpoint(1).await;

        let expected_balance = 989996871600000;
        let balance = poll_for_updated_balance(funded_accounts[0].address, expected_balance).await;
        assert_eq!(balance, Amount::from(expected_balance));

        let res = reqwest::get("http://localhost:27011/cosmos/bank/v1beta1/balances/cosmos1vd0r7t04vnr36x6pydel9eacvn776psehknf74").await.unwrap();
        let mut balances: serde_json::Value =
            serde_json::from_str(&res.text().await.unwrap()).expect("JSON was not well-formatted");

        let balance = balances["balances"]
            .as_array_mut()
            .unwrap()
            .iter()
            .find(|item| item["denom"] == "samoleans")
            .unwrap();
        assert_eq!(balance["amount"], "100000000");

        Command::new("hermes")
            .args([
                "create",
                "channel",
                "--a-chain",
                "nomic-e2e",
                "--b-chain",
                "ibc-0",
                "--a-port",
                "transfer",
                "--b-port",
                "transfer",
                "--new-client-connection",
                "--yes",
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        Command::new("hermes")
            .args([
                "tx",
                "ft-transfer",
                "--src-chain",
                "ibc-0",
                "--dst-chain",
                "nomic-e2e",
                "--src-port",
                "transfer",
                "--src-channel",
                "channel-0",
                "--amount",
                "1000000",
                "--timeout-seconds",
                "200",
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        Command::new("hermes")
            .args([
                "clear",
                "packets",
                "--chain",
                "ibc-0",
                "--port",
                "transfer",
                "--channel",
                "channel-0",
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        let res = reqwest::get("http://localhost:27011/cosmos/bank/v1beta1/balances/cosmos1vd0r7t04vnr36x6pydel9eacvn776psehknf74").await.unwrap();
        let mut balances: serde_json::Value =
            serde_json::from_str(&res.text().await.unwrap()).expect("JSON was not well-formatted");

        let balance = balances["balances"]
            .as_array_mut()
            .unwrap()
            .iter()
            .find(|item| item["denom"] == "samoleans")
            .unwrap();
        assert_eq!(balance["amount"], "99000000");

        Command::new("hermes")
            .args([
                "tx",
                "ft-transfer",
                "--dst-chain",
                "ibc-0",
                "--src-chain",
                "nomic-e2e",
                "--src-port",
                "transfer",
                "--src-channel",
                "channel-0",
                "--amount",
                "500000",
                "--timeout-seconds",
                "200",
                "--denom",
                "transfer/channel-0/samoleans",
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        Command::new("hermes")
            .args([
                "clear",
                "packets",
                "--chain",
                "nomic-e2e",
                "--port",
                "transfer",
                "--channel",
                "channel-0",
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        let res = reqwest::get("http://localhost:27011/cosmos/bank/v1beta1/balances/cosmos1vd0r7t04vnr36x6pydel9eacvn776psehknf74").await.unwrap();
        let mut balances: serde_json::Value =
            serde_json::from_str(&res.text().await.unwrap()).expect("JSON was not well-formatted");

        let balance = balances["balances"]
            .as_array_mut()
            .unwrap()
            .iter()
            .find(|item| item["denom"] == "samoleans")
            .unwrap();
        assert_eq!(balance["amount"], "99500000");

        let timeout_timestamp = 200_000_000 * 1_000_000_000 + Timestamp::now().nanoseconds();

        let ibc_dest = IbcDest {
            source_port: "transfer".try_into().unwrap(),
            source_channel: "channel-0".try_into().unwrap(),
            receiver: "cosmos1vd0r7t04vnr36x6pydel9eacvn776psehknf74"
                .to_string()
                .try_into()
                .unwrap(),
            sender: funded_accounts[0].address.to_string().try_into().unwrap(),
            timeout_timestamp,
            memo: "".try_into().unwrap(),
        };

        app_client()
            .with_wallet(funded_accounts[0].wallet.clone())
            .call(
                |app| build_call!(app.ibc_transfer_nbtc(ibc_dest, 9_913_960_000.into())),
                |app| build_call!(app.app_noop()),
            )
            .await
            .unwrap();

        deposit_bitcoin(
            &Address::from_str("nomic1vd0r7t04vnr36x6pydel9eacvn776psetwqndl").unwrap(),
            bitcoin::Amount::from_btc(1.0).unwrap(),
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

        Command::new("hermes")
            .args([
                "clear",
                "packets",
                "--chain",
                "nomic-e2e",
                "--port",
                "transfer",
                "--channel",
                "channel-0",
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();
        Command::new("hermes")
            .args([
                "clear",
                "packets",
                "--chain",
                "ibc-0",
                "--port",
                "transfer",
                "--channel",
                "channel-0",
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        let res = reqwest::get("http://localhost:27011/cosmos/bank/v1beta1/balances/cosmos1vd0r7t04vnr36x6pydel9eacvn776psehknf74").await.unwrap();
        let mut balances: serde_json::Value =
            serde_json::from_str(&res.text().await.unwrap()).expect("JSON was not well-formatted");

        let balance = balances["balances"]
            .as_array_mut()
            .unwrap()
            .iter()
            .find(|item| {
                item["denom"]
                    == "ibc/CB967CB169C4C51D8116D6FB2A2E919DDAC1CE4B91A21C641D050D757C54F2B3"
            })
            .unwrap();
        assert_eq!(balance["amount"], "9815068249");

        Command::new("hermes")
            .args([
                "tx",
                "ft-transfer",
                "--dst-chain",
                "nomic-e2e",
                "--src-chain",
                "ibc-0",
                "--src-port",
                "transfer",
                "--src-channel",
                "channel-0",
                "--amount",
                "9815060000",
                "--denom",
                "ibc/CB967CB169C4C51D8116D6FB2A2E919DDAC1CE4B91A21C641D050D757C54F2B3",
                "--timeout-seconds",
                "300",
                "--memo",
                &format!("withdraw:{}", funded_accounts[1].bitcoin_address()),
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        Command::new("hermes")
            .args([
                "clear",
                "packets",
                "--chain",
                "ibc-0",
                "--port",
                "transfer",
                "--channel",
                "channel-0",
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        let res = reqwest::get("http://localhost:27011/cosmos/bank/v1beta1/balances/cosmos1vd0r7t04vnr36x6pydel9eacvn776psehknf74").await.unwrap();
        let mut balances: serde_json::Value =
            serde_json::from_str(&res.text().await.unwrap()).expect("JSON was not well-formatted");

        let balance = balances["balances"]
            .as_array_mut()
            .unwrap()
            .iter()
            .find(|item| {
                item["denom"]
                    == "ibc/CB967CB169C4C51D8116D6FB2A2E919DDAC1CE4B91A21C641D050D757C54F2B3"
            })
            .unwrap();
        assert_eq!(balance["amount"], "8249");

        direct_deposit_bitcoin(
            "cosmos1vd0r7t04vnr36x6pydel9eacvn776psehknf74".to_string(),
            funded_accounts[0].address.to_string(),
            bitcoin::Amount::from_btc(0.5).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        deposit_bitcoin(
            &Address::from_str("nomic1vd0r7t04vnr36x6pydel9eacvn776psetwqndl").unwrap(),
            bitcoin::Amount::from_btc(1.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();
        deposit_bitcoin(
            &Address::from_str("nomic1vd0r7t04vnr36x6pydel9eacvn776psetwqndl").unwrap(),
            bitcoin::Amount::from_btc(1.0).unwrap(),
            &wallet,
        )
        .await
        .unwrap();

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1132).await.unwrap();
        app_client()
            .with_wallet(funded_accounts[0].wallet.clone())
            .call(
                |app| build_call!(app.bitcoin.transfer_to_fee_pool(10000000000.into())),
                |app| build_call!(app.app_noop()),
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

        Command::new("hermes")
            .args([
                "clear",
                "packets",
                "--chain",
                "nomic-e2e",
                "--port",
                "transfer",
                "--channel",
                "channel-0",
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();
        Command::new("hermes")
            .args([
                "clear",
                "packets",
                "--chain",
                "ibc-0",
                "--port",
                "transfer",
                "--channel",
                "channel-0",
            ])
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        let res = reqwest::get("http://localhost:27011/cosmos/bank/v1beta1/balances/cosmos1vd0r7t04vnr36x6pydel9eacvn776psehknf74").await.unwrap();
        let mut balances: serde_json::Value =
            serde_json::from_str(&res.text().await.unwrap()).expect("JSON was not well-formatted");

        let balance = balances["balances"]
            .as_array_mut()
            .unwrap()
            .iter()
            .find(|item| {
                item["denom"]
                    == "ibc/CB967CB169C4C51D8116D6FB2A2E919DDAC1CE4B91A21C641D050D757C54F2B3"
            })
            .unwrap();

        assert_eq!(balance["amount"], "8249");

        btc_client
            .generate_to_address(4, &async_wallet_address)
            .await
            .unwrap();

        poll_for_bitcoin_header(1136).await.unwrap();

        let received_bitcoin_amount =
            match wallet.get_received_by_address(&funded_accounts[1].bitcoin_address(), None) {
                Ok(amount) => amount.to_sat(),
                Err(e) => {
                    dbg!(e);
                    0
                }
            };

        assert_eq!(8999, received_bitcoin_amount);

        Command::new(gm_path.clone())
            .arg("stop")
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
    };

    poll_for_blocks().await;

    match futures::try_join!(
        headers,
        deposits,
        checkpoints,
        signer,
        test,
        grpc,
        GmHandler::start(gm_path.clone())
    ) {
        Err(Error::Test(_)) => (),
        Ok(_) => (),
        other => {
            other.unwrap();
        }
    }
}
