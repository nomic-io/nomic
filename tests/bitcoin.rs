// #![feature(async_closure)]

// use bitcoin::blockdata::transaction::EcdsaSighashType;
// use bitcoin::secp256k1;
// use bitcoincore_rpc_async::json::{
//     ImportMultiRequest, ImportMultiRequestScriptPubkey, ImportMultiRescanSince,
// };
// use bitcoind::bitcoincore_rpc::RpcApi;
// use bitcoind::{BitcoinD, Conf};
// use log::info;
// use nomic::app::DepositCommitment;
// use nomic::bitcoin::relayer::Config as RelayerConfig;
// use nomic::bitcoin::relayer::DepositAddress;
// use nomic::bitcoin::relayer::Relayer;
// use nomic::error::{Error, Result};
// use nomic::utils::{
//     declare_validator, generate_sign_doc, make_std_tx, poll_for_blocks, populate_bitcoin_block,
//     retry, setup_test_app, setup_test_signer, setup_time_context, test_bitcoin_client, KeyData,
// };
// use orga::abci::Node;
// use orga::coins::{Address, Amount};
// use orga::cosmrs::crypto::secp256k1::SigningKey;
// use orga::encoding::Encode;
// use orga::plugins::sdk_compat::sdk::{self, SignDoc};
// use orga::plugins::sdk_compat::sdk::{PubKey as OrgaPubKey, Signature as OrgaSignature};
// use reqwest::StatusCode;
// use serial_test::serial;
// use std::collections::HashMap;
// use std::str::FromStr;
// use std::sync::Once;
// use std::time::Duration;
// use tempfile::tempdir;
// use tendermint_rpc::{Client, HttpClient};

// static INIT: Once = Once::new();

// pub async fn withdraw(address: String, dest_addr: String, amount: u64) -> Result<SignDoc> {
//     let mut value = serde_json::Map::new();
//     value.insert("amount".to_string(), amount.to_string().into());
//     value.insert("dst_address".to_string(), dest_addr.into());

//     let address = address
//         .parse()
//         .map_err(|_| Error::Address("Failed to parse address".to_string()))?;
//     let nonce = app_client().nonce(address).await?;

//     Ok(generate_sign_doc(
//         sdk::Msg {
//             type_: "nomic/MsgWithdraw".to_string(),
//             value: value.into(),
//         },
//         nonce,
//     ))
// }

// async fn generate_deposit_address(address: &Address) -> Result<DepositAddress> {
//     info!("Generating deposit address for {}...", address);
//     let sigset = app_client().bitcoin.checkpoints.active_sigset().await??;
//     let script = sigset.output_script(
//         DepositCommitment::Address(*address)
//             .commitment_bytes()?
//             .as_slice(),
//     )?;

//     Ok(DepositAddress {
//         deposit_addr: bitcoin::Address::from_script(&script, bitcoin::Network::Regtest)
//             .unwrap()
//             .to_string(),
//         sigset_index: sigset.index(),
//     })
// }

// pub async fn broadcast_deposit_addr(
//     dest_addr: String,
//     sigset_index: u32,
//     relayer: String,
//     deposit_addr: String,
// ) -> Result<()> {
//     info!("Broadcasting deposit address to relayer...");
//     let dest_addr = dest_addr.parse().unwrap();

//     let commitment = DepositCommitment::Address(dest_addr).encode()?;

//     let url = format!("{}/address", relayer,);
//     let client = reqwest::Client::new();
//     let res = client
//         .post(url)
//         .query(&[
//             ("sigset_index", &sigset_index.to_string()),
//             ("deposit_addr", &deposit_addr),
//         ])
//         .body(commitment)
//         .send()
//         .await
//         .unwrap();
//     match res.status() {
//         StatusCode::OK => Ok(()),
//         _ => Err(Error::Relayer(format!(
//             "Relayer response returned with error code: {}",
//             res.status()
//         ))),
//     }
// }

// async fn poll_for_signatory_key() {
//     info!("Scanning for signatory key...");
//     let client = app_client();

//     loop {
//         match client.bitcoin.checkpoints.active_sigset().await {
//             Ok(_) => break,
//             Err(_) => tokio::time::sleep(Duration::from_secs(2)).await,
//         }
//     }
// }

// async fn poll_for_completed_checkpoint(num_checkpoints: u32) {
//     info!("Scanning for signed checkpoints...");
//     let client = app_client();

//     let mut signed_checkpoint = client
//         .bitcoin
//         .checkpoints
//         .completed()
//         .await
//         .unwrap()
//         .unwrap();

//     while signed_checkpoint.len() < num_checkpoints as usize {
//         signed_checkpoint = client
//             .bitcoin
//             .checkpoints
//             .completed()
//             .await
//             .unwrap()
//             .unwrap();
//         tokio::time::sleep(Duration::from_secs(1)).await;
//     }

//     info!("New signed checkpoint discovered")
// }

// async fn poll_for_bitcoin_header(height: u32) -> Result<()> {
//     info!("Scanning for bitcoin header {}...", height);
//     let client = app_client();
//     loop {
//         let current_height = client.bitcoin.headers.height().await??;
//         if current_height >= height {
//             info!("Found bitcoin header {}", height);
//             break Ok(());
//         }
//     }
// }

// async fn sign_and_broadcast(sign_doc: SignDoc, account: &KeyData) {
//     info!("Signing transaction...");
//     let sign_json = serde_json::to_vec(&sign_doc).unwrap();

//     let signing_key = SigningKey::from_bytes(&account.privkey.secret_bytes()).unwrap();

//     let pubkey = secp256k1::PublicKey::from_secret_key(
//         &bitcoin::secp256k1::Secp256k1::new(),
//         &account.privkey,
//     );

//     let orga_pubkey = OrgaPubKey {
//         type_: "tendermint/PubKeySecp256k1".to_string(),
//         value: base64::encode(pubkey.serialize()),
//     };

//     let signature = signing_key.sign(&sign_json).unwrap();
//     let orga_signature = OrgaSignature {
//         pub_key: orga_pubkey,
//         signature: base64::encode(signature),
//         r#type: Some("sdk".to_string()),
//     };

//     let tx = make_std_tx(sign_doc, orga_signature);
//     let tx_bytes = serde_json::to_string(&tx).unwrap();
//     let tm_client = HttpClient::new("http://127.0.0.1:26657").unwrap();
//     let transaction = orga::cosmrs::tendermint::abci::transaction::Transaction::from(
//         tx_bytes.as_bytes().to_vec(),
//     );

//     info!("Broadcasting transaction...");
//     tm_client.broadcast_tx_commit(transaction).await.unwrap();
// }

// async fn deposit_bitcoin(
//     address: &Address,
//     btc: bitcoin::Amount,
//     wallet: &bitcoind::bitcoincore_rpc::Client,
// ) -> Result<()> {
//     let deposit_address = generate_deposit_address(address).await.unwrap();

//     broadcast_deposit_addr(
//         address.to_string(),
//         deposit_address.sigset_index,
//         "http://localhost:8999".to_string(),
//         deposit_address.deposit_addr.clone(),
//     )
//     .await
//     .unwrap();

//     wallet
//         .send_to_address(
//             &bitcoin::Address::from_str(&deposit_address.deposit_addr).unwrap(),
//             btc,
//             None,
//             None,
//             None,
//             None,
//             None,
//             None,
//         )
//         .unwrap();

//     Ok(())
// }

// async fn withdraw_bitcoin(
//     nomic_account: &KeyData,
//     usats: u64,
//     dest_address: &bitcoin::Address,
// ) -> Result<()> {
//     let withdraw_sign_doc = withdraw(
//         nomic_account.address.to_string(),
//         dest_address.to_string(),
//         Amount::from(usats).into(),
//     )
//     .await
//     .unwrap();

//     sign_and_broadcast(withdraw_sign_doc, nomic_account).await;
//     Ok(())
// }

// #[tokio::test]
// #[serial]
// async fn bitcoin_test() {
//     INIT.call_once(|| {
//         pretty_env_logger::init();
//         setup_time_context();
//     });

//     let mut conf = Conf::default();
//     conf.args.push("-txindex");
//     let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();

//     let block_data = populate_bitcoin_block(&bitcoind);

//     let home = tempdir().unwrap();
//     let path = home.into_path();

//     let node_path = path.clone();
//     let signer_path = path.clone();
//     let header_relayer_path = path.clone();

//     std::env::set_var("NOMIC_HOME_DIR", &path);

//     let funded_accounts = setup_test_app(&path, &block_data);

//     std::thread::spawn(move || {
//         info!("Starting Nomic node...");
//         Node::<nomic::app::App>::new(&node_path, Default::default())
//             .run()
//             .unwrap();
//     });

//     let relayer_config = RelayerConfig {
//         network: bitcoin::Network::Regtest,
//     };

//     let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind).await, app_client())
//         .configure(relayer_config.clone());
//     let headers = relayer.start_header_relay();

//     let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind).await, app_client())
//         .configure(relayer_config.clone());
//     let deposits = relayer.start_deposit_relay(&header_relayer_path);

//     let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind).await, app_client())
//         .configure(relayer_config.clone());
//     let checkpoints = relayer.start_checkpoint_relay();

//     let mut relayer = Relayer::new(test_bitcoin_client(&bitcoind).await, app_client())
//         .configure(relayer_config.clone());
//     let disbursal = relayer.start_emergency_disbursal_transaction_relay();

//     let signer = async {
//         tokio::time::sleep(Duration::from_secs(20)).await;
//         setup_test_signer(&signer_path).start().await.unwrap();

//         Ok(())
//     };

//     let test = async {
//         poll_for_blocks().await;
//         declare_validator(&path).await.unwrap();

//         funded_accounts.iter().for_each(|account| {
//             println!("account: {}", account.address);
//         });

//         let wallet = retry(|| bitcoind.create_wallet("nomic-integration-test"), 10).unwrap();
//         let wallet_address = wallet.get_new_address(None, None).unwrap();

//         let withdraw_address = wallet.get_new_address(None, None).unwrap();

//         let mut labels = vec![];
//         for i in 0..funded_accounts.len() {
//             labels.push(format!("funded-account-{}", i));
//         }

//         let mut import_multi_reqest = vec![];
//         for (i, account) in funded_accounts.iter().enumerate() {
//             import_multi_reqest.push(ImportMultiRequest {
//                 timestamp: ImportMultiRescanSince::Now,
//                 descriptor: None,
//                 script_pubkey: Some(ImportMultiRequestScriptPubkey::Script(&account.script)),
//                 redeem_script: None,
//                 witness_script: None,
//                 pubkeys: &[],
//                 keys: &[],
//                 range: None,
//                 internal: None,
//                 watchonly: Some(true),
//                 label: Some(&labels[i]),
//                 keypool: None,
//             });
//         }

//         wallet.import_multi(&import_multi_reqest, None).unwrap();

//         retry(
//             || bitcoind.client.generate_to_address(120, &wallet_address),
//             10,
//         )
//         .unwrap();

//         poll_for_bitcoin_header(1120).await.unwrap();

//         let balance = app_client()
//             .bitcoin
//             .accounts
//             .balance(funded_accounts[0].address)
//             .await
//             .unwrap()
//             .unwrap();
//         assert_eq!(balance, Amount::from(0));

//         poll_for_signatory_key().await;

//         deposit_bitcoin(
//             &funded_accounts[0].address,
//             bitcoin::Amount::from_btc(10.0).unwrap(),
//             &wallet,
//         )
//         .await
//         .unwrap();

//         deposit_bitcoin(
//             &funded_accounts[1].address,
//             bitcoin::Amount::from_btc(0.4).unwrap(),
//             &wallet,
//         )
//         .await
//         .unwrap();

//         retry(
//             || bitcoind.client.generate_to_address(1, &wallet_address),
//             10,
//         )
//         .unwrap();

//         poll_for_bitcoin_header(1121).await.unwrap();
//         poll_for_completed_checkpoint(1).await;

//         let balance = app_client()
//             .bitcoin
//             .accounts
//             .balance(funded_accounts[0].address)
//             .await
//             .unwrap()
//             .unwrap();
//         assert_eq!(balance, Amount::from(799999747200000));
//         let balance = app_client()
//             .bitcoin
//             .accounts
//             .balance(funded_accounts[1].address)
//             .await
//             .unwrap()
//             .unwrap();

//         assert_eq!(balance, Amount::from(31999747200000));

//         withdraw_bitcoin(&funded_accounts[0], 7000000000, &withdraw_address)
//             .await
//             .unwrap();

//         poll_for_completed_checkpoint(2).await;

//         let balance = app_client()
//             .bitcoin
//             .accounts
//             .balance(funded_accounts[0].address)
//             .await
//             .unwrap()
//             .unwrap();

//         assert_eq!(balance, Amount::from(799992747200000));

//         tokio::time::sleep(Duration::from_secs(65)).await;

//         retry(
//             || bitcoind.client.generate_to_address(100, &wallet_address),
//             10,
//         )
//         .unwrap();

//         let funded_account_balances: Vec<_> = funded_accounts
//             .iter()
//             .map(|account| {
//                 let bitcoin_address =
//                     &bitcoin::Address::from_script(&account.script, bitcoin::Network::Regtest)
//                         .unwrap();
//                 match wallet.get_received_by_address(bitcoin_address, None) {
//                     Ok(amount) => amount.to_sat(),
//                     _ => 0,
//                 }
//             })
//             .collect();

//         let expected_account_balances: Vec<u64> = vec![799992560, 31999560, 0, 0, 0, 0, 0, 0, 0, 0];

//         assert_eq!(funded_account_balances, expected_account_balances);

//         for (i, account) in funded_accounts[0..=1].iter().enumerate() {
//             let dump_address = wallet.get_new_address(None, None).unwrap();
//             let disbursal_txs = app_client()
//                 .bitcoin
//                 .checkpoints
//                 .emergency_disbursal_txs()
//                 .await
//                 .unwrap()
//                 .unwrap();

//             let spending_tx = disbursal_txs.get(1).unwrap();
//             let vout = spending_tx
//                 .output
//                 .iter()
//                 .position(|output| output.script_pubkey == account.script)
//                 .unwrap();

//             let tx_in = bitcoincore_rpc_async::json::CreateRawTransactionInput {
//                 txid: spending_tx.txid(),
//                 vout: vout.try_into().unwrap(),
//                 sequence: None,
//             };
//             let mut outputs = HashMap::new();
//             outputs.insert(
//                 dump_address.to_string(),
//                 bitcoin::Amount::from_sat(expected_account_balances[i] - 10000),
//             );

//             let tx = bitcoind
//                 .client
//                 .create_raw_transaction(&[tx_in], &outputs, None, None)
//                 .unwrap();

//             let privkey = bitcoin::PrivateKey::new(account.privkey, bitcoin::Network::Regtest);
//             let sign_res = bitcoind
//                 .client
//                 .sign_raw_transaction_with_key(
//                     &tx,
//                     &[privkey],
//                     None,
//                     Some(EcdsaSighashType::All.into()),
//                 )
//                 .unwrap();
//             let signed_tx: bitcoin::Transaction = sign_res.transaction().unwrap();

//             bitcoind.client.send_raw_transaction(&signed_tx).unwrap();

//             retry(
//                 || bitcoind.client.generate_to_address(1, &wallet_address),
//                 10,
//             )
//             .unwrap();

//             let sent_amount = match wallet.get_received_by_address(&dump_address, None) {
//                 Ok(amount) => amount.to_sat(),
//                 _ => 0,
//             };

//             assert_eq!(sent_amount, expected_account_balances[i] - 10000);
//         }

//         Err::<(), Error>(Error::Test("Test completed successfully".to_string()))
//     };

//     poll_for_blocks().await;

//     match futures::try_join!(headers, deposits, checkpoints, disbursal, signer, test) {
//         Err(Error::Test(_)) => (),
//         Ok(_) => (),
//         other => {
//             other.unwrap();
//         }
//     }
// }
