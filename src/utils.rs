//! Utility functions used by end-to-end tests.

#![cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "full")]
use crate::app::App;
use crate::app::Dest;
use crate::app::InnerApp;
use crate::app::Nom;
use crate::app_client;
use crate::bitcoin::checkpoint::Config as CheckpointQueueConfig;
#[cfg(feature = "full")]
use crate::bitcoin::header_queue::Config as HeaderQueueConfig;
use crate::bitcoin::relayer::DepositAddress;
#[cfg(feature = "full")]
use crate::bitcoin::signer::Signer;
use crate::bitcoin::Adapter;
use crate::bitcoin::Config as BitcoinConfig;
use crate::error::{Error, Result};
use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::{self, rand, SecretKey};
use bitcoin::util::bip32::ExtendedPrivKey;
#[cfg(feature = "full")]
use bitcoin::BlockHeader;
use bitcoin::Script;
#[cfg(feature = "full")]
use bitcoincore_rpc_async::{Auth, Client as BitcoinRpcClient, RpcApi};
use ed::Encode;
#[cfg(feature = "full")]
use log::info;
use log::warn;
use orga::client::AppClient;
use orga::client::Wallet;
use orga::coins::staking::{Commission, Declaration};
use orga::coins::Amount;
use orga::coins::{Address, Coin, Decimal};
use orga::context::Context;
#[cfg(feature = "full")]
use orga::merk::MerkStore;
use orga::plugins::load_privkey as orga_load_privkey;
use orga::plugins::sdk_compat::sdk;
use orga::plugins::{ABCIPlugin, ChainId, SignerCall, Time, MIN_FEE};
use orga::state::State;
#[cfg(feature = "full")]
use orga::store::BackingStore;
use orga::store::Read;
#[cfg(feature = "full")]
use orga::store::Write;
#[cfg(feature = "full")]
use orga::store::{Shared, Store};
use orga::tendermint::client::HttpClient;
use orga::Result as OrgaResult;
use orga::{client::wallet::DerivedKey, macros::build_call};
use rand::Rng;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Debug;
use std::fs;
#[cfg(feature = "full")]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn poll_for_active_sigset() {
    info!("Polling for active sigset...");
    loop {
        match app_client(DEFAULT_RPC)
            .query(|app| Ok(app.bitcoin.checkpoints.active_sigset()?))
            .await
        {
            Ok(_) => break,
            Err(_) => sleep(2).await,
        }
    }
}

pub const DEFAULT_RPC: &str = "http://localhost:26657";

pub fn retry<F, T, E>(f: F, max_retries: u32) -> std::result::Result<T, E>
where
    F: Fn() -> std::result::Result<T, E>,
{
    let mut retries = 0;
    loop {
        match f() {
            Ok(val) => return Ok(val),
            Err(e) => {
                if retries >= max_retries {
                    return Err(e);
                }
                retries += 1;
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    }
}

pub fn time_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub async fn sleep(interval: u64) {
    #[cfg(feature = "devnet")]
    tokio::time::sleep(Duration::from_millis(interval)).await;

    #[cfg(not(feature = "devnet"))]
    tokio::time::sleep(Duration::from_secs(interval)).await;
}

pub fn generate_sign_doc(chain_id: String, msg: sdk::Msg, nonce: u64) -> sdk::SignDoc {
    sdk::SignDoc {
        account_number: "0".to_string(),
        chain_id,
        fee: sdk::Fee {
            amount: vec![sdk::Coin {
                amount: "0".to_string(),
                denom: "unom".to_string(),
            }],
            gas: MIN_FEE.to_string(),
        },
        memo: "".to_string(),
        msgs: vec![msg],
        sequence: (nonce + 1).to_string(),
    }
}

pub fn make_std_tx(
    sign_doc: sdk::SignDoc,
    signature: sdk::Signature,
) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "msg".to_string(),
        serde_json::to_value(sign_doc.msgs).unwrap(),
    );
    map.insert(
        "fee".to_string(),
        serde_json::to_value(sign_doc.fee).unwrap(),
    );
    map.insert(
        "signatures".to_string(),
        serde_json::to_value(vec![signature]).unwrap(),
    );
    map.insert(
        "memo".to_string(),
        serde_json::to_value(sign_doc.memo).unwrap(),
    );
    map
}

pub fn generate_bitcoin_key(network: bitcoin::Network) -> Result<ExtendedPrivKey> {
    let seed: [u8; 32] = rand::thread_rng().gen();

    let network = match network {
        bitcoin::Network::Bitcoin => bitcoin::Network::Bitcoin,
        bitcoin::Network::Testnet | bitcoin::Network::Signet | bitcoin::Network::Regtest => {
            bitcoin::Network::Testnet
        }
    };

    Ok(ExtendedPrivKey::new_master(network, seed.as_slice())?)
}

pub fn load_bitcoin_key<P: AsRef<Path> + Clone>(path: P) -> Result<ExtendedPrivKey> {
    if !path.as_ref().exists() {
        return Err(Error::Signer(format!(
            "Path `{}` does not exist",
            path.as_ref().display()
        )));
    }

    let bytes = fs::read(path.clone())?;
    let text = String::from_utf8(bytes).unwrap();

    text.trim().parse().map_err(|_| {
        Error::Signer(format!(
            "Unable to parse key at {}",
            path.as_ref().display()
        ))
    })
}

pub fn load_or_generate(path: PathBuf, network: bitcoin::Network) -> Result<ExtendedPrivKey> {
    if path.exists() {
        warn!("Bitcoin key already exists at {}", path.display());
        info!("Loading key from {}", path.display());
        load_bitcoin_key(path)
    } else {
        let key = generate_bitcoin_key(network)?;
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path.clone(), key.to_string())?;
        info!("Generated bitcoin key at {}", path.display());
        warn!("This is your signer key. Back it up!");
        Ok(key)
    }
}

pub fn load_privkey(dir: &Path) -> Result<SecretKey> {
    let orga_home = dir.join(".orga-wallet");

    std::fs::create_dir_all(&orga_home)?;
    let keypair_path = orga_home.join("privkey");
    if keypair_path.exists() {
        let bytes = std::fs::read(&keypair_path)?;
        Ok(SecretKey::from_slice(bytes.as_slice())?)
    } else {
        let mut rng = rand::thread_rng();
        let privkey = SecretKey::new(&mut rng);
        std::fs::write(&keypair_path, privkey.secret_bytes())?;
        Ok(privkey)
    }
}

pub fn load_consensus_key(dir: &Path) -> Result<[u8; 32]> {
    let privkey_path = dir.join("tendermint/config/priv_validator_key.json");
    let bytes = std::fs::read(privkey_path)?;

    let json: serde_json::Value = serde_json::from_slice(bytes.as_slice()).unwrap();
    let key_string = json["pub_key"]["value"].to_string().replace('"', "");
    Ok(base64::decode(key_string)
        .map_err(|_| orga::Error::App("invalid consensus key".to_string()))?
        .try_into()
        .map_err(|_| orga::Error::App("invalid consensus key".to_string()))?)
}

pub fn set_time<T: Into<Time>>(time: T) {
    Context::add(time.into());
}

pub fn setup_chain_id_context(chain_id: String) {
    let ctx = ChainId(chain_id);
    Context::add(ctx);
}

#[cfg(feature = "full")]
pub async fn test_bitcoin_client(rpc_url: String, cookie_file: PathBuf) -> BitcoinRpcClient {
    BitcoinRpcClient::new(rpc_url, Auth::CookieFile(cookie_file))
        .await
        .unwrap()
}

pub fn address_from_privkey(privkey: &SecretKey) -> Address {
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), privkey);
    Address::from_pubkey(pubkey.serialize())
}

#[cfg(feature = "full")]
pub fn setup_test_signer<T: AsRef<Path>, F>(home: T, client: F) -> Signer<DerivedKey, F>
where
    F: Fn() -> orga::client::AppClient<InnerApp, InnerApp, HttpClient, Nom, DerivedKey>,
{
    let signer_dir_path = home.as_ref().join("signer");

    if !signer_dir_path.exists() {
        std::fs::create_dir(&signer_dir_path).unwrap();
    }

    let key_path = signer_dir_path.join("xpriv");
    Signer::load_xprivs(
        address_from_privkey(&load_privkey(home.as_ref()).unwrap()),
        key_path,
        Vec::default(),
        0.1,
        1.0,
        0,
        None,
        client,
        None,
    )
    .unwrap()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeclareInfo {
    pub moniker: String,
    pub website: String,
    pub identity: String,
    pub details: String,
}

#[cfg(feature = "full")]
pub async fn declare_validator(
    consensus_key: [u8; 32],
    wallet: DerivedKey,
    amount: u64,
) -> Result<()> {
    info!("Declaring validator...");

    let info = DeclareInfo {
        moniker: "nomic-integration-test".to_string(),
        website: "https://nomic.io".to_string(),
        identity: "0".to_string(),
        details: "The FitnessGram™ Pacer Test is a multistage aerobic capacity test that progressively gets more difficult as it continues.".to_string(),
    };

    let info_json =
        serde_json::to_string(&info).map_err(|_| orga::Error::App("invalid json".to_string()))?;
    let info_bytes = info_json.as_bytes().to_vec();

    let declaration = Declaration {
        consensus_key,
        amount: amount.into(),
        validator_info: info_bytes.try_into().unwrap(),
        commission: Commission {
            rate: Decimal::from_str("0.1").unwrap(),
            max: Decimal::from_str("0.2").unwrap(),
            max_change: Decimal::from_str("0.1").unwrap(),
        },
        min_self_delegation: 0.into(),
    };

    app_client(DEFAULT_RPC)
        .with_wallet(wallet)
        .call(
            move |app| build_call!(app.accounts.take_as_funding((100000 + MIN_FEE).into())),
            move |app| build_call!(app.staking.declare_self(declaration.clone())),
        )
        .await?;
    info!("Validator declared");
    Ok(())
}

#[cfg(feature = "full")]
pub async fn poll_for_blocks() {
    info!("Scanning for blocks...");
    loop {
        match app_client(DEFAULT_RPC)
            .query(|app| app.app_noop_query())
            .await
        {
            Ok(_) => {
                break;
            }
            Err(_) => {
                sleep(1).await;
            }
        }
    }
}

pub async fn poll_for_updated_query_data<T: PartialEq>(
    rpc_url: String,
    polling_text: Option<String>,
    timeout_secs: Option<u64>,
    initial_data: T,
    query: impl Fn(crate::app::InnerApp) -> OrgaResult<T>,
) -> Result<T> {
    if let Some(text) = polling_text {
        info!("{}", text);
    }

    let start_time = std::time::Instant::now();
    loop {
        if let Some(timeout) = timeout_secs {
            if start_time.elapsed().as_secs() >= timeout {
                return Err(crate::error::Error::Orga(orga::Error::App(
                    "Polling timed out".to_string(),
                )));
            }
        }

        if let Ok(data) = app_client(&rpc_url).query(&query).await {
            if data != initial_data {
                return Ok(data);
            }
        }

        sleep(1).await;
    }
}

pub async fn poll_for_finalized_query_data<T: PartialEq + Debug>(
    rpc_url: String,
    polling_text: Option<String>,
    timeout_secs: Option<u64>,
    finalized_data: T,
    query: impl Fn(crate::app::InnerApp) -> OrgaResult<T>,
) -> Result<T> {
    if let Some(text) = polling_text.clone() {
        info!("{}", text);
    }

    let start_time = std::time::Instant::now();
    loop {
        if let Some(timeout) = timeout_secs {
            if start_time.elapsed().as_secs() >= timeout {
                return Err(crate::error::Error::Orga(orga::Error::App(
                    "Polling timed out".to_string(),
                )));
            }
        }

        if let Ok(data) = app_client(&rpc_url).query(&query).await {
            if data == finalized_data {
                return Ok(data);
            }
        }

        sleep(1).await;
    }
}

#[cfg(feature = "full")]
pub struct BitcoinBlockData {
    pub height: u32,
    pub block_header: BlockHeader,
}

#[cfg(feature = "full")]
pub async fn populate_bitcoin_block(client: &BitcoinRpcClient) -> BitcoinBlockData {
    let tip_address = client.get_new_address(Some("tip"), None).await.unwrap();

    client
        .generate_to_address(1000, &tip_address)
        .await
        .unwrap();

    let tip_hash = client.get_best_block_hash().await.unwrap();
    let tip_header = client.get_block_header(&tip_hash).await.unwrap();

    let tip_height = client
        .get_block_header_info(&tip_hash)
        .await
        .unwrap()
        .height;

    BitcoinBlockData {
        height: tip_height as u32,
        block_header: tip_header,
    }
}

#[derive(Clone)]
pub struct NomicTestWallet {
    pub privkey: SecretKey,
    pub address: Address,
    pub script: Script,
    pub wallet: DerivedKey,
}

impl Wallet for NomicTestWallet {
    fn address(&self) -> OrgaResult<Option<Address>> {
        Ok(Some(self.wallet.address()))
    }

    fn sign(&self, call_bytes: &[u8]) -> OrgaResult<SignerCall> {
        self.wallet.sign(call_bytes)
    }
}

impl NomicTestWallet {
    pub fn new_rand() -> Self {
        let privkey = SecretKey::new(&mut rand::thread_rng());
        let address = address_from_privkey(&privkey);
        let script = address_to_script(address).unwrap();
        let secret_key = orga::secp256k1::SecretKey::from_slice(&privkey.secret_bytes()).unwrap();
        let wallet = DerivedKey::from_secret_key(secret_key);
        Self {
            privkey,
            address,
            script,
            wallet,
        }
    }

    pub fn bitcoin_address(&self) -> bitcoin::Address {
        bitcoin::Address::from_script(&self.script, bitcoin::Network::Regtest).unwrap()
    }
}

#[cfg(feature = "full")]
pub fn setup_test_app(
    home: &Path,
    num_accounts: u16,
    header_queue_config: Option<HeaderQueueConfig>,
    checkpoint_queue_config: Option<CheckpointQueueConfig>,
    bitcoin_config: Option<BitcoinConfig>,
    funded_addresses: Option<Vec<Address>>,
) -> Vec<NomicTestWallet> {
    let mut app = ABCIPlugin::<App>::default();
    let mut store = Store::new(BackingStore::Merk(Shared::new(MerkStore::new(
        home.join("merk"),
    ))));

    app.attach(store.clone()).unwrap();

    let keys = {
        let inner_app = &mut app
            .inner
            .inner
            .borrow_mut()
            .inner
            .inner
            .inner
            .inner
            .inner
            .inner;

        if let Some(config) = header_queue_config {
            inner_app.bitcoin.headers.configure(config).unwrap();
        }

        if let Some(config) = checkpoint_queue_config {
            inner_app.bitcoin.checkpoints.configure(config);
        }

        if let Some(config) = bitcoin_config {
            inner_app.bitcoin.configure(config);
        }

        let address = address_from_privkey(&load_privkey(home).unwrap());
        inner_app
            .accounts
            .deposit(address, Coin::mint(1000000000))
            .unwrap();
        let keys: Vec<NomicTestWallet> = (0..num_accounts)
            .map(|_| NomicTestWallet::new_rand())
            .collect();

        keys.iter()
            .map(|key| key.address)
            .chain(funded_addresses.unwrap_or_default())
            .for_each(|address| {
                inner_app
                    .accounts
                    .deposit(address, Coin::mint(1000000000))
                    .unwrap();
            });

        keys
    };

    let mut bytes = Vec::new();
    app.flush(&mut bytes).unwrap();
    store.put(vec![], bytes).unwrap();

    if let BackingStore::Merk(inner_store) = store.into_backing_store().into_inner() {
        let mut store = inner_store.into_inner();
        store.write(vec![]).unwrap();
    }

    keys
}

pub fn address_to_script(address: Address) -> Result<Script> {
    let hash = bitcoin::hashes::hash160::Hash::from_str(address.bytes().to_hex().as_str())
        .map_err(|err| Error::BitcoinPubkeyHash(err.to_string()))?;
    let pubkey_hash = bitcoin::PubkeyHash::from(hash);
    Ok(bitcoin::Script::new_p2pkh(&pubkey_hash))
}

pub fn start_rest() -> Result<Child> {
    Ok(Command::new("cargo")
        .current_dir("./rest")
        .env("ROCKET_PORT", "8443")
        .env("ROCKET_ADDRESS", "0.0.0.0")
        .arg("run")
        .arg("start")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?)
}

pub fn export_state(path: &Path) -> Result<()> {
    let store_path = path.join("merk");
    let store = Store::new(BackingStore::Merk(Shared::new(MerkStore::open_readonly(
        store_path,
    )?)));
    let root_bytes = store.get(&[])?.unwrap();
    let app = ABCIPlugin::<App>::load(store, &mut root_bytes.as_slice())?;
    let file = std::fs::File::create("state.json")?;
    serde_json::to_writer_pretty(file, &app).unwrap();
    Ok(())
}

pub async fn generate_deposit_address(address: &Address) -> Result<DepositAddress> {
    info!("Generating deposit address for {}...", address);
    let (sigset, threshold) = app_client(DEFAULT_RPC)
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
        _ => Err(Error::Relayer(res.text().await.unwrap())),
    }
}

pub async fn set_recovery_address(nomic_account: NomicTestWallet) -> Result<()> {
    info!("Setting recovery address...");

    app_client(DEFAULT_RPC)
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

pub async fn withdraw_bitcoin(
    nomic_account: &NomicTestWallet,
    amount: bitcoin::Amount,
    dest_address: &bitcoin::Address,
) -> Result<()> {
    let dest_script = Adapter::new(dest_address.script_pubkey());
    let usats = amount.to_sat() * 1_000_000;
    app_client(DEFAULT_RPC)
        .with_wallet(nomic_account.wallet.clone())
        .call(
            move |app| build_call!(app.withdraw_nbtc(dest_script, Amount::from(usats))),
            |app| build_call!(app.app_noop()),
        )
        .await?;
    Ok(())
}

pub async fn get_signatory_script() -> Result<Script> {
    Ok(app_client(DEFAULT_RPC)
        .query(|app: InnerApp| {
            let tx = app.bitcoin.checkpoints.emergency_disbursal_txs()?;
            Ok(tx[0].output[1].script_pubkey.clone())
        })
        .await?)
}

pub fn client_provider() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, DerivedKey> {
    let val_priv_key = orga_load_privkey().unwrap();
    let wallet = DerivedKey::from_secret_key(val_priv_key);
    app_client(DEFAULT_RPC).with_wallet(wallet)
}

pub fn edit_block_time(cfg_path: &std::path::PathBuf, timeout_commit: &str) {
    configure_node(cfg_path, |cfg| {
        cfg["consensus"]["timeout_commit"] = toml_edit::value(timeout_commit);
    });
}

pub fn configure_node<P, F>(cfg_path: &P, configure: F)
where
    P: AsRef<std::path::Path>,
    F: Fn(&mut toml_edit::Document),
{
    let data = std::fs::read_to_string(cfg_path).expect("Failed to read config.toml");

    let mut toml = data
        .parse::<toml_edit::Document>()
        .expect("Failed to parse config.toml");

    configure(&mut toml);

    std::fs::write(cfg_path, toml.to_string()).expect("Failed to write config.toml");
}
