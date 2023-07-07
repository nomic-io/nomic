#[cfg(feature = "full")]
use crate::app::App;
use crate::app::Nom;
use crate::app::CHAIN_ID;
#[cfg(feature = "full")]
use crate::bitcoin::adapter::Adapter;
#[cfg(feature = "full")]
use crate::bitcoin::checkpoint::Config as CheckpointQueueConfig;
#[cfg(feature = "full")]
use crate::bitcoin::header_queue::Config as HeaderQueueConfig;
#[cfg(feature = "full")]
use crate::bitcoin::signer::Signer;
use crate::error::{Error, Result};
use crate::{app::InnerApp, app_client_testnet};
use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::{self, rand, SecretKey};
#[cfg(feature = "full")]
use bitcoin::BlockHeader;
use bitcoin::Script;
#[cfg(feature = "full")]
use bitcoind::bitcoincore_rpc::RpcApi;
#[cfg(feature = "full")]
use bitcoind::bitcoincore_rpc::{Auth, Client as BitcoinRpcClient};
#[cfg(feature = "full")]
use bitcoind::BitcoinD;
use chrono::{TimeZone, Utc};
#[cfg(feature = "full")]
use ed::Encode;
#[cfg(feature = "full")]
use log::info;
use orga::coins::staking::{Commission, Declaration};
use orga::coins::{Address, Coin, Decimal};
use orga::context::Context;
#[cfg(feature = "full")]
use orga::merk::MerkStore;
use orga::plugins::sdk_compat::sdk;
use orga::plugins::{ABCIPlugin, ChainId, Time, MIN_FEE};
use orga::state::State;
#[cfg(feature = "full")]
use orga::store::BackingStore;
#[cfg(feature = "full")]
use orga::store::Write;
#[cfg(feature = "full")]
use orga::store::{Shared, Store};
use orga::tendermint::client::HttpClient;
use orga::{client::wallet::DerivedKey, macros::build_call};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "full")]
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
#[cfg(feature = "full")]
use std::str::FromStr;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub fn sleep(seconds: u64) {
    let duration = std::time::Duration::from_secs(seconds);
    std::thread::sleep(duration);
}

pub fn generate_sign_doc(msg: sdk::Msg, nonce: u64) -> sdk::SignDoc {
    sdk::SignDoc {
        account_number: "0".to_string(),
        chain_id: CHAIN_ID.to_string(),
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

pub fn setup_time_context() {
    let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
    let ctx = Time::from_seconds(genesis_time.timestamp());
    Context::add(ctx);
}

pub fn setup_chain_id_context(chain_id: String) {
    let ctx = ChainId(chain_id);
    Context::add(ctx);
}

#[cfg(feature = "full")]
pub fn test_bitcoin_client(bitcoind: &BitcoinD) -> BitcoinRpcClient {
    let bitcoind_url = bitcoind.rpc_url();
    let bitcoin_cookie_file = bitcoind.params.cookie_file.clone();
    BitcoinRpcClient::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap()
}

pub fn address_from_privkey(privkey: &SecretKey) -> Address {
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), privkey);
    Address::from_pubkey(pubkey.serialize())
}

#[cfg(feature = "full")]
pub fn setup_test_signer<T: AsRef<Path>>(
    home: T,
    client: fn() -> orga::client::AppClient<InnerApp, InnerApp, HttpClient, Nom, DerivedKey>,
) -> Signer<DerivedKey> {
    let signer_dir_path = home.as_ref().join("signer");

    if !signer_dir_path.exists() {
        std::fs::create_dir(&signer_dir_path).unwrap();
    }

    let key_path = signer_dir_path.join("xpriv");
    Signer::load_or_generate(
        address_from_privkey(&load_privkey(home.as_ref()).unwrap()),
        key_path,
        0.1,
        1.0,
        client,
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
pub async fn declare_validator(home: &Path, wallet: DerivedKey) -> Result<()> {
    info!("Declaring validator...");

    let consensus_key = load_consensus_key(home)?;

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
        amount: 100000.into(),
        validator_info: info_bytes.try_into().unwrap(),
        commission: Commission {
            rate: Decimal::from_str("0.1").unwrap(),
            max: Decimal::from_str("0.2").unwrap(),
            max_change: Decimal::from_str("0.1").unwrap(),
        },
        min_self_delegation: 0.into(),
    };

    app_client_testnet()
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
        match app_client_testnet().query(|app| app.app_noop_query()).await {
            Ok(_) => {
                break;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(feature = "full")]
pub struct BitcoinBlockData {
    height: u32,
    block_header: BlockHeader,
}

#[cfg(feature = "full")]
pub fn populate_bitcoin_block(client: &BitcoinD) -> BitcoinBlockData {
    let tip_address = client.client.get_new_address(Some("tip"), None).unwrap();

    client
        .client
        .generate_to_address(1000, &tip_address)
        .unwrap();

    let tip_hash = client.client.get_best_block_hash().unwrap();
    let tip_header = client.client.get_block_header(&tip_hash).unwrap();

    let tip_height = client
        .client
        .get_block_header_info(&tip_hash)
        .unwrap()
        .height;

    BitcoinBlockData {
        height: tip_height as u32,
        block_header: tip_header,
    }
}

pub struct KeyData {
    pub privkey: SecretKey,
    pub address: Address,
    pub script: Script,
}

#[cfg(feature = "full")]
pub fn setup_test_app(home: &Path, block_data: &BitcoinBlockData) -> Vec<KeyData> {
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
        inner_app.bitcoin.headers.configure(headers_config).unwrap();

        let checkpoints_config = CheckpointQueueConfig {
            min_checkpoint_interval: 15,
            ..Default::default()
        };

        inner_app.bitcoin.checkpoints.configure(checkpoints_config);

        let address = address_from_privkey(&load_privkey(home).unwrap());
        inner_app
            .accounts
            .deposit(address, Coin::mint(1000000000))
            .unwrap();

        let keys: Vec<KeyData> = (0..10)
            .map(|_| {
                let privkey = SecretKey::new(&mut rand::thread_rng());
                let address = address_from_privkey(&privkey);
                let script = address_to_script(address).unwrap();
                KeyData {
                    privkey,
                    address,
                    script,
                }
            })
            .collect();

        keys.iter().for_each(|key| {
            inner_app
                .accounts
                .deposit(key.address, Coin::mint(1000000000))
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
