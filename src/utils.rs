#[cfg(feature = "full")]
use crate::app::App;
use crate::app::CHAIN_ID;
#[cfg(feature = "full")]
use crate::app_client;
#[cfg(feature = "full")]
use crate::bitcoin::adapter::Adapter;
#[cfg(feature = "full")]
use crate::bitcoin::checkpoint::Config as CheckpointQueueConfig;
#[cfg(feature = "full")]
use crate::bitcoin::header_queue::Config as HeaderQueueConfig;
#[cfg(feature = "full")]
use crate::bitcoin::signer::Signer;
use crate::error::Result;
use bitcoin::secp256k1::{self, rand, SecretKey};
#[cfg(feature = "full")]
use bitcoin::BlockHeader;
#[cfg(feature = "full")]
use bitcoincore_rpc_async::{Auth, Client as BitcoinRpcClient};
#[cfg(feature = "full")]
use bitcoind::bitcoincore_rpc::RpcApi;
#[cfg(feature = "full")]
use bitcoind::BitcoinD;
#[cfg(feature = "full")]
use ed::Encode;
#[cfg(feature = "full")]
use log::info;
#[cfg(feature = "full")]
use orga::merk::BackingStore;
#[cfg(feature = "full")]
use orga::merk::MerkStore;
use orga::prelude::sdk_compat::sdk;
#[cfg(feature = "full")]
use orga::prelude::{ABCIPlugin, Coin, Commission, Decimal, Declaration, State};
use orga::prelude::{Address, MIN_FEE};
#[cfg(feature = "full")]
use orga::store::Write;
#[cfg(feature = "full")]
use orga::store::{Shared, Store};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "full")]
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
#[cfg(feature = "full")]
use std::str::FromStr;
#[cfg(feature = "full")]
use std::time::Duration;

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

#[cfg(feature = "full")]
pub async fn test_bitcoin_client(bitcoind: &BitcoinD) -> BitcoinRpcClient {
    let bitcoind_url = bitcoind.rpc_url();
    let bitcoin_cookie_file = bitcoind.params.cookie_file.clone();
    BitcoinRpcClient::new(bitcoind_url, Auth::CookieFile(bitcoin_cookie_file))
        .await
        .unwrap()
}

pub fn address_from_privkey(privkey: &SecretKey) -> Address {
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &privkey);
    Address::from_pubkey(pubkey.serialize())
}

#[cfg(feature = "full")]
pub fn setup_test_signer<T: AsRef<Path>>(home: T) -> Signer {
    let signer_dir_path = home.as_ref().join("signer");

    if !signer_dir_path.exists() {
        std::fs::create_dir(&signer_dir_path).unwrap();
    }

    let key_path = signer_dir_path.join("xpriv");

    Signer::load_or_generate(
        address_from_privkey(&load_privkey(home.as_ref()).unwrap()),
        app_client(),
        key_path,
        0.1,
        1.0,
    )
    .unwrap()
}

#[cfg(feature = "full")]
fn get_tendermint_height() -> Result<Option<String>> {
    let curl_child = Command::new("curl")
        .arg("localhost:26657/status")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    Ok(Command::new("jq")
        .args(vec!["-r", ".result.sync_info.latest_block_height"])
        .stdin(Stdio::from(curl_child.stdout.unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?
        .stdout
        .map(|opt| {
            let mut reader = BufReader::new(opt);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            line
        }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeclareInfo {
    pub moniker: String,
    pub website: String,
    pub identity: String,
    pub details: String,
}

#[cfg(feature = "full")]
pub async fn declare_validator(home: &Path) -> Result<()> {
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

    app_client()
        .pay_from(async move |client| {
            client
                .accounts
                .take_as_funding((100000 + MIN_FEE).into())
                .await
        })
        .staking
        .declare_self(declaration)
        .await
        .unwrap();
    info!("Validator declared");
    Ok(())
}

#[cfg(feature = "full")]
pub async fn poll_for_blocks() {
    info!("Scanning for blocks...");
    let mut height = get_tendermint_height().ok().flatten();

    while height.is_none() || height == Some("".to_string()) {
        height = get_tendermint_height()
            .ok()
            .flatten()
            .filter(|height| height != "0");
        tokio::time::sleep(Duration::from_secs(1)).await;
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
}

#[cfg(feature = "full")]
pub fn setup_test_app(home: &Path, block_data: &BitcoinBlockData) -> Vec<KeyData> {
    let mut app = ABCIPlugin::<App>::default();
    let mut store = Store::new(BackingStore::Merk(Shared::new(MerkStore::new(
        home.join("merk"),
    ))));

    app.attach(store.clone()).unwrap();

    let headers_config = HeaderQueueConfig {
        encoded_trusted_header: Adapter::new(block_data.block_header)
            .encode()
            .unwrap()
            .try_into()
            .unwrap(),
        trusted_height: block_data.height,
        retargeting: false,
        min_difficulty_blocks: true,
        ..Default::default()
    };
    app.inner.bitcoin.headers.configure(headers_config).unwrap();

    let checkpoints_config = CheckpointQueueConfig {
        min_checkpoint_interval: 1,
        ..Default::default()
    };

    app.inner.bitcoin.checkpoints.configure(checkpoints_config);

    let address = address_from_privkey(&load_privkey(home).unwrap());
    app.inner
        .accounts
        .deposit(address, Coin::mint(1000000000))
        .unwrap();

    let keys: Vec<KeyData> = (0..10)
        .map(|_| {
            let privkey = SecretKey::new(&mut rand::thread_rng());
            let address = address_from_privkey(&privkey);
            KeyData { privkey, address }
        })
        .collect();

    keys.iter().for_each(|key| {
        app.inner
            .accounts
            .deposit(key.address, Coin::mint(1000000000))
            .unwrap();
    });

    let mut bytes = Vec::new();
    app.flush(&mut bytes).unwrap();

    store.put(vec![], bytes).unwrap();

    if let BackingStore::Merk(inner_store) = store.into_backing_store().into_inner() {
        inner_store.into_inner().write(vec![]).unwrap();
    }

    keys
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
