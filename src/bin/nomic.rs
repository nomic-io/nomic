#![feature(trivial_bounds)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(async_closure)]
#![feature(never_type)]

use std::path::PathBuf;

use bitcoincore_rpc_async::{Auth, Client as BtcClient};
use clap::Parser;
use futures::executor::block_on;
use nomic::bitcoin::{relayer::Relayer, signer::Signer};
use nomic::error::Result;
use nomicv2::command::Opts as LegacyOpts;
use orga::prelude::*;
use serde::{Deserialize, Serialize};
use tendermint_rpc::Client as _;

const STOP_SECONDS: i64 = 1657044000;

fn now_seconds() -> i64 {
    use std::time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn app_client() -> TendermintClient<nomic::app::App> {
    TendermintClient::new("http://localhost:26657").unwrap()
}

fn my_address() -> Address {
    let privkey = load_privkey().unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &privkey);
    Address::from_pubkey(pubkey.serialize())
}

#[derive(Parser, Debug)]
#[clap(
    version = env!("CARGO_PKG_VERSION"),
    author = "The Nomic Developers <hello@nomic.io>"
)]
pub struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    Start(StartCmd),
    #[cfg(debug_assertions)]
    StartDev(StartDevCmd),
    Send(SendCmd),
    SendNbtc(SendNbtcCmd),
    Balance(BalanceCmd),
    Delegations(DelegationsCmd),
    Validators(ValidatorsCmd),
    Delegate(DelegateCmd),
    Declare(DeclareCmd),
    Unbond(UnbondCmd),
    Redelegate(RedelegateCmd),
    Unjail(UnjailCmd),
    Edit(EditCmd),
    Claim(ClaimCmd),
    ClaimAirdrop(ClaimAirdropCmd),
    Legacy(LegacyCmd),
    Relayer(RelayerCmd),
    Signer(SignerCmd),
    SetSignatoryKey(SetSignatoryKeyCmd),
    Deposit(DepositCmd),
    Withdraw(WithdrawCmd),
}

impl Command {
    async fn run(&self) -> Result<()> {
        use Command::*;
        match self {
            Start(cmd) => cmd.run().await,
            #[cfg(debug_assertions)]
            StartDev(cmd) => cmd.run().await,
            Send(cmd) => cmd.run().await,
            SendNbtc(cmd) => cmd.run().await,
            Balance(cmd) => cmd.run().await,
            Delegate(cmd) => cmd.run().await,
            Declare(cmd) => cmd.run().await,
            Delegations(cmd) => cmd.run().await,
            Validators(cmd) => cmd.run().await,
            Unbond(cmd) => cmd.run().await,
            Redelegate(cmd) => cmd.run().await,
            Unjail(cmd) => cmd.run().await,
            Edit(cmd) => cmd.run().await,
            Claim(cmd) => cmd.run().await,
            ClaimAirdrop(cmd) => cmd.run().await,
            Legacy(cmd) => cmd.run().await,
            Relayer(cmd) => cmd.run().await,
            Signer(cmd) => cmd.run().await,
            SetSignatoryKey(cmd) => cmd.run().await,
            Deposit(cmd) => cmd.run().await,
            Withdraw(cmd) => cmd.run().await,
        }
    }
}

#[derive(Parser, Debug)]
pub struct StartCmd {
    #[clap(long, short)]
    pub state_sync: bool,
}

impl StartCmd {
    async fn run(&self) -> Result<()> {
        let state_sync = self.state_sync;

        tokio::task::spawn_blocking(move || {
            let old_name = nomicv2::app::CHAIN_ID;
            let new_name = nomic::app::CHAIN_ID;

            let has_old_node = Node::home(old_name).exists();
            let has_new_node = Node::home(new_name).exists();
            let started_old_node = Node::height(old_name).unwrap() > 0;
            let started_new_node = Node::height(new_name).unwrap() > 0;
            let upgrade_time_passed = now_seconds() > STOP_SECONDS;

            if has_old_node {
                println!("Legacy node height: {}", Node::height(old_name).unwrap());
            }

            let new_home = Node::home(new_name);
            let new_config_path = new_home.join("tendermint/config/config.toml");

            let old_home = Node::home(old_name);
            let old_config_path = old_home.join("tendermint/config/config.toml");

            if !upgrade_time_passed && !started_new_node {
                println!("Starting legacy node for migration...");

                let node = nomicv2::orga::abci::Node::<nomicv2::app::App>::new(
                    old_name,
                    Default::default(),
                )
                .with_genesis(include_bytes!("../../genesis/stakenet-2.json"))
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .stop_seconds(STOP_SECONDS);

                set_p2p_seeds(
                    &old_config_path,
                    &[
                        "238120dfe716082754048057c1fdc3d6f09609b5@161.35.51.124:26656",
                        "26814903a767984b3f46970160c8b6e46f3e35e6@66.94.126.60:26656",
                    ],
                );

                if !started_old_node {
                    // TODO: set default RPC boostrap nodes
                    configure_for_statesync(
                        &old_config_path,
                        &[
                            "http://161.35.51.124:26667",
                            "https://nomic-rpc.polkachu.com:443",
                        ],
                    );
                }

                let res = node.run();
                if let Err(nomicv2::orga::Error::ABCI(msg)) = res {
                    if &msg != "Reached stop height" {
                        panic!("{}", msg);
                    }
                } else {
                    res.unwrap();
                }
            }

            let has_old_node = Node::home(old_name).exists();

            if !has_new_node {
                println!("Initializing node at {}...", new_home.display());
                // TODO: configure default seeds
                Node::<nomic::app::App>::new(new_name, Default::default());

                if has_old_node {
                    let old_home = Node::home(old_name);
                    println!(
                        "Legacy network data detected, copying keys and config from {}...",
                        old_home.display(),
                    );

                    let copy = |file: &str| {
                        std::fs::copy(old_home.join(file), new_home.join(file)).unwrap();
                    };

                    copy("tendermint/config/priv_validator_key.json");
                    copy("tendermint/config/node_key.json");
                    copy("tendermint/config/config.toml");
                    deconfigure_statesync(&new_config_path);
                }

                edit_block_time(&new_config_path, "3s");
            }

            if upgrade_time_passed && !started_new_node && (!has_old_node || state_sync) {
                println!("Configuring node for state sync...");

                // TODO: set default seeds
                set_p2p_seeds(
                    &new_config_path,
                    &[
                        "238120dfe716082754048057c1fdc3d6f09609b5@161.35.51.124:26656",
                        "26814903a767984b3f46970160c8b6e46f3e35e6@66.94.126.60:26656",
                    ],
                );

                // TODO: set default RPC boostrap nodes
                configure_for_statesync(
                    &new_config_path,
                    &[
                        "http://161.35.51.124:26667",
                        "https://nomic-rpc.polkachu.com:443",
                    ],
                );
            }

            println!("Starting node...");
            // TODO: add cfg defaults
            Node::<nomic::app::App>::new(new_name, Default::default())
                .with_genesis(include_bytes!("../../genesis/stakenet-3.json"))
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .run()
                .unwrap();
        })
        .await
        .map_err(|err| orga::Error::App(err.to_string()))?;
        Ok(())
    }
}

fn configure_node<P, F>(cfg_path: &P, configure: F)
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

fn edit_block_time(cfg_path: &PathBuf, timeout_commit: &str) {
    configure_node(cfg_path, |cfg| {
        cfg["consensus"]["timeout_commit"] = toml_edit::value(timeout_commit);
    });
}

// TODO: append instead of replace
fn set_p2p_seeds(cfg_path: &PathBuf, seeds: &[&str]) {
    configure_node(cfg_path, |cfg| {
        cfg["p2p"]["seeds"] = toml_edit::value(seeds.join(","));
    });
}

fn deconfigure_statesync(cfg_path: &PathBuf) {
    configure_node(cfg_path, |cfg| {
        cfg["statesync"]["enable"] = toml_edit::value(false);
        cfg["statesync"]["rpc_servers"] = toml_edit::value("");
        cfg["statesync"]["trust_height"] = toml_edit::value(0);
        cfg["statesync"]["trust_hash"] = toml_edit::value("");
        cfg["statesync"]["trust_period"] = toml_edit::value("216h0m0s");
    });
}

fn configure_for_statesync(cfg_path: &PathBuf, rpc_servers: &[&str]) {
    println!("Getting bootstrap state for Tendermint light client...");
    let (height, hash) =
        block_on(get_bootstrap_state(rpc_servers)).expect("Failed to bootstrap state");
    println!(
        "Configuring light client at height {} with hash {}",
        height, hash
    );

    configure_node(cfg_path, |cfg| {
        cfg["statesync"]["enable"] = toml_edit::value(true);
        cfg["statesync"]["rpc_servers"] = toml_edit::value(rpc_servers.join(","));
        cfg["statesync"]["trust_height"] = toml_edit::value(height);
        cfg["statesync"]["trust_hash"] = toml_edit::value(hash.clone());
        cfg["statesync"]["trust_period"] = toml_edit::value("216h0m0s");
    });
}

async fn get_bootstrap_state(rpc_servers: &[&str]) -> Result<(i64, String)> {
    let rpc_clients: Vec<_> = rpc_servers
        .iter()
        .map(|addr| {
            tendermint_rpc::HttpClient::new(*addr).expect("Could not create tendermint RPC client")
        })
        .collect();

    // get median latest height
    let mut latest_heights = vec![];
    for client in rpc_clients.iter() {
        let status = client
            .status()
            .await
            .expect("Could not get tendermint status");
        let height = status.sync_info.latest_block_height.value();
        latest_heights.push(height);
    }
    latest_heights.sort_unstable();
    let latest_height = latest_heights[latest_heights.len() / 2] as u32;

    let height = latest_height.checked_sub(1000).unwrap_or(1);

    // get block hash
    let mut hash = None;
    for client in rpc_clients.iter() {
        let res = client
            .blockchain(height, height)
            .await
            .expect("Could not get tendermint block header");
        let block = &res.block_metas[0];
        if hash.is_none() {
            hash = Some(block.header.hash());
        }

        let hash = hash.as_ref().unwrap();
        if block.header.hash() != *hash {
            return Err(orga::Error::App("Block hashes do not match".to_string()).into());
        }
    }

    Ok((height as i64, hash.unwrap().to_string()))
}

#[cfg(debug_assertions)]
#[derive(Parser, Debug)]
pub struct StartDevCmd {}

#[cfg(debug_assertions)]
impl StartDevCmd {
    async fn run(&self) -> Result<()> {
        tokio::task::spawn_blocking(move || {
            let name = format!("{}-test", nomic::app::CHAIN_ID);

            println!("Starting node...");
            // TODO: add cfg defaults
            Node::<nomic::app::App>::new(name.as_str(), Default::default())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .run()
                .unwrap();
        })
        .await
        .map_err(|err| orga::Error::App(err.to_string()))?;
        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SendCmd {
    to_addr: Address,
    amount: u64,
}

impl SendCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .accounts
            .transfer(self.to_addr, self.amount.into())
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct SendNbtcCmd {
    to_addr: Address,
    amount: u64,
}

impl SendNbtcCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| {
                client
                    .bitcoin
                    .transfer(self.to_addr, self.amount.into())
                    .await
            })
            .noop()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct BalanceCmd {
    address: Option<Address>,
}

impl BalanceCmd {
    async fn run(&self) -> Result<()> {
        let address = self.address.unwrap_or_else(|| my_address());
        println!("address: {}", address);

        let balance = app_client().accounts.balance(address).await??;
        println!("{} NOM", balance);

        let balance = app_client().bitcoin.accounts.balance(address).await??;
        println!("{} NBTC", balance);

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DelegationsCmd;

impl DelegationsCmd {
    async fn run(&self) -> Result<()> {
        let address = my_address();
        let delegations = app_client().staking.delegations(address).await??;

        println!(
            "delegated to {} validator{}",
            delegations.len(),
            if delegations.len() == 1 { "" } else { "s" }
        );
        for (validator, delegation) in delegations {
            let staked = delegation.staked;
            let liquid: u64 = delegation
                .liquid
                .iter()
                .map(|(_, amount)| -> u64 { (*amount).into() })
                .sum();
            if staked == 0 && liquid == 0 {
                continue;
            }

            use nomic::app::Nom;
            use nomic::bitcoin::Nbtc;
            let liquid_nom = delegation
                .liquid
                .iter()
                .find(|(denom, _)| *denom == Nom::INDEX)
                .unwrap()
                .1;
            let liquid_nbtc = delegation
                .liquid
                .iter()
                .find(|(denom, _)| *denom == Nbtc::INDEX)
                .unwrap_or(&(0, 0.into()))
                .1;

            println!(
                "- {validator}: staked={staked} NOM, liquid={liquid_nom} NOM,{liquid_nbtc} NBTC",
            );
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct ValidatorsCmd;

impl ValidatorsCmd {
    async fn run(&self) -> Result<()> {
        let mut validators = app_client().staking.all_validators().await??;

        validators.sort_by(|a, b| b.amount_staked.cmp(&a.amount_staked));

        for validator in validators {
            let info: DeclareInfo =
                serde_json::from_slice(validator.info.bytes.as_slice()).unwrap();
            println!(
                "- {}\n\tVOTING POWER: {}\n\tMONIKER: {}\n\tDETAILS: {}",
                validator.address, validator.amount_staked, info.moniker, info.details
            );
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DelegateCmd {
    validator_addr: Address,
    amount: u64,
}

impl DelegateCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| {
                client
                    .accounts
                    .take_as_funding((self.amount + MIN_FEE).into())
                    .await
            })
            .staking
            .delegate_from_self(self.validator_addr, self.amount.into())
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct DeclareCmd {
    consensus_key: String,
    amount: u64,
    commission_rate: Decimal,
    commission_max: Decimal,
    commission_max_change: Decimal,
    min_self_delegation: u64,
    moniker: String,
    website: String,
    identity: String,
    details: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeclareInfo {
    moniker: String,
    website: String,
    identity: String,
    details: String,
}

impl DeclareCmd {
    async fn run(&self) -> Result<()> {
        use std::convert::TryInto;
        let consensus_key: [u8; 32] = base64::decode(&self.consensus_key)
            .map_err(|_| orga::Error::App("invalid consensus key".to_string()))?
            .try_into()
            .map_err(|_| orga::Error::App("invalid consensus key".to_string()))?;

        let info = DeclareInfo {
            moniker: self.moniker.clone(),
            website: self.website.clone(),
            identity: self.identity.clone(),
            details: self.details.clone(),
        };
        let info_json = serde_json::to_string(&info)
            .map_err(|_| orga::Error::App("invalid json".to_string()))?;
        let info_bytes = info_json.as_bytes().to_vec();

        let declaration = Declaration {
            consensus_key,
            amount: self.amount.into(),
            validator_info: info_bytes.into(),
            commission: Commission {
                rate: self.commission_rate,
                max: self.commission_max,
                max_change: self.commission_max_change,
            },
            min_self_delegation: self.min_self_delegation.into(),
        };

        Ok(app_client()
            .pay_from(async move |client| {
                client
                    .accounts
                    .take_as_funding((self.amount + MIN_FEE).into())
                    .await
            })
            .staking
            .declare_self(declaration)
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct EditCmd {
    commission_rate: Decimal,
    min_self_delegation: u64,
    moniker: String,
    website: String,
    identity: String,
    details: String,
}

impl EditCmd {
    async fn run(&self) -> Result<()> {
        let info = DeclareInfo {
            moniker: self.moniker.clone(),
            website: self.website.clone(),
            identity: self.identity.clone(),
            details: self.details.clone(),
        };
        let info_json = serde_json::to_string(&info)
            .map_err(|_| orga::Error::App("invalid json".to_string()))?;
        let info_bytes = info_json.as_bytes().to_vec();

        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .edit_validator_self(
                self.commission_rate,
                self.min_self_delegation.into(),
                info_bytes.into(),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct UnbondCmd {
    validator_addr: Address,
    amount: u64,
}

impl UnbondCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .unbond_self(self.validator_addr, self.amount.into())
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct RedelegateCmd {
    src_validator_addr: Address,
    dest_validator_addr: Address,
    amount: u64,
}

impl RedelegateCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .redelegate_self(
                self.src_validator_addr,
                self.dest_validator_addr,
                self.amount.into(),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct UnjailCmd {}

impl UnjailCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .unjail()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct ClaimCmd;

impl ClaimCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.staking.claim_all().await)
            .deposit_rewards()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct ClaimAirdropCmd;

impl ClaimAirdropCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.atom_airdrop.claim().await)
            .accounts
            .give_from_funding_all()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct LegacyCmd {
    #[clap(subcommand)]
    cmd: nomicv2::command::Command,
}

impl LegacyCmd {
    async fn run(&self) -> Result<()> {
        self.cmd.run().await.unwrap();

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct RelayerCmd {
    #[clap(short = 'p', long, default_value_t = 8332)]
    rpc_port: u16,

    #[clap(short = 'u', long)]
    rpc_user: Option<String>,

    #[clap(short = 'P', long)]
    rpc_pass: Option<String>,

    #[clap(long)]
    path: Option<String>,
}

impl RelayerCmd {
    async fn btc_client(&self) -> Result<BtcClient> {
        let rpc_url = format!("http://localhost:{}", self.rpc_port);
        let auth = match (self.rpc_user.clone(), self.rpc_pass.clone()) {
            (Some(user), Some(pass)) => Auth::UserPass(user, pass),
            _ => Auth::None,
        };

        let btc_client = BtcClient::new(rpc_url, auth)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;

        Ok(btc_client)
    }

    async fn run(&self) -> Result<()> {
        let create_relayer = async || {
            let btc_client = self.btc_client().await.unwrap();

            Relayer::new(btc_client, app_client()).await
        };

        let mut relayer = create_relayer().await;
        let headers = relayer.start_header_relay();

        let relayer_dir_path = self
            .path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| Node::home(nomic::app::CHAIN_ID).join("relayer"));
        if !relayer_dir_path.exists() {
            std::fs::create_dir(&relayer_dir_path)?;
        }
        let mut relayer = create_relayer().await;
        let deposits = relayer.start_deposit_relay(relayer_dir_path);

        let mut relayer = create_relayer().await;
        let checkpoints = relayer.start_checkpoint_relay();

        futures::try_join!(headers, deposits, checkpoints).unwrap();

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SignerCmd {
    #[clap(short, long)]
    path: Option<String>,
}

impl SignerCmd {
    async fn run(&self) -> Result<()> {
        let signer_dir_path = self
            .path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| Node::home(nomic::app::CHAIN_ID).join("signer"));
        if !signer_dir_path.exists() {
            std::fs::create_dir(&signer_dir_path)?;
        }
        let key_path = signer_dir_path.join("xpriv");

        let signer = Signer::load_or_generate(app_client(), key_path)?;
        signer.start().await?;

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SetSignatoryKeyCmd {
    xpub: bitcoin::util::bip32::ExtendedPubKey,
}

impl SetSignatoryKeyCmd {
    async fn run(&self) -> Result<()> {
        app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .bitcoin
            .set_signatory_key(self.xpub.into())
            .await?;

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DepositCmd {
    address: Option<Address>,
}

impl DepositCmd {
    async fn run(&self) -> Result<()> {
        let dest_addr = self.address.unwrap_or_else(|| my_address());

        let sigset = app_client().bitcoin.checkpoints.active_sigset().await??;
        let script = sigset.output_script(dest_addr)?;
        // TODO: get network from somewhere
        let btc_addr = bitcoin::Address::from_script(&script, bitcoin::Network::Bitcoin).unwrap();

        let client = reqwest::Client::new();
        client
            .post(format!(
                "https://relayer.nomic.io:8443?dest_addr={}&sigset_index={}&deposit_addr={}",
                dest_addr,
                sigset.index(),
                btc_addr,
            ))
            .send()
            .await
            .map_err(|err| nomic::error::Error::Orga(orga::Error::App(err.to_string())))?;

        println!("Deposit address: {}", btc_addr);
        println!("Expiration: {}", "5 days from now");
        // TODO: show real expiration

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct WithdrawCmd {
    dest: bitcoin::Address,
    amount: u64,
}

impl WithdrawCmd {
    async fn run(&self) -> Result<()> {
        use nomic::bitcoin::adapter::Adapter;

        let script = self.dest.script_pubkey();

        app_client()
            .pay_from(async move |client| {
                client
                    .bitcoin
                    .withdraw(Adapter::new(script), self.amount.into())
                    .await
            })
            .noop()
            .await?;

        Ok(())
    }
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    let is_start = std::env::args()
        .nth(1)
        .map(|s| s == "start")
        .unwrap_or(false);

    if is_start || now_seconds() > STOP_SECONDS {
        let opts = Opts::parse();
        if let Err(err) = opts.cmd.run().await {
            eprintln!("{}", err);
            std::process::exit(1);
        };
    } else {
        let opts = LegacyOpts::parse();

        if let Err(err) = opts.cmd.run().await {
            eprintln!("{}", err);
            std::process::exit(1);
        };
    }
}
