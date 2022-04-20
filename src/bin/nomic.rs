#![feature(trivial_bounds)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(async_closure)]
#![feature(never_type)]

use std::path::PathBuf;

use clap::Parser;
use futures::executor::block_on;
use nomic::error::Result;
use orga::prelude::*;
use serde::{Deserialize, Serialize};
use tendermint_rpc::Client as _;
use bitcoincore_rpc_async::{Auth, Client as BtcClient};
use nomic::bitcoin::relayer::Relayer;

const STOP_HEIGHT: u64 = 2_684_000;

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
    Init(InitCmd),
    Start(StartCmd),
    #[cfg(debug_assertions)]
    StartDev(StartDevCmd),
    Send(SendCmd),
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
}

impl Command {
    async fn run(&self) -> Result<()> {
        use Command::*;
        match self {
            Init(cmd) => cmd.run().await,
            Start(cmd) => cmd.run().await,
            #[cfg(debug_assertions)]
            StartDev(cmd) => cmd.run().await,
            Send(cmd) => cmd.run().await,
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
        }
    }
}

#[derive(Parser, Debug)]
pub struct InitCmd {}

impl InitCmd {
    async fn run(&self) -> Result<()> {
        tokio::task::spawn_blocking(|| {
            // TODO: add cfg defaults
            nomicv1::orga::abci::Node::<nomicv1::app::App>::new(nomicv1::app::CHAIN_ID);
        })
        .await
        .map_err(|err| orga::Error::App(err.to_string()))?;
        Ok(())
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
            let old_name = nomicv1::app::CHAIN_ID;
            let new_name = nomic::app::CHAIN_ID;

            let has_old_node = Node::home(old_name).exists();
            let has_new_node = Node::home(new_name).exists();
            let started_new_node = Node::height(old_name).unwrap() >= STOP_HEIGHT
                || Node::height(new_name).unwrap() > 0;
            if has_old_node {
                println!("Legacy node height: {}", Node::height(old_name).unwrap());
            }

            let new_home = Node::home(new_name);
            let config_path = new_home.join("tendermint/config/config.toml");

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
                }

                edit_block_time(&config_path, "3s");
            }

            if !has_old_node || state_sync {
                println!("Configuring node for state sync...");

                // TODO: set default seeds
                set_p2p_seeds(
                    &config_path,
                    &["238120dfe716082754048057c1fdc3d6f09609b5@161.35.51.124:26656"],
                );

                // TODO: set default RPC boostrap nodes
                configure_for_statesync(
                    &config_path,
                    &["http://161.35.51.124:27657", "http://161.35.51.124:28657"],
                );
            }

            if has_old_node && !started_new_node && !state_sync {
                println!("Starting legacy node for migration...");

                let res = nomicv1::orga::abci::Node::<nomicv1::app::App>::new(old_name)
                    .with_genesis(include_bytes!("../../genesis/stakenet.json"))
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit())
                    .stop_height(STOP_HEIGHT)
                    .run();

                if let Err(nomicv1::orga::Error::ABCI(msg)) = res {
                    if &msg != "Reached stop height" {
                        panic!("{}", msg);
                    }
                } else {
                    res.unwrap();
                }
            }

            println!("Starting node...");
            // TODO: add cfg defaults
            Node::<nomic::app::App>::new(new_name, Default::default())
                .with_genesis(include_bytes!(
                    "../../genesis/stakenet-2.json"
                ))
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

    // start from latest height - 1000
    let height = latest_height - 1000;

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
            .pay_from(async move |mut client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .accounts
            .transfer(self.to_addr, self.amount.into())
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct BalanceCmd;

impl BalanceCmd {
    async fn run(&self) -> Result<()> {
        let address = my_address();
        println!("address: {}", address);

        let balance = app_client().accounts.balance(address).await??;
        println!("balance: {} NOM", balance);

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
            let staked: u64 = delegation.staked.into();
            let liquid: u64 = delegation.liquid.into();
            if staked + liquid == 0 {
                continue;
            }
            println!(
                "- {}: staked={} NOM, liquid={} NOM",
                validator, staked, liquid
            );
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct ValidatorsCmd;

impl ValidatorsCmd {
    async fn run(&self) -> Result<()> {
        let validators = app_client().staking.all_validators().await??;

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
            .pay_from(async move |mut client| {
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
            .pay_from(async move |mut client| {
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
            .pay_from(async move |mut client| client.accounts.take_as_funding(MIN_FEE.into()).await)
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
            .pay_from(async move |mut client| client.accounts.take_as_funding(MIN_FEE.into()).await)
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
            .pay_from(async move |mut client| client.accounts.take_as_funding(MIN_FEE.into()).await)
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
            .pay_from(async move |mut client| client.accounts.take_as_funding(MIN_FEE.into()).await)
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
            .pay_from(async move |mut client| client.staking.claim_all().await)
            .accounts
            .give_from_funding_all()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct ClaimAirdropCmd;

impl ClaimAirdropCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |mut client| client.atom_airdrop.claim().await)
            .accounts
            .give_from_funding_all()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct LegacyCmd {
    #[clap(subcommand)]
    cmd: nomicv1::command::Command,
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
            let app_bitcoin_client = app_client()
                .pay_from(async move |mut client| client.accounts.take_as_funding(MIN_FEE.into()).await)
                .bitcoin;
            Relayer::new(btc_client, app_bitcoin_client)
        };

        let mut relayer = create_relayer().await;
        let headers = relayer.relay_headers().await;

        // let mut relayer = create_relayer().await;
        // let deposits = relayer.relay_deposits();

        // futures::try_join!(headers, deposits).unwrap();

        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    if let Err(err) = opts.cmd.run().await {
        eprintln!("{}", err);
        std::process::exit(1);
    };
}
