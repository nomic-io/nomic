#![feature(trivial_bounds)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(async_closure)]
#![feature(never_type)]

use bitcoind::bitcoincore_rpc::{Auth, Client as BtcClient};
use clap::Parser;
use nomic::app::DepositCommitment;
use nomic::app::InnerApp;
use nomic::app::{self, Nom};
use nomic::app_client_testnet;
use nomic::bitcoin::{relayer::Relayer, signer::Signer};
use nomic::error::Result;
use orga::abci::Node;
use orga::client::wallet::{SimpleWallet, Wallet};
use orga::coins::{Address, Commission, Decimal, Declaration, Symbol};
use orga::macros::build_call;
use orga::merk::MerkStore;
use orga::plugins::MIN_FEE;
use orga::prelude::*;
use orga::{client::AppClient, tendermint::client::HttpClient};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use tendermint_rpc::Client as _;

const BANNER: &str = r#"
███╗   ██╗  ██████╗  ███╗   ███╗ ██╗  ██████╗
████╗  ██║ ██╔═══██╗ ████╗ ████║ ██║ ██╔════╝
██╔██╗ ██║ ██║   ██║ ██╔████╔██║ ██║ ██║
██║╚██╗██║ ██║   ██║ ██║╚██╔╝██║ ██║ ██║
██║ ╚████║ ╚██████╔╝ ██║ ╚═╝ ██║ ██║ ╚██████╗
╚═╝  ╚═══╝  ╚═════╝  ╚═╝     ╚═╝ ╚═╝  ╚═════╝
"#;

fn app_client() -> AppClient<app::InnerApp, app::InnerApp, HttpClient, app::Nom, SimpleWallet> {
    app_client_testnet().with_wallet(wallet())
}

fn wallet() -> SimpleWallet {
    let path = home::home_dir().unwrap().join(".orga-wallet");
    SimpleWallet::open(path).unwrap()
}

fn my_address() -> Address {
    wallet().address().unwrap().unwrap()
}

#[derive(Parser, Debug)]
#[clap(
    version = env!("CARGO_PKG_VERSION"),
    author = "The Nomic Developers <hello@nomic.io>"
)]
pub struct Opts {
    #[clap(subcommand)]
    cmd: Command,

    #[clap(flatten)]
    config: nomic::network::Config,
}

#[derive(Parser, Debug)]
pub enum Command {
    Start(StartCmd),
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
    Airdrop(AirdropCmd),
    ClaimAirdrop(ClaimAirdropCmd),
    Relayer(RelayerCmd),
    Signer(SignerCmd),
    SetSignatoryKey(SetSignatoryKeyCmd),
    Deposit(DepositCmd),
    #[cfg(feature = "testnet")]
    InterchainDeposit(InterchainDepositCmd),
    Withdraw(WithdrawCmd),
    #[cfg(feature = "testnet")]
    IbcDepositNbtc(IbcDepositNbtcCmd),
    #[cfg(feature = "testnet")]
    IbcWithdrawNbtc(IbcWithdrawNbtcCmd),
    #[cfg(feature = "testnet")]
    Grpc(GrpcCmd),
    #[cfg(feature = "testnet")]
    IbcTransfer(IbcTransferCmd),
    Export(ExportCmd),
}

impl Command {
    fn run(&self, config: &nomic::network::Config) -> Result<()> {
        use Command::*;
        let rt = tokio::runtime::Runtime::new().unwrap();

        if let Start(cmd) = self {
            return Ok(cmd.run()?);
        }

        if let Some(legacy_bin) = legacy_bin(config)? {
            let mut legacy_cmd = std::process::Command::new(legacy_bin);
            legacy_cmd.args(std::env::args().skip(1));
            log::debug!("Running legacy binary... ({:#?})", legacy_cmd);
            legacy_cmd.spawn()?.wait()?;
            return Ok(());
        }

        rt.block_on(async move {
            match self {
                Start(_cmd) => unreachable!(),
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
                Airdrop(cmd) => cmd.run().await,
                Relayer(cmd) => cmd.run().await,
                Signer(cmd) => cmd.run().await,
                SetSignatoryKey(cmd) => cmd.run().await,
                Deposit(cmd) => cmd.run().await,
                #[cfg(feature = "testnet")]
                InterchainDeposit(cmd) => cmd.run().await,
                Withdraw(cmd) => cmd.run().await,
                #[cfg(feature = "testnet")]
                IbcDepositNbtc(cmd) => cmd.run().await,
                #[cfg(feature = "testnet")]
                IbcWithdrawNbtc(cmd) => cmd.run().await,
                #[cfg(feature = "testnet")]
                Grpc(cmd) => cmd.run().await,
                #[cfg(feature = "testnet")]
                IbcTransfer(cmd) => cmd.run().await,
                Export(cmd) => cmd.run().await,
            }
        })
    }
}

#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
pub struct StartCmd {
    #[clap(flatten)]
    config: nomic::network::Config,

    #[clap(long)]
    pub tendermint_logs: bool,
    #[clap(long)]
    pub clone_store: Option<String>,
    #[clap(long)]
    pub reset_store_height: bool,
    #[clap(long)]
    pub unsafe_reset: bool,
    #[clap(long)]
    pub skip_init_chain: bool,
    #[clap(long)]
    pub migrate: bool,
    #[clap(long)]
    pub legacy_home: Option<String>,
    #[clap(long)]
    pub freeze_valset: bool,
    #[clap(long)]
    pub signal_version: Option<String>,
    #[clap(long)]
    pub validator_key: Option<String>,
    #[clap(long)]
    pub node_key: Option<String>,
}

impl StartCmd {
    fn run(&self) -> orga::Result<()> {
        let cmd = self.clone();
        let home = cmd.config.home_expect()?;

        if cmd.freeze_valset {
            std::env::set_var("ORGA_STATIC_VALSET", "true");
        }

        let mut should_migrate = false;
        let legacy_bin = legacy_bin(&cmd.config)?;
        if let Some(legacy_bin) = legacy_bin {
            let mut legacy_cmd = std::process::Command::new(legacy_bin);
            if let Some(upgrade_height) = cmd.config.upgrade_height {
                legacy_cmd.env("ORGA_STOP_HEIGHT", upgrade_height.to_string());
            }

            #[cfg(feature = "testnet")]
            {
                let version_hex = hex::encode([InnerApp::CONSENSUS_VERSION]);
                legacy_cmd.args(["start", "--signal-version", &version_hex]);
                legacy_cmd.args(std::env::args().skip(2).collect::<Vec<_>>());
            }
            #[cfg(not(feature = "testnet"))]
            {
                legacy_cmd.args(["start", "--state-sync"]);
            }

            log::info!("Starting legacy node... ({:#?})", legacy_cmd);
            let res = legacy_cmd.spawn()?.wait()?;
            match res.code() {
                Some(138) => {
                    log::info!("Legacy node exited for upgrade");
                    should_migrate = true;
                }
                Some(code) => {
                    log::error!("Legacy node exited unexpectedly");
                    std::process::exit(code);
                }
                None => panic!("Legacy node exited unexpectedly"),
            }
        }

        println!("{}\nVersion {}\n\n", BANNER, env!("CARGO_PKG_VERSION"));

        let has_node = if !home.join("merk/db/CURRENT").exists() {
            false
        } else {
            let store = MerkStore::open_readonly(home.join("merk"));
            store.merk().get_aux(b"height").unwrap().is_some()
        };
        let config_path = home.join("tendermint/config/config.toml");
        let chain_id = cmd.config.chain_id.as_deref();
        if !has_node {
            log::info!("Initializing node at {}...", home.display());

            let node = Node::<nomic::app::App>::new(&home, chain_id, Default::default());

            if let Some(source) = cmd.clone_store {
                let mut source = PathBuf::from_str(&source).unwrap();
                if std::fs::read_dir(&source)?.any(|c| c.as_ref().unwrap().file_name() == "merk") {
                    source = source.join("merk");
                }
                log::info!("Cloning store from {}...", source.display());
                node.init_from_store(
                    source,
                    if cmd.reset_store_height {
                        Some(0)
                    } else {
                        None
                    },
                );
            }
            if let Some(val_key) = cmd.validator_key {
                let val_key = PathBuf::from_str(&val_key).unwrap();
                log::info!("Copying validator key from {}", val_key.display());
                std::fs::copy(
                    val_key,
                    home.join("tendermint/config/priv_validator_key.json"),
                )
                .unwrap();
            }
            if let Some(node_key) = cmd.node_key {
                let node_key = PathBuf::from_str(&node_key).unwrap();
                log::info!("Copying node key from {}", node_key.display());
                std::fs::copy(node_key, home.join("tendermint/config/node_key.json")).unwrap();
            }

            edit_block_time(&config_path, "3s");

            configure_node(&config_path, |cfg| {
                cfg["rpc"]["laddr"] = toml_edit::value("tcp://0.0.0.0:26657");
            });

            if !cmd.config.state_sync_rpc.is_empty() {
                let servers: Vec<_> = cmd
                    .config
                    .state_sync_rpc
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                configure_for_statesync(&home.join("tendermint/config/config.toml"), &servers);
            }
        } else if cmd.clone_store.is_some() {
            log::warn!(
                "--clone-store only applies used when initializing a network home, ignoring"
            );
        }

        let bin_path = home.join(format!("bin/nomic-{}", env!("CARGO_PKG_VERSION")));
        if !bin_path.exists() {
            log::debug!("Writing binary to {}", bin_path.display());
            let current_exe_bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
            std::fs::create_dir_all(home.join("bin")).unwrap();
            std::fs::write(&bin_path, current_exe_bytes).unwrap();
            std::fs::set_permissions(bin_path, Permissions::from_mode(0o777)).unwrap();
        }

        log::info!("Starting node at {}...", home.display());
        let mut node = Node::<nomic::app::App>::new(&home, chain_id, Default::default());

        if cmd.unsafe_reset {
            node = node.reset();
        }
        if let Some(genesis) = &cmd.config.genesis {
            let genesis_bytes = if genesis.contains('\n') {
                genesis.as_bytes().to_vec()
            } else {
                std::fs::read(genesis)?
            };
            std::fs::write(home.join("tendermint/config/genesis.json"), genesis_bytes)?;
        }
        if cmd.migrate || should_migrate {
            node = node.migrate(
                vec![InnerApp::CONSENSUS_VERSION],
                #[cfg(feature = "testnet")]
                false,
                #[cfg(not(feature = "testnet"))]
                true,
            );
        }
        if cmd.skip_init_chain {
            node = node.skip_init_chain();
        }
        if let Some(signal_version) = cmd.signal_version {
            let signal_version = hex::decode(signal_version).unwrap();
            let rt = tokio::runtime::Runtime::new().unwrap();
            std::thread::spawn(move || {
                rt.block_on(async move {
                    dbg!();
                    let signal_version = signal_version.clone();
                    let signal_version2 = signal_version.clone();
                    let signal_version3 = signal_version.clone();
                    let done = move || {
                        log::info!("Node has signaled {:?}", signal_version2);
                    };

                    loop {
                        let signal_version = signal_version.clone().try_into().unwrap();
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        if let Err(err) = app_client()
                            .call(
                                |app| build_call!(app.signal(signal_version)),
                                |app| build_call!(app.app_noop()),
                            )
                            .await
                        {
                            let msg = err.to_string();
                            if msg.ends_with("has already been signaled") {
                                return done();
                            } else {
                                log::debug!("Error when signaling: {}", msg);
                                continue;
                            }
                        } else {
                            log::info!("Signaled version {:?}", signal_version3);
                            return done();
                        }
                    }
                });
            });
        }

        if std::env::var("NOMIC_EXIT_ON_START").is_ok() {
            std::process::exit(139);
        }
        node.stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .print_tendermint_logs(cmd.tendermint_logs)
            .tendermint_flags(cmd.config.tendermint_flags.clone())
            .run()
    }
}

// TODO: move to config/nodehome?
fn legacy_bin(config: &nomic::network::Config) -> Result<Option<PathBuf>> {
    let home = match config.home() {
        Some(home) => home,
        None => {
            log::warn!("Unknown home directory, cannot automatically run legacy binary.");
            log::warn!("If the command fails, try running with --network, --home, or --chain-id.");
            return Ok(None);
        }
    };

    // TODO: skip if specifying node in config

    let legacy_version = std::env::var("NOMIC_LEGACY_VERSION")
        .ok()
        .or(config.legacy_version.clone());

    if let Some(legacy_version) = legacy_version {
        let (up_to_date, initialized) = {
            if !home.join("merk/db/CURRENT").exists() {
                (false, false)
            } else {
                let store = MerkStore::open_readonly(home.join("merk"));
                let store_ver = store.merk().get_aux(b"consensus_version").unwrap();
                let utd = if let Some(store_ver) = store_ver {
                    store_ver == vec![InnerApp::CONSENSUS_VERSION]
                } else {
                    false
                };
                let initialized = store.merk().get_aux(b"height").unwrap().is_some();
                (utd, initialized)
            }
        };

        // TODO: handle case where node is not initialized, but network is upgraded (can skip legacy binary)

        if up_to_date {
            log::debug!("Node version matches network version, no need to run legacy binary");
        } else {
            if legacy_version.is_empty() {
                log::warn!("Legacy version is empty, skipping run of legacy binary.");
                return Ok(None);
            }

            let bin_dir = home.join("bin");

            #[cfg(feature = "legacy-bin")]
            {
                if !bin_dir.exists() {
                    std::fs::create_dir_all(&bin_dir)?;
                }

                let bin_name = env!("NOMIC_LEGACY_BUILD_VERSION").trim().replace(' ', "-");
                let bin_path = bin_dir.join(bin_name);
                let bin_bytes = include_bytes!(env!("NOMIC_LEGACY_BUILD_PATH"));
                if !bin_path.exists() {
                    log::debug!("Writing legacy binary to {}...", bin_path.display());
                    std::fs::write(&bin_path, bin_bytes).unwrap();
                    std::fs::set_permissions(bin_path, Permissions::from_mode(0o777)).unwrap();
                }
            }

            if !bin_dir.exists() {
                log::warn!("Legacy binary does not exist, attempting to skip ahead");
            } else {
                let req = semver::VersionReq::parse(&legacy_version).unwrap();
                let mut legacy_bin = None;
                let mut legacy_ver = None;
                for bin in bin_dir.read_dir().unwrap() {
                    let bin = bin?;
                    let bin_name = bin.file_name();
                    if !bin_name
                        .clone()
                        .into_string()
                        .unwrap()
                        .starts_with("nomic-")
                    {
                        continue;
                    }
                    let bin_ver = bin_name.to_str().unwrap().trim_start_matches("nomic-");
                    let bin_ver = semver::Version::parse(bin_ver).unwrap();
                    if req.matches(&bin_ver) {
                        if let Some(lv) = &legacy_ver {
                            if &bin_ver > lv {
                                legacy_bin = Some(bin.path());
                                legacy_ver = Some(bin_ver);
                            }
                        } else {
                            legacy_bin = Some(bin.path());
                            legacy_ver = Some(bin_ver);
                        }
                    }
                }

                return if legacy_bin.is_none() {
                    if initialized {
                        return Err(orga::Error::App(format!("Could not find a legacy binary matching version {}, please build and run a compatible version first.", legacy_version)).into());
                    } else {
                        log::warn!("Could not find a legacy binary match, but node is uninitialized, continuing...");
                        Ok(None)
                    }
                } else {
                    let current_ver = semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
                    if &current_ver == legacy_ver.as_ref().unwrap() {
                        log::debug!(
                            "Legacy binary matches current binary, no need to run legacy binary"
                        );
                        Ok(None)
                    } else {
                        log::debug!(
                            "Found legacy binary {:?} matching version {}",
                            legacy_bin,
                            legacy_version
                        );
                        Ok(legacy_bin)
                    }
                };
            }
        }
    }

    Ok(None)
}

async fn relaunch_on_migrate(config: &nomic::network::Config) -> Result<()> {
    let home = match config.home() {
        Some(home) => home,
        None => {
            log::warn!("Unknown home directory, cannot automatically relaunch on migrate");
            return Ok(());
        }
    };

    let mut initial_ver = None;
    loop {
        if !home.exists() {
            continue;
        }
        let store = MerkStore::open_readonly(home.join("merk"));
        let store_ver = store.merk().get_aux(b"consensus_version").unwrap();
        if initial_ver.is_some() {
            if store_ver != initial_ver {
                log::info!(
                    "Node has migrated from version {:?} to version {:?}, exiting",
                    initial_ver,
                    store_ver
                );
                std::process::exit(138);
            }
        } else {
            initial_ver = store_ver;
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
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

fn configure_for_statesync(cfg_path: &PathBuf, rpc_servers: &[&str]) {
    log::info!("Getting bootstrap state for Tendermint light client...");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (height, hash) = rt
        .block_on(get_bootstrap_state(rpc_servers))
        .expect("Failed to bootstrap state");
    log::info!(
        "Configuring light client at height {} with hash {}",
        height,
        hash
    );

    configure_node(cfg_path, |cfg| {
        cfg["statesync"]["enable"] = toml_edit::value(true);
        cfg["statesync"]["rpc_servers"] = toml_edit::value(rpc_servers.join(","));
        cfg["statesync"]["trust_height"] = toml_edit::value(height);
        cfg["statesync"]["trust_hash"] = toml_edit::value(hash.clone());
        cfg["statesync"]["discovery_time"] = toml_edit::value("8s");
        if cfg["statesync"]["trust_period"].to_string() == "0" {
            cfg["statesync"]["trust_period"] = toml_edit::value("216h0m0s");
        }
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
        let status = match client.status().await {
            Ok(status) => status,
            Err(_) => continue,
        };
        let height = status.sync_info.latest_block_height.value();
        latest_heights.push(height);
    }

    if latest_heights.len() < rpc_servers.len() / 2 {
        return Err(orga::Error::App(
            "Failed to get state sync bootstrap data from nodes".to_string(),
        )
        .into());
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

#[derive(Parser, Debug)]
pub struct SendCmd {
    to_addr: Address,
    amount: u64,
}

impl SendCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.accounts.transfer(self.to_addr, self.amount.into())),
            )
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
            .call(
                |app| build_call!(app.bitcoin.transfer(self.to_addr, self.amount.into())),
                |app| build_call!(app.app_noop()),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct BalanceCmd {
    address: Option<Address>,
}

impl BalanceCmd {
    async fn run(&self) -> Result<()> {
        let address = self.address.unwrap_or_else(my_address);
        println!("address: {}", address);

        let balance = app_client()
            .query(|app| app.accounts.balance(address))
            .await?;
        println!("{} NOM", balance);

        let balance = app_client()
            .query(|app| app.bitcoin.accounts.balance(address))
            .await?;
        println!("{} NBTC", balance);

        #[cfg(feature = "testnet")]
        {
            let balance = app_client().query(|app| app.escrowed_nbtc(address)).await?;
            println!("{} IBC-escrowed NBTC", balance);
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DelegationsCmd;

impl DelegationsCmd {
    async fn run(&self) -> Result<()> {
        let address = my_address();
        let delegations = app_client()
            .query(|app| app.staking.delegations(address))
            .await?;

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
        let mut validators = app_client()
            .query(|app| app.staking.all_validators())
            .await?;

        validators.sort_by(|a, b| b.amount_staked.cmp(&a.amount_staked));

        for validator in validators {
            let bytes: Vec<u8> = validator.info.into();
            let info: DeclareInfo = serde_json::from_slice(bytes.as_slice()).unwrap();
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
            .call(
                |app| build_call!(app.accounts.take_as_funding((self.amount + MIN_FEE).into())),
                |app| {
                    build_call!(app
                        .staking
                        .delegate_from_self(self.validator_addr, self.amount.into()))
                },
            )
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
pub struct DeclareInfo {
    pub moniker: String,
    pub website: String,
    pub identity: String,
    pub details: String,
}

impl DeclareCmd {
    async fn run(&self) -> Result<()> {
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
            validator_info: info_bytes.try_into().unwrap(),
            commission: Commission {
                rate: self.commission_rate,
                max: self.commission_max,
                max_change: self.commission_max_change,
            },
            min_self_delegation: self.min_self_delegation.into(),
        };

        Ok(app_client()
            .call(
                |app| build_call!(app.accounts.take_as_funding((self.amount + MIN_FEE).into())),
                |app| build_call!(app.staking.declare_self(declaration.clone())),
            )
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
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| {
                    build_call!(app.staking.edit_validator_self(
                        self.commission_rate,
                        self.min_self_delegation.into(),
                        info_bytes.clone().try_into().unwrap()
                    ))
                },
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
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| {
                    build_call!(app
                        .staking
                        .unbond_self(self.validator_addr, self.amount.into()))
                },
            )
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
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| {
                    build_call!(app.staking.redelegate_self(
                        self.src_validator_addr,
                        self.dest_validator_addr,
                        self.amount.into()
                    ))
                },
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct UnjailCmd {}

impl UnjailCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.staking.unjail()),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct ClaimCmd;

impl ClaimCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .call(
                |app| build_call!(app.staking.claim_all()),
                |app| build_call!(app.deposit_rewards()),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct AirdropCmd {
    address: Option<Address>,
}

impl AirdropCmd {
    async fn run(&self) -> Result<()> {
        let client = app_client();

        let addr = self.address.unwrap_or_else(my_address);
        let acct = match client.query(|app| app.airdrop.get(addr)).await? {
            None => {
                println!("Address is not eligible for airdrop");
                return Ok(());
            }
            Some(acct) => acct,
        };

        println!("{:#?}", acct);

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct ClaimAirdropCmd {
    address: Option<Address>,
}

impl ClaimAirdropCmd {
    async fn run(&self) -> Result<()> {
        let client = app_client();

        let addr = self.address.unwrap_or_else(my_address);
        let acct = match client.query(|app| app.airdrop.get(addr)).await? {
            None => {
                println!("Address is not eligible for airdrop");
                return Ok(());
            }
            Some(acct) => acct,
        };

        let mut claimed = false;

        if acct.airdrop1.claimable > 0 {
            app_client()
                .call(
                    |app| build_call!(app.airdrop.claim_airdrop1()),
                    |app| build_call!(app.accounts.give_from_funding_all()),
                )
                .await?;
            println!("Claimed airdrop 1 ({} uNOM)", acct.airdrop1.claimable);
            claimed = true;
        }

        if acct.airdrop2.claimable > 0 {
            app_client()
                .call(
                    |app| build_call!(app.airdrop.claim_airdrop2()),
                    |app| build_call!(app.accounts.give_from_funding_all()),
                )
                .await?;
            println!("Claimed airdrop 2 ({} uNOM)", acct.airdrop2.claimable);
            claimed = true;
        }

        if !claimed {
            println!("No claimable airdrops");
        }

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

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl RelayerCmd {
    async fn btc_client(&self) -> Result<BtcClient> {
        let rpc_url = format!("http://localhost:{}", self.rpc_port);
        let auth = match (self.rpc_user.clone(), self.rpc_pass.clone()) {
            (Some(user), Some(pass)) => Auth::UserPass(user, pass),
            _ => Auth::None,
        };

        let btc_client =
            BtcClient::new(&rpc_url, auth).map_err(|e| orga::Error::App(e.to_string()))?;

        Ok(btc_client)
    }

    async fn run(&self) -> Result<()> {
        let create_relayer = async || {
            let btc_client = self.btc_client().await.unwrap();

            Relayer::new(btc_client)
        };

        let mut relayer = create_relayer().await;
        let headers = relayer.start_header_relay();

        let relayer_dir_path = self.config.home_expect()?.join("relayer");
        if !relayer_dir_path.exists() {
            std::fs::create_dir(&relayer_dir_path)?;
        }

        let relayer = create_relayer().await;
        let deposits = relayer.start_deposit_relay(relayer_dir_path);

        let mut relayer = create_relayer().await;
        let checkpoints = relayer.start_checkpoint_relay();

        let relaunch = relaunch_on_migrate(&self.config);

        futures::try_join!(headers, deposits, checkpoints, relaunch).unwrap();

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SignerCmd {
    #[clap(flatten)]
    config: nomic::network::Config,

    /// Limits the fraction of the total reserve that may be withdrawn within
    /// the trailing 24-hour period
    #[clap(long, default_value_t = 0.04)]
    max_withdrawal_rate: f64,
    /// Limits the maximum allowed signatory set change within 24 hours
    ///
    /// The Total Variation Distance between a day-old signatory set and the
    /// newly-proposed signatory set may not exceed this value
    #[clap(long, default_value_t = 0.04)]
    max_sigset_change_rate: f64,
}

impl SignerCmd {
    async fn run(&self) -> Result<()> {
        let signer_dir_path = self.config.home_expect()?.join("signer");
        if !signer_dir_path.exists() {
            std::fs::create_dir(&signer_dir_path)?;
        }

        let key_path = signer_dir_path.join("xpriv");

        let signer = Signer::load_or_generate(
            my_address(),
            key_path,
            self.max_withdrawal_rate,
            self.max_sigset_change_rate,
            app_client,
        )?
        .start();

        let relaunch = relaunch_on_migrate(&self.config);

        futures::try_join!(signer, relaunch).unwrap();

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
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(self.xpub.into())),
            )
            .await?;

        Ok(())
    }
}

async fn deposit(dest: DepositCommitment) -> Result<()> {
    let sigset = app_client()
        .query(|app| Ok(app.bitcoin.checkpoints.active_sigset()?))
        .await?;
    let script = sigset.output_script(dest.commitment_bytes()?.as_slice())?;
    let btc_addr = bitcoin::Address::from_script(&script, nomic::bitcoin::NETWORK).unwrap();

    let client = reqwest::Client::new();
    let res = client
        .post("https://testnet-relayer.nomic.io:8443/address")
        .query(&[
            ("sigset_index", sigset.index().to_string()),
            ("deposit_addr", btc_addr.to_string()),
        ])
        .body(dest.encode()?)
        .send()
        .await
        .map_err(|err| nomic::error::Error::Orga(orga::Error::App(err.to_string())))?;
    if res.status() != 200 {
        return Err(
            orga::Error::App(format!("Relayer responded with code {}", res.status())).into(),
        );
    }

    println!("Deposit address: {}", btc_addr);
    println!("Expiration: 5 days from now");
    // TODO: show real expiration
    Ok(())
}

#[derive(Parser, Debug)]
pub struct DepositCmd {
    address: Option<Address>,
}

impl DepositCmd {
    async fn run(&self) -> Result<()> {
        let dest_addr = self.address.unwrap_or_else(my_address);

        deposit(DepositCommitment::Address(dest_addr)).await
    }
}

#[cfg(feature = "testnet")]
#[derive(Parser, Debug)]
pub struct InterchainDepositCmd {
    #[clap(long, value_name = "ADDRESS")]
    receiver: String,
    #[clap(long, value_name = "CHANNEL_ID")]
    channel: String,
}

// #[cfg(feature = "testnet")]
// const ONE_DAY_NS: u64 = 86400 * 1_000_000_000;
#[cfg(feature = "testnet")]
impl InterchainDepositCmd {
    async fn run(&self) -> Result<()> {
        todo!()
        // use orga::ibc::encoding::Adapter;
        // let now_ns = now_seconds() as u64 * 1_000_000_000;
        // let dest = DepositCommitment::Ibc(nomic::app::IbcDepositCommitment {
        //     receiver: Adapter::new(self.receiver.parse().unwrap()),
        //     sender: Adapter::new(my_address().to_string().parse().unwrap()),
        //     source_channel: Adapter::new(self.channel.parse().unwrap()),
        //     source_port: Adapter::new("transfer".parse().unwrap()),
        //     timeout_timestamp: now_ns + 8 * ONE_DAY_NS - (now_ns % ONE_DAY_NS),
        // });

        // deposit(dest).await
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
            .call(
                |app| build_call!(app.withdraw_nbtc(Adapter::new(script), self.amount.into())),
                |app| build_call!(app.app_noop()),
            )
            .await?;

        Ok(())
    }
}

#[cfg(feature = "testnet")]
#[derive(Parser, Debug)]
pub struct IbcDepositNbtcCmd {
    to: Address,
    amount: u64,
}

#[cfg(feature = "testnet")]
impl IbcDepositNbtcCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .call(
                |app| build_call!(app.ibc_deposit_nbtc(self.to, self.amount.into())),
                |app| build_call!(app.app_noop()),
            )
            .await?)
    }
}

#[cfg(feature = "testnet")]
#[derive(Parser, Debug)]
pub struct IbcWithdrawNbtcCmd {
    amount: u64,
}

#[cfg(feature = "testnet")]
impl IbcWithdrawNbtcCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .call(
                |app| build_call!(app.ibc_withdraw_nbtc(self.amount.into())),
                |app| build_call!(app.app_noop()),
            )
            .await?)
    }
}

#[cfg(feature = "testnet")]
#[derive(Parser, Debug)]
pub struct GrpcCmd {
    #[clap(default_value_t = 9001)]
    port: u16,
}

#[cfg(feature = "testnet")]
impl GrpcCmd {
    async fn run(&self) -> Result<()> {
        use orga::ibc::GrpcOpts;
        orga::ibc::start_grpc(
            || app_client().sub(|app| app.ibc),
            &GrpcOpts {
                host: "127.0.0.1".to_string(),
                port: self.port,
            },
        )
        .await;

        Ok(())
    }
}

#[cfg(feature = "testnet")]
#[derive(Parser, Debug)]
pub struct IbcTransferCmd {
    receiver: String,
    amount: u64,
    channel_id: String,
    port_id: String,
    denom: String,
}

#[cfg(feature = "testnet")]
impl IbcTransferCmd {
    async fn run(&self) -> Result<()> {
        todo!()

        // let fee: u64 = nomic::app::ibc_fee(self.amount.into())?.into();
        // let amount_after_fee = self.amount - fee;
        // let transfer_args = TransferArgs {
        //     amount: amount_after_fee.into(),
        //     channel_id: self.channel_id.clone(),
        //     port_id: self.port_id.clone(),
        //     denom: self.denom.clone(),
        //     receiver: self.receiver.clone(),
        // };

        // Ok(app_client()
        //     .pay_from(async move |client| {
        //         client
        //             .ibc_deposit_nbtc(my_address(), self.amount.into())
        //             .await
        //     })
        //     .ibc
        //     .transfer(transfer_args.try_into()?)
        //     .await?)
    }
}

#[derive(Parser, Debug)]
pub struct ExportCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl ExportCmd {
    async fn run(&self) -> Result<()> {
        let home = self.config.home_expect()?;

        let store_path = home.join("merk");
        let store = Store::new(orga::store::BackingStore::Merk(orga::store::Shared::new(
            MerkStore::new(store_path),
        )));
        let root_bytes = store.get(&[])?.unwrap();

        let app =
            orga::plugins::ABCIPlugin::<nomic::app::App>::load(store, &mut root_bytes.as_slice())?;

        serde_json::to_writer_pretty(std::io::stdout(), &app).unwrap();

        Ok(())
    }
}

pub fn main() {
    if std::env::var("NOMIC_LOG_SIMPLE").is_ok() {
        pretty_env_logger::formatted_builder()
    } else {
        pretty_env_logger::formatted_timed_builder()
    }
    .filter_level(log::LevelFilter::Info)
    .parse_env("NOMIC_LOG")
    .init();

    log::debug!("nomic v{}", env!("CARGO_PKG_VERSION"));

    let backtrace_enabled = std::env::var("RUST_BACKTRACE").is_ok();

    let panic_handler = if backtrace_enabled {
        Some(std::panic::take_hook())
    } else {
        None
    };
    std::panic::set_hook(Box::new(move |info| {
        log::error!("{}", info);
        if let Some(f) = panic_handler.as_ref() {
            f(info)
        }
        std::process::exit(1);
    }));

    let opts = Opts::parse();
    if let Err(err) = opts.cmd.run(&opts.config) {
        log::error!("{}", err);
        std::process::exit(1);
    };
}
