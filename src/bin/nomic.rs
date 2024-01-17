#![feature(trivial_bounds)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(async_closure)]
#![feature(never_type)]

use bitcoincore_rpc_async::{Auth, Client as BtcClient};
use clap::Parser;
use nomic::app::Dest;
use nomic::app::IbcDest;
use nomic::app::InnerApp;
use nomic::app::Nom;
use nomic::bitcoin::Config;
use nomic::bitcoin::Nbtc;
use nomic::bitcoin::{relayer::Relayer, signer::Signer};
use nomic::constants::BTC_NATIVE_TOKEN_DENOM;
use nomic::constants::MAIN_NATIVE_TOKEN_DENOM;
use nomic::error::Result;
use nomic::utils::wallet_path;
use nomic::utils::write_orga_private_key_from_mnemonic;
use orga::abci::Node;
use orga::client::wallet::{SimpleWallet, Wallet};
use orga::coins::DelegationInfo;
use orga::coins::ValidatorQueryInfo;
use orga::coins::{Address, Commission, Decimal, Declaration, Symbol};
use orga::ibc::ibc_rs::core::{
    ics24_host::identifier::{ChannelId, PortId},
    timestamp::Timestamp,
};
use orga::macros::build_call;
use orga::merk::MerkStore;
use orga::plugins::MIN_FEE;
use orga::prelude::*;
use orga::{client::AppClient, tendermint::client::HttpClient};
use serde::{Deserialize, Serialize};
use serde_json::json;
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

fn wallet() -> SimpleWallet {
    SimpleWallet::open(wallet_path()).unwrap()
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
    UnbondingPeriod(UnbondingPeriodCmd),
    Validators(ValidatorsCmd),
    Delegate(DelegateCmd),
    Declare(DeclareCmd),
    Unbond(UnbondCmd),
    Redelegate(RedelegateCmd),
    Unjail(UnjailCmd),
    Edit(EditCmd),
    Claim(ClaimCmd),
    Relayer(RelayerCmd),
    Signer(SignerCmd),
    SetSignatoryKey(SetSignatoryKeyCmd),
    Deposit(DepositCmd),
    InterchainDeposit(InterchainDepositCmd),
    Withdraw(WithdrawCmd),
    // IbcDepositNbtc(IbcDepositNbtcCmd),
    IbcWithdrawNbtc(IbcWithdrawNbtcCmd),
    Grpc(GrpcCmd),
    IbcTransfer(IbcTransferCmd),
    Export(ExportCmd),
    UpgradeStatus(UpgradeStatusCmd),
    RelayOpKeys(RelayOpKeysCmd),
    SetRecoveryAddress(SetRecoveryAddressCmd),
    SigningStatus(SigningStatusCmd),
    BitcoinConfig(BitcoinConfigCmd),
}

impl Command {
    fn run(&self, config: &nomic::network::Config) -> Result<()> {
        use Command::*;
        let rt = tokio::runtime::Runtime::new().unwrap();

        if let Start(_cmd) = self {
            log::info!("nomic v{}", env!("CARGO_PKG_VERSION"));

            if let Some(network) = config.network() {
                log::info!("Configured for network {:?}", network);
            }
        } else {
            log::debug!("nomic v{}", env!("CARGO_PKG_VERSION"));

            if let Some(network) = config.network() {
                log::debug!("Configured for network {:?}", network);
            }

            if let Some(legacy_bin) = legacy_bin(config)? {
                let mut legacy_cmd = std::process::Command::new(legacy_bin);
                legacy_cmd.args(std::env::args().skip(1));
                log::debug!("Running legacy binary... ({:#?})", legacy_cmd);
                legacy_cmd.spawn()?.wait()?;
                return Ok(());
            }
        }

        rt.block_on(async move {
            match self {
                Start(cmd) => Ok(cmd.run().await?),
                Send(cmd) => cmd.run().await,
                SendNbtc(cmd) => cmd.run().await,
                Balance(cmd) => cmd.run().await,
                Delegate(cmd) => cmd.run().await,
                Declare(cmd) => cmd.run().await,
                Delegations(cmd) => cmd.run().await,
                UnbondingPeriod(cmd) => cmd.run().await,
                Validators(cmd) => cmd.run().await,
                Unbond(cmd) => cmd.run().await,
                Redelegate(cmd) => cmd.run().await,
                Unjail(cmd) => cmd.run().await,
                Edit(cmd) => cmd.run().await,
                Claim(cmd) => cmd.run().await,
                Relayer(cmd) => cmd.run().await,
                Signer(cmd) => cmd.run().await,
                SetSignatoryKey(cmd) => cmd.run().await,
                Deposit(cmd) => cmd.run().await,
                InterchainDeposit(cmd) => cmd.run().await,
                Withdraw(cmd) => cmd.run().await,
                // IbcDepositNbtc(cmd) => cmd.run().await,
                IbcWithdrawNbtc(cmd) => cmd.run().await,
                Grpc(cmd) => cmd.run().await,
                IbcTransfer(cmd) => cmd.run().await,
                Export(cmd) => cmd.run().await,
                UpgradeStatus(cmd) => cmd.run().await,
                RelayOpKeys(cmd) => cmd.run().await,
                SetRecoveryAddress(cmd) => cmd.run().await,
                SigningStatus(cmd) => cmd.run().await,
                BitcoinConfig(cmd) => cmd.run().await,
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
    async fn run(&self) -> orga::Result<()> {
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

            let version_hex = hex::encode([InnerApp::CONSENSUS_VERSION]);
            legacy_cmd.args(["start", "--signal-version", &version_hex]);
            legacy_cmd.args(std::env::args().skip(2).collect::<Vec<_>>());

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

            let node = Node::<nomic::app::App>::new(&home, chain_id, Default::default()).await;

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
                configure_for_statesync(&home.join("tendermint/config/config.toml"), &servers)
                    .await;
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
        let mut node = Node::<nomic::app::App>::new(&home, chain_id, Default::default()).await;

        if cmd.unsafe_reset {
            node = node.reset().await;
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
            node = node.migrate(vec![InnerApp::CONSENSUS_VERSION], false, true);
        }
        if cmd.skip_init_chain {
            node = node.skip_init_chain();
        }
        if let Some(signal_version) = cmd.signal_version {
            let signal_version = hex::decode(signal_version).unwrap();
            let rt = tokio::runtime::Runtime::new().unwrap();
            let client = self.config.client().with_wallet(wallet());
            std::thread::spawn(move || {
                rt.block_on(async move {
                    let signal_version = signal_version.clone();
                    let signal_version2 = signal_version.clone();
                    let signal_version3 = signal_version.clone();
                    let done = move || {
                        log::info!("Node has signaled {:?}", signal_version2);
                    };

                    loop {
                        let signal_version = signal_version.clone().try_into().unwrap();
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        if let Err(err) = client
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
            .await?
            .wait()
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
                    let store_ver = store.merk().get(b"/version").unwrap();
                    if let Some(store_ver) = store_ver {
                        store_ver == vec![1, InnerApp::CONSENSUS_VERSION]
                    } else {
                        false
                    }
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

                let bin_name = env!("NOMIC_LEGACY_VERSION").trim().replace(' ', "-");
                let bin_path = bin_dir.join(bin_name);
                let bin_bytes = include_bytes!(env!("NOMIC_LEGACY_PATH"));
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
    let mut initial_ver = None;
    loop {
        let version: Vec<_> = config
            .client()
            .query(|app: InnerApp| Ok(app.upgrade.current_version.get(())?.unwrap().clone()))
            .await?
            .into();

        if let Some(initial_ver) = initial_ver {
            if version != initial_ver {
                log::warn!(
                    "Version changed from {:?} to {:?}, exiting",
                    initial_ver,
                    version
                );
                std::process::exit(138);
            }
        }

        initial_ver = Some(version);

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

async fn configure_for_statesync(cfg_path: &PathBuf, rpc_servers: &[&str]) {
    log::info!("Getting bootstrap state for Tendermint light client...");

    let (height, hash) = get_bootstrap_state(rpc_servers)
        .await
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

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl SendCmd {
    async fn run(&self) -> Result<()> {
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
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

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl SendNbtcCmd {
    async fn run(&self) -> Result<()> {
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
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

    #[clap(long, global = true)]
    mnemonic_file: Option<String>,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl BalanceCmd {
    async fn run(&self) -> Result<()> {
        if let Some(file_path) = self.mnemonic_file.as_ref() {
            let mnemonic = std::fs::read_to_string(file_path)
                .expect(&format!("Can not read file {file_path}"));
            write_orga_private_key_from_mnemonic(&mnemonic);
        }

        let address = self.address.unwrap_or_else(my_address);
        println!("address: {}", address);

        let client = self.config.client();

        let balance = client
            .query(|app: InnerApp| app.accounts.balance(address))
            .await?;
        println!("{} {}", balance, MAIN_NATIVE_TOKEN_DENOM);

        let balance = client
            .query(|app: InnerApp| app.bitcoin.accounts.balance(address))
            .await?;
        println!("{} {}", balance, BTC_NATIVE_TOKEN_DENOM);

        let balance = client.query(|app| app.escrowed_nbtc(address)).await?;
        println!("{} IBC-escrowed NBTC", balance);

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DelegationsCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl DelegationsCmd {
    async fn run(&self) -> Result<()> {
        let address = my_address();
        let delegations: Vec<(Address, DelegationInfo)> = self
            .config
            .client()
            .query(|app: InnerApp| app.staking.delegations(address))
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
                "- {validator}: staked={staked} {MAIN_NATIVE_TOKEN_DENOM}, liquid={liquid_nom} {MAIN_NATIVE_TOKEN_DENOM},{liquid_nbtc} {BTC_NATIVE_TOKEN_DENOM}",
            );
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct UnbondingPeriodCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl UnbondingPeriodCmd {
    async fn run(&self) -> Result<()> {
        let unbonding_seconds = self
            .config
            .client()
            .query(|app: InnerApp| Ok(app.staking.unbonding_seconds))
            .await?;

        println!("unbonding period: {}", unbonding_seconds);
        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct ValidatorsCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl ValidatorsCmd {
    async fn run(&self) -> Result<()> {
        let mut validators: Vec<ValidatorQueryInfo> = self
            .config
            .client()
            .query(|app: InnerApp| app.staking.validators())
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

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl DelegateCmd {
    async fn run(&self) -> Result<()> {
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
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

    #[clap(flatten)]
    config: nomic::network::Config,
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

        // declare with nBTC if amount is 0
        if self.amount == 0 {
            return Ok(self
                .config
                .client()
                .with_wallet(wallet())
                .call(
                    |app| build_call!(app.declare_with_nbtc(declaration.clone())),
                    |app| build_call!(app.app_noop()),
                )
                .await?);
        }

        Ok(self
            .config
            .client()
            .with_wallet(wallet())
            .call(
                |app: &InnerApp| {
                    build_call!(app.accounts.take_as_funding((self.amount + MIN_FEE).into()))
                },
                |app: &InnerApp| build_call!(app.staking.declare_self(declaration.clone())),
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

    #[clap(flatten)]
    config: nomic::network::Config,
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

        Ok(self
            .config
            .client()
            .with_wallet(wallet())
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

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl UnbondCmd {
    async fn run(&self) -> Result<()> {
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
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

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl RedelegateCmd {
    async fn run(&self) -> Result<()> {
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
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
pub struct UnjailCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl UnjailCmd {
    async fn run(&self) -> Result<()> {
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.staking.unjail()),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct ClaimCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl ClaimCmd {
    async fn run(&self) -> Result<()> {
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
            .call(
                |app| build_call!(app.staking.claim_all()),
                |app| build_call!(app.deposit_rewards()),
            )
            .await?)
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

        let btc_client = BtcClient::new(rpc_url, auth)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;

        Ok(btc_client)
    }

    async fn run(&self) -> Result<()> {
        let create_relayer = async || {
            let btc_client = self.btc_client().await.unwrap();

            Relayer::new(btc_client, self.config.node.as_ref().unwrap().to_string())
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

        let mut relayer = create_relayer().await;
        let checkpoint_confs = relayer.start_checkpoint_conf_relay();

        let mut relayer = create_relayer().await;
        let emdis = relayer.start_emergency_disbursal_transaction_relay();

        let relaunch = relaunch_on_migrate(&self.config);

        futures::try_join!(
            headers,
            deposits,
            checkpoints,
            checkpoint_confs,
            emdis,
            relaunch
        )
        .unwrap();

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SignerCmd {
    #[clap(flatten)]
    config: nomic::network::Config,

    /// Limits the fraction of the total reserve that may be withdrawn within
    /// the trailing 24-hour period
    #[clap(long, default_value_t = 0.1)]
    max_withdrawal_rate: f64,

    /// Limits the maximum allowed signatory set change within 24 hours
    ///
    /// The Total Variation Distance between a day-old signatory set and the
    /// newly-proposed signatory set may not exceed this value
    #[clap(long, default_value_t = 0.1)]
    max_sigset_change_rate: f64,

    #[clap(long)]
    prometheus_addr: Option<std::net::SocketAddr>,

    // TODO: should be a flag
    reset_limits_at_index: Option<u32>,
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
            self.reset_limits_at_index,
            // TODO: check for custom RPC port, allow config, etc
            || nomic::app_client("http://localhost:26657").with_wallet(wallet()),
            self.prometheus_addr,
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

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl SetSignatoryKeyCmd {
    async fn run(&self) -> Result<()> {
        self.config
            .client()
            .with_wallet(wallet())
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(self.xpub.into())),
            )
            .await?;

        Ok(())
    }
}

async fn deposit(
    dest: Dest,
    client: AppClient<InnerApp, InnerApp, HttpClient, Nom, orga::client::wallet::Unsigned>,
    relayers: Vec<String>,
) -> Result<()> {
    if relayers.is_empty() {
        return Err(nomic::error::Error::Orga(orga::Error::App(format!(
            "No relayers configured, please specify at least one with --btc-relayer"
        ))));
    }

    let (sigset, threshold) = client
        .query(|app: InnerApp| {
            Ok((
                app.bitcoin.checkpoints.active_sigset()?,
                app.bitcoin.checkpoints.config.sigset_threshold,
            ))
        })
        .await?;
    let script = sigset.output_script(dest.commitment_bytes()?.as_slice(), threshold)?;
    let btc_addr = bitcoin::Address::from_script(&script, nomic::bitcoin::NETWORK).unwrap();

    let mut successes = 0;
    let required_successes = relayers.len() * 2 / 3 + 1;
    for relayer in relayers {
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/address", relayer))
            .query(&[
                ("sigset_index", sigset.index().to_string()),
                ("deposit_addr", btc_addr.to_string()),
            ])
            .body(dest.encode()?)
            .send()
            .await
            .map_err(|err| nomic::error::Error::Orga(orga::Error::App(err.to_string())))?;
        log::debug!("Relayer response status code: {}", res.status());
        if res.status() == 200 {
            successes += 1;
        }
    }

    if successes < required_successes {
        return Err(nomic::error::Error::Orga(orga::Error::App(format!(
            "Failed to broadcast deposit address to relayers"
        ))));
    }

    println!("Deposit address: {}", btc_addr);
    println!("Expiration: 5 days from now");
    // TODO: show real expiration
    Ok(())
}

#[derive(Parser, Debug)]
pub struct DepositCmd {
    address: Option<Address>,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl DepositCmd {
    async fn run(&self) -> Result<()> {
        let dest_addr = self.address.unwrap_or_else(my_address);

        deposit(
            Dest::Address(dest_addr),
            self.config.client(),
            self.config.btc_relayer.clone(),
        )
        .await
    }
}

#[derive(Parser, Debug)]
pub struct InterchainDepositCmd {
    address: String,
    channel: String,
    memo: String,

    #[clap(flatten)]
    config: nomic::network::Config,
}

const ONE_DAY_NS: u64 = 86400 * 1_000_000_000;
impl InterchainDepositCmd {
    async fn run(&self) -> Result<()> {
        use orga::encoding::Adapter;
        use std::time::SystemTime;

        let now_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            * 1_000_000_000;
        let dest = Dest::Ibc(nomic::app::IbcDest {
            source_port: "transfer".try_into().unwrap(),
            source_channel: self.channel.clone().try_into().unwrap(),
            sender: Adapter(my_address().to_string().into()),
            receiver: Adapter(self.address.clone().into()),
            timeout_timestamp: now_ns + ONE_DAY_NS,
            memo: self.memo.clone().try_into().unwrap(),
        });

        deposit(dest, self.config.client(), self.config.btc_relayer.clone()).await
    }
}

#[derive(Parser, Debug)]
pub struct WithdrawCmd {
    dest: bitcoin::Address,
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl WithdrawCmd {
    async fn run(&self) -> Result<()> {
        use nomic::bitcoin::adapter::Adapter;

        let script = self.dest.script_pubkey();

        self.config
            .client()
            .with_wallet(wallet())
            .call(
                |app| build_call!(app.withdraw_nbtc(Adapter::new(script), self.amount.into())),
                |app| build_call!(app.app_noop()),
            )
            .await?;

        Ok(())
    }
}

// #[derive(Parser, Debug)]
// pub struct IbcTransferNbtcCmd {
//     to: Address,
//     amount: u64,

//     #[clap(flatten)]
//     config: nomic::network::Config,
// }

// impl IbcTransferNbtcCmd {
//     async fn run(&self) -> Result<()> {
//         Ok(self
//             .config
//             .client()
//             .with_wallet(wallet())
//             .call(
//                 |app| build_call!(app.ibc_transfer_nbtc(self.to, self.amount.into())),
//                 |app| build_call!(app.app_noop()),
//             )
//             .await?)
//     }
// }

#[derive(Parser, Debug)]
pub struct IbcWithdrawNbtcCmd {
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl IbcWithdrawNbtcCmd {
    async fn run(&self) -> Result<()> {
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
            .call(
                |app| build_call!(app.ibc_withdraw_nbtc(self.amount.into())),
                |app| build_call!(app.app_noop()),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct GrpcCmd {
    #[clap(default_value_t = 9001)]
    port: u16,

    #[clap(short)]
    grpc_host: Option<String>,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl GrpcCmd {
    async fn run(&self) -> Result<()> {
        use orga::ibc::GrpcOpts;
        std::panic::set_hook(Box::new(|_| {}));
        orga::ibc::start_grpc(
            // TODO: support configuring RPC address
            || nomic::app_client("http://localhost:26657").sub(|app| app.ibc.ctx),
            &GrpcOpts {
                host: self.grpc_host.to_owned().unwrap_or("127.0.0.1".to_string()),
                port: self.port,
                chain_id: self.config.chain_id.clone().unwrap(),
            },
        )
        .await;

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct IbcTransferCmd {
    receiver: String,
    amount: u64,
    channel_id: ChannelId,
    port_id: PortId,
    memo: String,
    timeout_seconds: u64,
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl IbcTransferCmd {
    async fn run(&self) -> Result<()> {
        use orga::encoding::Adapter as EdAdapter;

        let my_address = my_address();
        let amount = self.amount;
        let now_ns = Timestamp::now().nanoseconds();
        let timeout_timestamp = self.timeout_seconds * 1_000_000_000 + now_ns;

        let ibc_dest = IbcDest {
            source_port: self.port_id.to_string().try_into()?,
            source_channel: self.channel_id.to_string().try_into()?,
            receiver: EdAdapter(self.receiver.clone().into()),
            sender: EdAdapter(my_address.to_string().into()),
            timeout_timestamp,
            memo: self.memo.clone().try_into()?,
        };

        Ok(self
            .config
            .client()
            .with_wallet(wallet())
            .call(
                |app| build_call!(app.ibc_transfer_nbtc(ibc_dest, amount.into())),
                |app| build_call!(app.app_noop()),
            )
            .await?)
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
            MerkStore::open_readonly(store_path),
        )));
        let root_bytes = store.get(&[])?.unwrap();

        let app =
            orga::plugins::ABCIPlugin::<nomic::app::App>::load(store, &mut root_bytes.as_slice())?;

        serde_json::to_writer_pretty(std::io::stdout(), &app).unwrap();

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct UpgradeStatusCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl UpgradeStatusCmd {
    async fn run(&self) -> Result<()> {
        use orga::coins::VersionedAddress;
        use std::collections::{HashMap, HashSet};
        let client = self.config.client();
        let tm_client =
            tendermint_rpc::HttpClient::new(self.config.node.as_ref().unwrap().as_str()).unwrap();
        let curr_height = tm_client
            .status()
            .await
            .unwrap()
            .sync_info
            .latest_block_height;
        let validators = tm_client
            .validators(curr_height, tendermint_rpc::Paging::All)
            .await
            .unwrap()
            .validators;

        let mut vp_map: HashMap<[u8; 32], u64> = HashMap::new();
        let mut total_vp = 0;
        for validator in validators {
            vp_map.insert(
                validator.pub_key.to_bytes().try_into().unwrap(),
                validator.power(),
            );
            total_vp += validator.power();
        }

        let (delay_seconds, threshold, current_version) = client
            .query(|app: InnerApp| {
                let current_version = app.upgrade.current_version.get(())?.unwrap();
                Ok((
                    app.upgrade.activation_delay_seconds,
                    app.upgrade.threshold,
                    current_version.to_vec(),
                ))
            })
            .await?;

        let next_version: orga::upgrade::Version = vec![current_version[0] + 1].try_into().unwrap();
        let mut signals: Vec<([u8; 32], i64)> = client
            .query(|app: InnerApp| {
                let mut signals = vec![];
                for entry in app.upgrade.signals.iter()? {
                    let (pubkey, signal) = entry?;
                    if signal.version == next_version {
                        signals.push((*pubkey, signal.time));
                    }
                }
                Ok(signals)
            })
            .await?;

        signals.sort_by(|a, b| a.1.cmp(&b.1));
        let mut signaled_vp = 0;
        let mut activation_time = None;
        let threshold: f64 = threshold.to_string().parse().unwrap();

        for (pubkey, time) in signals.iter() {
            signaled_vp += vp_map.get(pubkey).unwrap_or(&0);
            let frac = signaled_vp as f64 / total_vp as f64;
            if frac >= threshold && activation_time.is_none() {
                activation_time.replace(time + delay_seconds);
            }
        }
        let frac = signaled_vp as f64 / total_vp as f64;

        if frac < 0.01 {
            println!("No upgrade in progress");
            return Ok(());
        }

        let validators: Vec<ValidatorQueryInfo> = client
            .query(|app: InnerApp| app.staking.validators())
            .await?;

        let mut validator_names: HashMap<orga::coins::VersionedAddress, (String, u64)> =
            HashMap::new();
        validators
            .into_iter()
            .filter(|v| v.in_active_set)
            .for_each(|v| {
                let bytes: Vec<u8> = v.info.into();
                let name = if let Ok(info) =
                    serde_json::from_slice::<'_, serde_json::Value>(bytes.as_slice())
                {
                    info.get("moniker")
                        .and_then(|v| v.as_str())
                        .unwrap_or(v.address.to_string().as_str())
                        .to_string()
                } else {
                    v.address.to_string()
                };

                validator_names.insert(v.address, (name, v.amount_staked.into()));
            });

        let mut consensus_keys: HashMap<VersionedAddress, [u8; 32]> = HashMap::new();
        for (address, _) in validator_names.iter() {
            let consensus_key = client
                .query(|app: InnerApp| app.staking.consensus_key((*address).into()))
                .await?;
            consensus_keys.insert(*address, consensus_key);
        }
        let mut signaled_cons_keys: HashSet<[u8; 32]> = HashSet::new();

        for (cons_key, _) in signals.iter() {
            signaled_cons_keys.insert(*cons_key);
        }

        let mut entries = validator_names.iter().collect::<Vec<_>>();
        entries.sort_by(|(_, (_, a)), (_, (_, b))| b.cmp(a));

        println!("");
        println!("Upgraded:");
        for (addr, (name, power)) in entries.iter() {
            let cons_key = consensus_keys.get(addr).unwrap();
            if signaled_cons_keys.contains(cons_key) {
                println!(
                    "✅ {} ({:.2}%)",
                    name,
                    (*power as f64 / total_vp as f64) * 100.0
                );
            }
        }
        println!("");
        println!("Not upgraded:");
        for (addr, (name, power)) in entries.iter() {
            let cons_key = consensus_keys.get(addr).unwrap();
            if !signaled_cons_keys.contains(cons_key) {
                println!(
                    "❌ {} ({:.2}%)",
                    name,
                    (*power as f64 / total_vp as f64) * 100.0
                );
            }
        }
        println!("");

        println!(
            "Upgrade has been signaled by {:.2}% of voting power",
            frac * 100.0
        );

        if let Some(t) = activation_time {
            use chrono::prelude::*;
            let mut activation_date = chrono::Utc.timestamp_opt(t, 0).unwrap();
            if activation_date.hour() > 17
                || activation_date.hour() == 17 && activation_date.minute() >= 10
            {
                activation_date = activation_date
                    .checked_add_days(chrono::Days::new(1))
                    .unwrap();
            }
            activation_date = activation_date
                .with_hour(17)
                .unwrap()
                .with_minute(0)
                .unwrap()
                .with_second(0)
                .unwrap();

            while !nomic::app::in_upgrade_window(activation_date.timestamp()) {
                activation_date = activation_date
                    .checked_add_days(chrono::Days::new(1))
                    .unwrap();
            }
            println!("Upgrade will activate at {}", activation_date);
        } else {
            println!("Upgrade requires {:.2}% of voting power", threshold * 100.0);
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct RelayOpKeysCmd {
    client_id: String,
    rpc_url: String,
}

impl RelayOpKeysCmd {
    async fn run(&self) -> Result<()> {
        use nomic::cosmos::relay_op_keys;
        log::info!("Relaying operator keys for client {}", self.client_id);
        let bytes = format!("{}/", self.client_id).as_bytes().to_vec();
        let client_id = Decode::decode(&mut bytes.as_slice())?;
        relay_op_keys(
            || nomic::app_client("http://localhost:26657").with_wallet(wallet()),
            client_id,
            self.rpc_url.as_str(),
        )
        .await?;

        log::info!("Finished relaying operator keys");

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SetRecoveryAddressCmd {
    address: bitcoin::Address,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl SetRecoveryAddressCmd {
    async fn run(&self) -> Result<()> {
        let script = self.address.script_pubkey();
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| {
                    build_call!(app
                        .bitcoin
                        .set_recovery_script(nomic::bitcoin::adapter::Adapter::new(script.clone())))
                },
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct SigningStatusCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl SigningStatusCmd {
    async fn run(&self) -> Result<()> {
        use bitcoin::util::bip32::ChildNumber;
        let home = self.config.home_expect()?;

        let store_path = home.join("merk");
        let store = Store::new(orga::store::BackingStore::Merk(orga::store::Shared::new(
            MerkStore::open_readonly(store_path),
        )));
        let root_bytes = store.get(&[])?.unwrap();

        let app =
            orga::plugins::ABCIPlugin::<nomic::app::App>::load(store, &mut root_bytes.as_slice())?;

        let app = app
            .inner
            .inner
            .into_inner()
            .inner
            .inner
            .inner
            .inner
            .inner
            .inner;
        let Some(signing) = app.bitcoin.checkpoints.signing()? else {
            println!("No signing checkpoint");
            return Ok(());
        };
        let batch = signing.current_batch()?.unwrap();
        let mut lowest_index = 0;
        let mut lowest_frac = 2.0;
        let tx = batch.front()?.unwrap();
        for (index, inp) in (tx.input.iter()?).enumerate() {
            let inp = inp?;
            let sigs = &inp.signatures;
            let threshold = sigs.threshold;
            let signed = sigs.signed;
            let frac = signed as f64 / threshold as f64;
            if frac < lowest_frac {
                lowest_frac = frac;
                lowest_index = index as u64;
            }
        }
        let res_out = tx.input.get(lowest_index)?.unwrap();
        let sigs = &res_out.signatures;
        let sig_keys = &app.bitcoin.signatory_keys;
        let sigset_index = res_out.sigset_index;

        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let mut missing_cons_keys = vec![];
        for entry in sig_keys.map().iter()? {
            use nomic::bitcoin::threshold_sig::Pubkey;
            let (k, xpub) = entry?;

            let derive_path = [ChildNumber::from_normal_idx(sigset_index)?];
            let pubkey: Pubkey = xpub.derive_pub(&secp, &derive_path)?.public_key.into();
            let needs_to_sign = sigs.needs_sig(pubkey)?;
            if needs_to_sign {
                missing_cons_keys.push((k, *xpub));
            }
        }
        let all_vals = app.staking.validators()?;
        for val in all_vals {
            if val.amount_staked == 0 {
                continue;
            }
            let cons_key = app.staking.consensus_key(val.address.into())?;
            if missing_cons_keys.iter().any(|v| *v.0 == cons_key) {
                let json: serde_json::Value =
                    serde_json::from_str(String::from_utf8(val.info.to_vec()).unwrap().as_str())
                        .unwrap();
                let name = json.get("moniker").unwrap().to_string();
                println!("Missing signature from {}", name);
            }
        }

        println!(
            "Checkpoint is at {:.2}% of the minimum required voting power",
            lowest_frac * 100.0
        );

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct BitcoinConfigCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl BitcoinConfigCmd {
    async fn run(&self) -> Result<()> {
        let client = self.config.client();
        let config: Config = client.query(|app: InnerApp| Ok(app.bitcoin.config)).await?;
        let value = json!(config);
        println!("{}", value);

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
