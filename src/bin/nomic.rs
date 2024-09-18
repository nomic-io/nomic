//! This binary provides the command-line interface for running a Nomic full
//! node, as well as client commands for querying and broadcasting transactions.

#![feature(trivial_bounds)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(async_closure)]
#![feature(never_type)]

#[cfg(feature = "ethereum")]
use alloy::network::EthereumWallet;
#[cfg(feature = "ethereum")]
use alloy::signers::local::LocalSigner;

use bitcoin::consensus::{Decodable, Encodable};
#[cfg(feature = "ethereum")]
use bitcoin::secp256k1::Message;
use bitcoin::secp256k1::{self};

use bitcoin::util::bip32::ExtendedPubKey;
use bitcoincore_rpc_async::RpcApi;
use bitcoincore_rpc_async::{Auth, Client as BtcClient};
use clap::Parser;
use nomic::app::Dest;
use nomic::app::IbcDest;
use nomic::app::InnerApp;
use nomic::app::Nom;
use nomic::bitcoin::adapter::Adapter;
use nomic::bitcoin::matches_bitcoin_network;
use nomic::bitcoin::signatory::SignatorySet;
use nomic::bitcoin::Nbtc;
use nomic::bitcoin::{relayer::Relayer, signer::Signer};
use nomic::error::Result;
use nomic::utils::{load_bitcoin_key, load_or_generate};
use orga::abci::Node;
use orga::client::wallet::{SimpleWallet, Wallet};
use orga::coins::{Address, Commission, Decimal, Declaration, Symbol};
use orga::ibc::ibc_rs::core::{
    host::types::identifiers::{ChannelId, PortId},
    primitives::Timestamp,
};
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
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tendermint_rpc::Client as _;

const BANNER: &str = r#"
███╗   ██╗  ██████╗  ███╗   ███╗ ██╗  ██████╗
████╗  ██║ ██╔═══██╗ ████╗ ████║ ██║ ██╔════╝
██╔██╗ ██║ ██║   ██║ ██╔████╔██║ ██║ ██║
██║╚██╗██║ ██║   ██║ ██║╚██╔╝██║ ██║ ██║
██║ ╚████║ ╚██████╔╝ ██║ ╚═╝ ██║ ██║ ╚██████╗
╚═╝  ╚═══╝  ╚═════╝  ╚═╝     ╚═╝ ╚═╝  ╚═════╝
"#;

/// Builds a wallet to be used with the client based on storing a private key in
/// the `~/.orga-wallet` directory.
fn wallet() -> SimpleWallet {
    let path = home::home_dir().unwrap().join(".orga-wallet");
    SimpleWallet::open(path).unwrap()
}

/// Returns the address associated with the default client wallet defined in
/// [wallet].
fn my_address() -> Address {
    wallet().address().unwrap().unwrap()
}

/// Command line options for the `nomic` binary.
#[derive(Parser, Debug)]
#[clap(
    version = env!("CARGO_PKG_VERSION"),
    author = "The Nomic Developers <hello@nomic.io>"
)]
pub struct Opts {
    /// Top-level subcommands.
    #[clap(subcommand)]
    cmd: Command,

    /// Command-line options common to all subcommands.
    #[clap(flatten)]
    config: nomic::network::Config,
}

/// Top-level subcommands for the `nomic` binary.
#[derive(Parser, Debug)]
pub enum Command {
    /// Start a Nomic full node.
    Start(StartCmd),
    /// Transfers NOM to the specified destination.
    Send(SendCmd),
    /// Transfers nBTC to the specified destination.
    SendNbtc(SendNbtcCmd),
    /// Shows the wallet balance.
    Balance(BalanceCmd),
    /// Shows a list of the wallet's stake delegations.
    Delegations(DelegationsCmd),
    /// Shows a list of all network validators.
    Validators(ValidatorsCmd),
    /// Delegates stake to the given validator.
    Delegate(DelegateCmd),
    /// Declares a new validator.
    Declare(DeclareCmd),
    /// Unbonds a stake delegation.
    Unbond(UnbondCmd),
    /// Redelegates a stake delegation to a new validator without unbonding.
    Redelegate(RedelegateCmd),
    /// Unjails the jailed validator associated with the wallet's operator
    /// address.
    Unjail(UnjailCmd),
    /// Edits the description of the validator associated with the wallet's
    /// operator address.
    Edit(EditCmd),
    /// Claims the rewards earned by the wallet.
    Claim(ClaimCmd),
    /// Shows the wallet's available airdrop balances which can be claimed.
    Airdrop(AirdropCmd),
    /// Claims the airdrop balances associated with the wallet.
    ClaimAirdrop(ClaimAirdropCmd),
    /// Relays data between the Bitcoin and Nomic networks.
    Relayer(RelayerCmd),
    /// Signs Bitcoin transactions if the validator associated with the wallet's
    /// operator address is in a network signatory set.
    Signer(SignerCmd),
    /// Sets the key to use for signing Bitcoin transactions if the validator
    /// associated with the wallet's operator address is in a network signatory
    /// set.
    SetSignatoryKey(SetSignatoryKeyCmd),
    /// Shows a Bitcoin address for depositing Bitcoin to the Nomic network.
    Deposit(DepositCmd),
    /// Shows a Bitcoin address for depositing Bitcoin to a remote chain.
    InterchainDeposit(InterchainDepositCmd),
    /// Withdraws Bitcoin from the Nomic network to a Bitcoin address.
    Withdraw(WithdrawCmd),
    // IbcDepositNbtc(IbcDepositNbtcCmd),
    /// Withdraws nBTC from the wallet's IBC escrow account into its main nBTC
    /// account.
    IbcWithdrawNbtc(IbcWithdrawNbtcCmd),
    /// Runs a gRPC server for querying data from a Nomic full node.
    Grpc(GrpcCmd),
    /// Transfers tokens to a remote IBC chain.
    IbcTransfer(IbcTransferCmd),
    /// Dumps the application state as JSON.
    Export(ExportCmd),
    /// Shows the status of a pending network upgrade, if any.
    UpgradeStatus(UpgradeStatusCmd),
    /// Runs a process which scans a remote IBC chain for new validators and
    /// broadcasts them to the Nomic network.
    RelayOpKeys(RelayOpKeysCmd),
    /// Sets the Bitcoin recovery address for the wallet, used to recover funds
    /// in the event of an Emergency Disbursal.
    SetRecoveryAddress(SetRecoveryAddressCmd),
    /// Shows the network's Bitcoin checkpoint signing status.
    SigningStatus(SigningStatusCmd),
    /// Attempts to recover a deposit which has not yet been processed by the
    /// Nomic network by relaying a proof of its confirmation on the Bitcoin
    /// network.
    RecoverDeposit(RecoverDepositCmd),
    /// Pays nBTC into the network fee pool.
    PayToFeePool(PayToFeePoolCmd),
    #[cfg(feature = "ethereum")]
    RelayEthereum(RelayEthereumCmd),
    #[cfg(feature = "ethereum")]
    EthTransferNbtc(EthTransferNbtcCmd),
}

impl Command {
    /// Runs the command with the given configuration.
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
                RecoverDeposit(cmd) => cmd.run().await,
                PayToFeePool(cmd) => cmd.run().await,
                #[cfg(feature = "ethereum")]
                RelayEthereum(cmd) => cmd.run().await,
                #[cfg(feature = "ethereum")]
                EthTransferNbtc(cmd) => cmd.run().await,
            }
        })
    }
}

/// Start a Nomic full node.
#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
pub struct StartCmd {
    #[clap(flatten)]
    config: nomic::network::Config,

    /// Display all logs output by the Tendermint node.
    #[clap(long)]
    pub tendermint_logs: bool,
    /// Initializes a store by cloning one at the given path. The path may be
    /// either a network home, e.g. `~/.nomic-stakenet-3`, or a store path, e.g.
    /// `~/.nomic-stakenet-3/merk`.
    #[clap(long)]
    pub clone_store: Option<String>,
    /// Resets the store height to 0 when initializing the node. This is useful
    /// when cloning state from another network to initialize a new network
    /// which is starting from genesis.
    #[clap(long)]
    pub reset_store_height: bool,
    /// Removes all block and state data before initializing the node. Use
    /// caution as this action cannot be undone.
    #[clap(long)]
    pub unsafe_reset: bool,
    /// Skips the ABCI `init_chain` step when starting the node.
    #[clap(long)]
    pub skip_init_chain: bool,
    /// Attempts to migrate the store from a legacy encoding version to the
    /// latest encoding version.
    #[clap(long)]
    pub migrate: bool,
    /// The path to the legacy binary to run until the on-chain network upgrade
    /// mechanism triggers a transition to the new binary.
    #[clap(long)]
    pub legacy_home: Option<String>,
    /// Disables changes to the validator set. This is useful for ignoring the
    /// distribution of stake when running a local testing network.
    #[clap(long)]
    pub freeze_valset: bool,
    /// Publicly signals onchain that the node is ready to upgrade to the
    /// version specified by the given string.
    #[clap(long)]
    pub signal_version: Option<String>,
    /// Copies the validator private key at the specified path to the node's
    /// home directory when initializing.
    #[clap(long)]
    pub validator_key: Option<String>,
    /// Copies the P2P privaete key at the specified path to the node's home
    /// directory when initializing.
    #[clap(long)]
    pub node_key: Option<String>,
}

impl StartCmd {
    /// Run the `start` command.
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
/// Returns the path to the legacy binary if it exists.
///
/// If the `NOMIC_LEGACY_VERSION` environment variable is set, it will be used.
/// Otherwise, this will search for a binary with the configured legacy version
/// in the network home's `bin` subdirectory.
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

        // TODO: handle case where node is not initialized, but network is upgraded (can
        // skip legacy binary)

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
                if !env!("NOMIC_LEGACY_BUILD_VERSION").is_empty() {
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

/// Watches for the on-chain upgrade mechanism to signal a transition to a new
/// version, then exits the process.
async fn relaunch_on_migrate(config: &nomic::network::Config) -> Result<()> {
    let mut initial_ver = None;
    loop {
        let version: Vec<_> = config
            .client()
            .query(|app| Ok(app.upgrade.current_version.get(())?.unwrap().clone()))
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

/// Writes changes to the network's Tendermint `config.toml` file.
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

/// Edits the `timeout_commit` value in the network's Tendermint `config.toml`
/// file.
fn edit_block_time(cfg_path: &PathBuf, timeout_commit: &str) {
    configure_node(cfg_path, |cfg| {
        cfg["consensus"]["timeout_commit"] = toml_edit::value(timeout_commit);
    });
}

/// Edits the `statesync` values in the network's Tendermint `config.toml` file.
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

/// Gets the latest block height and hash from a set of Tendermint RPC servers
/// in order to initialize for state sync.
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

/// Transfers a given amount of native tokens to a given address.
#[derive(Parser, Debug)]
pub struct SendCmd {
    /// The address to send the tokens to.
    to_addr: Address,

    /// The amount of tokens to send (as an integer denominated in the
    /// smallest units).
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl SendCmd {
    /// Runs the `send` command.
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

/// Transfers a given amount of nBTC to a given address.
#[derive(Parser, Debug)]
pub struct SendNbtcCmd {
    /// The address to send the tokens to.
    to_addr: Address,

    /// The amount of tokens to send (as an integer denominated in the smallest
    /// units).
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl SendNbtcCmd {
    /// Runs the `send-nbtc` command.
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

/// Shows the balance of the given address, or the current wallet address if
/// none is provided.
#[derive(Parser, Debug)]
pub struct BalanceCmd {
    /// The address to show the balance of. If not provided, the balance of the
    /// current wallet address is shown.
    address: Option<Address>,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl BalanceCmd {
    /// Runs the `balance` command.
    async fn run(&self) -> Result<()> {
        let address = self.address.unwrap_or_else(my_address);
        println!("address: {}", address);

        let client = self.config.client();

        let balance = client.query(|app| app.accounts.balance(address)).await?;
        println!("{} NOM", balance);

        let balance = client
            .query(|app| app.bitcoin.accounts.balance(address))
            .await?;
        println!("{} NBTC", balance);

        let balance = client.query(|app| app.escrowed_nbtc(address)).await?;
        println!("{} IBC-escrowed NBTC", balance);

        Ok(())
    }
}

/// Shows the stake delegations of the current wallet address.
#[derive(Parser, Debug)]
pub struct DelegationsCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl DelegationsCmd {
    /// Runs the `delegations` command.
    async fn run(&self) -> Result<()> {
        let address = my_address();
        let delegations = self
            .config
            .client()
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

/// Shows a list of the validators of the network.
#[derive(Parser, Debug)]
pub struct ValidatorsCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl ValidatorsCmd {
    /// Runs the `validators` command.
    async fn run(&self) -> Result<()> {
        let mut validators = self
            .config
            .client()
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

/// Delegates stake to the given validator.
#[derive(Parser, Debug)]
pub struct DelegateCmd {
    /// The address of the validator to delegate to.
    validator_addr: Address,

    /// The amount of tokens to delegate (as an integer denominated in the
    /// smallest units).
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl DelegateCmd {
    /// Runs the `delegate` command.
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

/// Declares a new validator.
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

/// Infomation to be posted on-chain when declaring a new validator.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeclareInfo {
    /// The validator's name.
    pub moniker: String,
    /// The URL of the validator's website.
    pub website: String,
    /// The validator's Keybase fingerprint, to be used for verification and
    /// fetching an avatar.
    pub identity: String,
    /// Description text about the validator.
    pub details: String,
}

impl DeclareCmd {
    /// Runs the `declare` command.
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
                |app| build_call!(app.accounts.take_as_funding((self.amount + MIN_FEE).into())),
                |app| build_call!(app.staking.declare_self(declaration.clone())),
            )
            .await?)
    }
}

/// Edits the on-chain information of a validator.
#[derive(Parser, Debug)]
pub struct EditCmd {
    /// The commission rate the validator takes from rewards earned by
    /// delegators.
    commission_rate: Decimal,
    /// The minimum self-delegation required for the validator to remain active,
    /// useful to guarantee to delegators that the validator has stake at risk.
    min_self_delegation: u64,
    /// The validator's name.
    moniker: String,
    /// The URL of the validator's website.
    website: String,
    /// The validator's Keybase fingerprint, to be used for verification and
    /// fetching an avatar.
    identity: String,
    /// Description text about the validator.
    details: String,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl EditCmd {
    /// Runs the `edit` command.
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

/// Unbonds a validator's stake.
#[derive(Parser, Debug)]
pub struct UnbondCmd {
    /// The address of the validator which the wallet is currently delegated to
    /// which will be unbonded from.
    validator_addr: Address,
    /// The amount of stake to unbond (as an integer denominated in the smallest
    /// unit).
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl UnbondCmd {
    /// Runs the `unbond` command.
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

/// Redelegates a validator's stake to another validator without unbonding.
#[derive(Parser, Debug)]
pub struct RedelegateCmd {
    /// The address of the validator which the wallet is currently delegated to
    /// which will be re-delegated from.
    src_validator_addr: Address,
    /// The address of the validator which the wallet will re-delegate to.
    dest_validator_addr: Address,
    /// The amount of stake to redelegate (as an integer denominated in the
    /// smallest unit).
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl RedelegateCmd {
    /// Runs the `redelegate` command.
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

/// Unjails the jailed validator associated with the wallet's operator address.
#[derive(Parser, Debug)]
pub struct UnjailCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl UnjailCmd {
    /// Runs the `unjail` command.
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

/// Claims the rewards earned by the wallet.
#[derive(Parser, Debug)]
pub struct ClaimCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl ClaimCmd {
    /// Runs the `claim` command.
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

/// Shows the wallet's available airdrop balances which can be claimed.
#[derive(Parser, Debug)]
pub struct AirdropCmd {
    /// The address to check for airdrop eligibility. If not provided, the
    /// current wallet address is used.
    address: Option<Address>,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl AirdropCmd {
    /// Runs the `airdrop` command.
    async fn run(&self) -> Result<()> {
        let client = self.config.client();

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

/// Claims the airdrop balances associated with the wallet.
#[derive(Parser, Debug)]
pub struct ClaimAirdropCmd {
    // TODO: why is this an option?
    address: Option<Address>,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl ClaimAirdropCmd {
    /// Runs the `claim-airdrop` command.
    async fn run(&self) -> Result<()> {
        let client = self.config.client();

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
            self.config
                .client()
                .with_wallet(wallet())
                .call(
                    |app| build_call!(app.airdrop.claim_airdrop1()),
                    |app| build_call!(app.accounts.give_from_funding_all()),
                )
                .await?;
            println!("Claimed airdrop 1 ({} uNOM)", acct.airdrop1.claimable);
            claimed = true;
        }

        if acct.airdrop2.claimable > 0 {
            self.config
                .client()
                .with_wallet(wallet())
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

/// Relays data between the Bitcoin and Nomic networks.
#[derive(Parser, Debug)]
pub struct RelayerCmd {
    /// The port of the Bitcoin RPC server.
    // TODO: get the default based on the network
    #[clap(short = 'p', long, default_value_t = 8332)]
    rpc_port: u16,

    /// The username for the Bitcoin RPC server.
    #[clap(short = 'u', long)]
    rpc_user: Option<String>,

    /// The password for the Bitcoin RPC server.
    #[clap(short = 'P', long)]
    rpc_pass: Option<String>,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl RelayerCmd {
    /// Builds Bitcoin RPC client.
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

    /// Runs the `relayer` command.
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
        let deposits = relayer.start_deposit_relay(relayer_dir_path.clone(), 60 * 60 * 12);

        let mut relayer = create_relayer().await;
        let recovery_txs = relayer.start_recovery_tx_relay(relayer_dir_path);

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
            recovery_txs,
            checkpoints,
            checkpoint_confs,
            emdis,
            relaunch
        )
        .unwrap();

        Ok(())
    }
}

/// Signs Bitcoin transactions if the validator associated with the wallet's
/// operator address is in a network signatory set.
#[derive(Parser, Debug)]
pub struct SignerCmd {
    #[clap(flatten)]
    config: nomic::network::Config,

    /// Clears the rate limiting mechanism at the given checkpoint index. This
    /// can be used to manually override rate limiting at a certain point in
    /// time which has been verified to be legitimate.
    #[clap(long)]
    reset_limits_at_index: Option<u32>,

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

    /// The minimum number of Bitcoin blocks that must be mined before the
    /// signer will contribute its signature to the current signing
    /// checkpoint. This setting can be used to change the rate at which the
    /// network produces checkpoints (higher values cause less frequent
    /// checkpoints).
    ///
    /// Signatures will always be contributed to previously completed
    /// checkpoints.
    #[clap(long, default_value_t = 6)]
    min_blocks_per_checkpoint: u64,

    /// The address of the Prometheus server to which metrics will be sent.
    #[clap(long)]
    prometheus_addr: Option<std::net::SocketAddr>,

    /// The paths to the extended private keys used to sign Bitcoin
    /// transactions.
    ///
    /// Multiple may be specified, e.g. if the node has set a new key via the
    /// `set-signatory-key` command and the old key is still present in recent
    /// signatory sets.
    #[clap(long)]
    xpriv_paths: Vec<PathBuf>,
}

impl SignerCmd {
    /// Runs the `signer` command.
    async fn run(&self) -> Result<()> {
        let signer_dir_path = self.config.home_expect()?.join("signer");
        if !signer_dir_path.exists() {
            std::fs::create_dir(&signer_dir_path)?;
        }

        let default_key_path = signer_dir_path.join("xpriv");

        let signer = Signer::load_xprivs(
            my_address(),
            default_key_path,
            self.xpriv_paths.clone(),
            self.max_withdrawal_rate,
            self.max_sigset_change_rate,
            self.min_blocks_per_checkpoint,
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

/// Sets the key to use for signing Bitcoin transactions if the validator
/// associated with the wallet's operator address is in a network signatory set.
#[derive(Parser, Debug)]
pub struct SetSignatoryKeyCmd {
    /// The paths to the extended private keys used to sign Bitcoin
    /// transactions.
    // TODO: why can we specify multiple here?
    xpriv_path: Option<PathBuf>,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl SetSignatoryKeyCmd {
    /// Runs the `set-signatory-key` command.
    async fn run(&self) -> Result<()> {
        let xpriv = match self.xpriv_path.clone() {
            Some(xpriv_path) => load_bitcoin_key(xpriv_path)?,
            None => load_or_generate(
                self.config.home_expect().unwrap().join("signer/xpriv"),
                nomic::bitcoin::NETWORK,
            )?,
        };

        let xpub = ExtendedPubKey::from_priv(&secp256k1::Secp256k1::new(), &xpriv);

        self.config
            .client()
            .with_wallet(wallet())
            .call(
                |app| build_call!(app.accounts.take_as_funding(MIN_FEE.into())),
                |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
            )
            .await?;

        Ok(())
    }
}

/// Shows a Bitcoin address for depositing Bitcoin to the wallet's nBTC account
/// on the Nomic network.
async fn deposit(
    dest: Dest,
    client: AppClient<InnerApp, InnerApp, HttpClient, Nom, orga::client::wallet::Unsigned>,
    relayers: Vec<String>,
) -> Result<()> {
    if relayers.is_empty() {
        return Err(nomic::error::Error::Orga(orga::Error::App(
            "No relayers configured, please specify at least one with --btc-relayer".to_string(),
        )));
    }

    let (sigset, threshold) = client
        .query(|app| {
            Ok((
                app.bitcoin.checkpoints.active_sigset()?,
                app.bitcoin.checkpoints.config.sigset_threshold,
            ))
        })
        .await?;
    let commitment_bytes = dest.commitment_bytes()?;
    let script = sigset.output_script(&commitment_bytes, threshold)?;
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
        return Err(nomic::error::Error::Orga(orga::Error::App(
            "Failed to broadcast deposit address to relayers".to_string(),
        )));
    }

    println!("Deposit address: {}", btc_addr);
    println!("Expiration: 5 days from now");
    // TODO: show real expiration
    Ok(())
}

/// Shows a Bitcoin address for depositing Bitcoin to the wallet's nBTC account
/// on the Nomic network.
#[derive(Parser, Debug)]
pub struct DepositCmd {
    /// The destination to deposit to. If not provided, the current wallet
    /// address will be used.
    dest: Option<Dest>,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl DepositCmd {
    /// Runs the `deposit` command.
    async fn run(&self) -> Result<()> {
        let dest = self.dest.clone().unwrap_or_else(|| Dest::NativeAccount {
            address: my_address(),
        });

        deposit(dest, self.config.client(), self.config.btc_relayer.clone()).await
    }
}

/// Shows a Bitcoin address for depositing Bitcoin to a remote chain.
#[derive(Parser, Debug)]
pub struct InterchainDepositCmd {
    /// The destination address to deposit to (e.g. a Cosmos bech32 wallet
    /// address).
    address: String,
    /// The IBC channel to transfer the deposit through. Should be a string like
    /// "channel-123".
    channel: String,
    /// A memo to include with the deposit. This may be an empty string.
    memo: String,

    #[clap(flatten)]
    config: nomic::network::Config,
}

const ONE_DAY_NS: u64 = 86400 * 1_000_000_000;
impl InterchainDepositCmd {
    /// Runs the `interchain-deposit` command.
    async fn run(&self) -> Result<()> {
        let now_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            * 1_000_000_000;
        let dest = Dest::Ibc {
            data: nomic::app::IbcDest {
                source_port: "transfer".try_into()?,
                source_channel: self.channel.clone().try_into()?,
                sender: my_address().to_string().try_into()?,
                receiver: self.address.to_string().try_into()?,
                timeout_timestamp: now_ns + ONE_DAY_NS,
                memo: self.memo.to_string().try_into()?,
            },
        };

        deposit(dest, self.config.client(), self.config.btc_relayer.clone()).await
    }
}

/// Withdraws Bitcoin from the Nomic network to a Bitcoin address.
#[derive(Parser, Debug)]
pub struct WithdrawCmd {
    /// The destination Bitcoin address to withdraw to.
    dest: bitcoin::Address,
    /// The amount of Bitcoin to withdraw, in micro-satoshis.
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl WithdrawCmd {
    /// Runs the `withdraw` command.
    async fn run(&self) -> Result<()> {
        let script = self.dest.script_pubkey();
        if !matches_bitcoin_network(&self.dest.network) {
            return Err(nomic::error::Error::Address(format!(
                "Invalid network for destination address. Got {}, Expected {}",
                self.dest.network,
                nomic::bitcoin::NETWORK
            )));
        }

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

/// Withdraws nBTC from the wallet's IBC escrow account into its main account.
#[derive(Parser, Debug)]
pub struct IbcWithdrawNbtcCmd {
    /// The amount of nBTC to withdraw, in micro-satoshis.
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl IbcWithdrawNbtcCmd {
    /// Runs the `ibc-withdraw-nbtc` command.
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

/// Rusns a gRPC server for querying data from a Nomic full node.
#[cfg(feature = "ethereum")]
#[derive(Parser, Debug)]
pub struct EthTransferNbtcCmd {
    to: alloy::primitives::Address,
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

#[cfg(feature = "ethereum")]
impl EthTransferNbtcCmd {
    async fn run(&self) -> Result<()> {
        let to = self.to.0 .0.into();
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
            .call(
                |app| build_call!(app.eth_transfer_nbtc(to, self.amount.into())),
                |app| build_call!(app.app_noop()),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct GrpcCmd {
    /// The port to listen on.
    #[clap(default_value_t = 9001)]
    port: u16,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl GrpcCmd {
    /// Runs the `grpc` command.
    async fn run(&self) -> Result<()> {
        use orga::ibc::GrpcOpts;
        std::panic::set_hook(Box::new(|_| {}));
        orga::ibc::start_grpc(
            // TODO: support configuring RPC address
            || nomic::app_client("http://localhost:26657").sub(|app| app.ibc.ctx),
            &GrpcOpts {
                host: "127.0.0.1".to_string(),
                port: self.port,
                chain_id: self.config.chain_id.clone().unwrap(),
            },
        )
        .await;

        Ok(())
    }
}

/// Transfers nBTC to a remote chain using IBC.
#[derive(Parser, Debug)]
pub struct IbcTransferCmd {
    /// The address of the receiver on the remote chain (e.g. a Cosmos bech32
    /// wallet address).
    receiver: String,
    /// The amount of nBTC to transfer, in micro-satoshis.
    amount: u64,
    /// The IBC channel to transfer through. Should be a string like
    /// "channel-123".
    channel_id: ChannelId,
    /// The IBC port to transfer through. This is usually a string like
    /// "transfer".
    port_id: PortId,
    /// A memo to attach to the transfer. This can be an empty string.
    memo: String,
    /// The number of seconds in which the transfer must be completed before
    /// becoming invalid.
    timeout_seconds: u64,
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl IbcTransferCmd {
    /// Runs the `ibc-transfer` command.
    async fn run(&self) -> Result<()> {
        let my_address = my_address();
        let amount = self.amount;
        let now_ns = Timestamp::now().nanoseconds();
        let timeout_timestamp = self.timeout_seconds * 1_000_000_000 + now_ns;

        let ibc_dest = IbcDest {
            source_port: self.port_id.to_string().try_into()?,
            source_channel: self.channel_id.to_string().try_into()?,
            receiver: self.receiver.to_string().try_into()?,
            sender: my_address.to_string().try_into()?,
            timeout_timestamp,
            memo: self.memo.to_string().try_into()?,
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

/// Outputs the current network application state as JSON.
#[derive(Parser, Debug)]
pub struct ExportCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl ExportCmd {
    /// Runs the `export` command.
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

/// Shows the status of a pending network upgrade, if any.
#[derive(Parser, Debug)]
pub struct UpgradeStatusCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl UpgradeStatusCmd {
    /// Runs the `upgrade-status` command.
    async fn run(&self) -> Result<()> {
        use orga::coins::staking::ValidatorQueryInfo;
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

        let all_validators: Vec<ValidatorQueryInfo> = client
            .query(|app: InnerApp| app.staking.all_validators())
            .await?;

        let mut validator_names: HashMap<orga::coins::VersionedAddress, (String, u64)> =
            HashMap::new();
        all_validators
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

        println!();
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
        println!();
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
        println!();

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

/// Runs a process which scans a remote IBC chain for new validators and
/// broadcasts them to the Nomic network. This is used to populate the remote
/// chain's Emergency Disbursal multisig wallet.
#[derive(Parser, Debug)]
pub struct RelayOpKeysCmd {
    /// The ID of the IBC client which is connected to the remote chain.
    client_id: String,
    /// The URL of the remote chain's Tendermint RPC server.
    rpc_url: String,
}

impl RelayOpKeysCmd {
    /// Runs the `relay-op-keys` command.
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

/// Sets the Bitcoin recovery address for the wallet, used to recover funds in
/// the event of an Emergency Disbursal.
///
/// If an Emergency Disbursal happens, the nBTC held in the wallet's account
/// will be automatically paid to this recovery address.
#[derive(Parser, Debug)]
pub struct SetRecoveryAddressCmd {
    /// The Bitcoin address to set as the recovery address.
    address: bitcoin::Address,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl SetRecoveryAddressCmd {
    /// Runs the `set-recovery-address` command.
    async fn run(&self) -> Result<()> {
        let script = self.address.script_pubkey();
        if !matches_bitcoin_network(&self.address.network) {
            return Err(nomic::error::Error::Address(format!(
                "Invalid network for recovery address. Got {}, Expected {}",
                self.address.network,
                nomic::bitcoin::NETWORK
            )));
        }

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

/// Shows the network's Bitcoin checkpoint signing status.
#[derive(Parser, Debug)]
pub struct SigningStatusCmd {
    #[clap(flatten)]
    config: nomic::network::Config,
}

impl SigningStatusCmd {
    /// Runs the `signing-status` command.
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
        let all_vals = app.staking.all_validators()?;
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

/// Attempts to recover a deposit which has not yet been processed by the
/// Nomic network by relaying a proof of its confirmation on the Bitcoin
/// network.
///
/// This command is useful when a deposit has been made to the network and
/// confirmed on Bitcoin, but has not yet been relayed.
#[derive(Parser, Debug)]
pub struct RecoverDepositCmd {
    /// The port of the Bitcoin RPC server.
    // TODO: get default based on network
    #[clap(short = 'p', long, default_value_t = 8332)]
    rpc_port: u16,
    /// The username for the Bitcoin RPC server.
    #[clap(short = 'u', long)]
    rpc_user: Option<String>,
    /// The password for the Bitcoin RPC server.
    #[clap(short = 'P', long)]
    rpc_pass: Option<String>,

    /// The IBC channel ID (e.g. "channel-123") which the deposit was sent to,
    /// if it is an interchain deposit.
    #[clap(long)]
    channel: Option<String>,
    /// The remote address the deposit was made to, if it is an interchain
    /// deposit.
    ///
    /// For convenience, the `--remote-prefix` flag can be used instead
    /// to derive the remote address from the current wallet's address.
    #[clap(long)]
    remote_addr: Option<String>,
    /// The remote prefix of the deposit address (e.g. "osmo"), if it is an
    /// interchain deposit. The remote address will be derived from the current
    /// wallet's address but with the given prefix.
    ///
    /// If the remote address is not based on the current wallet's address, use
    /// the `--remote-addr` flag instead.
    #[clap(long)]
    remote_prefix: Option<String>,

    /// The Nomic bech32 wallet address associated with the deposit.
    #[clap(long)]
    nomic_addr: Address,
    /// The Bitcoin address the deposit was made to.
    #[clap(long)]
    deposit_addr: bitcoin::Address,
    /// The Bitcoin block hash the deposit transaction was confirmed in.
    #[clap(long)]
    block_hash: bitcoin::BlockHash,
    /// The Bitcoin transaction ID of the deposit transaction.
    #[clap(long)]
    txid: bitcoin::Txid,
    /// The output index within the deposit transaction, associated with the
    /// output which deposits to the Nomic signatory set.
    #[clap(long)]
    vout: u32,

    /// The path to a file containig the indexes and reserve scripts of
    /// signatories to search. This can be generated with the
    /// `get-reserve-scripts` binary.
    #[clap(long)]
    reserve_script_path: PathBuf,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl RecoverDepositCmd {
    /// Builds a Bitcoin RPC client.
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

    /// Relays a deposit to the Nomic network.
    async fn relay_deposit(&self, dest: Dest, sigset_index: u32) -> Result<()> {
        let nomic_client = self.config.client();
        let btc_client = self.btc_client().await?;

        let block_height = btc_client.get_block_info(&self.block_hash).await?.height as u32;

        let tx = btc_client
            .get_raw_transaction(&self.txid, Some(&self.block_hash))
            .await?;

        let proof_bytes = btc_client
            .get_tx_out_proof(&[tx.txid()], Some(&self.block_hash))
            .await?;
        let proof = ::bitcoin::MerkleBlock::consensus_decode(&mut proof_bytes.as_slice())?.txn;
        {
            let mut tx_bytes = vec![];
            tx.consensus_encode(&mut tx_bytes)?;
            let tx = ::bitcoin::Transaction::consensus_decode(&mut tx_bytes.as_slice())?;
            let tx = Adapter::new(tx);
            let proof = Adapter::new(proof);

            let dest2 = dest.clone();
            nomic_client
                .call(
                    move |app| {
                        build_call!(app.relay_deposit(
                            tx,
                            block_height,
                            proof,
                            self.vout,
                            sigset_index,
                            dest2
                        ))
                    },
                    |app| build_call!(app.app_noop()),
                )
                .await?;
        }

        log::info!(
            "Relayed deposit: {} sats, {:?}",
            tx.output[self.vout as usize].value,
            dest
        );

        Ok(())
    }

    /// Runs the `recover-deposit` command.
    async fn run(&self) -> Result<()> {
        let mut remote_addr = self.remote_addr.clone();
        if let Some(remote_prefix) = &self.remote_prefix {
            let data = bech32::decode(&self.nomic_addr.to_string()).unwrap().1;
            remote_addr =
                Some(bech32::encode(remote_prefix, data, bech32::Variant::Bech32).unwrap());
        }

        if self.channel.is_some() != remote_addr.is_some() {
            return Err(nomic::error::Error::Orga(orga::Error::App(
                "Both --channel and --remote-prefix or --remote-addr must be specified".to_string(),
            )));
        }

        let threshold = self
            .config
            .client()
            .query(|app| Ok(app.bitcoin.checkpoints.config.sigset_threshold))
            .await?;

        // TODO: support passing in script csv by path
        let sigsets: Vec<(u32, SignatorySet)> = std::fs::read_to_string(&self.reserve_script_path)?
            .lines()
            .map(|line| {
                let mut split = line.split(',');
                (split.next().unwrap(), split.next().unwrap())
            })
            .map(|(i, script_hex)| {
                let i = i.parse::<u32>().unwrap();
                let script = bitcoin::Script::from(hex::decode(script_hex).unwrap());
                let (sigset, _) = SignatorySet::from_script(&script, threshold).unwrap();
                (i, sigset)
            })
            .collect();

        dbg!(sigsets.len());

        if let (Some(channel), Some(remote_addr)) = (self.channel.as_ref(), remote_addr.as_ref()) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let start = (now + 60 * 60 * 24 * 7 - (now % (60 * 60))) * 1_000_000_000;
            let mut dest = Dest::Ibc {
                data: IbcDest {
                    source_port: "transfer".to_string().try_into()?,
                    source_channel: channel.to_string().try_into()?,
                    receiver: remote_addr.to_string().try_into()?,
                    sender: self.nomic_addr.to_string().try_into()?,
                    timeout_timestamp: start,
                    memo: "".to_string().try_into()?,
                },
            };

            dbg!(&dest);

            let mut i = 0;
            // TODO: support legacy encoding
            let mut dest_bytes = dest.commitment_bytes().unwrap();
            loop {
                for (sigset_index, sigset) in sigsets.iter() {
                    if i % 10_000 == 0 {
                        if let Dest::Ibc { data: dest } = &dest {
                            println!("{} {}", i, dest.timeout_timestamp);
                        } else {
                            unreachable!()
                        }
                    }

                    let script = sigset.output_script(&dest_bytes, threshold).unwrap();
                    let addr =
                        bitcoin::Address::from_script(&script, nomic::bitcoin::NETWORK).unwrap();
                    if addr.to_string().to_lowercase()
                        == self.deposit_addr.to_string().to_lowercase()
                    {
                        if let Dest::Ibc { data: ibc_dest } = &dest {
                            println!(
                                "Found at sigset index {}, timeout_timestamp {}",
                                sigset_index, ibc_dest.timeout_timestamp,
                            );
                        } else {
                            unreachable!()
                        }

                        return self.relay_deposit(dest, *sigset_index).await;
                    }

                    i += 1;
                }

                if let Dest::Ibc { data: ibc_dest } = &mut dest {
                    ibc_dest.timeout_timestamp -= 60 * 60 * 1_000_000_000;
                    // TODO: support legacy encoding
                    dest_bytes = dest.commitment_bytes().unwrap();
                } else {
                    unreachable!()
                }
            }
        }

        let dest = Dest::NativeAccount {
            address: self.nomic_addr,
        };
        // TODO: support legacy encoding
        let dest_bytes = dest.commitment_bytes().unwrap();

        for (sigset_index, sigset) in sigsets.iter() {
            let script = sigset.output_script(&dest_bytes, threshold).unwrap();
            let addr = bitcoin::Address::from_script(&script, nomic::bitcoin::NETWORK).unwrap();
            if addr.to_string().to_lowercase() == self.deposit_addr.to_string().to_lowercase() {
                println!("Found at sigset index {}", sigset_index,);
                return self.relay_deposit(dest, *sigset_index).await;
            }
        }

        Err(nomic::error::Error::Orga(orga::Error::App(
            "Deposit address not found in any sigset".to_string(),
        )))
    }
}

/// Pays nBTC into the network fee pool.
#[derive(Parser, Debug)]
pub struct PayToFeePoolCmd {
    /// The amount of nBTC to pay into the fee pool, in micro-satoshis.
    amount: u64,

    #[clap(flatten)]
    config: nomic::network::Config,
}

impl PayToFeePoolCmd {
    /// Runs the `pay-to-fee-pool` command.
    async fn run(&self) -> Result<()> {
        Ok(self
            .config
            .client()
            .with_wallet(wallet())
            .call(
                |app| build_call!(app.bitcoin.transfer_to_fee_pool(self.amount.into())),
                |app| build_call!(app.app_noop()),
            )
            .await?)
    }
}

#[cfg(feature = "ethereum")]
#[derive(Parser, Debug)]
pub struct RelayEthereumCmd {
    #[clap(long)]
    private_key: String, // TODO: use type that validates length, format (optional 0x)

    #[clap(long)]
    eth_rpc_url: String,

    #[clap(flatten)]
    config: nomic::network::Config,
}

#[cfg(feature = "ethereum")]
impl RelayEthereumCmd {
    async fn run(&self) -> Result<()> {
        let mut privkey_hex = self.private_key.as_str();
        if privkey_hex.starts_with("0x") {
            privkey_hex = &privkey_hex[2..];
        }
        let privkey = hex::decode(privkey_hex).unwrap(); // TODO
        if privkey.len() != 32 {
            return Err(nomic::error::Error::Orga(orga::Error::App(
                "Invalid private key".to_string(),
            )));
        }

        let try_relay_msg = || async {
            let client = self.config.clone().client();
            let (token_contract, bridge_contract) = client
                .query(|app| Ok((app.ethereum.token_contract, app.ethereum.bridge_contract)))
                .await?;

            let signer = LocalSigner::from_slice(privkey.as_slice()).unwrap(); // TODO
            let wallet = EthereumWallet::new(signer);
            let provider = alloy::providers::ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(wallet)
                .on_http(self.eth_rpc_url.parse().unwrap());
            let contract = nomic::ethereum::bridge_contract::new(
                alloy::core::primitives::Address::from_slice(&bridge_contract.bytes()),
                provider,
            );

            let msg_index: u64 = contract
                .state_lastEventNonce()
                .call()
                .await
                .unwrap()
                ._0
                .to();
            dbg!(msg_index);

            let Some((msg, sigs, data)) = client
                .query(|app| {
                    if app.ethereum.message_index < msg_index {
                        return Ok(None);
                    }

                    if !app.ethereum.get(msg_index)?.sigs.signed() {
                        log::debug!("Message {msg_index} is still being signed");
                        return Ok(None);
                    }

                    Ok(Some((
                        app.ethereum.get(msg_index)?.sigs.message,
                        app.ethereum.get_sigs(msg_index)?,
                        app.ethereum.get(msg_index)?.msg.clone(),
                    )))
                })
                .await?
            else {
                return Ok(());
            };

            let (ss_index, valset_index) = client
                .query(|app| {
                    for i in 1..msg_index {
                        let msg = app.ethereum.get(msg_index - i)?;
                        if let nomic::ethereum::OutMessageArgs::UpdateValset(
                            valset_index,
                            ref valset,
                        ) = msg.msg
                        {
                            return Ok((valset.index, valset_index));
                        }
                    }

                    Ok((0, 0))
                })
                .await?;
            let mut valset = client
                .query(|app| Ok(app.bitcoin.checkpoints.get(ss_index)?.sigset.clone()))
                .await?;
            valset.normalize_vp(u32::MAX as u64);

            let sigs = sigs
                .into_iter()
                .map(|(pk, sig)| {
                    let (v, r, s) = nomic::ethereum::to_eth_sig(
                        &bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig.0).unwrap(),
                        &bitcoin::secp256k1::PublicKey::from_slice(pk.as_slice()).unwrap(),
                        &Message::from_slice(&msg).unwrap(),
                    );
                    nomic::ethereum::bridge_contract::Signature {
                        v,
                        r: r.into(),
                        s: s.into(),
                    }
                })
                .collect();

            match data {
                nomic::ethereum::OutMessageArgs::Batch {
                    transfers,
                    timeout,
                    batch_index,
                } => {
                    dbg!(contract
                        .submitBatch(
                            valset.to_abi(valset_index),
                            sigs,
                            transfers
                                .iter()
                                .map(|t| alloy::core::primitives::U256::from(t.amount))
                                .collect(),
                            transfers
                                .iter()
                                .map(|t| alloy::core::primitives::Address::from_slice(
                                    &t.dest.bytes()
                                ))
                                .collect(),
                            transfers
                                .iter()
                                .map(|t| alloy::core::primitives::U256::from(t.fee_amount))
                                .collect(),
                            alloy::core::primitives::U256::from(batch_index),
                            alloy::core::primitives::Address::from_slice(&token_contract.bytes()),
                            alloy::core::primitives::U256::from(timeout),
                        )
                        .send()
                        .await
                        .unwrap()
                        .get_receipt()
                        .await
                        .unwrap());
                }
                nomic::ethereum::OutMessageArgs::LogicCall(_, _) => todo!(),
                nomic::ethereum::OutMessageArgs::UpdateValset(index, new_valset) => {
                    dbg!(contract
                        .updateValset(new_valset.to_abi(index), valset.to_abi(valset_index), sigs)
                        .send()
                        .await
                        .unwrap()
                        .get_receipt()
                        .await
                        .unwrap());
                }
            };

            Ok::<_, nomic::error::Error>(())
        };

        let try_relay_return = || async {
            let client = self.config.clone().client();
            let bridge_contract_addr = client.query(|app| Ok(app.ethereum.bridge_contract)).await?;

            let signer = LocalSigner::from_slice(privkey.as_slice()).unwrap(); // TODO
            let wallet = EthereumWallet::new(signer);
            let provider = alloy::providers::ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(wallet)
                .on_http(self.eth_rpc_url.parse().unwrap());
            let contract = nomic::ethereum::bridge_contract::new(
                alloy::core::primitives::Address::from_slice(&bridge_contract_addr.bytes()),
                provider,
            );

            let has_contract_index = !contract
                .state_lastReturnNonce()
                .call_raw()
                .await
                .unwrap()
                .is_empty();
            if !has_contract_index {
                dbg!("No return nonce");
                return Ok(());
            }

            let contract_index: u64 = contract
                .state_lastReturnNonce()
                .call()
                .await
                .unwrap()
                ._0
                .to();
            let nomic_index = client.query(|app| Ok(app.ethereum.return_index)).await?;

            if nomic_index == contract_index {
                return Ok(());
            }
            dbg!(contract_index, nomic_index);

            let dest_str = contract
                .state_returnDests(alloy::core::primitives::U256::from(nomic_index))
                .call()
                .await
                .unwrap()
                ._0;
            let amount: u64 = contract
                .state_returnAmounts(alloy::core::primitives::U256::from(nomic_index))
                .call()
                .await
                .unwrap()
                ._0
                .to();
            dbg!(&dest_str, amount);

            let dest: Dest = dest_str.parse().unwrap();
            // TODO: build proofs
            client
                .call(
                    move |app| {
                        build_call!(app.ethereum.relay_return(
                            (),
                            (),
                            vec![(nomic_index, dest.clone(), amount)]
                                .try_into()
                                .unwrap()
                        ))
                    },
                    |app| build_call!(app.app_noop()),
                )
                .await?;

            Ok::<_, nomic::error::Error>(())
        };

        let relay_to_eth = async {
            loop {
                if let Err(e) = try_relay_msg().await {
                    log::error!("Ethereum relayer error: {:?}", e);
                };

                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }

            #[allow(unreachable_code)]
            Ok::<_, nomic::error::Error>(())
        };

        let relay_to_nomic = async {
            loop {
                if let Err(e) = try_relay_return().await {
                    log::error!("Nomic relayer error: {:?}", e);
                };

                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }

            #[allow(unreachable_code)]
            Ok::<_, nomic::error::Error>(())
        };

        futures::try_join!(relay_to_eth, relay_to_nomic)?;

        Ok(())
    }
}

/// The entry point to the Nomic command line interface.
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
