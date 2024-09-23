//! Network configuration, for setting defaults configured for Nomic Stakenet,
//! Nomic Testnet, or a local network. This is largely used in the command line
//! interface.
//!
//! Predefined network configuration is stored in TOML within the
//! `nomic/networks` directory.

use crate::{
    app::{InnerApp, Nom},
    error::{Error, Result},
};
use clap::{self, ArgMatches, Args, Command, CommandFactory, ErrorKind, FromArgMatches, Parser};
use orga::{
    client::{wallet::Unsigned, AppClient},
    tendermint::client::HttpClient,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "full")]
use std::path::PathBuf;
use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

/// The network type to use for getting configuration defaults.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Nomic mainnet (currently Stakenet).
    Mainnet,
    /// Nomic testnet.
    Testnet,
    /// A local network.
    Local,
}

impl Network {
    /// Get the configuration defaults for the network.
    pub fn config(&self) -> InnerConfig {
        let toml_src = match self {
            Self::Mainnet => include_str!("../networks/stakenet.toml"),
            Self::Testnet => include_str!("../networks/testnet.toml"),
            Self::Local => return InnerConfig::default(),
        };

        let mut config: InnerConfig = toml::from_str(toml_src).unwrap();

        config.tendermint_flags = config
            .tendermint_flags
            .iter()
            .map(|s| s.trim().to_string())
            .collect();

        config
    }
}

impl FromStr for Network {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "stakenet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "local" => Ok(Self::Local),
            _ => Err(Error::Orga(orga::Error::App(format!(
                "Invalid network: {s}"
            )))),
        }
    }
}

/// Command line options for network configuration, used in all commands.
#[derive(Parser, Debug, Default, Clone, Serialize, Deserialize)]
pub struct InnerConfig {
    /// The addresses of Tendermint RPC nodes to use when initializing a new
    /// node via state sync. At least 2 values must be provided.
    ///
    /// If not provided, this will default to values specifies in the network
    /// config, if any. If provided, the network config values will be ignored.
    #[clap(long, global = true)]
    pub state_sync_rpc: Vec<String>,
    /// The Tendermint chain ID.
    ///
    /// This can not be used with `--network mainnet` or `--network testnet`,
    /// since the value will be taken from the network config instead.
    #[clap(long, global = true)]
    pub chain_id: Option<String>,
    /// The path to the genesis file.
    ///
    /// This can not be used with `--network mainnet` or `--network testnet`,
    /// since the value will be taken from the network config instead.
    ///
    /// When using this type as a library instead of via the CLI, this may be
    /// set to the full genesis file contents instead.
    #[clap(long, global = true)]
    pub genesis: Option<String>,
    /// The version of the legacy chain to upgrade from.
    #[clap(long, global = true)]
    pub legacy_version: Option<String>,
    /// The height at which to exit the legacy node then run a migration before
    /// transitioning to the upgraded node.
    #[clap(long, global = true)]
    pub upgrade_height: Option<u64>,
    /// The network to use for configuration defaults. This may be "mainnet" or
    /// "testnet" to connect to a known public network, or "local" to use a
    /// local network which may be manually configured.
    #[clap(long, global = true)]
    pub network: Option<Network>,
    /// The directory where network data and configuration will be stored.
    #[clap(long, global = true)]
    pub home: Option<String>,
    /// The address of the node to connect to (e.g. "http://localhost:26657").
    ///
    /// This is only relevant for client commands which make queries or
    /// broadcast transactions).
    #[clap(long, global = true)]
    pub node: Option<String>,
    /// The address of the Bitcoin relayer to use when broadcasting Bitcoin
    /// deposit addresses.
    ///
    /// This is only relevant for the `deposit` and `interchain-deposit`
    /// commands.
    #[clap(long, global = true)]
    pub btc_relayer: Vec<String>,

    /// Command line options to pass-through the to Tendermint node process.
    ///
    /// The options will be added to the end of the invocation of
    /// `tendermint start`, and should be an option known to Tendermint such as
    /// "--p2p.laddr http://localhost:26657".
    #[clap(long, global = true)]
    pub tendermint_flags: Vec<String>,
}

/// Command line options for network configuration, used
/// in all commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Config {
    args: InnerConfig,
}

impl Config {
    /// Get the network home directory, based on being set explicitly or given
    /// by the network default. If the value can not be determined, returns
    /// None.
    #[cfg(feature = "full")]
    pub fn home(&self) -> Option<PathBuf> {
        self.home
            .as_ref()
            .map(PathBuf::from)
            .or(self.chain_id.as_ref().map(|c| orga::abci::Node::home(c)))
    }

    /// Get the network home directory, based on being set explicitly or given
    /// by the network default. If the value can not be determined, returns an
    /// error.
    #[cfg(feature = "full")]
    pub fn home_expect(&self) -> Result<PathBuf> {
        self.home().ok_or_else(|| {
            // Don't show "--network" in error message if it was specified (e.g. `--network local`)
            if self.args.network.is_some() {
                orga::Error::App("Cannot get home directory. Please specify either --home, --chain-id, or --genesis.".to_string())
            } else {
                orga::Error::App("Cannot get home directory. Please specify either --network, --home, --chain-id, or --genesis.".to_string())
            }.into()
        })
    }

    /// Returns true if the required configuration options are not set.
    pub fn is_empty(&self) -> bool {
        self.args.network.is_none()
            && self.args.chain_id.is_none()
            && self.args.genesis.is_none()
            && self.args.home.is_none()
    }

    /// Builds a Nomic client based on the configuration.
    pub fn client(&self) -> AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned> {
        let node = self.args.node.as_ref().unwrap();
        crate::app_client(node)
    }

    /// Get the network used in the configuration for deriving default values.
    pub fn network(&self) -> Option<Network> {
        match self.args.network {
            Some(Network::Local) => None,
            Some(network) => Some(network),
            #[cfg(feature = "testnet")]
            None => Some(Network::Testnet),
            #[cfg(not(feature = "testnet"))]
            None => Some(Network::Mainnet),
        }
    }
}

impl Deref for Config {
    type Target = InnerConfig;
    fn deref(&self) -> &Self::Target {
        &self.args
    }
}

impl DerefMut for Config {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.args
    }
}

impl Parser for Config {}

impl FromArgMatches for Config {
    fn from_arg_matches(matches: &ArgMatches) -> std::result::Result<Self, clap::Error> {
        let mut config = Self {
            args: Default::default(),
        };
        config.update_from_arg_matches(matches)?;
        Ok(config)
    }

    fn update_from_arg_matches(
        &mut self,
        matches: &ArgMatches,
    ) -> std::result::Result<(), clap::Error> {
        self.args.update_from_arg_matches(matches)?;

        if let Some(network) = self.network() {
            let mut net_config = network.config();
            let arg_config = &self.args;

            if arg_config.chain_id.is_some() {
                return Err(clap::Error::raw(
                    ErrorKind::ArgumentConflict,
                    "Cannot use --chain-id with --network",
                ));
            }
            if arg_config.genesis.is_some() {
                return Err(clap::Error::raw(
                    ErrorKind::ArgumentConflict,
                    "Cannot use --genesis with --network",
                ));
            }
            if net_config.upgrade_height.is_some() && arg_config.upgrade_height.is_some() {
                return Err(clap::Error::raw(
                    ErrorKind::ArgumentConflict,
                    "Cannot use --upgrade_height with --network",
                ));
            } else if arg_config.upgrade_height.is_some() {
                net_config.upgrade_height = arg_config.upgrade_height;
            }
            if arg_config.home.is_some() {
                net_config.home.clone_from(&arg_config.home)
            }

            if !arg_config.state_sync_rpc.is_empty() {
                net_config
                    .state_sync_rpc
                    .clone_from(&arg_config.state_sync_rpc);
            }

            // TODO: should all built-in tmflags get shadowed by user-specified tmflags?
            net_config
                .tendermint_flags
                .extend(arg_config.tendermint_flags.iter().cloned());

            self.args = net_config;
        }

        if let Some(genesis) = self.args.genesis.as_ref() {
            let genesis_bytes = if genesis.contains('\n') {
                genesis.clone()
            } else {
                std::fs::read_to_string(genesis)?
            };
            let genesis: serde_json::Value = genesis_bytes.parse().unwrap();
            let gensis_cid = genesis["chain_id"].as_str().unwrap();

            if let Some(cid) = self.args.chain_id.as_ref() {
                if cid != gensis_cid {
                    return Err(clap::Error::raw(
                        ErrorKind::ArgumentConflict,
                        format!(
                            "Genesis chain ID ({}) does not match --chain-id ({})",
                            gensis_cid, cid
                        ),
                    ));
                }
            } else {
                self.args.chain_id = Some(gensis_cid.to_string());
            }
        }

        if self.args.node.is_none() {
            // TODO: get port from Tendermint config.toml for default
            self.args.node = Some("http://localhost:26657".to_string());
        }

        Ok(())
    }
}

impl CommandFactory for Config {
    fn into_app<'help>() -> Command<'help> {
        InnerConfig::into_app()
    }

    fn into_app_for_update<'help>() -> Command<'help> {
        InnerConfig::into_app_for_update()
    }
}

impl Args for Config {
    fn augment_args(cmd: Command<'_>) -> Command<'_> {
        InnerConfig::augment_args(cmd)
    }

    fn augment_args_for_update(cmd: Command<'_>) -> Command<'_> {
        InnerConfig::augment_args_for_update(cmd)
    }
}
