use crate::error::{Error, Result};
use clap::{self, ArgMatches, Args, Command, CommandFactory, ErrorKind, FromArgMatches, Parser};
use serde::{Deserialize, Serialize};
#[cfg(feature = "full")]
use std::path::PathBuf;
use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
    Local,
}

impl Network {
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
            "testnet" => Ok(Self::Testnet),
            "local" => Ok(Self::Local),
            _ => Err(Error::Orga(orga::Error::App(format!(
                "Invalid network: {s}"
            )))),
        }
    }
}

#[derive(Parser, Debug, Default, Clone, Serialize, Deserialize)]
pub struct InnerConfig {
    #[clap(long, global = true)]
    pub state_sync_rpc: Vec<String>,
    #[clap(long, global = true)]
    pub chain_id: Option<String>,
    #[clap(long, global = true)]
    pub genesis: Option<String>,
    #[clap(long, global = true)]
    pub legacy_version: Option<String>,
    #[clap(long, global = true)]
    pub upgrade_height: Option<u64>,
    #[clap(long, global = true)]
    pub network: Option<Network>,
    #[clap(long, global = true)]
    home: Option<String>,

    #[clap(global = true)]
    pub tendermint_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Config(InnerConfig);

impl Config {
    #[cfg(feature = "full")]
    pub fn home(&self) -> Option<PathBuf> {
        self.home
            .as_ref()
            .map(PathBuf::from)
            .or(self.chain_id.as_ref().map(|c| orga::abci::Node::home(c)))
    }

    #[cfg(feature = "full")]
    pub fn home_expect(&self) -> Result<PathBuf> {
        self.home().ok_or_else(|| {
            // Don't show "--network" in error message if it was specified (e.g. `--network local`)
            if self.0.network.is_some() {
                orga::Error::App("Cannot get home directory. Please specify either --home, --chain-id, or --genesis.".to_string())
            } else {
                orga::Error::App("Cannot get home directory. Please specify either --network, --home, --chain-id, or --genesis.".to_string())
            }.into()
        })
    }

    pub fn is_empty(&self) -> bool {
        self.0.network.is_none()
            && self.0.chain_id.is_none()
            && self.0.genesis.is_none()
            && self.0.home.is_none()
    }

    pub fn network(&self) -> Option<Network> {
        match self.0.network {
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
        &self.0
    }
}

impl DerefMut for Config {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Parser for Config {}

impl FromArgMatches for Config {
    fn from_arg_matches(matches: &ArgMatches) -> std::result::Result<Self, clap::Error> {
        let mut config = Self(Default::default());
        config.update_from_arg_matches(matches)?;
        Ok(config)
    }

    fn update_from_arg_matches(
        &mut self,
        matches: &ArgMatches,
    ) -> std::result::Result<(), clap::Error> {
        self.0.update_from_arg_matches(matches)?;

        if let Some(network) = self.network() {
            let mut net_config = network.config();
            let arg_config = &self.0;

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
                net_config.home = arg_config.home.clone();
            }

            // TODO: deduplicate
            net_config
                .state_sync_rpc
                .extend(arg_config.state_sync_rpc.iter().cloned());

            // TODO: should all built-in tmflags get shadowed by user-specified tmflags?
            net_config
                .tendermint_flags
                .extend(arg_config.tendermint_flags.iter().cloned());

            self.0 = net_config;
        }

        if let Some(genesis) = self.0.genesis.as_ref() {
            let genesis: serde_json::Value = genesis.parse().unwrap();
            let gensis_cid = genesis["chain_id"].as_str().unwrap();

            if let Some(cid) = self.0.chain_id.as_ref() {
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
                self.0.chain_id = Some(gensis_cid.to_string());
            }
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
