use crate::error::{Error, Result};
use clap::{self, ArgMatches, Args, Command, CommandFactory, ErrorKind, FromArgMatches, Parser};
use serde::{Deserialize, Serialize};
use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn config(&self) -> InnerConfig {
        let toml_src = match self {
            Self::Mainnet => panic!("Mainnet is not yet configured"),
            Self::Testnet => include_str!("../networks/testnet.toml"),
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
    pub upgrade_time: Option<i64>,
    #[clap(long, global = true)]
    pub network: Option<Network>,

    #[clap(global = true)]
    pub tendermint_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Config(InnerConfig);

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

        if let Some(network) = self.0.network {
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
            if net_config.upgrade_time.is_some() && arg_config.upgrade_time.is_some() {
                return Err(clap::Error::raw(
                    ErrorKind::ArgumentConflict,
                    "Cannot use --upgrade-time with --network",
                ));
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
