use clap::{self, Parser};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn config(&self) -> Config {
        let toml_src = match self {
            Self::Mainnet => panic!("Mainnet is not yet configured"),
            Self::Testnet => include_str!("../networks/testnet.toml"),
        };

        let mut config: Config = toml::from_str(toml_src).unwrap();

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

#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[clap(long)]
    pub state_sync_rpc: Vec<String>,
    #[clap(long)]
    pub chain_id: Option<String>,
    #[clap(long)]
    pub genesis: Option<String>,
    #[clap(long)]
    pub legacy_version: Option<String>,
    pub tendermint_flags: Vec<String>,

    #[cfg(feature = "compat")]
    #[clap(long)]
    pub upgrade_time: Option<i64>,
}
