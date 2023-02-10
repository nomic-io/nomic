use crate::error::{Error, Result};
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
}

impl FromStr for Network {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "devnet" => Ok(Self::Devnet),
            _ => Err(Error::Orga(orga::Error::App(format!(
                "Invalid network: {s}"
            )))),
        }
    }
}
