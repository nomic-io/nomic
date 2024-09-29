//! Nomic is a protocol which enables decentralized custody of Bitcoin, to power
//! bridging, L2's, Bitcoin staking, and more.
//!
//! This crate provides the core logic for both full nodes and clients of the
//! Nomic protocol.

#![feature(trivial_bounds)]
#![feature(never_type)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(type_alias_impl_trait)]
#![feature(trait_alias)]
#![feature(fn_traits)]

#[cfg(feature = "full")]
use orga::{
    client::{wallet::Unsigned, AppClient},
    tendermint::client::HttpClient,
};

pub use orga;
pub use thiserror;

pub mod airdrop;
pub mod app;
#[cfg(feature = "babylon")]
pub mod babylon;
pub mod bitcoin;
pub mod cosmos;
pub mod error;
#[cfg(feature = "ethereum")]
pub mod ethereum;
#[cfg(feature = "frost")]
pub mod frost;
pub mod incentives;
#[cfg(feature = "full")]
pub mod network;
#[cfg(feature = "full")]
pub mod utils;

#[cfg(feature = "full")]
pub fn app_client(
    addr: &str,
) -> AppClient<app::InnerApp, app::InnerApp, HttpClient, app::Nom, Unsigned> {
    let client = HttpClient::new(addr).unwrap();
    AppClient::new(client, Unsigned)
}
