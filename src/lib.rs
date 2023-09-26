#![feature(trivial_bounds)]
#![feature(never_type)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(type_alias_impl_trait)]
#![feature(async_closure)]
#![feature(string_leak)]

#[cfg(feature = "full")]
use orga::{
    client::{wallet::Unsigned, AppClient},
    tendermint::client::HttpClient,
};

pub use orga;
pub use thiserror;

pub mod airdrop;
pub mod app;
pub mod bitcoin;
pub mod cosmos;
pub mod error;
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
