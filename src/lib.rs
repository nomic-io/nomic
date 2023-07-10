#![feature(trivial_bounds)]
#![feature(never_type)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(type_alias_impl_trait)]
#![feature(async_closure)]

use orga::client::wallet::Unsigned;
use orga::client::AppClient;
#[cfg(feature = "full")]
use orga::tendermint::client::HttpClient;

pub use orga;
pub use thiserror;

pub mod airdrop;
pub mod app;
pub mod bitcoin;
pub mod error;
pub mod incentives;
pub mod network;
pub mod utils;

#[cfg(feature = "full")]
pub fn app_client_testnet(
) -> AppClient<app::InnerApp, app::InnerApp, HttpClient, app::Nom, Unsigned> {
    let client = HttpClient::new("http://localhost:26657").unwrap();
    AppClient::new(client, Unsigned)
}
