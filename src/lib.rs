#![feature(trivial_bounds)]
#![feature(never_type)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(type_alias_impl_trait)]
#![feature(async_closure)]

// #[cfg(feature = "full")]
use orga::client::wallet::DerivedKey;
use orga::client::{AppClient, Client};
use orga::tendermint::client::HttpClient;

pub use orga;
pub use thiserror;

pub mod airdrop;
pub mod app;
pub mod bitcoin;
pub mod error;
pub mod network;

#[cfg(feature = "full")]
pub fn app_client_testnet(
) -> AppClient<app::InnerAppTestnet, app::InnerAppTestnet, HttpClient, app::Nom, DerivedKey> {
    let client = HttpClient::new("http://localhost:26657").unwrap();
    // TODO: use file wallet
    AppClient::new(client, DerivedKey::new(b"test").unwrap())
}
