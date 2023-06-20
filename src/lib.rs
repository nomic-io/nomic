#![feature(trivial_bounds)]
#![feature(never_type)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(type_alias_impl_trait)]
#![feature(async_closure)]
#![feature(is_some_and)]

// #[cfg(feature = "full")]
use orga::client::wallet::DerivedKey;
use orga::client::AppClient;
use orga::tendermint::client::HttpClient;

pub use orga;
pub use thiserror;

pub mod airdrop;
pub mod app;
pub mod bitcoin;
pub mod error;
pub mod network;

#[cfg(feature = "full")]
pub fn app_client() -> AppClient<app::App, app::App, HttpClient, app::Nom, DerivedKey> {
    todo!()
    // TendermintClient::new("http://localhost:26657").unwrap()
}
