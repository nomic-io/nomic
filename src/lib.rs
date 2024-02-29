#![feature(trivial_bounds)]
#![feature(never_type)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(type_alias_impl_trait)]
#![feature(async_closure)]
#![feature(trait_alias)]

#[cfg(feature = "full")]
use orga::{
    client::{wallet::Unsigned, AppClient},
    tendermint::client::HttpClient,
};

pub use orga;
pub use thiserror;

pub mod app;
pub mod bitcoin;
pub mod cosmos;
pub mod error;
#[cfg(feature = "full")]
pub mod network;
#[cfg(feature = "full")]
pub mod utils;

pub mod constants;

#[cfg(feature = "full")]
pub fn app_client(
    addr: &str,
) -> AppClient<app::InnerApp, app::InnerApp, HttpClient, app::Nom, Unsigned> {
    let client = HttpClient::new(addr).unwrap();
    AppClient::new(client, Unsigned)
}
