#![feature(trivial_bounds)]
#![feature(never_type)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![allow(incomplete_features)]
#![feature(async_closure)]

#[cfg(feature = "full")]
use orga::abci::TendermintClient;

pub use orga;

pub mod command;

pub mod app;
// pub mod bitcoin;
// pub mod error;

#[cfg(feature = "full")]
pub fn app_client() -> TendermintClient<app::App> {
    TendermintClient::new("http://localhost:26657").unwrap()
}
