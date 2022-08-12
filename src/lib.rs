#![feature(trivial_bounds)]
#![feature(never_type)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]
#![feature(is_some_with)]
#![feature(async_closure)]

#[cfg(feature = "full")]
use orga::abci::TendermintClient;

pub use orga;
pub use thiserror;

pub mod app;
pub mod bitcoin;
pub mod error;

#[cfg(feature = "full")]
pub fn app_client() -> TendermintClient<app::App> {
    TendermintClient::new("http://localhost:26357").unwrap()
}
