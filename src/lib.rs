#![feature(proc_macro_hygiene, decl_macro)]
#![feature(negative_impls)]
#[macro_use]
extern crate rocket;
pub mod chain;
pub mod cli;
pub mod core;
mod main;
pub mod relayer;
pub mod signatory;
pub mod worker;

pub use failure::Error;
pub type Result<T> = std::result::Result<T, Error>;
