#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;

mod address_pool;
mod deposit;
mod error;

pub use error::*;
pub mod relayer;
