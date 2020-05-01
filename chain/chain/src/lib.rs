pub mod state_machine;
pub use orga;
pub use state_machine::State;

pub mod action;
pub use action::Action;

pub mod abci_server;
pub mod spv;

mod accounts;
pub mod peg;
#[cfg(test)]
mod test_utils;
mod work;

use lazy_static::lazy_static;
use secp256k1::{Secp256k1, VerifyOnly};
lazy_static! {
    static ref SECP: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}
