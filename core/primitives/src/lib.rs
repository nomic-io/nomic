mod account;
mod error;
pub use account::Account;
pub use error::*;
pub mod transaction;
use nomic_bitcoin::Script;
use orga::{Decode, Encode};

pub type Address = [u8; 33];
pub type Signature = [u8; 64];

#[derive(Encode, Decode)]
pub struct Withdrawal {
    pub value: u64,
    pub script: Script,
}
