pub mod handlers;
mod state;

pub use state::*;

pub const SIGNATORY_CHANGE_INTERVAL: u64 = 8;
pub const CHECKPOINT_INTERVAL: u64 = 60 * 2;
pub const CHECKPOINT_FEE_AMOUNT: u64 = 1_000;
