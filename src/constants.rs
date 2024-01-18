pub const MAIN_NATIVE_TOKEN_DENOM: &str = "uoraibtc";
pub const BTC_NATIVE_TOKEN_DENOM: &str = "usat";
pub const MIN_FEE_RATE: u64 = 2; // in satoshis per vbytes
pub const MAX_FEE_RATE: u64 = 200; // in satoshis per vbytes
pub const IBC_FEE: u64 = 0;
/// The default fee rate to be used to pay miner fees, in satoshis per virtual byte.
pub const DEFAULT_FEE_RATE: u64 = 10;
pub const BRIDGE_FEE_RATE: f64 = 0.0;