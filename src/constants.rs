pub const MAIN_NATIVE_TOKEN_DENOM: &str = "uoraibtc";
pub const BTC_NATIVE_TOKEN_DENOM: &str = "usat";
pub const MIN_FEE_RATE: u64 = 2; // in satoshis per vbytes
pub const MAX_FEE_RATE: u64 = 200; // in satoshis per vbytes
pub const IBC_FEE: u64 = 0;
/// The default fee rate to be used to pay miner fees, in satoshis per virtual byte.
pub const DEFAULT_FEE_RATE: u64 = 10;
pub const BRIDGE_FEE_RATE: f64 = 0.0;
pub const TRANSFER_FEE: u64 = 0;

// app constants
pub const IBC_FEE_USATS: u64 = 0;
pub const DECLARE_FEE_USATS: u64 = 0;

pub const INITIAL_SUPPLY_ORAIBTC: u64 = 1_000_000_000_000; // 1 millions oraibtc
pub const INITIAL_SUPPLY_USATS_FOR_RELAYER: u64 = 1_000_000_000_000; // 1 millions usats

pub const MIN_DEPOSIT_AMOUNT: u64 = 600; // in satoshis
pub const MIN_WITHDRAWAL_AMOUNT: u64 = 600; // in satoshis
