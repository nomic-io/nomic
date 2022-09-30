use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
pub struct DepositAddress {
    pub address: String,
    #[wasm_bindgen(js_name = sigsetIndex)]
    pub sigset_index: u32,
    pub expiration: u64,
}

#[wasm_bindgen(getter_with_clone)]
pub struct ValidatorQueryInfo {
    pub jailed: bool,
    pub address: String,
    pub commission: String,
    #[wasm_bindgen(js_name = inActiveSet)]
    pub in_active_set: bool,
    pub info: String,
    #[wasm_bindgen(js_name = amountStaked)]
    pub amount_staked: u64,
}

#[wasm_bindgen]
pub struct UnbondInfo {
    #[wasm_bindgen(js_name = startSeconds)]
    pub start_seconds: u64,
    pub amount: u64,
}

#[wasm_bindgen(getter_with_clone)]
pub struct Delegation {
    pub address: String,
    pub staked: u64,
    pub liquid: Vec<JsValue>,
    pub unbonding: Vec<JsValue>,
}

#[wasm_bindgen(getter_with_clone)]
pub struct Coin {
    pub denom: u8,
    pub amount: u64,
}

#[wasm_bindgen]
pub struct AirdropDetails {
    pub claimed: bool,
    pub claimable: bool,
    pub amount: u64,
}

#[wasm_bindgen(getter_with_clone)]
pub struct Airdrop {
    pub airdrop1: AirdropDetails,
    #[wasm_bindgen(js_name = btcDeposit)]
    pub btc_deposit: AirdropDetails,
    #[wasm_bindgen(js_name = btcWithdraw)]
    pub btc_withdraw: AirdropDetails,
    #[wasm_bindgen(js_name = ibcTransfer)]
    pub ibc_transfer: AirdropDetails,
}
