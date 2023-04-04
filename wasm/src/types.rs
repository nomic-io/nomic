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

#[derive(Clone, Default)]
#[wasm_bindgen]
pub struct AirdropDetails {
    pub locked: u64,
    pub claimed: u64,
    pub claimable: u64,
    pub amount: u64,
}

#[derive(Clone, Default)]
#[wasm_bindgen(getter_with_clone)]
pub struct Airdrop {
    pub airdrop1: AirdropDetails,
    #[wasm_bindgen(js_name = btcDeposit)]
    pub btc_deposit: AirdropDetails,
    #[wasm_bindgen(js_name = btcWithdraw)]
    pub btc_withdraw: AirdropDetails,
    #[wasm_bindgen(js_name = ibcTransfer)]
    pub ibc_transfer: AirdropDetails,
    #[wasm_bindgen(js_name = testnetParticipation)]
    pub testnet_participation: AirdropDetails,
}

#[wasm_bindgen]
impl Airdrop {
    #[wasm_bindgen(js_name = airdropTotal)]
    pub fn airdrop_total(&self) -> u64 {
        self.airdrop1.amount
            + self.btc_deposit.amount
            + self.btc_withdraw.amount
            + self.ibc_transfer.amount
            + self.testnet_participation.amount
    }

    #[wasm_bindgen(js_name = claimedTotal)]
    pub fn claimed_total(&self) -> u64 {
        self.airdrop1.claimed
            + self.btc_deposit.claimed
            + self.btc_withdraw.claimed
            + self.ibc_transfer.claimed
            + self.testnet_participation.claimed
    }
}
