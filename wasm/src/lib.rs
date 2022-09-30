#![feature(async_closure)]
#![feature(generic_associated_types)]

mod error;
mod internal;
mod types;
mod web_client;

use wasm_bindgen::prelude::*;

use crate::error::Error;
use crate::internal as Internal;
use crate::types::DepositAddress;
use js_sys::Array;

const REST_PORT: u64 = 8443;

fn into_js_res<T, E: Into<JsValue>>(res: Result<T, E>) -> Result<T, JsValue> {
    match res {
        Ok(res) => Ok(res),
        Err(err) => Err(err.into()),
    }
}

#[wasm_bindgen(start)]
pub fn main() -> std::result::Result<(), JsValue> {
    console_error_panic_hook::set_once();
    Ok(())
}

#[wasm_bindgen]
pub async fn transfer(to_addr: String, amount: u64) -> Result<JsValue, JsValue> {
    into_js_res(Internal::transfer(to_addr, amount).await)
}

#[wasm_bindgen]
pub async fn balance(addr: String) -> Result<u64, JsValue> {
    into_js_res(Internal::balance(addr).await)
}

#[wasm_bindgen(js_name = nomRewardBalance)]
pub async fn nom_reward_balance(addr: String) -> Result<u64, JsValue> {
    into_js_res(Internal::nom_reward_balance(addr).await)
}

#[wasm_bindgen(js_name = nbtcRewardBalance)]
pub async fn nbtc_reward_balance(addr: String) -> Result<u64, JsValue> {
    into_js_res(Internal::nbtc_reward_balance(addr).await)
}

#[wasm_bindgen]
pub async fn delegations(addr: String) -> Result<Array, JsValue> {
    into_js_res(Internal::delegations(addr).await)
}

#[wasm_bindgen(js_name = allValidators)]
pub async fn all_validators() -> Result<Array, JsValue> {
    into_js_res(Internal::all_validators().await)
}

#[wasm_bindgen]
pub async fn claim() -> Result<JsValue, JsValue> {
    into_js_res(Internal::claim().await)
}

#[wasm_bindgen(js_name = claimAirdrop)]
pub async fn claim_airdrop() -> Result<JsValue, JsValue> {
    into_js_res(Internal::claim_airdrop().await)
}

#[wasm_bindgen(js_name = claimBtcDepositAirdrop)]
pub async fn claim_btc_deposit_airdrop() -> Result<JsValue, JsValue> {
    into_js_res(Internal::claim_btc_deposit_airdrop().await)
}

#[wasm_bindgen(js_name = claimBtcWithdrawAirdrop)]
pub async fn claim_btc_withdraw_airdrop() -> Result<JsValue, JsValue> {
    into_js_res(Internal::claim_btc_withdraw_airdrop.await)
}

#[wasm_bindgen(js_name = claimIbcTransferAirdrop)]
pub async fn claim_ibc_transfer_airdrop() -> Result<JsValue, JsValue> {
    into_js_res(Internal::claim_ibc_transfer_airdrop.await)
}

#[wasm_bindgen(js_name = claimIncomingIbcBtc)]
pub async fn claim_incoming_ibc_btc() -> Result<JsValue, JsValue> {
    into_js_res(Internal::claim_incoming_ibc_btc().await)
}

#[wasm_bindgen]
pub async fn delegate(to_addr: String, amount: u64) -> Result<JsValue, JsValue> {
    into_js_res(Internal::delegate(to_addr, amount).await)
}

#[wasm_bindgen]
pub async fn unbond(val_addr: String, amount: u64) -> Result<JsValue, JsValue> {
    into_js_res(Internal::unbond(val_addr, amount).await)
}

#[wasm_bindgen]
pub async fn redelegate(
    src_addr: String,
    dst_addr: String,
    amount: u64,
) -> Result<JsValue, JsValue> {
    into_js_res(Internal::redelegate(src_addr, dst_addr, amount).await)
}

#[wasm_bindgen(js_name = airdropBalance)]
pub async fn airdrop_balance(addr: String) -> Result<Option<u64>, JsValue> {
    into_js_res(Internal::airdrop_balance(addr).await)
}

#[wasm_bindgen]
pub async fn nonce(addr: String) -> Result<u64, JsValue> {
    into_js_res(Internal::nonce(addr).await)
}

#[wasm_bindgen(js_name = getAddress)]
pub async fn get_address() -> Result<String, JsValue> {
    into_js_res(Internal::get_address().await)
}

#[wasm_bindgen(js_name = generateDepositAddress)]
pub async fn gen_deposit_addr(dest_addr: String) -> Result<DepositAddress, JsValue> {
    into_js_res(Internal::gen_deposit_addr(dest_addr).await)
}

#[wasm_bindgen(js_name = nbtcBalance)]
pub async fn nbtc_balance(addr: String) -> Result<u64, JsValue> {
    into_js_res(Internal::nbtc_balance(addr).await)
}

#[wasm_bindgen(js_name = incomingIbcNbtcBalance)]
pub async fn incoming_ibc_nbtc_balance(addr: String) -> Result<u64, JsValue> {
    into_js_res(Internal::incoming_ibc_nbtc_balance(addr).await)
}

#[wasm_bindgen(js_name = valueLocked)]
pub async fn value_locked() -> Result<u64, JsValue> {
    into_js_res(Internal::value_locked().await)
}

#[wasm_bindgen(js_name = latestCheckpointHash)]
pub async fn latest_checkpoint_hash() -> Result<String, JsValue> {
    into_js_res(Internal::latest_checkpoint_hash().await)
}

#[wasm_bindgen(js_name = bitcoinHeight)]
pub async fn bitcoin_height() -> Result<u32, JsValue> {
    into_js_res(Internal::bitcoin_height().await)
}

#[wasm_bindgen(js_name = broadcastDepositAddress)]
pub async fn broadcast_deposit_addr(
    addr: String,
    sigset_index: u32,
    relayers: js_sys::Array,
    deposit_addr: String
) -> Result<(), JsValue> {
    into_js_res(Internal::broadcast_deposit_addr(addr, sigset_index, relayers, deposit_addr).await)
}

#[wasm_bindgen]
pub async fn withdraw(dest_addr: String, amount: u64) -> Result<JsValue, JsValue> {
    into_js_res(Internal::withdraw(dest_addr, amount).await)
}

#[wasm_bindgen]
pub async fn ibc_transfer_out(amount: u64, channel_id: String, port_id: String, denom: String, self_address: String, receiver_address: String, ns_timeout_timestamp: u64) -> Result<JsValue, JsValue> {
    into_js_res(Internal::ibc_transfer_out(amount, channel_id, port_id, denom, self_address, receiver_address, ns_timeout_timestamp).await)
}