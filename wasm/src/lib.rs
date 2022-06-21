#![feature(async_closure)]
#![feature(generic_associated_types)]

mod error;
mod internal;
mod web_client;

use wasm_bindgen::prelude::*;

use crate::error::Error;
use crate::internal as Internal;
use js_sys::Array;

const REST_PORT: u64 = 8443;

#[wasm_bindgen(start)]
pub fn main() -> std::result::Result<(), JsValue> {
    console_error_panic_hook::set_once();
    Ok(())
}

#[wasm_bindgen]
pub async fn transfer(to_addr: String, amount: u64) -> Result<JsValue, JsValue> {
    match Internal::transfer(to_addr, amount).await {
        Ok(res) => Ok(res),
        Err(err) => Err(err.into()),
    }
}

#[wasm_bindgen]
pub async fn balance(addr: String) -> Result<u64, JsValue> {
    match Internal::balance(addr).await {
        Ok(res) => Ok(res),
        Err(err) => Err(err.into()),
    }
}

#[wasm_bindgen(js_name = rewardBalance)]
pub async fn reward_balance(addr: String) -> Result<u64, JsValue> {
    match Internal::reward_balance(addr).await {
        Ok(res) => Ok(res),
        Err(err) => Err(err.into()),
    }
}

#[wasm_bindgen]
pub async fn delegations(addr: String) -> Result<Array, JsValue> {
    match Internal::delegations(addr).await {
        Ok(res) => Ok(res),
        Err(err) => Err(err.into()),
    }
}

// #[wasm_bindgen(js_name = allValidators)]
// pub async fn all_validators() -> Result<Array> {
//     Internal::all_validators().await?
// }

// #[wasm_bindgen]
// pub async fn claim() -> Result<JsValue> {
//     Internal::claim().await?
// }

// #[wasm_bindgen(js_name = claimAirdrop)]
// pub async fn claim_airdrop() -> Result<JsValue> {
//     Internal::claim_airdrop.await?
// }

// #[wasm_bindgen]
// pub async fn delegate(to_addr: String, amount: u64) -> Result<JsValue> {
//     Internal::delegate(to_addr, amount).await?
// }

// #[wasm_bindgen]
// pub async fn unbond(val_addr: String, amount: u64) -> Result<JsValue> {
//     Internal::unbond(val_addr, amount).await?
// }

// #[wasm_bindgen]
// pub async fn redelegate(src_addr: String, dst_addr: String, amount: u64) -> Result<JsValue> {
//     Internal::redelegate(src_addr, dst_addr, amount).await?
// }

// #[wasm_bindgen(js_name = airdropBalance)]
// pub async fn airdrop_balance(addr: String) -> Result<Option<u64>> {
//     Internal::airdrop_balance(addr).await?
// }

// #[wasm_bindgen]
// pub async fn nonce(addr: String) -> Result<u64> {
//     Internal::nonce(addr).await?
// }

// #[wasm_bindgen(js_name = getAddress)]
// pub async fn get_address() -> Result<String> {
//     Internal::get_address().await?
// }

// #[wasm_bindgen(js_name = generateDepositAddress)]
// pub async fn gen_deposit_addr(dest_addr: String) -> Result<DepositAddress> {
//     Internal::gen_deposit_addr(dest_addr).await?
// }

// // #[wasm_bindgen(js_name = nbtcBalance)]
// // pub async fn nbtc_balance(addr: String) -> Result<u64> {

// // }

// // #[wasm_bindgen(js_name = valueLocked)]
// // pub async fn value_locked() -> Result<u64> {
// //     let client: WebClient<App> = WebClient::new();
// //     client.bitcoin.value_locked().await??
// // }

// // #[wasm_bindgen(js_name = latestCheckpointHash)]
// // pub async fn latest_checkpoint_hash() -> Result<String> {
// //     let client: WebClient<App> = WebClient::new();

// //     let last_checkpoint_id = client
// //         .bitcoin
// //         .checkpoints
// //         .last_completed_tx()
// //         .await??
// //         .txid();
// //     return last_checkpoint_id.to_string();
// // }

// // #[wasm_bindgen(js_name = bitcoinHeight)]
// // pub async fn bitcoin_height() -> Result<u32> {
// //     let client: WebClient<App> = WebClient::new();
// //     client.bitcoin.headers.height().await??
// // }

// // #[wasm_bindgen(js_name = broadcastDepositAddress)]
// // pub async fn broadcast_deposit_addr(
// //     addr: String,
// //     sigset_index: u32,
// //     relayers: js_sys::Array,
// // ) -> Result<()> {
// //     let window = web_sys::window()?;

// //     for relayer in relayers.iter() {
// //         let relayer = relayer.as_string()?;

// //         let mut opts = RequestInit::new();
// //         opts.method("POST");
// //         opts.mode(RequestMode::Cors);
// //         let url = format!("{}?addr={}&sigset_index={}", relayer, addr, sigset_index);

// //         let request = Request::new_with_str_and_init(&url, &opts)?;

// //         let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

// //         let res: Response = resp_value.dyn_into()?;
// //         let res = JsFuture::from(res.array_buffer()?).await?;
// //         let res = js_sys::Uint8Array::new(&res).to_vec();
// //         let res = String::from_utf8(res)?;
// //         web_sys::console::log_1(&format!("response: {}", &res).into());
// //     }
// //     Ok(())
// // }

// // #[wasm_bindgen]
// // pub async fn withdraw(dest_addr: String, amount: u64) -> Result<JsValue> {
// //     let mut value = serde_json::Map::new();
// //     value.insert("amount".to_string(), amount.to_string().into());
// //     value.insert("dst_address".to_string(), dest_addr.into());

// //     send_sdk_tx(sdk::Msg {
// //         type_: "nomic/MsgWithdraw".to_string(),
// //         value: value.into(),
// //     })
// //     .await
// // }
