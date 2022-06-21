#![feature(async_closure)]
#![feature(generic_associated_types)]

use crate::error::{Error, Result};
use crate::types::{Delegation, DepositAddress, UnbondInfo, ValidatorQueryInfo};
use crate::web_client::WebAdapter;
use crate::web_client::WebClient;
use js_sys::{Array, JsString};
use nomic::app::{Airdrop, App, InnerApp, Nom, CHAIN_ID};
use nomic::bitcoin::signatory::SignatorySet;
use nomic::orga::client::AsyncQuery;
use nomic::orga::merk::ABCIPrefixedProofStore;
use nomic::orga::plugins::sdk_compat::sdk;
use nomic::orga::prelude::AsyncCall;
use nomic::orga::prelude::MIN_FEE;
use std::convert::TryInto;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

pub async fn transfer(to_addr: String, amount: u64) -> Result<JsValue> {
    let mut client: WebClient<App> = WebClient::new();
    let address = to_addr
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    client
        .pay_from(async move |mut client| client.accounts.take_as_funding(MIN_FEE.into()).await)
        .accounts
        .transfer(address, amount.into())
        .await?;
    Ok(client.last_res()?)
}

pub async fn balance(addr: String) -> Result<u64> {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    Ok(client.accounts.balance(address).await??.into())
}

pub async fn reward_balance(addr: String) -> Result<u64> {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let delegations = client.staking.delegations(address).await??;

    Ok(delegations
        .iter()
        .map(|(_, d)| -> u64 { d.liquid.into() })
        .sum::<u64>())
}

pub async fn delegations(addr: String) -> Result<Array> {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let delegations = client.staking.delegations(address).await??;

    Ok(delegations
        .iter()
        .map(|(address, delegation)| Delegation {
            address: address.to_string(),
            staked: delegation.staked.into(),
            liquid: delegation.liquid.into(),
            unbonding: delegation
                .unbonding
                .iter()
                .map(|u| UnbondInfo {
                    start_seconds: u.start_seconds as u64,
                    amount: u.amount.into(),
                })
                .map(JsValue::from)
                .collect(),
        })
        .map(JsValue::from)
        .collect())
}

pub async fn all_validators() -> Result<Array> {
    let mut client: WebClient<App> = WebClient::new();

    let validators = client.staking.all_validators().await??;

    Ok(validators
        .iter()
        .map(|v| ValidatorQueryInfo {
            jailed: v.jailed,
            address: v.address.to_string(),
            commission: v.commission.rate.to_string(),
            in_active_set: v.in_active_set,
            info: String::from_utf8(v.info.bytes.clone()).unwrap_or(String::new()),
            amount_staked: v.amount_staked.into(),
        })
        .map(JsValue::from)
        .collect())
}

pub async fn get_address() -> Result<String> {
    let signer = nomic::orga::plugins::keplr::Signer;
    Ok(signer.address().await)
}

async fn send_sdk_tx(msg: sdk::Msg) -> Result<JsValue> {
    let my_addr = get_address().await?;
    let address = my_addr
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let mut client: WebClient<App> = WebClient::new();
    let nonce = client.nonce(address).await?;

    client
        .send_sdk_tx(sdk::SignDoc {
            account_number: "0".to_string(),
            chain_id: CHAIN_ID.to_string(),
            fee: sdk::Fee {
                amount: vec![sdk::Coin {
                    amount: "0".to_string(),
                    denom: "unom".to_string(),
                }],
                gas: MIN_FEE.to_string(),
            },
            memo: "".to_string(),
            msgs: vec![msg],
            sequence: (nonce + 1).to_string(),
        })
        .await?;

    Ok(client.last_res()?)
}

pub async fn claim() -> Result<JsValue> {
    send_sdk_tx(sdk::Msg {
        type_: "nomic/MsgClaimRewards".to_string(),
        value: serde_json::Map::new().into(),
    })
    .await
}

pub async fn claim_airdrop() -> Result<JsValue> {
    send_sdk_tx(sdk::Msg {
        type_: "nomic/MsgClaimAirdrop".to_string(),
        value: serde_json::Map::new().into(),
    })
    .await
}

pub async fn delegate(to_addr: String, amount: u64) -> Result<JsValue> {
    let my_addr = get_address().await?;

    let mut amount_obj = serde_json::Map::new();
    amount_obj.insert("amount".to_string(), amount.to_string().into());
    amount_obj.insert("denom".to_string(), "unom".into());

    let mut value = serde_json::Map::new();
    value.insert("delegator_address".to_string(), my_addr.into());
    value.insert("validator_address".to_string(), to_addr.into());
    value.insert("amount".to_string(), amount_obj.into());

    send_sdk_tx(sdk::Msg {
        type_: "cosmos-sdk/MsgDelegate".to_string(),
        value: value.into(),
    })
    .await
}

pub async fn unbond(val_addr: String, amount: u64) -> Result<JsValue> {
    let my_addr = get_address().await?;

    let mut amount_obj = serde_json::Map::new();
    amount_obj.insert("amount".to_string(), amount.to_string().into());
    amount_obj.insert("denom".to_string(), "unom".into());

    let mut value = serde_json::Map::new();
    value.insert("delegator_address".to_string(), my_addr.into());
    value.insert("validator_address".to_string(), val_addr.into());
    value.insert("amount".to_string(), amount_obj.into());

    send_sdk_tx(sdk::Msg {
        type_: "cosmos-sdk/MsgUndelegate".to_string(),
        value: value.into(),
    })
    .await
}

pub async fn redelegate(src_addr: String, dst_addr: String, amount: u64) -> Result<JsValue> {
    let my_addr = get_address().await?;

    let mut amount_obj = serde_json::Map::new();
    amount_obj.insert("amount".to_string(), amount.to_string().into());
    amount_obj.insert("denom".to_string(), "unom".into());

    let mut value = serde_json::Map::new();
    value.insert("delegator_address".to_string(), my_addr.into());
    value.insert("validator_src_address".to_string(), src_addr.into());
    value.insert("validator_dst_address".to_string(), dst_addr.into());
    value.insert("amount".to_string(), amount_obj.into());

    send_sdk_tx(sdk::Msg {
        type_: "cosmos-sdk/MsgBeginRedelegate".to_string(),
        value: value.into(),
    })
    .await
}

pub async fn airdrop_balance(addr: String) -> Result<Option<u64>> {
    let client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    Ok(client.atom_airdrop.balance(address).await??.map(Into::into))
}

pub async fn nonce(addr: String) -> Result<u64> {
    let client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    Ok(client.nonce(address).await?)
}

pub async fn gen_deposit_addr(dest_addr: String) -> Result<DepositAddress> {
    let client: WebClient<App> = WebClient::new();
    let dest_addr = dest_addr
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let sigset = client
        .bitcoin
        .checkpoints
        .active_sigset()
        .await
        .unwrap()
        .unwrap();
    let script = sigset.output_script(dest_addr)?;
    // TODO: get network from somewhere
    let btc_addr = match bitcoin::Address::from_script(&script, bitcoin::Network::Testnet) {
        Some(addr) => addr,
        None => return Err(Error::Wasm("Bitcoin Address not found".to_string())),
    };

    Ok(DepositAddress {
        address: btc_addr.to_string(),
        sigset_index: sigset.index(),
        expiration: sigset.deposit_timeout() * 1000,
    })
}

// pub async fn nbtc_balance(addr: String) -> Result<u64> {
//     let client: WebClient<App> = WebClient::new();
//     let addr: Address = addr.parse()?;

//     client.bitcoin.accounts.balance(addr).await??.into()
// }

// pub async fn value_locked() -> Result<u64> {
//     let client: WebClient<App> = WebClient::new();
//     client.bitcoin.value_locked().await??
// }

// pub async fn latest_checkpoint_hash() -> Result<String> {
//     let client: WebClient<App> = WebClient::new();

//     let last_checkpoint_id = client
//         .bitcoin
//         .checkpoints
//         .last_completed_tx()
//         .await??
//         .txid();
//     return last_checkpoint_id.to_string();
// }

// pub async fn bitcoin_height() -> Result<u32> {
//     let client: WebClient<App> = WebClient::new();
//     client.bitcoin.headers.height().await??
// }

// pub async fn broadcast_deposit_addr(
//     addr: String,
//     sigset_index: u32,
//     relayers: js_sys::Array,
// ) -> Result<()> {
//     let window = web_sys::window()?;

//     for relayer in relayers.iter() {
//         let relayer = relayer.as_string()?;

//         let mut opts = RequestInit::new();
//         opts.method("POST");
//         opts.mode(RequestMode::Cors);
//         let url = format!("{}?addr={}&sigset_index={}", relayer, addr, sigset_index);

//         let request = Request::new_with_str_and_init(&url, &opts)?;

//         let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

//         let res: Response = resp_value.dyn_into()?;
//         let res = JsFuture::from(res.array_buffer()?).await?;
//         let res = js_sys::Uint8Array::new(&res).to_vec();
//         let res = String::from_utf8(res)?;
//         web_sys::console::log_1(&format!("response: {}", &res).into());
//     }
//     Ok(())
// }

// pub async fn withdraw(dest_addr: String, amount: u64) -> Result<JsValue> {
//     let mut value = serde_json::Map::new();
//     value.insert("amount".to_string(), amount.to_string().into());
//     value.insert("dst_address".to_string(), dest_addr.into());

//     send_sdk_tx(sdk::Msg {
//         type_: "nomic/MsgWithdraw".to_string(),
//         value: value.into(),
//     })
//     .await
// }
