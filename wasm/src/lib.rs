#![feature(async_closure)]

mod error;
mod types;
mod web_client;

use crate::error::Error;
use crate::types::*;
use crate::web_client::WebClient;
use js_sys::Array;
use nomic::app::{App, DepositCommitment, Nom, CHAIN_ID};
use nomic::bitcoin::Nbtc;
use nomic::orga::coins::Symbol;
use nomic::orga::plugins::sdk_compat::sdk;
use nomic::orga::prelude::Address;
use nomic::orga::prelude::MIN_FEE;
use urlencoding::encode;
use wasm_bindgen::prelude::{wasm_bindgen, JsError, JsValue};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

const REST_PORT: u64 = 8443;

#[wasm_bindgen(start)]
pub fn main() -> std::result::Result<(), JsValue> {
    console_error_panic_hook::set_once();
    Ok(())
}

//bytes
#[wasm_bindgen]
pub async fn transfer(to_addr: String, amount: u64) -> Result<JsValue, JsError> {
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

#[wasm_bindgen]
pub async fn balance(addr: String) -> Result<u64, JsError> {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    Ok(client.accounts.balance(address).await??.into())
}

#[wasm_bindgen(js_name = nomRewardBalance)]
pub async fn nom_reward_balance(addr: String) -> Result<u64, JsError> {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let delegations = client.staking.delegations(address).await??;

    Ok(delegations
        .iter()
        .map(|(_, d)| -> u64 {
            d.liquid
                .iter()
                .find(|(denom, _)| *denom == Nom::INDEX)
                .unwrap_or(&(0, 0.into()))
                .1
                .into()
        })
        .sum::<u64>())
}

#[wasm_bindgen(js_name = nbtcRewardBalance)]
pub async fn nbtc_reward_balance(addr: String) -> Result<u64, JsError> {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let delegations = client.staking.delegations(address).await??;

    Ok(delegations
        .iter()
        .map(|(_, d)| -> u64 {
            d.liquid
                .iter()
                .find(|(denom, _)| *denom == Nbtc::INDEX)
                .unwrap_or(&(0, 0.into()))
                .1
                .into()
        })
        .sum::<u64>())
}

#[wasm_bindgen]
pub async fn delegations(addr: String) -> Result<Array, JsError> {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let delegations = client.staking.delegations(address).await??;

    Ok(delegations
        .iter()
        .map(|(address, delegation)| Delegation {
            address: address.to_string(),
            staked: delegation.staked.into(),
            liquid: delegation
                .liquid
                .iter()
                .map(|(denom, amount)| {
                    Coin {
                        denom: *denom,
                        amount: (*amount).into(),
                    }
                    .into()
                })
                .collect(),
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

#[wasm_bindgen(js_name = allValidators)]
pub async fn all_validators() -> Result<Array, JsError> {
    let mut client: WebClient<App> = WebClient::new();

    let validators = client.staking.all_validators().await??;
    Ok(validators
        .iter()
        .map(|v| {
            let info_bytes: Vec<u8> = v.info.clone().into();

            ValidatorQueryInfo {
                jailed: v.jailed,
                address: v.address.to_string(),
                commission: v.commission.rate.to_string(),
                in_active_set: v.in_active_set,
                info: String::from_utf8(info_bytes).unwrap_or(String::new()),
                amount_staked: v.amount_staked.into(),
            }
        })
        .map(JsValue::from)
        .collect())
}

#[wasm_bindgen]
pub async fn claim(address: String) -> Result<String, JsError> {
    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "nomic/MsgClaimRewards".to_string(),
            value: serde_json::Map::new().into(),
        },
    )
    .await
}

#[wasm_bindgen(js_name = claimAirdrop)]
pub async fn claim_airdrop(address: String) -> Result<String, JsError> {
    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "nomic/MsgClaimAirdrop1".to_string(),
            value: serde_json::Map::new().into(),
        },
    )
    .await
}

#[wasm_bindgen(js_name = claimBtcDepositAirdrop)]
pub async fn claim_btc_deposit_airdrop(address: String) -> Result<String, JsError> {
    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "nomic/MsgClaimBtcDepositAirdrop".to_string(),
            value: serde_json::Map::new().into(),
        },
    )
    .await
}

#[wasm_bindgen(js_name = claimBtcWithdrawAirdrop)]
pub async fn claim_btc_withdraw_airdrop(address: String) -> Result<String, JsError> {
    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "nomic/MsgClaimBtcWithdrawAirdrop".to_string(),
            value: serde_json::Map::new().into(),
        },
    )
    .await
}

#[wasm_bindgen(js_name = claimIbcTransferAirdrop)]
pub async fn claim_ibc_transfer_airdrop(address: String) -> Result<String, JsError> {
    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "nomic/MsgClaimIbcTransferAirdrop".to_string(),
            value: serde_json::Map::new().into(),
        },
    )
    .await
}

#[wasm_bindgen(js_name = claimTestnetParticipationAirdrop)]
pub async fn claim_testnet_participation_airdrop(address: String) -> Result<String, JsError> {
    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "nomic/MsgClaimTestnetParticipationAirdrop".to_string(),
            value: serde_json::Map::new().into(),
        },
    )
    .await
}
#[wasm_bindgen(js_name = claimIncomingIbcBtc)]
pub async fn claim_incoming_ibc_btc(address: String) -> Result<String, JsError> {
    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "nomic/MsgClaimIbcBitcoin".to_string(),
            value: serde_json::Map::new().into(),
        },
    )
    .await
}

//bytes
#[wasm_bindgen]
pub async fn delegate(from_addr: String, to_addr: String, amount: u64) -> Result<String, JsError> {
    let mut amount_obj = serde_json::Map::new();
    amount_obj.insert("amount".to_string(), amount.to_string().into());
    amount_obj.insert("denom".to_string(), "unom".into());

    let mut value = serde_json::Map::new();
    value.insert("delegator_address".to_string(), from_addr.clone().into());
    value.insert("validator_address".to_string(), to_addr.into());
    value.insert("amount".to_string(), amount_obj.into());

    gen_call_bytes(
        from_addr,
        sdk::Msg {
            type_: "cosmos-sdk/MsgDelegate".to_string(),
            value: value.into(),
        },
    )
    .await
}

#[wasm_bindgen]
pub async fn unbond(address: String, val_addr: String, amount: u64) -> Result<String, JsError> {
    let mut amount_obj = serde_json::Map::new();
    amount_obj.insert("amount".to_string(), amount.to_string().into());
    amount_obj.insert("denom".to_string(), "unom".into());

    let mut value = serde_json::Map::new();
    value.insert("delegator_address".to_string(), address.clone().into());
    value.insert("validator_address".to_string(), val_addr.into());
    value.insert("amount".to_string(), amount_obj.into());

    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "cosmos-sdk/MsgUndelegate".to_string(),
            value: value.into(),
        },
    )
    .await
}

#[wasm_bindgen]
pub async fn redelegate(
    address: String,
    src_addr: String,
    dst_addr: String,
    amount: u64,
) -> Result<String, JsError> {
    let mut amount_obj = serde_json::Map::new();
    amount_obj.insert("amount".to_string(), amount.to_string().into());
    amount_obj.insert("denom".to_string(), "unom".into());

    let mut value = serde_json::Map::new();
    value.insert("delegator_address".to_string(), address.clone().into());
    value.insert("validator_src_address".to_string(), src_addr.into());
    value.insert("validator_dst_address".to_string(), dst_addr.into());
    value.insert("amount".to_string(), amount_obj.into());

    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "cosmos-sdk/MsgBeginRedelegate".to_string(),
            value: value.into(),
        },
    )
    .await
}

fn parse_part(part: nomic::airdrop::Part) -> AirdropDetails {
    AirdropDetails {
        locked: part.locked,
        claimed: part.claimed,
        claimable: part.claimable,
        amount: part.claimed + part.claimable + part.locked,
    }
}

#[wasm_bindgen(js_name = airdropBalances)]
pub async fn airdrop_balances(addr: String) -> Result<Airdrop, JsError> {
    let client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    if let Some(account) = client.airdrop.get(address).await?? {
        Ok(Airdrop {
            airdrop1: parse_part(account.airdrop1),
            btc_deposit: parse_part(account.btc_deposit),
            btc_withdraw: parse_part(account.btc_withdraw),
            ibc_transfer: parse_part(account.ibc_transfer),
            testnet_participation: parse_part(account.testnet_participation),
        })
    } else {
        Ok(Airdrop::default())
    }
}

#[wasm_bindgen]
pub async fn nonce(addr: String) -> Result<u64, JsError> {
    let client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    Ok(client.nonce(address).await?)
}

//maybe bytes, not sure here
//actually probably not
#[wasm_bindgen(js_name = generateDepositAddress)]
pub async fn gen_deposit_addr(dest_addr: String) -> Result<DepositAddress, JsError> {
    let client: WebClient<App> = WebClient::new();
    let dest_addr = dest_addr
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let sigset = client.bitcoin.checkpoints.active_sigset().await??;
    let script = sigset.output_script(
        DepositCommitment::Address(dest_addr)
            .commitment_bytes()?
            .as_slice(),
    )?;
    // TODO: get network from somewhere
    // TODO: make test/mainnet option configurable
    let btc_addr = match bitcoin::Address::from_script(&script, bitcoin::Network::Testnet) {
        Some(addr) => addr,
        None => return Err(Error::Wasm("Bitcoin Address not found".to_string()).into()),
    };

    Ok(DepositAddress {
        address: btc_addr.to_string(),
        sigset_index: sigset.index(),
        expiration: sigset.deposit_timeout() * 1000,
    })
}

#[wasm_bindgen(js_name = nbtcBalance)]
pub async fn nbtc_balance(addr: String) -> Result<u64, JsError> {
    let client: WebClient<App> = WebClient::new();
    let addr = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    Ok(client.bitcoin.accounts.balance(addr).await??.into())
}

#[wasm_bindgen(js_name = incomingIbcNbtcBalance)]
pub async fn incoming_ibc_nbtc_balance(addr: String) -> Result<u64, JsError> {
    let client: WebClient<App> = WebClient::new();
    let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let balance = client
        .ibc
        .transfers
        .escrowed_balance(address, "usat".parse().unwrap())
        .await??;
    Ok(balance.into())
}

#[wasm_bindgen(js_name = valueLocked)]
pub async fn value_locked() -> Result<u64, JsError> {
    let client: WebClient<App> = WebClient::new();
    Ok(client.bitcoin.value_locked().await??)
}

#[wasm_bindgen(js_name = latestCheckpointHash)]
pub async fn latest_checkpoint_hash() -> Result<String, JsError> {
    let client: WebClient<App> = WebClient::new();

    let last_checkpoint_id = client
        .bitcoin
        .checkpoints
        .last_completed_tx()
        .await??
        .txid();
    Ok(last_checkpoint_id.to_string())
}

#[wasm_bindgen(js_name = bitcoinHeight)]
pub async fn bitcoin_height() -> Result<u32, JsError> {
    let client: WebClient<App> = WebClient::new();
    Ok(client.bitcoin.headers.height().await??)
}

#[wasm_bindgen(js_name = getAddress)]
pub async fn get_address() -> Result<String, JsError> {
    let signer = nomic::orga::plugins::keplr::Signer;
    Ok(signer.address().await)
}

#[wasm_bindgen(js_name = broadcastDepositAddress)]
pub async fn broadcast_deposit_addr(
    dest_addr: String,
    sigset_index: u32,
    relayers: js_sys::Array,
    deposit_addr: String,
) -> Result<(), JsError> {
    let dest_addr = dest_addr
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let commitment = DepositCommitment::Address(dest_addr);

    let window = match web_sys::window() {
        Some(window) => window,
        None => return Err(Error::Wasm("Window not found".to_string()).into()),
    };

    for relayer in relayers.iter() {
        let relayer = match relayer.as_string() {
            Some(relayer) => relayer,
            None => return Err(Error::Wasm("Relayer not found".to_string()).into()),
        };

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        let url = format!(
            "{}?dest_bytes={}&sigset_index={}&deposit_addr={}",
            relayer,
            encode(&commitment.to_base64()?),
            sigset_index,
            deposit_addr
        );

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

        let resp_value: JsValue = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

        let res: Response = resp_value
            .dyn_into()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        let status = res.status();
        if status != 200 {
            return Err(Error::Relayer(format!(
                "Relayer response returned with error code: {}",
                status
            ))
            .into());
        }
        let res_buf = res
            .array_buffer()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        let res = JsFuture::from(res_buf)
            .await
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        let res = js_sys::Uint8Array::new(&res).to_vec();
        let res = String::from_utf8(res)?;

        // web_sys::console::log_1(&format!("response: {}", &res).into());
    }
    Ok(())
}

#[wasm_bindgen]
pub async fn withdraw(address: String, dest_addr: String, amount: u64) -> Result<String, JsError> {
    let mut value = serde_json::Map::new();
    value.insert("amount".to_string(), amount.to_string().into());
    value.insert("dst_address".to_string(), dest_addr.into());

    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "nomic/MsgWithdraw".to_string(),
            value: value.into(),
        },
    )
    .await
}

#[wasm_bindgen(js_name = joinAirdropAccounts)]
pub async fn join_airdrop_accounts(
    source_address: String,
    destination_address: String,
) -> Result<String, JsError> {
    let address: Address = source_address
        .parse()
        .map_err(|e| Error::Wasm("Invalid source address".to_string()))?;
    let dest_addr: Address = destination_address
        .parse()
        .map_err(|e| Error::Wasm("Invalid destination address".to_string()))?;

    let mut value = serde_json::Map::new();
    value.insert("dest_address".to_string(), dest_addr.to_string().into());

    gen_call_bytes(
        address.to_string(),
        sdk::Msg {
            type_: "nomic/MsgJoinAirdropAccounts".to_string(),
            value: value.into(),
        },
    )
    .await
}

#[wasm_bindgen(js_name = ibcTransferOut)]
pub async fn ibc_transfer_out(
    amount: u64,
    channel_id: String,
    port_id: String,
    denom: String,
    self_address: String,
    receiver_address: String,
    timeout_timestamp: String,
) -> Result<String, JsError> {
    let mut client: WebClient<App> = WebClient::new();

    let mut value = serde_json::Map::new();
    value.insert("amount".to_string(), amount.into());
    value.insert("denom".to_string(), denom.into());
    value.insert("channel_id".to_string(), channel_id.into());
    value.insert("port_id".to_string(), port_id.into());
    value.insert("receiver".to_string(), receiver_address.into());
    value.insert("sender".to_string(), self_address.clone().into());
    value.insert("timeout_timestamp".to_string(), timeout_timestamp.into());

    let address = self_address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
    gen_call_bytes(
        address,
        sdk::Msg {
            type_: "nomic/MsgIbcTransferOut".to_string(),
            value: value.into(),
        },
    )
    .await
}

async fn gen_call_bytes(address: String, msg: sdk::Msg) -> Result<String, JsError> {
    let address = address
        .parse()
        .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

    let mut client: WebClient<App> = WebClient::new();
    let nonce = client.nonce(address).await?;
    let sign_doc = sdk::SignDoc {
        account_number: "0".to_string(),
        chain_id: CHAIN_ID.to_string(),
        //does this fee have to be a vec
        fee: sdk::Fee {
            amount: vec![sdk::Coin {
                amount: "0".to_string(),
                denom: "unom".to_string(),
            }],
            gas: MIN_FEE.to_string(),
        },
        memo: "".to_string(),
        //do these messages have to be a vec
        //might be utility in multiple messages
        msgs: vec![msg],
        sequence: (nonce + 1).to_string(),
    };

    Ok(serde_json::to_string(&sign_doc)?)
}

#[wasm_bindgen(js_name = convertEthAddress)]
pub fn convert_eth_address(str: String) -> Result<String, JsError> {
    if !str.starts_with("0x") {
        return Err(JsError::new("Address must start with 0x"));
    }
    if str.len() != 42 {
        return Err(JsError::new("Address must be 20 bytes"));
    }

    let bytes = hex::decode(&str[2..]).map_err(|_| Error::Wasm("Invalid address".to_string()))?;
    let mut arr = [0; Address::LENGTH];
    arr.copy_from_slice(&bytes[..]);
    let addr: Address = arr.into();

    Ok(addr.to_string())
}

// #[wasm_bindgen]
// pub async fn describe() -> nomic::orga::describe::Descriptor {
//     use nomic::orga::describe::Describe;
//     nomic::app::App::describe()
// }
