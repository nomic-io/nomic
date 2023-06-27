#[macro_use]
extern crate rocket;

use nomic::{
    app::{App, InnerApp, Nom, CHAIN_ID},
    app_client_testnet,
    orga::{
        coins::{Accounts, Address, Amount, Decimal, Staking},
        plugins::*,
        query::Query,
    },
};
use rocket::response::status::BadRequest;
use rocket::serde::json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tendermint_rpc as tm;
use tm::Client as _;

lazy_static::lazy_static! {
    static ref QUERY_CACHE: Arc<RwLock<HashMap<String, (u64, String)>>> = Arc::new(RwLock::new(HashMap::new()));
}

#[get("/cosmos/bank/v1beta1/balances/<address>")]
async fn bank_balances(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    let balance: u64 = app_client_testnet()
        .query(|app| app.accounts.balance(address))
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();

    Ok(json!({
        "balances": [
            {
                "denom": "unom",
                "amount": balance.to_string(),
            },
            {
                "denom": "nsat",
                "amount": balance.to_string(),
            }
        ],
        "pagination": {
            "next_key": null,
            "total": "0"
        }
    }))
}

#[get("/bank/balances/<address>")]
async fn bank_balances_2(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    let balance: u64 = app_client_testnet()
        .query(|app| app.accounts.balance(address))
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();

    Ok(json!({
        "height": "0",
        "result": [
            {
                "denom": "unom",
                "amount": balance.to_string(),
            }
        ]
    }))
}

#[get("/auth/accounts/<addr_str>")]
async fn auth_accounts(addr_str: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = addr_str.parse().unwrap();

    let balance: u64 = app_client_testnet()
        .query(|app| app.accounts.balance(address))
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();

    let mut nonce: u64 = app_client_testnet()
        .query_root(|app| app.inner.inner.borrow().inner.inner.inner.nonce(address))
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();
    nonce += 1;

    Ok(json!({
        "height": "0",
        "result": {
            "type": "cosmos-sdk/BaseAccount",
            "value": {
                "address": addr_str,
                "coins": [
                    {
                        "denom": "unom",
                        "amount": balance.to_string(),
                    }
                ],
                "sequence": nonce.to_string()
            }
        }
    }))
}

#[get("/cosmos/auth/v1beta1/accounts/<addr_str>")]
async fn auth_accounts2(addr_str: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = addr_str.parse().unwrap();

    let balance: u64 = app_client_testnet()
        .query(|app| app.accounts.balance(address))
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();

    let mut nonce: u64 = app_client_testnet()
        .query_root(|app| app.inner.inner.borrow().inner.inner.inner.nonce(address))
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();
    nonce += 1;

    Ok(json!({
        "account": {
          "@type": "/cosmos.auth.v1beta1.BaseAccount",
          "address": addr_str,
          "pub_key": {
            "@type": "/cosmos.crypto.secp256k1.PubKey",
            "key": "Atl2HeBoLMorGAUPTH0hXk2Sx72reuw8x2V1puqwV+jN"
          },
          "account_number": "0",
          "sequence": nonce.to_string()
        }
    }))
}

use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct TxRequest {
    tx: serde_json::Value,
    mode: String,
}

#[post("/txs", data = "<tx>")]
async fn txs(tx: &str) -> Result<Value, BadRequest<String>> {
    dbg!(tx);

    let client = tm::HttpClient::new("http://localhost:26657").unwrap();

    let tx_bytes = if let Some('{') = tx.chars().next() {
        let tx: TxRequest = serde_json::from_str(tx).unwrap();
        serde_json::to_vec(&tx.tx).unwrap()
    } else {
        base64::decode(tx).map_err(|e| BadRequest(Some(format!("{:?}", e))))?
    };

    let res = client
        .broadcast_tx_commit(tx_bytes.into())
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let tx_response = if res.check_tx.code.is_err() {
        &res.check_tx
    } else {
        &res.deliver_tx
    };

    Ok(json!({
        "height": "0",
        "txhash": res.hash,
        "codespace": tx_response.codespace,
        "code": tx_response.code,
        "data": "",
        "raw_log": "[]",
        "logs": [ tx_response.log ],
        "info": tx_response.info,
        "gas_wanted": tx_response.gas_wanted,
        "gas_used": tx_response.gas_used,
        "tx": null,
        "timestamp": ""
    }))
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct TxRequest2 {
    tx_bytes: String,
    mode: String,
}

#[post("/cosmos/tx/v1beta1/txs", data = "<tx>")]
async fn txs2(tx: &str) -> Result<Value, BadRequest<String>> {
    dbg!(tx);

    let client = tm::HttpClient::new("http://localhost:26657").unwrap();

    let tx_bytes = if let Some('{') = tx.chars().next() {
        let tx: TxRequest2 = serde_json::from_str(tx).unwrap();
        base64::decode(tx.tx_bytes.as_str()).map_err(|e| BadRequest(Some(format!("{:?}", e))))?
    } else {
        base64::decode(tx).map_err(|e| BadRequest(Some(format!("{:?}", e))))?
    };

    let res = client
        .broadcast_tx_commit(tx_bytes.into())
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let tx_response = if res.check_tx.code.is_err() {
        &res.check_tx
    } else {
        &res.deliver_tx
    };

    Ok(json!({
        "height": "0",
        "txhash": res.hash,
        "codespace": tx_response.codespace,
        "code": tx_response.code,
        "data": "",
        "raw_log": "[]",
        "logs": [ tx_response.log ],
        "info": tx_response.info,
        "gas_wanted": tx_response.gas_wanted,
        "gas_used": tx_response.gas_used,
        "tx": null,
        "timestamp": ""
    }))
}

fn time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u64
}

#[get("/query/<query>?<height>")]
async fn query(query: &str, height: Option<u32>) -> Result<String, BadRequest<String>> {
    let cache = QUERY_CACHE.clone();
    let lock = cache.read_owned().await;
    let cached_res = lock.get(query).map(|v| v.clone());
    let cache_hit = cached_res.is_some();
    drop(lock);

    dbg!((&query, cache_hit));
    let now = time_now();

    // if let Some((time, res)) = cached_res {
    //     if now - time < 15 {
    //         return Ok(res.clone())
    //     }
    // }

    let client = tm::HttpClient::new("http://localhost:26657").unwrap();

    let query_bytes = hex::decode(query).map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let res = client
        .abci_query(None, query_bytes, height.map(Into::into), true)
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let res_height: u64 = res.height.into();
    let res_height: u32 = res_height.try_into().unwrap();

    if let tendermint::abci::Code::Err(code) = res.code {
        let msg = format!("code {}: {}", code, res.log);
        return Err(BadRequest(Some(msg)));
    }

    let res_b64 = base64::encode([res_height.to_be_bytes().to_vec(), res.value].concat());

    let cache = QUERY_CACHE.clone();
    let mut lock = cache.write_owned().await;
    lock.insert(query.to_string(), (now, res_b64.clone()));
    drop(lock);

    Ok(res_b64)
}

#[get("/cosmos/staking/v1beta1/delegations/<address>")]
async fn staking_delegators_delegations(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    let delegations = app_client_testnet()
        .query(|app| app.staking.delegations(address))
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let total_staked: u64 = delegations
        .iter()
        .map(|(_, d)| -> u64 { d.staked.into() })
        .sum();

    Ok(json!({ "delegation_responses": [
        {
            "delegation": {
                "delegator_address": "",
                "validator_address": "",
                "shares": "0"
            },
            "balance": {
                "denom": "unom",
                "amount": total_staked.to_string(),
            }
          }
    ], "pagination": { "next_key": null, "total": "0" } }))
}

#[get("/staking/delegators/<address>/delegations")]
async fn staking_delegators_delegations_2(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    let delegations = app_client_testnet()
        .query(|app| app.staking.delegations(address))
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let total_staked: u64 = delegations
        .iter()
        .map(|(_, d)| -> u64 { d.staked.into() })
        .sum();

    Ok(json!({ "height": "0", "result": [
        {
            "delegator_address": "",
            "validator_address": "",
            "shares": "0",
            "balance": {
              "denom": "NOM",
              "amount": total_staked.to_string(),
            }
          }
    ] }))
}

#[get("/cosmos/staking/v1beta1/delegators/<address>/unbonding_delegations")]
fn staking_delegators_unbonding_delegations(address: &str) -> Value {
    json!({ "unbonding_responses": [], "pagination": { "next_key": null, "total": "0" } })
}

#[get("/staking/delegators/<address>/unbonding_delegations")]
fn staking_delegators_unbonding_delegations_2(address: &str) -> Value {
    json!({ "height": "0", "result": [] })
}

#[get("/staking/delegators/<address>/delegations")]
fn staking_delegations_2(address: &str) -> Value {
    json!({ "height": "0", "result": [] })
}

#[get("/cosmos/distribution/v1beta1/delegators/<address>/rewards")]
async fn distribution_delegatrs_rewards(address: &str) -> Value {
    // let address = address.parse().unwrap();

    // type AppQuery = <InnerApp as Query>::Query;
    // type StakingQuery = <Staking<Nom> as Query>::Query;

    // let delegations = app_client()
    //     .query(
    //         AppQuery::FieldStaking(StakingQuery::MethodDelegations(address, vec![])),
    //         |state| state.staking.delegations(address),
    //     )
    //     .await
    //     .unwrap();

    // let reward = (delegations
    //     .iter()
    //     .map(|(_, d)| -> u64 { d.liquid.into() })
    //     .sum::<u64>())
    //     .to_string();

    json!({ "height": "0", "result": {
        "rewards": [
        //   {
        //     "validator_address": "cosmosvaloper16xyempempp92x9hyzz9wrgf94r6j9h5f2w4n2l",
        //     "reward": [
        //       {
        //         "denom": "unom",
        //         "amount": reward
        //       }
        //     ]
        //   }
        ],
        "total": [
        //   {
        //     "denom": "unom",
        //     "amount": reward
        //   }
        ]
      } })
}

#[get("/distribution/delegators/<address>/rewards")]
async fn distribution_delegatrs_rewards_2(address: &str) -> Value {
    // let address = address.parse().unwrap();

    // type AppQuery = <InnerApp as Query>::Query;
    // type StakingQuery = <Staking<Nom> as Query>::Query;

    // let delegations = app_client()
    //     .query(
    //         AppQuery::FieldStaking(StakingQuery::MethodDelegations(address, vec![])),
    //         |state| state.staking.delegations(address),
    //     )
    //     .await
    //     .unwrap();

    // let reward = (delegations
    //     .iter()
    //     .map(|(_, d)| -> u64 { d.liquid.into() })
    //     .sum::<u64>())
    //     .to_string();

    json!({ "height": "0", "result": {
        "rewards": [
        //   {
        //     "validator_address": "cosmosvaloper16xyempempp92x9hyzz9wrgf94r6j9h5f2w4n2l",
        //     "reward": [
        //       {
        //         "denom": "unom",
        //         "amount": reward
        //       }
        //     ]
        //   }
        ],
        "total": [
        //   {
        //     "denom": "unom",
        //     "amount": reward
        //   }
        ]
      } })
}

#[get("/cosmos/mint/v1beta1/inflation")]
async fn minting_inflation() -> Result<Value, BadRequest<String>> {
    let validators = app_client_testnet()
        .query(|app| app.staking.all_validators())
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let total_staked: u64 = validators
        .iter()
        .map(|v| -> u64 { v.amount_staked.into() })
        .sum();
    let total_staked = Amount::from(total_staked + 1);
    let yearly_inflation = Decimal::from(64_682_541_340_000);
    let apr = (yearly_inflation / Decimal::from(4) / Decimal::from(total_staked))
        .result()
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    Ok(json!({ "inflation": apr.to_string() }))
}

#[get("/minting/inflation")]
async fn minting_inflation_2() -> Result<Value, BadRequest<String>> {
    let validators = app_client_testnet()
        .query(|app| app.staking.all_validators())
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let total_staked: u64 = validators
        .iter()
        .map(|v| -> u64 { v.amount_staked.into() })
        .sum();
    let total_staked = Amount::from(total_staked + 1);
    let yearly_inflation = Decimal::from(64_682_541_340_000);
    let apr = (yearly_inflation / Decimal::from(4) / Decimal::from(total_staked))
        .result()
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    Ok(json!({ "height": "0", "result": apr.to_string() }))
}

#[get("/bank/total/<denom>")]
fn bank_total(denom: &str) -> Value {
    json!({ "height": "0", "result": "0" })
}

#[get("/cosmos/staking/v1beta1/pool")]
fn staking_pool() -> Value {
    json!({
        "bonded_tokens": "0",
        "not_bonded_tokens": "0"
    })
}

#[get("/cosmos/bank/v1beta1/supply/unom")]
fn bank_supply_unom() -> Value {
    json!({
        "amount": {
            "denom": "unom",
            "amount": "1"
        }
    })
}

#[get("/staking/pool")]
fn staking_pool_2() -> Value {
    json!({ "height": "0", "result": {
        "loose_tokens": "0",
        "bonded_tokens": "0",
        "inflation_last_time": "0",
        "inflation": "1",
        "date_last_commission_reset": "0",
        "prev_bonded_shares": "0"
      } })
}

#[get("/ibc/apps/transfer/v1/params")]
fn ibc_apps_transfer_params() -> Value {
    json!({
        "params": {
            "send_enabled": false,
            "receive_enabled": false
        }
    })
}

#[get("/ibc/applications/transfer/v1/params")]
fn ibc_applications_transfer_params() -> Value {
    json!({
        "params": {
            "send_enabled": false,
            "receive_enabled": false
        }
    })
}

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{Request, Response};

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().attach(CORS).mount(
        "/",
        routes![
            bank_balances,
            bank_balances_2,
            auth_accounts,
            auth_accounts2,
            txs,
            txs2,
            query,
            staking_delegators_delegations,
            // staking_delegators_delegations_2,
            staking_delegators_unbonding_delegations,
            staking_delegators_unbonding_delegations_2,
            distribution_delegatrs_rewards,
            distribution_delegatrs_rewards_2,
            staking_delegations_2,
            minting_inflation,
            staking_pool,
            staking_pool_2,
            bank_total,
            ibc_apps_transfer_params,
            ibc_applications_transfer_params,
            bank_supply_unom,
        ],
    )
}
