#[macro_use]
extern crate rocket;

use bitcoin::Address as BitcoinAddress;
use nomic::{
    app::{InnerApp, Nom},
    bitcoin::{
        checkpoint::{CheckpointQueue, Config as CheckpointConfig},
        Config, Nbtc,
    },
    constants::MAIN_NATIVE_TOKEN_DENOM,
    orga::{
        client::{wallet::Unsigned, AppClient},
        coins::{Address, Amount, Decimal, DelegationInfo, Staking, Symbol, ValidatorQueryInfo},
        tendermint::client::HttpClient,
    },
    utils::DeclareInfo,
};
use rocket::response::status::BadRequest;
use rocket::serde::json::{json, Value};
use std::sync::Arc;
use std::{collections::HashMap, str::FromStr};
use tokio::sync::RwLock;

use tendermint_rpc as tm;
use tm::Client as _;

lazy_static::lazy_static! {
    static ref QUERY_CACHE: Arc<RwLock<HashMap<String, (u64, String)>>> = Arc::new(RwLock::new(HashMap::new()));
}

#[derive(Serialize, Deserialize)]
pub struct Balance {
    pub denom: String,
    pub amount: String,
}

fn app_client() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned> {
    nomic::app_client("http://localhost:26657")
}

async fn query_balances(address: &str) -> Result<Vec<Balance>, BadRequest<String>> {
    let address: Address = address.parse().unwrap();
    let mut balances: Vec<Balance> = vec![];

    let balance: u64 = app_client()
        .query(|app: InnerApp| app.accounts.balance(address))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();
    balances.push(Balance {
        denom: Nom::NAME.to_string(),
        amount: balance.to_string(),
    });

    let balance: u64 = app_client()
        .query(|app: InnerApp| app.bitcoin.accounts.balance(address))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();
    balances.push(Balance {
        denom: Nbtc::NAME.to_string(),
        amount: balance.to_string(),
    });
    Ok(balances)
}

// DONE /cosmos/bank/v1beta1/balances/{address}
// DONE /cosmos/distribution/v1beta1/delegators/{address}/rewards
// TODO /cosmos/staking/v1beta1/delegations/{address}
// DONE /cosmos/staking/v1beta1/validators
// DONE /cosmos/staking/v1beta1/delegators/{address}/unbonding_delegations
// /cosmos/staking/v1beta1/validators/{address}
// /cosmos/gov/v1beta1/proposals
// /cosmos/gov/v1beta1/proposals/{proposalId}
// /cosmos/gov/v1beta1/proposals/{proposalId}/votes/{address}
// /cosmos/gov/v1beta1/proposals/{proposalId}/tally
// /ibc/apps/transfer/v1/denom_traces/{hash}
// /ibc/core/channel/v1/channels/{channelId}/ports/{portId}/client_state

#[get("/cosmos/staking/v1beta1/validators")]
async fn get_validators() -> Value {
    let all_validators: Vec<ValidatorQueryInfo> = app_client()
        .query(|app: InnerApp| app.staking.all_validators())
        .await
        .unwrap();

    let mut validators = vec![];
    for validator in all_validators {
        let cons_key = app_client()
            .query(|app: InnerApp| app.staking.consensus_key(validator.address.into()))
            .await
            .unwrap(); // TODO: cache

        let status = if validator.unbonding {
            "BOND_STATUS_UNBONDING"
        } else if validator.in_active_set {
            "BOND_STATUS_BONDED"
        } else {
            "BOND_STATUS_UNBONDED"
        };

        let info: DeclareInfo =
            serde_json::from_str(String::from_utf8(validator.info.to_vec()).unwrap().as_str())
                .unwrap_or(DeclareInfo {
                    details: "".to_string(),
                    identity: "".to_string(),
                    moniker: "".to_string(),
                    website: "".to_string(),
                });

        validators.push(json!(
           {
             "operator_address": validator.address.to_string(),
             "consensus_pubkey": {
                 "@type": "/cosmos.crypto.ed25519.PubKey",
                 "key": base64::encode(cons_key)
             },
             "jailed": validator.jailed,
             "status": status,
             "tokens": validator.amount_staked.to_string(),
             "delegator_shares": validator.amount_staked.to_string(),
             "description": {
                 "moniker": info.moniker,
                 "identity": info.identity,
                 "website": info.website,
                 "security_contact": "",
                 "details": info.details
             },
             "unbonding_height": "0", // TODO
             "unbonding_time": "1970-01-01T00:00:00Z", // TODO
             "commission": {
                 "commission_rates": {
                 "rate": validator.commission.rate,
                 "max_rate": validator.commission.max,
                 "max_change_rate": validator.commission.max_change
                 },
                 "update_time": "2023-08-04T06:00:00.000000000Z" // TODO
             },
             "min_self_delegation": validator.min_self_delegation.to_string()
        }));
    }

    json!({
        "validators": validators,
        "pagination": {
            "next_key": null,
            "total": validators.len().to_string()
        }
    })
}

#[get("/cosmos/staking/v1beta1/validators/<address>")]
async fn get_validator(address: &str) -> Value {
    let address: Address = address.parse().unwrap();

    // TODO: cache
    let all_validators: Vec<ValidatorQueryInfo> = app_client()
        .query(|app: InnerApp| app.staking.all_validators())
        .await
        .unwrap();

    let mut validators = vec![];
    for validator in all_validators {
        if validator.address != address.into() {
            continue;
        }
        let cons_key = app_client()
            .query(|app: InnerApp| app.staking.consensus_key(validator.address.into()))
            .await
            .unwrap();

        let status = if validator.unbonding {
            "BOND_STATUS_UNBONDING"
        } else if validator.in_active_set {
            "BOND_STATUS_BONDED"
        } else {
            "BOND_STATUS_UNBONDED"
        };

        let info: DeclareInfo =
            serde_json::from_str(String::from_utf8(validator.info.to_vec()).unwrap().as_str())
                .unwrap_or(DeclareInfo {
                    details: "".to_string(),
                    identity: "".to_string(),
                    moniker: "".to_string(),
                    website: "".to_string(),
                });

        validators.push(json!(
           {
             "operator_address": validator.address.to_string(),
             "consensus_pubkey": {
                 "@type": "/cosmos.crypto.ed25519.PubKey",
                 "key": base64::encode(cons_key)
             },
             "jailed": validator.jailed,
             "status": status,
             "tokens": validator.amount_staked.to_string(),
             "delegator_shares": validator.amount_staked.to_string(),
             "description": {
                 "moniker": info.moniker,
                 "identity": info.identity,
                 "website": info.website,
                 "security_contact": "",
                 "details": info.details
             },
             "unbonding_height": "0", // TODO
             "unbonding_time": "1970-01-01T00:00:00Z", // TODO
             "commission": {
                 "commission_rates": {
                 "rate": validator.commission.rate,
                 "max_rate": validator.commission.max,
                 "max_change_rate": validator.commission.max_change
                 },
                 "update_time": "2023-08-04T06:00:00.000000000Z" // TODO
             },
             "min_self_delegation": validator.min_self_delegation.to_string()
        }));
    }
    let validator = validators.first().unwrap();

    json!({
        "validator": validator,
    })
}

#[get("/cosmos/bank/v1beta1/balances/<address>")]
async fn bank_balances(address: &str) -> Result<Value, BadRequest<String>> {
    let balances: Vec<Balance> = query_balances(address).await?;
    let total = balances.len().to_string();
    Ok(json!({
        "balances": balances,
        "pagination": {
            "next_key": null,
            "total": total
        }
    }))
}

#[get("/bank/balances/<address>")]
async fn bank_balances_2(address: &str) -> Result<Value, BadRequest<String>> {
    let balances: Vec<Balance> = query_balances(address).await?;
    let total = balances.len().to_string();
    Ok(json!({
        "balances": balances,
        "pagination": {
            "next_key": null,
            "total": total
        }
    }))
}

#[get("/auth/accounts/<addr_str>")]
async fn auth_accounts(addr_str: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = addr_str.parse().unwrap();

    let balances: Vec<Balance> = query_balances(addr_str).await?;

    let mut nonce: u64 = app_client()
        .query_root(|app| app.inner.inner.borrow().inner.inner.inner.nonce(address))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;
    nonce += 1;

    Ok(json!({
        "height": "0",
        "result": {
            "type": "cosmos-sdk/BaseAccount",
            "value": {
                "address": addr_str,
                "coins": balances,
                "sequence": nonce.to_string()
            }
        }
    }))
}

#[get("/cosmos/auth/v1beta1/accounts/<addr_str>")]
async fn auth_accounts2(addr_str: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = addr_str.parse().unwrap();

    // let _balance: u64 = app_client()
    //     .query(|app| app.accounts.balance(address))
    //     .await
    //     .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
    //     .into();

    let mut nonce: u64 = app_client()
        .query_root(|app| app.inner.inner.borrow().inner.inner.inner.nonce(address))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;
    nonce += 1;

    Ok(json!({
        "account": {
          "@type": "/cosmos.auth.v1beta1.BaseAccount",
          "address": addr_str,
          "pub_key": {
            "@type": "/cosmos.crypto.secp256k1.PubKey",
            "key": ""
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
        "height": res.height,
        "txhash": res.hash,
        "codespace": tx_response.codespace,
        "code": tx_response.code,
        "data": tx_response.data,
        "raw_log": tx_response.log,
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
        .as_secs()
}

#[get("/query/<query>?<height>")]
async fn query(query: &str, height: Option<u32>) -> Result<String, BadRequest<String>> {
    let cache = QUERY_CACHE.clone();
    let lock = cache.read_owned().await;
    let cached_res = lock.get(query).cloned();
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
async fn staking_delegators_delegations(address: &str) -> Value {
    let address: Address = address.parse().unwrap();

    let delegations: Vec<(Address, DelegationInfo)> = app_client()
        .query(|app: InnerApp| app.staking.delegations(address))
        .await
        .unwrap();

    let total_staked: u64 = delegations
        .iter()
        .map(|(_, d)| -> u64 { d.staked.into() })
        .sum();

    json!({
    "delegation_responses": [
        {
            "delegation": {
                "delegator_address": "",
                "validator_address": "",
                "shares": "0"
            },
            "balance": {
                "denom": MAIN_NATIVE_TOKEN_DENOM,
                "amount": total_staked.to_string(),
            }
          }
    ], "pagination": { "next_key": null, "total": "0" } })
}

#[get("/staking/delegators/<address>/delegations")]
async fn staking_delegators_delegations_2(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    let delegations: Vec<(Address, DelegationInfo)> = app_client()
        .query(|app: InnerApp| app.staking.delegations(address))
        .await
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

#[get("/bitcoin/config")]
async fn bitcoin_config() -> Result<Value, BadRequest<String>> {
    let config: Config = app_client()
        .query(|app: InnerApp| Ok(app.bitcoin.config))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    Ok(json!(config))
}

#[get("/bitcoin/checkpoint/config")]
async fn bitcoin_checkpoint_config() -> Result<Value, BadRequest<String>> {
    let config: CheckpointConfig = app_client()
        .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.config))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    Ok(json!(config))
}

#[get("/bitcoin/checkpoint")]
async fn bitcoin_latest_checkpoint() -> Result<Value, BadRequest<String>> {
    let checkpoint_queue: CheckpointQueue = app_client()
        .query(|app: InnerApp| Ok(app.bitcoin.checkpoints))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let index = checkpoint_queue.index;
    let list_checkpoints = checkpoint_queue.all().unwrap();
    if list_checkpoints.len() == 0 {
        return Ok(json!({}));
    }
    let current_checkpoint_ref = list_checkpoints.last().unwrap();
    let current_checkpoint = &current_checkpoint_ref.1;
    Ok(json!({
        "index": index,
        "confirmed_index": checkpoint_queue.confirmed_index,
        "current_fee_rate": current_checkpoint.fee_rate,
        "status": current_checkpoint.status
    }))
}

#[get("/bitcoin/checkpoint/current_checkpoint_size")]
async fn bitcoin_checkpoint_size() -> Result<Value, BadRequest<String>> {
    let config: usize = app_client()
        .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.building()?.checkpoint_tx()?.vsize()))
        .await
        .map_err(|e| BadRequest(Some(format!("error: {:?}", e))))?;

    let total_inputs: usize = app_client()
        .query(|app: InnerApp| {
            Ok(app
                .bitcoin
                .checkpoints
                .building()?
                .checkpoint_tx()?
                .input
                .len())
        })
        .await
        .map_err(|e| BadRequest(Some(format!("error: {:?}", e))))?;
    Ok(json!({
        "checkpoint_vsize": config,
        "total_input_size": total_inputs,
    }))
}

#[get("/bitcoin/checkpoint/last_checkpoint_size")]
async fn bitcoin_last_checkpoint_size() -> Result<Value, BadRequest<String>> {
    let config: usize = app_client()
        .query(|app: InnerApp| {
            Ok(app
                .bitcoin
                .checkpoints
                .last_completed()?
                .checkpoint_tx()?
                .vsize())
        })
        .await
        .map_err(|e| BadRequest(Some(format!("error: {:?}", e))))?;

    let total_inputs: usize = app_client()
        .query(|app: InnerApp| {
            Ok(app
                .bitcoin
                .checkpoints
                .last_completed()?
                .checkpoint_tx()?
                .input
                .len())
        })
        .await
        .map_err(|e| BadRequest(Some(format!("error: {:?}", e))))?;
    Ok(json!({
        "checkpoint_vsize": config,
        "total_input_size": total_inputs,
    }))
}

#[get("/bitcoin/checkpoint/checkpoint_size?<index>")]
async fn bitcoin_checkpoint_size_with_index(index: u32) -> Result<Value, BadRequest<String>> {
    let config: usize = app_client()
        .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.get(index)?.checkpoint_tx()?.vsize()))
        .await
        .map_err(|e| BadRequest(Some(format!("error: {:?}", e))))?;

    let total_inputs: usize = app_client()
        .query(|app: InnerApp| {
            Ok(app
                .bitcoin
                .checkpoints
                .get(index)?
                .checkpoint_tx()?
                .input
                .len())
        })
        .await
        .map_err(|e| BadRequest(Some(format!("error: {:?}", e))))?;
    Ok(json!({
        "checkpoint_vsize": config,
        "total_input_size": total_inputs,
    }))
}

#[get("/cosmos/staking/v1beta1/delegators/<address>/unbonding_delegations")]
async fn staking_delegators_unbonding_delegations(address: &str) -> Value {
    use chrono::{TimeZone, Utc};
    let address: Address = address.parse().unwrap();
    let delegations: Vec<(Address, DelegationInfo)> = app_client()
        .query(|app: InnerApp| app.staking.delegations(address))
        .await
        .unwrap();

    let mut unbonds = vec![];

    for (val_address, delegation) in delegations {
        let mut entries = vec![];
        for unbond in delegation.unbonding {
            let t = Utc.timestamp_opt(unbond.start_seconds, 0).unwrap();
            entries.push(json!({
                "creation_height": "0", // TODO
                "completion_time": t, // TODO
                "initial_balance": "0", // TODO
                "balance": "0" // TODO
            }))
        }
        unbonds.push(json!({
            "delegator_address": address,
            "validator_address": val_address,
            "entries": entries
        }))
    }

    json!({ "unbonding_responses": unbonds, "pagination": { "next_key": null, "total": unbonds.len().to_string() } })
}

#[get("/staking/delegators/<_address>/unbonding_delegations")]
fn staking_delegators_unbonding_delegations_2(_address: &str) -> Value {
    json!({ "height": "0", "result": [] })
}

#[get("/cosmos/distribution/v1beta1/delegators/<address>/rewards")]
async fn distribution_delegators_rewards(address: &str) -> Value {
    let address: Address = address.parse().unwrap();
    let delegations: Vec<(Address, DelegationInfo)> = app_client()
        .query(|app: InnerApp| app.staking.delegations(address))
        .await
        .unwrap();

    let mut rewards = vec![];
    let mut total_nom = 0;
    let mut total_nbtc = 0;
    for (validator, delegation) in delegations {
        let mut reward = vec![];
        let liquid: u64 = delegation
            .liquid
            .iter()
            .map(|(_, amount)| -> u64 { (*amount).into() })
            .sum();
        if liquid == 0 {
            continue;
        }

        let liquid_nom: u64 = delegation
            .liquid
            .iter()
            .find(|(denom, _)| *denom == Nom::INDEX)
            .unwrap_or(&(0, 0.into()))
            .1
            .into();
        total_nom += liquid_nom;
        reward.push(json!({
            "denom": "unom",
            "amount": liquid_nom.to_string(),
        }));
        let liquid_nbtc: u64 = delegation
            .liquid
            .iter()
            .find(|(denom, _)| *denom == Nbtc::INDEX)
            .unwrap_or(&(0, 0.into()))
            .1
            .into();
        reward.push(json!({
            "denom": "usat",
            "amount": liquid_nbtc.to_string(),
        }));
        total_nbtc += liquid_nbtc;

        rewards.push(json!({
            "validator_address": validator.to_string(),
            "reward": reward,
        }));
    }
    json!({
      "rewards": rewards,
      "total": [
          {
              "denom": "unom",
              "amount": total_nom.to_string(),
          },
          {
              "denom": "usat",
              "amount": total_nbtc.to_string(),
          }
      ]
    })
}

#[get("/cosmos/distribution/v1beta1/delegators/<address>/rewards/<validator_address>")]
async fn distribution_delegators_rewards_for_validator(
    address: &str,
    validator_address: &str,
) -> Value {
    let address: Address = address.parse().unwrap();
    let validator_address: Address = validator_address.parse().unwrap();

    let delegations: Vec<(Address, DelegationInfo)> = app_client()
        .query(|app: InnerApp| app.staking.delegations(address))
        .await
        .unwrap();

    let delegation: &DelegationInfo = delegations
        .iter()
        .find(|(validator, _delegation)| *validator == validator_address)
        .map(|(_validator, delegation)| delegation)
        .unwrap();

    let mut rewards = vec![];

    let liquid_nom: u64 = delegation
        .liquid
        .iter()
        .find(|(denom, _)| *denom == Nom::INDEX)
        .unwrap_or(&(0, 0.into()))
        .1
        .into();

    rewards.push(json!({
        "denom": "unom",
        "amount": liquid_nom.to_string(),
    }));

    let liquid_nbtc: u64 = delegation
        .liquid
        .iter()
        .find(|(denom, _)| *denom == Nbtc::INDEX)
        .unwrap_or(&(0, 0.into()))
        .1
        .into();

    rewards.push(json!({
        "denom": "usat",
        "amount": liquid_nbtc.to_string(),
    }));

    json!({
      "rewards": rewards
    })
}

#[get("/cosmos/mint/v1beta1/inflation")]
async fn minting_inflation() -> Result<Value, BadRequest<String>> {
    let validators: Vec<ValidatorQueryInfo> = app_client()
        .query(|app: InnerApp| app.staking.all_validators())
        .await
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
    let validators: Vec<ValidatorQueryInfo> = app_client()
        .query(|app: InnerApp| app.staking.all_validators())
        .await
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
async fn bank_total(denom: &str) -> Result<Value, BadRequest<String>> {
    let total_balances: u64 = app_client()
        .query(|app: InnerApp| app.get_total_balances(denom))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;
    Ok(json!({ "height": "0", "result":  total_balances.to_string()}))
}

#[get("/cosmos/staking/v1beta1/pool")]
async fn staking_pool() -> Result<Value, BadRequest<String>> {
    let staked: Amount = app_client()
        .query(|app: InnerApp| app.staking.staked())
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;
    let total_balances: u64 = app_client()
        .query(|app: InnerApp| app.get_total_balances(Nom::NAME))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;
    let staked_u64: u64 = staked.into();
    let not_bonded = total_balances - staked_u64;
    Ok(json!({
        "pool": {
            "bonded_tokens": staked.to_string(),
            "not_bonded_tokens": not_bonded.to_string()
        }
    }))
}

#[get("/cosmos/staking/v1beta1/params")]
async fn staking_params() -> Result<Value, BadRequest<String>> {
    let staking: Staking<Nom> = app_client()
        .query(|app: InnerApp| Ok(app.staking))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;
    Ok(json!({
        "params": {
            "unbonding_time": staking.unbonding_seconds,
            "max_validators": staking.max_validators,
            "max_entries": 7, // FIXME: nomic does not have this value,
            "historical_entries": 1000, // FIXME: nomic does not have this value,
            "bond_denom": Nom::NAME,
        }
    }))
}

#[get("/cosmos/bank/v1beta1/supply/<denom>")]
async fn bank_supply_unom(denom: &str) -> Result<Value, BadRequest<String>> {
    let total_balances: u64 = app_client()
        .query(|app: InnerApp| app.get_total_balances(denom))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;
    Ok(json!({
        "amount": {
            "denom": denom,
            "amount": total_balances.to_string()
        }
    }))
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

#[get("/bitcoin/recovery_address/<address>?<network>")]
async fn get_bitcoin_recovery_address(
    address: String,
    network: String,
) -> Result<Value, BadRequest<String>> {
    let netw = match network.as_str() {
        "bitcoin" => bitcoin::Network::Bitcoin,
        "regtest" => bitcoin::Network::Regtest,
        "testnet" => bitcoin::Network::Testnet,
        "signet" => bitcoin::Network::Signet,
        _ => bitcoin::Network::Bitcoin,
    };
    let recovery_address: String = app_client()
        .query(|app: InnerApp| {
            Ok(
                match app
                    .bitcoin
                    .recovery_scripts
                    .get(Address::from_str(&address).unwrap())?
                {
                    Some(script) => BitcoinAddress::from_script(&script, netw)
                        .unwrap()
                        .to_string(),
                    None => "".to_string(),
                },
            )
        })
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;
    Ok(json!(recovery_address.to_string()))
}

#[get("/bitcoin/script_pubkey/<address>")]
async fn get_script_pubkey(address: String) -> Result<Value, BadRequest<String>> {
    let bitcoin_address: bitcoin::Address = address.parse().unwrap();
    let script_pubkey = bitcoin_address.script_pubkey();
    let script_pubkey_bytes = script_pubkey.as_bytes();
    let base64_script_pubkey = base64::encode(script_pubkey_bytes);
    Ok(json!(base64_script_pubkey))
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

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
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
            staking_delegators_delegations_2,
            staking_delegators_unbonding_delegations,
            staking_delegators_unbonding_delegations_2,
            distribution_delegators_rewards,
            distribution_delegators_rewards_for_validator,
            minting_inflation,
            minting_inflation_2,
            staking_pool,
            staking_pool_2,
            bank_total,
            ibc_apps_transfer_params,
            ibc_applications_transfer_params,
            bank_supply_unom,
            bitcoin_config,
            bitcoin_checkpoint_config,
            bitcoin_latest_checkpoint,
            staking_params,
            get_validators,
            get_validator,
            get_bitcoin_recovery_address,
            bitcoin_checkpoint_size,
            bitcoin_last_checkpoint_size,
            bitcoin_checkpoint_size_with_index,
            get_script_pubkey
        ],
    )
}
