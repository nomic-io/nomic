#[macro_use]
extern crate rocket;

use chrono::{TimeZone, Utc};
use nomic::{
    app::{InnerApp, Nom},
    bitcoin::Nbtc,
    orga::{
        client::{wallet::Unsigned, AppClient},
        coins::{Address, Amount, Decimal, DelegationInfo, Symbol, ValidatorQueryInfo},
        encoding::EofTerminatedString,
        tendermint::client::HttpClient,
    },
    utils::DeclareInfo,
};

use rocket::response::status::BadRequest;
use rocket::serde::json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

use ibc::clients::tendermint::types::ClientState;
use ibc::core::host::types::identifiers::ConnectionId as IbcConnectionId;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::client::v1::IdentifiedClientState;
use ibc_proto::ibc::core::connection::v1::ConnectionEnd as RawConnectionEnd;
use ibc_proto::ibc::lightclients::tendermint::v1::ClientState as RawTmClientState;

use bech32::ToBase32;
use sha2::Digest;
use tendermint_proto::types::CommitSig as RawCommitSig;
use tendermint_rpc as tm;
use tm::Client as _;

lazy_static::lazy_static! {
    static ref QUERY_CACHE: Arc<RwLock<HashMap<String, (u64, String)>>> = Arc::new(RwLock::new(HashMap::new()));
}

fn app_host() -> &'static str {
    "http://localhost:26657"
}

fn app_client() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned> {
    nomic::app_client(app_host())
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

#[get("/cosmos/staking/v1beta1/validators?<status>")]
async fn validators(status: Option<String>) -> Value {
    let all_validators: Vec<ValidatorQueryInfo> = app_client()
        .query(|app: InnerApp| app.staking.all_validators())
        .await
        .unwrap();

    let all_keys: Vec<_> = app_client()
        .query(|app: InnerApp| app.staking.consensus_keys())
        .await
        .unwrap();

    let mut validators = vec![];
    for validator in all_validators {
        let validator_status = if validator.unbonding {
            "BOND_STATUS_UNBONDING"
        } else if validator.in_active_set {
            "BOND_STATUS_BONDED"
        } else {
            "BOND_STATUS_UNBONDED"
        };

        if !status.is_none() && status != Some(validator_status.to_owned()) {
            continue;
        }

        let cons_key = all_keys
            .iter()
            .find(|entry| (**entry).0 == validator.address.into())
            .map(|entry| (*entry).1)
            .unwrap();

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
             "status": validator_status,
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
async fn validator(address: &str) -> Value {
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
    let address: Address = address.parse().unwrap();

    let nom_balance: u64 = app_client()
        .query(|app| app.accounts.balance(address))
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?
        .into();
    let nbtc_balance: u64 = app_client()
        .query(|app| app.bitcoin.accounts.balance(address))
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?
        .into();

    Ok(json!({
        "balances": [
            {
                "denom": "unom",
                "amount": nom_balance.to_string(),
            },
            {
                "denom": "usat",
                "amount": nbtc_balance.to_string(),
            }
        ],
        "pagination": {
            "next_key": null,
            "total": "2"
        }
    }))
}

#[get("/bank/balances/<address>")]
async fn bank_balances_2(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    let balance: u64 = app_client()
        .query(|app| app.accounts.balance(address))
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?
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

    let balance: u64 = app_client()
        .query(|app| app.accounts.balance(address))
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?
        .into();

    let mut nonce: u64 = app_client()
        .query_root(|app| app.inner.inner.borrow().inner.inner.inner.nonce(address))
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?;
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

    let _balance: u64 = app_client()
        .query(|app| app.accounts.balance(address))
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?
        .into();

    let mut nonce: u64 = app_client()
        .query_root(|app| app.inner.inner.borrow().inner.inner.inner.nonce(address))
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?;
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

    let client = tm::HttpClient::new(app_host()).unwrap();

    let tx_bytes = if let Some('{') = tx.chars().next() {
        let tx: TxRequest = serde_json::from_str(tx).unwrap();
        serde_json::to_vec(&tx.tx).unwrap()
    } else {
        base64::decode(tx).map_err(|e| BadRequest(format!("{:?}", e)))?
    };

    let res = client
        .broadcast_tx_commit(tx_bytes.into())
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?;

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

    let client = tm::HttpClient::new(app_host()).unwrap();

    let tx_bytes = if let Some('{') = tx.chars().next() {
        let tx: TxRequest2 = serde_json::from_str(tx).unwrap();
        base64::decode(tx.tx_bytes.as_str()).map_err(|e| BadRequest(format!("{:?}", e)))?
    } else {
        base64::decode(tx).map_err(|e| BadRequest(format!("{:?}", e)))?
    };

    let res = client
        .broadcast_tx_commit(tx_bytes.into())
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?;

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

    let client = tm::HttpClient::new(app_host()).unwrap();

    let query_bytes = hex::decode(query).map_err(|e| BadRequest(format!("{:?}", e)))?;

    let res = client
        .abci_query(None, query_bytes, height.map(Into::into), true)
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?;

    let res_height: u64 = res.height.into();
    let res_height: u32 = res_height.try_into().unwrap();

    if let tendermint::abci::Code::Err(code) = res.code {
        let msg = format!("code {}: {}", code, res.log);
        return Err(BadRequest(msg));
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

    let delegations = app_client()
        .query(|app| app.staking.delegations(address))
        .await
        .unwrap();

    let mut entries = vec![];

    for (validator_address, delegation) in delegations {
        if delegation.staked == 0 {
            continue;
        }

        entries.push(json!({
            "delegation": {
                "delegator_address": address.to_string(),
                "validator_address": validator_address.to_string(),
                "shares": delegation.staked.to_string(),
            },
            "balance": {
                "denom": "unom",
                "amount": delegation.staked.to_string(),
            },
        }))
    }

    json!({
        "delegation_responses": entries,
        "pagination": { "next_key": null, "total": entries.len().to_string() }
    })
}

#[get("/staking/delegators/<address>/delegations")]
async fn staking_delegators_delegations_2(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    let delegations = app_client()
        .query(|app| app.staking.delegations(address))
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?;

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
async fn staking_delegators_unbonding_delegations(address: &str) -> Value {
    use chrono::{TimeZone, Utc};
    let address: Address = address.parse().unwrap();
    let delegations: Vec<(Address, DelegationInfo)> = app_client()
        .query(|app: InnerApp| app.staking.delegations(address))
        .await
        .unwrap();

    let mut unbonds = vec![];

    for (val_address, delegation) in delegations {
        if delegation.unbonding.len() == 0 {
            continue;
        }

        let mut entries = vec![];
        for unbond in delegation.unbonding {
            let t = Utc.timestamp_opt(unbond.start_seconds, 0).unwrap();
            entries.push(json!({
                "creation_height": "0", // TODO
                "completion_time": t, // TODO
                "initial_balance": unbond.amount.to_string(),
                "balance": unbond.amount.to_string()
            }))
        }
        unbonds.push(json!({
            "delegator_address": address,
            "validator_address": val_address,
            "entries": entries
        }))
    }

    json!({
        "unbonding_responses": unbonds,
        "pagination": { "next_key": null, "total": unbonds.len().to_string() }
    })
}

#[get("/staking/delegators/<_address>/unbonding_delegations")]
fn staking_delegators_unbonding_delegations_2(_address: &str) -> Value {
    json!({ "height": "0", "result": [] })
}

#[get("/cosmos/staking/v1beta1/validators/<address>/delegations")]
async fn staking_validators_delegations(address: &str) -> Value {
    let validator_address: Address = address.parse().unwrap();
    let delegations: Vec<(Address, DelegationInfo)> = app_client()
        .query(|app: InnerApp| app.staking.validator_delegations(validator_address))
        .await
        .unwrap();

    let mut entries = vec![];

    for (delegator_address, delegation) in delegations {
        if delegation.staked == 0 {
            continue;
        }

        entries.push(json!({
            "delegation": {
                "delegator_address": delegator_address.to_string(),
                "validator_address": validator_address.to_string(),
                "shares": delegation.staked.to_string(),
            },
            "balance": {
                "denom": "unom",
                "amount": delegation.staked.to_string(),
            },
        }))
    }

    json!({
        "delegation_responses": entries,
        "pagination": { "next_key": null, "total": entries.len().to_string() }
    })
}

#[get("/cosmos/staking/v1beta1/validators/<validator_address>/delegations/<delegator_address>")]
async fn staking_validator_single_delegation(
    validator_address: &str,
    delegator_address: &str,
) -> Value {
    let delegator_address: Address = delegator_address.parse().unwrap();
    let validator_address: Address = validator_address.parse().unwrap();

    let delegations: Vec<(Address, DelegationInfo)> = app_client()
        .query(|app: InnerApp| app.staking.delegations(delegator_address))
        .await
        .unwrap();

    let delegation: &DelegationInfo = delegations
        .iter()
        .find(|(validator, _delegation)| *validator == validator_address)
        .map(|(_validator, delegation)| delegation)
        .unwrap();

    json!({
        "delegation_response": {
            "delegation": {
                "delegator_address": delegator_address,
                "validator_address": validator_address,
                "shares": delegation.staked.to_string(),
            },
            "balance": {
                "denom": "unom",
                "amount": delegation.staked.to_string(),
            }
          }
    })
}

#[get("/cosmos/staking/v1beta1/validators/<address>/unbonding_delegations")]
async fn staking_validators_unbonding_delegations(address: &str) -> Value {
    let validator_address: Address = address.parse().unwrap();
    let delegations: Vec<(Address, DelegationInfo)> = app_client()
        .query(|app: InnerApp| app.staking.validator_delegations(validator_address))
        .await
        .unwrap();

    let mut unbonds = vec![];

    for (delegator_address, delegation) in delegations {
        if delegation.unbonding.len() == 0 {
            continue;
        }

        let mut entries = vec![];
        for unbond in delegation.unbonding {
            let t = Utc.timestamp_opt(unbond.start_seconds, 0).unwrap();
            entries.push(json!({
                "creation_height": "0", // TODO
                "completion_time": t, // TODO
                "initial_balance": unbond.amount.to_string(),
                "balance": unbond.amount.to_string()
            }))
        }
        unbonds.push(json!({
            "delegator_address": delegator_address,
            "validator_address": validator_address,
            "entries": entries
        }))
    }

    json!({
        "unbonding_responses": unbonds,
        "pagination": { "next_key": null, "total": unbonds.len().to_string()
    } })
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
    let validators = app_client()
        .query(|app| app.staking.all_validators())
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?;

    let total_staked: u64 = validators
        .iter()
        .map(|v| -> u64 { v.amount_staked.into() })
        .sum();
    let total_staked = Amount::from(total_staked + 1);
    let yearly_inflation = Decimal::from(64_682_541_340_000);
    let apr = (yearly_inflation / Decimal::from(4) / Decimal::from(total_staked))
        .result()
        .map_err(|e| BadRequest(format!("{:?}", e)))?;

    Ok(json!({ "inflation": apr.to_string() }))
}

#[get("/minting/inflation")]
async fn minting_inflation_2() -> Result<Value, BadRequest<String>> {
    let validators = app_client()
        .query(|app| app.staking.all_validators())
        .await
        .map_err(|e| BadRequest(format!("{:?}", e)))?;

    let total_staked: u64 = validators
        .iter()
        .map(|v| -> u64 { v.amount_staked.into() })
        .sum();
    let total_staked = Amount::from(total_staked + 1);
    let yearly_inflation = Decimal::from(64_682_541_340_000);
    let apr = (yearly_inflation / Decimal::from(4) / Decimal::from(total_staked))
        .result()
        .map_err(|e| BadRequest(format!("{:?}", e)))?;

    Ok(json!({ "height": "0", "result": apr.to_string() }))
}

#[get("/bank/total/<denom>")]
fn bank_total(denom: &str) -> Value {
    json!({ "height": "0", "result": "0" })
}

#[get("/cosmos/staking/v1beta1/pool")]
async fn staking_pool() -> Value {
    let validators = app_client()
        .query(|app| app.staking.all_validators())
        .await
        .unwrap();

    let total_bonded: u64 = validators
        .iter()
        .filter(|v| v.in_active_set)
        .map(|v| -> u64 { v.amount_staked.into() })
        .sum();

    let total_not_bonded: u64 = validators
        .iter()
        .filter(|v| !v.in_active_set)
        .map(|v| -> u64 { v.amount_staked.into() })
        .sum();

    json!({
        "pool": {
            "bonded_tokens": total_bonded.to_string(),
            "not_bonded_tokens": total_not_bonded.to_string()
        }
    })
}

#[get("/cosmos/bank/v1beta1/supply/unom")]
async fn bank_supply_unom() -> Value {
    let supply = app_client().query(|app| app.total_supply()).await.unwrap();

    json!({
        "amount": {
            "denom": "unom",
            "amount": supply.to_string(),
        }
    })
}

#[get("/cosmos/bank/v1beta1/supply")]
async fn bank_supply() -> Value {
    let supply = app_client().query(|app| app.total_supply()).await.unwrap();

    json!({
        "supply": [
            {
                "denom": "unom",
                "amount": supply.to_string()
            }
        ],
        "pagination": {
            "next_key": null,
            "total": "1",
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

#[get("/cosmos/staking/v1beta1/params")]
async fn staking_params() -> Value {
    let (unbonding_seconds, max_validators) = app_client()
        .query(|app| Ok((app.staking.unbonding_seconds, app.staking.max_validators)))
        .await
        .unwrap();

    json!({
        "params": {
            "unbonding_time": unbonding_seconds.to_string() + "s",
            "max_validators": max_validators,
            "max_entries": 7,
            "historical_entries": 10000,
            "bond_denom": "unom"
        }
    })
}

#[get("/cosmos/slashing/v1beta1/params")]
async fn slashing_params() -> Value {
    let (
        max_offline_blocks,
        slash_fraction_double_sign,
        slash_fraction_downtime,
        downtime_jail_seconds,
    ) = app_client()
        .query(|app| {
            Ok((
                app.staking.max_offline_blocks,
                app.staking.slash_fraction_double_sign,
                app.staking.slash_fraction_downtime,
                app.staking.downtime_jail_seconds,
            ))
        })
        .await
        .unwrap();

    json!({
        "params": {
            "signed_blocks_window": max_offline_blocks.to_string(),
            "min_signed_per_window": "0.0",
            "downtime_jail_duration": downtime_jail_seconds.to_string() + "s",
            "slash_fraction_double_sign": slash_fraction_double_sign.to_string(),
            "slash_fraction_downtime": slash_fraction_downtime.to_string()
        }
    })
}

async fn get_signing_infos() -> Vec<Value> {
    let client = tm::HttpClient::new(app_host()).unwrap();

    let all_validators: Vec<ValidatorQueryInfo> = app_client()
        .query(|app: InnerApp| app.staking.all_validators())
        .await
        .unwrap();

    let all_keys: Vec<_> = app_client()
        .query(|app: InnerApp| app.staking.consensus_keys())
        .await
        .unwrap();

    let last_signed_blocks = app_client()
        .query(|app: InnerApp| app.staking.last_signed_blocks())
        .await
        .unwrap();

    let latest_block_response = client.latest_block().await.unwrap();
    let latest_block: u64 = latest_block_response.block.header.height.value();

    let mut signing_infos = vec![];

    for validator in all_validators {
        let cons_key = all_keys
            .iter()
            .find(|entry| (**entry).0 == validator.address.into())
            .map(|entry| (*entry).1)
            .unwrap();

        let mut hasher = sha2::Sha256::new();
        hasher.update(cons_key);
        let hash = hasher.finalize().to_vec()[..20].to_vec();

        let address = bech32::encode(
            "nomicvalcons",
            hash.to_vec().to_base32(),
            bech32::Variant::Bech32,
        )
        .unwrap();

        let last_signed_block: u64 = last_signed_blocks
            .iter()
            .find(|entry| (**entry).0 == validator.address.into())
            .map(|entry| (*entry).1)
            .unwrap()
            .unwrap_or(latest_block);

        let skipped_blocks: u64 = latest_block - last_signed_block;

        signing_infos.push(json!({
            "address": address,
            "start_height": "0", // TODO: fix,
            "index_offset": "0", // TODO: fix,
            "jailed_until": Utc.timestamp_opt(validator.jailed_until.unwrap_or(0), 0)
                .unwrap()
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
            "tombstoned": validator.tombstoned,
            "missed_blocks_counter": skipped_blocks.to_string(),
        }))
    }

    signing_infos
}

#[get("/cosmos/slashing/v1beta1/signing_infos")]
async fn signing_infos() -> Value {
    let signing_infos: Vec<_> = get_signing_infos().await;

    json!({
        "info": signing_infos,
        "pagination": {
            "next_key": null,
            "total": signing_infos.len().to_string(),
        }
    })
}

#[get("/cosmos/slashing/v1beta1/signing_infos/<cons_addr>")]
async fn signing_info(cons_addr: &str) -> Value {
    let signing_infos: Vec<_> = get_signing_infos().await;

    let signing_info = signing_infos
        .iter()
        .find(|value| (**value).get("address").unwrap() == cons_addr)
        .unwrap();

    json!({
        "val_signing_info": signing_info
    })
}

fn parse_block(res: tendermint_rpc::endpoint::block::Response) -> Value {
    let last_commit = res.block.last_commit.unwrap();
    let signatures: Vec<_> = last_commit
        .signatures
        .iter()
        .map(|signature| -> Value {
            let signature_raw = RawCommitSig::from(signature.clone());

            json!({
                "validator_address": base64::encode(signature_raw.validator_address),
                "block_id_flag": match signature_raw.block_id_flag {
                    1 => "BLOCK_ID_FLAG_ABSENT",
                    2 => "BLOCK_ID_FLAG_COMMIT",
                    3 => "BLOCK_ID_FLAG_NIL",
                    i32::MIN..=0_i32 | 4_i32..=i32::MAX => "BLOCK_ID_FLAG_UNKNOWN"
                },
                "timestamp": signature_raw.timestamp,
                "signature": base64::encode(signature_raw.signature),
            })
        })
        .collect();

    json!({
        "block_id": res.block_id,
        "block": {
            "header": {
                "version": {
                    "block": res.block.header.version.block,
                    "app": res.block.header.version.block,
                },
                "chain_id": res.block.header.chain_id,
                "height": res.block.header.height,
                "time": res.block.header.time,
                "last_block_id": res.block.header.last_block_id,
                "last_commit_hash": res.block.header.last_commit_hash.map(|hash| base64::encode(hash.as_bytes())),
                "data_hash": res.block.header.data_hash.map(|hash| base64::encode(hash.as_bytes())),
                "validators_hash": base64::encode(res.block.header.validators_hash.as_bytes()),
                "next_validators_hash": base64::encode(res.block.header.next_validators_hash.as_bytes()),
                "consensus_hash": base64::encode(res.block.header.consensus_hash.as_bytes()),
                "app_hash": base64::encode(res.block.header.app_hash.value()),
                "last_results_hash": res.block.header.last_results_hash.map(|hash| base64::encode(hash.as_bytes())),
                "evidence_hash": res.block.header.evidence_hash.map(|hash| base64::encode(hash.as_bytes())),
                "proposer_address": base64::encode(res.block.header.proposer_address),
            },
            "data": res.block.data,
            "evidence": res.block.evidence,
            "last_commit": {
                "block_id": last_commit.block_id,
                "signatures": signatures
            }
        }
    })
}

#[get("/cosmos/base/tendermint/v1beta1/blocks/latest")]
async fn latest_block() -> Value {
    let client = tm::HttpClient::new(app_host()).unwrap();

    let res = client.latest_block().await.unwrap();
    parse_block(res)
}

#[get("/cosmos/base/tendermint/v1beta1/blocks/<height>")]
async fn block(height: u32) -> Value {
    let client = tm::HttpClient::new(app_host()).unwrap();

    let res = client
        .block(tendermint::block::Height::from(height))
        .await
        .unwrap();

    parse_block(res)
}

fn parse_validator_set(res: tendermint_rpc::endpoint::validators::Response) -> Value {
    let validators: Vec<_> = res
        .validators
        .iter()
        .map(|validator| -> Value {
            json!({
                "address": validator.address,
                "voting_power": i64::from(validator.power).to_string(),
                "proposer_priority": i64::from(validator.proposer_priority).to_string(),
                "pub_key": {
                    "@type": "/cosmos.crypto.ed25519.PubKey",
                    "key": base64::encode(validator.pub_key.ed25519().unwrap().to_bytes()),
                }
            })
        })
        .collect();

    json!({
        "block_height": res.block_height,
        "validators": validators,
        "pagination": {
            "next_key": null,
            "total": res.validators.len(),
        }
    })
}

#[get("/cosmos/base/tendermint/v1beta1/validatorsets/latest")]
async fn latest_validator_set() -> Value {
    let client = tm::HttpClient::new(app_host()).unwrap();

    let block = client.latest_block().await.unwrap();

    let res = client
        .validators(block.block.header.height, tendermint_rpc::Paging::All)
        .await
        .unwrap();

    parse_validator_set(res)
}

#[get("/cosmos/base/tendermint/v1beta1/validatorsets/<height>")]
async fn validator_set(height: u32) -> Value {
    let client = tm::HttpClient::new(app_host()).unwrap();

    let res = client
        .validators(height, tendermint_rpc::Paging::All)
        .await
        .unwrap();

    parse_validator_set(res)
}

#[get("/cosmos/distribution/v1beta1/community_pool")]
async fn community_pool() -> Value {
    let community_pool = app_client()
        .query(|app| Ok(app.community_pool.amount))
        .await
        .unwrap();

    json!({
        "pool": [
            {
                "denom": "unom",
                "amount": community_pool.to_string()
            }
        ]
    })
}

#[get("/cosmos/gov/v1beta1/proposals")]
fn proposals() -> Value {
    json!({
        "proposals": [],
        "pagination": {
            "next_key": null,
            "total": 0
        }
    })
}

#[get("/ibc/core/connection/v1/connections/<connection>/client_state")]
#[allow(deprecated)]
async fn ibc_connection_client_state(connection: &str) -> Value {
    let connection = app_client()
        .query(|app| {
            app.ibc.ctx.query_connection(EofTerminatedString(
                IbcConnectionId::from_str(connection).unwrap(),
            ))
        })
        .await
        .unwrap()
        .unwrap();

    let states: Vec<IdentifiedClientState> = app_client()
        .query(|app| app.ibc.ctx.query_client_states())
        .await
        .unwrap();

    let state: &IdentifiedClientState = states
        .iter()
        .find(|state| state.client_id == connection.client_id().to_string())
        .unwrap();

    let state_as_any: Any = state.client_state.clone().unwrap();

    let client_state_tmp: ClientState = ClientState::try_from(state_as_any).unwrap().to_owned();
    let client_state = client_state_tmp.clone();
    let raw_client_state: RawTmClientState = RawTmClientState::from(client_state_tmp);

    let proof_specs: Vec<_> = raw_client_state
        .proof_specs
        .iter()
        .map(|spec| {
            json!({
                "inner_spec": spec.inner_spec.clone().map(|inner_spec| json!({
                    "child_order": inner_spec.child_order,
                    "child_size": inner_spec.child_size,
                    "min_prefix_length": inner_spec.child_size,
                    "max_prefix_length": inner_spec.max_prefix_length,
                    "empty_child": inner_spec.empty_child,
                    "hash": inner_spec.hash
                })),
                "leaf_spec": spec.leaf_spec,
            })
        })
        .collect();

    json!({
        "identified_client_state": {
            "client_id": state.client_id,
            "client_state": {
                "@type": "/ibc.lightclients.tendermint.v1.ClientState",
                "chain_id": raw_client_state.chain_id,
                "trust_level": client_state.trust_level,
                "trusting_period": raw_client_state.trusting_period.map(|v| format!("{}s", v.seconds)),
                "unbonding_period": format!("{}s", client_state.unbonding_period.as_secs()),
                "max_clock_drift": raw_client_state.max_clock_drift.map(|v| format!("{}s", v.seconds)),
                "frozen_height": raw_client_state.frozen_height.map(|h| json!({
                    "revision_height": h.revision_height.to_string(),
                    "revision_number": h.revision_number.to_string(),
                })),
                "latest_height": raw_client_state.latest_height.map(|h| json!({
                    "revision_height": h.revision_height.to_string(),
                    "revision_number": h.revision_number.to_string(),
                })),
                "proof_specs": proof_specs,
                "upgrade_path": client_state.upgrade_path,
                "allow_update_after_expiry": raw_client_state.allow_update_after_expiry,
                "allow_update_after_misbehaviour": raw_client_state.allow_update_after_misbehaviour,
            }
        },
        "proof": null,
        "proof_height": {
            "revision_number": "0",
            "revision_height": "0"
        }
    })
}

#[get("/ibc/core/channel/v1/connections/<connection>/channels")]
async fn ibc_connection_channels(connection: &str) -> Value {
    let channels = app_client()
        .query(|app| {
            app.ibc.ctx.query_connection_channels(EofTerminatedString(
                IbcConnectionId::from_str(connection).unwrap(),
            ))
        })
        .await
        .unwrap();

    let json_channels: Vec<_> = channels
        .iter()
        .map(|channel| {
            json!({
                "state": match channel.state {
                    0 => "STATE_UNINITIALIZED_UNSPECIFIED",
                    1 => "STATE_INIT",
                    2 => "STATE_TRYOPEN",
                    3 => "STATE_OPEN",
                    i32::MIN..=-1_i32 | 4_i32..=i32::MAX => "STATE_UNINITIALIZED_UNSPECIFIED"
                },
                "ordering": match channel.ordering {
                    0 => "ORDER_NONE_UNSPECIFIED",
                    1 => "ORDER_UNORDERED",
                    2 => "ORDER_ORDERED",
                    i32::MIN..=-1_i32 | 3_i32..=i32::MAX => "ORDER_NONE_UNSPECIFIED"
                },
                "counterparty": channel.counterparty,
                "connection_hops": channel.connection_hops,
                "version": channel.version,
                "port_id": channel.port_id,
                "channel_id": channel.channel_id,
            })
        })
        .collect();

    json!({
        "channels": json_channels,
        "proof_height": {
            "revision_number": "0",
            "revision_height": "0"
        },
    })
}

#[get("/ibc/core/connection/v1/connections/<connection>")]
async fn ibc_connection(connection: &str) -> Value {
    let connection = app_client()
        .query(|app| {
            app.ibc.ctx.query_connection(EofTerminatedString(
                IbcConnectionId::from_str(connection).unwrap(),
            ))
        })
        .await
        .unwrap()
        .unwrap();

    let raw_connection = RawConnectionEnd::from(connection);

    json!({
        "connection": {
            "client_id": raw_connection.client_id,
            "versions": raw_connection.versions,
            "state": match raw_connection.state {
                0 => "STATE_UNINITIALIZED_UNSPECIFIED",
                1 => "STATE_INIT",
                2 => "STATE_TRYOPEN",
                3 => "STATE_OPEN",
                i32::MIN..=-1_i32 | 4_i32..=i32::MAX => "STATE_UNINITIALIZED_UNSPECIFIED"
            },
            "counterparty": raw_connection.counterparty,
            "delay_period": raw_connection.delay_period,
        },
        "proof_height": {
            "revision_number": "0",
            "revision_height": "0"
        },
    })
}

#[get("/ibc/core/connection/v1/connections")]
async fn ibc_connections() -> Value {
    let connections = app_client()
        .query(|app| app.ibc.ctx.query_all_connections())
        .await
        .unwrap();

    json!({
        "connections": connections,
        "pagination": {
            "next_key": null,
            "total": connections.len().to_string()
          },
        "proof_height": {
            "revision_number": "0",
            "revision_height": "0"
        },
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
            staking_validators_delegations,
            staking_validators_unbonding_delegations,
            staking_validator_single_delegation,
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
            bank_supply,
            validators,
            validator,
            staking_params,
            slashing_params,
            signing_infos,
            signing_info,
            latest_block,
            block,
            latest_validator_set,
            validator_set,
            community_pool,
            proposals,
            ibc_connection,
            ibc_connections,
            ibc_connection_client_state,
            ibc_connection_channels,
        ],
    )
}
