#[macro_use]
extern crate rocket;

use rocket::serde::json::{json, Value};
use rocket::response::status::BadRequest;
use nomic::{app_client, app::{Nom, InnerApp, CHAIN_ID}, orga::{query::Query, coins::{Amount, Accounts, Address, Staking, Decimal}, plugins::*}};

use tendermint_rpc as tm;
use tm::Client as _;

#[derive(Debug, Serialize, Deserialize)]
struct DeclareInfo {
    moniker: String,
    website: String,
    identity: String,
    details: String,
}

#[get("/cosmos/bank/v1beta1/balances/<address>")]
async fn bank_balances(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    let balance: u64 = app_client().accounts.balance(address)
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();

    let btcbalance: u64 = app_client().bitcoin.accounts.balance(address)
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
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
                "amount": btcbalance.to_string(),
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

    let balance: u64 = app_client().accounts.balance(address)
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
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

    let balance: u64 = app_client().accounts.balance(address)
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();

    type NonceQuery = <NoncePlugin<PayablePlugin<FeePlugin<Nom, InnerApp>>> as Query>::Query;
    let mut nonce: u64 = app_client().query(
            NonceQuery::Nonce(address),
            |state| state.nonce(address),
        )
        .await
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

use serde::{Serialize, Deserialize};
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
        base64::decode(tx)
            .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
    };
    
    let res = client.broadcast_tx_commit(tx_bytes.into())
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
        base64::decode(tx.tx_bytes.as_str())
            .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
    } else {
        base64::decode(tx)
            .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
    };
    
    let res = client.broadcast_tx_commit(tx_bytes.into())
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

#[get("/query/<query>")]
async fn query(query: &str) -> Result<String, BadRequest<String>> {
    dbg!(query);

    let client = tm::HttpClient::new("http://localhost:26657").unwrap();

    let query_bytes = hex::decode(query)
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let res = client
        .abci_query(None, query_bytes, None, true)
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    if let tendermint::abci::Code::Err(code) = res.code {
        let msg = format!("code {}: {}", code, res.log);
        return Err(BadRequest(Some(msg)));
    }

    Ok(base64::encode(res.value))
}

#[get("/staking/delegators/<address>/delegations")]
async fn staking_delegators_delegations_2(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    let delegations = app_client().staking.delegations(address)
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let total_staked: u64 = delegations.iter().map(|(_, d)| -> u64 { d.staked.into() }).sum();

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
    let validators = app_client().staking.all_validators()
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let total_staked: u64 = validators.iter().map(|v| -> u64 { v.amount_staked.into() }).sum();
    let total_staked = Amount::from(total_staked + 1);
    let yearly_inflation = Decimal::from(64_682_541_340_000);
    let apr = (yearly_inflation / Decimal::from(4) / Decimal::from(total_staked))
        .result()
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    Ok(json!({ "inflation": apr.to_string() }))
}

#[get("/minting/inflation")]
async fn minting_inflation_2() -> Result<Value, BadRequest<String>> {
    let validators = app_client().staking.all_validators()
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let total_staked: u64 = validators.iter().map(|v| -> u64 { v.amount_staked.into() }).sum();
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

#[get("/cosmos/staking/v1beta1/delegations/<address>")]
async fn staking_delegators_delegations(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    let delegations = app_client().staking.delegations(address)
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let total_staked: u64 = delegations.iter().map(|(_, d)| -> u64 { d.staked.into() }).sum();
    
    let mut valarray = Vec::new();

    for (validator, delegation) in delegations {
        let staked = delegation.staked;
        let liquid: u64 = delegation
            .liquid
            .iter()
            .map(|(_, amount)| -> u64 { (*amount).into() })
            .sum();
        if staked == 0 && liquid == 0 {
            continue;
        }

        use nomic::app::Nom;
        use nomic::bitcoin::Nbtc;
        use nomic::orga::coins::Symbol;
        
        let liquid_nom = delegation
            .liquid
            .iter()
            .find(|(denom, _)| *denom == Nom::INDEX)
            .unwrap()
            .1;
        let liquid_nbtc = delegation
            .liquid
            .iter()
            .find(|(denom, _)| *denom == Nbtc::INDEX)
            .unwrap_or(&(0, 0.into()))
            .1;

            let valaddr = validator.to_string();
            let staked = staked.to_string();
            
            let mut owned_string: String = "validator:".to_owned();
            let borrowed_string: &str = &validator.to_string();
            
            owned_string.push_str(borrowed_string);


            let full_name = "John Doe";
            let age_last_year = 42;
            let  ranphone = 23456;
            
            let data = json!({
                "_delegation": {
                    "_delegator_address": &address.to_string(),
                    "_validator_address": &validator.to_string(),
                    "shares": staked.to_string()
                },
                "balance": {
                    "_denom": "unom",
                    "amount": staked.to_string()
                }
            });

            valarray.push(data); 
    }
    Ok(json!({ "_delegation_responses": &valarray, "total_staked": total_staked.to_string(), "pagination": {"next_key": null, "total": "0"} }))

}

#[get("/cosmos/staking/v1beta1/validators")]
async fn staking_validators() -> Result<Value, BadRequest<String>> {
    let validators = app_client().staking.all_validators()
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let mut fullarray = Vec::new();

    for validator in validators {
        let info: DeclareInfo =
            serde_json::from_slice(validator.info.bytes.as_slice()).unwrap();
            
            let data = json!({
                "active": validator.in_active_set.to_string(),
                "operator_address": validator.address.to_string(),
                "tokens": validator.amount_staked.to_string(),                
                "jailed": validator.jailed.to_string(),                               
                "min_self_delegation": validator.min_self_delegation.to_string(),
                "description": {
                    "moniker": info.moniker.to_string(),
                    "identity": info.identity.to_string(),
                    "website": info.website.to_string(),
                    "details": info.details.to_string(),
                },
                "commission": {
                    "commission_rates": {
                        "rate": validator.commission.rate.to_string(),
                        "max_rate": validator.commission.max.to_string(),
                        "max_change_rate": validator.commission.max_change.to_string()
                    }
                },
                "unbonding": validator.unbonding.to_string(),
                "unbonding_time": validator.unbonding_start_seconds.to_string(),
                "tombstoned": validator.tombstoned.to_string()                
            });

            serde_json::to_string_pretty(&fullarray.push(data));

    }

    Ok(json!({ "validators": fullarray }))
}

#[get("/staking/validators")]
async fn staking_validators2() -> Result<Value, BadRequest<String>> {
    let validators = app_client().staking.all_validators()
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    let mut fullarray = Vec::new();

    for validator in validators {
        let info: DeclareInfo =
            serde_json::from_slice(validator.info.bytes.as_slice()).unwrap();
            
            let data = json!({
                "operator_address": validator.address.to_string(),                
                "tokens": validator.amount_staked.to_string(),                
                "jailed": validator.jailed.to_string(),                               
                "min_self_delegation": validator.min_self_delegation.to_string(),
                "description": {
                    "moniker": info.moniker.to_string(),
                    "identity": info.identity.to_string(),
                    "website": info.website.to_string(),
                    "details": info.details.to_string(),
                },
                "commission": {
                    "commission_rates": {
                        "rate": validator.commission.rate.to_string(),
                        "max_rate": validator.commission.max.to_string(),
                        "max_change_rate": validator.commission.max_change.to_string()
                    }
                },
                "unbonding": validator.unbonding.to_string(),
                "unbonding_time": validator.unbonding_start_seconds.to_string(),
                "tombstoned": validator.tombstoned.to_string()
                
            });

            serde_json::to_string_pretty(&fullarray.push(data));

    }

    Ok(json!({ "validators": fullarray }))
}

use rocket::http::Header;
use rocket::{Request, Response};
use rocket::fairing::{Fairing, Info, Kind};

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET, PATCH, OPTIONS"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().attach(CORS).mount("/", routes![
        bank_balances,
        bank_balances_2,
        auth_accounts,
        txs,
        txs2,
        query,        
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
        staking_delegators_delegations,
        staking_validators,
        staking_validators2,
    ])
}