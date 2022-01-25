#[macro_use]
extern crate rocket;

use rocket::serde::json::{json, Value};
use rocket::response::status::BadRequest;
use nomic::{app_client, app::{Nom, InnerApp}, orga::{query::Query, coins::{Accounts, Address, Staking}}};

use tendermint_rpc as tm;
use tm::Client as _;

#[get("/bank/balances/<address>")]
async fn bank_balances(address: &str) -> Result<Value, BadRequest<String>> {
    let address: Address = address.parse().unwrap();

    type AppQuery = <InnerApp as Query>::Query;
    type AcctQuery = <Accounts<Nom> as Query>::Query;

    let q = AppQuery::FieldAccounts(AcctQuery::MethodBalance(address, vec![]));
    let balance: u64 = app_client()
        .query(q, |state| state.accounts.balance(address))
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?
        .into();

    let balance = balance.to_string();

    Ok(json!({
        "height": "1044580",
        "result": [
            {
                "denom": "unom",
                "amount": balance,
            }
        ]
    }))
}

#[get("/auth/accounts/<address>")]
fn auth_accounts(address: &str) -> Value {
    json!({
        "height": "1044580",
        "result": {
            "type": "cosmos-sdk/BaseAccount",
            "value": {
                "account_number": "1234",
                // "address": "string",
                "coins": [
                    {
                        "denom": "unom",
                        "amount": "1234567890"
                    },
                    {
                        "denom": "unbtc",
                        "amount": "12345678"
                    }
                ],
                "public_key": {
                    "type": "tendermint/PubKeyEd25519",
                    "value": "7abai/qElNAJRqaOTlxZ8ZOX5mOW0rmSzKWt0igCyg0="
                },
                "sequence": "123"
            }
        }
    })
}

#[post("/txs", data = "<tx>")]
async fn txs(tx: &str) -> Result<Value, BadRequest<String>> {
    dbg!(tx);

    let client = tm::HttpClient::new("http://localhost:26657").unwrap();

    let tx_bytes = base64::decode(tx)
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;
    
    let res = client.broadcast_tx_commit(tx_bytes.into())
        .await
        .map_err(|e| BadRequest(Some(format!("{:?}", e))))?;

    Ok(json!(res))
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
fn staking_delegators_delegations(address: &str) -> Value {
    json!({ "height": "1044580", "result": [] })
}

#[get("/staking/delegators/<address>/unbonding_delegations")]
fn staking_delegators_unbonding_delegations(address: &str) -> Value {
    json!({ "height": "1044580", "result": [] })
}

#[get("/distribution/delegators/<address>/rewards")]
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

    json!({ "height": "1044580", "result": {
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

#[get("/minting/inflation")]
fn minting_inflation() -> Value {
    json!({ "height": "1044580", "result": "1" })
}

#[get("/bank/total/<denom>")]
fn bank_total(denom: &str) -> Value {
    json!({ "height": "1044580", "result": "100" })
}

#[get("/staking/pool")]
fn staking_pool() -> Value {
    json!({ "height": "1044580", "result": {
        "loose_tokens": "1",
        "bonded_tokens": "20",
        "inflation_last_time": "3",
        "inflation": "0.1",
        "date_last_commission_reset": "0",
        "prev_bonded_shares": "6"
      } })
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
        auth_accounts,
        txs,
        query,
        staking_delegators_delegations,
        staking_delegators_unbonding_delegations,
        distribution_delegatrs_rewards,
        minting_inflation,
        staking_pool, 
        bank_total,
    ])
}
