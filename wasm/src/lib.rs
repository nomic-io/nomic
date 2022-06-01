#![feature(async_closure)]
#![feature(generic_associated_types)]

use wasm_bindgen::prelude::*;
use nomic::app::{App, InnerApp, Nom, Airdrop, CHAIN_ID};
use nomic::orga::prelude::*;
use nomic::orga::client::AsyncQuery;
use nomic::orga::merk::ABCIPrefixedProofStore;
use nomic::bitcoin::signatory::SignatorySet;
use std::ops::{Deref, DerefMut};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};
use std::convert::TryInto;
use js_sys::{Array, JsString};
use std::sync::{Arc, Mutex};

const REST_PORT: u64 = 8443;

#[wasm_bindgen(start)]
pub fn main() -> std::result::Result<(), JsValue> {
    console_error_panic_hook::set_once();
    Ok(())
}

#[wasm_bindgen]
pub async fn transfer(to_addr: String, amount: u64) -> JsValue {
    let mut client: WebClient<App> = WebClient::new();
    client
        .pay_from(async move |mut client| {
            client.accounts.take_as_funding(MIN_FEE.into()).await
        })
        .accounts
        .transfer(
            to_addr.parse().unwrap(),
            amount.into(),
        )
        .await
        .unwrap();
    client.last_res()
}

#[wasm_bindgen]
pub async fn balance(addr: String) -> u64 {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().unwrap();

    client.accounts.balance(address)
        .await
        .unwrap()
        .unwrap()
        .into()
}

#[wasm_bindgen(js_name = rewardBalance)]
pub async fn reward_balance(addr: String) -> u64 {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().unwrap();

    let delegations = client.staking.delegations(address)
        .await
        .unwrap()
        .unwrap();

    delegations
        .iter()
        .map(|(_, d)| -> u64 { d.liquid.into() })
        .sum::<u64>()
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
    pub liquid: u64,
    pub unbonding: Vec<JsValue>,
}

#[wasm_bindgen]
pub async fn delegations(addr: String) -> Array {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().unwrap();

    let delegations = client.staking.delegations(address)
        .await
        .unwrap()
        .unwrap();

    delegations
        .iter()
        .map(|(address, delegation)| Delegation {
            address: address.to_string(),
            staked: delegation.staked.into(),
            liquid: delegation.liquid.into(),
            unbonding: delegation.unbonding.iter().map(|u| UnbondInfo {
                start_seconds: u.start_seconds as u64,
                amount: u.amount.into(),
            }).map(JsValue::from).collect(),
        })
        .map(JsValue::from)
        .collect()
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

#[wasm_bindgen(js_name = allValidators)]
pub async fn all_validators() -> Array {
    let mut client: WebClient<App> = WebClient::new();

    let validators = client.staking.all_validators()
        .await
        .unwrap()
        .unwrap();

    validators
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
        .collect()
}

use nomic::orga::plugins::sdk_compat::sdk;

async fn send_sdk_tx(msg: sdk::Msg) -> JsValue {
    let my_addr = get_address().await;

    let mut client: WebClient<App> = WebClient::new();
    let nonce = client.nonce(my_addr.parse().unwrap()).await.unwrap();

    client.send_sdk_tx(sdk::SignDoc {
        account_number: "0".to_string(),
        chain_id: CHAIN_ID.to_string(),
        fee: sdk::Fee {
            amount: vec![ sdk::Coin { amount: "0".to_string(), denom: "unom".to_string() } ],
            gas: MIN_FEE.to_string(),
        },
        memo: "".to_string(),
        msgs: vec![ msg ],
        sequence: (nonce + 1).to_string(),
    }).await.unwrap();

    client.last_res()
}

#[wasm_bindgen]
pub async fn claim() -> JsValue {
    send_sdk_tx(sdk::Msg {
        type_: "nomic/MsgClaimRewards".to_string(),
        value: serde_json::Map::new().into(),
    }).await
}

#[wasm_bindgen(js_name = claimAirdrop)]
pub async fn claim_airdrop() -> JsValue {
    send_sdk_tx(sdk::Msg {
        type_: "nomic/MsgClaimAirdrop".to_string(),
        value: serde_json::Map::new().into(),
    }).await
}

#[wasm_bindgen]
pub async fn delegate(to_addr: String, amount: u64) -> JsValue {
    let my_addr = get_address().await;

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
    }).await
}

#[wasm_bindgen]
pub async fn unbond(val_addr: String, amount: u64) -> JsValue {
    let my_addr = get_address().await;

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
    }).await
}

#[wasm_bindgen]
pub async fn redelegate(src_addr: String, dst_addr: String, amount: u64) -> JsValue {
    let my_addr = get_address().await;

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
    }).await
}

#[wasm_bindgen(js_name = airdropBalance)]
pub async fn airdrop_balance(addr: String) -> Option<u64> {
    let client: WebClient<App> = WebClient::new();
    let address = addr.parse().unwrap();

    client.atom_airdrop.balance(address)
        .await
        .unwrap()
        .unwrap()
        .map(Into::into)
}

#[wasm_bindgen]
pub async fn nonce(addr: String) -> u64 {
    let client: WebClient<App> = WebClient::new();
    let address = addr.parse().unwrap();

    client.nonce(address)
        .await
        .unwrap()
}

#[wasm_bindgen(js_name = getAddress)]
pub async fn get_address() -> String {
    let signer = nomic::orga::plugins::keplr::Signer;
    signer.address().await
}

#[wasm_bindgen(getter_with_clone)]
pub struct DepositAddress {
    pub address: String,
    #[wasm_bindgen(js_name = sigsetIndex)]
    pub sigset_index: u32,
    pub expiration: u64,
}

#[wasm_bindgen(js_name = generateDepositAddress)]
pub async fn gen_deposit_addr(dest_addr: String) -> DepositAddress {
    let client: WebClient<App> = WebClient::new();
    let dest_addr: Address = dest_addr.parse().unwrap();

    let sigset = client.bitcoin.checkpoints.active_sigset().await.unwrap().unwrap();
    let script =  sigset.output_script(dest_addr).unwrap();
    // TODO: get network from somewhere
    let btc_addr = bitcoin::Address::from_script(&script, bitcoin::Network::Testnet).unwrap();

    DepositAddress {
        address: btc_addr.to_string(),
        sigset_index: sigset.index(),
        expiration: sigset.deposit_timeout() * 1000,
    }
}

#[wasm_bindgen(js_name = nbtcBalance)]
pub async fn nbtc_balance(addr: String) -> u64 {
    let client: WebClient<App> = WebClient::new();
    let addr: Address = addr.parse().unwrap();

    client.bitcoin.accounts.balance(addr)
        .await
        .unwrap()
        .unwrap()
        .into()
}

#[wasm_bindgen(js_name = getTvl)]
pub async fn get_tvl() -> JsValue {
    let client: WebClient<App> = WebClient::new();
    client.bitcoin.get_tvl()
}

#[wasm_bindgen(js_name = broadcastDepositAddress)]
pub async fn broadcast_deposit_addr(addr: String, sigset_index: u32, relayers: js_sys::Array) {
    let window = web_sys::window().unwrap();

    for relayer in relayers.iter() {
        let relayer = relayer.as_string().unwrap();

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        let url = format!("{}?addr={}&sigset_index={}", relayer, addr, sigset_index);

        let request = Request::new_with_str_and_init(&url, &opts).unwrap();

        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.unwrap();

        let res: Response = resp_value.dyn_into().unwrap();
        let res = JsFuture::from(res.array_buffer().unwrap()).await.unwrap();
        let res = js_sys::Uint8Array::new(&res).to_vec();
        let res = String::from_utf8(res).unwrap();
        web_sys::console::log_1(&format!("response: {}", &res).into());
    }
}

#[wasm_bindgen]
pub async fn withdraw(dest_addr: String, amount: u64) -> JsValue {
    let mut value = serde_json::Map::new();
    value.insert("amount".to_string(), amount.to_string().into());
    value.insert("dst_address".to_string(), dest_addr.into());

    send_sdk_tx(sdk::Msg {
        type_: "nomic/MsgWithdraw".to_string(),
        value: value.into(),
    }).await
}

pub struct WebClient<T: Client<WebAdapter<T>>> {
    state_client: T::Client,
    last_res: Arc<Mutex<Option<String>>>,
}

impl<T: Client<WebAdapter<T>>> WebClient<T> {
    pub fn new() -> Self {
        let last_res = Arc::new(Mutex::new(None));
        let state_client = T::create_client(WebAdapter {
            marker: std::marker::PhantomData,
            last_res: last_res.clone(),
        });
        WebClient {
            state_client,
            last_res,
        }
    }

    fn last_res(&mut self) -> JsValue {
        let res_json = self.last_res.lock().unwrap().take().unwrap();
        js_sys::JSON::parse(&res_json).unwrap()
    }
}

impl<T: Client<WebAdapter<T>>> Deref for WebClient<T> {
    type Target = T::Client;

    fn deref(&self) -> &Self::Target {
        &self.state_client
    }
}

impl<T: Client<WebAdapter<T>>> DerefMut for WebClient<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state_client
    }
}

pub struct WebAdapter<T> {
    marker: std::marker::PhantomData<fn() -> T>,
    last_res: Arc<Mutex<Option<String>>>,
}

impl<T> Clone for WebAdapter<T> {
    fn clone(&self) -> WebAdapter<T> {
        WebAdapter {
            marker: self.marker,
            last_res: self.last_res.clone(),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<T: Call> AsyncCall for WebAdapter<T>
where
    T::Call: Send,
{
    type Call = T::Call;

    async fn call(&self, call: Self::Call) -> Result<()> {
        let tx = call.encode()?;
        let tx = base64::encode(&tx);
        web_sys::console::log_1(&format!("call: {}", tx).into());

        let window = web_sys::window().unwrap();

        let location = window.location();
        let rest_server = format!("{}//{}:{}", location.protocol().unwrap(), location.hostname().unwrap(), REST_PORT);

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.body(Some(&tx.into()));
        opts.mode(RequestMode::Cors);
        let url = format!("{}/txs", rest_server);
    
        let request = Request::new_with_str_and_init(&url, &opts).unwrap();

        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.unwrap();

        let res: Response = resp_value.dyn_into().unwrap();
        let res = JsFuture::from(res.array_buffer().unwrap()).await.unwrap();
        let res = js_sys::Uint8Array::new(&res).to_vec();
        let res = String::from_utf8(res).unwrap();
        web_sys::console::log_1(&format!("response: {}", &res).into());

        self.last_res.lock().unwrap().replace(res);
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl<T: Query + State + 'static> AsyncQuery for WebAdapter<T> {
    type Query = T::Query;
    type Response<'a> = &'a T;

    async fn query<F, R>(&self, query: T::Query, mut check: F) -> Result<R>
    where
        F: FnMut(Self::Response<'_>) -> Result<R>,
    {
        let query = query.encode()?;
        let query = hex::encode(&query);
        web_sys::console::log_1(&format!("query: {}", query).into());

        let window = web_sys::window().unwrap();
        let location = window.location();
        let rest_server = format!("{}//{}:{}", location.protocol().unwrap(), location.hostname().unwrap(), REST_PORT);

        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);
        let url = format!("{}/query/{}", rest_server, query);
    
        let request = Request::new_with_str_and_init(&url, &opts).unwrap();

        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.unwrap();

        let resp: Response = resp_value.dyn_into().unwrap();
        let res = JsFuture::from(resp.array_buffer().unwrap()).await.unwrap();
        let res = js_sys::Uint8Array::new(&res).to_vec();
        let res = String::from_utf8(res).unwrap();
        web_sys::console::log_1(&format!("response: {}", res).into());
        let res = base64::decode(&res).unwrap();

        // // TODO: we shouldn't need to include the root hash in the result, it
        // // should come from a trusted source
        let root_hash = match res[0..32].try_into() {
            Ok(inner) => inner,
            _ => panic!("Cannot convert result to fixed size array"),
        };
        let proof_bytes = &res[32..];

        let map = nomic::orga::merk::merk::proofs::query::verify(proof_bytes, root_hash).unwrap();
        let root_value = match map.get(&[]).unwrap() {
            Some(root_value) => root_value,
            None => panic!("Missing root value"),
        };
        let encoding = T::Encoding::decode(root_value).unwrap();
        let store: Shared<ABCIPrefixedProofStore> = Shared::new(ABCIPrefixedProofStore::new(map));
        let state = T::create(Store::new(store.into()), encoding).unwrap();

        check(&state)
    }
}
