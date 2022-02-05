#![feature(async_closure)]

use wasm_bindgen::prelude::*;
use nomic::app::{App, InnerApp, Nom, Airdrop};
use nomic::orga::prelude::*;
use nomic::orga::merk::ABCIPrefixedProofStore;
use std::ops::{Deref, DerefMut};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};
use std::convert::TryInto;
use js_sys::{Array, JsString};

const REST_PORT: u64 = 8443;

#[wasm_bindgen(start)]
pub fn main() -> std::result::Result<(), JsValue> {
    console_error_panic_hook::set_once();
    Ok(())
}

#[wasm_bindgen]
pub async fn transfer(to_addr: String, amount: u64) {
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
}

#[wasm_bindgen]
pub async fn balance(addr: String) -> u64 {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().unwrap();

    type NonceQuery = <NoncePlugin<PayablePlugin<FeePlugin<Nom, InnerApp>>> as Query>::Query;
    type AppQuery = <InnerApp as Query>::Query;
    type AcctQuery = <Accounts<Nom> as Query>::Query;

    let q = NonceQuery::Inner(AppQuery::FieldAccounts(AcctQuery::MethodBalance(address, vec![])));
    client
        .query(q, |state| state.accounts.balance(address))
        .await
        .unwrap()
        .into()
}

#[wasm_bindgen(js_name = rewardBalance)]
pub async fn reward_balance(addr: String) -> u64 {
    let mut client: WebClient<App> = WebClient::new();
    let address = addr.parse().unwrap();

    type NonceQuery = <NoncePlugin<PayablePlugin<FeePlugin<Nom, InnerApp>>> as Query>::Query;
    type AppQuery = <InnerApp as Query>::Query;
    type StakingQuery = <Staking<Nom> as Query>::Query;

    let delegations = client
        .query(
            NonceQuery::Inner(AppQuery::FieldStaking(StakingQuery::MethodDelegations(address, vec![]))),
            |state| state.staking.delegations(address),
        )
        .await
        .unwrap();

    delegations
        .iter()
        .map(|(_, d)| -> u64 { d.liquid.into() })
        .sum::<u64>()
}

#[wasm_bindgen]
pub struct UnbondInfo {
    start_seconds: u64,
    amount: u64,
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

    type NonceQuery = <NoncePlugin<PayablePlugin<FeePlugin<Nom, InnerApp>>> as Query>::Query;
    type AppQuery = <InnerApp as Query>::Query;
    type StakingQuery = <Staking<Nom> as Query>::Query;

    let delegations = client
        .query(
            NonceQuery::Inner(AppQuery::FieldStaking(StakingQuery::MethodDelegations(address, vec![]))),
            |state| state.staking.delegations(address),
        )
        .await
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

    type NonceQuery = <NoncePlugin<PayablePlugin<FeePlugin<Nom, InnerApp>>> as Query>::Query;
    type AppQuery = <InnerApp as Query>::Query;
    type StakingQuery = <Staking<Nom> as Query>::Query;

    let validators = client
        .query(
            NonceQuery::Inner(AppQuery::FieldStaking(StakingQuery::MethodAllValidators(vec![]))),
            |state| state.staking.all_validators(),
        )
        .await
        .unwrap();

    validators
        .iter()
        .map(|v| ValidatorQueryInfo {
            jailed: v.jailed,
            address: v.address.to_string(),
            commission: v.commission.to_string(),
            in_active_set: v.in_active_set,
            info: String::from_utf8(v.info.bytes.clone()).unwrap_or(String::new()),
            amount_staked: v.amount_staked.into(),
        })
        .map(JsValue::from)
        .collect()
}


#[wasm_bindgen]
pub async fn claim() {
    let mut client: WebClient<App> = WebClient::new();
    
    client
        .pay_from(async move |mut client| {
            client.staking.claim_all().await
        })
        .accounts
        .give_from_funding_all()
        .await
        .unwrap();
}

#[wasm_bindgen]
pub async fn delegate(to_addr: String, amount: u64) {
    let mut client: WebClient<App> = WebClient::new();
    let to_addr = to_addr.parse().unwrap();
    client
        .pay_from(async move |mut client| {
            client.accounts.take_as_funding((amount + MIN_FEE).into()).await
        })
        .staking
        .delegate_from_self(to_addr, amount.into())
        .await
        .unwrap();
}

#[wasm_bindgen]
pub async fn unbond(validator_addr: String, amount: u64) {
    let mut client: WebClient<App> = WebClient::new();
    let validator_addr = validator_addr.parse().unwrap();
    client
        .pay_from(async move |mut client| {
            client.accounts.take_as_funding(MIN_FEE.into()).await
        })
        .staking
        .unbond_self(validator_addr, amount.into())
        .await
        .unwrap();
}

#[wasm_bindgen(js_name = airdropBalance)]
pub async fn airdrop_balance(addr: String) -> Option<u64> {
    let client: WebClient<App> = WebClient::new();
    let address = addr.parse().unwrap();

    type NonceQuery = <NoncePlugin<PayablePlugin<FeePlugin<Nom, InnerApp>>> as Query>::Query;
    type AppQuery = <InnerApp as Query>::Query;
    type AirdropQuery = <Airdrop<Nom> as Query>::Query;

    client
        .query(
            NonceQuery::Inner(AppQuery::FieldAtomAirdrop(AirdropQuery::MethodBalance(address, vec![]))),
            |state| state.atom_airdrop.balance(address),
        )
        .await
        .unwrap()
        .map(Into::into)
}

#[wasm_bindgen(js_name = claimAirdrop)]
pub async fn claim_airdrop() {
    let mut client: WebClient<App> = WebClient::new();

    client
        .pay_from(async move |mut client| {
            client.atom_airdrop.claim().await
        })
        .accounts
        .give_from_funding_all()
        .await
        .unwrap();
}

#[wasm_bindgen(js_name = getAddress)]
pub async fn get_address() -> String {
    let mut signer = nomic::orga::plugins::keplr::Signer::new();
    signer.address().await
}

pub struct WebClient<T: Client<WebAdapter<T>>> {
    state_client: T::Client,
}

impl<T: Client<WebAdapter<T>>> WebClient<T> {
    pub fn new() -> Self {
        let state_client = T::create_client(WebAdapter {
            marker: std::marker::PhantomData,
        });
        WebClient {
            state_client,
        }
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

impl<T: Client<WebAdapter<T>> + Query + State> WebClient<T> {
    pub async fn query<F, R>(&self, query: T::Query, check: F) -> Result<R>
    where
        F: Fn(&T) -> Result<R>,
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

pub struct WebAdapter<T> {
    marker: std::marker::PhantomData<fn() -> T>,
}

impl<T> Clone for WebAdapter<T> {
    fn clone(&self) -> WebAdapter<T> {
        WebAdapter {
            marker: self.marker,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<T: Call> AsyncCall for WebAdapter<T>
where
    T::Call: Send,
{
    type Call = T::Call;

    async fn call(&mut self, call: Self::Call) -> Result<()> {
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

        let resp: Response = resp_value.dyn_into().unwrap();
        let res = JsFuture::from(resp.array_buffer().unwrap()).await.unwrap();
        let res = js_sys::Uint8Array::new(&res).to_vec();
        let res = String::from_utf8(res).unwrap();
        web_sys::console::log_1(&format!("response: {}", res).into());

        // TODO: handle error response

        Ok(())
    }
}
