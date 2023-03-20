use nomic::orga::call::Call;
use nomic::orga::client::{AsyncCall, AsyncQuery, Client};
use nomic::orga::encoding::Encode;
use nomic::orga::merk::{BackingStore, ProofStore};
use nomic::orga::plugins::ABCIPlugin;
use nomic::orga::prelude::Shared;
use nomic::orga::query::Query;
use nomic::orga::state::State;
use nomic::orga::store::Store;
use nomic::orga::{Error, Result};
use std::convert::TryInto;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

const REST_PORT: u64 = 8443;

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

    pub fn last_res(&mut self) -> Result<JsValue> {
        let mut lock = self
            .last_res
            .lock()
            .map_err(|e| Error::App(format!("{:?}", e)))?;

        let res_json: String = match lock.take() {
            Some(res) => res,
            None => return Err(Error::App("Lock not found".to_string()))?,
        };

        Ok(js_sys::JSON::parse(&res_json).map_err(|e| Error::App(format!("{:?}", e)))?)
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

        #[cfg(feature = "logging")]
        web_sys::console::log_1(&format!("call: {}", tx).into());

        let window = match web_sys::window() {
            Some(window) => window,
            None => return Err(Error::App("Window not found".to_string())),
        };

        let storage = window
            .local_storage()
            .map_err(|_| Error::App("Could not get local storage".into()))?
            .unwrap();
        let rest_server = storage
            .get("nomic/rest_server")
            .map_err(|_| Error::App("Could not load from local storage".into()))?
            .unwrap();

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.body(Some(&tx.into()));
        opts.mode(RequestMode::Cors);
        let url = format!("{}/txs", rest_server);

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|e| Error::App(format!("{:?}", e)))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| Error::App(format!("{:?}", e)))?;

        let res: Response = resp_value
            .dyn_into()
            .map_err(|e| Error::App(format!("{:?}", e)))?;
        let res = JsFuture::from(
            res.array_buffer()
                .map_err(|e| Error::App(format!("{:?}", e)))?,
        )
        .await
        .map_err(|e| Error::App(format!("{:?}", e)))?;
        let res = js_sys::Uint8Array::new(&res).to_vec();
        let res = String::from_utf8(res).map_err(|e| Error::App(format!("{:?}", e)))?;

        #[cfg(feature = "logging")]
        web_sys::console::log_1(&format!("response: {}", &res).into());

        self.last_res
            .lock()
            .map_err(|e| Error::App(format!("{:?}", e)))?
            .replace(res);
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl<T: Query + State> AsyncQuery for WebAdapter<T> {
    type Query = T::Query;
    type Response<'a> = std::rc::Rc<T>;

    async fn query<F, R>(&self, query: T::Query, mut check: F) -> Result<R>
    where
        F: FnMut(Self::Response<'_>) -> Result<R>,
    {
        let query = Encode::encode(&query)?;
        let query = hex::encode(&query);

        #[cfg(feature = "logging")]
        web_sys::console::log_1(&format!("query: {}", query).into());

        let window = match web_sys::window() {
            Some(window) => window,
            None => return Err(Error::App("Window not found".to_string())),
        };
        let storage = window
            .local_storage()
            .map_err(|_| Error::App("Could not get local storage".into()))?
            .unwrap();
        let rest_server = storage
            .get("nomic/rest_server")
            .map_err(|_| Error::App("Could not load from local storage".into()))?
            .unwrap();

        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);
        let url = format!("{}/query/{}", rest_server, query);

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|e| Error::App(format!("{:?}", e)))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| Error::App(format!("{:?}", e)))?;

        let resp: Response = resp_value
            .dyn_into()
            .map_err(|e| Error::App(format!("{:?}", e)))?;

        let resp_buf = resp
            .array_buffer()
            .map_err(|e| Error::App(format!("{:?}", e)))?;

        let res = JsFuture::from(resp_buf)
            .await
            .map_err(|e| Error::App(format!("{:?}", e)))?;
        let res = js_sys::Uint8Array::new(&res).to_vec();
        let res = String::from_utf8(res).map_err(|e| Error::App(format!("{:?}", e)))?;

        #[cfg(feature = "logging")]
        web_sys::console::log_1(&format!("response: {}", res).into());

        let res = base64::decode(&res).map_err(|e| Error::App(format!("{:?}", e)))?;

        // // TODO: we shouldn't need to include the root hash in the result, it
        // // should come from a trusted source
        let root_hash = match res[0..32].try_into() {
            Ok(inner) => inner,
            _ => panic!("Cannot convert result to fixed size array"),
        };
        let proof_bytes = &res[32..];

        let map = nomic::orga::merk::merk::proofs::query::verify(proof_bytes, root_hash)?;
        let root_value = match map.get(&[])? {
            Some(root_value) => root_value.to_vec(),
            None => panic!("Missing root value"),
        };

        let store: Shared<ProofStore> = Shared::new(ProofStore(map));
        let store = BackingStore::ProofMap(store);
        let state = <ABCIPlugin<T>>::load(Store::new(store), &mut root_value.as_slice())?;

        check(std::rc::Rc::new(state.inner))
    }
}
