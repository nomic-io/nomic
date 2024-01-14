use nomic::orga::abci::App;
use nomic::orga::call::Call;
use nomic::orga::client::Transport;
use nomic::orga::encoding::Encode;
use nomic::orga::merk::ProofStore;
use nomic::orga::plugins::ABCIPlugin;
use nomic::orga::query::Query;
use nomic::orga::state::State;
use nomic::orga::store::Store;
use nomic::orga::store::{BackingStore, Shared};
use nomic::orga::{Error, Result};
use std::convert::TryInto;
use std::sync::Mutex;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use web_sys::{Request, RequestInit, RequestMode, Response};

use crate::global::Global;

#[derive(Default)]
pub struct WebClient {
    height: Mutex<Option<u32>>,
    rest_server: String,
}

impl WebClient {
    pub fn new(url: String) -> Self {
        let mut client = Self::default();
        client.rest_server = url;
        client
    }
}

impl<T: App + Call + Query + State + Default> Transport<ABCIPlugin<T>> for WebClient {
    async fn call(&self, _call: <ABCIPlugin<T> as Call>::Call) -> Result<()> {
        todo!()
        // TODO: shouldn't need to deal with ABCIPlugin at this level
    }

    async fn query(&self, query: T::Query) -> Result<Store> {
        let query_bytes = query.encode()?;
        let query = hex::encode(query_bytes);
        // let maybe_height: Option<u32> = self.height.lock().unwrap().map(Into::into);

        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);
        let url = format!("{}/query/{}", self.rest_server, query);
        // if let Some(height) = maybe_height {
        //     url.push_str(&format!("?height={}", height));
        // }

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|e| Error::App(format!("{:?}", e)))?;

        let global = match js_sys::global().dyn_into::<Global>() {
            Ok(global) => global,
            Err(_) => return Err(Error::App("Object class not found".to_string())),
        };

        let resp_value = JsFuture::from(global.js_fetch(&request))
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
        let res = base64::decode(res).map_err(|e| Error::App(format!("{:?}", e)))?;

        // TODO: we shouldn't need to include the root hash in the result, it
        // should come from a trusted source
        let res_height = match res[0..4].try_into() {
            Ok(inner) => u32::from_be_bytes(inner),
            _ => panic!("Cannot convert result to fixed size array"),
        };
        let mut height = self.height.lock().unwrap();
        if let Some(height) = height.as_ref() {
            if *height != res_height {
                web_sys::console::warn_1(
                    &format!("Height mismatch: expected {}, got {}", height, res_height).into(),
                );
            }
        }
        height.replace(res_height);
        let root_hash = match res[4..36].try_into() {
            Ok(inner) => inner,
            _ => panic!("Cannot convert result to fixed size array"),
        };
        let proof_bytes = &res[36..];

        let map = nomic::orga::merk::merk::proofs::query::verify(proof_bytes, root_hash)?;

        let store: Shared<ProofStore> = Shared::new(ProofStore(map));
        let store = Store::new(BackingStore::ProofMap(store));

        Ok(store)
    }
}
