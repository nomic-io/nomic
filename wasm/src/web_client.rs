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

#[derive(Default)]
pub struct WebClient {
    height: Mutex<Option<u32>>,
}

impl WebClient {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<T: App + Call + Query + State + Default> Transport<ABCIPlugin<T>> for WebClient {
    async fn call(&self, _call: <ABCIPlugin<T> as Call>::Call) -> Result<()> {
        todo!()
        // TODO: shouldn't need to deal with ABCIPlugin at this level
        // let call = match call {
        //     ABCICall::DeliverTx(call) => call,
        //     _ => return Err(Error::Client("Unexpected call type".into())),
        // };
        // let call_bytes = call.encode()?;
        // let tx = base64::encode(&call_bytes);
        // // let res = block_on(self.client.broadcast_tx_commit(call_bytes))?;

        // let window = match web_sys::window() {
        //     Some(window) => window,
        //     None => return Err(Error::App("Window not found".to_string())),
        // };

        // let storage = window
        //     .local_storage()
        //     .map_err(|_| Error::App("Could not get local storage".into()))?
        //     .unwrap();
        // let rest_server = storage
        //     .get("nomic/rest_server")
        //     .map_err(|_| Error::App("Could not load from local storage".into()))?
        //     .unwrap();

        // let url = format!("{}/txs", rest_server);

        // // let request = Request::new_with_str_and_init(&url, &opts)
        // //     .map_err(|e| Error::App(format!("{:?}", e)))?;

        // // let resp_value = JsFuture::from(window.fetch_with_request(&request))
        // //     .await
        // //     .map_err(|e| Error::App(format!("{:?}", e)))?;

        // // let res: Response = resp_value
        // //     .dyn_into()
        // //     .map_err(|e| Error::App(format!("{:?}", e)))?;
        // // let res = JsFuture::from(
        // //     res.array_buffer()
        // //         .map_err(|e| Error::App(format!("{:?}", e)))?,
        // // )
        // // .await
        // // .map_err(|e| Error::App(format!("{:?}", e)))?;
        // let client = reqwest_wasm::blocking::Client::new();
        // let res = client
        //     .post(url)
        //     .body(tx)
        //     .send()
        //     .map_err(|e| Error::App(format!("{:?}", e)))?
        //     .text()
        //     .map_err(|e| Error::App(format!("{:?}", e)))?;
        // // let res = js_sys::Uint8Array::new(&res).to_vec();
        // // let res = String::from_utf8(res).map_err(|e| Error::App(format!("{:?}", e)))?;

        // #[cfg(feature = "logging")]
        // web_sys::console::log_1(&format!("response: {}", &res).into());

        // self.last_res
        //     .lock()
        //     .map_err(|e| Error::App(format!("{:?}", e)))?
        //     .replace(res);

        // // if let tendermint::abci::Code::Err(code) = res.check_tx.code {
        // //     let msg = format!("code {}: {}", code, res.check_tx.log);
        // //     return Err(Error::Call(msg));
        // // }

        // Ok(())
    }

    async fn query(&self, query: T::Query) -> Result<Store> {
        let query_bytes = query.encode()?;
        let query = hex::encode(query_bytes);
        let maybe_height: Option<u32> = self.height.lock().unwrap().map(Into::into);

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
        let mut url = format!("{}/query/{}", rest_server, query);
        if let Some(height) = maybe_height {
            url.push_str(&format!("?height={}", height));
        }

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
                return Err(Error::App(format!(
                    "Height mismatch: expected {}, got {}",
                    height, res_height
                )));
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
