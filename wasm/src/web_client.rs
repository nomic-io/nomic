use futures_lite::Future;
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
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use wasm_bindgen::{JsCast, JsValue};
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
    }

    async fn query(&self, query: T::Query) -> Result<Store> {
        UnsafeSendFuture(async move {
            let query_bytes = query.encode()?;
            let query = hex::encode(query_bytes);
            let maybe_height: Option<u32> = self.height.lock().unwrap().map(Into::into);

            let window = match web_sys::window() {
                Some(window) => window,
                None => return Err(Error::App("Window not found".to_string())),
            };

            let rest_server = {
                let storage = window
                    .local_storage()
                    .map_err(|_| Error::App("Could not get local storage".into()))?
                    .unwrap();
                storage
                    .get("nomic/rest_server")
                    .map_err(|_| Error::App("Could not load from local storage".into()))?
                    .unwrap()
            };

            let resp_value = {
                JsFuture::from(window.fetch_with_request(&{
                    let mut opts = RequestInit::new();
                    opts.method("GET");
                    opts.mode(RequestMode::Cors);
                    let mut url = format!("{}/query/{}", rest_server, query);
                    if let Some(height) = maybe_height {
                        url.push_str(&format!("?height={}", height));
                    }

                    Request::new_with_str_and_init(&url, &opts)
                        .map_err(|e| Error::App(format!("{:?}", e)))?
                }))
                .await
                .map_err(|e| Error::App(format!("{:?}", e)))?
            };

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
        })
        .await
    }
}

pub struct UnsafeSendFuture<F>(F);

unsafe impl<F> Send for UnsafeSendFuture<F> {}

impl<F: std::future::Future> Future for UnsafeSendFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        inner.poll(cx)
    }
}

struct UnsafeSend<T>(pub T);

impl<T: Unpin + Future<Output = std::result::Result<JsValue, JsValue>>> Future for UnsafeSend<T> {
    type Output = std::result::Result<JsValue, JsValue>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::result::Result<JsValue, JsValue>> {
        let inner = unsafe { Pin::new_unchecked(&mut self.get_mut().0) };
        inner.poll(cx)
    }
}

unsafe impl<T> Send for UnsafeSend<T> {}
