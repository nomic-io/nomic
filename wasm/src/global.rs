use js_sys::{Object, Promise};
use wasm_bindgen::prelude::wasm_bindgen;

use web_sys::Request;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends=Object, js_name=Object, typescript_type="Object")]
    pub type Global;

    #[wasm_bindgen (method, structural, js_class="Object", js_name=fetch)]
    pub fn js_fetch(this: &Global, input: &Request) -> Promise;

    #[wasm_bindgen(method, structural, js_class = "Object", indexing_getter)]
    pub fn get(this: &Global, name: &str) -> Option<Object>;
}
