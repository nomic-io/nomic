use std::string::FromUtf8Error;

use nomic::thiserror;
use wasm_bindgen::prelude::JsValue;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Nomic(#[from] nomic::error::Error),
    #[error(transparent)]
    Orga(#[from] nomic::orga::Error),
    #[error("{0:?}")]
    Js(wasm_bindgen::JsValue),
    #[error(transparent)]
    Utf8(#[from] FromUtf8Error),
    #[error("{0}")]
    Wasm(String),
    #[error("{0}")]
    Relayer(String),
}

impl From<JsValue> for Error {
    fn from(err: JsValue) -> Self {
        Self::Js(err)
    }
}
