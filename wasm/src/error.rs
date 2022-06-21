use nomic::thiserror;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Orga(#[from] nomic::orga::Error),
    #[error("{0}")]
    Wasm(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Into<wasm_bindgen::JsValue> for Error {
    fn into(self) -> wasm_bindgen::JsValue {
        wasm_bindgen::JsValue::from_str(&format!("{:?}", self))
    }
}
