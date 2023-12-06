wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
use wasm_bindgen_test::*;

use crate::balance;

fn mock_data(rest_server: &str) {
    let window = match web_sys::window() {
        Some(window) => window,
        None => panic!("Window not found"),
    };

    let storage = window.local_storage().unwrap().unwrap();

    storage.set("nomic/rest_server", rest_server).unwrap();

    let rest_server = storage.get("nomic/rest_server").unwrap();
    web_sys::console::log_1(&rest_server.into());
}

#[wasm_bindgen_test]
async fn test_get_balance() {
    mock_data("https://oraibtc.lcd.orai.io");

    let ret = balance("oraibtc1ehmhqcn8erf3dgavrca69zgp4rtxj5kqzpga4j".to_string())
        .await
        .ok();

    web_sys::console::log_1(&ret.into());
}
