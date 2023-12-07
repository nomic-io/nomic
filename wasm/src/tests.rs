use wasm_bindgen_test::*;

use crate::OraiBtc;

#[wasm_bindgen_test]
async fn test_get_balance() {
    let app = OraiBtc::new("https://oraibtc.lcd.orai.io", "OraiBtcSubnet");

    let ret = app
        .balance("oraibtc1ehmhqcn8erf3dgavrca69zgp4rtxj5kqzpga4j".to_string())
        .await
        .ok()
        .unwrap();

    println!("{}", ret);
}
