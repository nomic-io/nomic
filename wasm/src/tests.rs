use wasm_bindgen_test::*;

use crate::{NetWorkEnum, OraiBtc};

#[wasm_bindgen_test]
async fn test_get_balance() {
    let app = OraiBtc::new(
        "https://oraibtc.lcd.orai.io",
        "OraiBtcSubnet",
        NetWorkEnum::Bitcoin,
    );

    let ret = app
        .gen_deposit_addr(
            "orai12zyu8w93h0q2lcnt50g3fn0w3yqnhy4fvawaqz".to_string(),
            Some("channel-0".to_string()),
            Some("oraibtc1ehmhqcn8erf3dgavrca69zgp4rtxj5kqzpga4j".to_string()),
            None,
            None,
        )
        .await
        .ok()
        .unwrap();

    println!("{:?}", ret.address);
}
