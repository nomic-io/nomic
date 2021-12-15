#![cfg(todo)]

use bitcoincore_rpc::{Auth, Client as BtcClient, RpcApi};
use bitcoind::BitcoinD;
use nomic::bitcoin::adapter::Adapter;
use nomic::bitcoin::header_queue::{Config, HeaderQueue};
use nomic::bitcoin::relayer::Relayer;
use orga::encoding::Encode;
use orga::store::{MapStore, Shared, Store};

#[test]
fn relayer() {
    let bitcoind = BitcoinD::new(bitcoind::downloaded_exe_path().unwrap()).unwrap();

    let address = bitcoind.client.get_new_address(None, None).unwrap();
    bitcoind.client.generate_to_address(32, &address).unwrap();
    let trusted_hash = bitcoind.client.get_block_hash(32).unwrap();
    let trusted_header = bitcoind.client.get_block_header(&trusted_hash).unwrap();

    let bitcoind_url = bitcoind.rpc_url();
    let bitcoin_cookie_file = bitcoind.params.cookie_file.clone();
    let rpc_client = BtcClient::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

    let encoded_header = Encode::encode(&Adapter::new(trusted_header)).unwrap();
    let mut config: Config = Default::default();
    config.encoded_trusted_header = encoded_header;
    config.trusted_height = 32;
    config.retargeting = false;

    bitcoind
        .client
        .generate_to_address(10 as u64, &address)
        .unwrap();

    let store = Store::new(Shared::new(MapStore::new()));

    let mut header_queue = HeaderQueue::with_conf(store, Default::default(), config).unwrap();
    let relayer = Relayer::new(rpc_client);
    relayer.bounded_listen(10, &mut header_queue).unwrap();
    let height = header_queue.height().unwrap();

    assert_eq!(height, 42);
}
