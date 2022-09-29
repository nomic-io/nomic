// use bitcoin::consensus::Decodable;
// use bitcoin::BlockHeader;
// use bitcoind::bitcoincore_rpc::{self, Error as RpcError, RpcApi};
// use bitcoind::BitcoinD;
// use bitcoind::Conf;
// use bitcoind::P2P;
// use nomic::bitcoin::adapter::Adapter;
// use nomic::bitcoin::header_queue::Config;
// use nomic::bitcoin::header_queue::HeaderQueue;
// use nomic::bitcoin::header_queue::WrappedHeader;
// use orga::encoding::Encode;
// use orga::store::{MapStore, Shared, Store};
// use std::fs;

// fn into_json<T>(val: T) -> Result<bitcoincore_rpc::jsonrpc::serde_json::Value, RpcError>
// where
//     T: serde::ser::Serialize,
// {
//     Ok(serde_json::to_value(val)?)
// }

// #[test]
// fn reorg() {
//     let mut conf = Conf::default();
//     conf.p2p = P2P::Yes;
//     let node_1 = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();

//     let mut conf = Conf::default();
//     conf.p2p = node_1.p2p_connect(true).unwrap();
//     let node_2 = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
//     let alice_address = node_1.client.get_new_address(Some("alice"), None).unwrap();
//     let bob_address = node_2.client.get_new_address(Some("bob"), None).unwrap();

//     node_1
//         .client
//         .generate_to_address(1, &alice_address)
//         .unwrap();

//     let tip_hash = node_1.client.get_best_block_hash().unwrap();
//     let tip_header = node_1.client.get_block_header(&tip_hash).unwrap();
//     let tip_height = node_1
//         .client
//         .get_block_header_info(&tip_hash)
//         .unwrap()
//         .height;
//     let encoded_header = Encode::encode(&Adapter::new(tip_header)).unwrap();

//     let mut config: Config = Default::default();
//     config.encoded_trusted_header = encoded_header;
//     config.trusted_height = tip_height as u32;
//     config.retargeting = false;

//     let store = Store::new(Shared::new(MapStore::new()).into());
//     let mut header_queue = HeaderQueue::with_conf(store, Default::default(), config).unwrap();

//     let mut headers = Vec::with_capacity(11);
//     for _ in 0..10 {
//         node_1
//             .client
//             .generate_to_address(1, &alice_address)
//             .unwrap();

//         let tip_hash = node_1.client.get_best_block_hash().unwrap();
//         let tip_header = node_1.client.get_block_header(&tip_hash).unwrap();
//         let tip_height_info = node_1.client.get_block_header_info(&tip_hash).unwrap();
//         let tip_height = tip_height_info.height;

//         headers.push(WrappedHeader::from_header(&tip_header, tip_height as u32));
//     }

//     header_queue.add(headers.into()).unwrap();

//     node_2
//         .client
//         .call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
//             "disconnectnode",
//             &[into_json(node_1.params.p2p_socket.unwrap()).unwrap()],
//         )
//         .unwrap();

//     node_1
//         .client
//         .generate_to_address(1, &alice_address)
//         .unwrap();

//     let tip_hash = node_1.client.get_best_block_hash().unwrap();
//     let tip_header = node_1.client.get_block_header(&tip_hash).unwrap();
//     let tip_header_info = node_1.client.get_block_header_info(&tip_hash).unwrap();
//     let tip_height = tip_header_info.height;

//     header_queue
//         .add(vec![WrappedHeader::from_header(&tip_header, tip_height as u32)].into())
//         .unwrap();

//     let mut headers = Vec::with_capacity(5);
//     for _ in 0..5 {
//         node_2.client.generate_to_address(1, &bob_address).unwrap();

//         let tip_hash = node_2.client.get_best_block_hash().unwrap();
//         let tip_header = node_2.client.get_block_header(&tip_hash).unwrap();
//         let tip_header_info = node_2.client.get_block_header_info(&tip_hash).unwrap();
//         let tip_height = tip_header_info.height;

//         headers.push(WrappedHeader::from_header(&tip_header, tip_height as u32));
//     }

//     header_queue.add(headers.into()).unwrap();

//     assert_eq!(header_queue.height().unwrap(), 16);
// }

// #[test]
// fn reorg_competing_chain_similar() {
//     let mut conf = Conf::default();
//     conf.p2p = P2P::Yes;
//     let node_1 = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();

//     let mut conf = Conf::default();
//     conf.p2p = node_1.p2p_connect(true).unwrap();
//     let node_2 = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
//     let alice_address = node_1.client.get_new_address(Some("alice"), None).unwrap();
//     let bob_address = node_2.client.get_new_address(Some("bob"), None).unwrap();

//     node_1
//         .client
//         .generate_to_address(1, &alice_address)
//         .unwrap();

//     let tip_hash = node_1.client.get_best_block_hash().unwrap();
//     let tip_header = node_1.client.get_block_header(&tip_hash).unwrap();
//     let tip_height = node_1
//         .client
//         .get_block_header_info(&tip_hash)
//         .unwrap()
//         .height;
//     let encoded_header = Encode::encode(&Adapter::new(tip_header)).unwrap();

//     let mut config: Config = Default::default();
//     config.encoded_trusted_header = encoded_header;
//     config.trusted_height = tip_height as u32;
//     config.retargeting = false;

//     let store = Store::new(Shared::new(MapStore::new()).into());
//     let mut header_queue = HeaderQueue::with_conf(store, Default::default(), config).unwrap();

//     let mut headers = Vec::with_capacity(11);
//     for _ in 0..10 {
//         node_1
//             .client
//             .generate_to_address(1, &alice_address)
//             .unwrap();

//         let tip_hash = node_1.client.get_best_block_hash().unwrap();
//         let tip_header = node_1.client.get_block_header(&tip_hash).unwrap();
//         let tip_header_info = node_1.client.get_block_header_info(&tip_hash).unwrap();
//         let tip_height = tip_header_info.height;

//         headers.push(WrappedHeader::from_header(&tip_header, tip_height as u32));
//     }

//     header_queue.add(headers.into()).unwrap();

//     node_2
//         .client
//         .call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
//             "disconnectnode",
//             &[into_json(node_1.params.p2p_socket.unwrap()).unwrap()],
//         )
//         .unwrap();

//     let mut headers = Vec::with_capacity(5);
//     for _ in 0..1 {
//         node_1.client.generate_to_address(1, &bob_address).unwrap();

//         let tip_hash = node_1.client.get_best_block_hash().unwrap();
//         let tip_header = node_1.client.get_block_header(&tip_hash).unwrap();
//         let tip_header_info = node_1.client.get_block_header_info(&tip_hash).unwrap();
//         let tip_height = tip_header_info.height;

//         headers.push(WrappedHeader::from_header(&tip_header, tip_height as u32));
//     }

//     header_queue.add(headers.into()).unwrap();

//     let mut headers = Vec::with_capacity(5);
//     for _ in 0..2 {
//         node_2
//             .client
//             .generate_to_address(1, &alice_address)
//             .unwrap();

//         let tip_hash = node_2.client.get_best_block_hash().unwrap();
//         let tip_header = node_2.client.get_block_header(&tip_hash).unwrap();
//         let tip_header_info = node_2.client.get_block_header_info(&tip_hash).unwrap();
//         let tip_height = tip_header_info.height;

//         headers.push(WrappedHeader::from_header(&tip_header, tip_height as u32));
//     }

//     header_queue.add(headers.into()).unwrap();

//     assert_eq!(header_queue.height().unwrap(), 13);
// }

// #[test]
// #[ignore]
// fn reorg_deep() {
//     let mut conf = Conf::default();
//     conf.p2p = P2P::Yes;
//     let node_1 = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();

//     let mut conf = Conf::default();
//     conf.p2p = node_1.p2p_connect(true).unwrap();
//     let node_2 = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();
//     let alice_address = node_1.client.get_new_address(Some("alice"), None).unwrap();
//     let bob_address = node_2.client.get_new_address(Some("bob"), None).unwrap();

//     node_1
//         .client
//         .generate_to_address(1, &alice_address)
//         .unwrap();

//     let tip_hash = node_1.client.get_best_block_hash().unwrap();
//     let tip_header = node_1.client.get_block_header(&tip_hash).unwrap();
//     let tip_height = node_1
//         .client
//         .get_block_header_info(&tip_hash)
//         .unwrap()
//         .height;
//     let encoded_header = Encode::encode(&Adapter::new(tip_header)).unwrap();

//     let mut config: Config = Default::default();
//     config.encoded_trusted_header = encoded_header;
//     config.trusted_height = tip_height as u32;
//     config.retargeting = false;

//     let store = Store::new(Shared::new(MapStore::new()).into());
//     let mut header_queue = HeaderQueue::with_conf(store, Default::default(), config).unwrap();

//     let mut headers = Vec::with_capacity(10);
//     for _ in 0..10 {
//         node_1
//             .client
//             .generate_to_address(1, &alice_address)
//             .unwrap();

//         let tip_hash = node_1.client.get_best_block_hash().unwrap();
//         let tip_header = node_1.client.get_block_header(&tip_hash).unwrap();
//         let tip_header_info = node_1.client.get_block_header_info(&tip_hash).unwrap();
//         let tip_height = tip_header_info.height;

//         headers.push(WrappedHeader::from_header(&tip_header, tip_height as u32));
//     }

//     header_queue.add(headers.into()).unwrap();

//     node_2
//         .client
//         .call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
//             "disconnectnode",
//             &[into_json(node_1.params.p2p_socket.unwrap()).unwrap()],
//         )
//         .unwrap();

//     let mut headers = Vec::with_capacity(10);
//     for _ in 0..10 {
//         node_1
//             .client
//             .generate_to_address(1, &alice_address)
//             .unwrap();

//         let tip_hash = node_1.client.get_best_block_hash().unwrap();
//         let tip_header = node_1.client.get_block_header(&tip_hash).unwrap();
//         let tip_header_info = node_1.client.get_block_header_info(&tip_hash).unwrap();
//         let tip_height = tip_header_info.height;

//         headers.push(WrappedHeader::from_header(&tip_header, tip_height as u32));
//     }

//     header_queue.add(headers.into()).unwrap();
//     let mut headers = Vec::with_capacity(1000);
//     for _ in 0..1000 {
//         node_2.client.generate_to_address(1, &bob_address).unwrap();

//         let tip_hash = node_2.client.get_best_block_hash().unwrap();
//         let tip_header = node_2.client.get_block_header(&tip_hash).unwrap();
//         let tip_header_info = node_2.client.get_block_header_info(&tip_hash).unwrap();
//         let tip_height = tip_header_info.height;

//         headers.push(WrappedHeader::from_header(&tip_header, tip_height as u32));
//     }

//     header_queue.add(headers.into()).unwrap();

//     assert_eq!(header_queue.height().unwrap(), 1011);
// }

// #[test]
// #[ignore]
// fn mainnet_from_file() {
//     let block_data = fs::read("tests/data/block-data").unwrap();

//     let headers: Vec<BlockHeader> = block_data
//         .chunks(80)
//         .map(|chunk| BlockHeader::consensus_decode(chunk).unwrap())
//         .collect();

//     let first_encoded_header = headers.get(2016).unwrap();

//     let mut config: Config = Default::default();
//     config.encoded_trusted_header = Encode::encode(&Adapter::new(first_encoded_header)).unwrap();
//     config.trusted_height = 2016;

//     let store = Store::new(Shared::new(MapStore::new()).into());
//     let mut header_queue = HeaderQueue::with_conf(store, Default::default(), config).unwrap();

//     let mut add_headers = Vec::new();
//     for i in 2017..headers.len() - 1 {
//         let header = headers.get(i).unwrap();

//         if i % 100000 == 0 {
//             header_queue.add(add_headers.clone().into()).unwrap();
//             add_headers.clear();
//             add_headers.push(WrappedHeader::from_header(header, i as u32));
//         } else {
//             add_headers.push(WrappedHeader::from_header(header, i as u32));
//         }
//     }

//     header_queue.add(add_headers.into()).unwrap();
// }
