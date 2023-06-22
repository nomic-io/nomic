// use clap::Parser;
// use csv::Reader;
// use nomic::airdrop::Part;
// use nomic::app::App;
// use orga::merk::BackingStore;
// use orga::merk::MerkStore;
// use orga::prelude::Address;
// use orga::state::State;
// use orga::store::Shared;
// use orga::store::Store;
// use std::str::FromStr;

// #[derive(Parser, Debug)]
// pub struct Opts {
//     #[clap(short, long)]
//     merk_path: String,
//     #[clap(short, long)]
//     airdrop_csv_path: String,
// }

// fn is_claimed(airdrop_part: &Part) -> bool {
//     airdrop_part.claimed > 0 || airdrop_part.claimable > 0
// }

// pub fn main() {
//     let opts = Opts::parse();

//     let mut reader = Reader::from_path(&opts.airdrop_csv_path).unwrap();
//     let mut headers = reader.headers().unwrap().clone();
//     headers.extend([
//         "btc_deposit_claimed",
//         "btc_withdraw_claimed",
//         "ibc_transfer_claimed",
//     ]);

//     let merk = MerkStore::new(&opts.merk_path);
//     let root_bytes = merk.merk().get(&[]).unwrap().unwrap();
//     let app = orga::plugins::ABCIPlugin::<App>::load(
//         Store::new(BackingStore::Merk(Shared::new(merk))),
//         &mut root_bytes.as_slice(),
//     )
//     .unwrap();

//     let mut writer = csv::Writer::from_writer(std::io::stdout());
//     writer.write_record(&headers).unwrap();
//     for result in reader.records() {
//         let mut record = result.unwrap();
//         let addr = record.get(0).unwrap();
//         if addr.len() != 44 {
//             continue;
//         }
//         let airdrop_account = app
//             .inner
//             .airdrop
//             .get(Address::from_str(addr).unwrap())
//             .unwrap()
//             .unwrap();

//         record.push_field(
//             is_claimed(&airdrop_account.btc_deposit)
//                 .to_string()
//                 .as_str(),
//         );
//         record.push_field(
//             is_claimed(&airdrop_account.btc_withdraw)
//                 .to_string()
//                 .as_str(),
//         );
//         record.push_field(
//             is_claimed(&airdrop_account.ibc_transfer)
//                 .to_string()
//                 .as_str(),
//         );
//         writer.write_record(&record).unwrap();
//     }
// }

fn main() {}
