use clap::Parser;
use leveldb::database::Database;
use leveldb::iterator::Iterable;
use leveldb::options::{Options, ReadOptions};
use nomic::app::App;
use nomic::app::InnerApp;
use nomic::app::InnerAppFieldCall;
use nomic::app::Nom;
use nomic::orga::coins::accounts::AccountsMethodCall;
use nomic::orga::coins::Address;
use orga::call::Call;
use orga::call::Item;
use orga::encoding::Decode;
use orga::plugins::sdk_compat::sdk::Tx;
use orga::plugins::PayableCall;
use orga::plugins::{FeePlugin, NoncePlugin, PayablePlugin};
use prost::Message;
use std::ops::Deref;
use std::path::PathBuf;
use tendermint_proto::abci::TxResult;

#[derive(Parser, Debug)]
pub struct Opts {
    address: Address,
    tx_index_path: PathBuf,
    out_path: PathBuf,
}

type BaseCall = <App as Call>::Call;
type InnerAppCall = <InnerApp as Call>::Call;
type NoncePluginWrapper = NoncePlugin<PayablePlugin<FeePlugin<Nom, InnerApp>>>;

#[derive(Debug)]
struct Delegation {
    hash: Vec<u8>,
    height: i64,
    validator_address: String,
    amount: String,
}

#[derive(Debug)]
struct Redelegation {
    hash: Vec<u8>,
    height: i64,
    validator_src_address: String,
    validator_dst_address: String,
    amount: String,
}

#[derive(Debug)]
struct RewardClaim {
    hash: Vec<u8>,
    height: i64,
}

#[derive(Debug)]
struct Send {
    hash: Vec<u8>,
    height: i64,
    to: String,
    amount: String,
}

#[tokio::main]
pub async fn main() {
    let opts = Opts::parse();

    let mut options = Options::new();
    options.create_if_missing = true;
    let database = match Database::open(&opts.tx_index_path, &Options::new()) {
        Ok(db) => db,
        Err(e) => {
            panic!("failed to open database: {:?}", e)
        }
    };

    let mut delegation_data: Vec<Delegation> = Vec::new();
    let mut undelegation_data: Vec<Delegation> = Vec::new();
    let mut redelegation_data: Vec<Redelegation> = Vec::new();
    let mut claim_data: Vec<RewardClaim> = Vec::new();
    let mut send_data: Vec<Send> = Vec::new();

    database.iter(&ReadOptions::new()).for_each(|(key, value)| {
        if key.len() != 32 {
            return;
        }

        let tx_res = TxResult::decode(value.deref()).unwrap();
        let height = tx_res.height;
        let call_res = BaseCall::decode(tx_res.tx.as_ref());

        let call = call_res.unwrap();
        if let BaseCall::Sdk(tx) = call {
            match tx {
                Tx::Amino(amino_tx) => {
                    let msgs = amino_tx.msg.clone();
                    if msgs.len() < 1 {
                        return;
                    }
                    let msg = &msgs[0];
                    let pubkey = amino_tx.signatures[0].pub_key.value.clone();
                    let pubkey_bytes = base64::decode(pubkey).unwrap();
                    let address = Address::from_pubkey(pubkey_bytes.as_slice().try_into().unwrap());
                    if address != opts.address {
                        return;
                    }
                    if let Some(value_map) = msg.value.as_object() {
                        match msg.type_.as_str() {
                            "cosmos-sdk/MsgDelegate" => {
                                delegation_data.push(Delegation {
                                    hash: key.to_vec(),
                                    height,
                                    validator_address: value_map["validator_address"].to_string(),
                                    amount: value_map["amount"].to_string(),
                                });
                            }
                            "cosmos-sdk/MsgUndelegate" => {
                                undelegation_data.push(Delegation {
                                    hash: key.to_vec(),
                                    height,
                                    validator_address: value_map["validator_address"].to_string(),
                                    amount: value_map["amount"].to_string(),
                                });
                            }
                            "cosmos-sdk/MsgBeginRedelegate" => {
                                redelegation_data.push(Redelegation {
                                    hash: key.to_vec(),
                                    height,
                                    validator_src_address: value_map["validator_src_address"]
                                        .to_string(),
                                    validator_dst_address: value_map["validator_dst_address"]
                                        .to_string(),
                                    amount: value_map["amount"].to_string(),
                                });
                            }
                            "cosmos-sdk/MsgClaimRewards" => {
                                claim_data.push(RewardClaim {
                                    hash: key.to_vec(),
                                    height,
                                });
                            }
                            "cosmos-sdk/MsgSend" => {
                                send_data.push(Send {
                                    hash: key.to_vec(),
                                    height,
                                    to: value_map["to_address"].to_string(),
                                    amount: value_map["amount"].to_string(),
                                });
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        } else if let BaseCall::Native(call) = call {
            if let Some(pubkey) = call.pubkey {
                let address = Address::from_pubkey(pubkey.as_slice().try_into().unwrap());
                if address != opts.address {
                    return;
                }
                let bytes = &call.call_bytes["nomic-stakenet-3".len()..];
                let inner: <NoncePluginWrapper as Call>::Call = Decode::decode(bytes).unwrap();
                if let PayableCall::Paid(inner) = inner.inner_call {
                    match inner.paid {
                        Item::Field(inner) => match inner {
                            InnerAppFieldCall::Staking(_) => {}
                            InnerAppFieldCall::Accounts(call) => {
                                if let Item::Method(method_call) = call {
                                    match method_call {
                                        AccountsMethodCall::Transfer(address, amount) => {
                                            send_data.push(Send {
                                                hash: key.to_vec(),
                                                height,
                                                to: address.to_string(),
                                                amount: amount.to_string(),
                                            });
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            InnerAppFieldCall::Bitcoin(_) => {}
                            InnerAppFieldCall::Incentives(_) => {}
                            InnerAppFieldCall::Airdrop(_) => {}
                            InnerAppFieldCall::Noop(_) => {}
                        },
                        Item::Method(_) => {}
                    }
                }
            }
        }
    });

    let mut writer = csv::Writer::from_path(opts.out_path.join("delegations-606.csv")).unwrap();
    writer
        .write_record(&["height", "hash", "validator_address", "amount"])
        .unwrap();
    delegation_data
        .iter()
        .map(|d| {
            vec![
                d.height.to_string(),
                hex::encode(&d.hash),
                d.validator_address.clone(),
                d.amount.clone(),
            ]
        })
        .for_each(|row| {
            writer.write_record(row).unwrap();
        });
    writer.flush().unwrap();

    let mut writer = csv::Writer::from_path(opts.out_path.join("undelegations-606.csv")).unwrap();
    writer
        .write_record(&["height", "hash", "validator_address", "amount"])
        .unwrap();
    undelegation_data
        .iter()
        .map(|d| {
            vec![
                d.height.to_string(),
                hex::encode(&d.hash),
                d.validator_address.clone(),
                d.amount.clone(),
            ]
        })
        .for_each(|row| {
            writer.write_record(row).unwrap();
        });
    writer.flush().unwrap();

    let mut writer = csv::Writer::from_path(opts.out_path.join("redelegations-606.csv")).unwrap();
    writer
        .write_record(&[
            "height",
            "hash",
            "validator_src_address",
            "validator_dst_address",
            "amount",
        ])
        .unwrap();
    redelegation_data
        .iter()
        .map(|d| {
            vec![
                d.height.to_string(),
                hex::encode(&d.hash),
                d.validator_src_address.clone(),
                d.validator_dst_address.clone(),
                d.amount.clone(),
            ]
        })
        .for_each(|row| {
            writer.write_record(row).unwrap();
        });
    writer.flush().unwrap();

    let mut writer = csv::Writer::from_path(opts.out_path.join("claims-606.csv")).unwrap();
    writer.write_record(&["height", "hash"]).unwrap();
    claim_data
        .iter()
        .map(|d| vec![d.height.to_string(), hex::encode(&d.hash)])
        .for_each(|row| {
            writer.write_record(row).unwrap();
        });
    writer.flush().unwrap();

    let mut writer = csv::Writer::from_path(opts.out_path.join("transfers-606.csv")).unwrap();
    writer
        .write_record(&["height", "hash", "to", "amount"])
        .unwrap();
    send_data
        .iter()
        .map(|d| {
            vec![
                d.height.to_string(),
                hex::encode(&d.hash),
                d.to.clone(),
                d.amount.clone(),
            ]
        })
        .for_each(|row| {
            writer.write_record(row).unwrap();
        });
    writer.flush().unwrap();
}
