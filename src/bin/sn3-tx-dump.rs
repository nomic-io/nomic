use clap::Parser;
use leveldb::database::Database;
use leveldb::iterator::Iterable;
use leveldb::options::{Options, ReadOptions};
use nomic::app::App;
use nomic::app::InnerApp;
use nomic::app::Nom;
use nomic::orga::coins::Address;
use orga::call::Call;
use orga::coins::Accounts;
use orga::coins::Staking;
use orga::encoding::Decode;
use orga::plugins::PayableCall;
use orga::plugins::{FeePlugin, NoncePlugin, PayablePlugin};
use prost::Message;
use std::convert::TryInto;
use std::ops::Deref;
use std::path::PathBuf;
use tendermint_proto::types::Block;
use tendermint_proto::types::Part;

#[derive(Parser, Debug)]
pub struct Opts {
    address: Address,
    blockdata_path: PathBuf,
    out_path: PathBuf,
}

type BaseCall = <App as Call>::Call;
type InnerAppCall = <InnerApp as Call>::Call;
type AccountsCall = <Accounts<Nom> as Call>::Call;
type StakingCall = <Staking<Nom> as Call>::Call;
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
    let database = match Database::open(&opts.blockdata_path, &Options::new()) {
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

    for (key, value) in database.iter(&ReadOptions::new()) {
        let key_string = std::str::from_utf8(key.deref()).unwrap();
        if !key_string.starts_with("P:") {
            continue;
        }
        let key_parts = key_string.split(":").collect::<Vec<&str>>();
        let height = key_parts[1].parse::<i64>().unwrap();

        let part = Part::decode(value.deref()).unwrap();

        //NEED THE ACTUAL HASH STILL
        let key = [0; 32];
        let mut block_parts = vec![part];
        block_parts.sort_by(|a, b| a.index.cmp(&b.index));
        let mut block_bytes = Vec::new();
        for part in block_parts.iter() {
            block_bytes.extend_from_slice(&part.bytes);
        }
        let block = Block::decode(block_bytes.as_slice()).unwrap();
        if block.data.is_none() {
            // JUDD: would unwrap here, not sure if possible
            continue;
        }
        for tx in block.data.unwrap().txs.iter() {
            //tx is orga bytes
            let call_res = BaseCall::decode::<&[u8]>(tx.as_ref());
            let call = call_res.unwrap();
            if let BaseCall::Sdk(tx) = call {
                let msgs = tx.msg.clone();
                if msgs.len() < 1 {
                    continue;
                }
                let msg = &msgs[0];
                let pubkey = tx.signatures[0].pub_key.value.clone();
                let pubkey_bytes = base64::decode(pubkey).unwrap();
                let address = Address::from_pubkey(pubkey_bytes.as_slice().try_into().unwrap());
                if address != opts.address {
                    continue;
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
            } else if let BaseCall::Native(call) = call {
                if let Some(pubkey) = call.pubkey {
                    let address = Address::from_pubkey(pubkey.as_slice().try_into().unwrap());
                    if address != opts.address {
                        continue;
                    }

                    let bytes = &call.call_bytes["nomic-stakenet-3".len()..];
                    let inner: <NoncePluginWrapper as Call>::Call = Decode::decode(bytes).unwrap();
                    if let PayableCall::Paid(inner) = inner.inner_call {
                        match inner.paid {
                            InnerAppCall::FieldStaking(inner) => {
                                let staking_call = StakingCall::decode(inner.as_slice()).unwrap();

                                match staking_call {
                                    StakingCall::MethodDelegateFromSelf(
                                        validator_address,
                                        amount,
                                        _,
                                    ) => {
                                        delegation_data.push(Delegation {
                                            hash: key.to_vec(),
                                            height,
                                            validator_address: validator_address.to_string(),
                                            amount: amount.to_string(),
                                        });
                                    }
                                    StakingCall::MethodUnbondSelf(validator_address, amount, _) => {
                                        undelegation_data.push(Delegation {
                                            hash: key.to_vec(),
                                            height,
                                            validator_address: validator_address.to_string(),
                                            amount: amount.to_string(),
                                        });
                                    }
                                    StakingCall::MethodRedelegateSelf(
                                        validator_src_address,
                                        validator_dst_address,
                                        amount,
                                        _,
                                    ) => {
                                        redelegation_data.push(Redelegation {
                                            hash: key.to_vec(),
                                            height,
                                            validator_src_address: validator_src_address
                                                .to_string(),
                                            validator_dst_address: validator_dst_address
                                                .to_string(),
                                            amount: amount.to_string(),
                                        });
                                    }
                                    StakingCall::MethodClaimAll(_) => {
                                        claim_data.push(RewardClaim {
                                            hash: key.to_vec(),
                                            height,
                                        });
                                    }
                                    _ => {}
                                }
                            }
                            InnerAppCall::FieldAccounts(inner) => {
                                let account_call = AccountsCall::decode(inner.as_slice()).unwrap();

                                match account_call {
                                    AccountsCall::MethodTransfer(to, amount, _) => {
                                        send_data.push(Send {
                                            hash: key.to_vec(),
                                            height,
                                            to: to.to_string(),
                                            amount: amount.to_string(),
                                        });
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    let mut writer = csv::Writer::from_path(opts.out_path.join("delegations-2.csv")).unwrap();
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

    let mut writer = csv::Writer::from_path(opts.out_path.join("undelegations-2.csv")).unwrap();
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

    let mut writer = csv::Writer::from_path(opts.out_path.join("redelegations-2.csv")).unwrap();
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

    let mut writer = csv::Writer::from_path(opts.out_path.join("claims-2.csv")).unwrap();
    writer.write_record(&["height", "hash"]).unwrap();
    claim_data
        .iter()
        .map(|d| vec![d.height.to_string(), hex::encode(&d.hash)])
        .for_each(|row| {
            writer.write_record(row).unwrap();
        });
    writer.flush().unwrap();

    let mut writer = csv::Writer::from_path(opts.out_path.join("transfers-2.csv")).unwrap();
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
