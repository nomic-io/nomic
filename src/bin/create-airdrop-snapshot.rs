#![feature(hash_drain_filter)]

use clap::Parser;
use std::collections::HashMap;

#[derive(Parser, Debug)]
pub struct Opts {
    input_files: Vec<String>,

    #[clap(short, long)]
    skip_validators: usize,

    #[clap(short, long)]
    min_balance: u64,

    #[clap(short, long)]
    trim_decimals: Vec<u32>,
}

#[tokio::main]
pub async fn main() {
    let opts = Opts::parse();

    if opts.input_files.is_empty() {
        panic!("Must specify at least one input file");
    }

    if opts.trim_decimals.len() != opts.input_files.len() {
        panic!("Must specify one --trim-decimals flag for each input file");
    }

    let networks = opts
        .input_files
        .iter()
        .zip(opts.trim_decimals.iter())
        .map(|(path, trim_decimals)| {
            dbg!(&path, &trim_decimals);
            process_input(path.as_str(), opts.skip_validators, *trim_decimals)
        })
        .collect();
    let rows = to_rows(networks, opts.min_balance);

    let mut out = csv::Writer::from_writer(std::io::stdout());
    for row in rows {
        out.write_record(row).unwrap();
    }
}

type Recipient = (u64, u16);
type Recipients = HashMap<Vec<u8>, Recipient>;
type Network = (String, Recipients);

fn process_input(path: &str, skip_validators: usize, trim_decimals: u32) -> Network {
    let file = std::fs::read_to_string(path).unwrap();
    let data = serde_json::from_str::<serde_json::Value>(file.as_str()).unwrap();

    let chain_id = data["chain_id"].as_str().unwrap().to_string();
    let recipients = get_recipients(&data, skip_validators, trim_decimals);

    (chain_id, recipients)
}

fn get_included_vals(data: &serde_json::Value, skip_validators: usize) -> HashMap<String, f64> {
    let staking = &data["app_state"]["staking"];

    let mut vals: Vec<_> = staking["validators"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| {
            let jailed = v["jailed"].as_bool().unwrap();
            let status = v["status"].as_str().unwrap();
            if jailed || status != "BOND_STATUS_BONDED" {
                return None;
            }

            let addr = v["operator_address"].as_str().unwrap().to_string();
            let tokens: u128 = v["tokens"].as_str().unwrap().parse().unwrap();
            let shares: f64 = v["delegator_shares"].as_str().unwrap().parse().unwrap();
            let rate: f64 = tokens as f64 / shares;
            Some((addr, tokens, rate))
        })
        .collect();

    vals.sort_by(|a, b| b.1.cmp(&a.1));

    vals.into_iter()
        .skip(skip_validators)
        .map(|v| (v.0, v.2))
        .collect()
}

fn get_recipients(
    data: &serde_json::Value,
    skip_validators: usize,
    trim_decimals: u32,
) -> Recipients {
    let vals = get_included_vals(data, skip_validators);

    let mut recipients = HashMap::new();
    data["app_state"]["staking"]["delegations"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| {
            let val_addr = d["validator_address"].as_str().unwrap();
            vals.get(val_addr).map(|val_rate| {
                let del_addr = d["delegator_address"].as_str().unwrap();
                let shares: f64 = d["shares"].as_str().unwrap().parse().unwrap();
                let tokens = (shares * val_rate / 10f64.powf(trim_decimals as f64)) as u64;
                (decode_addr(del_addr), tokens)
            })
        })
        .for_each(|(del_addr, tokens)| {
            recipients
                .entry(del_addr)
                .and_modify(|(accum_tokens, count)| {
                    *accum_tokens += tokens;
                    *count += 1;
                })
                .or_insert((tokens, 1));
        });

    recipients
}

fn to_rows(networks: Vec<Network>, min_balance: u64) -> Vec<Vec<String>> {
    let headers = std::iter::once("address".to_string())
        .chain(networks.iter().flat_map(|(chain_id, _)| {
            vec![
                format!("{}_staked", chain_id),
                format!("{}_count", chain_id),
            ]
        }))
        .collect();

    let mut combined: HashMap<String, (u64, Vec<String>)> = HashMap::new();
    for (i, (_, recipients)) in networks.into_iter().enumerate() {
        let len = (i + 1) * 2;

        for (addr, (staked, count)) in recipients {
            let extend = |row: &mut (u64, Vec<String>)| {
                row.0 += staked;
                row.1.extend([staked.to_string(), count.to_string()])
            };
            combined
                .entry(encode_addr(addr))
                .and_modify(extend)
                .or_insert_with(|| {
                    let mut row = (0, vec!["0".to_string(); len - 2]);
                    extend(&mut row);
                    row
                });
        }

        for (_, row) in combined.iter_mut() {
            let add = len - row.1.len();
            row.1.extend(vec!["0".to_string(); add]);
        }
    }

    combined.drain_filter(|_, (balance, _)| *balance < min_balance);

    let mut rows: Vec<_> = std::iter::once(headers)
        .chain(combined.into_iter().map(|(addr, (_, fields))| {
            let mut row = vec![addr];
            row.extend(fields);
            row
        }))
        .collect();

    rows.sort_by(|a, b| a[0].cmp(&b[0]));

    rows
}

fn decode_addr(addr: &str) -> Vec<u8> {
    use bech32::FromBase32;
    let (_, data, _) = bech32::decode(addr).unwrap();
    Vec::<u8>::from_base32(&data).unwrap()
}

fn encode_addr(data: Vec<u8>) -> String {
    use bech32::ToBase32;
    let data = data.to_base32();
    bech32::encode("nomic", data, bech32::Variant::Bech32).unwrap()
}
