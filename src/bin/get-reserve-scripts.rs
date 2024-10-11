//! This script is used to get the reserve scripts for the last N days by
//! fetching the chain of checkpoint transactions confirmed on Bitcoin.
//!
//! This is useful for backfilling checkpoint data, or for recovering deposits
//! against old checkpoints (e.g. in the `nomic recover-deposit` command).

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use bitcoincore_rpc_async::{Auth, Client, RpcApi};
use clap::Parser;

/// Command line options for the get-reserve-scripts command.
#[derive(Parser, Debug)]
pub struct Opts {
    /// The number of days to look back.
    #[clap(default_value_t = 30)]
    lookback_days: u64,

    /// The port of the Bitcoin RPC server.
    // TODO: get default based on network
    #[clap(short = 'p', long, default_value_t = 8332)]
    rpc_port: u16,

    /// The username for the Bitcoin RPC server.
    #[clap(short = 'u', long)]
    rpc_user: Option<String>,

    /// The password for the Bitcoin RPC server.
    #[clap(short = 'P', long)]
    rpc_pass: Option<String>,
}

/// Outputs the reserve scripts for the last N days.
#[tokio::main]
pub async fn main() {
    let opts = Opts::parse();

    let rpc_url = format!("http://localhost:{}", opts.rpc_port);
    let auth = match (opts.rpc_user, opts.rpc_pass) {
        (Some(user), Some(pass)) => Auth::UserPass(user, pass),
        _ => Auth::None,
    };
    let btc_client = Client::new(rpc_url, auth).await.unwrap();

    let nomic_client = nomic::app_client("http://localhost:26657");

    let (last_conf_index, last_conf_cp) = nomic_client
        .query(|app| {
            let conf_index = app.bitcoin.checkpoints.confirmed_index.unwrap();
            let conf_cp = app.bitcoin.checkpoints.get(conf_index)?;
            Ok((conf_index, conf_cp.checkpoint_tx()?.txid()))
        })
        .await
        .unwrap();

    let mut index = last_conf_index;
    let mut prev_txid = last_conf_cp;
    let mut block_hash = btc_client.get_best_block_hash().await.unwrap();
    let mut scripts = vec![];

    let target_time = now() - 60 * 60 * 24 * opts.lookback_days;

    loop {
        let block = btc_client.get_block_info(&block_hash).await.unwrap();
        let has_tx = block.tx.iter().any(|txid| *txid == prev_txid);
        if !has_tx {
            block_hash = block.previousblockhash.unwrap();
            continue;
        }

        let tx = btc_client
            .get_raw_transaction(&prev_txid, Some(&block_hash))
            .await
            .unwrap();
        prev_txid = tx.input[0].previous_output.txid;
        index -= 1;

        scripts.push((index, tx.input[0].witness.last().unwrap().to_vec()));

        if (block.time as u64) < target_time {
            break;
        }
    }

    for (index, script) in scripts.iter() {
        println!("{},{}", index, hex::encode(script));
    }
}

/// Returns the current time as a Unix timestamp (in seconds).
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
