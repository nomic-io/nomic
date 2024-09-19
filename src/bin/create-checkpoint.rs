//! Outputs a block header for Bitcoin in JSON, which can be used to bootstrap a
//! [nomic::bitcoin::HeaderQueue] state to avoid the need to sync all headers
//! from the genesis block. This command connects to the specified Bitcoin RPC
//! server and fetches the block header at the specified height, or the latest
//! block at the start of the previous retarget period if no height is
//! specified.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use bitcoincore_rpc_async::{Auth, Client, RpcApi};
use clap::Parser;

/// Command line options for the create-checkpoint command.
#[derive(Parser, Debug)]
pub struct Opts {
    /// The height of the block to output. Must be a multiple of 2016.
    ///
    /// If not specified, the latest block at the start of the previous
    /// retarget period will be used.
    height: Option<u64>,

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

/// Outputs a block header for Bitcoin in JSON.
#[tokio::main]
pub async fn main() {
    let opts = Opts::parse();

    let rpc_url = format!("http://localhost:{}", opts.rpc_port);
    let auth = match (opts.rpc_user, opts.rpc_pass) {
        (Some(user), Some(pass)) => Auth::UserPass(user, pass),
        _ => Auth::None,
    };
    let client = Client::new(rpc_url, auth).await.unwrap();

    let height = match opts.height {
        // TODO: support other retarget intervals
        Some(height) if height % 2016 != 0 => {
            panic!("height must be a multiple of 2016")
        }
        Some(height) => height,
        None => {
            let best_hash = client.get_best_block_hash().await.unwrap();
            let best_height = client
                .get_block_header_info(&best_hash)
                .await
                .unwrap()
                .height as u64;
            best_height - (best_height % 2016) - 2016
        }
    };

    let hash = client.get_block_hash(height).await.unwrap();
    let header = client.get_block_header(&hash).await.unwrap();

    let header_json = serde_json::to_string_pretty(&(height, header)).unwrap();
    println!("{}", header_json);
}
