use bitcoincore_rpc_async::{Auth, Client, RpcApi};
use clap::Parser;

#[derive(Parser, Debug)]
pub struct Opts {
    height: Option<u64>,

    #[clap(short = 'p', long, default_value_t = 8332)]
    rpc_port: u16,

    #[clap(short = 'u', long)]
    rpc_user: Option<String>,

    #[clap(short = 'P', long)]
    rpc_pass: Option<String>,
}

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
