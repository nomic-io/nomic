use clap::Parser;
use bitcoincore_rpc::{Auth, Client, RpcApi};

#[derive(Parser, Debug)]
pub struct Opts {
    height: u64,

    #[clap(short = 'p', long, default_value_t = 8332)]
    rpc_port: u16,

    #[clap(short = 'u', long)]
    rpc_user: Option<String>,

    #[clap(short = 'P', long)]
    rpc_pass: Option<String>,
}

pub fn main() {
    let opts = Opts::parse();

    if opts.height % 2016 != 0 {
        panic!("height must be a multiple of 2016");
    }

    let rpc_url = format!("http://localhost:{}", opts.rpc_port);
    let auth = match (opts.rpc_user, opts.rpc_pass) {
        (Some(user), Some(pass)) => Auth::UserPass(user, pass),
        _ => Auth::None,
    };
    
    let client = Client::new(&rpc_url, auth).unwrap();

    let hash = client.get_block_hash(opts.height).unwrap();
    let header = client.get_block_header(&hash).unwrap();

    let header_json = serde_json::to_string_pretty(&header).unwrap();
    println!("{}", header_json);
}
