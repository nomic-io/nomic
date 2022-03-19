#![feature(trivial_bounds)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(async_closure)]
#![feature(never_type)]

use clap::Parser;
mod command;
use command::Opts;
mod app;

#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    if let Err(err) = opts.cmd.run().await {
        eprintln!("{}", err);
        std::process::exit(1);
    };
}
