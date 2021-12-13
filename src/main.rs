#![feature(trivial_bounds)]
#![allow(incomplete_features)]
#![feature(specialization)]

use clap::Parser;
use orga::prelude::*;
use app::App;

mod app;
mod bitcoin;
mod error;

const NETWORK_NAME: &str = "guccinet";

pub fn rpc_client() -> TendermintClient<App> {
    TendermintClient::new("http://localhost:26657").unwrap()
}

#[derive(Parser, Debug)]
#[clap(version = "0.1", author = "The Nomic Developers <hello@nomic.io>")]
pub struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    Init(InitCmd),
    Start(StartCmd),
    Send(SendCmd),
    Balance(BalanceCmd),
    Delegations(DelegationsCmd),
    Delegate(DelegateCmd),
}

impl Command {
    async fn run(&self) -> Result<()> {
        use Command::*;
        match self {
            Init(cmd) => cmd.run().await,
            Start(cmd) => cmd.run().await,
            Send(cmd) => cmd.run().await,
            Balance(cmd) => cmd.run().await,
            Delegate(cmd) => cmd.run().await,
            Delegations(cmd) => cmd.run().await,
        }
    }
}


#[derive(Parser, Debug)]
pub struct InitCmd {}

impl InitCmd {
    async fn run(&self) -> Result<()> {
        tokio::task::spawn_blocking(|| {
            Node::<App>::new(NETWORK_NAME);
        })
        .await
        .map_err(|err| orga::Error::App(err.to_string()))?;
        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct StartCmd {}

impl StartCmd {
    async fn run(&self) -> Result<()> {
        tokio::task::spawn_blocking(|| {
            Node::<App>::new(NETWORK_NAME)
                .with_genesis(include_bytes!("../genesis.json"))
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .run()
        })
        .await
        .map_err(|err| orga::Error::App(err.to_string()))?;
        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SendCmd {
    to_addr: Address,
    amount: u64,
}

impl SendCmd {
    async fn run(&self) -> Result<()> {
        todo!()
    }
}

#[derive(Parser, Debug)]
pub struct DelegationsCmd;

impl DelegationsCmd {
    async fn run(&self) -> Result<()> {
        todo!()
    }
}

#[derive(Parser, Debug)]
pub struct BalanceCmd;

impl BalanceCmd {
    async fn run(&self) -> Result<()> {
        todo!()
    }
}

#[derive(Parser, Debug)]
pub struct DelegateCmd {
    validator_addr: String,
    amount: u64,
}

impl DelegateCmd {
    async fn run(&self) -> Result<()> {
        todo!()
    }
}

#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    opts.cmd.run().await.unwrap();
}
