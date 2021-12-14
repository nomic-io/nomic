#![feature(trivial_bounds)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(async_closure)]
#![feature(never_type)]

use crate::bitcoin::relayer::Relayer;
use app::*;
use bitcoincore_rpc::{Auth, Client as BtcClient};
use clap::Parser;
use orga::prelude::*;

mod app;
mod bitcoin;
mod error;

const NETWORK_NAME: &str = "guccinet";

pub fn app_client() -> TendermintClient<app::App> {
    TendermintClient::new("http://localhost:26657").unwrap()
}

fn my_address() -> Address {
    load_keypair().unwrap().public.to_bytes().into()
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
    Declare(DeclareCmd),
    Unbond(UnbondCmd),
    Claim(ClaimCmd),
    Relayer(RelayerCmd),
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
            Declare(cmd) => cmd.run().await,
            Delegations(cmd) => cmd.run().await,
            Unbond(cmd) => cmd.run().await,
            Claim(cmd) => cmd.run().await,
            Relayer(cmd) => cmd.run().await,
        }
    }
}

#[derive(Parser, Debug)]
pub struct InitCmd {}

impl InitCmd {
    async fn run(&self) -> Result<()> {
        tokio::task::spawn_blocking(|| {
            Node::<app::App>::new(NETWORK_NAME);
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
            Node::<app::App>::new(NETWORK_NAME)
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
        app_client()
            .accounts
            .transfer(self.to_addr, self.amount.into())
            .await
    }
}

#[derive(Parser, Debug)]
pub struct BalanceCmd;

impl BalanceCmd {
    async fn run(&self) -> Result<()> {
        let address = my_address();
        let client = app_client();
        type AppQuery = <InnerApp as Query>::Query;
        type AcctQuery = <Accounts<Gucci> as Query>::Query;

        let q = AppQuery::FieldAccounts(AcctQuery::MethodBalance(address, vec![]));
        let balance: u64 = client
            .query(q, |state| state.accounts.balance(address))
            .await?
            .into();

        println!("address: {}", address);
        println!("balance: {} GUCCI", balance);

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DelegationsCmd;

impl DelegationsCmd {
    async fn run(&self) -> Result<()> {
        let address = my_address();

        type AppQuery = <InnerApp as Query>::Query;
        type StakingQuery = <Staking<Gucci> as Query>::Query;

        let delegations = app_client()
            .query(
                AppQuery::FieldStaking(StakingQuery::MethodDelegations(address, vec![])),
                |state| state.staking.delegations(address),
            )
            .await?;

        println!(
            "delegated to {} validator{}",
            delegations.len(),
            if delegations.len() == 1 { "" } else { "s" }
        );
        for (validator, delegation) in delegations {
            let staked: u64 = delegation.staked.into();
            let liquid: u64 = delegation.liquid.into();
            println!(
                "- {}: staked={} GUCCI, liquid={} GUCCI",
                validator, staked, liquid
            );
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DelegateCmd {
    validator_addr: Address,
    amount: u64,
}

impl DelegateCmd {
    async fn run(&self) -> Result<()> {
        app_client()
            .pay_from(async move |mut client| {
                client.accounts.take_as_funding(self.amount.into()).await
            })
            .staking
            .delegate_from_self(self.validator_addr, self.amount.into())
            .await
    }
}

#[derive(Parser, Debug)]
pub struct DeclareCmd {
    consensus_key: String,
    amount: u64,
}

impl DeclareCmd {
    async fn run(&self) -> Result<()> {
        use std::convert::TryInto;
        let consensus_key: [u8; 32] = base64::decode(&self.consensus_key)
            .map_err(|_| orga::Error::App("invalid consensus key".to_string()))?
            .try_into()
            .map_err(|_| orga::Error::App("invalid consensus key".to_string()))?;
        let consensus_key: Address = consensus_key.into();

        app_client()
            .pay_from(async move |mut client| {
                client.accounts.take_as_funding(self.amount.into()).await
            })
            .staking
            .declare_self(consensus_key, self.amount.into())
            .await
    }
}

#[derive(Parser, Debug)]
pub struct UnbondCmd {
    validator_addr: Address,
    amount: u64,
}

impl UnbondCmd {
    async fn run(&self) -> Result<()> {
        app_client()
            .staking
            .unbond_self(self.validator_addr, self.amount.into())
            .await
    }
}

#[derive(Parser, Debug)]
pub struct ClaimCmd;

impl ClaimCmd {
    async fn run(&self) -> Result<()> {
        let address = my_address();

        type AppQuery = <InnerApp as Query>::Query;
        type StakingQuery = <Staking<Gucci> as Query>::Query;

        let delegations = app_client()
            .query(
                AppQuery::FieldStaking(StakingQuery::MethodDelegations(address, vec![])),
                |state| state.staking.delegations(address),
            )
            .await?;

        for (validator, delegation) in delegations {
            let liquid: u64 = delegation.liquid.into();
            if liquid <= 1 {
                continue;
            }
            let liquid = liquid - 1;

            app_client()
                .pay_from(async move |mut client| {
                    client
                        .staking
                        .take_as_funding(validator, delegation.liquid)
                        .await
                })
                .accounts
                .give_from_funding(liquid.into())
                .await?;

            println!("claimed {} GUCCI from {}", liquid, validator);
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct RelayerCmd {
    btc_rpc_user: String,
    btc_rpc_pass: String,
}

impl RelayerCmd {
    async fn run(&self) -> Result<()> {
        let auth = Auth::UserPass(self.btc_rpc_user.clone(), self.btc_rpc_pass.clone());
        let btc_rpc = BtcClient::new("http://127.0.0.1:8332", auth).unwrap();

        println!("starting relayer");
        let mut relayer = Relayer::new(btc_rpc, app_client());
        relayer.start().await.unwrap();
    }
}

#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    opts.cmd.run().await.unwrap();
}
