#![feature(trivial_bounds)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(async_closure)]
#![feature(never_type)]

use bitcoincore_rpc::{Auth, Client as BtcClient};
use clap::Parser;
use nomic::app::*;
use orga::prelude::*;
use serde::{Deserialize, Serialize};

pub fn app_client() -> TendermintClient<nomic::app::App> {
    TendermintClient::new("http://localhost:26657").unwrap()
}

fn my_address() -> Address {
    let privkey = load_privkey().unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &privkey);
    Address::from_pubkey(pubkey.serialize())
}

#[derive(Parser, Debug)]
#[clap(
    version = env!("CARGO_PKG_VERSION"),
    author = "The Nomic Developers <hello@nomic.io>"
)]
pub struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    Init(InitCmd),
    Start(StartCmd),
    #[cfg(debug)]
    StartDev(StartDevCmd),
    Send(SendCmd),
    Balance(BalanceCmd),
    Delegations(DelegationsCmd),
    Validators(ValidatorsCmd),
    Delegate(DelegateCmd),
    Declare(DeclareCmd),
    Unbond(UnbondCmd),
    Claim(ClaimCmd),
    ClaimAirdrop(ClaimAirdropCmd),
}

impl Command {
    async fn run(&self) -> Result<()> {
        use Command::*;
        match self {
            Init(cmd) => cmd.run().await,
            Start(cmd) => cmd.run().await,
            #[cfg(debug)]
            StartDev(cmd) => cmd.run().await,
            Send(cmd) => cmd.run().await,
            Balance(cmd) => cmd.run().await,
            Delegate(cmd) => cmd.run().await,
            Declare(cmd) => cmd.run().await,
            Delegations(cmd) => cmd.run().await,
            Validators(cmd) => cmd.run().await,
            Unbond(cmd) => cmd.run().await,
            Claim(cmd) => cmd.run().await,
            ClaimAirdrop(cmd) => cmd.run().await,
        }
    }
}

#[derive(Parser, Debug)]
pub struct InitCmd {}

impl InitCmd {
    async fn run(&self) -> Result<()> {
        tokio::task::spawn_blocking(|| {
            // TODO: add cfg defaults
            Node::<nomic::app::App>::new(CHAIN_ID, Default::default());
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
            let old_name = nomicv1::app::CHAIN_ID;
            let new_name = nomic::app::CHAIN_ID;

            let has_old_node = Node::home(old_name).exists();
            let has_new_node = Node::home(new_name).exists();
            let started_new_node = Node::height(new_name).unwrap() > 0;

            if !has_new_node {
                let new_home = Node::home(new_name);
                println!("Initializing node at {}...", new_home.display());
                // TODO: configure default seeds and timeout_commit
                Node::<nomic::app::App>::new(new_name, Default::default());

                if has_old_node {
                    let old_home = Node::home(old_name);
                    println!(
                        "Legacy network data detected, copying keys and config from {}...",
                        old_home.display()
                    );

                    std::fs::copy(
                        old_home.join("tendermint/config/priv_validator_key.json"),
                        new_home.join("tendermint/config/priv_validator_key.json"),
                    )
                    .unwrap();
                    std::fs::copy(
                        old_home.join("tendermint/config/node_key.json"),
                        new_home.join("tendermint/config/node_key.json"),
                    )
                    .unwrap();
                    // TODO: remove copying config for v1 -> v2
                    std::fs::copy(
                        old_home.join("tendermint/config/config.toml"),
                        new_home.join("tendermint/config/config.toml"),
                    )
                    .unwrap();
                }
            }

            if has_old_node && !started_new_node {
                println!("Starting legacy node for migration...");

                let res = nomicv1::orga::abci::Node::<nomicv1::app::App>::new(old_name)
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit())
                    .stop_height(500)
                    .run();

                if let Err(nomicv1::orga::Error::ABCI(msg)) = res {
                    if &msg != "Reached stop height" {
                        panic!("{}", msg);
                    }
                } else {
                    res.unwrap();
                }
            }

            println!("Starting node...");
            // TODO: add cfg defaults
            Node::<nomic::app::App>::new(new_name, Default::default())
                .with_genesis(include_bytes!("../../genesis/practicenet-3-post.json"))
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .run()
                .unwrap();
        })
        .await
        .map_err(|err| orga::Error::App(err.to_string()))?;
        Ok(())
    }
}

#[cfg(debug)]
#[derive(Parser, Debug)]
pub struct StartDevCmd {}

#[cfg(debug)]
impl StartDevCmd {
    async fn run(&self) -> Result<()> {
        tokio::task::spawn_blocking(|| unimplemented!())
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
            .pay_from(async move |mut client| client.accounts.take_as_funding(MIN_FEE.into()).await)
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
        println!("address: {}", address);

        let balance = app_client().accounts.balance(address).await??;
        println!("balance: {} NOM", balance);

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DelegationsCmd;

impl DelegationsCmd {
    async fn run(&self) -> Result<()> {
        let address = my_address();
        let delegations = app_client().staking.delegations(address).await??;

        println!(
            "delegated to {} validator{}",
            delegations.len(),
            if delegations.len() == 1 { "" } else { "s" }
        );
        for (validator, delegation) in delegations {
            let staked: u64 = delegation.staked.into();
            let liquid: u64 = delegation.liquid.into();
            if staked + liquid == 0 {
                continue;
            }
            println!(
                "- {}: staked={} NOM, liquid={} NOM",
                validator, staked, liquid
            );
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct ValidatorsCmd;

impl ValidatorsCmd {
    async fn run(&self) -> Result<()> {
        let validators = app_client().staking.all_validators().await??;

        for validator in validators {
            let info: DeclareInfo =
                serde_json::from_slice(validator.info.bytes.as_slice()).unwrap();
            println!(
                "- {}\n\tVOTING POWER: {}\n\tMONIKER: {}\n\tDETAILS: {}",
                validator.address, validator.amount_staked, info.moniker, info.details
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
                client
                    .accounts
                    .take_as_funding((self.amount + MIN_FEE).into())
                    .await
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
    commission_rate: Decimal,
    commission_max: Decimal,
    commission_max_change: Decimal,
    min_self_delegation: u64,
    moniker: String,
    website: String,
    identity: String,
    details: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeclareInfo {
    moniker: String,
    website: String,
    identity: String,
    details: String,
}

impl DeclareCmd {
    async fn run(&self) -> Result<()> {
        use std::convert::TryInto;
        let consensus_key: [u8; 32] = base64::decode(&self.consensus_key)
            .map_err(|_| orga::Error::App("invalid consensus key".to_string()))?
            .try_into()
            .map_err(|_| orga::Error::App("invalid consensus key".to_string()))?;

        let info = DeclareInfo {
            moniker: self.moniker.clone(),
            website: self.website.clone(),
            identity: self.identity.clone(),
            details: self.details.clone(),
        };
        let info_json = serde_json::to_string(&info)
            .map_err(|_| orga::Error::App("invalid json".to_string()))?;
        let info_bytes = info_json.as_bytes().to_vec();

        let declaration = Declaration {
            consensus_key,
            amount: self.amount.into(),
            validator_info: info_bytes.into(),
            commission: Commission {
                rate: self.commission_rate,
                max: self.commission_max,
                max_change: self.commission_max_change,
            },
            min_self_delegation: self.min_self_delegation.into(),
        };

        app_client()
            .pay_from(async move |mut client| {
                client
                    .accounts
                    .take_as_funding((self.amount + MIN_FEE).into())
                    .await
            })
            .staking
            .declare_self(declaration)
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
            .pay_from(async move |mut client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .unbond_self(self.validator_addr, self.amount.into())
            .await
    }
}

#[derive(Parser, Debug)]
pub struct ClaimCmd;

impl ClaimCmd {
    async fn run(&self) -> Result<()> {
        app_client()
            .pay_from(async move |mut client| client.staking.claim_all().await)
            .accounts
            .give_from_funding_all()
            .await
    }
}

#[derive(Parser, Debug)]
pub struct ClaimAirdropCmd;

impl ClaimAirdropCmd {
    async fn run(&self) -> Result<()> {
        app_client()
            .pay_from(async move |mut client| client.atom_airdrop.claim().await)
            .accounts
            .give_from_funding_all()
            .await
    }
}

#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    if let Err(err) = opts.cmd.run().await {
        eprintln!("{}", err);
        std::process::exit(1);
    };
}
