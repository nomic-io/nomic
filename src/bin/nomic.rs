#![feature(trivial_bounds)]
#![allow(incomplete_features)]
#![feature(specialization)]
#![feature(async_closure)]
#![feature(never_type)]

use std::convert::TryInto;
use std::env::Args;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::str::FromStr;

use bitcoincore_rpc_async::{Auth, Client as BtcClient};
use clap::Parser;
use futures::executor::block_on;
use nomic::app::{AppV0, DepositCommitment, IbcDepositCommitment};
use nomic::bitcoin::{relayer::Relayer, signer::Signer};
use nomic::error::Result;
use nomic::network::Network;
use orga::encoding::Decode;
use orga::merk::merk::Merk;
use orga::merk::MerkStore;
use orga::migrate::MigrateInto;
use orga::prelude::*;
use serde::{Deserialize, Serialize};
use tendermint_rpc::Client as _;

fn now_seconds() -> i64 {
    use std::time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

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
    Start(StartCmd),
    Send(SendCmd),
    SendNbtc(SendNbtcCmd),
    Balance(BalanceCmd),
    Delegations(DelegationsCmd),
    Validators(ValidatorsCmd),
    Delegate(DelegateCmd),
    Declare(DeclareCmd),
    Unbond(UnbondCmd),
    Redelegate(RedelegateCmd),
    Unjail(UnjailCmd),
    Edit(EditCmd),
    Claim(ClaimCmd),
    Airdrop(AirdropCmd),
    ClaimAirdrop(ClaimAirdropCmd),
    Relayer(RelayerCmd),
    Signer(SignerCmd),
    SetSignatoryKey(SetSignatoryKeyCmd),
    Deposit(DepositCmd),
    InterchainDeposit(InterchainDepositCmd),
    Withdraw(WithdrawCmd),
    IbcDepositNbtc(IbcDepositNbtcCmd),
    IbcWithdrawNbtc(IbcWithdrawNbtcCmd),
    Grpc(GrpcCmd),
    IbcTransfer(IbcTransferCmd),
}

impl Command {
    async fn run(&self) -> Result<()> {
        use Command::*;
        match self {
            Start(cmd) => cmd.run().await,
            Send(cmd) => cmd.run().await,
            SendNbtc(cmd) => cmd.run().await,
            Balance(cmd) => cmd.run().await,
            Delegate(cmd) => cmd.run().await,
            Declare(cmd) => cmd.run().await,
            Delegations(cmd) => cmd.run().await,
            Validators(cmd) => cmd.run().await,
            Unbond(cmd) => cmd.run().await,
            Redelegate(cmd) => cmd.run().await,
            Unjail(cmd) => cmd.run().await,
            Edit(cmd) => cmd.run().await,
            Claim(cmd) => cmd.run().await,
            ClaimAirdrop(cmd) => cmd.run().await,
            Airdrop(cmd) => cmd.run().await,
            Relayer(cmd) => cmd.run().await,
            Signer(cmd) => cmd.run().await,
            SetSignatoryKey(cmd) => cmd.run().await,
            Deposit(cmd) => cmd.run().await,
            InterchainDeposit(cmd) => cmd.run().await,
            Withdraw(cmd) => cmd.run().await,
            IbcDepositNbtc(cmd) => cmd.run().await,
            IbcWithdrawNbtc(cmd) => cmd.run().await,
            Grpc(cmd) => cmd.run().await,
            IbcTransfer(cmd) => cmd.run().await,
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct StartCmd {
    #[clap(long, default_value = "mainnet")]
    pub network: Network,
    #[clap(long)]
    pub state_sync: bool,
    #[clap(long)]
    pub tendermint_logs: bool,
    #[clap(long)]
    pub clone_store: Option<String>,
    #[clap(long)]
    pub reset_store_height: bool,
    #[clap(long)]
    pub reset: bool,
    #[clap(long)]
    pub skip_init_chain: bool,
    #[clap(long)]
    pub chain_id: Option<String>,
    #[cfg(feature = "compat")]
    #[clap(long)]
    pub legacy_home: Option<String>,
    #[cfg(feature = "compat")]
    #[clap(long)]
    pub upgrade_time: Option<i64>,
    #[cfg(not(feature = "compat"))]
    #[clap(long)]
    pub legacy_bin: Option<String>,
    #[cfg(not(feature = "compat"))]
    #[clap(long)]
    pub legacy_version: Option<String>,
    #[clap(long)]
    pub home: Option<String>,
    #[clap(long)]
    pub migrate: bool,
    #[clap(long)]
    pub freeze_valset: bool,
    #[clap(long)]
    pub genesis: Option<String>,
    #[clap(long)]
    pub signal_version: Option<String>,
    pub tendermint_flags: Vec<String>,
}

impl StartCmd {
    async fn run(&self) -> Result<()> {
        let cmd = self.clone();

        tokio::task::spawn_blocking(move || {
            let home = cmd.home.map_or_else(
                || {
                    Node::home(
                        &cmd.chain_id
                            .expect("Expected a chain-id or home directory to be set"),
                    )
                },
                |home| PathBuf::from_str(&home).unwrap(),
            );

            #[cfg(feature = "compat")]
            match (cmd.legacy_home, cmd.upgrade_time) {
                (Some(legacy_home), Some(upgrade_time)) => {
                    let legacy_home = PathBuf::from_str(&legacy_home).unwrap();

                    let store_path = legacy_home.join("merk");
                    let store = MerkStore::new(store_path);
                    let timestamp = store
                        .merk()
                        .get_aux(b"timestamp")?
                        .map(|ts| i64::decode(ts.as_slice()))
                        .transpose()?
                        .unwrap_or_default();
                    drop(store);
                    log::debug!("Legacy timestamp: {}", timestamp);

                    if timestamp < upgrade_time {
                        let bin_path = legacy_home.join("nomic-v4");
                        // TODO: check version

                        let mut cmd = std::process::Command::new(bin_path);
                        cmd.arg("start").env("STOP_TIME", upgrade_time.to_string());
                        log::info!("Starting legacy node... ({:#?})", cmd);
                        // TODO: verify output (or return code) of legacy node shows it exited cleanly
                        cmd.spawn()?.wait()?;
                    } else {
                        log::info!("Upgrade time has passed");
                    }
                }
                (None, None) => {}
                _ => panic!("Must specify both --legacy-home and --upgrade-time"),
            }

            #[cfg(not(feature = "compat"))]
            if let Some(legacy_bin) = cmd.legacy_bin {
                let version_hex = hex::encode([nomic::app::CONSENSUS_VERSION]);

                let net_ver_path = home.join("network_version");
                let up_to_date = if net_ver_path.exists() {
                    let net_ver = String::from_utf8(std::fs::read(net_ver_path).unwrap())
                        .unwrap()
                        .trim()
                        .to_string();
                    version_hex == net_ver
                } else {
                    false
                };

                if up_to_date {
                    log::info!("Node version matches network version, ignoring --legacy-bin");
                } else {
                    let mut cmd = std::process::Command::new(legacy_bin);
                    cmd.args([
                        "start",
                        "--signal-version",
                        &version_hex,
                        "--home",
                        home.to_str().unwrap(),
                    ]);
                    log::info!("Starting legacy node... ({:#?})", cmd);
                    let res = cmd.spawn()?.wait()?;
                    dbg!(res.signal(), res.stopped_signal(), res.code());
                    match res.code() {
                        Some(138) => {
                            log::info!("Legacy node exited for upgrade");
                        }
                        Some(code) => {
                            log::error!("Legacy node exited unexpectedly");
                            std::process::exit(code);
                        }
                        None => panic!("Legacy node exited unexpectedly"),
                    }
                }
            }

            let has_node = home.exists();
            let started_node = Node::height(&home).unwrap() > 0;
            let config_path = home.join("tendermint/config/config.toml");
            if !has_node {
                log::info!("Initializing node at {}...", home.display());

                let mut node = Node::<nomic::app::App>::new(&home, Default::default());

                if let Some(source) = cmd.clone_store {
                    let mut source = PathBuf::from_str(&source).unwrap();
                    if std::fs::read_dir(&source)?
                        .find(|c| c.as_ref().unwrap().file_name() == "merk")
                        .is_some()
                    {
                        source = source.join("merk");
                    }
                    log::info!("Cloning store from {}...", source.display());
                    node = node.init_from_store(
                        source,
                        if cmd.reset_store_height {
                            Some(0)
                        } else {
                            None
                        },
                    );
                }

                edit_block_time(&config_path, "3s");
            }

            let bin_path = home.join(format!("bin/nomic-{}", env!("CARGO_PKG_VERSION")));
            if !bin_path.exists() {
                log::debug!("Writing binary to {}", bin_path.display());
                let current_exe_bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
                std::fs::create_dir_all(home.join("bin")).unwrap();
                std::fs::write(&bin_path, current_exe_bytes).unwrap();
                std::fs::set_permissions(bin_path, Permissions::from_mode(0o777)).unwrap();
            }

            log::info!("Starting node at {}...", home.display());
            let mut node = Node::<nomic::app::App>::new(&home, Default::default());

            if cmd.reset {
                node = node.reset();
            }
            if cmd.migrate {
                node = node.migrate::<AppV0>();
            }
            if cmd.skip_init_chain {
                node = node.skip_init_chain();
            }
            if cmd.freeze_valset {
                std::env::set_var("ORGA_STATIC_VALSET", "true");
            }
            if let Some(genesis_path) = cmd.genesis {
                let genesis_bytes = std::fs::read(genesis_path)?;
                std::fs::write(home.join("tendermint/config/genesis.json"), genesis_bytes)?;
            }
            if let Some(signal_version) = cmd.signal_version {
                let signal_version = hex::decode(signal_version).unwrap();
                tokio::spawn(async move {
                    let signal_version = signal_version.clone();
                    let signal_version2 = signal_version.clone();
                    let signal_version3 = signal_version.clone();
                    let done = move || {
                        log::info!("Node has signaled {:?}", signal_version2);
                    };

                    loop {
                        let signal_version = signal_version.clone();
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        if let Err(err) = app_client()
                            .pay_from(async move |client| {
                                client.signal(signal_version.try_into().unwrap()).await
                            })
                            .noop()
                            .await
                        {
                            let msg = err.to_string();
                            if msg.ends_with("has already been signaled") {
                                return done();
                            } else {
                                log::debug!("Error when signaling: {}", msg);
                                continue;
                            }
                        } else {
                            log::info!("Signaled version {:?}", signal_version3);
                            return done();
                        }
                    }
                });
            }

            node.stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .print_tendermint_logs(cmd.tendermint_logs)
                .tendermint_flags(cmd.tendermint_flags)
                .run()
        })
        .await
        .unwrap()?;

        Ok(())
    }
}

fn configure_node<P, F>(cfg_path: &P, configure: F)
where
    P: AsRef<std::path::Path>,
    F: Fn(&mut toml_edit::Document),
{
    let data = std::fs::read_to_string(cfg_path).expect("Failed to read config.toml");

    let mut toml = data
        .parse::<toml_edit::Document>()
        .expect("Failed to parse config.toml");

    configure(&mut toml);

    std::fs::write(cfg_path, toml.to_string()).expect("Failed to write config.toml");
}

fn edit_block_time(cfg_path: &PathBuf, timeout_commit: &str) {
    configure_node(cfg_path, |cfg| {
        cfg["consensus"]["timeout_commit"] = toml_edit::value(timeout_commit);
    });
}

// TODO: append instead of replace
fn set_p2p_seeds(cfg_path: &PathBuf, seeds: &[&str]) {
    configure_node(cfg_path, |cfg| {
        cfg["p2p"]["seeds"] = toml_edit::value(seeds.join(","));
    });
}

fn deconfigure_statesync(cfg_path: &PathBuf) {
    configure_node(cfg_path, |cfg| {
        cfg["statesync"]["enable"] = toml_edit::value(false);
        cfg["statesync"]["rpc_servers"] = toml_edit::value("");
        cfg["statesync"]["trust_height"] = toml_edit::value(0);
        cfg["statesync"]["trust_hash"] = toml_edit::value("");
        cfg["statesync"]["trust_period"] = toml_edit::value("216h0m0s");
    });
}

fn configure_for_statesync(cfg_path: &PathBuf, rpc_servers: &[&str]) {
    log::info!("Getting bootstrap state for Tendermint light client...");
    let (height, hash) =
        block_on(get_bootstrap_state(rpc_servers)).expect("Failed to bootstrap state");
    log::info!(
        "Configuring light client at height {} with hash {}",
        height,
        hash
    );

    configure_node(cfg_path, |cfg| {
        cfg["statesync"]["enable"] = toml_edit::value(true);
        cfg["statesync"]["rpc_servers"] = toml_edit::value(rpc_servers.join(","));
        cfg["statesync"]["trust_height"] = toml_edit::value(height);
        cfg["statesync"]["trust_hash"] = toml_edit::value(hash.clone());
        cfg["statesync"]["discovery_time"] = toml_edit::value("8s");
        if cfg["statesync"]["trust_period"].to_string() == "0" {
            cfg["statesync"]["trust_period"] = toml_edit::value("216h0m0s");
        }
    });
}

async fn get_bootstrap_state(rpc_servers: &[&str]) -> Result<(i64, String)> {
    let rpc_clients: Vec<_> = rpc_servers
        .iter()
        .map(|addr| {
            tendermint_rpc::HttpClient::new(*addr).expect("Could not create tendermint RPC client")
        })
        .collect();

    // get median latest height
    let mut latest_heights = vec![];
    for client in rpc_clients.iter() {
        let status = match client.status().await {
            Ok(status) => status,
            Err(_) => continue,
        };
        let height = status.sync_info.latest_block_height.value();
        latest_heights.push(height);
    }

    if latest_heights.len() < rpc_servers.len() / 2 {
        return Err(orga::Error::App(
            "Failed to get state sync bootstrap data from nodes".to_string(),
        )
        .into());
    }

    latest_heights.sort_unstable();
    let latest_height = latest_heights[latest_heights.len() / 2] as u32;

    let height = latest_height.checked_sub(1000).unwrap_or(1);

    // get block hash
    let mut hash = None;
    for client in rpc_clients.iter() {
        let res = client
            .blockchain(height, height)
            .await
            .expect("Could not get tendermint block header");
        let block = &res.block_metas[0];
        if hash.is_none() {
            hash = Some(block.header.hash());
        }

        let hash = hash.as_ref().unwrap();
        if block.header.hash() != *hash {
            return Err(orga::Error::App("Block hashes do not match".to_string()).into());
        }
    }

    Ok((height as i64, hash.unwrap().to_string()))
}

#[derive(Parser, Debug)]
pub struct SendCmd {
    to_addr: Address,
    amount: u64,
}

impl SendCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .accounts
            .transfer(self.to_addr, self.amount.into())
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct SendNbtcCmd {
    to_addr: Address,
    amount: u64,
}

impl SendNbtcCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| {
                client
                    .bitcoin
                    .transfer(self.to_addr, self.amount.into())
                    .await
            })
            .noop()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct BalanceCmd {
    address: Option<Address>,
}

impl BalanceCmd {
    async fn run(&self) -> Result<()> {
        let address = self.address.unwrap_or_else(|| my_address());
        println!("address: {}", address);

        let balance = app_client().accounts.balance(address).await??;
        println!("{} NOM", balance);

        let balance = app_client().bitcoin.accounts.balance(address).await??;
        println!("{} NBTC", balance);

        let balance = app_client().escrowed_nbtc(address).await??;
        println!("{} IBC-escrowed NBTC", balance);

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
            let staked = delegation.staked;
            let liquid: u64 = delegation
                .liquid
                .iter()
                .map(|(_, amount)| -> u64 { (*amount).into() })
                .sum();
            if staked == 0 && liquid == 0 {
                continue;
            }

            use nomic::app::Nom;
            use nomic::bitcoin::Nbtc;
            let liquid_nom = delegation
                .liquid
                .iter()
                .find(|(denom, _)| *denom == Nom::INDEX)
                .unwrap()
                .1;
            let liquid_nbtc = delegation
                .liquid
                .iter()
                .find(|(denom, _)| *denom == Nbtc::INDEX)
                .unwrap_or(&(0, 0.into()))
                .1;

            println!(
                "- {validator}: staked={staked} NOM, liquid={liquid_nom} NOM,{liquid_nbtc} NBTC",
            );
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct ValidatorsCmd;

impl ValidatorsCmd {
    async fn run(&self) -> Result<()> {
        let mut validators = app_client().staking.all_validators().await??;

        validators.sort_by(|a, b| b.amount_staked.cmp(&a.amount_staked));

        for validator in validators {
            let bytes: Vec<u8> = validator.info.into();
            let info: DeclareInfo = serde_json::from_slice(bytes.as_slice()).unwrap();
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
        Ok(app_client()
            .pay_from(async move |client| {
                client
                    .accounts
                    .take_as_funding((self.amount + MIN_FEE).into())
                    .await
            })
            .staking
            .delegate_from_self(self.validator_addr, self.amount.into())
            .await?)
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
            validator_info: info_bytes.try_into().unwrap(),
            commission: Commission {
                rate: self.commission_rate,
                max: self.commission_max,
                max_change: self.commission_max_change,
            },
            min_self_delegation: self.min_self_delegation.into(),
        };

        Ok(app_client()
            .pay_from(async move |client| {
                client
                    .accounts
                    .take_as_funding((self.amount + MIN_FEE).into())
                    .await
            })
            .staking
            .declare_self(declaration)
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct EditCmd {
    commission_rate: Decimal,
    min_self_delegation: u64,
    moniker: String,
    website: String,
    identity: String,
    details: String,
}

impl EditCmd {
    async fn run(&self) -> Result<()> {
        let info = DeclareInfo {
            moniker: self.moniker.clone(),
            website: self.website.clone(),
            identity: self.identity.clone(),
            details: self.details.clone(),
        };
        let info_json = serde_json::to_string(&info)
            .map_err(|_| orga::Error::App("invalid json".to_string()))?;
        let info_bytes = info_json.as_bytes().to_vec();

        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .edit_validator_self(
                self.commission_rate,
                self.min_self_delegation.into(),
                info_bytes.try_into().unwrap(),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct UnbondCmd {
    validator_addr: Address,
    amount: u64,
}

impl UnbondCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .unbond_self(self.validator_addr, self.amount.into())
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct RedelegateCmd {
    src_validator_addr: Address,
    dest_validator_addr: Address,
    amount: u64,
}

impl RedelegateCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .redelegate_self(
                self.src_validator_addr,
                self.dest_validator_addr,
                self.amount.into(),
            )
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct UnjailCmd {}

impl UnjailCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .staking
            .unjail()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct ClaimCmd;

impl ClaimCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.staking.claim_all().await)
            .deposit_rewards()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct AirdropCmd {
    address: Option<Address>,
}

impl AirdropCmd {
    async fn run(&self) -> Result<()> {
        let client = app_client();

        let addr = self.address.unwrap_or_else(|| my_address());
        let acct = match client.airdrop.get(addr).await?? {
            None => {
                println!("Address is not eligible for airdrop");
                return Ok(());
            }
            Some(acct) => acct,
        };

        println!("{:#?}", acct);

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct ClaimAirdropCmd {
    address: Option<Address>,
}

impl ClaimAirdropCmd {
    async fn run(&self) -> Result<()> {
        let client = app_client();

        let addr = self.address.unwrap_or_else(|| my_address());
        let acct = match client.airdrop.get(addr).await?? {
            None => {
                println!("Address is not eligible for airdrop");
                return Ok(());
            }
            Some(acct) => acct,
        };

        let mut claimed = false;

        if acct.airdrop1.claimable > 0 {
            app_client()
                .pay_from(async move |client| client.airdrop.claim_airdrop1().await)
                .accounts
                .give_from_funding_all()
                .await?;
            println!("Claimed airdrop 1 ({} uNOM)", acct.airdrop1.claimable);
            claimed = true;
        }

        if acct.btc_deposit.claimable > 0 {
            app_client()
                .pay_from(async move |client| client.airdrop.claim_btc_deposit().await)
                .accounts
                .give_from_funding_all()
                .await?;
            println!(
                "Claimed BTC deposit airdrop ({} uNOM)",
                acct.btc_deposit.claimable
            );
            claimed = true;
        }

        if acct.btc_withdraw.claimable > 0 {
            app_client()
                .pay_from(async move |client| client.airdrop.claim_btc_withdraw().await)
                .accounts
                .give_from_funding_all()
                .await?;
            println!(
                "Claimed BTC withdraw airdrop ({} uNOM)",
                acct.btc_withdraw.claimable
            );
            claimed = true;
        }

        if acct.ibc_transfer.claimable > 0 {
            app_client()
                .pay_from(async move |client| client.airdrop.claim_ibc_transfer().await)
                .accounts
                .give_from_funding_all()
                .await?;
            println!(
                "Claimed IBC transfer airdrop ({} uNOM)",
                acct.ibc_transfer.claimable
            );
            claimed = true;
        }

        if !claimed {
            println!("No claimable airdrops");
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct RelayerCmd {
    #[clap(short = 'p', long, default_value_t = 8332)]
    rpc_port: u16,

    #[clap(short = 'u', long)]
    rpc_user: Option<String>,

    #[clap(short = 'P', long)]
    rpc_pass: Option<String>,

    #[clap(long)]
    path: Option<String>,
}

impl RelayerCmd {
    async fn btc_client(&self) -> Result<BtcClient> {
        let rpc_url = format!("http://localhost:{}", self.rpc_port);
        let auth = match (self.rpc_user.clone(), self.rpc_pass.clone()) {
            (Some(user), Some(pass)) => Auth::UserPass(user, pass),
            _ => Auth::None,
        };

        let btc_client = BtcClient::new(rpc_url, auth)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;

        Ok(btc_client)
    }

    async fn run(&self) -> Result<()> {
        let create_relayer = async || {
            let btc_client = self.btc_client().await.unwrap();

            Relayer::new(btc_client, app_client()).await
        };

        let mut relayer = create_relayer().await;
        let headers = relayer.start_header_relay();

        let relayer_dir_path = self
            .path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| Node::home(nomic::app::CHAIN_ID).join("relayer"));
        if !relayer_dir_path.exists() {
            std::fs::create_dir(&relayer_dir_path)?;
        }
        let mut relayer = create_relayer().await;
        let deposits = relayer.start_deposit_relay(relayer_dir_path);

        let mut relayer = create_relayer().await;
        let checkpoints = relayer.start_checkpoint_relay();

        futures::try_join!(headers, deposits, checkpoints).unwrap();

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SignerCmd {
    /// Path to the signatory private key
    #[clap(short, long)]
    path: Option<String>,
    /// Limits the fraction of the total reserve that may be withdrawn within
    /// the trailing 24-hour period
    #[clap(long, default_value_t = 0.04)]
    max_withdrawal_rate: f64,
    /// Limits the maximum allowed signatory set change within 24 hours
    ///
    /// The Total Variation Distance between a day-old signatory set and the
    /// newly-proposed signatory set may not exceed this value
    #[clap(long, default_value_t = 0.04)]
    max_sigset_change_rate: f64,
}

impl SignerCmd {
    async fn run(&self) -> Result<()> {
        let signer_dir_path = self
            .path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| Node::home(nomic::app::CHAIN_ID).join("signer"));
        if !signer_dir_path.exists() {
            std::fs::create_dir(&signer_dir_path)?;
        }
        let key_path = signer_dir_path.join("xpriv");

        let signer = Signer::load_or_generate(
            my_address(),
            app_client(),
            key_path,
            self.max_withdrawal_rate,
            self.max_sigset_change_rate,
        )?;
        signer.start().await?;

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct SetSignatoryKeyCmd {
    xpub: bitcoin::util::bip32::ExtendedPubKey,
}

impl SetSignatoryKeyCmd {
    async fn run(&self) -> Result<()> {
        app_client()
            .pay_from(async move |client| client.accounts.take_as_funding(MIN_FEE.into()).await)
            .bitcoin
            .set_signatory_key(self.xpub.into())
            .await?;

        Ok(())
    }
}

async fn deposit(dest: DepositCommitment) -> Result<()> {
    let sigset = app_client().bitcoin.checkpoints.active_sigset().await??;
    let script = sigset.output_script(dest.commitment_bytes()?.as_slice())?;
    let btc_addr = bitcoin::Address::from_script(&script, nomic::bitcoin::NETWORK).unwrap();

    let client = reqwest::Client::new();
    let res = client
        .post("https://testnet-relayer.nomic.io:8443")
        .query(&[
            ("dest_bytes", dest.to_base64()?),
            ("sigset_index", sigset.index().to_string()),
            ("deposit_addr", btc_addr.to_string()),
        ])
        .send()
        .await
        .map_err(|err| nomic::error::Error::Orga(orga::Error::App(err.to_string())))?;
    if res.status() != 200 {
        return Err(orga::Error::App(
            format!("Relayer responded with code {}", res.status()).to_string(),
        )
        .into());
    }

    println!("Deposit address: {}", btc_addr);
    println!("Expiration: {}", "5 days from now");
    // TODO: show real expiration
    Ok(())
}

#[derive(Parser, Debug)]
pub struct DepositCmd {
    address: Option<Address>,
}

impl DepositCmd {
    async fn run(&self) -> Result<()> {
        let dest_addr = self.address.unwrap_or_else(|| my_address());

        deposit(DepositCommitment::Address(dest_addr)).await
    }
}

#[derive(Parser, Debug)]
pub struct InterchainDepositCmd {
    #[clap(long, value_name = "ADDRESS")]
    receiver: String,
    #[clap(long, value_name = "CHANNEL_ID")]
    channel: String,
}

const ONE_DAY_NS: u64 = 86400 * 1_000_000_000;
impl InterchainDepositCmd {
    async fn run(&self) -> Result<()> {
        use orga::ibc::encoding::Adapter;
        let now_ns = now_seconds() as u64 * 1_000_000_000;
        let dest = DepositCommitment::Ibc(IbcDepositCommitment {
            receiver: Adapter::new(self.receiver.parse().unwrap()),
            sender: Adapter::new(my_address().to_string().parse().unwrap()),
            source_channel: Adapter::new(self.channel.parse().unwrap()),
            source_port: Adapter::new("transfer".parse().unwrap()),
            timeout_timestamp: now_ns + 8 * ONE_DAY_NS - (now_ns % ONE_DAY_NS),
        });

        deposit(dest).await
    }
}

#[derive(Parser, Debug)]
pub struct WithdrawCmd {
    dest: bitcoin::Address,
    amount: u64,
}

impl WithdrawCmd {
    async fn run(&self) -> Result<()> {
        use nomic::bitcoin::adapter::Adapter;

        let script = self.dest.script_pubkey();

        app_client()
            .pay_from(async move |client| {
                client
                    .withdraw_nbtc(Adapter::new(script), self.amount.into())
                    .await
            })
            .noop()
            .await?;

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct IbcDepositNbtcCmd {
    to: Address,
    amount: u64,
}

impl IbcDepositNbtcCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| {
                client.ibc_deposit_nbtc(self.to, self.amount.into()).await
            })
            .noop()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct IbcWithdrawNbtcCmd {
    amount: u64,
}

impl IbcWithdrawNbtcCmd {
    async fn run(&self) -> Result<()> {
        Ok(app_client()
            .pay_from(async move |client| client.ibc_withdraw_nbtc(self.amount.into()).await)
            .noop()
            .await?)
    }
}

#[derive(Parser, Debug)]
pub struct GrpcCmd {
    #[clap(default_value_t = 9001)]
    port: u16,
}

impl GrpcCmd {
    async fn run(&self) -> Result<()> {
        let ibc_client = app_client().ibc.clone();
        orga::ibc::start_grpc(
            app_client(),
            ibc_client,
            &|client| client.ibc.clone(),
            self.port,
        )
        .await;

        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct IbcTransferCmd {
    receiver: String,
    amount: u64,
    channel_id: String,
    port_id: String,
    denom: String,
}

use orga::ibc::TransferArgs;
impl IbcTransferCmd {
    async fn run(&self) -> Result<()> {
        let fee: u64 = nomic::app::ibc_fee(self.amount.into())?.into();
        let amount_after_fee = self.amount - fee;
        let transfer_args = TransferArgs {
            amount: amount_after_fee.into(),
            channel_id: self.channel_id.clone(),
            port_id: self.port_id.clone(),
            denom: self.denom.clone(),
            receiver: self.receiver.clone(),
        };

        Ok(app_client()
            .pay_from(async move |client| {
                client
                    .ibc_deposit_nbtc(my_address(), self.amount.into())
                    .await
            })
            .ibc
            .transfer(transfer_args.try_into()?)
            .await?)
    }
}

#[tokio::main]
async fn main() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(log::LevelFilter::Info)
        .parse_env("NOMIC_LOG")
        .init();

    let backtrace_enabled = std::env::var("RUST_BACKTRACE").is_ok();

    let panic_handler = if backtrace_enabled {
        Some(std::panic::take_hook())
    } else {
        None
    };
    std::panic::set_hook(Box::new(move |info| {
        log::error!("{}", info);
        if let Some(f) = panic_handler.as_ref() {
            f(info)
        }
        std::process::exit(1);
    }));

    let opts = Opts::parse();
    if let Err(err) = opts.cmd.run().await {
        log::error!("{}", err);
        std::process::exit(1);
    };
}
