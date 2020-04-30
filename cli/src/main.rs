#![allow(unused_braces)]
mod tendermint;
mod wallet;

use clap::Clap;
use colored::*;
use failure::bail;
use log::{debug, info, warn};
use nomic_chain::abci_server;
use nomic_client::Client;
use nomic_primitives::Result;
use std::{env, fs};
use wallet::Wallet;

/// Command-line interface for interacting with the Nomic Bitcoin sidechain
#[derive(Clap)]
#[clap(version = "0.1.0")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,

    /// Use a local chain in development mode
    #[clap(short = "d", long = "dev")]
    dev: bool,
}

#[derive(Clap)]
enum SubCommand {
    /// Relays data between a local Bitcoin full node and the sidechain
    #[clap(name = "relayer", version = "0.1.0")]
    Relayer(Relayer),

    /// Starts a sidechain full node
    #[clap(name = "start")]
    Start(Start),

    /// Generate voting power for the validator running locally
    #[clap(name = "worker")]
    Worker(Worker),

    /// Deposit Bitcoin into your sidechain account
    #[clap(name = "deposit")]
    Deposit(Deposit),

    /// Displays the balance in your sidechain account
    #[clap(name = "balance")]
    Balance(Balance),

    /// Send coins to another address
    #[clap(name = "send")]
    Transfer(Transfer),

    /// Withdraw coins to a Bitcoin address
    #[clap(name = "withdraw")]
    Withdraw(Withdraw),
}

#[derive(Clap)]
struct Start;

#[derive(Clap)]
struct Relayer;

#[derive(Clap)]
struct Worker;

#[derive(Clap)]
struct Deposit;

#[derive(Clap)]
struct Balance;

#[derive(Clap)]
struct Transfer {
    address: String,
    amount: u64,
}

#[derive(Clap)]
struct Withdraw {
    bitcoin_address: String,
    amount: u64,
}

fn main() {
    let opts: Opts = Opts::parse();

    let default_log_level = |level: &str| {
        let level = env::var("NOMIC_LOG").unwrap_or(level.to_string());
        env::set_var("NOMIC_LOG", level);
        pretty_env_logger::init_custom_env("NOMIC_LOG");
    };

    // Ensure nomic-testnet home directory
    let mut nomic_home = dirs::home_dir()
        .unwrap_or(std::env::current_dir().expect("Failed to create Nomic home directory"));
    if opts.dev {
        nomic_home.push(".nomic-dev");
    } else {
        nomic_home.push(".nomic-testnet");
    }
    let mkdir_result = fs::create_dir(&nomic_home);
    if let Err(_) = mkdir_result {
        // TODO: Panic if this error is anything except "directory already exists"
    }

    match opts.subcmd {
        SubCommand::Relayer(_) => {
            default_log_level("info");
            relayer::relayer::start();
        }
        SubCommand::Start(_) => {
            default_log_level("info");
            // Install and start Tendermint
            tendermint::install(&nomic_home);
            tendermint::init(&nomic_home, opts.dev);
            tendermint::start(&nomic_home);

            // Start the ABCI server
            info!("Starting ABCI server");
            let nomic_home_abci = nomic_home.clone();
            std::thread::spawn(move || {
                abci_server::start(nomic_home_abci);
            });

            // Start the signatory process
            // TODO: poll until the node is caught up
            std::thread::sleep(std::time::Duration::from_secs(10));
            info!("Starting signatory process");
            nomic_signatory::start(nomic_home).unwrap();
        }
        SubCommand::Worker(_) => {
            default_log_level("info");
            nomic_worker::generate();
        }
        SubCommand::Deposit(_) => {
            default_log_level("warn");
            fn submit_address(address: &[u8], relayer_host: &str) -> Result<()> {
                // TODO: send address to multiple relayers
                debug!("Sending address to relayer: {}", relayer_host);
                let client = reqwest::blocking::Client::new();
                let res = client
                    .post(format!("{}/addresses/{}", relayer_host, hex::encode(address)).as_str())
                    .send()?;

                if res.status() == 200 {
                    return Ok(());
                } else {
                    bail!("Invalid request to the address pool: {}", res.status());
                }
            }

            let client = Client::new("localhost:26657").unwrap();
            let signatory_snapshot = client.get_signatory_set_snapshot().unwrap();

            let wallet_path = nomic_home.join("wallet.key");
            let wallet = Wallet::load_or_generate(wallet_path).unwrap();
            let address = wallet.deposit_address(&signatory_snapshot.signatories);

            use nomic_chain::peg::{CHECKPOINT_INTERVAL, SIGNATORY_CHANGE_INTERVAL};
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let expiration =
                signatory_snapshot.time + SIGNATORY_CHANGE_INTERVAL * CHECKPOINT_INTERVAL;
            let days_until_expiration =
                ((expiration.saturating_sub(now)) as f64 / (60 * 60 * 24) as f64).round() as usize;

            let relayer = if opts.dev {
                "http://localhost:8880"
            } else {
                "http://kep.io:8880"
            };
            submit_address(wallet.pubkey_bytes().as_slice(), relayer).unwrap();

            println!("YOUR DEPOSIT ADDRESS:");
            println!("{}", address.to_string().cyan().bold());
            println!();
            println!("EXPIRES:");
            println!(
                "{}",
                format!(
                    "{} day{} from now",
                    days_until_expiration,
                    if days_until_expiration == 1 { "" } else { "s" }
                )
                .red()
                .bold()
            );
            println!();
            println!("Send testnet Bitcoin to this address to deposit into your");
            println!("sidechain account. After the transaction has been confirmed,");
            println!(
                "you can check your balance with `{}`.",
                "nomic balance".blue().italic()
            );
            println!();
            println!(
                "{} send to this address after it expires or you will risk",
                "DO NOT".red().bold()
            );
            println!("loss of funds.");
        }
        SubCommand::Balance(_) => {
            default_log_level("warn");

            let client = Client::new("localhost:26657").unwrap();

            let wallet_path = nomic_home.join("wallet.key");
            let wallet = Wallet::load_or_generate(wallet_path).unwrap();

            let balance = client.get_balance(&wallet.pubkey_bytes()).unwrap();
            let balance = format_amount(balance);

            println!("YOUR ADDRESS: {}", wallet.receive_address().cyan().bold());
            println!("YOUR BALANCE: {} NBTC", balance.cyan().bold());
        }
        SubCommand::Transfer(transfer) => {
            default_log_level("error");

            let receiver_address = transfer.address;
            let amount = transfer.amount;

            let mut client = Client::new("localhost:26657").unwrap();

            let wallet_path = nomic_home.join("wallet.key");
            let wallet = Wallet::load_or_generate(wallet_path).unwrap();

            if let Err(err) = wallet.send(&mut client, receiver_address.as_str(), amount) {
                // TODO: fix upstream response parsing in tendermint-rs, and fail if this errors
                warn!("{}", err);
            }
            println!(
                "Sent {} coins to {}.",
                // TODO: format amount
                format_amount(amount).cyan().bold(),
                receiver_address.cyan().bold()
            );
        }

        SubCommand::Withdraw(withdrawal) => {
            let mut client = Client::new("localhost:26657").unwrap();
            let wallet_path = nomic_home.join("wallet.key");
            let wallet = Wallet::load_or_generate(wallet_path).unwrap();

            if let Err(err) = wallet.withdraw(
                &mut client,
                withdrawal.bitcoin_address.as_str(),
                withdrawal.amount,
            ) {
                // TODO: fix upstream response parsing in tendermint-rs, and fail if this errors
                warn!("{}", err);
            }

            println!(
                "Withdrew {} Bitcoin to {}.",
                format_amount(withdrawal.amount).cyan().bold(),
                withdrawal.bitcoin_address
            );
        }
    }
}

fn format_amount(amount: u64) -> String {
    format!(
        "{}.{:0>8}",
        amount / 100_000_000,
        (amount % 100_000_000).to_string()
    )
}
