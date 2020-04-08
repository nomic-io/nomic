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

    /// Start a local testnet for development
    #[clap(name = "dev")]
    Dev(Dev),

    /// Deposit Bitcoin into your sidechain account
    #[clap(name = "deposit")]
    Deposit(Deposit),

    /// Displays the balance in your sidechain account
    #[clap(name = "balance")]
    Balance(Balance),

    /// Send coins to another address
    #[clap(name = "send")]
    Transfer(Transfer),
}

#[derive(Clap)]
struct Start {}

#[derive(Clap)]
struct Dev {}

#[derive(Clap)]
struct Relayer {}

#[derive(Clap)]
struct Worker {}

#[derive(Clap)]
struct Deposit {}

#[derive(Clap)]
struct Balance {}

#[derive(Clap)]
struct Transfer {
    address: String,
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
    if let SubCommand::Dev(_) = opts.subcmd {
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
            tendermint::init(&nomic_home, false);
            tendermint::start(&nomic_home);
            // Start the ABCI server
            info!("Starting ABCI server");
            abci_server::start(&nomic_home);
        }
        SubCommand::Dev(_) => {
            default_log_level("info");
            // Install and start Tendermint
            tendermint::install(&nomic_home);
            tendermint::init(&nomic_home, true);
            tendermint::start(&nomic_home);
            // Start the ABCI server
            info!("Starting ABCI server");
            abci_server::start(&nomic_home);
        }
        SubCommand::Worker(_) => {
            default_log_level("info");
            nomic_worker::generate();
        }
        SubCommand::Deposit(_) => {
            default_log_level("warn");
            fn submit_address(address: &[u8]) -> Result<()> {
                let relayer = "http://kep.io:8880";
                debug!("Sending address to relayer: {}", relayer);
                let client = reqwest::blocking::Client::new();
                let res = client
                    .post(format!("{}/addresses/{}", relayer, hex::encode(address)).as_str())
                    .send()?;

                if res.status() == 200 {
                    return Ok(());
                } else {
                    bail!("Invalid request to the address pool: {}", res.status());
                }
            }

            let mut client = Client::new("localhost:26657").unwrap();
            let signatory_snapshot = client.get_signatory_set_snapshot().unwrap();

            let wallet_path = nomic_home.join("wallet.key");
            let wallet = Wallet::load_or_generate(wallet_path).unwrap();
            let address = wallet.deposit_address(&signatory_snapshot.signatories);

            use nomic_chain::state_machine::SIGNATORY_CHANGE_INTERVAL;
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let expiration = signatory_snapshot.time + SIGNATORY_CHANGE_INTERVAL;
            let days_until_expiration =
                ((expiration - now) as f64 / (60 * 60 * 24) as f64).round() as usize;

            submit_address(wallet.pubkey_bytes().as_slice()).unwrap();

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

            let mut client = Client::new("localhost:26657").unwrap();

            let wallet_path = nomic_home.join("wallet.key");
            let wallet = Wallet::load_or_generate(wallet_path).unwrap();

            let balance = client.get_balance(&wallet.pubkey_bytes()).unwrap();
            let balance = format!(
                "{}.{:0>8}",
                balance / 100_000_000,
                (balance % 100_000_000).to_string()
            );

            println!("YOUR ADDRESS: {}", wallet.receive_address().cyan().bold());
            println!("YOUR BALANCE: {} NBTC", balance.cyan().bold());
        },
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
                amount.to_string().cyan().bold(),
                receiver_address.cyan().bold()
            );
        }
    }
}
    