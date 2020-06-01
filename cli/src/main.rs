#![allow(unused_braces)]
mod tendermint;
mod wallet;

use clap::Clap;
use colored::*;
use failure::bail;
use log::{debug, info};
use nomic_chain::abci_server;
use nomic_client::Client;
use nomic_primitives::Result;
use std::{env, fs};
use wallet::Wallet;

/// Command-line interface for interacting with the Nomic Bitcoin sidechain
#[derive(Clap)]
#[clap(version = "0.2.2")]
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
    #[clap(name = "relayer")]
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
    amount: f64,
}

#[derive(Clap)]
struct Withdraw {
    bitcoin_address: String,
    amount: f64,
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
            loop {
                // poll until RPC is available
                if let Ok(_) = Client::new("localhost:26657") {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
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
            let last_checkpoint_time = client
                .state()
                .unwrap()
                .peg
                .last_checkpoint_time
                .get()
                .unwrap();
            let checkpoint_index = client.state().unwrap().peg.checkpoint_index.get_or_default().unwrap();
            let checkpoints_until_change =
                SIGNATORY_CHANGE_INTERVAL - (checkpoint_index % SIGNATORY_CHANGE_INTERVAL);
            let time_until_change =
                (checkpoints_until_change * CHECKPOINT_INTERVAL).saturating_sub(now - last_checkpoint_time);
            let hours_until_expiration =
                (time_until_change as f64 / (60.0 * 60.0)).round() as usize;
            let minutes_until_expiration = (time_until_change as f64 / 60.0).round() as usize;

            if minutes_until_expiration <= 60 {
                let message = format!(
                    "The signatory set is currently changing. Try this command again in {} minutes.",
                    minutes_until_expiration.to_string().bold()
                );
                println!("{}", message.yellow());
                return;
            }
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
                    "{} hour{} from now",
                    hours_until_expiration,
                    if hours_until_expiration == 1 { "" } else { "s" }
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
        }
        SubCommand::Balance(_) => {
            default_log_level("warn");

            let client = Client::new("localhost:26657").unwrap();

            let wallet_path = nomic_home.join("wallet.key");
            let wallet = Wallet::load_or_generate(wallet_path).unwrap();

            let balance = client.get_balance(&wallet.pubkey_bytes()).unwrap();
            let balance = format_amount(balance);

            println!("YOUR NOMIC ADDRESS:");
            println!("{}", wallet.receive_address().cyan().bold());
            println!();
            println!("YOUR BALANCE:");
            println!("{} NBTC", balance.cyan().bold());
        }
        SubCommand::Transfer(transfer) => {
            default_log_level("warn");

            let receiver_address = transfer.address;
            let amount = to_satoshis(transfer.amount);

            let mut client = Client::new("localhost:26657").unwrap();

            let wallet_path = nomic_home.join("wallet.key");
            let wallet = Wallet::load_or_generate(wallet_path).unwrap();

            if let Err(err) = wallet.send(&mut client, receiver_address.as_str(), amount) {
                let err: nomic_client::RpcError = err.downcast().unwrap();
                if err.message() != "tx already exists in cache" {
                    panic!(err);
                }
            }
            println!(
                "Sent {} coins to {}.",
                format_amount(amount).cyan().bold(),
                receiver_address.cyan().bold()
            );
        }

        SubCommand::Withdraw(withdrawal) => {
            default_log_level("warn");

            let amount = to_satoshis(withdrawal.amount);

            let mut client = Client::new("localhost:26657").unwrap();
            let wallet_path = nomic_home.join("wallet.key");
            let wallet = Wallet::load_or_generate(wallet_path).unwrap();

            if let Err(err) =
                wallet.withdraw(&mut client, withdrawal.bitcoin_address.as_str(), amount)
            {
                let err: nomic_client::RpcError = err.downcast().unwrap();
                if err.message() != "tx already exists in cache" {
                    panic!(err);
                }
            }

            println!(
                "Withdrew {} Bitcoin to {}.",
                format_amount(amount).cyan().bold(),
                withdrawal.bitcoin_address
            );
        }
    }
}

const COIN: u64 = 100_000_000;

fn format_amount(amount: u64) -> String {
    format!("{}.{:0>8}", amount / COIN, (amount % COIN).to_string())
}

fn to_satoshis(amount: f64) -> u64 {
    (amount * COIN as f64).round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_satoshis() {
        assert_eq!(to_satoshis(0.00000012), 12);
        assert_eq!(to_satoshis(100.0), 10_000_000_000);
    }
}
