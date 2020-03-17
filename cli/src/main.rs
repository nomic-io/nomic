mod tendermint;
mod wallet;

use clap::Clap;
use log::info;
use nomic_chain::abci_server;
use nomic_client::Client;
use std::fs;
use colored::*;
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
}

#[derive(Clap)]
struct Start {}

#[derive(Clap)]
struct Dev {}
#[derive(Clap)]
struct Relayer {}

#[derive(Clap)]
struct Worker {}

fn main() {
    let opts: Opts = Opts::parse();

    pretty_env_logger::init_custom_env("NOMIC_LOG");

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
            relayer::relayer::start();
        }
        SubCommand::Start(_) => {
            // Install and start Tendermint
            tendermint::install(&nomic_home);
            tendermint::init(&nomic_home, false);
            tendermint::start(&nomic_home);
            // Start the ABCI server
            info!("Starting ABCI server");
            abci_server::start(&nomic_home);
        }
        SubCommand::Dev(_) => {
            // Install and start Tendermint
            tendermint::install(&nomic_home);
            tendermint::init(&nomic_home, true);
            tendermint::start(&nomic_home);
            // Start the ABCI server
            info!("Starting ABCI server");
            abci_server::start(&nomic_home);
        }
        SubCommand::Worker(_) => {
            nomic_worker::generate();
        }
    }
}
