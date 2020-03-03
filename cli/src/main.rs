mod tendermint;
use clap::Clap;
use nomic_chain::abci_server;
use std::fs;
use log::info;

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
}

#[derive(Clap)]
struct Start {}

#[derive(Clap)]
struct Relayer {}

#[derive(Clap)]
struct Worker {}

fn main() {
    let opts: Opts = Opts::parse();

    pretty_env_logger::init();

    // Ensure nomic-testnet home directory
    let mut nomic_home = dirs::home_dir()
        .unwrap_or(std::env::current_dir().expect("Failed to create Nomic home directory"));
    nomic_home.push(".nomic-testnet");
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
            tendermint::start(&nomic_home);
            // Start the ABCI server
            info!("ABCI server started");
            abci_server::start(&nomic_home);
        }
        SubCommand::Worker(_) => {
            nomic_worker::generate();
        }
    }
}
