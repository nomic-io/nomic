use clap::Clap;
use nomic_chain::abci_server;

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
}

#[derive(Clap)]
struct Start {}

#[derive(Clap)]
struct Relayer {}

fn main() {
    let opts: Opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Relayer(r) => {
            relayer::relayer::start();
        }
        SubCommand::Start(s) => {
            // Start the ABCI server
            abci_server::start();
        }
    }
}
