use bitcoincore_rpc::{Auth, Client, RpcApi};
use nomic_primitives::transaction::Transaction;
use std::env;

#[derive(Debug)]
pub enum RelayerState {
    Initialize,
    FetchBestBitcoinBlockHash,
    FetchPegBlockHashes,
    ComputeCommonAncestor,
    FetchLinkingHeaders,
    BuildHeaderTransaction,
    BroadcastHeaderTransaction,
    Failure,
}

#[derive(Debug)]
pub enum RelayerEvent {
    BitcoinRpcReady,
    BitcoinRpcError,
    PegClientReady,
    PegClientError,
    Initialized,
    FetchBestBitcoinBlockHashSuccess,
    FetchBestBitcoinBlockHashFailure,
    FetchPegBlockHashesSuccess,
    FetchPegBlockHashesFailure,
    ComputeCommonAncestorSuccess,
    ComputeCommonAncestorFailure,
    FetchLinkingHeadersSuccess,
    FetchLinkingHeadersFailure,
    BuiltHeaderTransaction,
    BroadcastHeaderTransactionSuccess,
    BroadcastHeaderTransactionFailure,
}

impl RelayerState {
    pub fn next(self, event: RelayerEvent) -> Self {
        use self::RelayerEvent::*;
        use self::RelayerState::*;
        match (self, event) {
            (s, e) => Failure,
        }
    }
}

pub struct RelayerStateMachine {
    pub state: RelayerState,
    rpc: Client,
}

impl RelayerStateMachine {
    pub fn new() -> Self {
        let rpc_user = env::var("BTC_RPC_USER").unwrap();
        let rpc_pass = env::var("BTC_RPC_PASS").unwrap();
        let rpc_auth = Auth::UserPass(rpc_user, rpc_pass);
        let rpc_url = "http://localhost:18332";
        RelayerStateMachine {
            state: RelayerState::Initialize,
            rpc: Client::new(rpc_url.to_string(), rpc_auth).unwrap(),
        }
    }

    pub fn run(&mut self) -> RelayerEvent {
        match &mut self.state {
            _ => {
                get_best_hash(&self.rpc);
                RelayerEvent::Initialized
            }
        }
    }
}

fn get_best_hash(rpc: &Client) {
    let hash = &rpc.get_best_block_hash().unwrap();
    println!("best hash: {}", hash);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn run_relayer_state_machine() {
        let mut sm = RelayerStateMachine::new();
        let event = sm.run();
    }
}
