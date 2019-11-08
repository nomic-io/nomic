use bitcoin::hashes::sha256d::Hash;
use bitcoincore_rpc::{Auth, Client, Error, RpcApi};
use nomic_client::{Client as PegClient, ClientError as PegClientError};
use nomic_primitives::transaction::Transaction;
use std::env;

#[derive(Debug)]
pub enum RelayerState {
    InitializeBitcoinRpc,
    InitializePegClient,
    FetchPegBlockHashes,
    ComputeCommonAncestor {
        peg_block_hashes: Vec<Hash>,
    },
    FetchLinkingHeaders {
        common_block_hash: Hash,
    },
    BuildHeaderTransaction {
        linking_headers: Vec<Hash>,
    },
    BroadcastHeaderTransaction {
        header_transaction: Transaction::Headers,
    },
    Failure,
}

#[derive(Debug)]
pub enum RelayerEvent {
    InitializeBitcoinRpcSuccess,
    InitializeBitcoinRpcFailure,
    InitializePegClientSuccess,
    InitializePegClientFailure,
    FetchPegBlockHashesSuccess {
        peg_block_hashes: Vec<Hash>,
    },
    FetchPegBlockHashesFailure,
    ComputeCommonAncestorSuccess {
        common_block_hash: Hash,
    },
    ComputeCommonAncestorFailure,
    FetchLinkingHeadersSuccess {
        linking_headers: Vec<Hash>,
    },
    FetchLinkingHeadersFailure,
    BuiltHeaderTransaction {
        header_transaction: Transaction::Headers,
    },
    BroadcastHeaderTransactionSuccess,
    BroadcastHeaderTransactionFailure,
}

impl RelayerState {
    pub fn next(self, event: RelayerEvent) -> Self {
        use self::RelayerEvent::*;
        use self::RelayerState::*;
        match (self, event) {
            (InitializeBitcoinRpc, InitializeBitcoinRpcSuccess) => InitializePegClient,
            (InitializePegClient, InitializePegClientSuccess) => FetchPegBlockHashes,
            (FetchPegBlockHashes, FetchPegBlockHashesSuccess) => ComputeCommonAncestor,
            (FetchPegBlockHashes, FetchPegBlockHashesFailure) => FetchPegBlockHashes,
            (ComputeCommonAncestor, ComputeCommonAncestorSuccess) => FetchLinkingHeaders,
            (FetchLinkingHeaders, FetchLinkingHeadersSuccess) => BuildHeaderTransaction,
            (BuildHeaderTransaction, BuiltHeaderTransaction) => BroadcastHeaderTransaction,
            (BroadcastHeaderTransaction, BroadcastHeaderTransactionSuccess) => FetchPegBlockHashes,
            (BroadcastHeaderTransaction, BroadcastHeaderTransactionFailure) => {
                BroadcastHeaderTransaction
            }
            (_, _) => Failure,
        }
    }
}

pub struct RelayerStateMachine {
    pub state: RelayerState,
    rpc: Option<Client>,
    peg_client: Option<PegClient>,
}

impl RelayerStateMachine {
    pub fn new() -> Self {
        RelayerStateMachine {
            state: RelayerState::InitializeBitcoinRpc,
            rpc: None,
            peg_client: None,
        }
    }

    pub fn run(&mut self) -> RelayerEvent {
        use self::RelayerEvent::*;
        use self::RelayerState::*;
        match &mut self.state {
            InitializeBitcoinRpc => {
                let rpc = make_rpc_client();
                match rpc {
                    Ok(rpc) => {
                        self.rpc = Some(rpc);
                        InitializeBitcoinRpcSuccess
                    }
                    Err(_) => InitializeBitcoinRpcFailure,
                }
            }
            InitializePegClient => {
                let peg_client = PegClient::new();
                match peg_client {
                    Ok(peg_client) => {
                        self.peg_client = Some(peg_client);
                        InitializePegClientSuccess
                    }
                    Err(_) => InitializePegClientFailure,
                }
            }

            FetchPegBlockHashes => {
                let peg_client = self.peg_client.as_ref().unwrap();
                let peg_headers = peg_client.get_bitcoin_block_hashes();

                match peg_headers {
                    Ok(headers) => FetchPegBlockHashesSuccess,
                    Err(_) => FetchPegBlockHashesFailure,
                }
            }

            _ => panic!("Relayer is in an unhandled state"),
        }
    }
}

pub fn make_rpc_client() -> Result<Client, Error> {
    let rpc_user = env::var("BTC_RPC_USER").unwrap();
    let rpc_pass = env::var("BTC_RPC_PASS").unwrap();
    let rpc_auth = Auth::UserPass(rpc_user, rpc_pass);
    let rpc_url = "http://localhost:18332";
    Client::new(rpc_url.to_string(), rpc_auth)
}

fn get_best_bitcoin_hash(rpc: &Client) {
    let hash = &rpc.get_best_block_hash().unwrap();
    println!("best hash: {}", hash);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn run_relayer_state_machine() {
        let mut sm = RelayerStateMachine::new();
        for _ in 0..2 {
            let event = sm.run();
            sm.state = sm.state.next(event);
            println!("sm state: {:?}", sm.state);
        }
    }
}
