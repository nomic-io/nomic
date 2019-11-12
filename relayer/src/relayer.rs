use bitcoin::hashes::sha256d::Hash;
use bitcoincore_rpc::{Auth, Client, Error, RpcApi};
use nomic_client::{Client as PegClient, ClientError as PegClientError};
use nomic_primitives::transaction::HeaderTransaction;
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
        linking_headers: Vec<bitcoin::BlockHeader>,
    },
    BroadcastHeaderTransaction {
        header_transaction: HeaderTransaction,
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
        linking_headers: Vec<bitcoin::BlockHeader>,
    },
    FetchLinkingHeadersFailure,
    BuiltHeaderTransaction {
        header_transaction: HeaderTransaction,
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
            (FetchPegBlockHashes, FetchPegBlockHashesSuccess { peg_block_hashes }) => {
                ComputeCommonAncestor { peg_block_hashes }
            }
            (FetchPegBlockHashes, FetchPegBlockHashesFailure) => FetchPegBlockHashes,
            (ComputeCommonAncestor { .. }, ComputeCommonAncestorSuccess { common_block_hash }) => {
                FetchLinkingHeaders { common_block_hash }
            }
            (FetchLinkingHeaders { .. }, FetchLinkingHeadersSuccess { linking_headers }) => {
                BuildHeaderTransaction { linking_headers }
            }
            (BuildHeaderTransaction { .. }, BuiltHeaderTransaction { header_transaction }) => {
                BroadcastHeaderTransaction { header_transaction }
            }
            (BroadcastHeaderTransaction { .. }, BroadcastHeaderTransactionSuccess) => {
                FetchPegBlockHashes
            }
            (
                BroadcastHeaderTransaction { header_transaction },
                BroadcastHeaderTransactionFailure,
            ) => BroadcastHeaderTransaction { header_transaction },
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
                let peg_client = match self.peg_client.as_ref() {
                    Some(peg_client) => peg_client,
                    None => return FetchPegBlockHashesFailure,
                };

                let peg_hashes = peg_client.get_bitcoin_block_hashes();

                match peg_hashes {
                    Ok(hashes) => FetchPegBlockHashesSuccess {
                        peg_block_hashes: hashes,
                    },
                    Err(_) => FetchPegBlockHashesFailure,
                }
            }

            ComputeCommonAncestor { peg_block_hashes } => {
                let rpc = match self.rpc.as_ref() {
                    Some(rpc) => rpc,
                    None => return ComputeCommonAncestorFailure,
                };
                match compute_common_ancestor(rpc, peg_block_hashes) {
                    Ok(hash) => ComputeCommonAncestorSuccess {
                        common_block_hash: hash,
                    },
                    Err(_) => ComputeCommonAncestorFailure,
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

/// Iterate over peg hashes, starting from the tip and going backwards.
/// The first hash that we find that's in our full node's longest chain
/// is considered the common ancestor.
pub fn compute_common_ancestor(rpc: &Client, peg_hashes: &[Hash]) -> Result<Hash, Error> {
    for hash in peg_hashes.iter().rev() {
        let rpc_response = rpc.get_block_header_verbose(hash);
        match rpc_response {
            Ok(response) => {
                let confs = response.confirmations;
                if confs > 0 {
                    return Ok(response.hash);
                }
            }
            Err(e) => return Err(e),
        }
    }

    // No rpc error, but no common headers found
    panic!("No common headers found");
}

/// Fetch all the Bitcoin block headers that connect the peg zone to the tip of Bitcoind's longest
/// chain.
pub fn fetch_linking_headers(
    rpc: &Client,
    common_block_hash: Hash,
) -> Result<Vec<bitcoin::BlockHeader>, Error> {
    // Start at bitcoind's best block
    let best_block_hash = rpc.get_best_block_hash()?;
    let mut headers: Vec<bitcoin::BlockHeader> = Vec::new();
    let mut header = rpc.get_block_header_raw(&best_block_hash)?;
    headers.push(header);

    loop {
        header = rpc.get_block_header_raw(&header.prev_blockhash)?;

        if header.prev_blockhash == common_block_hash {
            headers.push(header);
            break;
        } else {
            headers.push(header);
        }
    }

    Ok(headers)
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
