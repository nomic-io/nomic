use bitcoin::hashes::sha256d::Hash;
use bitcoincore_rpc::{Auth, Client, Error as RpcError, RpcApi};
use nomic_client::{Client as PegClient, ClientError as PegClientError};
use nomic_primitives::transaction::{HeaderTransaction, Transaction};
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
    BuildHeaderTransactions {
        linking_headers: Vec<bitcoin::BlockHeader>,
    },
    BroadcastHeaderTransactions {
        header_transactions: Vec<HeaderTransaction>,
    },
    Failure {
        event: RelayerEvent,
    },
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
    BuiltHeaderTransactions {
        header_transactions: Vec<HeaderTransaction>,
    },
    BroadcastHeaderTransactionsSuccess,
    BroadcastHeaderTransactionsFailure,
    Restart,
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
                BuildHeaderTransactions { linking_headers }
            }
            (
                BuildHeaderTransactions { .. },
                BuiltHeaderTransactions {
                    header_transactions,
                },
            ) => BroadcastHeaderTransactions {
                header_transactions,
            },
            (BroadcastHeaderTransactions { .. }, BroadcastHeaderTransactionsSuccess) => {
                FetchPegBlockHashes
            }
            (
                BroadcastHeaderTransactions {
                    header_transactions,
                },
                BroadcastHeaderTransactionsFailure,
            ) => BroadcastHeaderTransactions {
                header_transactions,
            },
            // Restart loop on failure
            (Failure { .. }, Restart) => InitializeBitcoinRpc,
            (_, event) => Failure { event },
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
                let peg_client = match self.peg_client.as_mut() {
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

            FetchLinkingHeaders { common_block_hash } => {
                let rpc = match self.rpc.as_ref() {
                    Some(rpc) => rpc,
                    None => return FetchLinkingHeadersFailure,
                };

                let linking_headers = fetch_linking_headers(rpc, *common_block_hash);
                match linking_headers {
                    Ok(linking_headers) => FetchLinkingHeadersSuccess { linking_headers },
                    Err(_) => FetchLinkingHeadersFailure,
                }
            }

            BuildHeaderTransactions { linking_headers } => {
                let header_transactions = build_header_transactions(&mut linking_headers.to_vec());
                BuiltHeaderTransactions {
                    header_transactions,
                }
            }

            BroadcastHeaderTransactions {
                header_transactions,
            } => {
                let peg_client = match self.peg_client.as_mut() {
                    Some(peg_client) => peg_client,
                    None => return BroadcastHeaderTransactionsFailure,
                };

                match broadcast_header_transactions(peg_client, header_transactions.clone()) {
                    Ok(_) => BroadcastHeaderTransactionsSuccess,
                    Err(_) => BroadcastHeaderTransactionsFailure,
                }
            }

            Failure { event } => {
                println!("Entered failure state");
                Restart {}
            }
        }
    }
}

pub struct RelayerError {}

impl RelayerError {
    fn new() -> Self {
        RelayerError {}
    }
}

pub fn make_rpc_client() -> Result<Client, RpcError> {
    let rpc_user = env::var("BTC_RPC_USER").unwrap();
    let rpc_pass = env::var("BTC_RPC_PASS").unwrap();
    let rpc_auth = Auth::UserPass(rpc_user, rpc_pass);
    let rpc_url = "http://localhost:18332";
    Client::new(rpc_url.to_string(), rpc_auth)
}

/// Iterate over peg hashes, starting from the tip and going backwards.
/// The first hash that we find that's in our full node's longest chain
/// is considered the common ancestor.
pub fn compute_common_ancestor(rpc: &Client, peg_hashes: &[Hash]) -> Result<Hash, RelayerError> {
    for hash in peg_hashes.iter().rev() {
        let rpc_response = rpc.get_block_header_verbose(hash);
        match rpc_response {
            Ok(response) => {
                let confs = response.confirmations;
                if confs > 0 {
                    return Ok(response.hash);
                }
            }
            Err(_) => return Err(RelayerError::new()),
        }
    }

    Err(RelayerError::new())
}

/// Fetch all the Bitcoin block headers that connect the peg zone to the tip of Bitcoind's longest
/// chain.
pub fn fetch_linking_headers(
    rpc: &Client,
    common_block_hash: Hash,
) -> Result<Vec<bitcoin::BlockHeader>, RpcError> {
    // Start at bitcoind's best block
    let best_block_hash = rpc.get_best_block_hash()?;
    let mut headers: Vec<bitcoin::BlockHeader> = Vec::new();

    // Handle case where peg and bitcoin are already synced
    if best_block_hash == common_block_hash {
        return Ok(headers);
    }

    let mut header = rpc.get_block_header_raw(&best_block_hash)?;
    headers.push(header);

    let mut count = 0;
    loop {
        header = rpc.get_block_header_raw(&header.prev_blockhash)?;

        if header.prev_blockhash == common_block_hash {
            headers.push(header);
            return Ok(headers);
        } else {
            count += 1;
            if count > 2016 {
                println!("WARNING: Relayer fetched more than 2016 headers");
            }
            headers.push(header);
        }
    }
}

pub fn build_header_transactions(
    headers: &mut Vec<bitcoin::BlockHeader>,
) -> Vec<HeaderTransaction> {
    const BATCH_SIZE: usize = 100;
    headers.reverse();
    headers
        .chunks(BATCH_SIZE)
        .map(|block_headers| HeaderTransaction {
            block_headers: block_headers.to_vec(),
        })
        .collect()
}

/// Broadcast header relay transactions to the peg.
/// Returns an error result if any transactions aren't successfully broadcasted.
pub fn broadcast_header_transactions(
    peg_client: &mut PegClient,
    header_transactions: Vec<HeaderTransaction>,
) -> Result<(), PegClientError> {
    for header_transaction in header_transactions {
        peg_client.send(Transaction::Header(header_transaction))?;
        println!(
            "peg client header len: {}",
            peg_client.get_bitcoin_block_hashes().unwrap().len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn run_relayer_state_machine() {
        let mut sm = RelayerStateMachine::new();
        for _ in 0..2000000 {
            let event = sm.run();
            //println!("sm event: {:?}", event);
            sm.state = sm.state.next(event);
            //println!("sm state: {:?}", sm.state);
        }
    }
}
