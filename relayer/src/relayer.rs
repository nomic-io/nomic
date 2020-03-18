use crate::address_pool::AddressPool;
use crate::deposit::relay_deposits;
use crate::Result;
use bitcoin::hash_types::BlockHash as Hash;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use failure::bail;
use nomic_bitcoin::{bitcoin, bitcoincore_rpc};
use nomic_client::Client as PegClient;
use nomic_primitives::transaction::{HeaderTransaction, Transaction};
use std::env;

pub fn make_rpc_client() -> Result<Client> {
    let rpc_user = env::var("BTC_RPC_USER")?;
    let rpc_pass = env::var("BTC_RPC_PASS")?;
    let rpc_auth = Auth::UserPass(rpc_user, rpc_pass);
    let rpc_url = "http://localhost:18332";
    Ok(Client::new(rpc_url.to_string(), rpc_auth)?)
}

/// Iterate over peg hashes, starting from the tip and going backwards.
/// The first hash that we find that's in our full node's longest chain
/// is considered the common ancestor.
pub fn compute_common_ancestor(rpc: &Client, peg_hashes: &[Hash]) -> Result<Hash> {
    for hash in peg_hashes.iter().rev() {
        let rpc_response = rpc.get_block_header_verbose(hash);
        match rpc_response {
            Ok(response) => {
                return Ok(response.hash);
            }
            Err(err) => {
                // XXX: the bitcoincore-rpc library is beig overly strict and failing when confirmations are negative
                if err.to_string() == "JSON-RPC error: JSON decode error: invalid value: integer `-1`, expected u32" {
                    continue;
                }
                bail!("Failed to compute common ancestor");
            }
        }
    }

    bail!("Failed to compute common ancestor");
}

/// Fetch all the Bitcoin block headers that connect the peg zone to the tip of Bitcoind's longest
/// chain.
pub fn fetch_linking_headers(
    rpc: &Client,
    common_block_hash: Hash,
) -> Result<Vec<bitcoin::BlockHeader>> {
    // Start at bitcoind's best block
    let best_block_hash = rpc.get_best_block_hash()?;
    let mut headers: Vec<bitcoin::BlockHeader> = Vec::new();

    // Handle case where peg and bitcoin are already synced
    if best_block_hash == common_block_hash {
        return Ok(headers);
    }

    let mut header = rpc.get_block_header_raw(&best_block_hash)?;

    loop {
        if header.prev_blockhash == common_block_hash {
            headers.push(header);
            headers.reverse();
            return Ok(headers);
        } else {
            headers.push(header);
        }

        header = rpc.get_block_header_raw(&header.prev_blockhash)?;
    }
}

pub fn build_header_transaction(headers: &mut Vec<bitcoin::BlockHeader>) -> HeaderTransaction {
    const BATCH_SIZE: usize = 100;

    HeaderTransaction {
        block_headers: headers[..BATCH_SIZE].to_vec(),
    }
}

/// Broadcast header relay transactions to the peg.
/// Returns an error result if any transactions aren't successfully broadcasted.
pub fn broadcast_header_transaction(
    peg_client: &PegClient,
    header_transaction: HeaderTransaction,
) -> Result<()> {
    peg_client.send(Transaction::Header(header_transaction))?;
    Ok(())
}

/// Start the relayer process
pub fn start() {
    let address_pool = AddressPool::new();

    let relayer_step = || -> Result<()> {
        let btc_rpc = make_rpc_client()?;
        let mut peg_client = PegClient::new("localhost:26657")?;

        // Fetch peg hashes
        let peg_hashes = peg_client.get_bitcoin_block_hashes()?;
        // Compute common header
        let common_block_hash = compute_common_ancestor(&btc_rpc, &peg_hashes)?;
        // Fetch linking headers
        let linking_headers = fetch_linking_headers(&btc_rpc, common_block_hash)?;
        // Build header transactions

        let header_transaction = build_header_transaction(&mut linking_headers.to_vec());
        // Broadcast header transactions

        broadcast_header_transaction(&peg_client, header_transaction)?;
        // Relay deposits
        let possible_addresses = address_pool.addresses();
        relay_deposits(possible_addresses, &btc_rpc, &peg_client)?;
        Ok(())
    };
    println!("Relayer process started. Watching Bitcoin network for new block headers.");
    loop {
        match relayer_step() {
            Err(_) => {}
            Ok(_) => {}
        };
    }
}
