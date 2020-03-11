use crate::spv::headercache::HeaderCache;
use crate::Action;
use bitcoin::Network::Testnet as bitcoin_network;
use bitcoin::Txid;
use failure::bail;
use nomic_bitcoin::{bitcoin, EnrichedHeader};
use nomic_primitives::transaction::Transaction;
use nomic_primitives::{Error, Result};
use nomic_work::work;
use orga::Store;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MIN_WORK: u64 = 1 << 20;
/// Main entrypoint to the core bitcoin peg state machine.
///
/// This function implements the conventions set by Orga, though this may change as our core
/// framework design settles.
pub fn run(
    store: &mut dyn Store,
    action: Action,
    validators: &mut BTreeMap<Vec<u8>, u64>,
) -> Result<()> {
    match action {
        Action::Transaction(transaction) => match transaction {
            Transaction::WorkProof(work_transaction) => {
                let mut hasher = Sha256::new();
                hasher.input(&work_transaction.public_key);
                let nonce_bytes = work_transaction.nonce.to_be_bytes();
                hasher.input(&nonce_bytes);
                let hash = hasher.result().to_vec();
                let work_proof_value = work(&hash);

                if work_proof_value >= MIN_WORK {
                    // Make sure this proof hasn't been redeemed yet
                    let value_at_work_proof_hash = store.get(&hash).unwrap_or(None);
                    if let None = value_at_work_proof_hash {
                        // Grant voting power
                        let current_voting_power = *validators
                            .get(&work_transaction.public_key)
                            .unwrap_or(&(0 as u64));

                        validators.insert(
                            work_transaction.public_key,
                            current_voting_power + work_proof_value,
                        );
                        // Write the redeemed hash to the store so it can't be replayed
                        store.put(hash.to_vec(), vec![0])?;
                    } else {
                        println!("duplicate work proof: {:?},\n\nHash: {:?}, \n\nValue stored at hash on store: {:?}", work_transaction, hash, value_at_work_proof_hash);
                    }
                }
            }
            Transaction::Header(header_transaction) => {
                let mut header_cache = HeaderCache::new(bitcoin_network, store);
                for header in header_transaction.block_headers {
                    match header_cache.add_header(&header) {
                        Ok(_) => {}
                        Err(e) => {
                            bail!("header add err: {:?}", e);
                        }
                    }
                }
            }

            Transaction::Deposit(deposit_transaction) => {
                // Hash transactions and check for duplicates
                let txs = deposit_transaction.txs;
                let mut txids: Vec<Txid> = txs.iter().map(|tx| tx.tx.txid()).collect();
                for txid in txids.iter() {
                    let hash = txid.as_hash();
                    let key = [b"tx/", hash.as_ref()].concat();
                    if let Some(_val) = store.get(key.as_slice())? {
                        bail!("Duplicate transaction in deposit proof");
                    }
                }
                // Fetch merkle root for this block by its height
                let mut header_cache = HeaderCache::new(bitcoin_network, store);
                let tx_height = deposit_transaction.height;
                let header = header_cache.get_header_for_height(tx_height)?;

                let header_merkle_root = match header {
                    Some(header) => header.stored.header.merkle_root,
                    None => bail!("Merkle root not found for deposit transaction"),
                };

                // Verify proof against the merkle root
                let proof = deposit_transaction.proof;
                let mut indexes = txs.iter().map(|tx| tx.index).collect();
                let proof_merkle_root = proof
                    .extract_matches(&mut txids, &mut indexes)
                    .map_err(Error::from)?;

                let proof_matches_chain_merkle_root = proof_merkle_root == header_merkle_root;
                if !proof_matches_chain_merkle_root {
                    bail!("Proof merkle root does not match chain");
                }
                // Verify transactions against the proof
                // Deposit is valid, mark transactions as relayed
                // Mint coins
            }
        },
    };

    Ok(())
}

/// Called once at genesis to write some data to the store.
pub fn initialize(store: &mut dyn Store) -> Result<()> {
    let mut header_cache = HeaderCache::new(bitcoin_network, store);
    let checkpoint = get_checkpoint_header();

    header_cache
        .add_header_raw(checkpoint.header, checkpoint.height)
        .map_err(|e| e.into())
}

fn get_checkpoint_header() -> EnrichedHeader {
    let encoded_checkpoint = include_bytes!("../../../config/header.json");
    let checkpoint: EnrichedHeader = serde_json::from_slice(&encoded_checkpoint[..])
        .expect("Failed to deserialize checkpoint header");

    checkpoint
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network::Testnet as bitcoin_network;
    use orga::MapStore;
    use std::collections::BTreeMap;
    #[test]
    fn init() {
        let mut store = MapStore::new();
        let chkpt = get_checkpoint_header();
        initialize(&mut store);

        let mut header_cache = HeaderCache::new(bitcoin_network, &mut store);
        let header = header_cache.get_header_for_height(0).unwrap().unwrap();
        assert_eq!(header.stored.header, chkpt.header);
    }
}
