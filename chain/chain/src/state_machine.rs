use crate::spv::headercache::HeaderCache;
use crate::Action;
use nomic_bitcoin::{bitcoin, EnrichedHeader};
use nomic_primitives::transaction::Transaction;
use nomic_work::work;
use bitcoin::Network::Testnet as bitcoin_network;
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
) -> Result<(), StateMachineError> {
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
                        store.put(hash.to_vec(), vec![0]);
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
                            println!("header add err: {:?}", e);
                            return Err(StateMachineError::new());
                        }
                    }
                }
            }
            _ => (),
        },
        _ => (),
    };

    Ok(())
}

/// Called once at genesis to write some data to the store.
pub fn initialize(store: &mut dyn Store) {
    let mut header_cache = HeaderCache::new(bitcoin_network, store);
    let checkpoint = get_checkpoint_header();

    header_cache.add_header_raw(checkpoint.header, checkpoint.height);
}

fn get_checkpoint_header() -> EnrichedHeader {
    let encoded_checkpoint = include_bytes!("../../../config/header");
    let checkpoint: EnrichedHeader = bincode::deserialize(&encoded_checkpoint[..])
        .expect("Failed to deserialize checkpoint header");

    checkpoint
}

#[derive(Debug)]
pub struct StateMachineError {}

impl StateMachineError {
    fn new() -> Self {
        StateMachineError {}
    }
}
