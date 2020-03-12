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
                    if let Some(_) = store.get(key.as_slice())? {
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
    let checkpoint = get_checkpoint_header();
    let mut header_cache = HeaderCache::new(bitcoin_network, store);

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
    use crate::Action;
    use nomic_primitives::transaction::*;
    use bitcoin::Network::Testnet as bitcoin_network;
    use bitcoin::util::hash::bitcoin_merkle_root;
    use bitcoin::util::merkleblock::PartialMerkleTree;
    use bitcoin::consensus::encode as bitcoin_encode;
    use orga::MapStore;
    use std::collections::{BTreeMap, HashSet};

    #[derive(Default)]
    struct MockNet {
        store: MapStore,
        validators: BTreeMap<Vec<u8>, u64>
    }

    impl MockNet {
        fn new(initial_header: bitcoin::BlockHeader) -> Self {
            let mut net: Self = Default::default();
            net.spv().add_header_raw(initial_header, 0)
                .expect("failed to create mock net");
            net
        }

        fn spv(&mut self) -> HeaderCache {
            HeaderCache::new(bitcoin::Network::Regtest, &mut self.store)
        }
    }

    fn build_txout(value: u64, script_pubkey: bitcoin::Script) -> bitcoin::TxOut {
        bitcoin::TxOut { value, script_pubkey }
    }

    fn build_tx(outputs: Vec<bitcoin::TxOut>) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![],
            output: outputs
        }
    }

    fn build_block(txs: Vec<bitcoin::Transaction>) -> bitcoin::Block {
        let hashes = txs.iter().map(|tx| tx.txid().as_hash());
        let merkle_root = bitcoin_merkle_root(hashes).into();

        let header = bitcoin::BlockHeader {
            version: 1,
            prev_blockhash: Default::default(),
            merkle_root,
            time: 1,
            bits: 0x207fffff,
            nonce: 0
        };

        bitcoin::Block {
            header,
            txdata: txs
        }
    }

    fn invalidate_proof(proof: PartialMerkleTree) -> PartialMerkleTree {
        let mut proof_bytes = bitcoin_encode::serialize(&proof);
        proof_bytes[10] ^= 1;
        bitcoin_encode::deserialize(proof_bytes.as_slice()).unwrap()
    }

    #[test]
    fn init() {
        let mut store = MapStore::new();
        let chkpt = get_checkpoint_header();
        initialize(&mut store).unwrap();

        let mut header_cache = HeaderCache::new(bitcoin_network, &mut store);
        let header = header_cache
            .get_header_for_height(chkpt.height)
            .unwrap()
            .unwrap();
        assert_eq!(header.stored.header, chkpt.header);
    }

    #[test]
    #[should_panic(expected = "Merkle root not found for deposit transaction")]
    fn deposit_invalid_height() {
        let tx = build_tx(vec![
            build_txout(100_000_000, vec![].into())
        ]);
        let block = build_block(vec![ tx.clone() ]);
        let mut net = MockNet::new(block.header.clone());

        let mut txids = HashSet::new();
        txids.insert(tx.txid());
        let proof = bitcoin::MerkleBlock::from_block(&block, &txids).txn;

        let deposit = DepositTransaction {
            height: 100,
            proof,
            txs: vec![ IncludedTx { index: 0, tx: tx.clone() } ]
        };
        let action = Action::Transaction(Transaction::Deposit(deposit));

        run(&mut net.store, action, &mut net.validators).unwrap();
    }

    #[test]
    #[should_panic(expected = "Proof merkle root does not match chain")]
    fn deposit_invalid_proof() {
        let tx = build_tx(vec![
            build_txout(100_000_000, vec![].into())
        ]);
        let block = build_block(vec![ tx.clone() ]);
        let mut net = MockNet::new(block.header.clone());

        let mut txids = HashSet::new();
        txids.insert(tx.txid());
        let proof = bitcoin::MerkleBlock::from_block(&block, &txids).txn;
        let proof = invalidate_proof(proof);

        let deposit = DepositTransaction {
            height: 0,
            proof,
            txs: vec![ IncludedTx { index: 0, tx: tx.clone() } ]
        };
        let action = Action::Transaction(Transaction::Deposit(deposit));

        run(&mut net.store, action, &mut net.validators).unwrap();
    }
}
