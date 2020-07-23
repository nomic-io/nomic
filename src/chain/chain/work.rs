use crate::core::primitives::{transaction::WorkProofTransaction, Result};
use crate::core::work::work;
use failure::bail;
use orga::{collections::Set, Store};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MIN_WORK: u64 = 1 << 20;

pub type State<S> = Set<S, [u8; 32]>;

pub mod handlers {
    use super::*;

    pub fn work_proof_tx<S: Store>(
        redeemed_work_hashes: &mut State<S>,
        validators: &mut BTreeMap<Vec<u8>, u64>,
        tx: WorkProofTransaction,
    ) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.input(&tx.public_key);
        let nonce_bytes = tx.nonce.to_be_bytes();
        hasher.input(&nonce_bytes);
        let hash: [u8; 32] = hasher.result().into();
        let work_proof_value = work(&hash);

        if work_proof_value < MIN_WORK {
            bail!("Proof has less than minimum work value")
        }

        // Make sure this proof hasn't been redeemed yet
        if redeemed_work_hashes.contains(hash)? {
            bail!("Work proof has already been redeemed")
        }

        // Grant voting power
        let current_voting_power = *validators.get(&tx.public_key).unwrap_or(&0);
        let new_voting_power = work_proof_value / MIN_WORK;

        validators.insert(tx.public_key, current_voting_power + new_voting_power);
        // Write the redeemed hash to the store so it can't be replayed
        redeemed_work_hashes.insert(hash)?;

        Ok(())
    }
}
