use super::CHECKPOINT_FEE_AMOUNT;
use failure::bail;
use nomic_bitcoin::bitcoin;
use nomic_primitives::{Result, Signature, Withdrawal};
use nomic_signatory_set::SignatorySetSnapshot;
use orga::{
    collections::{Deque, Set},
    state, Decode, Encode, Store, Value, Wrapper,
};

#[state]
pub struct State {
    pub signatory_sets: Deque<SignatorySetSnapshot>,
    pub processed_deposit_txids: Set<[u8; 32]>,
    pub pending_withdrawals: Deque<Withdrawal>,
    pub utxos: Deque<Utxo>,
    pub finalized_checkpoint: FinalizedCheckpoint,
    pub last_checkpoint_time: Value<u64>,
    pub active_checkpoint: ActiveCheckpoint,
    pub checkpoint_index: Value<u64>,
    pub headers: Wrapper,
}

#[derive(Clone, Encode, Decode)]
pub struct Utxo {
    pub outpoint: nomic_bitcoin::Outpoint,
    pub value: u64,
    pub signatory_set_index: u64,
    pub data: Vec<u8>,
}

#[state]
pub struct FinalizedCheckpoint {
    pub withdrawals: Deque<Withdrawal>,
    pub signatory_set_index: Value<u64>,
    pub utxos: Deque<Utxo>,
    pub signatures: Deque<Option<Vec<Signature>>>,
    pub next_signatory_set: Value<Option<SignatorySetSnapshot>>,
}

#[state]
pub struct ActiveCheckpoint {
    pub is_active: Value<bool>,
    pub signatures: Deque<Option<Vec<Signature>>>,
    pub signed_voting_power: Value<u64>,
    pub signatory_set_index: Value<u64>,
    pub utxos: Deque<Utxo>,
    pub withdrawals: Deque<Withdrawal>,
    pub next_signatory_set: Value<Option<SignatorySetSnapshot>>,
}

impl<S: Store> State<S> {
    pub fn current_signatory_set(&self) -> Result<SignatorySetSnapshot> {
        Ok(self.signatory_sets.back()?.unwrap())
    }

    pub fn pending_utxos(&self) -> Result<Vec<Utxo>> {
        // TODO: don't prune utxos, support spending from older signatory set
        let current_signatory_set_index = self
            .signatory_sets
            .fixed_index(self.signatory_sets.len() - 1);

        self.utxos
            .iter()
            .filter(|utxo| match utxo {
                Err(_) => true,
                Ok(utxo) => utxo.signatory_set_index == current_signatory_set_index,
            })
            .collect()
    }

    pub fn active_utxos(&self) -> Result<Vec<Utxo>> {
        // TODO: don't prune utxos, support spending from older signatory set
        let signatory_set_index = self.active_checkpoint.signatory_set_index.get()?;

        self.active_checkpoint
            .utxos
            .iter()
            .filter(|utxo| match utxo {
                Err(_) => true,
                Ok(utxo) => utxo.signatory_set_index == signatory_set_index,
            })
            .collect()
    }

    pub fn active_checkpoint_tx(&self) -> Result<bitcoin::Transaction> {
        let mut input_amount = 0;
        let mut output_amount = 0;

        let signatory_set_index = self
            .active_checkpoint
            .signatory_set_index
            .get_or_default()?;
        let signatories = self
            .signatory_sets
            .get_fixed(signatory_set_index)?
            .signatories;

        let inputs = self
            .active_utxos()?
            .into_iter()
            .map(|utxo| {
                input_amount += utxo.value;
                bitcoin::TxIn {
                    previous_output: utxo.outpoint.clone().into(),
                    script_sig: vec![].into(),
                    sequence: u32::MAX,
                    witness: vec![],
                }
            })
            .collect();

        let mut outputs: Vec<_> = self
            .active_checkpoint
            .withdrawals
            .iter()
            .map(|w| {
                w.map(|withdrawal| {
                    output_amount += withdrawal.value;
                    withdrawal.clone().into()
                })
            })
            .collect::<Result<_>>()?;

        // TODO: calculate fee based on final tx size
        let change_amount = input_amount - output_amount - CHECKPOINT_FEE_AMOUNT;
        let next_signatory_set = self.active_checkpoint.next_signatory_set.get_or_default()?;
        let change_signatories = match next_signatory_set {
            Some(next_snapshot) => next_snapshot.signatories,
            None => signatories,
        };
        let change_script = nomic_signatory_set::output_script(&change_signatories, vec![]);
        outputs.push(bitcoin::TxOut {
            value: change_amount,
            script_pubkey: change_script,
        });

        let tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: inputs,
            output: outputs,
        };

        Ok(tx)
    }

    pub fn has_finalized_checkpoint(&self) -> bool {
        !self.finalized_checkpoint.utxos.is_empty()
    }

    pub fn finalized_checkpoint_tx(&self) -> Result<bitcoin::Transaction> {
        if !self.has_finalized_checkpoint() {
            bail!("No finalized checkpoint");
        }

        let mut input_amount = 0;
        let mut output_amount = 0;

        let sig_set_index = self
            .finalized_checkpoint
            .signatory_set_index
            .get_or_default()?;
        let signatories = self.signatory_sets.get(sig_set_index)?.signatories;

        let inputs = self
            .finalized_checkpoint
            .utxos
            .iter()
            .filter(|utxo| match utxo {
                Err(_) => true,
                Ok(utxo) => utxo.signatory_set_index == sig_set_index,
            })
            .enumerate()
            .map(|(i, utxo)| {
                utxo.map(|utxo| {
                    input_amount += utxo.value;

                    let mut witness: Vec<_> = self
                        .finalized_checkpoint
                        .signatures
                        .iter()
                        .collect::<Result<Vec<_>>>()? // TODO: implement DoubleEndedIterator for Deque Iter
                        .iter()
                        .rev()
                        .map(|maybe_sigs| {
                            maybe_sigs.as_ref().map_or(vec![], |sigs| {
                                let sig = secp256k1::Signature::from_compact(&sigs[i][..]).unwrap();
                                let mut sig = sig.serialize_der().to_vec();
                                sig.push(
                                    bitcoin::blockdata::transaction::SigHashType::All.as_u32()
                                        as u8,
                                );
                                sig
                            })
                        })
                        .collect();

                    let redeem_script = nomic_signatory_set::redeem_script(&signatories, utxo.data);
                    witness.push(redeem_script.to_bytes());

                    Ok(bitcoin::TxIn {
                        previous_output: utxo.outpoint.clone().into(),
                        script_sig: vec![].into(),
                        sequence: u32::MAX,
                        witness,
                    })
                })?
            })
            .collect::<Result<_>>()?;

        let mut outputs: Vec<_> = self
            .finalized_checkpoint
            .withdrawals
            .iter()
            .map(|w| {
                w.map(|withdrawal| {
                    output_amount += withdrawal.value;
                    withdrawal.clone().into()
                })
            })
            .collect::<Result<_>>()?;

        // TODO: calculate fee based on final tx size
        let change_amount = input_amount - output_amount - CHECKPOINT_FEE_AMOUNT;
        let next_signatory_set = self
            .finalized_checkpoint
            .next_signatory_set
            .get_or_default()?;
        let change_signatories = match next_signatory_set {
            Some(next_snapshot) => next_snapshot.signatories,
            None => signatories,
        };
        let change_script = nomic_signatory_set::output_script(&change_signatories, vec![]);
        outputs.push(bitcoin::TxOut {
            value: change_amount,
            script_pubkey: change_script,
        });

        let tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: inputs,
            output: outputs,
        };

        Ok(tx)
    }
}
