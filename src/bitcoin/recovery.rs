use super::{
    adapter::Adapter,
    checkpoint::{BitcoinTx, Input},
    signatory::{derive_pubkey, SignatorySet},
    threshold_sig::Signature,
    Xpub,
};
use crate::{
    app::Dest,
    error::{Error, Result},
};
use bitcoin::{OutPoint, Transaction, TxOut};
use orga::{collections::Deque, encoding::LengthVec, orga};

#[orga(skip(Default))]
pub struct RecoveryTx {
    tx: BitcoinTx,
    old_sigset_index: u32,
    new_sigset_index: u32,
    dest: Dest,
}

#[orga(skip(Default))]
pub struct SignedRecoveryTx {
    pub tx: Adapter<Transaction>,
    pub sigset_index: u32,
    pub dest: Dest,
}

#[orga]
pub struct RecoveryTxs {
    txs: Deque<RecoveryTx>,
}

pub struct RecoveryTxInput<'a> {
    pub expired_tx: Transaction,
    pub vout: u32,
    pub old_sigset: &'a SignatorySet,
    pub new_sigset: &'a SignatorySet,
    pub threshold: (u64, u64),
    pub fee_rate: u64,
    pub dest: Dest,
}

#[orga]
impl RecoveryTxs {
    pub fn new() -> Self {
        Self { txs: Deque::new() }
    }

    pub fn create_recovery_tx(&mut self, args: RecoveryTxInput) -> Result<()> {
        let expired_output = args
            .expired_tx
            .output
            .get(args.vout as usize)
            .ok_or_else(|| Error::Signer("Invalid recovery tx vout".to_string()))?;
        let commitment_bytes = args.dest.commitment_bytes()?;

        let input = Input::new(
            OutPoint::new(args.expired_tx.txid(), args.vout),
            args.old_sigset,
            &commitment_bytes,
            expired_output.value,
            args.threshold,
        )?;
        let script_pubkey = args
            .new_sigset
            .output_script(&commitment_bytes, args.threshold)?;
        let output = TxOut {
            value: expired_output.value,
            script_pubkey,
        };

        let mut tx = BitcoinTx::default();
        tx.input.push_back(input)?;
        tx.output.push_back(Adapter::new(output))?;

        tx.deduct_fee(args.fee_rate * tx.est_vsize()?)?;

        tx.populate_input_sig_message(0)?;

        self.txs.push_back(RecoveryTx {
            tx,
            old_sigset_index: args.old_sigset.index,
            new_sigset_index: args.new_sigset.index,
            dest: args.dest,
        })?;

        Ok(())
    }

    #[query]
    pub fn to_sign(&self, xpub: Xpub) -> Result<Vec<([u8; 32], u32)>> {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        let mut msgs = vec![];

        for tx in self.txs.iter()? {
            let tx = tx?;
            for input in tx.tx.input.iter()? {
                let input = input?;

                let pubkey = derive_pubkey(&secp, xpub, input.sigset_index)?;
                if input.signatures.needs_sig(pubkey.into())? {
                    msgs.push((input.signatures.message(), input.sigset_index));
                }
            }
        }

        Ok(msgs)
    }

    #[call]
    fn sign(&mut self, xpub: Xpub, sigs: LengthVec<u16, Signature>) -> Result<()> {
        super::exempt_from_fee()?;

        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        let mut sig_index = 0;

        if sigs.is_empty() {
            return Err(Error::Signer(
                "No signatures supplied for recovery transaction".to_string(),
            ));
        }

        for i in 0..self.txs.len() {
            let mut tx = self
                .txs
                .get_mut(i)?
                .ok_or_else(|| Error::Signer("Error getting recovery transaction".to_string()))?;

            for k in 0..tx.tx.input.len() {
                let mut input = tx.tx.input.get_mut(k)?.unwrap();
                let pubkey = derive_pubkey(&secp, xpub, input.sigset_index)?;

                if !input.signatures.needs_sig(pubkey.into())? {
                    continue;
                }

                if sig_index >= sigs.len() {
                    return Err(Error::Signer(
                        "Not enough signatures supplied for recovery transaction".to_string(),
                    ));
                }
                let sig = sigs[sig_index];
                sig_index += 1;

                let input_was_signed = input.signatures.signed();
                input.signatures.sign(pubkey.into(), sig)?;

                if !input_was_signed && input.signatures.signed() {
                    tx.tx.signed_inputs += 1;
                }
            }
        }

        if sig_index != sigs.len() {
            return Err(Error::Signer(
                "Excess signatures supplied for recovery transaction".to_string(),
            ));
        }

        Ok(())
    }

    #[query]
    pub fn signed(&self) -> Result<Vec<SignedRecoveryTx>> {
        let mut txs = vec![];

        for tx in self.txs.iter()? {
            let tx = tx?;
            if tx.tx.signed() {
                txs.push(SignedRecoveryTx {
                    tx: Adapter::new(tx.tx.to_bitcoin_tx()?),
                    sigset_index: tx.new_sigset_index,
                    dest: tx.dest.clone(),
                });
            }
        }

        Ok(txs)
    }
}
