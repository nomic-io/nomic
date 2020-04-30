use super::{State as PegState, Utxo};
use super::{CHECKPOINT_INTERVAL, SIGNATORY_CHANGE_INTERVAL};
use crate::{accounts::State as AccountState, spv::headercache::HeaderCache, SECP};
use bitcoin::hashes::Hash;
use bitcoin::Network::Testnet as bitcoin_network;
use failure::bail;
use log::info;
use nomic_bitcoin::bitcoin;
use nomic_bitcoin::EnrichedHeader;
use nomic_primitives::{transaction::*, Address, Error, Result, Signature, Withdrawal};
use nomic_signatory_set::{Signatory, SignatorySet, SignatorySetSnapshot};
use orga::{abci::messages::Header, Store};
use std::collections::BTreeMap;

pub fn initialize<S: Store>(state: &mut PegState<S>) -> Result<()> {
    // TODO: this should be an action
    let checkpoint = get_checkpoint_header();
    let mut header_cache = HeaderCache::new(bitcoin_network, &mut state.headers);

    header_cache
        .add_header_raw(checkpoint.header, checkpoint.height)
        .map_err(|e| e.into())
}

fn get_checkpoint_header() -> EnrichedHeader {
    let encoded_checkpoint = include_bytes!("../../../../config/header.json");
    let checkpoint: EnrichedHeader = serde_json::from_slice(&encoded_checkpoint[..])
        .expect("Failed to deserialize checkpoint header");

    checkpoint
}

pub fn deposit_tx<S: Store>(
    peg_state: &mut PegState<S>,
    account_state: &mut AccountState<S>,
    deposit_transaction: DepositTransaction,
) -> Result<()> {
    // Hash transaction and check for duplicate
    let txid = deposit_transaction.tx.txid();
    if peg_state
        .processed_deposit_txids
        .contains(txid.as_hash().into_inner())?
    {
        bail!("Transaction was already processed");
    }

    // Fetch merkle root for this block by its height
    let mut header_cache = HeaderCache::new(bitcoin_network, &mut peg_state.headers);
    let tx_height = deposit_transaction.height;
    let header = header_cache.get_header_for_height(tx_height)?;

    let header_merkle_root = match header {
        Some(header) => header.stored.header.merkle_root,
        None => bail!("Merkle root not found for deposit transaction"),
    };

    // Verify proof against the merkle root
    let proof = deposit_transaction.proof;
    let mut txids = vec![txid];
    let mut indexes = vec![deposit_transaction.block_index];
    let proof_merkle_root = proof
        .extract_matches(&mut txids, &mut indexes)
        .map_err(Error::from)?;

    let proof_matches_chain_merkle_root = proof_merkle_root == header_merkle_root;
    if !proof_matches_chain_merkle_root {
        bail!("Proof merkle root does not match chain");
    }

    // Ensure tx contains deposit outputs
    let mut recipients = deposit_transaction.recipients.iter().peekable();
    let mut contains_deposit_outputs = false;
    for (i, txout) in deposit_transaction.tx.output.iter().enumerate() {
        let recipient = match recipients.peek() {
            Some(recipient) => recipient,
            None => bail!("Consumed all recipients"),
        };
        if recipient.len() != 33 {
            bail!("Recipient must be 33 bytes");
        }
        // TODO: support older signatory sets
        let signatory_set_index = peg_state
            .signatory_sets
            .fixed_index(peg_state.signatory_sets.len() - 1);
        let signatory_set = peg_state.current_signatory_set()?;
        let expected_script =
            nomic_signatory_set::output_script(&signatory_set.signatories, recipient.to_vec());
        if txout.script_pubkey != expected_script {
            continue;
        }

        // mint coins
        let depositor_address = unsafe_slice_to_address(recipient.as_slice());
        let mut depositor_account = account_state.get(depositor_address)?.unwrap_or_default();
        depositor_account.balance += txout.value;
        account_state.insert(depositor_address, depositor_account)?;

        // Add UTXO to peg_state
        let utxo = Utxo {
            outpoint: bitcoin::OutPoint {
                txid: deposit_transaction.tx.txid(),
                vout: i as u32,
            }
            .into(),
            signatory_set_index: signatory_set_index as u64,
            data: recipient.to_vec(),
            value: txout.value,
        };
        peg_state.utxos.push_back(utxo)?;

        contains_deposit_outputs = true;
    }
    if !contains_deposit_outputs {
        bail!("Transaction does not contain any deposit outputs");
    }

    // Deposit is valid, mark transaction as processed
    peg_state
        .processed_deposit_txids
        .insert(txid.as_hash().into_inner())?;
    Ok(())
}

pub fn begin_block<S: Store>(
    state: &mut PegState<S>,
    validators: &BTreeMap<Vec<u8>, u64>,
    header: Header,
) -> Result<()> {
    let now = header.get_time().get_seconds() as u64;

    if let None = state.signatory_sets.back()? {
        // init signatories at start of chain
        let signatories = SignatorySetSnapshot {
            time: now,
            signatories: signatories_from_validators(validators)?,
        };
        state.signatory_sets.push_back(signatories)?;
    }

    let time_since_last_checkpoint = now - state.last_checkpoint_time.get_or_default()?;
    if time_since_last_checkpoint > CHECKPOINT_INTERVAL {
        state.last_checkpoint_time.set(now)?;

        if state.pending_utxos()?.is_empty() {
            return Ok(());
        }

        if state.active_checkpoint.is_active.get_or_default()? {
            return Ok(());
        }

        // Starting checkpoint process
        let checkpoint_index = state.checkpoint_index.get_or_default()? + 1;
        state.checkpoint_index.set(checkpoint_index)?;

        state.active_checkpoint.is_active.set(true)?;

        let signatories = state.current_signatory_set()?.signatories;
        for _ in 0..signatories.len() {
            state.active_checkpoint.signatures.push_back(None)?;
        }

        let signatory_set_index = state
            .signatory_sets
            .fixed_index(state.signatory_sets.len() - 1);
        state
            .active_checkpoint
            .signatory_set_index
            .set(signatory_set_index)?;

        state.utxos.drain_into(&mut state.active_checkpoint.utxos)?;
        state
            .pending_withdrawals
            .drain_into(&mut state.active_checkpoint.withdrawals)?;

        // Check if this checkpoint should cause a signatory set transition
        if checkpoint_index % SIGNATORY_CHANGE_INTERVAL == 0 {
            let new_signatories = SignatorySetSnapshot {
                time: now,
                signatories: signatories_from_validators(validators)?,
            };

            state
                .active_checkpoint
                .next_signatory_set
                .set(Some(new_signatories))?;
        }
    }

    Ok(())
}

pub fn header_tx<S: Store>(state: &mut PegState<S>, tx: HeaderTransaction) -> Result<()> {
    let mut header_cache = HeaderCache::new(bitcoin_network, &mut state.headers);
    for header in tx.block_headers {
        header_cache.add_header(&header)?;
    }
    Ok(())
}

pub fn withdrawal_tx<S: Store>(
    state: &mut PegState<S>,
    account_state: &mut AccountState<S>,
    tx: WithdrawalTransaction,
) -> Result<()> {
    if tx.from.len() != 33 {
        bail!("Invalid sender address");
    }
    let maybe_sender_account = account_state.get(unsafe_slice_to_address(&tx.from[..]))?;
    let mut sender_account = match maybe_sender_account {
        Some(sender_account) => sender_account,
        None => bail!("Account does not exist"),
    };

    if sender_account.balance < tx.amount {
        bail!("Insufficient balance in sender account");
    }

    // Verify the nonce
    if tx.nonce != sender_account.nonce {
        bail!("Invalid account nonce for withdrawal transaction");
    }
    // Verify signature
    if !tx.verify_signature(&SECP)? {
        bail!("Invalid signature");
    }

    sender_account.nonce += 1;

    sender_account.balance -= tx.amount;
    account_state.insert(unsafe_slice_to_address(&tx.from[..]), sender_account)?;

    use nomic_bitcoin::Script;
    // Push withdrawal to pending withdrawals deque
    let withdrawal = Withdrawal {
        value: tx.amount,
        script: Script(tx.to),
    };
    Ok(state.pending_withdrawals.push_back(withdrawal)?)
}

pub fn signature_tx<S: Store>(state: &mut PegState<S>, tx: SignatureTransaction) -> Result<()> {
    if !state.active_checkpoint.is_active.get_or_default()? {
        bail!("No checkpoint in progress");
    }

    if tx.signatures.len() != state.active_utxos()?.len() {
        bail!("Number of signatures does not match number of inputs");
    }
    let sigs: Vec<_> = tx
        .signatures
        .iter()
        .map(|sig| {
            if sig.len() != 64 {
                bail!("Invalid signature length")
            } else {
                Ok(unsafe_slice_to_signature(sig.as_slice()))
            }
        })
        .collect::<Result<_>>()?;

    let signatory_index = tx.signatory_index;
    let btc_tx = state.active_checkpoint_tx()?;
    info!("received signature for btc_tx: {:?}", &btc_tx);

    let signatory_set_index = state.active_checkpoint.signatory_set_index.get()?;
    let signatories = state
        .signatory_sets
        .get_fixed(signatory_set_index)?
        .signatories;
    if signatory_index as usize >= signatories.len() {
        bail!("Signatory index out of bounds");
    }
    if let Some(_) = state
        .active_checkpoint
        .signatures
        .get(signatory_index as u64)?
    {
        bail!("Signatory has already signed");
    }
    let signatory = signatories
        .iter()
        .skip(signatory_index as usize)
        .next()
        .unwrap();
    let pubkey = signatory.pubkey.key;

    // Verify signatures
    for (i, signature) in sigs.iter().enumerate() {
        let utxo = state.active_checkpoint.utxos.get(i as u64)?;
        let signatories = state
            .signatory_sets
            .get_fixed(utxo.signatory_set_index)?
            .signatories;

        let script = nomic_signatory_set::redeem_script(&signatories, utxo.data);
        let sighash = bitcoin::util::bip143::SighashComponents::new(&btc_tx).sighash_all(
            &btc_tx.input[i],
            &script,
            utxo.value,
        );

        let message = secp256k1::Message::from_slice(sighash.as_ref())?;
        let signature = secp256k1::Signature::from_compact(&signature[..])?;
        SECP.verify(&message, &signature, &pubkey)?;
    }

    // Increment signed voting power
    let mut signed_voting_power = state
        .active_checkpoint
        .signed_voting_power
        .get_or_default()?;
    signed_voting_power += signatory.voting_power;

    state
        .active_checkpoint
        .signatures
        .set(signatory_index as u64, Some(sigs))?;

    // If >2/3, finalize checkpoint, clear active_checkpoint fields, update last checkpoint time
    if signed_voting_power as u128 > signatories.two_thirds_voting_power() {
        if let Some(new_signatories) = state
            .active_checkpoint
            .next_signatory_set
            .get_or_default()?
        {
            state.signatory_sets.push_back(new_signatories)?;
        }

        state.finalized_checkpoint.utxos.clear()?;
        state.finalized_checkpoint.withdrawals.clear()?;
        state.finalized_checkpoint.signatures.clear()?;

        state
            .active_checkpoint
            .utxos
            .drain_into(&mut state.finalized_checkpoint.utxos)?;
        state
            .active_checkpoint
            .withdrawals
            .drain_into(&mut state.finalized_checkpoint.withdrawals)?;
        state
            .active_checkpoint
            .signatures
            .drain_into(&mut state.finalized_checkpoint.signatures)?;

        state.active_checkpoint.is_active.set(false)?;
        state.active_checkpoint.signed_voting_power.set(0)?;

        state
            .finalized_checkpoint
            .signatory_set_index
            .set(state.active_checkpoint.signatory_set_index.get()?)?;
        state.finalized_checkpoint.next_signatory_set.set(
            state
                .active_checkpoint
                .next_signatory_set
                .get_or_default()?,
        )?;
        state.active_checkpoint.next_signatory_set.set(None)?;

        state.utxos.push_back(Utxo {
            outpoint: nomic_bitcoin::Outpoint {
                txid: btc_tx.txid().as_hash().into_inner(),
                index: btc_tx.output.len() as u32 - 1,
            },
            value: btc_tx.output.last().unwrap().value,
            signatory_set_index: state
                .signatory_sets
                .fixed_index(state.signatory_sets.len() - 1),
            data: vec![],
        })?;
    } else {
        state
            .active_checkpoint
            .signed_voting_power
            .set(signed_voting_power)?;
    }

    Ok(())
}

pub fn signatories_from_validators(validators: &BTreeMap<Vec<u8>, u64>) -> Result<SignatorySet> {
    let mut signatories = SignatorySet::new();
    for (key_bytes, voting_power) in validators.iter() {
        let key = bitcoin::PublicKey::from_slice(key_bytes.as_slice())?;
        signatories.set(Signatory::new(key, *voting_power));
    }
    Ok(signatories)
}

fn unsafe_slice_to_address(slice: &[u8]) -> Address {
    // warning: only call this with a slice of length 32
    let mut buf: Address = [0; 33];
    buf.copy_from_slice(slice);
    buf
}

fn unsafe_slice_to_signature(slice: &[u8]) -> Signature {
    // warning: only call this with a slice of length 64
    let mut buf: Signature = [0; 64];
    buf.copy_from_slice(slice);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    use crate::peg::handlers::signatories_from_validators;
    use crate::spv::headercache::HeaderCache;
    use bitcoin::Network::Testnet as bitcoin_network;
    use lazy_static::lazy_static;
    use nomic_bitcoin::bitcoin;
    use nomic_primitives::transaction::*;
    use nomic_primitives::Account;
    use nomic_signatory_set::{Signatory, SignatorySet, SignatorySetSnapshot};
    use orga::{abci::messages::Header as TendermintHeader, MapStore, WrapStore};
    use protobuf::well_known_types::Timestamp;

    use secp256k1::{Secp256k1, SignOnly};

    lazy_static! {
        pub static ref SECP: Secp256k1<SignOnly> = Secp256k1::signing_only();
    }
    #[test]
    fn init() {
        let mut store = MapStore::new();
        let mut state = PegState::wrap_store(&mut store).unwrap();
        let chkpt = get_checkpoint_header();
        super::initialize(&mut state).unwrap();

        let mut header_cache = HeaderCache::new(bitcoin_network, &mut state.headers);
        let header = header_cache
            .get_header_for_height(chkpt.height)
            .unwrap()
            .unwrap();
        assert_eq!(header.stored.header, chkpt.header);
    }

    #[test]
    #[ignore]
    fn begin_block() {
        let mut net = MockNet::new();
        let mut state = PegState::wrap_store(&mut net.store).unwrap();

        // initial signatories
        let validator_pubkey = mock_validator_set().0.into_iter().next().unwrap().0;
        let mut expected_signatories = SignatorySet::new();
        expected_signatories.set(Signatory {
            pubkey: bitcoin::PublicKey::from_slice(validator_pubkey.as_slice()).unwrap(),
            voting_power: 100,
        });
        assert_eq!(
            state.current_signatory_set().unwrap(),
            SignatorySetSnapshot {
                time: 123,
                signatories: expected_signatories
            }
        );

        // changed validator set, should be same sig set
        net.validators.insert(
            vec![
                2, 120, 15, 192, 99, 177, 43, 235, 23, 134, 193, 123, 205, 196, 253, 121, 49, 80,
                163, 93, 230, 224, 193, 88, 89, 18, 15, 145, 105, 217, 229, 114, 148,
            ],
            555,
        );
        let mut header: TendermintHeader = Default::default();
        let mut timestamp = Timestamp::new();
        timestamp.set_seconds(456);
        header.set_time(timestamp);
        super::begin_block(&mut state, &mut net.validators, header).unwrap();
        let mut expected_signatories = SignatorySet::new();
        expected_signatories.set(Signatory {
            pubkey: bitcoin::PublicKey::from_slice(validator_pubkey.as_slice()).unwrap(),
            voting_power: 100,
        });

        let mut state = PegState::wrap_store(&mut net.store).unwrap();
        assert_eq!(
            state.current_signatory_set().unwrap(),
            SignatorySetSnapshot {
                time: 123,
                signatories: expected_signatories
            }
        );

        // lots of time has passed, signatory set should be updated
        let mut header: TendermintHeader = Default::default();
        let mut timestamp = Timestamp::new();
        timestamp.set_seconds(1_000_000_000);
        header.set_time(timestamp);
        super::begin_block(&mut state, &mut net.validators, header).unwrap();
        let mut expected_signatories = SignatorySet::new();
        let mut state = PegState::wrap_store(&mut net.store).unwrap();
        expected_signatories.set(Signatory {
            pubkey: bitcoin::PublicKey::from_slice(&[
                2, 120, 15, 192, 99, 177, 43, 235, 23, 134, 193, 123, 205, 196, 253, 121, 49, 80,
                163, 93, 230, 224, 193, 88, 89, 18, 15, 145, 105, 217, 229, 114, 148,
            ])
            .unwrap(),
            voting_power: 555,
        });
        expected_signatories.set(Signatory {
            pubkey: bitcoin::PublicKey::from_slice(validator_pubkey.as_slice()).unwrap(),
            voting_power: 100,
        });
        assert_eq!(
            state.current_signatory_set().unwrap(),
            SignatorySetSnapshot {
                time: 1_000_000_000,
                signatories: expected_signatories
            }
        );
    }

    #[test]
    #[should_panic(expected = "Merkle root not found for deposit transaction")]
    fn deposit_invalid_height() {
        let mut net = MockNet::new();

        let (tx, proof) = net.create_btc_proof();
        let deposit = DepositTransaction {
            height: 100,
            proof,
            tx,
            block_index: 0,
            recipients: vec![],
        };

        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        deposit_tx(&mut peg_state, &mut account_state, deposit).unwrap();
    }

    #[test]
    #[should_panic(expected = "Proof merkle root does not match chain")]
    fn deposit_invalid_proof() {
        let mut net = MockNet::new();

        let (tx, proof) = net.create_btc_proof();
        let proof = invalidate_proof(proof);

        let deposit = DepositTransaction {
            height: 0,
            proof,
            tx,
            block_index: 0,
            recipients: vec![],
        };
        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        deposit_tx(&mut peg_state, &mut account_state, deposit).unwrap();
    }

    #[test]
    #[should_panic(expected = "Transaction does not contain any deposit outputs")]
    fn deposit_irrelevant() {
        let mut net = MockNet::new();

        let (tx, proof) = net.create_btc_proof();
        let deposit = DepositTransaction {
            height: 0,
            proof,
            tx,
            block_index: 0,
            recipients: vec![vec![123; 33]],
        };
        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        deposit_tx(&mut peg_state, &mut account_state, deposit).unwrap();
    }

    #[test]
    #[should_panic(expected = "Transaction was already processed")]
    fn deposit_duplicate() {
        let tx = build_tx(vec![build_txout(
            100_000_000,
            nomic_signatory_set::output_script(
                &signatories_from_validators(&mock_validator_set().0).unwrap(),
                vec![123; 33],
            ),
        )]);
        let block = build_block(vec![tx.clone()]);
        let mut net = MockNet::with_btc_block(block);

        let (_, proof) = net.create_btc_proof();
        let deposit = DepositTransaction {
            height: 0,
            proof,
            tx,
            block_index: 0,
            recipients: vec![vec![123; 33]],
        };

        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        deposit_tx(&mut peg_state, &mut account_state, deposit.clone()).unwrap();
        deposit_tx(&mut peg_state, &mut account_state, deposit).unwrap();
    }

    #[test]
    #[should_panic(expected = "Consumed all recipients")]
    fn deposit_no_recipients() {
        let tx = build_tx(vec![build_txout(
            100_000_000,
            nomic_signatory_set::output_script(
                &signatories_from_validators(&mock_validator_set().0).unwrap(),
                vec![123; 33],
            ),
        )]);
        let block = build_block(vec![tx.clone()]);
        let mut net = MockNet::with_btc_block(block);

        let (_, proof) = net.create_btc_proof();
        let deposit = DepositTransaction {
            height: 0,
            proof,
            tx,
            block_index: 0,
            recipients: vec![],
        };
        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        deposit_tx(&mut peg_state, &mut account_state, deposit).unwrap();
    }

    #[test]
    fn deposit_ok() {
        let tx = build_tx(vec![build_txout(
            100_000_000,
            nomic_signatory_set::output_script(
                &signatories_from_validators(&mock_validator_set().0).unwrap(),
                vec![123; 33],
            ),
        )]);

        let block = build_block(vec![tx.clone()]);
        let mut net = MockNet::with_btc_block(block);
        let (tx, proof) = net.create_btc_proof();
        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        let deposit = DepositTransaction {
            height: 0,
            proof,
            tx,
            block_index: 0,
            recipients: vec![vec![123; 33]],
        };

        deposit_tx(&mut peg_state, &mut account_state, deposit).unwrap();
        // check recipient balance
        assert_eq!(
            account_state.get([123; 33]).unwrap().unwrap(),
            Account {
                balance: 100_000_000,
                nonce: 0
            }
        );
    }

    #[test]
    fn withdrawal_ok() {
        let mut net = MockNet::new();
        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        let sender = create_sender(&mut account_state, 1234, 0);

        let mut tx = WithdrawalTransaction {
            from: sender.address.clone(),
            to: bitcoin::Script::from(vec![123]),
            amount: 1000,
            signature: vec![],
            nonce: 0,
        };
        let sig = sign(&mut tx, sender.privkey);
        tx.signature = sig;
        withdrawal_tx(&mut peg_state, &mut account_state, tx).unwrap();

        assert_eq!(
            account_state
                .get(unsafe_slice_to_address(&sender.address[..]))
                .unwrap()
                .unwrap(),
            Account {
                balance: 234,
                nonce: 1,
            }
        );
        assert_eq!(peg_state.pending_withdrawals.get(0).unwrap().value, 1000);
    }

    #[test]
    #[should_panic(expected = "Invalid signature")]
    fn withdrawal_invalid_signature() {
        let mut net = MockNet::new();
        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        let sender = create_sender(&mut account_state, 1234, 0);

        let mut tx = WithdrawalTransaction {
            from: sender.address.clone(),
            to: bitcoin::Script::from(vec![123]),
            amount: 1000,
            signature: vec![],
            nonce: 0,
        };
        let sig = sign(&mut tx, sender.privkey);
        tx.signature = sig;
        tx.signature[10] ^= 1;
        withdrawal_tx(&mut peg_state, &mut account_state, tx).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid account nonce for withdrawal transaction")]
    fn withdrawal_invalid_nonce() {
        let mut net = MockNet::new();
        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        let sender = create_sender(&mut account_state, 1234, 100);

        let mut tx = WithdrawalTransaction {
            from: sender.address.clone(),
            to: bitcoin::Script::from(vec![123]),
            amount: 1000,
            signature: vec![],
            nonce: 0,
        };
        let sig = sign(&mut tx, sender.privkey);
        tx.signature = sig;
        withdrawal_tx(&mut peg_state, &mut account_state, tx).unwrap();
    }

    #[test]
    #[should_panic(expected = "Insufficient balance in sender account")]
    fn withdrawal_insufficient_balance() {
        let mut net = MockNet::new();
        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        let sender = create_sender(&mut account_state, 1234, 0);

        let mut tx = WithdrawalTransaction {
            from: sender.address.clone(),
            to: bitcoin::Script::from(vec![123]),
            amount: 2000,
            signature: vec![],
            nonce: 0,
        };
        let sig = sign(&mut tx, sender.privkey);
        tx.signature = sig;
        withdrawal_tx(&mut peg_state, &mut account_state, tx).unwrap();
    }

    #[test]
    #[should_panic(expected = "Account does not exist")]
    fn withdrawal_from_nonexistent_account() {
        let mut net = MockNet::new();
        let mut peg_state = PegState::wrap_store(&mut net.store).unwrap();
        let mut account_state = AccountState::wrap_store(&mut net.store2).unwrap();

        let (sender_privkey, sender_pubkey) = create_keypair(1);
        let sender_address = sender_pubkey.serialize().to_vec();

        let mut tx = WithdrawalTransaction {
            from: sender_address,
            to: bitcoin::Script::from(vec![123]),
            amount: 1000,
            signature: vec![],
            nonce: 0,
        };
        let sig = sign(&mut tx, sender_privkey);
        tx.signature = sig;
        withdrawal_tx(&mut peg_state, &mut account_state, tx).unwrap();
    }

    // Signature tx tests
    #[test]
    #[should_panic(expected = "No checkpoint in progress")]
    fn signatory_signature_no_active_checkpoint() {
        let mut net = MockNet::new();
        let mut state = PegState::wrap_store(&mut net.store).unwrap();

        let tx = SignatureTransaction {
            signatures: vec![],
            signatory_index: 0,
        };
        signature_tx(&mut state, tx).unwrap();
    }

    #[test]
    #[ignore]
    #[should_panic(expected = "Number of signatures does not match number of inputs")]
    fn signatory_signature_incorrect_signature_count() {
        let mut net = MockNet::with_active_checkpoint();
        let mut state = PegState::wrap_store(&mut net.store).unwrap();

        let tx = SignatureTransaction {
            signatures: vec![],
            signatory_index: 0,
        };
        signature_tx(&mut state, tx).unwrap();
    }

    #[test]
    #[ignore]
    #[should_panic(expected = "Invalid signature length")]
    fn signatory_invalid_signature_length() {
        let mut net = MockNet::with_active_checkpoint();
        let mut state = PegState::wrap_store(&mut net.store).unwrap();

        let tx = SignatureTransaction {
            signatures: vec![vec![1, 2, 3]],
            signatory_index: 0,
        };
        signature_tx(&mut state, tx).unwrap();
    }

    #[test]
    #[ignore]
    #[should_panic(expected = "Signatory index out of bounds")]
    fn signatory_invalid_signatory_index() {
        let mut net = MockNet::with_active_checkpoint();
        let mut state = PegState::wrap_store(&mut net.store).unwrap();

        let tx = SignatureTransaction {
            signatures: vec![vec![123; 64]],
            signatory_index: 123,
        };
        signature_tx(&mut state, tx).unwrap();
    }

    #[test]
    #[ignore]
    #[should_panic(expected = "IncorrectSignature")]
    fn signatory_invalid_signature() {
        let mut net = MockNet::with_active_checkpoint();
        let mut state = PegState::wrap_store(&mut net.store).unwrap();

        let tx = SignatureTransaction {
            signatures: vec![vec![123; 64]],
            signatory_index: 0,
        };
        signature_tx(&mut state, tx).unwrap();
    }

    #[test]
    #[ignore]
    fn signatory_ok() {
        let mut net = MockNet::with_active_checkpoint();

        let mut state = PegState::wrap_store(&mut net.store).unwrap();
        assert!(state.active_checkpoint.is_active.get().unwrap());
        assert_eq!(state.utxos.len(), 0);

        let utxo = state.active_checkpoint.utxos.get(0).unwrap();
        let signatories = state.signatory_sets.get_fixed(0).unwrap().signatories;
        let btc_tx = state.active_checkpoint_tx().unwrap();
        let script = nomic_signatory_set::output_script(&signatories, utxo.data);
        let sighash = btc_tx
            .signature_hash(0, &script, bitcoin::SigHashType::All.as_u32())
            .as_hash()
            .into_inner();

        let message = secp256k1::Message::from_slice(&sighash[..]).unwrap();
        let privkey = &net.validator_privkeys[0];
        let mut sig = SECP.sign(&message, privkey).serialize_compact().to_vec();

        let tx = SignatureTransaction {
            signatures: vec![sig],
            signatory_index: 0,
        };
        signature_tx(&mut state, tx).unwrap();

        let mut state = PegState::wrap_store(&mut net.store).unwrap();
        assert_eq!(state.utxos.len(), 1);
        assert!(!state.active_checkpoint.is_active.get().unwrap());
        assert_eq!(state.active_checkpoint.utxos.len(), 0);
        assert_eq!(state.active_checkpoint.withdrawals.len(), 0);
        assert_eq!(
            state.active_checkpoint.signed_voting_power.get().unwrap(),
            0
        );
        assert_eq!(state.active_checkpoint.signatures.len(), 0);
        assert_eq!(state.finalized_checkpoint.signatures.len(), 1);
        assert_eq!(state.finalized_checkpoint.utxos.len(), 1);
        assert_eq!(state.finalized_checkpoint.withdrawals.len(), 0);
    }
}
