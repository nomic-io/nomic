use crate::SECP;
use failure::bail;
use nomic_primitives::{transaction::TransferTransaction, Account, Address, Result};
use orga::{collections::Map, Store};

pub type State<S> = Map<S, Address, Account>;

pub mod handlers {
    use super::*;

    pub fn transfer_tx<S: Store>(accounts: &mut State<S>, tx: TransferTransaction) -> Result<()> {
        if tx.from == tx.to {
            bail!("Account cannot send to itself");
        }
        if tx.fee_amount < 1000 {
            bail!("Transaction fee is too small");
        }
        if tx.from.len() != 33 {
            bail!("Invalid sender address");
        }
        if tx.to.len() != 33 {
            bail!("Invalid recipient address");
        }
        // Retrieve sender account from store
        let maybe_sender_account = accounts.get(unsafe_slice_to_address(&tx.from[..]))?;
        let mut sender_account = match maybe_sender_account {
            Some(sender_account) => sender_account,
            None => bail!("Account does not exist"),
        };
        // Check that the sender account has enough coins
        if sender_account.balance < (tx.amount + tx.fee_amount) {
            bail!("Insufficient balance in sender account");
        }
        // Verify the nonce
        if tx.nonce != sender_account.nonce {
            bail!("Invalid account nonce for transaction");
        }
        // Verify the signature
        if !tx.verify_signature(&SECP)? {
            bail!("Invalid signature");
        }
        // Increment sender's nonce
        sender_account.nonce += 1;
        // Subtract coins from sender
        sender_account.balance -= tx.amount + tx.fee_amount;
        // Fetch (and maybe create) recipient account
        let mut recipient_account = accounts
            .get(unsafe_slice_to_address(&tx.to[..]))?
            .unwrap_or_default();
        // Add coins to recipient
        recipient_account.balance += tx.amount;
        // Save updated accounts to store
        accounts.insert(unsafe_slice_to_address(&tx.from[..]), sender_account)?;
        accounts.insert(unsafe_slice_to_address(&tx.to[..]), recipient_account)?;
        Ok(())
    }
}

fn unsafe_slice_to_address(slice: &[u8]) -> Address {
    // warning: only call this with a slice of length 32
    let mut buf: Address = [0; 33];
    buf.copy_from_slice(slice);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use orga::WrapStore;

    #[test]
    #[should_panic(expected = "Transaction fee is too small")]
    fn transfer_insufficient_fee() {
        let mut net = MockNet::new();

        let mut accounts = State::wrap_store(&mut net.store).unwrap();

        let receiver_address = vec![124; 33];
        let sender = create_sender(&mut accounts, 1234, 0);

        let mut tx = TransferTransaction {
            from: sender.address,
            to: receiver_address.clone(),
            signature: vec![],
            amount: 100,
            nonce: 0,
            fee_amount: 0,
        };
        let sig = sign(&mut tx, sender.privkey);
        tx.signature = sig;

        handlers::transfer_tx(&mut accounts, tx).unwrap();
    }

    #[test]
    #[should_panic(expected = "Account does not exist")]
    fn transfer_from_nonexistent_account() {
        let mut net = MockNet::new();

        let (sender_privkey, sender_pubkey) = create_keypair(1);
        let sender_address = sender_pubkey.serialize().to_vec();
        let receiver_address = vec![124; 33];

        let mut tx = TransferTransaction {
            from: sender_address,
            to: receiver_address.clone(),
            signature: vec![],
            amount: 100,
            nonce: 0,
            fee_amount: 1000,
        };
        let sig = sign(&mut tx, sender_privkey);
        tx.signature = sig;

        let mut accounts = State::wrap_store(&mut net.store).unwrap();
        handlers::transfer_tx(&mut accounts, tx).unwrap();
    }

    #[test]
    #[should_panic(expected = "Insufficient balance in sender account")]
    fn transfer_insufficient_balance() {
        let mut net = MockNet::new();

        let mut accounts = State::wrap_store(&mut net.store).unwrap();
        let receiver_address = vec![124; 33];
        let sender = create_sender(&mut accounts, 1234, 0);

        let mut tx = TransferTransaction {
            from: sender.address,
            to: receiver_address.clone(),
            signature: vec![],
            amount: 300,
            nonce: 0,
            fee_amount: 1000,
        };
        let sig = sign(&mut tx, sender.privkey);
        tx.signature = sig;

        handlers::transfer_tx(&mut accounts, tx).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid account nonce for transaction")]
    fn transfer_invalid_nonce() {
        let mut net = MockNet::new();

        let mut accounts = State::wrap_store(&mut net.store).unwrap();
        let receiver_address = vec![124; 33];
        let sender = create_sender(&mut accounts, 1234, 100);

        let mut tx = TransferTransaction {
            from: sender.address,
            to: receiver_address.clone(),
            signature: vec![],
            amount: 100,
            nonce: 0,
            fee_amount: 1000,
        };
        let sig = sign(&mut tx, sender.privkey);
        tx.signature = sig;

        handlers::transfer_tx(&mut accounts, tx).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid signature")]
    fn transfer_invalid_signature() {
        let mut net = MockNet::new();

        let mut accounts = State::wrap_store(&mut net.store).unwrap();
        let receiver_address = vec![124; 33];
        let sender = create_sender(&mut accounts, 1234, 0);

        let mut tx = TransferTransaction {
            from: sender.address,
            to: receiver_address.clone(),
            signature: vec![],
            amount: 100,
            nonce: 0,
            fee_amount: 1000,
        };
        let sig = sign(&mut tx, sender.privkey);
        tx.signature = sig;
        tx.signature[10] ^= 1;

        handlers::transfer_tx(&mut accounts, tx).unwrap();
    }

    #[test]
    fn transfer_ok() {
        let mut net = MockNet::new();

        let mut accounts = State::wrap_store(&mut net.store).unwrap();
        let receiver_address = vec![124; 33];
        let sender = create_sender(&mut accounts, 1234, 0);

        let mut tx = TransferTransaction {
            from: sender.address.clone(),
            to: receiver_address.clone(),
            signature: vec![],
            amount: 100,
            nonce: 0,
            fee_amount: 1000,
        };
        let sig = sign(&mut tx, sender.privkey);
        tx.signature = sig;

        handlers::transfer_tx(&mut accounts, tx).unwrap();

        assert_eq!(
            accounts
                .get(unsafe_slice_to_address(&receiver_address[..]))
                .unwrap()
                .unwrap(),
            Account {
                balance: 100,
                nonce: 0
            }
        );
        assert_eq!(
            accounts
                .get(unsafe_slice_to_address(&sender.address[..]))
                .unwrap()
                .unwrap(),
            Account {
                balance: 134,
                nonce: 1
            }
        );
    }
    // TODO: test for transfer to self
}
