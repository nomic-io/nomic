use crate::peg::handlers::signatories_from_validators;
use crate::spv::headercache::HeaderCache;
use bitcoin::consensus::encode as bitcoin_encode;
use bitcoin::util::hash::bitcoin_merkle_root;
use bitcoin::util::merkleblock::PartialMerkleTree;
use lazy_static::lazy_static;
use nomic_bitcoin::bitcoin;
use nomic_primitives::{
    transaction::{DepositTransaction, Sighash},
    Account, Address,
};
use orga::{abci::messages::Header as TendermintHeader, MapStore, Store, WrapStore};

use protobuf::well_known_types::Timestamp;
use secp256k1::{Secp256k1, SecretKey, SignOnly};
use std::collections::{BTreeMap, HashSet};

lazy_static! {
    pub static ref SECP: Secp256k1<SignOnly> = Secp256k1::signing_only();
}

pub fn mock_validator_set() -> (BTreeMap<Vec<u8>, u64>, Vec<SecretKey>) {
    let (val_privkey, val_pubkey) = create_keypair(1);
    let val_address = val_pubkey.serialize().to_vec();
    let mut vals = BTreeMap::new();
    vals.insert(val_address, 100);
    (vals, vec![val_privkey])
}

pub struct MockNet {
    pub store: MapStore,
    pub store2: MapStore,
    pub validators: BTreeMap<Vec<u8>, u64>,
    pub btc_block: bitcoin::Block,
    pub validator_privkeys: Vec<SecretKey>,
}

impl MockNet {
    pub fn new() -> Self {
        let tx = build_tx(vec![build_txout(100_000_000, vec![].into())]);
        let block = build_block(vec![tx.clone()]);
        MockNet::with_btc_block(block)
    }

    pub fn with_btc_block(initial_block: bitcoin::Block) -> Self {
        let validators = mock_validator_set();
        let mut net = MockNet {
            store: Default::default(),
            store2: Default::default(),
            validators: validators.0,
            btc_block: initial_block.clone(),
            validator_privkeys: validators.1,
        };

        let mut state = crate::peg::State::wrap_store(&mut net.store).unwrap();
        HeaderCache::new(bitcoin::Network::Regtest, &mut state.headers)
            .add_header_raw(initial_block.header, 0)
            .expect("failed to create mock net");

        // initial beginblock
        let mut header: TendermintHeader = Default::default();
        let mut timestamp = Timestamp::new();
        timestamp.set_seconds(0);
        header.set_time(timestamp);

        crate::peg::handlers::begin_block(&mut state, &mut net.validators, header).unwrap();

        net
    }

    pub fn create_btc_proof(
        &self,
    ) -> (
        bitcoin::Transaction,
        bitcoin::util::merkleblock::PartialMerkleTree,
    ) {
        let tx = self.btc_block.txdata[0].clone();
        let mut txids = HashSet::new();
        txids.insert(tx.txid());
        (
            tx,
            bitcoin::MerkleBlock::from_block(&self.btc_block, &txids).txn,
        )
    }

    pub fn with_active_checkpoint() -> MockNet {
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
        
        let mut peg_state = crate::peg::State::wrap_store(&mut net.store).unwrap();
        let mut account_state = crate::accounts::State::wrap_store(&mut net.store2).unwrap();

        let deposit = DepositTransaction {
            height: 0,
            proof,
            tx,
            block_index: 0,
            recipients: vec![vec![123; 33]],
        };
        
        crate::peg::handlers::deposit_tx(&mut peg_state, &mut account_state, deposit.clone()).unwrap();

        let mut header: orga::abci::messages::Header = Default::default();
        let mut timestamp = Timestamp::new();
        timestamp.set_seconds(super::peg::CHECKPOINT_INTERVAL as i64 * 2);
        header.set_time(timestamp);
        crate::peg::handlers::begin_block(&mut peg_state, &mut net.validators, header).unwrap();

        net
    }
}

pub fn build_txout(value: u64, script_pubkey: bitcoin::Script) -> bitcoin::TxOut {
    bitcoin::TxOut {
        value,
        script_pubkey,
    }
}

pub fn build_tx(outputs: Vec<bitcoin::TxOut>) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: outputs,
    }
}

pub fn build_block(txs: Vec<bitcoin::Transaction>) -> bitcoin::Block {
    let hashes = txs.iter().map(|tx| tx.txid().as_hash());
    let merkle_root = bitcoin_merkle_root(hashes).into();

    let header = bitcoin::BlockHeader {
        version: 1,
        prev_blockhash: Default::default(),
        merkle_root,
        time: 1,
        bits: 0x207fffff,
        nonce: 0,
    };

    bitcoin::Block {
        header,
        txdata: txs,
    }
}

pub fn invalidate_proof(proof: PartialMerkleTree) -> PartialMerkleTree {
    let mut proof_bytes = bitcoin_encode::serialize(&proof);
    proof_bytes[10] ^= 1;
    bitcoin_encode::deserialize(proof_bytes.as_slice()).unwrap()
}

pub fn create_keypair(byte: u8) -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    let privkey = secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP, &privkey);
    (privkey, pubkey)
}

pub fn sign<S: Sighash>(tx: &mut S, privkey: secp256k1::SecretKey) -> Vec<u8> {
    let message = secp256k1::Message::from_slice(tx.sighash().unwrap().as_slice()).unwrap();
    let signature = SECP.sign(&message, &privkey);
    signature.serialize_compact().to_vec()
}

fn unsafe_slice_to_address(slice: &[u8]) -> Address {
    // warning: only call this with a slice of length 32
    let mut buf: Address = [0; 33];
    buf.copy_from_slice(slice);
    buf
}

pub struct Sender {
    pub address: Vec<u8>,
    pub privkey: secp256k1::SecretKey,
}
pub fn create_sender<S: Store>(
    accounts: &mut crate::accounts::State<S>,
    balance: u64,
    nonce: u64,
) -> Sender {
    let (privkey, pubkey) = create_keypair(1);
    let address = pubkey.serialize().to_vec();

    accounts
        .insert(
            unsafe_slice_to_address(address.as_slice()),
            Account { balance, nonce },
        )
        .unwrap();

    Sender { address, privkey }
}
