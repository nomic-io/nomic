use crate::Result;
use bitcoin::Network::Testnet as bitcoin_network;
use bitcoincore_rpc::{Client, RpcApi};
use nomic_bitcoin::{bitcoin, bitcoincore_rpc};
use nomic_client::Client as PegClient;
use nomic_primitives::transaction::{DepositTransaction, Transaction};
use std::collections::HashSet;
/// Scan target address for any deposit transactions
fn scan_for_deposits(
    btc_rpc: &Client,
    address: bitcoin::Address,
) -> Result<Vec<VerboseTransaction>> {
    let unspent = btc_rpc.list_unspent(None, None, Some(&[address]), None, None)?;

    unspent
        .into_iter()
        .map(|unspent| get_transaction_by_txid(btc_rpc, unspent.txid))
        .collect()
}

struct VerboseTransaction {
    pub height: u32,
    pub blockhash: bitcoin::BlockHash,
    pub tx: bitcoin::Transaction,
    pub index: u32,
}
fn get_transaction_by_txid(btc_rpc: &Client, txid: bitcoin::Txid) -> Result<VerboseTransaction> {
    let tx_result = btc_rpc.get_transaction(&txid, Some(true)).unwrap();
    let index = tx_result.info.blockindex.unwrap() as u32;
    let blockhash = tx_result.info.blockhash.expect("Blockhash was None");
    let block_info = btc_rpc.get_block_info(&blockhash)?;
    let height = block_info.height as u32;
    let tx = tx_result.transaction()?;
    Ok(VerboseTransaction {
        height,
        tx,
        index,
        blockhash,
    })
}

fn build_deposit_tx(
    btc_rpc: &Client,
    tx: VerboseTransaction,
    recipients: Vec<[u8; 32]>,
) -> Transaction {
    let block = btc_rpc.get_block(&tx.blockhash).unwrap();
    let mut txids = HashSet::new();
    txids.insert(tx.tx.txid());
    let proof = bitcoin::MerkleBlock::from_block(&block, &txids).txn;

    let deposit_tx = DepositTransaction {
        height: tx.height,
        proof,
        tx: tx.tx,
        block_index: tx.index,
        recipients,
    };

    Transaction::Deposit(deposit_tx)
}

fn possible_bitcoin_addresses(
    signatory_sets: Vec<SignatorySet>,
    possible_recipients: Vec<[u8; 32]>,
) -> impl Iterator<Item = (bitcoin::Address, [u8; 32])> {
    signatory_sets
        .iter()
        .map(|signatory_set| {
            possible_recipients.iter().map(|possible_recipient| {
                let script =
                    nomic_signatory_set::output_script(signatory_set, possible_recipient.to_vec());
                bitcoin::Address::from_script(script, bitcoin_network)
            })
        })
        .flatten()
}

pub fn relay_deposits(
    possible_recipients: Vec<[u8; 32]>,
    btc_rpc: &Client,
    peg_client: &mut PegClient,
) -> Result<()> {
    let signatory_sets = peg_client.get_signatory_sets()?;
    for (address, recipient) in possible_bitcoin_addresses(signatory_sets, possible_recipients) {
        let btc_deposit_txs = scan_for_deposits(btc_rpc, address)?;
        btc_deposit_txs
            .into_iter()
            .map(|btc_deposit_tx| build_deposit_tx(&btc_rpc, btc_deposit_tx, recipient))
            .for_each(|tx| {
                peg_client.send(tx);
            });
    }
    Ok(())
}
