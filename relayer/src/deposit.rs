use crate::Result;
use bitcoin::Network::Testnet as bitcoin_network;
use bitcoincore_rpc::{Client, RpcApi};
use log::warn;
use nomic_bitcoin::{bitcoin, bitcoincore_rpc};
use nomic_client::Client as PegClient;
use nomic_primitives::transaction::{DepositTransaction, Transaction};
use nomic_signatory_set::SignatorySet;
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
    recipients: &[Vec<u8>],
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
        recipients: recipients.to_vec(),
    };

    Transaction::Deposit(deposit_tx)
}

fn possible_bitcoin_addresses(
    signatory_sets: Vec<SignatorySet>,
    possible_recipients: Vec<Vec<u8>>,
) -> Vec<(bitcoin::Address, Vec<u8>)> {
    let result = signatory_sets
        .iter()
        .map(|signatory_set| {
            possible_recipients.iter().map(move |possible_recipient| {
                let script =
                    nomic_signatory_set::output_script(&signatory_set, possible_recipient.clone());
                (
                    bitcoin::Address::from_script(&script, bitcoin_network).unwrap(),
                    possible_recipient.clone(),
                )
            })
        })
        .flatten()
        .collect();

    result
}

pub fn relay_deposits(
    possible_recipients: &HashSet<Vec<u8>>,
    btc_rpc: &Client,
    peg_client: &PegClient,
) -> Result<()> {
    let signatory_sets = peg_client.get_signatory_sets()?;
    let recipients = possible_recipients.iter().cloned().collect();
    for (address, recipient) in
        possible_bitcoin_addresses(signatory_sets, recipients)
    {
        let btc_deposit_txs = scan_for_deposits(btc_rpc, address)?;
        let recipients = &[recipient];
        btc_deposit_txs
            .into_iter()
            .map(|btc_deposit_tx| build_deposit_tx(&btc_rpc, btc_deposit_tx, recipients))
            .for_each(|tx| {
                let result = peg_client.send(tx);
                // Swallow error; the relayer will just retry
                match result {
                    Err(e) => warn!("Error sending deposit tx: {:?}", e),
                    _ => (),
                }
            });
    }
    Ok(())
}

pub fn import_addresses(
    possible_recipients: Vec<Vec<u8>>,
    btc_rpc: &Client,
    peg_client: &PegClient,
) -> Result<()> {
    let signatory_sets = peg_client.get_signatory_sets()?;
    let recipients = possible_recipients.into_iter().collect();
    for (address, _) in
        possible_bitcoin_addresses(signatory_sets, recipients)
    {
        btc_rpc.import_address(&address, None, Some(false), None)?;
    }
    Ok(())
}
