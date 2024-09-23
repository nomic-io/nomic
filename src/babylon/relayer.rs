// TODO: scan loop
// TODO: relay confirmed delegations to nomic
// TODO: relay signed, confirmed delegations to babylon

use bech32::ToBase32;
use bitcoin::{
    consensus::{Decodable, Encodable},
    psbt::serialize::Serialize,
    secp256k1::{self, hashes::Hash},
    Block, BlockHash, TxMerkleNode, TxOut, Txid,
};
use bitcoincore_rpc_async::{Client as BitcoinRpcClient, RpcApi};
use cosmos_sdk_proto::cosmos::crypto::secp256k1::PubKey;
use cosmrs::{
    crypto::secp256k1::SigningKey,
    tx::{mode_info::Single, MessageExt, ModeInfo, SignDoc, SignMode},
};
use orga::{
    call::build_call,
    client::{wallet::Unsigned, AppClient},
    tendermint::client::HttpClient,
};
use sha2::{Digest, Sha256};

use crate::{
    app::{InnerApp, Nom},
    babylon::DelegationStatus,
    bitcoin::{adapter::Adapter, checkpoint::CheckpointStatus},
    error::{Error, Result},
};

use super::{
    proto::{self, MsgCreateBtcDelegation},
    Delegation,
};

pub async fn relay_staking_confs(
    app_client: &AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    btc_client: &BitcoinRpcClient,
) -> Result<()> {
    let delegations = app_client
        .query(|app| {
            for del in app.babylon.delegations.iter()? {
                del?;
            }

            Ok(app.babylon.delegations)
        })
        .await?;

    let delegations = delegations
        .iter()?
        .filter_map(|del| match del {
            Err(err) => Some(Err(err)),
            Ok(del) => {
                if del.staking_outpoint.is_some() {
                    return None;
                }
                Some(Ok(del))
            }
        })
        .collect::<orga::Result<Vec<_>>>()?;

    if delegations.is_empty() {
        return Ok(());
    }

    log::info!("Found {} unconfirmed delegations", delegations.len());

    for del in delegations {
        maybe_relay_staking_conf(app_client, btc_client, &del).await?;
    }

    Ok(())
}

pub async fn maybe_relay_staking_conf(
    app_client: &AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    btc_client: &BitcoinRpcClient,
    del: &Delegation,
) -> Result<bool> {
    if del.staking_outpoint.is_some() {
        log::debug!("Staking tx relayed, continuing");
        return Ok(true);
    }

    let (cp_status, tx) = app_client
        .query(|app| {
            let cp = app.bitcoin.checkpoints.get(del.checkpoint_index)?;
            Ok((cp.status, cp.checkpoint_tx()?))
        })
        .await?;
    if cp_status != CheckpointStatus::Complete {
        log::debug!("Checkpoint not yet finalized");
        return Ok(false);
    }

    let maybe_conf = scan_for_txid(btc_client, tx.txid(), 100).await?;
    if let Some((height, block_hash)) = maybe_conf {
        let proof_bytes = btc_client
            .get_tx_out_proof(&[tx.txid()], Some(&block_hash))
            .await?;
        let proof = ::bitcoin::MerkleBlock::consensus_decode(&mut proof_bytes.as_slice())?.txn;

        let staking_script = del.staking_script()?;
        let vout = tx
            .output
            .iter()
            .position(|out| {
                let stake_amount: u64 = del.stake.amount.into();
                *out == TxOut {
                    script_pubkey: staking_script.clone(),
                    value: stake_amount / 1_000_000, // TODO: get conversion from config
                }
            })
            .ok_or_else(|| {
                Error::Orga(orga::Error::App(format!(
                    "Staking output not found in checkpoint tx {}",
                    tx.txid()
                )))
            })? as u32;

        log::info!("Submitting staking tx proof...");
        app_client
            .call(
                |app| {
                    build_call!(app.relay_btc_staking_tx(
                        del.index,
                        height,
                        Adapter::new(proof.clone()),
                        tx.clone(),
                        vout
                    ))
                },
                |app| build_call!(app.app_noop()),
            )
            .await?;
    }

    Ok(false)
}

// TODO: dedupe from bitcoin relayer
async fn scan_for_txid(
    client: &BitcoinRpcClient,
    txid: bitcoin::Txid,
    num_blocks: usize,
) -> Result<Option<(u32, BlockHash)>> {
    let tip = client.get_best_block_hash().await?;
    let base_height = client.get_block_header_info(&tip).await?.height;
    let blocks = last_n_blocks(client, num_blocks, tip).await?;

    for (i, block) in blocks.into_iter().enumerate().rev() {
        let height = (base_height - i) as u32;
        for tx in block.txdata.iter() {
            if tx.txid() == txid {
                return Ok(Some((height, block.block_hash())));
            }
        }
    }

    Ok(None)
}

// TODO: dedupe from bitcoin relayer
pub async fn last_n_blocks(
    client: &BitcoinRpcClient,
    n: usize,
    hash: BlockHash,
) -> Result<Vec<Block>> {
    let mut blocks = vec![];

    let mut hash = bitcoin::BlockHash::from_inner(hash.into_inner());

    for _ in 0..n {
        let block = client.get_block(&hash.clone()).await?;
        hash = block.header.prev_blockhash;

        let mut block_bytes = vec![];
        block.consensus_encode(&mut block_bytes).unwrap();
        let block = Block::consensus_decode(&mut block_bytes.as_slice()).unwrap();

        blocks.push(block);
    }

    Ok(blocks)
}
