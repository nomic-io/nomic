// TODO: scan loop
// TODO: relay confirmed delegations to nomic
// TODO: relay signed, confirmed delegations to babylon

use bitcoin::{
    consensus::{Decodable, Encodable},
    secp256k1::hashes::Hash,
    Block, BlockHash, TxOut,
};
use bitcoincore_rpc_async::{Client as BitcoinRpcClient, RpcApi};
use ed::{Decode, Encode};
use orga::{
    call::build_call,
    client::{wallet::Unsigned, AppClient},
    tendermint::client::HttpClient,
};

use crate::{
    app::{Identity, InnerApp, Nom},
    babylon::DelegationStatus,
    bitcoin::{
        adapter::Adapter,
        checkpoint::{BatchType, CheckpointStatus},
    },
    error::{Error, Result},
};

use super::Delegation;

pub async fn relay_staking_confs(
    app_client: &AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    btc_client: &BitcoinRpcClient,
) -> Result<()> {
    let (owners, params) = app_client
        .query(|app| {
            let mut owners = vec![];
            for entry in app.babylon.delegations.iter()? {
                let (owner, _) = entry?;
                let owner = owner.encode()?;
                let owner = Identity::decode(&mut owner.as_slice())?;
                owners.push(owner);
            }
            Ok((owners, app.babylon.params.clone()))
        })
        .await?;
    for owner in owners {
        let unconf_dels = app_client
            .query(|app| {
                let mut unconf_dels = vec![];
                for entry in app.babylon.delegations.get(owner)?.unwrap().iter()? {
                    let del = entry?.encode()?;
                    let del = Delegation::decode(&mut del.as_slice())?;
                    if del.staking_outpoint.is_none() {
                        unconf_dels.push(del);
                    }
                }
                Ok(unconf_dels)
            })
            .await?;

        log::info!(
            "Found {} unconfirmed delegations for owner {}",
            unconf_dels.len(),
            owner,
        );

        for del in unconf_dels {
            maybe_relay_staking_conf(app_client, btc_client, &del, &params).await?;
        }
    }

    Ok(())
}

pub async fn maybe_relay_staking_conf(
    app_client: &AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    btc_client: &BitcoinRpcClient,
    del: &Delegation,
    params: &crate::babylon::Params,
) -> Result<bool> {
    if del.staking_outpoint.is_some() {
        log::debug!("Staking tx relayed, continuing");
        return Ok(true);
    }

    let (cp_status, tx) = app_client
        .query(|app| {
            let cp = app.bitcoin.checkpoints.get(del.checkpoint_batch_index.0)?;
            let batch = cp.batches.get(BatchType::Checkpoint as u64)?.unwrap();
            let tx = batch.get(del.checkpoint_batch_index.1)?.unwrap();
            Ok((cp.status, tx.to_bitcoin_tx()?))
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

        let staking_script = del.staking_script(params)?;
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
                        del.owner,
                        del.index,
                        height,
                        Adapter::new(proof.clone()),
                        Adapter::new(tx.clone()),
                        vout
                    ))
                },
                |app| build_call!(app.app_noop()),
            )
            .await?;
    }

    Ok(false)
}

pub async fn relay_unbonding_confs(
    app_client: &AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    btc_client: &BitcoinRpcClient,
) -> Result<()> {
    let (owners, params) = app_client
        .query(|app| {
            let mut owners = vec![];
            for entry in app.babylon.delegations.iter()? {
                let (owner, _) = entry?;
                let owner = owner.encode()?;
                let owner = Identity::decode(&mut owner.as_slice())?;
                owners.push(owner);
            }
            Ok((owners, app.babylon.params.clone()))
        })
        .await?;
    for owner in owners {
        let unconf_dels = app_client
            .query(|app| {
                let mut unconf_dels = vec![];
                for entry in app.babylon.delegations.get(owner)?.unwrap().iter()? {
                    let del = entry?.encode()?;
                    let del = Delegation::decode(&mut del.as_slice())?;
                    if del.status() == DelegationStatus::SignedUnbond {
                        unconf_dels.push(del);
                    }
                }
                Ok(unconf_dels)
            })
            .await?;

        log::info!(
            "Found {} SignedUnbond delegations for owner {}",
            unconf_dels.len(),
            owner,
        );

        for del in unconf_dels {
            maybe_relay_unbonding_conf(app_client, btc_client, &del, &params).await?;
        }
    }

    Ok(())
}

pub async fn maybe_relay_unbonding_conf(
    app_client: &AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    btc_client: &BitcoinRpcClient,
    del: &Delegation,
    params: &crate::babylon::Params,
) -> Result<bool> {
    if del.unbonding_height.is_some() {
        log::debug!("Unbonding tx relayed, continuing");
        return Ok(true);
    }

    let tx = del.unbonding_tx(params)?;

    let maybe_conf = scan_for_txid(btc_client, tx.txid(), 100).await?;
    if let Some((height, block_hash)) = maybe_conf {
        let proof_bytes = btc_client
            .get_tx_out_proof(&[tx.txid()], Some(&block_hash))
            .await?;
        let proof = ::bitcoin::MerkleBlock::consensus_decode(&mut proof_bytes.as_slice())?.txn;

        log::info!("Submitting unbonding tx proof...");
        app_client
            .call(
                |app| {
                    build_call!(app.relay_btc_unbonding_tx(
                        del.owner,
                        del.index,
                        height,
                        Adapter::new(proof.clone()),
                        Adapter::new(tx.clone())
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
