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

use super::{Delegation, Params};

/// Relay all staking txs that have been confirmed on the Bitcoin chain.
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
                for del in app.babylon.owner_delegations(owner)? {
                    if del.staking_outpoint.is_none() {
                        unconf_dels.push(del);
                    }
                }
                Ok(unconf_dels)
            })
            .await?;

        if unconf_dels.is_empty() {
            continue;
        }

        log::info!(
            "Found {} unconfirmed delegation{} for owner {}",
            unconf_dels.len(),
            if unconf_dels.len() == 1 { "" } else { "s" },
            owner,
        );

        for del in unconf_dels {
            maybe_relay_staking_conf(app_client, btc_client, &del, &params).await?;
        }
    }

    Ok(())
}

/// Relay a staking tx if it has been confirmed on the Bitcoin chain.
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
            let status = app
                .bitcoin
                .checkpoints
                .get(del.checkpoint_batch_index.0)?
                .status;
            let tx = app
                .bitcoin
                .checkpoints
                .cp_tx(del.checkpoint_batch_index.0, del.checkpoint_batch_index.1)?;

            Ok((status, tx.into_inner()))
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

/// Relay all unbonding txs that have been confirmed on the Bitcoin chain.
pub async fn relay_unbonding_confs(
    app_client: &AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    btc_client: &BitcoinRpcClient,
    bbn_api_addr: &str,
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
        let unconf_dels: Vec<_> = app_client
            .query(|app| {
                Ok(app
                    .babylon
                    .owner_delegations(owner)?
                    .into_iter()
                    .filter(|del| del.status() == DelegationStatus::SignedUnbond)
                    .collect())
            })
            .await?;

        if unconf_dels.is_empty() {
            continue;
        }

        log::info!(
            "Found {} SignedUnbond delegation{} for owner {}",
            unconf_dels.len(),
            if unconf_dels.len() == 1 { "" } else { "s" },
            owner,
        );

        for del in unconf_dels {
            maybe_relay_unbonding_conf(app_client, btc_client, bbn_api_addr, &del, &params).await?;
        }
    }

    Ok(())
}

/// Relay an unbonding tx if it has been confirmed on the Bitcoin chain.
///
/// This function will also submit the unbonding tx to the Babylon API, so that
/// the covenant committee can sign the unbonding tx and the Babylon API can
/// broadcast the unbonding tx to the Bitcoin network.
pub async fn maybe_relay_unbonding_conf(
    app_client: &AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    btc_client: &BitcoinRpcClient,
    bbn_api_addr: &str,
    del: &Delegation,
    params: &crate::babylon::Params,
) -> Result<bool> {
    if del.unbonding_height.is_some() {
        log::debug!("Unbonding tx relayed, continuing");
        return Ok(true);
    }

    let unbonding_tx = del.unbonding_tx(params)?;

    try_submit_unbond(del, bbn_api_addr, params).await?;

    let maybe_conf = scan_for_txid(btc_client, unbonding_tx.txid(), 100).await?;
    if let Some((height, block_hash)) = maybe_conf {
        let proof_bytes = btc_client
            .get_tx_out_proof(&[unbonding_tx.txid()], Some(&block_hash))
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
                        Adapter::new(unbonding_tx.clone())
                    ))
                },
                |app| build_call!(app.app_noop()),
            )
            .await?;
    }

    Ok(false)
}

/// Relay all withdrawal txs to the Bitcoin network.
pub async fn relay_withdrawal_txs(
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
        let withdrawing_dels: Vec<_> = app_client
            .query(|app| {
                Ok(app
                    .babylon
                    .owner_delegations(owner)?
                    .into_iter()
                    .filter(|del| del.status() == DelegationStatus::Withdrawn)
                    .collect())
            })
            .await?;

        for del in withdrawing_dels {
            if let Err(e) = relay_withdrawal_tx(btc_client, &del, &params).await {
                log::error!("Failed to relay withdrawal tx: {:?}", e);
            }
        }
    }

    Ok(())
}

/// Relay a withdrawal tx to the Bitcoin network.
pub async fn relay_withdrawal_tx(
    btc_client: &BitcoinRpcClient,
    del: &Delegation,
    params: &crate::babylon::Params,
) -> Result<()> {
    let withdrawal_tx = del.unbonding_withdrawal_tx(params)?;
    let mut withdrawal_tx_bytes = vec![];
    withdrawal_tx
        .consensus_encode(&mut withdrawal_tx_bytes)
        .unwrap();

    btc_client
        .send_raw_transaction(&withdrawal_tx_bytes)
        .await?;
    log::info!(
        "Relayed withdrawal tx. txid={}, owner={}, index={}",
        withdrawal_tx.txid(),
        del.owner,
        del.index
    );

    Ok(())
}

/// Scans the Bitcoin chain for a txid in the last `num_blocks` blocks.
///
/// This is written as a full scan so nodes aren't required to have been run
/// with `-txindex`.
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

/// Get the last `n` blocks from the Bitcoin chain.
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

/// Submit an unbonding tx to the Babylon API.
pub async fn try_submit_unbond(del: &Delegation, api_addr: &str, params: &Params) -> Result<()> {
    let unbonding_tx = del.unbonding_tx(params)?;
    let mut unbonding_tx_bytes = vec![];
    unbonding_tx
        .consensus_encode(&mut unbonding_tx_bytes)
        .unwrap();

    let body = format!(
        r#"
    {{
        "staker_signed_signature_hex": "{}",
        "staking_tx_hash_hex": "{}",
        "unbonding_tx_hash_hex": "{}",
        "unbonding_tx_hex": "{}"
    }}"#,
        hex::encode(del.staking_unbonding_sig.unwrap().0),
        del.staking_outpoint.unwrap().txid,
        unbonding_tx.txid(),
        hex::encode(unbonding_tx_bytes),
    );

    let res = reqwest::Client::new()
        .post(format!("{}/v1/unbonding", api_addr))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| Error::Relayer(e.to_string()))?;
    let status = res.status().as_u16();

    let res_body: serde_json::Value = res
        .json()
        .await
        .map_err(|e| Error::Relayer(e.to_string()))?;

    if status != 202 {
        let err_message = res_body
            .as_object()
            .cloned()
            .unwrap_or_default()
            .get("message")
            .cloned()
            .unwrap_or_default()
            .as_str()
            .unwrap_or_default()
            .to_string();
        if !err_message.contains("delegation state is not active") {
            log::error!("Failed to submit unbonding tx: {:?}", res_body);
            return Ok(());
        }
    }

    log::info!("Unbonding request submitted to Babylon API");

    Ok(())
}
