// TODO: scan loop
// TODO: relay confirmed delegations to nomic
// TODO: relay signed, confirmed delegations to babylon

use bech32::ToBase32;
use bitcoin::{
    consensus::{Decodable, Encodable},
    psbt::serialize::Serialize,
    secp256k1::{self, hashes::Hash, KeyPair, Secp256k1},
    Block, BlockHash, TxOut,
};
use bitcoincore_rpc_async::{json::GetBlockHeaderResult, Client as BitcoinRpcClient, RpcApi};
use cosmos_sdk_proto::cosmos::crypto::secp256k1::PubKey;
use cosmrs::{
    crypto::secp256k1::SigningKey,
    tx::{mode_info::Single, MessageExt, ModeInfo, SignDoc, SignMode},
};
use orga::ibc::ibc_rs::clients::AsAny;
use orga::{
    call::build_call,
    client::{wallet::Unsigned, AppClient, Client},
    tendermint::client::HttpClient,
};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::{
    app::{InnerApp, Nom},
    babylon::DelegationStatus,
    bitcoin::{adapter::Adapter, checkpoint::CheckpointStatus, threshold_sig::Pubkey},
    error::{Error, Result},
};

use super::{proto, Delegation};

// TODO: scan loop
// TODO: sign and submit pops
// TODO: sign and submit slashing sigs

pub async fn maybe_relay_staking_conf(
    app_client: AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    btc_client: BitcoinRpcClient,
    del: &Delegation,
) -> Result<bool> {
    dbg!(&del);

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

    let maybe_conf = scan_for_txid(&btc_client, tx.txid(), 100).await?;
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

pub async fn maybe_relay_create_delegation(
    btc_client: &BitcoinRpcClient,
    bbn_privkey: &secp256k1::SecretKey,
    del: &Delegation,
) -> Result<bool> {
    if del.status()? != DelegationStatus::Signed {
        log::debug!("Delegation not yet signed");
        return Ok(false);
    }

    let block_hash = btc_client
        .get_block_hash(del.staking_height.unwrap() as u64)
        .await?;
    let block = btc_client.get_block_info(&block_hash).await?;
    let (block_index, proof_bytes) =
        super::create_proof(&block.tx, del.staking_outpoint.unwrap().txid);

    let staking_tx_bytes = btc_client
        .get_raw_transaction(&del.staking_outpoint.unwrap().txid, Some(&block_hash))
        .await?
        .serialize();

    let mut sha = Sha256::new();
    sha.update(del.bbn_key.as_slice());
    let hash = sha.finalize();
    use ripemd::Digest as _;
    let mut ripemd = ripemd::Ripemd160::new();
    ripemd.update(hash);
    let hash = ripemd.finalize();
    let mut bbn_addr_bytes = [0; orga::coins::Address::LENGTH];
    bbn_addr_bytes.copy_from_slice(hash.as_slice());
    let bbn_addr =
        bech32::encode("bbn", bbn_addr_bytes.to_base32(), bech32::Variant::Bech32).unwrap();

    let pop = proto::ProofOfPossession {
        babylon_sig: del.pop_bbn_sig.unwrap().to_vec(),
        btc_sig: del.pop_btc_sig.unwrap().to_vec(),
        btc_sig_type: proto::BtcSigType::Bip322.into(),
    };

    let msg = proto::MsgCreateBtcDelegation {
        babylon_pk: Some(PubKey {
            key: del.bbn_key.as_slice().to_vec(),
        }),
        btc_pk: del.btc_key.to_vec(),
        fp_btc_pk_list: del.fp_keys.iter().map(|k| k.to_vec()).collect(),
        pop: Some(pop),
        staking_time: del.staking_period as u32,
        staking_tx: Some(proto::btccheckpoint::TransactionInfo {
            key: Some(proto::btccheckpoint::TransactionKey {
                index: block_index,
                hash: block_hash.as_ref().to_vec(),
            }),
            transaction: staking_tx_bytes,
            proof: proof_bytes,
        }),
        staking_value: del.stake_sats() as i64,
        unbonding_time: del.unbonding_period as u32,
        unbonding_value: (del.stake_sats() - 1_000) as i64, // TODO: get from config
        delegator_slashing_sig: del.slashing_tx_sig.unwrap().to_vec(),
        delegator_unbonding_slashing_sig: del.unbonding_slashing_tx_sig.unwrap().to_vec(),
        signer: bbn_addr,
        slashing_tx: del.slashing_tx()?.serialize(),
        unbonding_tx: del.unbonding_tx()?.serialize(),
        unbonding_slashing_tx: del.unbonding_slashing_tx()?.serialize(),
    };

    let body = cosmrs::tx::Body::new([msg.to_any().unwrap()], "", u32::MAX);
    let auth_info = cosmrs::tx::AuthInfo {
        signer_infos: vec![cosmrs::tx::SignerInfo {
            public_key: Some(cosmrs::tx::SignerPublicKey::Single(
                cosmrs::tendermint::public_key::PublicKey::from_raw_secp256k1(
                    del.bbn_key.as_slice(),
                )
                .unwrap()
                .into(),
            )),
            mode_info: ModeInfo::Single(Single {
                mode: SignMode::Direct,
            }),
            sequence: 0,
        }],
        fee: cosmrs::tx::Fee {
            gas_limit: 200_000,
            amount: vec![cosmrs::Coin {
                denom: "ubbn".parse().unwrap(),
                amount: 200,
            }],
            payer: None,
            granter: None,
        },
    };

    let sign_doc = SignDoc::new(&body, &auth_info, &"bbn-test-3".parse().unwrap(), 224180).unwrap();
    let signing_key = SigningKey::from_slice(&bbn_privkey.secret_bytes()).unwrap();
    let tx_signed = sign_doc.sign(&signing_key).unwrap().to_bytes().unwrap();

    dbg!(hex::encode(&del.btc_key));

    log::info!("Broadcasting MsgCreateBtcDelegation to Babylon");
    use tendermint_rpc::Client;
    dbg!(
        tendermint_rpc::HttpClient::new("https://rpc.testnet3.babylonchain.io") // TODO: pass in
            .unwrap()
            .broadcast_tx_sync(tx_signed)
            .await
            .unwrap()
    );

    Ok(true)
}
