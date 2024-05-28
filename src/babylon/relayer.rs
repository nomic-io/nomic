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
use cosmos_sdk_proto::{cosmos::crypto::secp256k1::PubKey, traits::TypeUrl};
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

pub async fn relay_create_msgs(
    app_client: &AppClient<InnerApp, InnerApp, HttpClient, Nom, Unsigned>,
    btc_client: &BitcoinRpcClient,
    relayer_privkey: secp256k1::SecretKey,
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
                if del.status().unwrap() != DelegationStatus::Signed {
                    return None;
                }
                Some(Ok(del))
            }
        })
        .collect::<orga::Result<Vec<_>>>()?;

    if delegations.is_empty() {
        return Ok(());
    }

    log::info!("Found {} signed delegations", delegations.len());

    for del in delegations {
        maybe_relay_create_delegation(btc_client, relayer_privkey, &del).await?;
    }

    todo!()
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

pub fn bbn_addr(pubkey: secp256k1::PublicKey) -> String {
    let mut sha = Sha256::new();
    sha.update(pubkey.serialize());
    let hash = sha.finalize();

    use ripemd::Digest as _;
    let mut ripemd = ripemd::Ripemd160::new();
    ripemd.update(hash);
    let hash = ripemd.finalize();

    let mut bbn_addr_bytes = [0; orga::coins::Address::LENGTH];
    bbn_addr_bytes.copy_from_slice(hash.as_slice());

    bech32::encode("bbn", bbn_addr_bytes.to_base32(), bech32::Variant::Bech32).unwrap()
}

impl Delegation {
    pub fn to_create_msg(&self, relayer_addr: String) -> Result<proto::MsgCreateBtcDelegation> {
        let pop = proto::ProofOfPossession {
            babylon_sig: self.pop_bbn_sig.unwrap().to_vec(),
            btc_sig: self.pop_btc_sig.unwrap().to_vec(),
            btc_sig_type: proto::BtcSigType::Bip322.into(),
        };

        Ok(proto::MsgCreateBtcDelegation {
            babylon_pk: Some(PubKey {
                key: self.bbn_key.as_slice().to_vec(),
            }),
            btc_pk: self.btc_key.to_vec(),
            fp_btc_pk_list: self.fp_keys.iter().map(|k| k.to_vec()).collect(),
            pop: Some(pop),
            staking_time: self.staking_period as u32,
            staking_tx: None,
            staking_value: self.stake_sats() as i64,
            unbonding_time: self.unbonding_period as u32,
            unbonding_value: (self.stake_sats() - 1_000) as i64, // TODO: get from config
            delegator_slashing_sig: self.slashing_tx_sig.unwrap().to_vec(),
            delegator_unbonding_slashing_sig: self.unbonding_slashing_tx_sig.unwrap().to_vec(),
            signer: relayer_addr.to_string(),
            slashing_tx: self.slashing_tx()?.serialize(),
            unbonding_tx: self.unbonding_tx()?.serialize(),
            unbonding_slashing_tx: self.unbonding_slashing_tx()?.serialize(),
        })
    }
}

pub async fn maybe_relay_create_delegation(
    btc_client: &BitcoinRpcClient,
    relayer_privkey: secp256k1::SecretKey,
    del: &Delegation,
) -> Result<bool> {
    if del.status()? != DelegationStatus::Signed {
        log::debug!("Delegation not yet signed");
        return Ok(false);
    }

    if del.index == 4 {
        return Ok(true);
    }
    dbg!(del.index, del.staking_outpoint);

    let secp = secp256k1::Secp256k1::new();

    let relayer_pubkey = relayer_privkey.public_key(&secp);
    let relayer_addr = bbn_addr(relayer_pubkey);
    dbg!(&relayer_addr);

    let mut msg = del.to_create_msg(relayer_addr)?;

    let block_hash = btc_client
        .get_block_hash(del.staking_height.unwrap() as u64)
        .await?;
    let block = btc_client.get_block_info(&block_hash).await?;
    let (block_index, proof_bytes) = create_proof(
        &block.tx,
        del.staking_outpoint.unwrap().txid,
        Some(block.merkleroot),
    );
    let staking_tx_bytes = btc_client
        .get_raw_transaction(&del.staking_outpoint.unwrap().txid, Some(&block_hash))
        .await?
        .serialize();
    msg.staking_tx = Some(proto::btccheckpoint::TransactionInfo {
        key: Some(proto::btccheckpoint::TransactionKey {
            index: block_index,
            hash: block_hash.as_ref().to_vec(),
        }),
        transaction: staking_tx_bytes,
        proof: proof_bytes,
    });

    let body = cosmrs::tx::Body::new([msg.to_any().unwrap()], "", u32::MAX);
    let auth_info = cosmrs::tx::AuthInfo {
        signer_infos: vec![cosmrs::tx::SignerInfo {
            public_key: Some(cosmrs::tx::SignerPublicKey::Single(
                cosmrs::tendermint::public_key::PublicKey::from_raw_secp256k1(
                    relayer_pubkey.serialize().as_slice(),
                )
                .unwrap()
                .into(),
            )),
            mode_info: ModeInfo::Single(Single {
                mode: SignMode::Direct,
            }),
            sequence: 4,
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

    let sign_doc = SignDoc::new(&body, &auth_info, &"bbn-test-4".parse().unwrap(), 224180).unwrap();
    let signing_key = SigningKey::from_slice(&relayer_privkey.secret_bytes()).unwrap();
    let tx_signed = sign_doc.sign(&signing_key).unwrap().to_bytes().unwrap();

    dbg!(hex::encode(del.btc_key));

    log::info!("Broadcasting MsgCreateBtcDelegation to Babylon");
    use tendermint_rpc::Client;
    dbg!(
        tendermint_rpc::HttpClient::new("https://rpc.testnet4.babylonchain.io") // TODO: pass in
            .unwrap()
            .broadcast_tx_sync(tx_signed)
            .await
            .unwrap()
    );

    Ok(true)
}

impl TypeUrl for MsgCreateBtcDelegation {
    const TYPE_URL: &'static str = "/babylon.btcstaking.v1.MsgCreateBTCDelegation";
}

fn tree_hash(left: Option<[u8; 32]>, right: Option<[u8; 32]>) -> Option<[u8; 32]> {
    if left.is_none() && right.is_none() {
        return None;
    }

    let mut first = Sha256::new();
    first.update(left.unwrap());
    first.update(right.unwrap_or(left.unwrap()));

    let mut second = Sha256::new();
    second.update(first.finalize());
    Some(second.finalize().into())
}

fn tree_node(hashes: &[[u8; 32]], index: u32, level: u32) -> Option<[u8; 32]> {
    if level == 0 {
        return hashes.get(index as usize).copied();
    }

    let left = tree_node(hashes, index << 1, level - 1)?;
    let right = tree_node(hashes, index << 1 | 1, level - 1);
    tree_hash(Some(left), right)
}

pub fn create_proof(
    txids: &[Txid],
    target_txid: Txid,
    root: Option<TxMerkleNode>,
) -> (u32, Vec<u8>) {
    let index = txids.iter().position(|txid| *txid == target_txid).unwrap() as u32;
    let hashes: Vec<_> = txids.iter().map(|txid| txid.into_inner()).collect();
    let levels = 0usize.leading_zeros() - (hashes.len() - 1).leading_zeros();
    dbg!(hashes.len(), levels);

    let mut proof_bytes = vec![];
    let mut idx = index;
    let mut size = hashes.len() as u32;
    for level in 0..levels {
        dbg!(level, size, idx);
        let sibling = tree_node(&hashes, idx ^ 1, level)
            .unwrap_or(tree_node(&hashes, size - 1, level).unwrap());
        proof_bytes.extend_from_slice(&sibling);
        idx >>= 1;
        size = (size + 1) / 2;
    }

    if let Some(root) = root {
        assert_eq!(root.as_ref(), tree_node(&hashes, 0, levels).unwrap());
    }

    (index, proof_bytes)
}
