use super::proofs::{BridgeContractData, StateProof};
use crate::app::InnerApp;
use crate::app_client;
use crate::error::Result as AppResult;
use crate::error::Result;
use crate::ethereum::proofs::extra_slots_required;
use crate::utils::sleep;
use alloy_core::primitives::Address as EthAddress;
use alloy_primitives::Uint;
use alloy_provider::Provider;
use alloy_signer_local::LocalSigner;
use alloy_transport::Transport;
use bitcoin::secp256k1::Message;
use orga::call::build_call;
use orga::client::Wallet;
use orga::coins::Address;

pub struct Relayer<T, U, P> {
    app_client_addr: String,
    wallet: U,
    provider: P,
    phantom: std::marker::PhantomData<T>,
}

impl<
        U: Wallet,
        T: Transport + Clone,
        P: Provider<T, alloy_provider::network::Ethereum> + Clone,
    > Relayer<T, U, P>
{
    pub fn new(app_client_addr: String, wallet: U, provider: P) -> Self {
        Self {
            app_client_addr,
            wallet,
            provider,
            phantom: std::marker::PhantomData,
        }
    }

    pub async fn start_eth_relay(
        &self,
        private_key: String,
        eth_rpc_url: String,
        beacon_api_url: String,
        eth_chainid: u32,
        eth_contract: String,
    ) -> Result<()> {
        let mut privkey_hex = private_key.as_str();
        if privkey_hex.starts_with("0x") {
            privkey_hex = &privkey_hex[2..];
        }
        let privkey = hex::decode(privkey_hex).unwrap(); // TODO
        if privkey.len() != 32 {
            return Err(crate::error::Error::Orga(orga::Error::App(
                "Invalid private key".to_string(),
            )));
        }

        if !eth_contract.starts_with("0x") {
            return Err(crate::error::Error::Orga(orga::Error::App(
                "Invalid contract address".to_string(),
            )));
        }
        if eth_contract.len() != 42 {
            return Err(crate::error::Error::Orga(orga::Error::App(
                "Invalid contract address".to_string(),
            )));
        }
        let bridge_contract_vec = hex::decode(&eth_contract[2..]).unwrap();
        let mut bridge_contract = [0u8; 20];
        bridge_contract.copy_from_slice(&bridge_contract_vec);
        let bridge_contract = Address::from(bridge_contract);

        let relay_msgs = async {
            loop {
                if let Err(e) = self.try_relay_msg(eth_chainid, bridge_contract).await {
                    log::error!("Ethereum relayer error: {:?}", e);
                };

                sleep(10).await;
            }

            #[allow(unreachable_code)]
            Ok::<_, crate::error::Error>(())
        };

        let relay_returns = async {
            loop {
                if let Err(e) = self
                    .try_relay_return(
                        eth_chainid,
                        eth_rpc_url.clone(),
                        bridge_contract,
                        privkey.clone(),
                    )
                    .await
                {
                    log::error!("Nomic relayer error: {:?}", e);
                };

                sleep(10).await;
            }

            #[allow(unreachable_code)]
            Ok::<_, crate::error::Error>(())
        };

        #[cfg(not(feature = "devnet"))]
        let relay_consensus = async {
            loop {
                if let Err(e) = self
                    .try_relay_consensus(beacon_api_url.clone(), eth_chainid)
                    .await
                {
                    log::error!("Nomic relayer error: {:?}", e);
                };

                sleep(10).await;
            }

            #[allow(unreachable_code)]
            Ok::<_, crate::error::Error>(())
        };

        #[cfg(not(feature = "devnet"))]
        futures::try_join!(relay_msgs, relay_returns, relay_consensus)?;

        #[cfg(feature = "devnet")]
        futures::try_join!(relay_msgs, relay_returns)?;

        Ok(())
    }

    async fn try_relay_msg(&self, eth_chainid: u32, bridge_contract: Address) -> Result<()> {
        let client = app_client(&self.app_client_addr);

        let token_contract = client
            .query(|app| Ok(app.ethereum.token_contract(eth_chainid, bridge_contract)?))
            .await?;

        let bridge_contract_addr =
            alloy_core::primitives::Address::from_slice(&bridge_contract.bytes());
        let contract =
            crate::ethereum::bridge_contract::new(bridge_contract_addr, self.provider.clone());

        let msg_index = match contract.state_lastEventNonce().call().await {
            Ok(res) => res._0.to(),
            Err(e) => {
                return Err(crate::error::Error::Orga(orga::Error::App(e.to_string())));
            }
        };

        let Some((msg, sigs, data)) = client
            .query(|app| {
                if app.ethereum.message_index(eth_chainid, bridge_contract)? < msg_index {
                    return Ok(None);
                }

                if !app
                    .ethereum
                    .signed(eth_chainid, bridge_contract, msg_index)?
                {
                    log::debug!("Message {msg_index} is still being signed");
                    return Ok(None);
                }

                Ok(Some(app.ethereum.msd(
                    eth_chainid,
                    bridge_contract,
                    msg_index,
                )?))
            })
            .await?
        else {
            return Ok(());
        };

        let (ss_index, valset_index) = client
            .query(|app| {
                for i in 1..msg_index {
                    let (_, _, args) =
                        app.ethereum
                            .msd(eth_chainid, bridge_contract, msg_index - i)?;
                    if let crate::ethereum::OutMessageArgs::UpdateValset(valset_index, ref valset) =
                        args
                    {
                        return Ok((valset.index, valset_index));
                    }
                }

                Ok((0, 0))
            })
            .await?;

        let mut valset = client
            .query(|app| Ok(app.bitcoin.checkpoints.get(ss_index)?.sigset.clone()))
            .await?;
        valset.normalize_vp(u32::MAX as u64);

        let sigs: Vec<_> = sigs
            .into_iter()
            .map(|(pk, sig)| {
                let Some(sig) = sig else {
                    return crate::ethereum::bridge_contract::Signature {
                        v: 0,
                        r: [0; 32].into(),
                        s: [0; 32].into(),
                    };
                };
                let (v, r, s) = crate::ethereum::to_eth_sig(
                    &bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig.0).unwrap(),
                    &bitcoin::secp256k1::PublicKey::from_slice(pk.as_slice()).unwrap(),
                    &Message::from_slice(&msg).unwrap(),
                );
                crate::ethereum::bridge_contract::Signature {
                    v,
                    r: r.into(),
                    s: s.into(),
                }
            })
            .collect();

        match data {
            crate::ethereum::OutMessageArgs::Batch {
                transfers,
                timeout,
                batch_index,
            } => {
                contract
                    .submitBatch(
                        valset.to_abi(valset_index),
                        sigs,
                        transfers
                            .iter()
                            .map(|t| alloy_core::primitives::U256::from(t.amount))
                            .collect(),
                        transfers
                            .iter()
                            .map(|t| alloy_core::primitives::Address::from_slice(&t.dest.bytes()))
                            .collect(),
                        transfers
                            .iter()
                            .map(|t| alloy_core::primitives::U256::from(t.fee_amount))
                            .collect(),
                        alloy_core::primitives::U256::from(batch_index),
                        alloy_core::primitives::Address::from_slice(&token_contract.bytes()),
                        alloy_core::primitives::U256::from(timeout),
                    )
                    .send()
                    .await
                    .map_err(|e| crate::error::Error::Orga(orga::Error::App(e.to_string())))?
                    .get_receipt()
                    .await
                    .unwrap();
            }
            crate::ethereum::OutMessageArgs::ContractCall {
                contract_address,
                data,
                max_gas,
                fallback_address,
                transfer_amount,
                fee_amount,
                message_index,
            } => {
                contract
                    .submitLogicCall(
                        valset.to_abi(valset_index),
                        sigs,
                        crate::ethereum::logic_call_args(
                            transfer_amount,
                            fee_amount,
                            token_contract.into(),
                            contract_address,
                            data.as_slice(),
                            max_gas,
                            fallback_address,
                            message_index,
                        ),
                    )
                    .send()
                    .await
                    .unwrap()
                    .get_receipt()
                    .await
                    .unwrap();
            }
            crate::ethereum::OutMessageArgs::UpdateValset(index, new_valset) => {
                contract
                    .updateValset(new_valset.to_abi(index), valset.to_abi(valset_index), sigs)
                    .send()
                    .await
                    .unwrap()
                    .get_receipt()
                    .await
                    .unwrap();
            }
        };

        Ok(())
    }

    async fn try_relay_return(
        &self,
        eth_chainid: u32,
        eth_rpc_url: String,
        bridge_contract: Address,
        privkey: Vec<u8>,
    ) -> Result<()> {
        let client = app_client(&self.app_client_addr);

        let signer = LocalSigner::from_slice(privkey.as_slice()).unwrap();
        let contract = crate::ethereum::bridge_contract::new(
            alloy_core::primitives::Address::from_slice(&bridge_contract.bytes()),
            self.provider.clone(),
        );
        let bridge_contract_addr =
            alloy_core::primitives::Address::from_slice(&bridge_contract.bytes());

        let has_contract_index = !contract
            .state_lastReturnNonce()
            .call_raw()
            .await
            .unwrap()
            .is_empty();
        if !has_contract_index {
            return Ok(());
        }

        let contract_index: u64 = contract
            .state_lastReturnNonce()
            .call()
            .await
            .unwrap()
            ._0
            .to();
        let nomic_index = client
            .query(|app| Ok(app.ethereum.return_index(eth_chainid, bridge_contract)?))
            .await?;

        if nomic_index == contract_index {
            return Ok(());
        }

        let block_number = app_client(&self.app_client_addr)
            .query(|app| Ok(app.ethereum.block_number(eth_chainid)?))
            .await?;

        log::debug!(
            "Getting state proof... (chainid={}, block_number={})",
            eth_chainid,
            block_number
        );

        let state_proof = crate::ethereum::relayer::get_state_proof(
            &self.provider,
            bridge_contract_addr,
            nomic_index,
            block_number,
        )
        .await?;

        app_client(&self.app_client_addr)
            .with_wallet(self.wallet.clone())
            .call(
                move |app| {
                    build_call!(app.ethereum.relay_return(
                        eth_chainid,
                        bridge_contract,
                        state_proof.clone()
                    ))
                },
                |app| build_call!(app.app_noop()),
            )
            .await?;

        Ok::<_, crate::error::Error>(())
    }

    async fn try_relay_consensus(&self, beacon_api_url: String, eth_chainid: u32) -> Result<()> {
        let client = app_client(&self.app_client_addr);

        let rpc_client =
            crate::ethereum::consensus::relayer::RpcClient::new(beacon_api_url.clone());
        // TODO: use chain_id in closure without breaking fn coercion
        let lc = client.sub(move |app: InnerApp| Ok(app.ethereum.light_client(11155111)?));
        let updates = crate::ethereum::consensus::relayer::get_updates(&lc, &rpc_client).await?;

        for update in updates {
            log::info!(
                "Relaying Ethereum consensus update... (chainid={},
    slot={})",
                11155111, // TODO: self.eth_chainid,
                update.finalized_header.beacon.slot
            );

            app_client(&self.app_client_addr)
                .call(
                    move |app| {
                        build_call!(app
                            .ethereum
                            .relay_consensus_update(eth_chainid, update.clone()))
                    },
                    |app| build_call!(app.app_noop()),
                )
                .await?;

            log::info!("Consensus update relayed.");
        }

        Ok(())
    }
}

/// Builds a proof of the account and storage for state slots relevant to the
/// return message queue in the bridge contract.
pub async fn get_state_proof<
    T: Clone + Transport,
    P: Provider<T, alloy_provider::network::Ethereum> + Clone,
>(
    provider: P,
    address: EthAddress,
    index: u64,
    block_number: u64,
) -> AppResult<StateProof> {
    let contract = super::bridge_contract::new(address, provider.clone());
    let contract_index: u64 = contract
        .state_lastReturnNonce()
        .call()
        .await
        .unwrap()
        ._0
        .to();

    let indices = index..contract_index;
    let mut dests = vec![];

    for i in indices {
        let idx = Uint::<256, 4>::from(i);
        let dest: String = contract.state_returnDests(idx).call().await.unwrap()._0;
        dests.push((dest, i));
    }

    let mut keys_to_prove = vec![];
    for (dest, index) in dests.iter().cloned() {
        let dest_key = BridgeContractData::dest_key(index);
        let amount_key = BridgeContractData::amount_key(index);
        let sender_key = BridgeContractData::sender_key(index);
        keys_to_prove.push(dest_key);
        keys_to_prove.push(amount_key);
        keys_to_prove.push(sender_key);

        let num_extra_dest_slots = extra_slots_required(dest.len());
        for i in 0..num_extra_dest_slots {
            let key = BridgeContractData::dest_chunk_key(index, i as u64);
            keys_to_prove.push(key);
        }
    }

    let proof_res = provider
        .get_proof(
            address,
            keys_to_prove.into_iter().map(|k| k.into()).collect(),
        )
        .number(block_number)
        .await
        .map_err(|e| crate::error::Error::Relayer(e.to_string()))?;

    let state_proof = StateProof::from_response(proof_res, dests).unwrap();

    Ok(state_proof)
}
