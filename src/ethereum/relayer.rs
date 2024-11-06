use super::proofs::{BridgeContractData, StateProof};
use crate::error::Result as AppResult;
use crate::ethereum::proofs::extra_slots_required;
use alloy_core::primitives::Address as EthAddress;
use alloy_primitives::Uint;
use alloy_provider::Provider;
use alloy_transport::Transport;

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
        let dest = contract.state_returnDests(idx).call().await.unwrap()._0;
        let amount = contract.state_returnAmounts(idx).call().await.unwrap()._0;
        log::debug!("Return entry {}: dest={}, amount={}", i, dest, amount);
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
