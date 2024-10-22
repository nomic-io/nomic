use crate::error::Result;
use bitcoin::{Address, Txid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deposit {
    pub txid: Txid,
    pub vout: u32,
    pub amount: u64,
    pub height: Option<u64>,
    pub sigset_index: u32,
    pub miner_fee_rate: f64,
    pub bridge_fee_rate: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositInfo {
    pub deposit: Deposit,
    pub confirmations: u64,
}

type ReceiverIndex = HashMap<String, HashMap<Address, HashMap<(Txid, u32), Deposit>>>;

#[derive(Default, Debug)]
pub struct DepositIndex {
    pub receiver_index: ReceiverIndex,
}

impl DepositIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_deposit(
        &mut self,
        receiver: String,
        address: bitcoin::Address,
        deposit: Deposit,
    ) {
        self.receiver_index
            .entry(receiver)
            .or_default()
            .entry(address)
            .or_default()
            .insert((deposit.txid, deposit.vout), deposit);
    }

    fn remove_address_index_deposit(
        &mut self,
        receiver: String,
        address: bitcoin::Address,
        txid: Txid,
        vout: u32,
    ) -> Result<()> {
        self.receiver_index
            .get_mut(&receiver)
            .unwrap_or(&mut HashMap::new())
            .get_mut(&address)
            .unwrap_or(&mut HashMap::new())
            .remove(&(txid, vout));

        Ok(())
    }

    pub fn remove_deposit(
        &mut self,
        receiver: String,
        address: bitcoin::Address,
        txid: Txid,
        vout: u32,
    ) -> Result<()> {
        self.remove_address_index_deposit(receiver, address, txid, vout)?;
        Ok(())
    }

    pub fn get_deposits_by_receiver(
        &self,
        receiver: String,
        current_btc_height: u64,
    ) -> Result<Vec<DepositInfo>> {
        let mut deposits = Vec::new();
        if let Some(address_map) = self.receiver_index.get(&receiver) {
            for address in address_map.values() {
                for (_, deposit) in address.iter() {
                    let confirmations = match deposit.height {
                        Some(height) => current_btc_height.saturating_sub(height) + 1,
                        None => 0,
                    };

                    deposits.push(DepositInfo {
                        deposit: deposit.clone(),
                        confirmations,
                    });
                }
            }
        }

        Ok(deposits)
    }
}
