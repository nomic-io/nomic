use ed::{Decode, Encode};
use orga::encoding::LengthVec;
use reqwest::get;
use serde::{Deserialize, Serialize};

use super::{encode_sync_aggregate, Header, SyncAggregate, SyncCommittee, Update};
use crate::error::Result;

use super::{encode_header, encode_sync_committee};

pub struct Client {
    rpc_addr: String,
}

impl Client {
    pub fn new(rpc_addr: String) -> Self {
        Self { rpc_addr }
    }

    pub async fn get_updates(&self, start_period: u64, count: u64) -> Result<Vec<UpdateContainer>> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.rpc_addr, start_period, count,
        );
        let response = get(&url).await.unwrap();
        let res = response.json().await.unwrap();
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
        Ok(res)
    }

    pub async fn finality_update(&self) -> Result<UpdateContainer> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/finality_update",
            self.rpc_addr,
        );
        let response = get(&url).await.unwrap();
        let res = response.json().await.unwrap();
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
        Ok(res)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateContainer {
    pub version: Option<String>,
    pub data: Update,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_updates() {
        let client = Client::new("https://www.lightclientdata.org".to_string());
        let updates = client.get_updates(1229, 1).await.unwrap();
        let updates = client.finality_update().await.unwrap();
    }
}
