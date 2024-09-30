use ed::{Decode, Encode};
use orga::encoding::LengthVec;
use reqwest::get;
use serde::{Deserialize, Serialize};

use super::{
    encode_sync_aggregate, Bootstrap, Bytes32, Header, SyncAggregate, SyncCommittee, Update,
};
use crate::error::Result;

use super::{encode_header, encode_sync_committee};

pub struct Client {
    rpc_addr: String,
}

impl Client {
    pub fn new(rpc_addr: String) -> Self {
        Self { rpc_addr }
    }

    pub async fn get_updates(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Vec<Response<Update>>> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.rpc_addr, start_period, count,
        );
        let response = get(&url).await.unwrap();
        let res = response.json().await.unwrap();
        Ok(res)
    }

    pub async fn get_finality_update(&self) -> Result<Response<Update>> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/finality_update",
            self.rpc_addr,
        );
        let response = get(&url).await.unwrap();
        let res = response.json().await.unwrap();
        Ok(res)
    }

    pub async fn bootstrap(&self, block_root: Bytes32) -> Result<Response<Bootstrap>> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/{}",
            self.rpc_addr, block_root,
        );
        let response = get(&url).await.unwrap();
        let res = response.json().await.unwrap();
        Ok(res)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response<T> {
    pub version: Option<String>,
    pub data: T,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_updates() {
        let client = Client::new("https://www.lightclientdata.org".to_string());
        let updates = client.get_updates(1229, 1).await.unwrap();
        let update = client.get_finality_update().await.unwrap();
        let bootstrap = client
            .bootstrap(
                "0xb2536a96e35df54caf8d37e958d2899a6c6b8616342a9e38c913c62e5c85aa93"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap();
    }
}
