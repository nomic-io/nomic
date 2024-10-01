use ed::{Decode, Encode};
use orga::{client::Client as OrgaClient, encoding::LengthVec};
use reqwest::get;
use serde::{Deserialize, Serialize};

use super::{
    encode_sync_aggregate, Bootstrap, Bytes32, Header, LightClient, SyncAggregate, SyncCommittee,
    Update,
};
use crate::{app, babylon::proto::FinalityProvider, error::Result};

use super::{encode_header, encode_sync_committee};

async fn get_updates<C: OrgaClient<LightClient>>(
    app_client: &C,
    eth_client: &RpcClient,
) -> Result<Vec<Update>> {
    let lc = app_client.query(Ok).await?;

    let finality_update = eth_client.get_finality_update().await?.data;

    let app_epoch = lc.slot() / 32;
    let eth_epoch = finality_update.finalized_header.slot / 32;

    let app_period = app_epoch / 256;
    let eth_period = eth_epoch / 256;

    let mut updates = vec![];

    let updates_needed = eth_period - app_period;
    if updates_needed > 0 {
        updates = eth_client
            .get_updates(app_period, updates_needed)
            .await?
            .into_iter()
            .map(|u| u.data)
            .collect();
    }

    if eth_epoch > app_epoch {
        updates.push(finality_update);
    }

    Ok(updates)
}

pub struct RpcClient {
    rpc_addr: String,
}

impl RpcClient {
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
        let response = get(&url)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        let res = response
            .json()
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        Ok(res)
    }

    pub async fn get_finality_update(&self) -> Result<Response<Update>> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/finality_update",
            self.rpc_addr,
        );
        let response = get(&url)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        let res = response
            .json()
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        Ok(res)
    }

    pub async fn bootstrap(&self, block_root: Bytes32) -> Result<Response<Bootstrap>> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/{}",
            self.rpc_addr, block_root,
        );
        let response = get(&url)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        let res = response
            .json()
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
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
        let client = RpcClient::new("https://www.lightclientdata.org".to_string());
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
