use crate::bitcoin::header_queue::{HeaderQueue, WrappedHeader, HeaderList};
use crate::error::Result;
use bitcoincore_rpc::{Client as BtcClient, RpcApi};
use orga::prelude::*;
use crate::app::InnerApp;
use orga::Result as OrgaResult;

const SEEK_BATCH_SIZE: u32 = 10;

type AppClient = TendermintClient<crate::app::App>;

pub struct Relayer {
    btc_client: BtcClient,
    app_client: AppClient,
}

type AppQuery = <InnerApp as Query>::Query;
type HeaderQueueQuery = <HeaderQueue as Query>::Query;

impl Relayer {
    pub fn new(btc_client: BtcClient, app_client: AppClient) -> Self {
        Relayer { btc_client, app_client }
    }

    async fn app_height(&self) -> OrgaResult<u32> {
        self.app_client.query(
            AppQuery::FieldBtcHeaders(HeaderQueueQuery::MethodHeight(vec![])),
            |state| Ok(state.btc_headers.height().unwrap()),
        ).await
    }

    async fn app_trusted_height(&self) -> OrgaResult<u32> {
        self.app_client.query(
            AppQuery::FieldBtcHeaders(HeaderQueueQuery::MethodTrustedHeight(vec![])),
            |state| Ok(state.btc_headers.trusted_height()),
        ).await
    }

    async fn app_add(&mut self, headers: HeaderList) -> OrgaResult<()> {
        self
            .app_client
            .btc_headers
            .add(headers)
            .await
    }

    pub async fn start(&mut self) -> Result<!> {
        self.wait_for_trusted_header().await?;
        self.listen().await
    }

    async fn wait_for_trusted_header(&self) -> Result<()> {
        loop {
            let tip_hash = self.btc_client.get_best_block_hash()?;
            let tip_height = self.btc_client.get_block_header_info(&tip_hash)?.height;
            println!("wait_for_trusted_header: btc={}", tip_height);
            if (tip_height as u32) < self.app_trusted_height().await? {
                std::thread::sleep(std::time::Duration::from_secs(1));
            } else {
                break;
            }
        }

        Ok(())
    }

    async fn listen(&mut self) -> Result<!> {
        loop {
            let tip_hash = self.btc_client.get_best_block_hash()?;
            let tip_height = self.btc_client.get_block_header_info(&tip_hash)?.height;
            println!("relayer listen: btc={}, app={}", tip_height, self.app_height().await?);
            if tip_height as u32 > self.app_height().await? {
                self.seek_to_tip().await?;
            } else {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }

    pub async fn bounded_listen(&mut self, num_blocks: u32) -> Result<()> {
        for _ in 0..num_blocks {
            let tip_hash = self.btc_client.get_best_block_hash()?;
            let tip_height = self.btc_client.get_block_header_info(&tip_hash)?.height;
            if tip_height as u32 > self.app_height().await? {
                self.seek_to_tip().await?;
            } else {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }

        Ok(())
    }

    async fn seek_to_tip(&mut self) -> Result<()> {
        let tip_height = self.get_rpc_height()?;
        let mut app_height = self.app_height().await?;
        while app_height < tip_height {
            println!("seek_to_tip: btc={}, app={}", tip_height, app_height);
            let headers = self.get_header_batch(SEEK_BATCH_SIZE).await?;
            self.app_add(headers.into()).await?;
            app_height = self.app_height().await?;
        }
        Ok(())
    }

    async fn get_header_batch(
        &self,
        batch_size: u32,
    ) -> Result<Vec<WrappedHeader>> {
        let mut headers = Vec::with_capacity(batch_size as usize);
        for i in 1..=batch_size {
            let hash = match self
                .btc_client
                .get_block_hash((self.app_height().await? + i) as u64)
            {
                Ok(hash) => hash,
                Err(_) => break,
            };

            let header = self.btc_client.get_block_header(&hash)?;
            let height = self.btc_client.get_block_header_info(&hash)?.height;
            let wrapped_header = WrappedHeader::from_header(&header, height as u32);
            headers.push(wrapped_header);
        }

        Ok(headers)
    }

    fn get_rpc_height(&self) -> Result<u32> {
        let tip_hash = self.btc_client.get_best_block_hash()?;
        let tip_height = self.btc_client.get_block_header_info(&tip_hash)?.height;

        Ok(tip_height as u32)
    }
}

#[cfg(todo)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::adapter::Adapter;
    use crate::bitcoin::header_queue::Config;
    use bitcoincore_rpc::Auth;
    use bitcoind::BitcoinD;
    use orga::encoding::Encode;
    use orga::store::{MapStore, Shared, Store};

    #[test]
    fn relayer_seek() {
        let bitcoind = BitcoinD::new(bitcoind::downloaded_exe_path().unwrap()).unwrap();

        let address = bitcoind.client.get_new_address(None, None).unwrap();
        bitcoind.client.generate_to_address(30, &address).unwrap();
        let trusted_hash = bitcoind.client.get_block_hash(30).unwrap();
        let trusted_header = bitcoind.client.get_block_header(&trusted_hash).unwrap();

        let bitcoind_url = bitcoind.rpc_url();
        let bitcoin_cookie_file = bitcoind.params.cookie_file.clone();
        let rpc_client = BtcClient::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

        let encoded_header = Encode::encode(&Adapter::new(trusted_header)).unwrap();
        let mut config: Config = Default::default();
        config.encoded_trusted_header = encoded_header;
        config.trusted_height = 30;
        config.retargeting = false;

        bitcoind.client.generate_to_address(100, &address).unwrap();

        let store = Store::new(Shared::new(MapStore::new()));

        let mut header_queue = HeaderQueue::with_conf(store, Default::default(), config).unwrap();
        let relayer = Relayer::new(rpc_client);
        relayer.seek_to_tip(&mut header_queue).unwrap();
        let height = header_queue.height().unwrap();

        assert_eq!(height, 130);
    }

    #[test]
    fn relayer_seek_uneven_batch() {
        let bitcoind = BitcoinD::new(bitcoind::downloaded_exe_path().unwrap()).unwrap();

        let address = bitcoind.client.get_new_address(None, None).unwrap();
        bitcoind.client.generate_to_address(30, &address).unwrap();
        let trusted_hash = bitcoind.client.get_block_hash(30).unwrap();
        let trusted_header = bitcoind.client.get_block_header(&trusted_hash).unwrap();

        let bitcoind_url = bitcoind.rpc_url();
        let bitcoin_cookie_file = bitcoind.params.cookie_file.clone();
        let rpc_client = BtcClient::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

        let encoded_header = Encode::encode(&Adapter::new(trusted_header)).unwrap();
        let mut config: Config = Default::default();
        config.encoded_trusted_header = encoded_header;
        config.trusted_height = 30;
        config.retargeting = false;

        bitcoind
            .client
            .generate_to_address(42 as u64, &address)
            .unwrap();

        let store = Store::new(Shared::new(MapStore::new()));

        let mut header_queue = HeaderQueue::with_conf(store, Default::default(), config).unwrap();
        let relayer = Relayer::new(rpc_client);
        relayer.seek_to_tip(&mut header_queue).unwrap();
        let height = header_queue.height().unwrap();

        assert_eq!(height, 72);
    }
}
