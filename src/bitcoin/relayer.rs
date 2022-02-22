use super::Bitcoin;
use crate::bitcoin::header_queue::{HeaderList, WrappedHeader};
use crate::error::Result;
use bitcoin::{hashes::Hash, BlockHash};
use bitcoincore_rpc::json::GetBlockHeaderResult;
use bitcoincore_rpc::{Client as BtcClient, RpcApi};
use orga::client::{AsyncCall, AsyncQuery};
use orga::prelude::*;
use orga::Result as OrgaResult;

const HEADER_BATCH_SIZE: usize = 50;

type AppClient<T> = <Bitcoin as Client<T>>::Client;

pub struct Relayer<T: Clone + Send> {
    btc_client: BtcClient,
    app_client: AppClient<T>,
}

impl<T: Clone + Send> Relayer<T>
where
    T: AsyncQuery<Query = <Bitcoin as Query>::Query>,
    T: AsyncQuery<Response = Bitcoin>,
    T: AsyncCall<Call = <Bitcoin as Call>::Call>,
{
    pub fn new(btc_client: BtcClient, app_client: AppClient<T>) -> Self {
        Relayer {
            btc_client,
            app_client,
        }
    }

    async fn sidechain_block_hash(&self) -> Result<BlockHash> {
        let hash = self.app_client.headers.hash().await??;
        let hash = bitcoin::BlockHash::from_slice(hash.as_slice())?;
        Ok(hash)
    }

    async fn app_add(&mut self, headers: HeaderList) -> OrgaResult<()> {
        self.app_client.headers.add(headers).await
    }

    pub async fn start(&mut self) -> Result<!> {
        println!("Starting relayer...");
        self.relay_headers().await
    }

    async fn relay_headers(&mut self) -> Result<!> {
        loop {
            let fullnode_hash = self.btc_client.get_best_block_hash()?;
            let sidechain_hash = self.sidechain_block_hash().await?;

            if fullnode_hash != sidechain_hash {
                self.relay_header_batch(fullnode_hash, sidechain_hash)
                    .await?;
                continue;
            }

            let info = self.btc_client.get_block_info(&fullnode_hash)?;
            println!(
                "Sidechain header state is up-to-date:\n\thash={}\n\theight={}",
                info.hash, info.height
            );

            self.btc_client.wait_for_new_block(30_000)?;
        }
    }

    async fn relay_header_batch(
        &mut self,
        fullnode_hash: BlockHash,
        sidechain_hash: BlockHash,
    ) -> Result<()> {
        let get_info = |hash| self.btc_client.get_block_header_info(&hash);

        let fullnode_info = get_info(fullnode_hash)?;
        let sidechain_info = get_info(sidechain_hash)?;

        if fullnode_info.height < sidechain_info.height {
            // full node is still syncing
            return Ok(());
        }

        let start = self.common_ancestor(fullnode_hash, sidechain_hash)?;
        let batch = self.get_header_batch(start.hash)?;

        println!(
            "Relaying headers...\n\thash={}\n\theight={}\n\tbatch_len={}",
            start.hash,
            start.height,
            batch.len(),
        );

        self.app_add(batch.into()).await?;

        Ok(())
    }

    fn get_header_batch(&self, from_hash: BlockHash) -> Result<Vec<WrappedHeader>> {
        let get_info = |hash| self.btc_client.get_block_header_info(&hash);

        let mut cursor = get_info(from_hash)?;

        let mut headers = Vec::with_capacity(HEADER_BATCH_SIZE as usize);
        for _ in 0..HEADER_BATCH_SIZE {
            match cursor.next_block_hash {
                Some(next_hash) => cursor = get_info(next_hash)?,
                None => break,
            };

            let header = self.btc_client.get_block_header(&cursor.hash)?;
            let header = WrappedHeader::from_header(&header, cursor.height as u32);

            headers.push(header);
        }

        Ok(headers)
    }

    fn common_ancestor(&self, a: BlockHash, b: BlockHash) -> Result<GetBlockHeaderResult> {
        let get_info = |hash| self.btc_client.get_block_header_info(&hash);

        let mut a = get_info(a)?;
        let mut b = get_info(b)?;

        while a != b {
            if a.height > b.height {
                a = get_info(a.previous_block_hash.unwrap())?;
            } else {
                b = get_info(b.previous_block_hash.unwrap())?;
            }
        }

        Ok(a)
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
        let rpc_client =
            BtcClient::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

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
        let rpc_client =
            BtcClient::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

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
