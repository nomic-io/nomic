use crate::bitcoin::header_queue::Config;
use crate::bitcoin::header_queue::{HeaderQueue, WrappedHeader};
use crate::error::{Error, Result};
use bitcoincore_rpc::{Client, RpcApi};
use orga::state::State;
use orga::store::Store;
use orga::Result as OrgaResult;

const SEEK_BATCH_SIZE: u32 = 255;

pub struct Relayer {
    rpc_client: Client,
}

impl Relayer {
    pub fn new(client: Client) -> Self {
        Relayer { rpc_client: client }
    }

    pub fn start(&self, header_queue: &mut HeaderQueue) -> Result<!> {
        self.wait_for_trusted_header(header_queue)?;
        self.listen(header_queue)?;
    }

    fn wait_for_trusted_header(&self, header_queue: &HeaderQueue) -> Result<()> {
        loop {
            let tip_hash = self.rpc_client.get_best_block_hash()?;
            let tip_height = self.rpc_client.get_block_header_info(&tip_hash)?.height;
            if (tip_height as u32) < header_queue.trusted_height() {
                std::thread::sleep(std::time::Duration::from_secs(1));
            } else {
                break;
            }
        }

        Ok(())
    }

    fn listen(&self, header_queue: &mut HeaderQueue) -> Result<!> {
        loop {
            let tip_hash = self.rpc_client.get_best_block_hash()?;
            let tip_height = self.rpc_client.get_block_header_info(&tip_hash)?.height;
            if tip_height as u32 > header_queue.height()? {
                self.seek_to_tip(header_queue)?;
            } else {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }

    pub fn bounded_listen(&self, num_blocks: u32, header_queue: &mut HeaderQueue) -> Result<()> {
        for _ in 0..num_blocks {
            let tip_hash = self.rpc_client.get_best_block_hash()?;
            let tip_height = self.rpc_client.get_block_header_info(&tip_hash)?.height;
            if tip_height as u32 > header_queue.height()? {
                self.seek_to_tip(header_queue)?;
            } else {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }

        Ok(())
    }

    fn seek_to_tip(&self, header_queue: &mut HeaderQueue) -> Result<()> {
        let tip_height = self.get_rpc_height()?;
        while header_queue.height()? < tip_height {
            let headers = self.get_header_batch(SEEK_BATCH_SIZE, header_queue)?;
            header_queue.add(headers.into())?;
        }
        Ok(())
    }

    fn get_header_batch(
        &self,
        batch_size: u32,
        header_queue: &HeaderQueue,
    ) -> Result<Vec<WrappedHeader>> {
        let mut headers = Vec::with_capacity(batch_size as usize);
        for i in 1..=batch_size {
            let hash = match self
                .rpc_client
                .get_block_hash((header_queue.height()? + i) as u64)
            {
                Ok(hash) => hash,
                Err(_) => break,
            };

            let header = self.rpc_client.get_block_header(&hash)?;
            let height = self.rpc_client.get_block_header_info(&hash)?.height;
            let wrapped_header = WrappedHeader::from_header(&header, height as u32);
            headers.push(wrapped_header);
        }

        Ok(headers)
    }

    fn get_rpc_height(&self) -> Result<u32> {
        let tip_hash = self.rpc_client.get_best_block_hash()?;
        let tip_height = self.rpc_client.get_block_header_info(&tip_hash)?.height;

        Ok(tip_height as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::adapter::Adapter;
    use bitcoincore_rpc::Auth;
    use bitcoind::BitcoinD;
    use orga::encoding::Encode;
    use orga::store::{MapStore, Shared};

    #[test]
    fn relayer_seek() {
        let bitcoind = BitcoinD::new(bitcoind::downloaded_exe_path().unwrap()).unwrap();

        let address = bitcoind.client.get_new_address(None, None).unwrap();
        bitcoind.client.generate_to_address(30, &address).unwrap();
        let trusted_hash = bitcoind.client.get_block_hash(30).unwrap();
        let trusted_header = bitcoind.client.get_block_header(&trusted_hash).unwrap();

        let bitcoind_url = bitcoind.rpc_url();
        let bitcoin_cookie_file = bitcoind.params.cookie_file.clone();
        let rpc_client = Client::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

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
        let rpc_client = Client::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

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
