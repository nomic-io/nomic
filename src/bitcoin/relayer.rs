use crate::bitcoin::header_queue::Config;
use crate::bitcoin::header_queue::{HeaderQueue, WrappedHeader};
use crate::error::{Error, Result};
use bitcoincore_rpc::{Client, RpcApi};
use orga::state::State;
use orga::store::Store;
use orga::Result as OrgaResult;

const SEEK_BATCH_SIZE: u32 = 255;

pub struct Relayer {
    header_queue: HeaderQueue,
    rpc_client: Option<Client>,
}

impl State for Relayer {
    type Encoding = <HeaderQueue as State>::Encoding;

    fn create(store: Store, data: Self::Encoding) -> OrgaResult<Self> {
        Ok(Relayer {
            header_queue: HeaderQueue::create(store, data)?,
            rpc_client: None,
        })
    }

    fn flush(self) -> OrgaResult<Self::Encoding> {
        self.header_queue.flush()
    }
}

impl From<Relayer> for <Relayer as State>::Encoding {
    fn from(relayer: Relayer) -> Self {
        relayer.header_queue.into()
    }
}

impl Relayer {
    pub fn rpc_client(&mut self, client: Client) -> &Self {
        self.rpc_client = Some(client);
        self
    }

    pub fn height(&self) -> Result<u32> {
        self.header_queue.height()
    }

    pub fn start(&mut self) -> Result<!> {
        if let None = self.rpc_client {
            return Err(Error::Relayer(
                "No rpc client provided to relayer".to_string(),
            ));
        }

        self.wait_for_trusted_header()?;
        self.listen()?;
    }

    fn wait_for_trusted_header(&mut self) -> Result<()> {
        loop {
            let rpc_client = self.rpc_client.as_ref().unwrap();
            let tip_hash = rpc_client.get_best_block_hash()?;
            let tip_height = rpc_client.get_block_header_info(&tip_hash)?.height;
            if (tip_height as u32) < self.header_queue.trusted_height() {
                std::thread::sleep(std::time::Duration::from_secs(1));
            } else {
                break;
            }
        }

        Ok(())
    }

    fn listen(&mut self) -> Result<!> {
        loop {
            let rpc_client = self.rpc_client.as_ref().unwrap();
            let tip_hash = rpc_client.get_best_block_hash()?;
            let tip_height = rpc_client.get_block_header_info(&tip_hash)?.height;
            if tip_height as u32 > self.height()? {
                self.seek_to_tip()?;
            } else {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }

    pub fn bounded_listen(&mut self, num_blocks: u32) -> Result<()> {
        for _ in 0..num_blocks {
            let rpc_client = self.rpc_client.as_ref().unwrap();
            let tip_hash = rpc_client.get_best_block_hash()?;
            let tip_height = rpc_client.get_block_header_info(&tip_hash)?.height;
            if tip_height as u32 > self.height()? {
                self.seek_to_tip()?;
            } else {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }

        Ok(())
    }

    fn seek_to_tip(&mut self) -> Result<()> {
        let tip_height = self.get_rpc_height()?;
        while self.header_queue.height()? < tip_height {
            let headers = self.get_header_batch(SEEK_BATCH_SIZE)?;
            self.header_queue.add(headers.into())?;
        }
        Ok(())
    }

    fn get_header_batch(&self, batch_size: u32) -> Result<Vec<WrappedHeader>> {
        let rpc_client = match self.rpc_client {
            Some(ref client) => client,
            None => {
                return Err(Error::Relayer(
                    "No rpc client provided to relayer".to_string(),
                ));
            }
        };

        let mut headers = Vec::with_capacity(batch_size as usize);
        for i in 1..=batch_size {
            let hash = match rpc_client.get_block_hash((self.header_queue.height()? + i) as u64) {
                Ok(hash) => hash,
                Err(_) => break,
            };

            let header = rpc_client.get_block_header(&hash)?;
            let height = rpc_client.get_block_header_info(&hash)?.height;
            let wrapped_header = WrappedHeader::from_header(&header, height as u32);
            headers.push(wrapped_header);
        }

        Ok(headers)
    }

    fn get_rpc_height(&self) -> Result<u32> {
        let rpc_client = match self.rpc_client {
            Some(ref client) => client,
            None => {
                return Err(Error::Relayer(
                    "No rpc client provided to relayer".to_string(),
                ));
            }
        };
        let tip_hash = rpc_client.get_best_block_hash()?;
        let tip_height = rpc_client.get_block_header_info(&tip_hash)?.height;

        Ok(tip_height as u32)
    }

    pub fn with_conf(
        store: Store,
        data: <Self as State>::Encoding,
        config: Config,
    ) -> Result<Self> {
        let mut relayer = Relayer::create(store.clone(), data.clone())?;
        let header_queue = HeaderQueue::with_conf(store, data, config)?;
        relayer.header_queue = header_queue;
        Ok(relayer)
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

        let mut relayer = Relayer::with_conf(store, Default::default(), config).unwrap();
        relayer.rpc_client(rpc_client);
        relayer.seek_to_tip().unwrap();
        let height = relayer.height().unwrap();

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

        let mut relayer = Relayer::with_conf(store, Default::default(), config).unwrap();
        relayer.rpc_client(rpc_client);
        relayer.seek_to_tip().unwrap();
        let height = relayer.height().unwrap();

        assert_eq!(height, 72);
    }
}
