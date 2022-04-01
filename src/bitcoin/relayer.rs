use super::Bitcoin;
use crate::bitcoin::{adapter::Adapter, header_queue::WrappedHeader};
use crate::error::Result;
use bitcoin::{
    hashes::{hex::ToHex, Hash},
    Block, BlockHash, Script, Transaction,
};
use bitcoincore_rpc::json::GetBlockHeaderResult;
use bitcoincore_rpc::{Client as BtcClient, RpcApi};
use orga::client::{AsyncCall, AsyncQuery};
use orga::coins::Address;
use orga::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::task::block_in_place as block;

const HEADER_BATCH_SIZE: usize = 50;

type AppClient<T> = <Bitcoin as Client<T>>::Client;

// TODO
fn derive_script(addr: Address, sig_set: &SignatorySet) -> Script {
    let data = (addr, sig_set.0 as u64).encode().unwrap();
    bitcoin::Script::new_op_return(&data).to_v0_p2wsh()
}

pub struct Relayer<T: Clone + Send> {
    btc_client: BtcClient,
    app_client: AppClient<T>,

    scripts: WatchedScripts,
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
            scripts: WatchedScripts::new(derive_script, 86_400, 144),
        }
    }

    async fn sidechain_block_hash(&self) -> Result<BlockHash> {
        let hash = self.app_client.headers.hash().await??;
        let hash = bitcoin::BlockHash::from_slice(hash.as_slice())?;
        Ok(hash)
    }

    pub async fn relay_headers(&mut self) -> Result<()> {
        println!("Starting header relay...");

        loop {
            let fullnode_hash = block(|| self.btc_client.get_best_block_hash())?;
            dbg!(fullnode_hash);
            let sidechain_hash = self.sidechain_block_hash().await?;
            dbg!(sidechain_hash);

            if fullnode_hash != sidechain_hash {
                self.relay_header_batch(fullnode_hash, sidechain_hash)
                    .await?;
                continue;
            }

            let info = block(|| self.btc_client.get_block_info(&fullnode_hash))?;
            println!(
                "Sidechain header state is up-to-date:\n\thash={}\n\theight={}",
                info.hash, info.height
            );

            block(|| self.btc_client.wait_for_new_block(0))?;
        }
    }

    pub async fn relay_deposits(&mut self) -> Result<!> {
        println!("Starting deposit relay...");

        // TODO: remove this (just added for testing)
        self.scripts.add_address([0; 20].into());
        self.scripts.add_sig_set(SignatorySet(0));

        let block_hash = self.sidechain_block_hash().await?;
        for block in self.last_n_blocks(1008, block_hash)? {
            for tx in self.relevant_txs(&block) {
                self.maybe_relay_deposit(tx).await?;
            }
        }

        loop {
            block(|| std::thread::sleep(std::time::Duration::from_secs(1)));
        }
    }

    pub fn last_n_blocks(&self, n: usize, mut hash: BlockHash) -> Result<Vec<Block>> {
        (0..n)
            .map(move |_| {
                let block =
                    tokio::task::block_in_place(|| self.btc_client.get_block(&hash.clone()));
                if let Ok(ref block) = block {
                    hash = block.header.prev_blockhash;
                }
                Ok(block?)
            })
            .collect()
    }

    pub fn relevant_txs<'a>(&self, block: &'a Block) -> Vec<&'a Transaction> {
        block
            .txdata
            .iter()
            .filter(move |tx| tx.output.iter().any(|s| self.scripts.has(&s.script_pubkey)))
            .collect()
    }

    async fn maybe_relay_deposit(&mut self, tx: &Transaction) -> Result<()> {
        let txid = Adapter::new(tx.txid());
        if self.app_client.was_relayed(txid).await?? {
            println!("Detected already-relayed deposit: {}", txid.to_hex());
            return Ok(());
        }

        let _tx = Adapter::new(tx.clone());
        // self.app_client.deposit(tx, 2).await?;
        println!("Relayed deposit: {}", txid.to_hex());

        Ok(())
    }

    async fn relay_header_batch(
        &mut self,
        fullnode_hash: BlockHash,
        sidechain_hash: BlockHash,
    ) -> Result<()> {
        let get_info = |hash| block(|| self.btc_client.get_block_header_info(&hash));

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

        self.app_client.headers.add(batch.into()).await?;
        println!("Relayed headers");

        Ok(())
    }

    fn get_header_batch(&self, from_hash: BlockHash) -> Result<Vec<WrappedHeader>> {
        let get_info = |hash| block(|| self.btc_client.get_block_header_info(&hash));

        let mut cursor = get_info(from_hash)?;

        let mut headers = Vec::with_capacity(HEADER_BATCH_SIZE as usize);
        for _ in 0..HEADER_BATCH_SIZE {
            match cursor.next_block_hash {
                Some(next_hash) => cursor = get_info(next_hash)?,
                None => break,
            };

            let header = block(|| self.btc_client.get_block_header(&cursor.hash))?;
            let header = WrappedHeader::from_header(&header, cursor.height as u32);

            dbg!(&header);

            headers.push(header);
        }

        Ok(headers)
    }

    fn common_ancestor(&self, a: BlockHash, b: BlockHash) -> Result<GetBlockHeaderResult> {
        let get_info = |hash| block(|| self.btc_client.get_block_header_info(&hash));

        let mut a = get_info(a)?;
        let mut b = get_info(b)?;

        let prev =
            |header: GetBlockHeaderResult| get_info(header.previous_block_hash.unwrap());

        while a != b {
            if a.height > b.height && (b.confirmations - 1) as usize == a.height - b.height {
                return Ok(b);
            } else if b.height > a.height && (a.confirmations - 1) as usize == b.height - a.height {
                return Ok(a);
            } else if a.height > b.height {
                a = prev(a)?;
            } else {
                b = prev(b)?;
            }
        }

        Ok(a)
    }
}

// TODO: implement actual signatory set type
#[derive(Hash)]
pub struct SignatorySet(usize);

fn time_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A collection which stores all watched addresses and signatory sets, for
/// efficiently detecting deposit output scripts.
pub struct WatchedScripts {
    scripts: HashMap<Script, (Address, usize)>,

    addr_queue: VecDeque<(u64, Address)>,
    addrs: HashSet<Address>,

    sig_set_index: usize,
    sig_sets: VecDeque<SignatorySet>,

    derive_script: fn(Address, &SignatorySet) -> Script,
    addr_ttl: u64,
    max_sig_sets: usize,
}

impl WatchedScripts {
    pub fn new(
        derive_script: fn(Address, &SignatorySet) -> Script,
        addr_ttl: u64,
        max_sig_sets: usize,
    ) -> Self {
        Self {
            scripts: HashMap::new(),

            addr_queue: VecDeque::new(),
            addrs: HashSet::new(),

            sig_set_index: 0,
            sig_sets: VecDeque::new(),

            derive_script,
            addr_ttl,
            max_sig_sets,
        }
    }

    pub fn get(&self, script: &Script) -> Option<(Address, &SignatorySet)> {
        self.scripts.get(script).map(|&(addr, sig_set_index)| {
            let sig_set = self.sig_set(sig_set_index);
            (addr, sig_set)
        })
    }

    pub fn has(&self, script: &Script) -> bool {
        self.scripts.contains_key(script)
    }

    pub fn len(&self) -> usize {
        self.scripts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    pub fn add_address(&mut self, addr: Address) {
        let now = time_now();
        self.addr_queue.push_back((now, addr));
        self.addrs.insert(addr);

        for (sig_set_index, script) in self.scripts_for_addr(addr) {
            self.scripts.insert(script, (addr, sig_set_index));
        }
    }

    pub fn remove_expired_addrs(&mut self) {
        let now = time_now();

        while let Some(&(time, addr)) = self.addr_queue.front() {
            let age = now - time;
            if age < self.addr_ttl {
                break;
            }

            self.addrs.remove(&addr);
            self.addr_queue.pop_front();

            for (_, script) in self.scripts_for_addr(addr) {
                self.scripts.remove(&script);
            }
        }
    }

    fn scripts_for_addr(&self, addr: Address) -> Vec<(usize, Script)> {
        self.sig_sets
            .iter()
            .enumerate()
            .map(|(i, sig_set)| {
                let index = self.sig_set_index - self.sig_sets.len() + i;
                let script = (self.derive_script)(addr, sig_set);
                (index, script)
            })
            .collect()
    }

    pub fn add_sig_set(&mut self, sig_set: SignatorySet) {
        for (addr, script) in self.scripts_for_sig_set(&sig_set) {
            self.scripts.insert(script, (addr, self.sig_set_index + 1));
        }

        self.sig_sets.push_back(sig_set);
        self.sig_set_index += 1;

        while self.sig_sets.len() > self.max_sig_sets {
            self.remove_sig_set();
        }
    }

    fn remove_sig_set(&mut self) {
        let sig_set = self.sig_sets.pop_front().unwrap();

        for (_, script) in self.scripts_for_sig_set(&sig_set) {
            self.scripts.remove(&script);
        }
    }

    fn scripts_for_sig_set(&self, sig_set: &SignatorySet) -> Vec<(Address, Script)> {
        self.addrs
            .iter()
            .map(|&addr| {
                let script = (self.derive_script)(addr, sig_set);
                (addr, script)
            })
            .collect()
    }

    fn sig_set(&self, index: usize) -> &SignatorySet {
        &self.sig_sets[index - (self.sig_set_index - self.sig_sets.len() + 1)]
    }
}

#[cfg(todo)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::adapter::Adapter;
    use crate::bitcoin::header_queue::{Config, HeaderQueue};
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

        let store = Store::new(Shared::new(MapStore::new()).into());
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
