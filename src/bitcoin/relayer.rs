use super::{Bitcoin, SignatorySet};
use crate::bitcoin::{adapter::Adapter, header_queue::WrappedHeader};
use crate::error::Result;
use ::bitcoin::consensus::Decodable as _;
use ::bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoincore_rpc_async::bitcoin;
use bitcoincore_rpc_async::bitcoin::consensus::Encodable;
use bitcoincore_rpc_async::bitcoin::{
    consensus::Decodable,
    hashes::{hex::ToHex, Hash},
    Block, BlockHash, Script, Transaction,
};
use bitcoincore_rpc_async::json::GetBlockHeaderResult;
use bitcoincore_rpc_async::{Client as BtcClient, RpcApi};
use orga::client::{AsyncCall, AsyncQuery};
use orga::coins::Address;
use orga::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

const HEADER_BATCH_SIZE: usize = 100;

type AppClient<T> = <Bitcoin as Client<T>>::Client;

pub struct Relayer<T: Clone + Send> {
    btc_client: BtcClient,
    app_client: AppClient<T>,

    scripts: WatchedScripts,
}

impl<T: Clone + Send> Relayer<T>
where
    T: AsyncQuery<Query = <Bitcoin as Query>::Query>,
    T: for<'a> AsyncQuery<Response<'a> = &'a Bitcoin>,
    T: AsyncCall<Call = <Bitcoin as Call>::Call>,
{
    pub fn new(btc_client: BtcClient, app_client: AppClient<T>) -> Self {
        Relayer {
            btc_client,
            app_client,
            scripts: WatchedScripts::new(),
        }
    }

    async fn sidechain_block_hash(&self) -> Result<BlockHash> {
        let hash = self.app_client.headers.hash().await??;
        let hash = BlockHash::from_slice(hash.as_slice())?;
        Ok(hash)
    }

    pub async fn relay_headers(&mut self) -> Result<()> {
        println!("Starting header relay...");

        let mut last_hash = None;

        loop {
            let fullnode_hash = self.btc_client.get_best_block_hash().await?;
            let sidechain_hash = self.sidechain_block_hash().await?;

            if fullnode_hash != sidechain_hash {
                self.relay_header_batch(fullnode_hash, sidechain_hash)
                    .await?;
                continue;
            }

            if last_hash.is_none() || last_hash.is_some_and(|h| h != &fullnode_hash) {
                last_hash = Some(fullnode_hash);
                let info = self.btc_client.get_block_info(&fullnode_hash).await?;
                println!(
                    "Sidechain header state is up-to-date:\n\thash={}\n\theight={}",
                    info.hash, info.height
                );
            }

            self.btc_client.wait_for_new_block(3_000).await?;
        }
    }

    pub async fn relay_deposits(&mut self) -> Result<!> {
        println!("Starting deposit relay...");

        // TODO: load address state

        println!("deposit addrs:");
        for (script, (depositor, sigset)) in self.scripts.scripts.iter() {
            let addr = ::bitcoin::Address::from_script(script, ::bitcoin::Network::Testnet).unwrap();
            println!(" - {} ({}, {})", addr, depositor, sigset);
        }

        println!("Scanning recent blocks for deposits...");
        let tip = self.sidechain_block_hash().await?;
        let base_height = self.btc_client.get_block_header_info(&tip).await?.height;
        let blocks = self.last_n_blocks(1008, tip).await?;
        for (i, block) in blocks.into_iter().enumerate().rev() {
            let height = (base_height - i) as u32;
            for (tx, matches) in self.relevant_txs(&block) {
                for output in matches {
                    self.maybe_relay_deposit(tx, height, &block.block_hash(), output)
                        .await?;
                }
            }
        }

        println!("Watching for new deposits...");
        let mut prev_tip = tip;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            // TODO: add new sig sets when detected
            // TODO: remove old sigsets when expired

            let tip = self.sidechain_block_hash().await?;
            if tip != prev_tip {
                let start_height = self.common_ancestor(tip, prev_tip).await?.height;
                let end_height = self.btc_client.get_block_header_info(&tip).await?.height;

                let blocks = self.last_n_blocks(end_height - start_height, tip).await?;
                for (i, block) in blocks.into_iter().enumerate().rev() {
                    let height = (end_height - i) as u32;
                    for (tx, matches) in self.relevant_txs(&block) {
                        for output in matches {
                            self.maybe_relay_deposit(tx, height, &block.block_hash(), output)
                                .await?;
                        }
                    }
                }

                prev_tip = tip;
            }
        }
    }

    pub async fn last_n_blocks(&self, n: usize, hash: BlockHash) -> Result<Vec<Block>> {
        let mut blocks = vec![];

        let mut hash = bitcoin::BlockHash::from_inner(hash.into_inner());

        for _ in 0..n {
            let block = self.btc_client.get_block(&hash.clone()).await?;
            hash = block.header.prev_blockhash;

            let mut block_bytes = vec![];
            block.consensus_encode(&mut block_bytes).unwrap();
            let block = Block::consensus_decode(block_bytes.as_slice()).unwrap();

            blocks.push(block);
        }

        Ok(blocks)
    }

    pub fn relevant_txs<'a>(
        &'a self,
        block: &'a Block,
    ) -> impl Iterator<Item = (&'a Transaction, impl Iterator<Item = OutputMatch> + 'a)> + 'a {
        block
            .txdata
            .iter()
            .map(move |tx| (tx, self.relevant_outputs(tx)))
    }

    pub fn relevant_outputs<'a>(
        &'a self,
        tx: &'a Transaction,
    ) -> impl Iterator<Item = OutputMatch> + 'a {
        tx.output
            .iter()
            .enumerate()
            .filter_map(move |(vout, output)| {
                let mut script_bytes = vec![];
                output
                    .script_pubkey
                    .consensus_encode(&mut script_bytes)
                    .unwrap();
                let script = ::bitcoin::Script::consensus_decode(script_bytes.as_slice()).unwrap();

                self.scripts
                    .get(&script)
                    .map(|(dest, sigset_index)| OutputMatch {
                        sigset_index: sigset_index as u64,
                        vout: vout as u32,
                        dest,
                    })
            })
    }

    async fn maybe_relay_deposit(
        &self,
        tx: &Transaction,
        height: u32,
        block_hash: &BlockHash,
        output: OutputMatch,
    ) -> Result<()> {
        use self::bitcoin::hashes::Hash as _;
        use ::bitcoin::hashes::Hash as _;

        let txid = tx.txid();
        let outpoint = (txid.into_inner(), output.vout);

        if self
            .app_client
            .processed_outpoints
            .contains(outpoint)
            .await??
        {
            println!("Detected already-relayed deposit: {}", txid.to_hex());
            return Ok(());
        }

        let proof_bytes = self
            .btc_client
            .get_tx_out_proof(&[tx.txid()], Some(block_hash))
            .await?;
        let proof = ::bitcoin::MerkleBlock::consensus_decode(proof_bytes.as_slice())?.txn;

        {
            let mut tx_bytes = vec![];
            tx.consensus_encode(&mut tx_bytes)?;
            let tx = ::bitcoin::Transaction::consensus_decode(tx_bytes.as_slice())?;
            let tx = Adapter::new(tx.clone());

            let proof = Adapter::new(proof);

            self.app_client
                .relay_deposit(
                    tx,
                    height,
                    proof,
                    output.vout,
                    output.sigset_index,
                    output.dest,
                )
                .await?;
        }

        println!(
            "Relayed deposit: {} sats, {}",
            tx.output[output.vout as usize].value, output.dest
        );

        Ok(())
    }

    async fn relay_header_batch(
        &mut self,
        fullnode_hash: BlockHash,
        sidechain_hash: BlockHash,
    ) -> Result<()> {
        let fullnode_info = self
            .btc_client
            .get_block_header_info(&fullnode_hash)
            .await?;
        let sidechain_info = self
            .btc_client
            .get_block_header_info(&sidechain_hash)
            .await?;

        if fullnode_info.height < sidechain_info.height {
            // full node is still syncing
            return Ok(());
        }

        let start = self.common_ancestor(fullnode_hash, sidechain_hash).await?;
        let batch = self.get_header_batch(start.hash).await?;

        println!(
            "Relaying headers...\n\thash={}\n\theight={}\n\tbatch_len={}",
            batch[0].block_hash(),
            batch[0].height(),
            batch.len(),
        );

        self.app_client.headers.add(batch.into()).await?;
        println!("Relayed headers");

        Ok(())
    }

    async fn get_header_batch(&self, from_hash: BlockHash) -> Result<Vec<WrappedHeader>> {
        let mut cursor = self.btc_client.get_block_header_info(&from_hash).await?;

        let mut headers = Vec::with_capacity(HEADER_BATCH_SIZE as usize);
        for _ in 0..HEADER_BATCH_SIZE {
            match cursor.next_block_hash {
                Some(next_hash) => {
                    cursor = self.btc_client.get_block_header_info(&next_hash).await?
                }
                None => break,
            };

            let header = self.btc_client.get_block_header(&cursor.hash).await?;
            let mut header_bytes = vec![];
            header.consensus_encode(&mut header_bytes).unwrap();
            let header = ::bitcoin::BlockHeader::consensus_decode(header_bytes.as_slice()).unwrap();

            let header = WrappedHeader::from_header(&header, cursor.height as u32);

            headers.push(header);
        }

        Ok(headers)
    }

    async fn common_ancestor(&self, a: BlockHash, b: BlockHash) -> Result<GetBlockHeaderResult> {
        let mut a = self.btc_client.get_block_header_info(&a).await?;
        let mut b = self.btc_client.get_block_header_info(&b).await?;

        while a != b {
            if a.height > b.height && (b.confirmations - 1) as usize == a.height - b.height {
                return Ok(b);
            } else if b.height > a.height && (a.confirmations - 1) as usize == b.height - a.height {
                return Ok(a);
            } else if a.height > b.height {
                let prev = a.previous_block_hash.unwrap();
                a = self.btc_client.get_block_header_info(&prev).await?;
            } else {
                let prev = b.previous_block_hash.unwrap();
                b = self.btc_client.get_block_header_info(&prev).await?;
            }
        }

        Ok(a)
    }
}

pub struct OutputMatch {
    sigset_index: u64,
    vout: u32,
    dest: Address,
}

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
    scripts: HashMap<::bitcoin::Script, (Address, u64)>,
    sigsets: BTreeMap<u64, (SignatorySet, Vec<Address>)>,
}

impl WatchedScripts {
    pub fn new() -> Self {
        Self {
            scripts: HashMap::new(),
            sigsets: BTreeMap::new(),
        }
    }

    pub fn get(&self, script: &::bitcoin::Script) -> Option<(Address, u64)> {
        self.scripts.get(script).copied()
    }

    pub fn has(&self, script: &::bitcoin::Script) -> bool {
        self.scripts.contains_key(script)
    }

    pub fn len(&self) -> usize {
        self.scripts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    pub fn insert(&mut self, addr: Address, sigset: &SignatorySet) {
        let script = self.derive_script(addr, sigset);
        self.scripts.insert(script, (addr, sigset.index()));

        let (sigset, addrs) = self
            .sigsets
            .entry(sigset.index())
            .or_insert((sigset.clone(), vec![]));
        addrs.push(addr);
    }

    pub fn remove_expired(&mut self) {
        let now = time_now();

        for (i, (sigset, addrs)) in self.sigsets.iter() {
            if now < sigset.deposit_timeout() {
                break;
            }

            for addr in addrs {
                let script = self.derive_script(*addr, sigset);
                self.scripts.remove(&script);
            }
        }
    }

    fn derive_script(&self, addr: Address, sigset: &SignatorySet) -> ::bitcoin::Script {
        sigset.output_script(addr.bytes().to_vec())
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
