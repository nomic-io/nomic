use super::signatory::Signatory;
use super::SignatorySet;
use crate::app::App;
use crate::app::DepositCommitment;
use crate::bitcoin::{adapter::Adapter, header_queue::WrappedHeader};
use crate::error::Result;
use bitcoincore_rpc_async::bitcoin;
use bitcoincore_rpc_async::bitcoin::consensus::Encodable;
use bitcoincore_rpc_async::bitcoin::{
    consensus::Decodable, hashes::Hash, Block, BlockHash, Transaction,
};
use bitcoincore_rpc_async::json::GetBlockHeaderResult;
use bitcoincore_rpc_async::{Client as BitcoinRpcClient, RpcApi};
use futures::{pin_mut, select, FutureExt};
use log::{debug, error, info, warn};
use orga::abci::TendermintClient;
use orga::encoding::Decode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use warp::reject;

const HEADER_BATCH_SIZE: usize = 25;

pub struct Relayer {
    btc_client: BitcoinRpcClient,
    app_client: TendermintClient<App>,

    scripts: Option<WatchedScriptStore>,
}

impl Relayer {
    pub async fn new(btc_client: BitcoinRpcClient, app_client: TendermintClient<App>) -> Self {
        Relayer {
            btc_client,
            app_client,
            scripts: None,
        }
    }

    async fn sidechain_block_hash(&self) -> Result<BlockHash> {
        let hash = self.app_client.bitcoin.headers.hash().await??;
        let hash = BlockHash::from_slice(hash.as_slice())?;
        Ok(hash)
    }

    pub async fn start_header_relay(&mut self) -> Result<!> {
        info!("Starting header relay...");

        loop {
            if let Err(e) = self.relay_headers().await {
                error!("Header relay error: {}", e);
            }

            sleep(2).await;
        }
    }

    async fn relay_headers(&mut self) -> Result<()> {
        let mut last_hash = None;

        loop {
            let fullnode_hash = self.btc_client.get_best_block_hash().await?;
            let sidechain_hash = self.sidechain_block_hash().await?;

            if fullnode_hash != sidechain_hash {
                self.relay_header_batch(fullnode_hash, sidechain_hash)
                    .await?;
                continue;
            }

            if last_hash.is_none() || last_hash.is_some_and(|h| h != fullnode_hash) {
                last_hash = Some(fullnode_hash);
                let info = self.btc_client.get_block_info(&fullnode_hash).await?;
                info!(
                    "Sidechain header state is up-to-date:\n\thash={}\n\theight={}",
                    info.hash, info.height
                );
            }

            self.btc_client.wait_for_new_block(3_000).await?;
        }
    }

    pub async fn start_deposit_relay<P: AsRef<Path>>(&mut self, store_path: P) -> Result<()> {
        info!("Starting deposit relay...");

        let scripts = WatchedScriptStore::open(store_path, &self.app_client).await?;
        self.scripts = Some(scripts);

        let (server, mut recv) = self.create_address_server();
        let server = server.fuse();

        let do_relaying = async {
            loop {
                if let Err(e) = self.relay_deposits(&mut recv).await {
                    error!("Deposit relay error: {}", e);
                }

                sleep(2).await;
            }
        }
        .fuse();

        pin_mut!(server, do_relaying);

        select! {
            () = server => (),
            () = do_relaying => ()
        };

        Ok(())
    }

    fn create_address_server(
        &self,
    ) -> (impl Future<Output = ()>, Receiver<(DepositCommitment, u32)>) {
        let (send, recv) = tokio::sync::mpsc::channel(1024);

        let sigsets = Arc::new(Mutex::new(BTreeMap::new()));

        // TODO: configurable listen address
        use bytes::Bytes;
        use warp::Filter;
        let bcast_route = warp::post()
            .and(warp::path("address"))
            .and(warp::query::<DepositAddress>())
            .and(warp::filters::body::bytes())
            .map(move |query: DepositAddress, body| (query, send.clone(), sigsets.clone(), body))
            .and_then(
                async move |(query, send, sigsets, body): (
                    DepositAddress,
                    tokio::sync::mpsc::Sender<_>,
                    Arc<Mutex<BTreeMap<_, _>>>,
                    Bytes,
                )| {
                    let dest = DepositCommitment::decode(body.to_vec().as_slice())
                        .map_err(|_| warp::reject::reject())?;

                    let mut sigsets = sigsets.lock().await;
                    let app_client = crate::app_client(); // TODO: get from elsewhere

                    let sigset = match sigsets.get(&query.sigset_index) {
                        Some(sigset) => sigset,
                        None => {
                            let sigset = app_client
                                .bitcoin
                                .checkpoints
                                .get(query.sigset_index)
                                .await
                                .map_err(|_| reject())?
                                .map_err(|_| reject())?
                                .sigset
                                .clone();
                            sigsets.insert(query.sigset_index, sigset);
                            sigsets.get(&query.sigset_index).unwrap()
                            // TODO: prune sigsets
                        }
                    };
                    let expected_addr = ::bitcoin::Address::from_script(
                        &sigset
                            .output_script(
                                dest.commitment_bytes().map_err(|_| reject())?.as_slice(),
                            )
                            .map_err(|_| reject())?,
                        super::NETWORK,
                    )
                    .unwrap()
                    .to_string();
                    if expected_addr != query.deposit_addr {
                        return Err(reject());
                    }

                    Ok::<_, warp::Rejection>((dest, query.sigset_index, send))
                },
            )
            .then(
                async move |(dest, sigset_index, send): (
                    DepositCommitment,
                    u32,
                    tokio::sync::mpsc::Sender<_>,
                )| {
                    debug!("Received deposit commitment: {:?}, {}", dest, sigset_index);
                    send.send((dest, sigset_index)).await.unwrap();
                    "OK"
                },
            );

        let sigset_route = warp::path("sigset")
            .and_then(async move || {
                let app_client = crate::app_client(); // TODO: get from elsewhere
                let sigset: RawSignatorySet = app_client
                    .bitcoin
                    .checkpoints
                    .active_sigset()
                    .await
                    .map_err(|_| reject())?
                    .map_err(|_| reject())?
                    .into();

                Ok::<_, warp::Rejection>(warp::reply::json(&sigset))
            })
            .with(warp::cors().allow_any_origin());

        let server = warp::serve(
            warp::any().and(bcast_route).or(sigset_route).with(
                warp::cors()
                    .allow_any_origin()
                    .allow_headers(vec![
                        "User-Agent",
                        "Sec-Fetch-Mode",
                        "Referer",
                        "Origin",
                        "Access-Control-Request-Method",
                        "Access-Control-Request-Headers",
                        "content-type",
                    ])
                    .allow_method("POST"),
            ),
        )
        .run(([0, 0, 0, 0], 8999));
        (server, recv)
    }

    async fn relay_deposits(&mut self, recv: &mut Receiver<(DepositCommitment, u32)>) -> Result<!> {
        let mut prev_tip = None;
        loop {
            sleep(2).await;

            self.insert_announced_addrs(recv).await?;

            let tip = self.sidechain_block_hash().await?;
            let prev = prev_tip.unwrap_or(tip);
            if prev_tip.is_some() && prev == tip {
                continue;
            }

            let start_height = self.common_ancestor(tip, prev).await?.height;
            let end_height = self.btc_client.get_block_header_info(&tip).await?.height;
            let num_blocks = (end_height - start_height).max(1100);

            self.scan_for_deposits(num_blocks).await?;

            prev_tip = Some(tip);
        }
    }

    async fn scan_for_deposits(&mut self, num_blocks: usize) -> Result<BlockHash> {
        let tip = self.sidechain_block_hash().await?;
        let base_height = self.btc_client.get_block_header_info(&tip).await?.height;
        let blocks = self.last_n_blocks(num_blocks, tip).await?;

        for (i, block) in blocks.into_iter().enumerate().rev() {
            let height = (base_height - i) as u32;
            for (tx, matches) in self.relevant_txs(&block) {
                for output in matches {
                    if let Err(err) = self
                        .maybe_relay_deposit(tx, height, &block.block_hash(), output)
                        .await
                    {
                        // TODO: filter out harmless errors (e.g. deposit too small)
                        warn!("Skipping deposit for error: {}", err);
                    }
                }
            }
        }

        Ok(tip)
    }

    pub async fn start_checkpoint_relay(&mut self) -> Result<!> {
        info!("Starting checkpoint relay...");

        loop {
            if let Err(e) = self.relay_checkpoints().await {
                if !e.to_string().contains("No completed checkpoints yet") {
                    error!("Checkpoint relay error: {}", e);
                }
            }

            sleep(2).await;
        }
    }

    async fn relay_checkpoints(&mut self) -> Result<()> {
        let last_checkpoint = self
            .app_client
            .bitcoin
            .checkpoints
            .last_completed_tx()
            .await??;
        info!("Last checkpoint tx: {}", last_checkpoint.txid());

        let mut relayed = HashSet::new();

        loop {
            let txs = self
                .app_client
                .bitcoin
                .checkpoints
                .completed_txs()
                .await??;
            for tx in txs {
                if relayed.contains(&tx.txid()) {
                    continue;
                }

                let mut tx_bytes = vec![];
                tx.consensus_encode(&mut tx_bytes)?;

                match self.btc_client.send_raw_transaction(&tx_bytes).await {
                    Ok(_) => {
                        info!("Relayed checkpoint: {}", tx.txid());
                    }
                    Err(err) if err.to_string().contains("bad-txns-inputs-missingorspent") => {}
                    Err(err)
                        if err
                            .to_string()
                            .contains("Transaction already in block chain") => {}
                    Err(err) => Err(err)?,
                }

                relayed.insert(tx.txid());
            }

            sleep(1).await;
        }
    }

    async fn insert_announced_addrs(
        &mut self,
        recv: &mut Receiver<(DepositCommitment, u32)>,
    ) -> Result<()> {
        while let Ok((addr, sigset_index)) = recv.try_recv() {
            let checkpoint_res = self
                .app_client
                .bitcoin
                .checkpoints
                .get(sigset_index)
                .await?;
            let sigset = match &checkpoint_res {
                Ok(checkpoint) => &checkpoint.sigset,
                Err(err) => {
                    error!("{}", err);
                    continue;
                }
            };

            self.scripts.as_mut().unwrap().insert(addr, sigset)?;
        }

        self.scripts.as_mut().unwrap().scripts.remove_expired()?;

        Ok(())
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
                    .as_ref()
                    .unwrap()
                    .scripts
                    .get(&script)
                    .map(|(dest, sigset_index)| OutputMatch {
                        sigset_index,
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

        let txid = tx.txid();
        let outpoint = (txid.into_inner(), output.vout);
        let dest = output.dest.clone();
        let vout = output.vout;

        if self
            .app_client
            .bitcoin
            .processed_outpoints
            .contains(outpoint)
            .await??
        {
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

            let res = self
                .app_client
                .clone()
                .pay_from(async move |client| {
                    client
                        .relay_deposit(
                            tx,
                            height,
                            proof,
                            output.vout,
                            output.sigset_index,
                            output.dest,
                        )
                        .await
                })
                .noop()
                .await;

            match res {
                Err(err)
                    if err.to_string().contains("Deposit amount is below minimum")
                        || err
                            .to_string()
                            .contains("Deposit amount is too small to pay its spending fee") =>
                {
                    return Ok(());
                }
                _ => res?,
            };
        }

        info!(
            "Relayed deposit: {} sats, {:?}",
            tx.output[vout as usize].value, dest
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

        info!(
            "Relaying headers...\n\thash={}\n\theight={}\n\tbatch_len={}",
            batch[0].block_hash(),
            batch[0].height(),
            batch.len(),
        );

        let res = self
            .app_client
            .pay_from(async move |client| client.bitcoin.headers.add(batch.into()).await)
            .noop()
            .await;
        let current_tip = self.sidechain_block_hash().await?;
        if current_tip == fullnode_hash {
            info!("Relayed headers");
        } else {
            res?;
        }

        Ok(())
    }

    async fn get_header_batch(&self, from_hash: BlockHash) -> Result<Vec<WrappedHeader>> {
        let mut cursor = self.btc_client.get_block_header_info(&from_hash).await?;

        let mut headers = Vec::with_capacity(HEADER_BATCH_SIZE);
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

#[derive(Serialize, Deserialize)]
struct DepositAddress {
    sigset_index: u32,
    deposit_addr: String,
}

pub struct OutputMatch {
    sigset_index: u32,
    vout: u32,
    dest: DepositCommitment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RawSignatorySet {
    pub signatories: Vec<RawSignatory>,
    pub index: u32,
}

impl From<SignatorySet> for RawSignatorySet {
    fn from(sigset: SignatorySet) -> Self {
        let signatories = sigset
            .iter()
            .map(|s| RawSignatory::from(s.clone()))
            .collect();

        RawSignatorySet {
            signatories,
            index: sigset.index(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RawSignatory {
    pub voting_power: u64,
    pub pubkey: Vec<u8>,
}

impl From<Signatory> for RawSignatory {
    fn from(sig: Signatory) -> Self {
        RawSignatory {
            voting_power: sig.voting_power,
            pubkey: sig.pubkey.as_slice().to_vec(),
        }
    }
}

fn time_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn sleep(seconds: u64) {
    let duration = std::time::Duration::from_secs(seconds);
    tokio::time::sleep(duration).await;
}

/// A collection which stores all watched addresses and signatory sets, for
/// efficiently detecting deposit output scripts.
#[derive(Default)]
pub struct WatchedScripts {
    scripts: HashMap<::bitcoin::Script, (DepositCommitment, u32)>,
    sigsets: BTreeMap<u32, (SignatorySet, Vec<DepositCommitment>)>,
}

impl WatchedScripts {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn get(&self, script: &::bitcoin::Script) -> Option<(DepositCommitment, u32)> {
        self.scripts.get(script).cloned()
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

    pub fn insert(&mut self, dest: DepositCommitment, sigset: &SignatorySet) -> Result<bool> {
        let script = self.derive_script(&dest, sigset)?;

        if self.scripts.contains_key(&script) {
            return Ok(false);
        }

        self.scripts.insert(script, (dest.clone(), sigset.index()));

        let (_, dests) = self
            .sigsets
            .entry(sigset.index())
            .or_insert((sigset.clone(), vec![]));
        dests.push(dest);

        Ok(true)
    }

    pub fn remove_expired(&mut self) -> Result<()> {
        let now = time_now();

        for (_, (sigset, dests)) in self.sigsets.iter() {
            if now < sigset.deposit_timeout() {
                break;
            }

            for dest in dests {
                let script = self.derive_script(dest, sigset)?;
                self.scripts.remove(&script);
            }
        }

        Ok(())
    }

    fn derive_script(
        &self,
        dest: &DepositCommitment,
        sigset: &SignatorySet,
    ) -> Result<::bitcoin::Script> {
        sigset.output_script(dest.commitment_bytes()?.as_slice())
    }
}

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

pub struct WatchedScriptStore {
    scripts: WatchedScripts,
    file: File,
}

impl WatchedScriptStore {
    pub async fn open<P: AsRef<Path>>(path: P, app_client: &TendermintClient<App>) -> Result<Self> {
        let path = path.as_ref().join("watched-addrs.csv");

        let mut scripts = WatchedScripts::new();
        Self::maybe_load(&path, &mut scripts, app_client).await?;

        let tmp_path = path.with_file_name("watched-addrs-tmp.csv");
        let mut tmp_file = File::create(&tmp_path)?;
        for (addr, sigset_index) in scripts.scripts.values() {
            Self::write(&mut tmp_file, addr, *sigset_index)?;
        }
        tmp_file.flush()?;
        drop(tmp_file);
        std::fs::rename(tmp_path, &path)?;

        let file = File::options().append(true).create(true).open(&path)?;

        info!("Keeping track of deposit addresses at {}", path.display());

        Ok(WatchedScriptStore { scripts, file })
    }

    async fn maybe_load<P: AsRef<Path>>(
        path: P,
        scripts: &mut WatchedScripts,
        client: &TendermintClient<App>,
    ) -> Result<()> {
        let file = match File::open(&path) {
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
            Ok(file) => file,
        };

        let mut sigsets = BTreeMap::new();
        for (index, checkpoint) in client.bitcoin.checkpoints.all().await?? {
            sigsets.insert(index, checkpoint.sigset.clone());
        }

        let lines = BufReader::new(file).lines();
        for line in lines {
            let line = line?;
            let items: Vec<_> = line.split(',').collect();

            let sigset_index: u32 = items[1]
                .parse()
                .map_err(|_| orga::Error::App("Could not parse sigset index".to_string()))?;
            let sigset = match sigsets.get(&sigset_index) {
                Some(sigset) => sigset,
                None => continue,
            };

            let dest = DepositCommitment::from_base64(items[0])?;

            scripts.insert(dest, sigset)?;
        }

        scripts.remove_expired()?;

        info!("Loaded {} deposit addresses", scripts.len());

        Ok(())
    }

    pub fn insert(&mut self, dest: DepositCommitment, sigset: &SignatorySet) -> Result<()> {
        if self.scripts.insert(dest.clone(), sigset)? {
            Self::write(&mut self.file, &dest, sigset.index())?;
        }

        Ok(())
    }

    fn write(file: &mut File, dest: &DepositCommitment, sigset_index: u32) -> Result<()> {
        writeln!(file, "{},{}", dest.to_base64()?, sigset_index)?;
        file.flush()?;
        Ok(())
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
            BitcoinRpcClient::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

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
            BitcoinRpcClient::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

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
