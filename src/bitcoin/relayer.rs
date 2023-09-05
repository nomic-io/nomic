use super::signatory::Signatory;
use super::SignatorySet;
use crate::app::Dest;
use crate::app_client;
use crate::bitcoin::{adapter::Adapter, header_queue::WrappedHeader};
use crate::error::Error;
use crate::error::Result;
use crate::utils::time_now;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::{hashes::Hash, Block, BlockHash, Transaction};
use bitcoind::bitcoincore_rpc::json::GetBlockHeaderResult;
use bitcoind::bitcoincore_rpc::{Client as BitcoinRpcClient, RpcApi};
use log::{debug, error, info, warn};
use orga::encoding::Decode;
use orga::macros::build_call;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use tokio::join;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use warp::reject;
use warp::reply::Json;

pub fn warp_reply_json<T>(val: T) -> Json
where
    T: Serialize,
{
    warp::reply::json(&val)
}

const HEADER_BATCH_SIZE: usize = 250;

pub struct Relayer {
    btc_client: BitcoinRpcClient,
    app_client_addr: String,

    scripts: Option<WatchedScriptStore>,
}

impl Relayer {
    pub fn new(btc_client: BitcoinRpcClient, app_client_addr: String) -> Self {
        Relayer {
            btc_client,
            app_client_addr,
            scripts: None,
        }
    }

    async fn sidechain_block_hash(&self) -> Result<BlockHash> {
        let hash = app_client(&self.app_client_addr)
            .query(|app| Ok(app.bitcoin.headers.hash()?))
            .await?;
        let hash = BlockHash::from_slice(hash.as_slice())?;
        Ok(hash)
    }

    pub async fn start_header_relay(&mut self) -> Result<()> {
        info!("Starting header relay...");

        loop {
            if let Err(e) = self.relay_headers().await {
                error!("Header relay error: {}", e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    }

    async fn relay_headers(&mut self) -> Result<()> {
        let mut last_hash = None;

        loop {
            let fullnode_hash = self.btc_client.get_best_block_hash()?;
            let sidechain_hash = self.sidechain_block_hash().await?;

            if fullnode_hash != sidechain_hash {
                self.relay_header_batch(fullnode_hash, sidechain_hash)
                    .await?;
                continue;
            }

            if last_hash.is_none() || last_hash.is_some_and(|h| h != fullnode_hash) {
                last_hash = Some(fullnode_hash);
                let info = self.btc_client.get_block_info(&fullnode_hash)?;
                info!(
                    "Sidechain header state is up-to-date:\n\thash={}\n\theight={}",
                    info.hash, info.height
                );
            }

            self.btc_client.wait_for_new_block(3_000)?;
        }
    }

    pub async fn start_deposit_relay<P: AsRef<Path>>(mut self, store_path: P) -> Result<()> {
        info!("Starting deposit relay...");

        let scripts = WatchedScriptStore::open(store_path, &self.app_client_addr).await?;
        self.scripts = Some(scripts);

        let (server, mut recv) = self.create_address_server();

        let deposit_relay = async {
            loop {
                if let Err(e) = self.relay_deposits(&mut recv).await {
                    error!("Deposit relay error: {}", e);
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        };

        join!(server, deposit_relay);
        Ok(())
    }

    fn create_address_server(&self) -> (impl Future<Output = ()>, Receiver<(Dest, u32)>) {
        let (send, recv) = tokio::sync::mpsc::channel(1024);

        let sigsets = Arc::new(Mutex::new(BTreeMap::new()));

        // TODO: pass into closures more cleanly
        let app_client_addr: &'static str = self.app_client_addr.clone().leak();

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
                    let dest = Dest::decode(body.to_vec().as_slice())
                        .map_err(|e| warp::reject::custom(Error::from(e)))?;

                    let mut sigsets = sigsets.lock().await;

                    //TODO: Replace catch-all 404 rejections
                    let sigset = match sigsets.get(&query.sigset_index) {
                        Some(sigset) => sigset,
                        None => {
                            app_client(app_client_addr)
                                .query(|app| {
                                    let sigset = app
                                        .bitcoin
                                        .checkpoints
                                        .get(query.sigset_index)?
                                        .sigset
                                        .clone();
                                    Ok(sigsets.insert(query.sigset_index, sigset))
                                })
                                .await
                                .map_err(|e| warp::reject::custom(Error::from(e)))?;
                            // TODO: prune sigsets
                            sigsets.get(&query.sigset_index).unwrap()
                        }
                    };
                    let expected_addr = ::bitcoin::Address::from_script(
                        &sigset
                            .output_script(
                                dest.commitment_bytes().map_err(|_| reject())?.as_slice(),
                            )
                            .map_err(warp::reject::custom)?,
                        super::NETWORK,
                    )
                    .unwrap()
                    .to_string();
                    if expected_addr != query.deposit_addr {
                        return Err(warp::reject::custom(Error::InvalidDepositAddress));
                    }

                    Ok::<_, warp::Rejection>((dest, query.sigset_index, send))
                },
            )
            .then(
                async move |(dest, sigset_index, send): (
                    Dest,
                    u32,
                    tokio::sync::mpsc::Sender<_>,
                )| {
                    debug!("Received deposit commitment: {:?}, {}", dest, sigset_index);
                    send.send((dest, sigset_index)).await.unwrap();
                    "OK"
                },
            );

        let sigset_route = warp::path("sigset")
            .and_then(move || async {
                let sigset = app_client(app_client_addr)
                    .query(|app| {
                        let sigset: RawSignatorySet =
                            app.bitcoin.checkpoints.active_sigset()?.into();
                        Ok(sigset)
                    })
                    .await
                    .map_err(|_| reject())?;

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

    async fn relay_deposits(&mut self, recv: &mut Receiver<(Dest, u32)>) -> Result<!> {
        let mut prev_tip = None;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            self.insert_announced_addrs(recv).await?;

            let tip = self.sidechain_block_hash().await?;
            let prev = prev_tip.unwrap_or(tip);
            if prev_tip.is_some() && prev == tip {
                continue;
            }

            let start_height = self.common_ancestor(tip, prev)?.height;
            let end_height = self.btc_client.get_block_header_info(&tip)?.height;
            let num_blocks = (end_height - start_height).max(1100);

            self.scan_for_deposits(num_blocks).await?;

            prev_tip = Some(tip);
        }
    }

    async fn scan_for_deposits(&mut self, num_blocks: usize) -> Result<BlockHash> {
        let tip = self.sidechain_block_hash().await?;
        let base_height = self.btc_client.get_block_header_info(&tip)?.height;
        let blocks = self.last_n_blocks(num_blocks, tip)?;

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

    pub async fn start_emergency_disbursal_transaction_relay(&mut self) -> Result<()> {
        info!("Starting emergency disbursal transaction relay...");

        loop {
            if let Err(e) = self.relay_emergency_disbursal_transactions().await {
                if !e.to_string().contains("No completed checkpoints yet") {
                    error!("Emergency disbursal relay error: {}", e);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    }

    async fn relay_emergency_disbursal_transactions(&mut self) -> Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut relayed = HashSet::new();
        loop {
            let disbursal_txs = app_client(&self.app_client_addr)
                .query(|app| Ok(app.bitcoin.checkpoints.emergency_disbursal_txs()?))
                .await?;

            for tx in disbursal_txs.iter() {
                if relayed.contains(&tx.txid()) {
                    continue;
                }

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now < tx.lock_time.to_u32() as u64 {
                    return Ok(());
                }

                let mut tx_bytes = vec![];
                tx.consensus_encode(&mut tx_bytes)?;

                match self.btc_client.send_raw_transaction(&tx_bytes) {
                    Ok(_) => {
                        info!("Relayed emergency disbursal transaction: {}", tx.txid());
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

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    }

    pub async fn start_checkpoint_relay(&mut self) -> Result<()> {
        info!("Starting checkpoint relay...");

        loop {
            if let Err(e) = self.relay_checkpoints().await {
                if !e.to_string().contains("No completed checkpoints yet") {
                    error!("Checkpoint relay error: {}", e);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    }

    async fn relay_checkpoints(&mut self) -> Result<()> {
        let last_checkpoint = app_client(&self.app_client_addr)
            .query(|app| Ok(app.bitcoin.checkpoints.last_completed_tx()?))
            .await?;
        info!("Last checkpoint tx: {}", last_checkpoint.txid());

        let mut relayed = HashSet::new();

        loop {
            let txs = app_client(&self.app_client_addr)
                .query(|app| Ok(app.bitcoin.checkpoints.completed_txs(1_000)?))
                .await?;
            for tx in txs {
                if relayed.contains(&tx.txid()) {
                    continue;
                }

                let mut tx_bytes = vec![];
                tx.consensus_encode(&mut tx_bytes)?;

                match self.btc_client.send_raw_transaction(&tx_bytes) {
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

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    }

    async fn insert_announced_addrs(&mut self, recv: &mut Receiver<(Dest, u32)>) -> Result<()> {
        while let Ok((addr, sigset_index)) = recv.try_recv() {
            let sigset_res = app_client(&self.app_client_addr)
                .query(|app| Ok(app.bitcoin.checkpoints.get(sigset_index)?.sigset.clone()))
                .await;
            let sigset = match sigset_res {
                Ok(sigset) => sigset,
                Err(err) => {
                    error!("{}", err);
                    continue;
                }
            };

            self.scripts.as_mut().unwrap().insert(addr, &sigset)?;
        }

        self.scripts.as_mut().unwrap().scripts.remove_expired()?;

        Ok(())
    }

    pub fn last_n_blocks(&self, n: usize, hash: BlockHash) -> Result<Vec<Block>> {
        let mut blocks = vec![];

        let mut hash = bitcoin::BlockHash::from_inner(hash.into_inner());

        for _ in 0..n {
            let block = self.btc_client.get_block(&hash.clone())?;
            hash = block.header.prev_blockhash;

            let mut block_bytes = vec![];
            block.consensus_encode(&mut block_bytes).unwrap();
            let block = Block::consensus_decode(&mut block_bytes.as_slice()).unwrap();

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
                let script =
                    ::bitcoin::Script::consensus_decode(&mut script_bytes.as_slice()).unwrap();

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
        use bitcoin::hashes::Hash as _;

        let txid = tx.txid();
        let outpoint = (txid.into_inner(), output.vout);
        let dest = output.dest.clone();
        let vout = output.vout;
        let contains_outpoint = app_client(&self.app_client_addr)
            .query(|app| app.bitcoin.processed_outpoints.contains(outpoint))
            .await?;

        if contains_outpoint {
            return Ok(());
        }

        let proof_bytes = self
            .btc_client
            .get_tx_out_proof(&[tx.txid()], Some(block_hash))?;
        let proof = ::bitcoin::MerkleBlock::consensus_decode(&mut proof_bytes.as_slice())?.txn;

        {
            let mut tx_bytes = vec![];
            tx.consensus_encode(&mut tx_bytes)?;
            let tx = ::bitcoin::Transaction::consensus_decode(&mut tx_bytes.as_slice())?;
            let tx = Adapter::new(tx);
            let proof = Adapter::new(proof);

            let res = app_client(&self.app_client_addr)
                .call(
                    move |app| {
                        build_call!(app.relay_deposit(
                            tx,
                            height,
                            proof,
                            output.vout,
                            output.sigset_index,
                            output.dest
                        ))
                    },
                    |app| build_call!(app.app_noop()),
                )
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
        let fullnode_info = self.btc_client.get_block_header_info(&fullnode_hash)?;
        let sidechain_info = self.btc_client.get_block_header_info(&sidechain_hash)?;

        if fullnode_info.height < sidechain_info.height {
            // full node is still syncing
            return Ok(());
        }

        let start = self.common_ancestor(fullnode_hash, sidechain_hash)?;
        let batch = self.get_header_batch(start.hash)?;

        info!(
            "Relaying headers...\n\thash={}\n\theight={}\n\tbatch_len={}",
            batch[0].block_hash(),
            batch[0].height(),
            batch.len(),
        );
        app_client(&self.app_client_addr)
            .call(
                |app| build_call!(app.bitcoin.headers.add(batch.clone().into_iter().collect())),
                |app| build_call!(app.app_noop()),
            )
            .await?;
        let res = app_client(&self.app_client_addr)
            .call(
                move |app| build_call!(app.bitcoin.headers.add(batch.clone().into())),
                |app| build_call!(app.app_noop()),
            )
            .await;

        let current_tip = self.sidechain_block_hash().await?;
        if current_tip == fullnode_hash {
            info!("Relayed headers");
        } else {
            res?;
        }

        Ok(())
    }

    fn get_header_batch(&self, from_hash: BlockHash) -> Result<Vec<WrappedHeader>> {
        let mut cursor = self.btc_client.get_block_header_info(&from_hash)?;

        let mut headers = Vec::with_capacity(HEADER_BATCH_SIZE);
        for _ in 0..HEADER_BATCH_SIZE {
            match cursor.next_block_hash {
                Some(next_hash) => cursor = self.btc_client.get_block_header_info(&next_hash)?,
                None => break,
            };

            let header = self.btc_client.get_block_header(&cursor.hash)?;
            let mut header_bytes = vec![];
            header.consensus_encode(&mut header_bytes).unwrap();
            let header =
                ::bitcoin::BlockHeader::consensus_decode(&mut header_bytes.as_slice()).unwrap();

            let header = WrappedHeader::from_header(&header, cursor.height as u32);

            headers.push(header);
        }

        Ok(headers)
    }

    fn common_ancestor(&self, a: BlockHash, b: BlockHash) -> Result<GetBlockHeaderResult> {
        let mut a = self.btc_client.get_block_header_info(&a)?;
        let mut b = self.btc_client.get_block_header_info(&b)?;

        while a != b {
            if a.height > b.height && (b.confirmations - 1) as usize == a.height - b.height {
                return Ok(b);
            } else if b.height > a.height && (a.confirmations - 1) as usize == b.height - a.height {
                return Ok(a);
            } else if a.height > b.height {
                let prev = a.previous_block_hash.unwrap();
                a = self.btc_client.get_block_header_info(&prev)?;
            } else {
                let prev = b.previous_block_hash.unwrap();
                b = self.btc_client.get_block_header_info(&prev)?;
            }
        }

        Ok(a)
    }
}

#[derive(Serialize, Deserialize)]
pub struct DepositAddress {
    pub sigset_index: u32,
    pub deposit_addr: String,
}

pub struct OutputMatch {
    sigset_index: u32,
    vout: u32,
    dest: Dest,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
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

#[derive(Clone, Serialize, Deserialize, Debug)]
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

/// A collection which stores all watched addresses and signatory sets, for
/// efficiently detecting deposit output scripts.
#[derive(Default)]
pub struct WatchedScripts {
    scripts: HashMap<::bitcoin::Script, (Dest, u32)>,
    sigsets: BTreeMap<u32, (SignatorySet, Vec<Dest>)>,
}

impl WatchedScripts {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn get(&self, script: &::bitcoin::Script) -> Option<(Dest, u32)> {
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

    pub fn insert(&mut self, dest: Dest, sigset: &SignatorySet) -> Result<bool> {
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

    fn derive_script(&self, dest: &Dest, sigset: &SignatorySet) -> Result<::bitcoin::Script> {
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
    pub async fn open<P: AsRef<Path>>(path: P, app_client_addr: &str) -> Result<Self> {
        let path = path.as_ref().join("watched-addrs.csv");

        let mut scripts = WatchedScripts::new();
        Self::maybe_load(&path, &mut scripts, app_client_addr).await?;

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
        app_client_addr: &str,
    ) -> Result<()> {
        let file = match File::open(&path) {
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
            Ok(file) => file,
        };

        let mut sigsets = BTreeMap::new();
        app_client(app_client_addr)
            .query(|app| {
                for (index, checkpoint) in app.bitcoin.checkpoints.all()? {
                    sigsets.insert(index, checkpoint.sigset.clone());
                }
                Ok(())
            })
            .await?;

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

            let dest = Dest::from_base64(items[0])?;

            scripts.insert(dest, sigset)?;
        }

        scripts.remove_expired()?;

        info!("Loaded {} deposit addresses", scripts.len());

        Ok(())
    }

    pub fn insert(&mut self, dest: Dest, sigset: &SignatorySet) -> Result<()> {
        if self.scripts.insert(dest.clone(), sigset)? {
            Self::write(&mut self.file, &dest, sigset.index())?;
        }

        Ok(())
    }

    fn write(file: &mut File, dest: &Dest, sigset_index: u32) -> Result<()> {
        writeln!(file, "{},{}", dest.to_base64()?, sigset_index)?;
        file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoind::bitcoincore_rpc::{Auth, RpcApi};
    use bitcoind::BitcoinD;

    #[tokio::test]
    async fn relayer_fetch_batch() {
        let bitcoind = BitcoinD::new(bitcoind::downloaded_exe_path().unwrap()).unwrap();

        let address = bitcoind.client.get_new_address(None, None).unwrap();
        bitcoind.client.generate_to_address(30, &address).unwrap();

        let bitcoind_url = bitcoind.rpc_url();
        let bitcoin_cookie_file = bitcoind.params.cookie_file.clone();
        let rpc_client =
            BitcoinRpcClient::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

        bitcoind.client.generate_to_address(25, &address).unwrap();
        let relayer = Relayer::new(rpc_client, "http://localhost:26657".to_string());

        let block_hash = bitcoind.client.get_block_hash(30).unwrap();
        let headers = relayer.get_header_batch(block_hash).unwrap();

        assert_eq!(headers.len(), 25);

        for (i, header) in headers.iter().enumerate() {
            let height = 31 + i;
            let btc_hash = bitcoind.client.get_block_hash(height as u64).unwrap();
            let btc_header = bitcoind.client.get_block_header(&btc_hash).unwrap();

            assert_eq!(header.block_hash(), btc_header.block_hash());
            assert_eq!(header.bits(), btc_header.bits);
            assert_eq!(header.target(), btc_header.target());
            assert_eq!(header.work(), btc_header.work());
        }
    }

    #[tokio::test]
    async fn relayer_seek_uneven_batch() {
        let bitcoind = BitcoinD::new(bitcoind::downloaded_exe_path().unwrap()).unwrap();

        let address = bitcoind.client.get_new_address(None, None).unwrap();
        bitcoind.client.generate_to_address(30, &address).unwrap();

        let bitcoind_url = bitcoind.rpc_url();
        let bitcoin_cookie_file = bitcoind.params.cookie_file.clone();
        let rpc_client =
            BitcoinRpcClient::new(&bitcoind_url, Auth::CookieFile(bitcoin_cookie_file)).unwrap();

        bitcoind.client.generate_to_address(7, &address).unwrap();
        let relayer = Relayer::new(rpc_client, "http://localhost:26657".to_string());
        let block_hash = bitcoind.client.get_block_hash(30).unwrap();
        let headers = relayer.get_header_batch(block_hash).unwrap();

        assert_eq!(headers.len(), 7);

        for (i, header) in headers.iter().enumerate() {
            let height = 31 + i;
            let btc_hash = bitcoind.client.get_block_hash(height as u64).unwrap();
            let btc_header = bitcoind.client.get_block_header(&btc_hash).unwrap();

            assert_eq!(header.block_hash(), btc_header.block_hash());
            assert_eq!(header.bits(), btc_header.bits);
            assert_eq!(header.target(), btc_header.target());
            assert_eq!(header.work(), btc_header.work());
        }
    }
}
