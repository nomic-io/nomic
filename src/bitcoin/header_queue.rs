use crate::bitcoin::adapter::Adapter;
use crate::error::{Error, Result};
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::consensus::Encodable;
use bitcoin::util::uint::Uint256;
use bitcoin::BlockHash;
use bitcoin::TxMerkleNode;
use orga::collections::Deque;
use orga::encoding::LengthVec;
use orga::migrate::MigrateFrom;
use orga::orga;
use orga::prelude::*;
use orga::Error as OrgaError;
use orga::Result as OrgaResult;

const MAX_LENGTH: u64 = 24_192; // ~6 months
const MAX_RELAY: u64 = 250;
const MAX_TIME_INCREASE: u32 = 2 * 60 * 60;
const RETARGET_INTERVAL: u32 = 2016;
const TARGET_SPACING: u32 = 10 * 60;
const TARGET_TIMESPAN: u32 = RETARGET_INTERVAL * TARGET_SPACING;
const MAX_TARGET: u32 = 0x1d00ffff;

/// A wrapper around a bitcoin::BlockHeader that implements the core orga
/// traits, and includes the block's height.
#[orga(skip(Default))]
#[derive(Clone, Debug, PartialEq)]
pub struct WrappedHeader {
    height: u32,
    header: Adapter<BlockHeader>,
}

impl WrappedHeader {
    /// Create a new WrappedHeader from an Adapter<bitcoin::BlockHeader> and a
    /// height.
    pub fn new(header: Adapter<BlockHeader>, height: u32) -> Self {
        WrappedHeader { height, header }
    }

    /// Create a new WrappedHeader from a bitcoin::BlockHeader and a height.
    pub fn from_header(header: &BlockHeader, height: u32) -> Self {
        WrappedHeader {
            height,
            header: Adapter::new(*header),
        }
    }

    /// The timestamp of the block header.
    pub fn time(&self) -> u32 {
        self.header.time
    }

    /// The target - the value the hash must be less than to be valid
    /// proof-of-work.
    pub fn target(&self) -> Uint256 {
        self.header.target()
    }

    /// The block hash.
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// The previous block hash.
    pub fn prev_blockhash(&self) -> BlockHash {
        self.header.prev_blockhash
    }

    /// The total estimated number of work (measured in hashes) represented by
    /// the block header's proof-of-work.
    pub fn work(&self) -> Uint256 {
        self.header.work()
    }

    /// The height of the block header.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The target, in compact form.
    pub fn bits(&self) -> u32 {
        self.header.bits
    }

    /// Converts a compact target to a Uint256.
    pub fn u256_from_compact(compact: u32) -> Uint256 {
        BlockHeader::u256_from_compact_target(compact)
    }

    /// Converts a Uint256 to a compact target.
    pub fn compact_target_from_u256(target: &Uint256) -> u32 {
        BlockHeader::compact_target_from_u256(target)
    }

    /// Converts a u32 to a Uint256.
    fn u32_to_u256(value: u32) -> Uint256 {
        let bytes = value.to_be_bytes();
        let mut buffer = [0u8; 32];
        buffer[32 - bytes.len()..].copy_from_slice(&bytes);

        Uint256::from_be_bytes(buffer)
    }

    /// Validates the proof-of-work of the block header, returning an error if
    /// the proof-of-work is invalid.
    fn validate_pow(&self, required_target: &Uint256) -> Result<BlockHash> {
        Ok(self.header.validate_pow(required_target)?)
    }
}

/// A list of WrappedHeaders.
// TODO: remove this in favor of e.g. `LengthVec<u8, WrappedHeader>`
#[derive(Debug)]
pub struct HeaderList(Vec<WrappedHeader>);

impl From<Vec<WrappedHeader>> for HeaderList {
    fn from(headers: Vec<WrappedHeader>) -> Self {
        HeaderList(headers)
    }
}

impl From<HeaderList> for Vec<WrappedHeader> {
    fn from(headers: HeaderList) -> Self {
        headers.0
    }
}

impl Encode for HeaderList {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> orga::encoding::Result<()> {
        // TODO: emit a more suitable error
        if self.0.len() >= 256 {
            return Err(orga::encoding::Error::UnexpectedByte(0));
        }
        dest.write_all(&[self.0.len() as u8])?;
        self.0.encode_into(dest)
    }

    fn encoding_length(&self) -> orga::encoding::Result<usize> {
        Ok(1 + self.0.encoding_length()?)
    }
}

impl Decode for HeaderList {
    fn decode<R: std::io::Read>(mut reader: R) -> orga::encoding::Result<Self> {
        let mut len = [0u8];
        reader.read_exact(&mut len[..])?;
        let len = len[0] as usize;

        let mut headers = Vec::with_capacity(len);
        for _ in 0..len {
            headers.push(WrappedHeader::decode(&mut reader)?);
        }
        Ok(HeaderList(headers))
    }
}

impl FromIterator<WrappedHeader> for HeaderList {
    fn from_iter<T: IntoIterator<Item = WrappedHeader>>(iter: T) -> Self {
        HeaderList(iter.into_iter().collect())
    }
}

impl Terminated for HeaderList {}

/// A `WrappedHeader`, along with a total estimated amount of work (measured in
/// hashes) done in the header and previous headers.
#[orga(skip(Default))]
#[derive(Clone, Debug)]
pub struct WorkHeader {
    pub chain_work: Adapter<Uint256>,
    pub header: WrappedHeader,
}

impl WorkHeader {
    /// Create a new `WorkHeader`` from a `WrappedHeader` and a `Uint256`.
    pub fn new(header: WrappedHeader, chain_work: Uint256) -> WorkHeader {
        WorkHeader {
            header,
            chain_work: Adapter::new(chain_work),
        }
    }

    /// The timestamp of the block header.
    pub fn time(&self) -> u32 {
        self.header.time()
    }

    /// The target - the value the hash must be less than to be valid
    /// proof-of-work.
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// The estimated amount of work (measured in hashes) done in the header,
    /// not including work done in any previous headers.
    pub fn work(&self) -> Uint256 {
        self.header.work()
    }

    /// The height of the block header.
    pub fn height(&self) -> u32 {
        self.header.height()
    }

    /// The Merkle root of the block header.
    pub fn merkle_root(&self) -> TxMerkleNode {
        self.header.header.merkle_root
    }
}

/// Configuration parameters for Bitcoin header processing.
// TODO: implement trait that returns constants for bitcoin::Network variants
#[orga(skip(Default))]
#[derive(Clone, Debug)]
pub struct Config {
    /// The maximum number of headers that can be stored in the header queue
    /// before pruning.
    pub max_length: u64,
    /// The maximum amount of time (in seconds) that can pass between the
    /// timestamp of the last header in the header queue and the timestamp of
    /// the next header to be added.
    pub max_time_increase: u32,
    /// The height of the trusted header.
    pub trusted_height: u32,
    /// The interval (in blocks) at which the difficulty target is adjusted.
    pub retarget_interval: u32,
    /// The target time interval (in seconds) between blocks.
    pub target_spacing: u32,
    /// The target amount of time (in seconds) that should pass between the
    /// timestamps of the first and last header in a retargeting period. This
    /// should be equivalent to `retarget_interval * target_spacing`.
    // TODO: derive from `retarget_interval` and `target_spacing`
    pub target_timespan: u32,
    /// The maximum target value.
    pub max_target: u32,
    /// Whether or not the header queue should retarget difficulty.
    pub retargeting: bool,
    /// Whether or not the header queue should drop back down to the minimum
    /// difficulty after a certain amount of time has passed (used in Bitcoin
    /// testnet).
    pub min_difficulty_blocks: bool,
    /// The trusted header (the header which populates the queue when it is
    /// newly created), as encoded bytes.
    pub encoded_trusted_header: LengthVec<u8, u8>,
}

impl Default for Config {
    fn default() -> Self {
        match super::NETWORK {
            bitcoin::Network::Bitcoin => Config::mainnet(),
            bitcoin::Network::Testnet => Config::testnet(),
            bitcoin::Network::Regtest => Config::regtest(),
            bitcoin::Network::Signet => Config::signet(),
        }
    }
}

impl Config {
    pub fn mainnet() -> Self {
        let checkpoint_json = include_str!("./checkpoint.json");
        let checkpoint: (u32, BlockHeader) = serde_json::from_str(checkpoint_json).unwrap();
        let (height, header) = checkpoint;

        let mut header_bytes = vec![];
        header.consensus_encode(&mut header_bytes).unwrap();

        Self {
            max_length: MAX_LENGTH,
            max_time_increase: MAX_TIME_INCREASE,
            trusted_height: height,
            retarget_interval: RETARGET_INTERVAL,
            target_spacing: TARGET_SPACING,
            target_timespan: TARGET_TIMESPAN,
            max_target: MAX_TARGET,
            encoded_trusted_header: header_bytes.try_into().unwrap(),
            retargeting: true,
            min_difficulty_blocks: false,
        }
    }

    pub fn testnet() -> Self {
        let checkpoint_json = include_str!("./testnet_checkpoint.json");
        let checkpoint: (u32, BlockHeader) = serde_json::from_str(checkpoint_json).unwrap();
        let (height, header) = checkpoint;

        let mut header_bytes = vec![];
        header.consensus_encode(&mut header_bytes).unwrap();

        Self {
            max_length: MAX_LENGTH,
            max_time_increase: MAX_TIME_INCREASE,
            retarget_interval: RETARGET_INTERVAL,
            target_spacing: TARGET_SPACING,
            target_timespan: TARGET_TIMESPAN,
            max_target: MAX_TARGET,
            trusted_height: height,
            encoded_trusted_header: header_bytes.try_into().unwrap(),
            retargeting: true,
            min_difficulty_blocks: true,
        }
    }

    pub fn signet() -> Self {
        let checkpoint_json = include_str!("./signet_checkpoint.json");
        let checkpoint: (u32, BlockHeader) = serde_json::from_str(checkpoint_json).unwrap();
        let (height, header) = checkpoint;

        let mut header_bytes = vec![];
        header.consensus_encode(&mut header_bytes).unwrap();

        Self {
            max_length: MAX_LENGTH,
            max_time_increase: MAX_TIME_INCREASE,
            retarget_interval: RETARGET_INTERVAL,
            target_spacing: TARGET_SPACING,
            target_timespan: TARGET_TIMESPAN,
            max_target: 0x1e0377ae,
            trusted_height: height,
            encoded_trusted_header: header_bytes.try_into().unwrap(),
            retargeting: true,
            min_difficulty_blocks: false,
        }
    }

    pub fn regtest() -> Self {
        let checkpoint_json = include_str!("./testnet_checkpoint.json");
        let checkpoint: (u32, BlockHeader) = serde_json::from_str(checkpoint_json).unwrap();
        let (height, header) = checkpoint;

        let mut header_bytes = vec![];
        header.consensus_encode(&mut header_bytes).unwrap();

        Self {
            max_length: MAX_LENGTH,
            max_time_increase: MAX_TIME_INCREASE,
            retarget_interval: RETARGET_INTERVAL,
            target_spacing: TARGET_SPACING,
            target_timespan: TARGET_TIMESPAN,
            max_target: MAX_TARGET,
            trusted_height: height,
            encoded_trusted_header: header_bytes.try_into().unwrap(),
            retargeting: false,
            min_difficulty_blocks: true,
        }
    }
}

/// A queue of Bitcoin block headers, along with the total estimated amount of
/// work (measured in hashes) done in the headers included in the queue.
///
/// The header queue is used to validate headers as they are received from the
/// Bitcoin network, ensuring each header is associated with a valid
/// proof-of-work and that the chain of headers is valid.
///
/// The queue is able to reorg if a new chain of headers is received that
/// contains more work than the current chain, however it can not process reorgs
/// that are deeper than the length of the queue (the length will be at the
/// configured pruning level based on the `max_length` config parameter).
#[orga(skip(Default), version = 1)]
pub struct HeaderQueue {
    pub(crate) deque: Deque<WorkHeader>,
    pub(crate) current_work: Adapter<Uint256>,
    pub(crate) config: Config,
}

impl MigrateFrom<HeaderQueueV0> for HeaderQueueV1 {
    fn migrate_from(_value: HeaderQueueV0) -> OrgaResult<Self> {
        unreachable!()
    }
}

impl Default for HeaderQueue {
    fn default() -> Self {
        let mut deque = Deque::default();
        let config = Config::default();
        let decoded_adapter: Adapter<BlockHeader> =
            Decode::decode(config.encoded_trusted_header.as_slice()).unwrap();
        let wrapped_header = WrappedHeader::new(decoded_adapter, config.trusted_height);
        let work_header = WorkHeader::new(wrapped_header.clone(), wrapped_header.work());
        let current_work = Adapter::new(work_header.work());
        deque.push_front(work_header).unwrap();
        Self {
            deque,
            current_work,
            config,
        }
    }
}

#[orga]
impl HeaderQueue {
    /// Verify and add a list of headers to the header queue.
    ///
    /// The headers must be consecutive and must bring the chain to a final
    /// state that has more work than the current chain.
    ///
    /// If the headers are valid, they will be added to the header queue. If the
    /// headers start from a height lower than the current height, the header
    /// queue will be reorged to the new chain.
    ///
    /// If the headers are invalid (e.g. by not including a valid proof-of-work,
    /// using a difficulty other than what was expected, using invalid
    /// timestamps, etc.), an error will be returned and the header queue will
    /// not be modified.
    #[call]
    pub fn add(&mut self, headers: HeaderList) -> Result<()> {
        super::exempt_from_fee()?;

        let headers: Vec<_> = headers.into();

        if headers.len() as u64 > MAX_RELAY {
            return Err(
                OrgaError::App("Exceeded maximum amount of relayed headers".to_string()).into(),
            );
        }

        self.add_into_iter(headers)
            .map_err(|err| OrgaError::App(err.to_string()).into())
    }

    /// Verify and add an iterator of headers to the header queue.
    ///
    /// The headers must be consecutive and must bring the chain to a final
    /// state that has more work than the current chain.
    ///
    /// If the headers are valid, they will be added to the header queue. If the
    /// headers start from a height lower than the current height, the header
    /// queue will be reorged to the new chain.
    ///
    /// If the headers are invalid (e.g. by not including a valid proof-of-work,
    /// using a difficulty other than what was expected, using invalid
    /// timestamps, etc.), an error will be returned and the header queue will
    /// not be modified.
    pub fn add_into_iter<T>(&mut self, headers: T) -> Result<()>
    where
        T: IntoIterator<Item = WrappedHeader>,
    {
        let headers: Vec<WrappedHeader> = headers.into_iter().collect();
        let current_height = self.height()?;

        let first = headers
            .first()
            .ok_or_else(|| Error::Header("Passed header list empty".into()))?;

        let mut removed_work = Uint256::default();
        if first.height <= current_height {
            let first_replaced = self
                .get_by_height(first.height)?
                .ok_or_else(|| Error::Header("Header not found".into()))?;

            if first_replaced.block_hash() == first.block_hash() {
                return Err(Error::Header("Provided redundant header.".into()));
            }

            removed_work = self.pop_back_to(first.height)?;
        }

        let added_work = self.verify_and_add_headers(&headers)?;
        if added_work <= removed_work {
            return Err(Error::Header(
                "New best chain must include more work than old best chain.".into(),
            ));
        }

        // Prune the header queue if it has grown too large.
        while self.len() > self.config.max_length {
            let header = match self.deque.pop_front()? {
                Some(inner) => inner,
                None => {
                    break;
                }
            };
            // TODO: do we really want to subtract work when pruning?
            let current_work = *self.current_work - header.work();
            self.current_work = Adapter::new(current_work);
        }

        Ok(())
    }

    /// Verify and add a list of headers to the header queue, returning the
    /// amount of additional estimated work added to the header queue.
    fn verify_and_add_headers(&mut self, headers: &[WrappedHeader]) -> Result<Uint256> {
        let first_height = headers
            .first()
            .ok_or_else(|| Error::Header("Passed header list is empty".into()))?
            .height;
        if first_height == 0 {
            return Err(Error::Header("Headers must start after height 0".into()));
        }

        let prev_header = [self
            .get_by_height(first_height - 1)?
            .ok_or_else(|| Error::Header("Headers not connect to chain".into()))?
            .header];

        let headers = prev_header.iter().chain(headers.iter()).zip(headers.iter());

        let mut work = Uint256::default();

        for (prev_header, header) in headers {
            if header.height() != prev_header.height() + 1 {
                return Err(Error::Header("Non-consecutive headers passed".into()));
            }

            if header.prev_blockhash() != prev_header.block_hash() {
                return Err(Error::Header(
                    "Passed header references incorrect previous block hash".into(),
                ));
            }

            if self.deque.len() >= 11 {
                self.validate_time(header)?;
            }

            let target = self.get_next_target(header, prev_header)?;
            header.validate_pow(&target)?;

            let header_work = header.work();
            work = work + header_work;

            let chain_work = *self.current_work + header_work;
            let work_header = WorkHeader::new(header.clone(), chain_work);
            self.deque.push_back(work_header)?;
            self.current_work = Adapter::new(chain_work);
        }

        Ok(work)
    }

    /// Calculate the expected next target based on the passed header and the
    /// previous header.
    fn get_next_target(
        &self,
        header: &WrappedHeader,
        previous_header: &WrappedHeader,
    ) -> Result<Uint256> {
        if header.height() % self.config.retarget_interval == 0 {
            let first_reorg_height = header.height() - self.config.retarget_interval;
            return self.calculate_next_target(previous_header, first_reorg_height);
        }

        if !self.config.min_difficulty_blocks {
            return Ok(previous_header.target());
        }

        if header.time() > previous_header.time() + self.config.target_spacing * 2 {
            return Ok(WrappedHeader::u256_from_compact(self.config.max_target));
        }

        let mut current_header_index = previous_header.height();
        let mut current_header = previous_header.to_owned();

        while current_header_index > 0
            && current_header_index % self.config.retarget_interval != 0
            && current_header.bits() == self.config.max_target
        {
            current_header_index -= 1;

            current_header = match self.get_by_height(current_header_index)? {
                Some(inner) => inner.header.clone(),
                None => {
                    return Err(Error::Header("No previous header exists".into()));
                }
            };
        }
        Ok(WrappedHeader::u256_from_compact(current_header.bits()))
    }

    /// Calculate the expected next target based on the passed header and the
    /// height of the previous retargeting header.
    fn calculate_next_target(
        &self,
        header: &WrappedHeader,
        first_reorg_height: u32,
    ) -> Result<Uint256> {
        if !self.config.retargeting {
            return Ok(WrappedHeader::u256_from_compact(header.bits()));
        }

        if header.height() < self.config.retarget_interval {
            return Err(Error::Header("Invalid trusted header. Trusted header have height which is a multiple of the retarget interval".into()));
        }

        let prev_retarget = match self.get_by_height(first_reorg_height)? {
            Some(inner) => inner.time(),
            None => {
                return Err(Error::Header(
                    "No previous retargeting header exists".into(),
                ));
            }
        };

        let mut timespan = header.time() - prev_retarget;

        if timespan < self.config.target_timespan / 4 {
            timespan = self.config.target_timespan / 4;
        }

        if timespan > self.config.target_timespan * 4 {
            timespan = self.config.target_timespan * 4;
        }

        let target_timespan = WrappedHeader::u32_to_u256(self.config.target_timespan);
        let timespan = WrappedHeader::u32_to_u256(timespan);

        let target = header.target() * timespan / target_timespan;
        let target_u32 = BlockHeader::compact_target_from_u256(&target);
        let target = WrappedHeader::u256_from_compact(target_u32);

        if target > WrappedHeader::u256_from_compact(self.config.max_target) {
            Ok(WrappedHeader::u256_from_compact(self.config.max_target))
        } else {
            Ok(target)
        }
    }

    /// Remove headers from the header queue until the height of the last header
    /// in the queue is equal to the passed height.
    fn pop_back_to(&mut self, height: u32) -> Result<Uint256> {
        let mut work = Uint256::default();

        while self.height()? >= height {
            let header = self
                .deque
                .pop_back()?
                .ok_or_else(|| Error::Header("Removed all headers".into()))?;

            work = work + header.work();
        }

        Ok(work)
    }

    /// Validate the timestamp of the passed header.
    fn validate_time(&self, current_header: &WrappedHeader) -> Result<()> {
        let mut prev_stamps: Vec<u32> = Vec::with_capacity(11);

        for i in 0..11 {
            let index = self.height()? - i;

            let current_item = match self.get_by_height(index)? {
                Some(inner) => inner,
                None => return Err(Error::Header("Deque does not contain any elements".into())),
            };
            prev_stamps.push(current_item.time());
        }

        prev_stamps.sort_unstable();

        let median_stamp = match prev_stamps.get(5) {
            Some(inner) => inner,
            None => {
                return Err(Error::Header("Median timestamp does not exist".into()));
            }
        };

        if current_header.time() <= *median_stamp {
            return Err(Error::Header("Header contains an invalid timestamp".into()));
        }

        // TODO: compare timestamps with max_time_increase over the current
        // clock time (not the previous header's time)
        // if max(current_header.time(), previous_header.time())
        //     - min(current_header.time(), previous_header.time())
        //     > self.config.max_time_increase
        // {
        //     return Err(Error::Header(
        //         "Timestamp is too far ahead of previous timestamp".into(),
        //     ));
        // }

        Ok(())
    }

    /// The height of the last header in the header queue.
    #[query]
    pub fn height(&self) -> Result<u32> {
        match self.deque.back()? {
            Some(inner) => Ok((*inner).height()),
            None => Ok(0),
        }
    }

    /// The hash of the last header in the header queue.
    #[query]
    pub fn hash(&self) -> Result<Vec<u8>> {
        match self.deque.back()? {
            Some(inner) => Ok((*inner).block_hash().to_vec()),
            None => Err(Error::Header("HeaderQueue is empty".into())),
        }
    }

    /// The number of headers in the header queue.
    // TODO: remove this attribute, not sure why clippy is complaining when is_empty is defined
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.deque.len()
    }

    /// Whether or not the header queue is empty.
    ///
    /// This will always return `false`, as the header queue is initialized with
    /// a trusted header.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get a header from the header queue by its height.
    ///
    /// If the header queue does not contain a header at the passed height,
    /// `None` will be returned.
    ///
    /// If the passed height is less than the initial height of the header
    /// queue, an error will be returned.
    #[query]
    pub fn get_by_height(&self, height: u32) -> Result<Option<WorkHeader>> {
        let initial_height = match self.deque.front()? {
            Some(inner) => inner.height(),
            None => return Err(Error::Header("Queue does not contain any headers".into())),
        };

        if height < initial_height {
            // TODO: error message is wrong
            // TODO: shouldn't this just return None?
            return Err(Error::Header(
                "Passed index is greater than initial height. Referenced header does not exist on the Header Queue".into(),
            ));
        }

        match self.deque.get((height - initial_height) as u64)? {
            Some(inner) => Ok(Some((*inner).clone())),
            None => Ok(None),
        }
    }

    /// The height of the configured trusted header.
    #[query]
    pub fn trusted_height(&self) -> u32 {
        self.config.trusted_height
    }

    /// Clears the header queue and configures it with the passed config,
    /// adding the trusted header to the queue.
    pub fn configure(&mut self, config: Config) -> OrgaResult<()> {
        if !self.deque.is_empty() {
            while !self.deque.is_empty() {
                self.deque.pop_back()?;
            }
        }

        let decoded_adapter: Adapter<BlockHeader> =
            Decode::decode(config.encoded_trusted_header.as_slice())?;
        let wrapped_header = WrappedHeader::new(decoded_adapter, config.trusted_height);
        let work_header = WorkHeader::new(wrapped_header.clone(), wrapped_header.work());

        self.current_work = Adapter::new(wrapped_header.work());
        self.deque.pop_back()?;

        self.deque.push_front(work_header)?;

        self.config = config;

        Ok(())
    }

    /// The network the header queue is configured for.
    pub fn network(&self) -> bitcoin::Network {
        // TODO: should be dynamic, from config
        super::NETWORK
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::hash_types::TxMerkleNode;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::sha256d::Hash;
    use bitcoin::BlockHash;
    use chrono::{TimeZone, Utc};
    use orga::context::Context;
    use orga::plugins::Paid;
    use serial_test::serial;

    #[test]
    fn primitive_adapter_encode_decode() {
        let stamp = Utc.with_ymd_and_hms(2009, 1, 10, 17, 39, 13).unwrap();
        //Bitcoin block 42
        let header = BlockHeader {
            version: 0x1,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_hex("00000000ad2b48c7032b6d7d4f2e19e54d79b1c159f5599056492f2cd7bb528b")
                    .unwrap(),
            ),
            merkle_root: "27c4d937dca276fb2b61e579902e8a876fd5b5abc17590410ced02d5a9f8e483"
                .parse()
                .unwrap(),
            time: stamp.timestamp() as u32,
            bits: 486_604_799,
            nonce: 3_600_650_283,
        };

        let adapter = Adapter::new(header);
        let encoded_adapter = adapter.encode().unwrap();

        let decoded_adapter: Adapter<BlockHeader> =
            Decode::decode(encoded_adapter.as_slice()).unwrap();

        assert_eq!(*decoded_adapter, header);
    }

    #[test]
    #[serial]
    fn add_multiple() {
        let ctx = Paid::default();
        Context::add(ctx);

        let stamp = Utc.with_ymd_and_hms(2009, 1, 10, 17, 44, 37).unwrap();

        let header_43 = BlockHeader {
            version: 0x1,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_hex("00000000314e90489514c787d615cea50003af2023796ccdd085b6bcc1fa28f5")
                    .unwrap(),
            ),
            merkle_root: TxMerkleNode::from_hash(
                Hash::from_hex("2f5c03ce19e9a855ac93087a1b68fe6592bcf4bd7cbb9c1ef264d886a785894e")
                    .unwrap(),
            ),
            time: stamp.timestamp() as u32,
            bits: 486_604_799,
            nonce: 2_093_702_200,
        };

        let stamp = Utc.with_ymd_and_hms(2009, 1, 10, 17, 59, 21).unwrap();

        let header_44 = BlockHeader {
            version: 0x1,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_hex("00000000ac21f2862aaab177fd3c5c8b395de842f84d88c9cf3420b2d393e550")
                    .unwrap(),
            ),
            merkle_root: TxMerkleNode::from_hash(
                Hash::from_hex("439aee1e1aa6923ad61c1990459f88de1faa3e18b4ee125f99b94b82e1e0af5f")
                    .unwrap(),
            ),
            time: stamp.timestamp() as u32,
            bits: 486_604_799,
            nonce: 429_798_192,
        };

        let stamp = Utc.with_ymd_and_hms(2009, 1, 10, 18, 11, 8).unwrap();

        let header_45 = BlockHeader {
            version: 0x1,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_hex("000000002978eecde8d020f7f057083bc990002fff495121d7dc1c26d00c00f8")
                    .unwrap(),
            ),
            merkle_root: TxMerkleNode::from_hash(
                Hash::from_hex("f69778085f1e78a1ea1cfcfe3b61ffb5c99870f5ae382e41ec43cf165d66a6d9")
                    .unwrap(),
            ),
            time: stamp.timestamp() as u32,
            bits: 486_604_799,
            nonce: 2_771_238_433,
        };

        let stamp = Utc.with_ymd_and_hms(2009, 1, 10, 18, 23, 13).unwrap();

        let header_46 = BlockHeader {
            version: 0x1,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_hex("000000009189006e461d2f4037a819d00217412ac01900ddbf09461100b836bb")
                    .unwrap(),
            ),
            merkle_root: TxMerkleNode::from_hash(
                Hash::from_hex("ddd4d06365155ab4caaaee552fb3d8643207bd06efe14f920698a6dd4eb22ffa")
                    .unwrap(),
            ),
            time: stamp.timestamp() as u32,
            bits: 486_604_799,
            nonce: 1_626_117_377,
        };

        let stamp = Utc.with_ymd_and_hms(2009, 1, 10, 18, 41, 28).unwrap();

        let header_47 = BlockHeader {
            version: 0x1,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_hex("0000000002d5f429a2e3a9d9f82b777469696deb64038803c87833aa8ee9c08e")
                    .unwrap(),
            ),
            merkle_root: TxMerkleNode::from_hash(
                Hash::from_hex("d17b9c9c609309049dfb9005edd7011f02d7875ca7dab6effddf4648bb70eff6")
                    .unwrap(),
            ),
            time: stamp.timestamp() as u32,
            bits: 486_604_799,
            nonce: 2_957_174_816,
        };

        let stamp = Utc.with_ymd_and_hms(2009, 1, 10, 18, 45, 40).unwrap();

        let header_48 = BlockHeader {
            version: 0x1,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_hex("000000001a5c4531f86aa874e711e1882038336e2610f70ce750cdd690c57a81")
                    .unwrap(),
            ),
            merkle_root: TxMerkleNode::from_hash(
                Hash::from_hex("32edede0b7d0c37340a665de057f418df634452f6bb80dcb8a5ff0aeddf1158a")
                    .unwrap(),
            ),
            time: stamp.timestamp() as u32,
            bits: 486_604_799,
            nonce: 3_759_171_867,
        };

        let stamp = Utc.with_ymd_and_hms(2009, 1, 10, 18, 56, 42).unwrap();

        let header_49 = BlockHeader {
            version: 0x1,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_hex("0000000088960278f4060b8747027b2aac0eb443aedbb1b75d1a72cf71826e89")
                    .unwrap(),
            ),
            merkle_root: TxMerkleNode::from_hash(
                Hash::from_hex("194c9715279d8626bc66f2b6552f2ae67b3df3a00b88553245b12bffffad5b59")
                    .unwrap(),
            ),
            time: stamp.timestamp() as u32,
            bits: 486_604_799,
            nonce: 3_014_810_412,
        };

        let header_list = vec![
            WrappedHeader::new(Adapter::new(header_43), 43),
            WrappedHeader::new(Adapter::new(header_44), 44),
            WrappedHeader::new(Adapter::new(header_45), 45),
            WrappedHeader::new(Adapter::new(header_46), 46),
            WrappedHeader::new(Adapter::new(header_47), 47),
            WrappedHeader::new(Adapter::new(header_48), 48),
            WrappedHeader::new(Adapter::new(header_49), 49),
        ];

        let test_config = Config {
            max_length: 2000,
            max_time_increase: 8 * 60 * 60,
            trusted_height: 42,
            retarget_interval: 2016,
            target_spacing: 10 * 60,
            target_timespan: 2016 * (10 * 60),
            max_target: 0x1d00ffff,
            retargeting: true,
            min_difficulty_blocks: false,
            encoded_trusted_header: vec![
                1, 0, 0, 0, 139, 82, 187, 215, 44, 47, 73, 86, 144, 89, 245, 89, 193, 177, 121, 77,
                229, 25, 46, 79, 125, 109, 43, 3, 199, 72, 43, 173, 0, 0, 0, 0, 131, 228, 248, 169,
                213, 2, 237, 12, 65, 144, 117, 193, 171, 181, 213, 111, 135, 138, 46, 144, 121,
                229, 97, 43, 251, 118, 162, 220, 55, 217, 196, 39, 65, 221, 104, 73, 255, 255, 0,
                29, 43, 144, 157, 214,
            ]
            .try_into()
            .unwrap(),
        };
        let mut q = HeaderQueue::default();
        q.configure(test_config).unwrap();
        q.add(header_list.into()).unwrap();
    }

    #[test]
    fn add_into_iterator() {
        let stamp = Utc.with_ymd_and_hms(2009, 1, 10, 17, 44, 37).unwrap();

        let header = BlockHeader {
            version: 0x1,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_hex("00000000314e90489514c787d615cea50003af2023796ccdd085b6bcc1fa28f5")
                    .unwrap(),
            ),
            merkle_root: TxMerkleNode::from_hash(
                Hash::from_hex("2f5c03ce19e9a855ac93087a1b68fe6592bcf4bd7cbb9c1ef264d886a785894e")
                    .unwrap(),
            ),
            time: stamp.timestamp() as u32,
            bits: 486_604_799,
            nonce: 2_093_702_200,
        };

        let test_config = Config {
            max_length: 2000,
            max_time_increase: 8 * 60 * 60,
            trusted_height: 42,
            retarget_interval: 2016,
            target_spacing: 10 * 60,
            target_timespan: 2016 * (10 * 60),
            max_target: 0x1d00ffff,
            retargeting: true,
            min_difficulty_blocks: false,
            encoded_trusted_header: vec![
                1, 0, 0, 0, 139, 82, 187, 215, 44, 47, 73, 86, 144, 89, 245, 89, 193, 177, 121, 77,
                229, 25, 46, 79, 125, 109, 43, 3, 199, 72, 43, 173, 0, 0, 0, 0, 131, 228, 248, 169,
                213, 2, 237, 12, 65, 144, 117, 193, 171, 181, 213, 111, 135, 138, 46, 144, 121,
                229, 97, 43, 251, 118, 162, 220, 55, 217, 196, 39, 65, 221, 104, 73, 255, 255, 0,
                29, 43, 144, 157, 214,
            ]
            .try_into()
            .unwrap(),
        };

        let adapter = Adapter::new(header);
        let header_list = [WrappedHeader::new(adapter, 43)];
        let mut q = HeaderQueue::default();
        q.configure(test_config).unwrap();
        q.add_into_iter(header_list).unwrap();
    }

    #[test]
    #[should_panic(expected = "Bitcoin(BlockBadTarget)")]
    fn add_wrong_bits_non_retarget() {
        let stamp = Utc.with_ymd_and_hms(2009, 1, 10, 17, 44, 37).unwrap();

        let header = BlockHeader {
            version: 0x1,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_hex("00000000314e90489514c787d615cea50003af2023796ccdd085b6bcc1fa28f5")
                    .unwrap(),
            ),
            merkle_root: TxMerkleNode::from_hash(
                Hash::from_hex("2f5c03ce19e9a855ac93087a1b68fe6592bcf4bd7cbb9c1ef264d886a785894e")
                    .unwrap(),
            ),
            time: stamp.timestamp() as u32,
            bits: 486_604_420,
            nonce: 2_093_702_200,
        };

        let test_config = Config {
            max_length: 2000,
            max_time_increase: 8 * 60 * 60,
            trusted_height: 42,
            retarget_interval: 2016,
            target_spacing: 10 * 60,
            target_timespan: 2016 * (10 * 60),
            max_target: 0x1d00ffff,
            retargeting: true,
            min_difficulty_blocks: false,
            encoded_trusted_header: vec![
                1, 0, 0, 0, 139, 82, 187, 215, 44, 47, 73, 86, 144, 89, 245, 89, 193, 177, 121, 77,
                229, 25, 46, 79, 125, 109, 43, 3, 199, 72, 43, 173, 0, 0, 0, 0, 131, 228, 248, 169,
                213, 2, 237, 12, 65, 144, 117, 193, 171, 181, 213, 111, 135, 138, 46, 144, 121,
                229, 97, 43, 251, 118, 162, 220, 55, 217, 196, 39, 65, 221, 104, 73, 255, 255, 0,
                29, 43, 144, 157, 214,
            ]
            .try_into()
            .unwrap(),
        };

        let adapter = Adapter::new(header);
        let header_list = [WrappedHeader::new(adapter, 43)];
        let mut q = HeaderQueue::default();
        q.configure(test_config).unwrap();
        q.add_into_iter(header_list).unwrap();
    }
}
