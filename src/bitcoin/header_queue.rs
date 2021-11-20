use crate::bitcoin::adapter::Adapter;
use crate::error::{Error, Result};
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::util::uint::Uint256;
use bitcoin::BlockHash;
use orga::collections::Deque;
use orga::prelude::*;
use orga::state::State;
use orga::store::Store;
use orga::Result as OrgaResult;
use std::cmp::{max, min};

const MAX_LENGTH: u64 = 2000;
const MAX_TIME_INCREASE: u32 = 8 * 60 * 60;
const TRUSTED_HEIGHT: u32 = 42;
const RETARGET_INTERVAL: u32 = 2016;
const TARGET_SPACING: u32 = 10 * 60;
const TARGET_TIMESPAN: u32 = RETARGET_INTERVAL * TARGET_SPACING;
const MAX_TARGET: u32 = 0x1d00ffff;
const ENCODED_TRUSTED_HEADER: [u8; 80] = [
    1, 0, 0, 0, 139, 82, 187, 215, 44, 47, 73, 86, 144, 89, 245, 89, 193, 177, 121, 77, 229, 25,
    46, 79, 125, 109, 43, 3, 199, 72, 43, 173, 0, 0, 0, 0, 131, 228, 248, 169, 213, 2, 237, 12, 65,
    144, 117, 193, 171, 181, 213, 111, 135, 138, 46, 144, 121, 229, 97, 43, 251, 118, 162, 220, 55,
    217, 196, 39, 65, 221, 104, 73, 255, 255, 0, 29, 43, 144, 157, 214,
];

#[derive(Clone, Debug, PartialEq, State)]
pub struct WrappedHeader {
    height: u32,
    header: Adapter<BlockHeader>,
}

impl WrappedHeader {
    fn new(header: Adapter<BlockHeader>, height: u32) -> Self {
        WrappedHeader { height, header }
    }

    fn time(&self) -> u32 {
        self.header.time
    }

    fn target(&self) -> Uint256 {
        self.header.target()
    }

    fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    fn prev_blockhash(&self) -> BlockHash {
        self.header.prev_blockhash
    }

    fn work(&self) -> Uint256 {
        self.header.work()
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn bits(&self) -> u32 {
        self.header.bits
    }

    fn u256_from_compact(compact: u32) -> Uint256 {
        BlockHeader::u256_from_compact_target(compact)
    }

    fn validate_pow(&self, required_target: &Uint256) -> Result<BlockHash> {
        Ok(self.header.validate_pow(&required_target)?)
    }
}

#[derive(Clone, Debug, State)]
pub struct WorkHeader {
    chain_work: Adapter<Uint256>,
    header: WrappedHeader,
}

impl WorkHeader {
    fn new(header: WrappedHeader, chain_work: Uint256) -> WorkHeader {
        WorkHeader {
            header,
            chain_work: Adapter::new(chain_work),
        }
    }

    fn time(&self) -> u32 {
        self.header.time()
    }

    fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    fn work(&self) -> Uint256 {
        self.header.work()
    }

    fn height(&self) -> u32 {
        self.header.height()
    }
}

pub struct HeaderQueue {
    deque: Deque<WorkHeader>,
    current_work: Adapter<Uint256>,
}

impl State for HeaderQueue {
    type Encoding = (
        <Deque<WorkHeader> as State>::Encoding,
        <Adapter<Uint256> as State>::Encoding,
    );

    fn create(store: Store, data: Self::Encoding) -> OrgaResult<Self> {
        let mut queue = Self {
            deque: State::create(store.sub(&[0]), data.0)?,
            current_work: State::create(store.sub(&[1]), data.1)?,
        };

        if queue.height().unwrap() == 0 {
            let decoded_adapter: Adapter<BlockHeader> =
                Decode::decode(ENCODED_TRUSTED_HEADER.as_slice())?;
            let wrapped_header = WrappedHeader::new(decoded_adapter, TRUSTED_HEIGHT);
            let work_header = WorkHeader::new(wrapped_header.clone(), wrapped_header.work());
            queue.current_work = Adapter::new(work_header.work());
            queue.deque.push_front(work_header.into())?;
        }

        Ok(queue)
    }

    fn flush(self) -> OrgaResult<Self::Encoding> {
        Ok((
            State::<DefaultBackingStore>::flush(self.deque)?,
            State::<DefaultBackingStore>::flush(self.current_work)?,
        ))
    }
}

impl From<HeaderQueue> for <HeaderQueue as State>::Encoding {
    fn from(value: HeaderQueue) -> Self {
        (value.deque.into(), value.current_work)
    }
}

impl HeaderQueue {
    pub fn add<T>(&mut self, headers: T) -> Result<()>
    where
        T: IntoIterator<Item = WrappedHeader>,
    {
        let headers: Vec<WrappedHeader> = headers.into_iter().collect();
        let current_height = self.height()?;

        let first = match headers.first() {
            Some(inner) => inner.clone(),
            None => {
                return Err(Error::Header("Passed header list empty".into()));
            }
        };

        let last = match headers.last() {
            Some(inner) => inner.clone(),
            None => {
                return Err(Error::Header("Passed header list empty".into()));
            }
        };

        if first.height > current_height + 1 {
            return Err(Error::Header(
                "Start of headers is ahead of chain tip.".into(),
            ));
        }

        if last.height <= current_height {
            return Err(Error::Header("New tip is behind current tip.".into()));
        }

        if first.height <= current_height {
            self.reorg(headers.clone(), &first.height, &last.height)?;
        }

        self.verify_headers(&headers)?;

        while self.height()? as u64 > MAX_LENGTH {
            let header = match self.deque.pop_front()? {
                Some(inner) => inner,
                None => {
                    break;
                }
            };
            let current_work = *self.current_work - header.work();
            self.current_work = Adapter::new(current_work);
        }

        Ok(())
    }

    fn verify_headers(&mut self, headers: &[WrappedHeader]) -> Result<()> {
        let deque_last = match self.get_by_height(self.height()?)? {
            Some(inner) => vec![inner.header],
            None => return Err(Error::Header("No previous header exists on deque".into())),
        };

        let headers: Vec<&WrappedHeader> = deque_last.iter().chain(headers.iter()).collect();

        for (i, header) in headers[1..].iter().enumerate() {
            let header = *header;
            let previous_header = match headers.get(i) {
                Some(inner) => inner,
                None => {
                    return Err(Error::Header("No previous header exists".into()));
                }
            };

            if header.height() != previous_header.height() + 1 {
                return Err(Error::Header("Non-consecutive headers passed".into()));
            }

            if header.prev_blockhash() != previous_header.block_hash() {
                return Err(Error::Header(
                    "Passed header references incorrect previous block hash".into(),
                ));
            }

            if self.deque.len() >= 6 {
                self.validate_time(header, previous_header)?;
            }

            let target = self.calculate_target(header, previous_header)?;
            header.validate_pow(&target)?;

            let chain_work = *self.current_work + header.work();
            let work_header = WorkHeader::new(header.clone(), chain_work);
            self.deque.push_back(work_header.into())?;
            let current_work = *self.current_work + header.work();
            self.current_work = Adapter::new(current_work);
        }

        Ok(())
    }

    fn calculate_target(
        &self,
        header: &WrappedHeader,
        previous_header: &WrappedHeader,
    ) -> Result<Uint256> {
        let ret_span;

        if header.height() % 2016 == 0 {
            let prev_retarget = match self.get_by_height(header.height() - 2016)? {
                Some(inner) => inner.time(),
                None => {
                    return Err(Error::Header(
                        "No previous retargeting header exists".into(),
                    ));
                }
            };

            let prev_retarget_256 = WrappedHeader::u256_from_compact(prev_retarget);

            let mut timespan = WrappedHeader::u256_from_compact(header.time() - prev_retarget);
            let target_timespan = WrappedHeader::u256_from_compact(TARGET_TIMESPAN);
            let four_256 = WrappedHeader::u256_from_compact(4);

            if timespan > target_timespan * four_256 {
                timespan = target_timespan * four_256;
            }

            if timespan < target_timespan / four_256 {
                timespan = target_timespan / four_256;
            }

            ret_span = prev_retarget_256 * timespan / target_timespan;
        } else if header.bits() != previous_header.bits() {
            return Err(Error::Header(
                "Passed header references incorrect previous bits".into(),
            ));
        } else {
            ret_span = header.target();
        }

        if ret_span > WrappedHeader::u256_from_compact(MAX_TARGET) {
            Ok(WrappedHeader::u256_from_compact(MAX_TARGET))
        } else {
            Ok(ret_span)
        }
    }

    fn reorg(
        &mut self,
        headers: Vec<WrappedHeader>,
        first_height: &u32,
        last_height: &u32,
    ) -> Result<()> {
        let first_deque_height = match self.deque.front()? {
            Some(inner) => inner.header.height(),
            None => {
                return Err(Error::Header("No previous header exists on deque".into()));
            }
        };
        let reorg_index = first_height - 1 - first_deque_height;

        let first_removal_hash = match self.deque.get((reorg_index + 1) as u64)? {
            Some(inner) => inner.block_hash(),
            None => {
                return Err(Error::Header(
                    "No header exists after calculated reorg index".into(),
                ));
            }
        };

        let first_passed_hash = match headers.get(0) {
            Some(inner) => inner.block_hash(),
            None => {
                return Err(Error::Header(
                    "Passed header list does not contain any headers. Could not calculate block hash".into()
                ));
            }
        };

        if first_removal_hash == first_passed_hash {
            return Err(Error::Header(
                "Reorg rebroadcasting existing longest work chain".into(),
            ));
        }

        let passed_headers_work = headers
            .iter()
            .fold(Uint256::default(), |work, header| work + header.work());

        let prev_chain_work = match self.deque.get(reorg_index as u64)? {
            Some(inner) => inner.chain_work.clone(),
            None => {
                return Err(Error::Header(
                    "No header exists at calculated reorg index".into(),
                ))
            }
        };

        if *prev_chain_work + passed_headers_work > *self.current_work {
            let last_index = last_height - first_deque_height;
            for _ in 0..(last_index - reorg_index) {
                let header_work = match self.deque.pop_back()? {
                    Some(inner) => *inner.chain_work,
                    None => {
                        break;
                    }
                };

                let current_work = *self.current_work - header_work;
                self.current_work = Adapter::new(current_work);
            }
        }

        Ok(())
    }

    fn validate_time(
        &self,
        current_header: &WrappedHeader,
        previous_header: &WrappedHeader,
    ) -> Result<()> {
        let mut prev_stamps: Vec<u32> = Vec::with_capacity(11);
        for i in 0..=11 {
            let last_index = self.length() - 1;
            let mut index = 0;

            if last_index >= i {
                index = last_index - i;
            }

            let current_item = match self.deque.get(index)? {
                Some(inner) => inner,
                None => return Err(Error::Header("Deque does not contain any elements".into())),
            };
            prev_stamps.push(current_item.time());
        }

        prev_stamps.sort_unstable();

        let median_stamp = match prev_stamps.get(6) {
            Some(inner) => inner,
            None => {
                return Err(Error::Header("Median timestamp does not exist".into()));
            }
        };

        if current_header.time() <= *median_stamp {
            return Err(Error::Header("Header contains an invalid timestamp".into()));
        }

        if max(current_header.time(), previous_header.time())
            - min(current_header.time(), previous_header.time())
            > MAX_TIME_INCREASE
        {
            return Err(Error::Header(
                "Timestamp is too far ahead of previous timestamp".into(),
            ));
        }

        Ok(())
    }

    fn length(&self) -> u64 {
        self.deque.len()
    }

    fn height(&self) -> Result<u32> {
        match self.deque.back()? {
            Some(inner) => Ok((*inner).height()),
            None => Ok(0),
        }
    }

    pub fn get_by_height(&self, height: u32) -> Result<Option<WorkHeader>> {
        let initial_height = match self.deque.front()? {
            Some(inner) => inner.height(),
            None => return Err(Error::Header("Queue does not contain any headers".into())),
        };

        match self.deque.get((height - initial_height) as u64)? {
            Some(inner) => Ok(Some((*inner).clone())),
            None => Ok(None),
        }
    }

    #[cfg(test)]
    fn test_create(
        store: Store,
        data: <Self as State>::Encoding,
        trusted_header: [u8; 80],
        trusted_height: u32,
    ) -> OrgaResult<Self> {
        let mut queue = Self {
            deque: State::create(store.sub(&[0]), data.0)?,
            current_work: State::create(store.sub(&[1]), data.1)?,
        };
        let decoded_adapter: Adapter<BlockHeader> = Decode::decode(trusted_header.as_slice())?;
        let wrapped_header = WrappedHeader::new(decoded_adapter, trusted_height);
        let work_header = WorkHeader::new(wrapped_header.clone(), wrapped_header.work());

        queue.current_work = Adapter::new(wrapped_header.work());
        queue.deque.push_front(work_header.into())?;

        Ok(queue)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::hash_types::TxMerkleNode;
    use bitcoin::BlockHash;
    use bitcoin_hashes::hex::FromHex;
    use bitcoin_hashes::sha256d::Hash;
    use chrono::{TimeZone, Utc};

    #[test]
    fn create() {
        let store = Store::new(Shared::new(MapStore::new()));
        let q = HeaderQueue::create(store, Default::default()).unwrap();

        let decoded_adapter: Adapter<BlockHeader> =
            Decode::decode(ENCODED_TRUSTED_HEADER.as_slice()).unwrap();
        let wrapped_header = WrappedHeader::new(decoded_adapter, TRUSTED_HEIGHT);

        assert_eq!(q.height().unwrap(), wrapped_header.height());
        assert_eq!(*q.current_work, wrapped_header.work());
    }

    #[test]
    fn primitive_adapter_encode_decode() {
        let stamp = Utc.ymd(2009, 1, 10).and_hms(17, 39, 13);
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
    fn add_multiple() {
        let stamp = Utc.ymd(2009, 1, 10).and_hms(17, 44, 37);

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

        let stamp = Utc.ymd(2009, 1, 10).and_hms(17, 59, 21);

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

        let stamp = Utc.ymd(2009, 1, 10).and_hms(18, 11, 8);

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

        let stamp = Utc.ymd(2009, 1, 10).and_hms(18, 23, 13);

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

        let stamp = Utc.ymd(2009, 1, 10).and_hms(18, 41, 28);

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

        let stamp = Utc.ymd(2009, 1, 10).and_hms(18, 45, 40);

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

        let stamp = Utc.ymd(2009, 1, 10).and_hms(18, 56, 42);

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

        let header_list = [
            WrappedHeader::new(Adapter::new(header_43), 43),
            WrappedHeader::new(Adapter::new(header_44), 44),
            WrappedHeader::new(Adapter::new(header_45), 45),
            WrappedHeader::new(Adapter::new(header_46), 46),
            WrappedHeader::new(Adapter::new(header_47), 47),
            WrappedHeader::new(Adapter::new(header_48), 48),
            WrappedHeader::new(Adapter::new(header_49), 49),
        ];
        // Bitcoin block 42
        let trusted_header = [
            1, 0, 0, 0, 139, 82, 187, 215, 44, 47, 73, 86, 144, 89, 245, 89, 193, 177, 121, 77,
            229, 25, 46, 79, 125, 109, 43, 3, 199, 72, 43, 173, 0, 0, 0, 0, 131, 228, 248, 169,
            213, 2, 237, 12, 65, 144, 117, 193, 171, 181, 213, 111, 135, 138, 46, 144, 121, 229,
            97, 43, 251, 118, 162, 220, 55, 217, 196, 39, 65, 221, 104, 73, 255, 255, 0, 29, 43,
            144, 157, 214,
        ];

        let store = Store::new(Shared::new(MapStore::new()));
        let mut q =
            HeaderQueue::test_create(store, Default::default(), trusted_header, 42).unwrap();
        q.add(header_list).unwrap();
    }

    #[test]
    fn add_into_iterator() {
        let stamp = Utc.ymd(2009, 1, 10).and_hms(17, 44, 37);

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

        let adapter = Adapter::new(header);
        let header_list = [WrappedHeader::new(adapter, 43)];
        let store = Store::new(Shared::new(MapStore::new()));
        let mut q = HeaderQueue::create(store, Default::default()).unwrap();
        q.add(header_list).unwrap();

        let adapter = Adapter::new(header);
        let header_list = vec![WrappedHeader::new(adapter, 43)];
        let store = Store::new(Shared::new(MapStore::new()));
        let mut q = HeaderQueue::create(store, Default::default()).unwrap();
        q.add(header_list).unwrap();
    }

    #[test]
    #[should_panic(expected = "Passed header references incorrect previous bits")]
    fn add_wrong_bits_non_retarget() {
        let stamp = Utc.ymd(2009, 1, 10).and_hms(17, 44, 37);

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

        let adapter = Adapter::new(header);
        let header_list = [WrappedHeader::new(adapter, 43)];
        let store = Store::new(Shared::new(MapStore::new()));
        let mut q = HeaderQueue::create(store, Default::default()).unwrap();
        q.add(header_list).unwrap();
    }
}
