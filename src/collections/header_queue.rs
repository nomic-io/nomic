use crate::error::{Error, Result};
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::consensus::{Decodable, Encodable};
use orga::collections::Deque;
use orga::encoding::Result as EncodingResult;
use orga::prelude::*;
use orga::state::State;
use orga::store::Store;
use std::io::{Read, Write};
use std::ops::{Add, AddAssign, Deref, DerefMut, Sub, SubAssign};

const MAX_LENGTH: u64 = 2000;

#[derive(Clone, Debug, PartialEq)]
pub struct HeaderAdapter(BlockHeader);

//need to make sure that this doesn't cause any issues after the state is reset from the store
impl Default for HeaderAdapter {
    fn default() -> Self {
        HeaderAdapter(BlockHeader {
            version: Default::default(),
            prev_blockhash: Default::default(),
            merkle_root: Default::default(),
            time: Default::default(),
            bits: Default::default(),
            nonce: Default::default(),
        })
    }
}

impl State for HeaderAdapter {
    type Encoding = Self;

    fn create(_: Store, data: Self::Encoding) -> orga::Result<Self> {
        Ok(data)
    }

    fn flush(self) -> orga::Result<Self::Encoding> {
        Ok(self)
    }
}

impl Deref for HeaderAdapter {
    type Target = BlockHeader;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HeaderAdapter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for HeaderAdapter {
    fn encode(&self) -> EncodingResult<Vec<u8>> {
        let mut dest: Vec<u8> = Vec::new();
        self.encode_into(&mut dest)?;
        Ok(dest)
    }

    fn encode_into<W: Write>(&self, dest: &mut W) -> EncodingResult<()> {
        match self.0.consensus_encode(dest) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn encoding_length(&self) -> EncodingResult<usize> {
        let mut _dest: Vec<u8> = Vec::new();
        match self.0.consensus_encode(_dest) {
            Ok(inner) => Ok(inner),
            Err(e) => Err(e.into()),
        }
    }
}

impl Decode for HeaderAdapter {
    fn decode<R: Read>(input: R) -> EncodingResult<Self> {
        let decoded_bytes = Decodable::consensus_decode(input);
        match decoded_bytes {
            Ok(inner) => Ok(Self(inner)),
            Err(_) => {
                let std_e = std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to decode bitcoin primitive",
                );
                Err(std_e.into())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct Uint256(bitcoin::util::uint::Uint256);

impl Terminated for Uint256 {}

impl From<bitcoin::util::uint::Uint256> for Uint256 {
    fn from(value: bitcoin::util::uint::Uint256) -> Self {
        Uint256(value)
    }
}

impl Add for Uint256 {
    type Output = Uint256;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for Uint256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = Self(self.0 + rhs.0);
    }
}

impl Sub for Uint256 {
    type Output = Uint256;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Mul for Uint256 {
    type Output = Uint256;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Div for Uint256 {
    type Output = Uint256;

    fn div(self, rhs: Self) -> Self::Output {
        Self(self.0 / rhs.0)
    }
}

impl SubAssign for Uint256 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = Self(self.0 - rhs.0);
    }
}

impl Encode for Uint256 {
    fn encode(&self) -> EncodingResult<Vec<u8>> {
        let mut dest: Vec<u8> = Vec::new();
        self.encode_into(&mut dest)?;
        Ok(dest)
    }

    fn encode_into<W: Write>(&self, dest: &mut W) -> EncodingResult<()> {
        match self.0.consensus_encode(dest) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn encoding_length(&self) -> EncodingResult<usize> {
        let mut _dest: Vec<u8> = Vec::new();
        match self.0.consensus_encode(_dest) {
            Ok(inner) => Ok(inner),
            Err(e) => Err(e.into()),
        }
    }
}

impl Decode for Uint256 {
    fn decode<R: Read>(input: R) -> EncodingResult<Self> {
        let decoded_bytes = Decodable::consensus_decode(input);
        match decoded_bytes {
            Ok(inner) => Ok(Self(inner)),
            Err(_) => {
                let std_e = std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to decode bitcoin primitive",
                );
                Err(std_e.into())
            }
        }
    }
}

impl State for Uint256 {
    type Encoding = Self;

    fn create(_: Store, data: Self::Encoding) -> orga::Result<Self> {
        Ok(data)
    }

    fn flush(self) -> orga::Result<Self::Encoding> {
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, State)]
pub struct WrappedHeader {
    height: u32,
    header: HeaderAdapter,
}

impl WrappedHeader {
    fn time(&self) -> u32 {
        self.header.time
    }

    fn target(&self) -> Uint256 {
        Uint256(self.header.target())
    }

    fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    fn prev_blockhash(&self) -> BlockHash {
        self.header.prev_blockhash
    }

    fn work(&self) -> Uint256 {
        Uint256(self.header.work())
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn validate_pow(&self, required_target: &Uint256) -> Result<BlockHash> {
        Ok(self.header.validate_pow(&required_target.0)?)
    }
}

#[derive(Clone, Debug, State)]
pub struct WorkHeader {
    chain_work: Uint256,
    header: WrappedHeader,
}

impl WorkHeader {
    fn time(&self) -> u32 {
        self.header.time()
    }

    fn target(&self) -> Uint256 {
        self.header.target()
    }

    fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    fn prev_blockhash(&self) -> BlockHash {
        self.header.prev_blockhash()
    }

    fn work(&self) -> Uint256 {
        self.header.work()
    }

    fn height(&self) -> u32 {
        self.header.height()
    }

    fn validate_pow(&self, required_target: &Uint256) -> Result<BlockHash> {
        Ok(self.header.validate_pow(required_target)?)
    }
}

#[derive(State)]
pub struct HeaderQueue {
    deque: Deque<WorkHeader>,
    current_work: Uint256,
    trusted_header: WrappedHeader,
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
            //not sure if this should return an error or just be a no-op
            None => {
                return Err(Error::Header("Passed header list empty".into()));
            }
        };

        let last = match headers.last() {
            Some(inner) => inner.clone(),
            //not sure if this should return an error or just be a no-op
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
            self.reorg(headers, &first.height, &last.height)?;
        }

        while self.length() > MAX_LENGTH {
            let header = match self.deque.pop_front()? {
                Some(inner) => inner.header.header.clone(),
                None => {
                    break;
                }
            };

            self.current_work -= header.work().into();
        }

        Ok(())
    }

    fn reorg(
        &mut self,
        headers: Vec<WrappedHeader>,
        first_height: &u32,
        last_height: &u32,
    ) -> Result<()> {
        let reorg_index = first_height - 1 - self.trusted_header.height;

        let first_removal_hash = match self.deque.get((reorg_index + 1) as u64)? {
            Some(inner) => inner.header.header.block_hash(),
            None => {
                return Err(Error::Header(
                    "No header exists after calculated reorg index".into(),
                ));
            }
        };

        let first_passed_hash = match headers.get(0) {
            Some(inner) => inner.header.block_hash(),
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

        let passed_headers_work = headers.iter().fold(Uint256::default(), |work, header| {
            work + header.header.work().into()
        });

        let prev_chain_work = match self.deque.get(reorg_index as u64)? {
            Some(inner) => inner.chain_work.clone(),
            None => {
                return Err(Error::Header(
                    "No header exists at calculated reorg index".into(),
                ))
            }
        };

        if prev_chain_work + passed_headers_work > self.current_work {
            let last_index = last_height - self.trusted_header.height;
            for _ in 0..(last_index - reorg_index) {
                let header_work = match self.deque.pop_back()? {
                    Some(inner) => inner.chain_work.clone(),
                    None => {
                        break;
                    }
                };

                self.current_work -= header_work;
            }

            for item in headers {
                let header_work = item.header.work();
                let work_header = WorkHeader {
                    chain_work: self.current_work.clone() + header_work.into(),
                    header: item,
                };

                self.deque.push_front(work_header.into())?;
                self.current_work += header_work.into()
            }
        }

        Ok(())
    }

    fn length(&self) -> u64 {
        self.deque.len()
    }

    fn height(&self) -> Result<u32> {
        match self.deque.back()? {
            Some(inner) => Ok((*inner).header.height),
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::BlockHash;
    use bitcoin_hashes::hex::FromHex;
    use bitcoin_hashes::sha256d::Hash;
    use chrono::{TimeZone, Utc};

    #[test]
    fn primitive_adapter_encode_decode() {
        let stamp = Utc.ymd(2009, 1, 10).and_hms(11, 39, 0);

        //Bitcoin block 42
        let header = BlockHeader {
            version: 1,
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

        let adapter = HeaderAdapter(header);
        let encoded_adapter = adapter.encode().unwrap();

        let decoded_adapter: HeaderAdapter = Decode::decode(encoded_adapter.as_slice()).unwrap();

        assert_eq!(*decoded_adapter, header);
    }

    #[test]
    fn add_into_iterator() {
        let stamp = Utc.ymd(2009, 1, 10).and_hms(11, 39, 0);

        let header = BlockHeader {
            version: 1,
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

        let adapter = HeaderAdapter(header);

        let header_list = [WrappedHeader {
            height: 1,
            header: adapter,
        }];

        let store = Store::new(Shared::new(MapStore::new()));
        let mut q = HeaderQueue::create(store, Default::default()).unwrap();
        q.add(header_list).unwrap();

        let adapter = HeaderAdapter(header);

        let header_list = vec![WrappedHeader {
            height: 1,
            header: adapter,
        }];

        let store = Store::new(Shared::new(MapStore::new()));
        let mut q = HeaderQueue::create(store, Default::default()).unwrap();
        q.add(header_list).unwrap();
    }
}
