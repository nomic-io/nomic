use bitcoin::blockdata::block::BlockHeader;
use bitcoin::consensus::{Decodable, Encodable};
use orga::collections::Deque;
use orga::encoding::Result as EncodingResult;
use orga::prelude::*;
use orga::state::State;
use orga::store::Store;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};

pub struct HeaderAdapter {
    inner: BlockHeader,
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
        &self.inner
    }
}

impl DerefMut for HeaderAdapter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Encode for HeaderAdapter {
    fn encode(&self) -> EncodingResult<Vec<u8>> {
        let mut dest: Vec<u8> = Vec::new();
        self.encode_into(&mut dest)?;
        Ok(dest)
    }

    fn encode_into<W: Write>(&self, dest: &mut W) -> EncodingResult<()> {
        match self.inner.consensus_encode(dest) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn encoding_length(&self) -> EncodingResult<usize> {
        let mut _dest: Vec<u8> = Vec::new();
        match self.inner.consensus_encode(_dest) {
            Ok(inner) => Ok(inner),
            Err(e) => Err(e.into()),
        }
    }
}

impl Decode for HeaderAdapter {
    fn decode<R: Read>(input: R) -> EncodingResult<Self> {
        let decoded_bytes = Decodable::consensus_decode(input);
        match decoded_bytes {
            Ok(inner) => Ok(Self { inner }),
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

#[derive(State)]
pub struct WrappedHeader {
    height: u32,
    header: HeaderAdapter,
}

#[derive(State)]
pub struct HeaderQueue {
    inner: Deque<WrappedHeader>,
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

        let adapter = HeaderAdapter { inner: header };
        let encoded_adapter = adapter.encode().unwrap();

        let decoded_adapter: HeaderAdapter = Decode::decode(encoded_adapter.as_slice()).unwrap();

        assert_eq!(*decoded_adapter, header);
    }
}
