use bitcoin::blockdata::block::BlockHeader;
use bitcoin::consensus::{Decodable, Encodable};
use ed::{Decode, Encode};
use orga::collections::Deque;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};

struct BitcoinAdapter<T> {
    inner: T,
}

impl<T> Deref for BitcoinAdapter<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for BitcoinAdapter<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Encodable> Encode for BitcoinAdapter<T> {
    fn encode(&self) -> ed::Result<Vec<u8>> {
        let mut dest: Vec<u8> = Vec::new();
        self.encode_into(&mut dest)?;
        Ok(dest)
    }

    fn encode_into<W: Write>(&self, dest: &mut W) -> ed::Result<()> {
        match self.inner.consensus_encode(dest) {
            Ok(_) => Ok(()),
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        let mut _dest: Vec<u8> = Vec::new();
        match self.inner.consensus_encode(_dest) {
            Ok(inner) => Ok(inner),
            Err(e) => Err(e.into()),
        }
    }
}

impl<T: Decodable> Decode for BitcoinAdapter<T> {
    fn decode<R: Read>(input: R) -> ed::Result<Self> {
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

pub struct HeaderQueue {}
