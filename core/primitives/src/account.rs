use crate::Result;
use orga::{Decode, Encode, Store};
use std::io::{Read, Write};

#[derive(Debug, Default, PartialEq)]
pub struct Account {
    pub nonce: u64,
    pub balance: u64,
}

impl Encode for Account {
    fn encode_into<W: Write>(&self, dest: &mut W) -> Result<()> {
        self.nonce.encode_into(dest)?;
        self.balance.encode_into(dest)
    }

    fn encoding_length(&self) -> Result<usize> {
        Ok(self.nonce.encoding_length()? + self.balance.encoding_length()?)
    }
}

impl Decode for Account {
    fn decode<R: Read>(mut input: R) -> Result<Self> {
        Ok(Self {
            nonce: u64::decode(&mut input)?,
            balance: u64::decode(&mut input)?,
        })
    }
}
