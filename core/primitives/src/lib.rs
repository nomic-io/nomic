mod account;
mod error;
pub use account::Account;
pub use error::*;
pub mod transaction;
use std::io::{Read, Write};
use orga::{Decode, Encode};
use nomic_bitcoin::Script;

pub type Address = [u8; 33];
pub type Signature = [u8; 64];

pub struct Withdrawal {
    pub value: u64,
    pub script: Script,
}

impl Encode for Withdrawal {
  fn encode_into<W: Write>(&self, dest: &mut W) -> Result<()> {
      self.value.encode_into(dest)?;
      self.script.encode_into(dest)
  }

  fn encoding_length(&self) -> Result<usize> {
      Ok(self.value.encoding_length()? + self.script.encoding_length()?)
  }
}

impl Decode for Withdrawal {
   fn decode<R: Read>(mut input: R) -> Result<Self> {
       Ok(Self {
           value: u64::decode(&mut input)?,
           script: Script::decode(&mut input)?,
       })
   }
 }

