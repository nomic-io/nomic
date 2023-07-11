use bitcoin::consensus::{Decodable, Encodable};
use orga::describe::Describe;
use orga::encoding::Result as EncodingResult;
use orga::migrate::MigrateFrom;
use orga::prelude::*;
use orga::state::State;
use orga::store::Store;
use orga::Result as OrgaResult;
use serde::Serialize;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Adapter<T> {
    inner: T,
}
impl<T> MigrateFrom for Adapter<T> {
    fn migrate_from(other: Self) -> Result<Self> {
        Ok(other)
    }
}

impl<T> Adapter<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Default> Default for Adapter<T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}

impl<T> Terminated for Adapter<T> {}

impl<T: Encodable + Decodable + 'static> State for Adapter<T> {
    #[inline]
    fn attach(&mut self, _: Store) -> OrgaResult<()> {
        Ok(())
    }

    #[inline]
    fn flush<W: std::io::Write>(self, out: &mut W) -> OrgaResult<()> {
        Ok(self.encode_into(out)?)
    }

    fn load(_store: Store, bytes: &mut &[u8]) -> OrgaResult<Self> {
        Ok(Self::decode(bytes)?)
    }
}

impl<T: Encodable + Decodable + 'static> Describe for Adapter<T> {
    fn describe() -> orga::describe::Descriptor {
        orga::describe::Builder::new::<Self>().build()
    }
}

impl<T> Deref for Adapter<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Adapter<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Encodable> Encode for Adapter<T> {
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
        match self.inner.consensus_encode(&mut _dest) {
            Ok(inner) => Ok(inner),
            Err(e) => Err(e.into()),
        }
    }
}

impl<T: Decodable> Decode for Adapter<T> {
    fn decode<R: Read>(mut input: R) -> EncodingResult<Self> {
        let decoded_bytes = Decodable::consensus_decode(&mut input);
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

impl<T> Query for Adapter<T> {
    type Query = ();

    fn query(&self, _: Self::Query) -> Result<()> {
        Ok(())
    }
}

impl<T> Call for Adapter<T> {
    type Call = ();

    fn call(&mut self, _: Self::Call) -> Result<()> {
        Ok(())
    }
}

impl<T: Copy> Copy for Adapter<T> {}
