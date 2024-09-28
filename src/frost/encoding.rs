use ed::{Decode, Encode, Terminated};
use orga::describe::Descriptor;
use orga::migrate::Migrate;
use orga::query::Query;
use orga::state::State;
use orga::store::Store;
use orga::Result;
use orga::{describe::Describe, encoding::LengthVec};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Adapter<T> {
    pub inner: T,
}

impl<T> Query for Adapter<T> {
    type Query = ();

    fn query(&self, _query: Self::Query) -> Result<()> {
        Ok(())
    }
}

impl<T> Describe for Adapter<T> {
    fn describe() -> Descriptor {
        orga::describe::Builder::new::<()>().build()
    }
}

impl<T: 'static + Serialize + for<'de> Deserialize<'de>> Migrate for Adapter<T> {}
impl<T> Terminated for Adapter<T> {}

impl<T: 'static + Serialize + for<'de> Deserialize<'de>> State for Adapter<T> {
    fn attach(&mut self, _store: Store) -> Result<()> {
        Ok(())
    }

    fn load(_store: Store, bytes: &mut &[u8]) -> Result<Self> {
        Ok(Self::decode(bytes)?)
    }

    fn flush<W: std::io::Write>(self, out: &mut W) -> Result<()> {
        self.encode_into(out)?;

        Ok(())
    }
}

impl<T: 'static + Serialize + for<'de> Deserialize<'de>> Encode for Adapter<T> {
    fn encode_into<W: std::io::prelude::Write>(&self, dest: &mut W) -> ed::Result<()> {
        let bytes: LengthVec<u16, u8> = serde_json::to_vec(&self.inner)
            .map_err(|_| ed::Error::UnexpectedByte(123))?
            .try_into()
            .map_err(|_| ed::Error::UnexpectedByte(123))?;

        bytes.encode_into(dest)
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        let mut bytes: Vec<u8> = vec![];
        self.encode_into(&mut bytes)?;

        Ok(bytes.len())
    }
}

impl<T: 'static + Serialize + for<'de> Deserialize<'de>> Decode for Adapter<T> {
    fn decode<R: std::io::prelude::Read>(bytes: R) -> ed::Result<Self> {
        let bytes: LengthVec<u16, u8> = Decode::decode(bytes)?;
        let inner =
            serde_json::from_reader(&bytes[..]).map_err(|_| ed::Error::UnexpectedByte(123))?;
        Ok(Self { inner })
    }
}
