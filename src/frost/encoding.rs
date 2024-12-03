//! Encoding and decoding for the [`Frost`] module.
use std::marker::PhantomData;

use ed::{Decode, Encode, Terminated};
use orga::describe::Descriptor;
use orga::migrate::Migrate;
use orga::query::Query;
use orga::state::State;
use orga::store::Store;
use orga::{describe::Describe, encoding::LengthVec};
use orga::{orga, Result};
use serde::{Deserialize, Serialize};

use orga::Error;

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

#[orga]
#[derive(Clone, Debug)]
pub struct Encrypted<T> {
    _marker: PhantomData<T>,
    bytes: LengthVec<u16, u8>,
}

impl<T> Encrypted<T> {
    pub fn decrypt(&self, sk: &[u8]) -> Result<T>
    where
        T: Decode,
    {
        let bytes = ecies::decrypt(sk, &self.bytes)
            .map_err(|_| Error::App("Failed to decrypt value".to_string()))?;

        T::decode(bytes.as_slice())
            .map_err(|_| Error::App("Failed to decode encrypted value".to_string()))
    }

    pub fn encrypt(pk: &[u8], value: T) -> Result<Self>
    where
        T: Encode,
    {
        let bytes = value.encode()?;

        let enc = ecies::encrypt(pk, &bytes)
            .map_err(|_| Error::App("Failed to encrypt value".to_string()))?;

        Ok(Self {
            bytes: enc.try_into()?,
            _marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ecies::utils::generate_keypair;

    #[derive(Encode, Decode, PartialEq, Eq, Debug, Clone)]
    pub struct SecretMessage {
        n: u64,
        msg: Vec<u8>,
    }

    #[test]
    fn encrypt_decrypt() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        let (sk3, _pk3) = generate_keypair();

        let msg1 = SecretMessage {
            n: 42,
            msg: b"hello pk2".to_vec(),
        };
        let msg2 = SecretMessage {
            n: 69,
            msg: b"hello pk1".to_vec(),
        };

        let encrypted1 = Encrypted::encrypt(&pk2.serialize(), msg1.clone()).unwrap();
        let encrypted2 = Encrypted::encrypt(&pk1.serialize(), msg2.clone()).unwrap();

        assert!(encrypted1.decrypt(&sk1.serialize()).is_err());
        let dec1 = encrypted1.decrypt(&sk2.serialize()).unwrap();
        assert!(encrypted1.decrypt(&sk3.serialize()).is_err());
        assert_eq!(msg1, dec1);

        let dec2 = encrypted2.decrypt(&sk1.serialize()).unwrap();
        assert!(encrypted2.decrypt(&sk2.serialize()).is_err());
        assert!(encrypted2.decrypt(&sk3.serialize()).is_err());
        assert_eq!(msg2, dec2);
    }
}
