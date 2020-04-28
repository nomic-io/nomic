use bitcoin::PublicKey;
use nomic_bitcoin::bitcoin;
use nomic_primitives::Result;
use orga::{Decode, Encode, Terminated};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signatory {
    pub voting_power: u64,
    pub pubkey: PublicKey,
}

impl Signatory {
    pub fn new(pubkey: PublicKey, voting_power: u64) -> Self {
        Signatory {
            pubkey,
            voting_power,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct SignatorySet {
    map: HashMap<PublicKey, Signatory>,
    set: BTreeSet<Signatory>,
    total_voting_power: u128,
}

impl SignatorySet {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn total_voting_power(&self) -> u128 {
        self.total_voting_power
    }

    pub fn two_thirds_voting_power(&self) -> u128 {
        // it is safe that we round down since the script does a
        // greater than comparison
        self.total_voting_power * 2 / 3
    }

    pub fn remove(&mut self, pubkey: &PublicKey) -> Option<Signatory> {
        self.map.remove(pubkey).map(|signatory| {
            self.set.remove(&signatory);
            self.total_voting_power -= signatory.voting_power as u128;
            signatory
        })
    }

    pub fn set(&mut self, signatory: Signatory) -> Option<Signatory> {
        let previous = self.remove(&signatory.pubkey);
        self.add(signatory);
        previous
    }

    fn add(&mut self, signatory: Signatory) {
        self.total_voting_power += signatory.voting_power as u128;
        self.map.insert(signatory.pubkey.clone(), signatory.clone());
        self.set.insert(signatory);
    }

    pub fn iter(&self) -> impl Iterator<Item = &Signatory> {
        self.set.iter().rev()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SerializableSignatorySetSnapshot {
    time: u64,
    signatories: Vec<(Vec<u8>, u64)>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignatorySetSnapshot {
    pub time: u64,
    pub signatories: SignatorySet,
}

impl SignatorySetSnapshot {
    fn to_serializable(&self) -> SerializableSignatorySetSnapshot {
        let signatories = self
            .signatories
            .iter()
            .map(|signatory| (signatory.pubkey.to_bytes(), signatory.voting_power))
            .collect();
        SerializableSignatorySetSnapshot {
            time: self.time,
            signatories,
        }
    }

    fn from_serializable(serializable: &SerializableSignatorySetSnapshot) -> Result<Self> {
        let mut signatories = SignatorySet::new();
        for (pubkey_bytes, voting_power) in serializable.signatories.iter() {
            signatories.set(Signatory {
                pubkey: PublicKey::from_slice(pubkey_bytes)?,
                voting_power: *voting_power,
            });
        }
        Ok(SignatorySetSnapshot {
            time: serializable.time,
            signatories,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let serializable =
            bincode::deserialize(bytes).map_err(|err| failure::format_err!("{}", err))?;
        Ok(Self::from_serializable(&serializable)?)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let serializable = self.to_serializable();
        bincode::serialize(&serializable).map_err(|err| failure::format_err!("{}", err))
    }
}

use std::io::{Read, Write};
impl Encode for SignatorySetSnapshot {
    fn encode_into<W: Write>(&self, dest: &mut W) -> Result<()> {
        let bytes = SignatorySetSnapshot::encode(self)?;
        dest.write_all(bytes.as_slice())?;
        Ok(())
    }

    fn encoding_length(&self) -> Result<usize> {
        let bytes = SignatorySetSnapshot::encode(self)?;
        Ok(bytes.len())
    }
}

impl Decode for SignatorySetSnapshot {
    fn decode<R: Read>(mut input: R) -> Result<Self> {
        let mut buf = vec![];
        input.read_to_end(&mut buf)?;
        SignatorySetSnapshot::decode(buf.as_slice())
    }
}

impl !Terminated for SignatorySetSnapshot {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn len() {
        let mut set = SignatorySet::new();
        assert_eq!(set.len(), 0);
        set.add(mock_signatory(1, 123));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn remove_nonexistent() {
        let mut set = SignatorySet::new();
        assert!(set.remove(&mock_pubkey(1)).is_none());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn total_voting_power() {
        let mut set = SignatorySet::new();
        set.add(mock_signatory(1, 100));
        set.add(mock_signatory(2, 100));
        assert_eq!(set.total_voting_power(), 200);
        set.remove(&mock_pubkey(1));
        assert_eq!(set.total_voting_power(), 100);
    }

    #[test]
    fn two_thirds_voting_power() {
        let mut set = SignatorySet::new();
        set.add(mock_signatory(1, 100));
        set.add(mock_signatory(2, 100));
        assert_eq!(set.two_thirds_voting_power(), 133);
        set.remove(&mock_pubkey(1));
        assert_eq!(set.two_thirds_voting_power(), 66);
    }

    #[test]
    fn iter() {
        let mut set = SignatorySet::new();
        set.add(mock_signatory(3, 100));
        set.add(mock_signatory(6, 150));
        set.add(mock_signatory(2, 100));
        set.add(mock_signatory(1, 200));

        let mut iter = set.iter();
        assert_eq!(iter.next().unwrap(), &mock_signatory(1, 200));
        assert_eq!(iter.next().unwrap(), &mock_signatory(6, 150));
        assert_eq!(iter.next().unwrap(), &mock_signatory(2, 100));
        assert_eq!(iter.next().unwrap(), &mock_signatory(3, 100));
    }

    #[test]
    fn snapshot_encode_fixture() {
        let mut set = SignatorySet::new();
        set.add(mock_signatory(2, 100));
        set.add(mock_signatory(1, 200));

        let snapshot = SignatorySetSnapshot {
            time: 123,
            signatories: set,
        };
        assert_eq!(
            snapshot.encode().unwrap(),
            vec![
                123, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 3, 27,
                132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24,
                52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143, 200, 0, 0, 0, 0, 0, 0, 0,
                33, 0, 0, 0, 0, 0, 0, 0, 2, 77, 75, 108, 209, 54, 16, 50, 202, 155, 210, 174, 185,
                217, 0, 170, 77, 69, 217, 234, 216, 10, 201, 66, 51, 116, 196, 81, 167, 37, 77, 7,
                102, 100, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn snapshot_decode_fixture() {
        let mut set = SignatorySet::new();
        set.add(mock_signatory(2, 100));
        set.add(mock_signatory(1, 200));

        let expected_snapshot = SignatorySetSnapshot {
            time: 123,
            signatories: set,
        };

        let bytes = vec![
            123, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 3, 27, 132,
            197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52, 96, 72,
            25, 255, 156, 23, 245, 233, 213, 221, 7, 143, 200, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0,
            0, 0, 0, 2, 77, 75, 108, 209, 54, 16, 50, 202, 155, 210, 174, 185, 217, 0, 170, 77, 69,
            217, 234, 216, 10, 201, 66, 51, 116, 196, 81, 167, 37, 77, 7, 102, 100, 0, 0, 0, 0, 0,
            0, 0,
        ];
        assert_eq!(
            SignatorySetSnapshot::decode(bytes.as_slice()).unwrap(),
            expected_snapshot
        );
    }
}
