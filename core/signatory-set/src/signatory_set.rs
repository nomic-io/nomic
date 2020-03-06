use super::{Error, Result};
use bitcoin::PublicKey;
use failure::bail;
use nomic_bitcoin::bitcoin;
use std::collections::btree_set::Iter;
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signatory {
    pub voting_power: u32,
    pub pubkey: PublicKey,
}

impl Signatory {
    pub fn new(pubkey: PublicKey, voting_power: u32) -> Self {
        Signatory {
            pubkey,
            voting_power,
        }
    }
}

#[derive(Default)]
pub struct SignatorySet {
    map: HashMap<PublicKey, Signatory>,
    set: BTreeSet<Signatory>,
    total_voting_power: u32,
}

impl SignatorySet {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn total_voting_power(&self) -> u32 {
        self.total_voting_power
    }

    pub fn remove(&mut self, pubkey: &PublicKey) -> Option<Signatory> {
        self.map.remove(pubkey).map(|signatory| {
            self.set.remove(&signatory);
            self.total_voting_power -= signatory.voting_power;
            signatory
        })
    }

    pub fn set(&mut self, signatory: Signatory) -> Option<Signatory> {
        let previous = self.remove(&signatory.pubkey);
        self.add(signatory);
        previous
    }

    fn add(&mut self, signatory: Signatory) {
        // TODO: ensure we don't overflow total_voting_power

        self.total_voting_power += signatory.voting_power;
        self.map.insert(signatory.pubkey.clone(), signatory.clone());
        self.set.insert(signatory);
    }

    pub fn iter(&self) -> impl Iterator<Item = &Signatory> {
        self.set.iter().rev()
    }
}

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
}
