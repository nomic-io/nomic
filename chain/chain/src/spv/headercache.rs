//
// Copyright 2018-2019 Tamas Blummer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//!
//! # Cache of headers and the chain with most work
//!

use super::error::Error;
use bitcoin::{
    blockdata::block::BlockHeader, hashes as bitcoin_hashes, network::constants::Network,
    util::uint::Uint256, BitcoinHash,
};
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::Hash;
use orga::Store;
use serde::de::{
    self, Deserialize, Deserializer, Error as DeserializationError, MapAccess, SeqAccess, Visitor,
};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use serde::{Deserialize as DeserializeMacro, Serialize as SerializeMacro};
use std::collections::HashMap;
use std::fmt;

impl<'de> Deserialize<'de> for StoredHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Height,
            Header,
            Log2work,
        };

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`height` or `header` or `log2work`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "height" => Ok(Field::Height),
                            "log2work" => Ok(Field::Log2work),
                            "header" => Ok(Field::Header),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct StoredHeaderVisitor;

        impl<'de> Visitor<'de> for StoredHeaderVisitor {
            type Value = StoredHeader;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct StoredHeader")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<StoredHeader, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let header_element = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                // TODO: change error handling here
                let header = bitcoin::consensus::deserialize(header_element).unwrap();

                let height = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                let log2work = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                Ok(StoredHeader {
                    header,
                    height,
                    log2work,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<StoredHeader, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut header = None;
                let mut height = None;
                let mut log2work = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Header => {
                            if header.is_some() {
                                return Err(de::Error::duplicate_field("header"));
                            }
                            header = Some(map.next_value()?);
                        }
                        Field::Height => {
                            if height.is_some() {
                                return Err(de::Error::duplicate_field("height"));
                            }
                            height = Some(map.next_value()?);
                        }

                        Field::Log2work => {
                            if log2work.is_some() {
                                return Err(de::Error::duplicate_field("log2work"));
                            }
                            log2work = Some(map.next_value()?);
                        }
                    }
                }
                let header = header.ok_or_else(|| de::Error::missing_field("header"))?;
                // TODO: error handling
                let header = bitcoin::consensus::deserialize(header).unwrap();
                let height = height.ok_or_else(|| de::Error::missing_field("height"))?;
                let log2work = log2work.ok_or_else(|| de::Error::missing_field("log2work"))?;
                Ok(StoredHeader {
                    header,
                    height,
                    log2work,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["header", "height", "log2work"];
        deserializer.deserialize_struct("StoredHeader", FIELDS, StoredHeaderVisitor)
    }
}

/// Custom serialization/deserialization because I can't get the derive macro to work with
/// rust-bitcoin.
impl Serialize for StoredHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("StoredHeader", 3)?;
        state.serialize_field("height", &self.height)?;
        state.serialize_field("log2work", &self.log2work)?;
        state.serialize_field("header", &bitcoin::consensus::serialize(&self.header))?;
        state.end()
    }
}

/// A header enriched with information about its position on the blockchain
#[derive(Debug, Clone)]
pub struct StoredHeader {
    /// header
    pub header: BlockHeader,
    /// chain height
    pub height: u32,
    /// log2 of total work
    pub log2work: f64,
}

// need to implement if put_hash_keyed and get_hash_keyed should be used
impl BitcoinHash for StoredHeader {
    fn bitcoin_hash(&self) -> bitcoin_hashes::sha256d::Hash {
        self.header.bitcoin_hash()
    }
}
#[derive(Debug, Clone, SerializeMacro, Deserialize)]
pub struct CachedHeader {
    pub stored: StoredHeader,
    id: Sha256dHash,
}

impl CachedHeader {
    pub fn new(id: &Sha256dHash, header: StoredHeader) -> CachedHeader {
        CachedHeader {
            stored: header,
            id: id.clone(),
        }
    }

    /// Computes the target [0, T] that a blockhash must land in to be valid
    pub fn target(&self) -> Uint256 {
        // This is a floating-point "compact" encoding originally used by
        // OpenSSL, which satoshi put into consensus code, so we're stuck
        // with it. The exponent needs to have 3 subtracted from it, hence
        // this goofy decoding code:
        let (mant, expt) = {
            let unshifted_expt = self.stored.header.bits >> 24;
            if unshifted_expt <= 3 {
                (
                    (self.stored.header.bits & 0xFFFFFF) >> (8 * (3 - unshifted_expt)),
                    0,
                )
            } else {
                (
                    self.stored.header.bits & 0xFFFFFF,
                    8 * ((self.stored.header.bits >> 24) - 3),
                )
            }
        };

        // The mantissa is signed but may not be negative
        if mant > 0x7FFFFF {
            Default::default()
        } else {
            Uint256::from_u64(mant as u64).unwrap() << (expt as usize)
        }
    }

    /// Performs an SPV validation of a block, which confirms that the proof-of-work
    /// is correct, but does not verify that the transactions are valid or encoded
    /// correctly.
    pub fn spv_validate(&self, required_target: &Uint256) -> Result<(), Error> {
        use byteorder::{ByteOrder, LittleEndian};

        let target = &self.target();
        if target != required_target {
            return Err(Error::SpvBadTarget);
        }
        let data: [u8; 32] = self.bitcoin_hash().into_inner();
        let mut ret = [0u64; 4];
        LittleEndian::read_u64_into(&data, &mut ret);
        let hash = &Uint256(ret);
        if hash <= target {
            Ok(())
        } else {
            Err(Error::SpvBadProofOfWork)
        }
    }

    /// Returns the total work of the block
    pub fn work(&self) -> Uint256 {
        // 2**256 / (target + 1) == ~target / (target+1) + 1    (eqn shamelessly stolen from bitcoind)
        let mut ret = !self.target();
        let mut ret1 = self.target();
        ret1.increment();
        ret = ret / ret1;
        ret.increment();
        ret
    }
}

impl BitcoinHash for CachedHeader {
    fn bitcoin_hash(&self) -> Sha256dHash {
        self.id
    }
}

pub struct HeaderCache<'a> {
    // network
    network: Network,
    // all known headers
    //    pub headers: HashMap<Sha256dHash, CachedHeader>,
    // header chain with most work
    pub trunk: Vec<Sha256dHash>,
    // orga store to use instead of headers hashmap
    store: &'a mut dyn Store,
}

const EXPECTED_CHAIN_LENGTH: usize = 600000;

impl<'a> HeaderCache<'a> {
    pub fn new(network: Network, store: &'a mut dyn Store) -> HeaderCache {
        HeaderCache {
            network,
            store,
            trunk: Vec::with_capacity(EXPECTED_CHAIN_LENGTH),
        }
    }

    /// Write the current state of the header cache into the store at the provided key.
    pub fn save(&mut self, store: &mut dyn Store, key: &[u8]) {
        println!("saving headercache.");
    }

    pub fn add_header_unchecked(&mut self, id: &Sha256dHash, stored: &StoredHeader) {
        let cached = CachedHeader::new(id, stored.clone());
        self.insert_header(id.clone(), cached);
        self.trunk.push(id.clone());
    }

    pub fn reverse_trunk(&mut self) {
        self.trunk.reverse()
    }

    pub fn len(&self) -> usize {
        self.trunk.len()
    }

    /// add a Bitcoin header
    pub fn add_header(
        &mut self,
        header: &BlockHeader,
    ) -> Result<
        Option<(
            CachedHeader,
            Option<Vec<Sha256dHash>>,
            Option<Vec<Sha256dHash>>,
        )>,
        Error,
    > {
        if self.get_header(&header.bitcoin_hash()).is_some() {
            // ignore already known header
            return Ok(None);
        }
        if header.prev_blockhash != Sha256dHash::default() {
            // regular update
            let previous;
            if let Some(prev) = self.get_header(&header.prev_blockhash) {
                previous = prev.clone();
            } else {
                // reject unconnected
                return Err(Error::UnconnectedHeader);
            }
            // add  to tree
            return Ok(Some(self.add_header_to_tree(&previous, header)?));
        } else {
            // insert genesis
            let new_tip = header.bitcoin_hash();
            let stored = CachedHeader::new(
                &new_tip,
                StoredHeader {
                    header: header.clone(),
                    height: 0,
                    log2work: Self::log2(header.work()),
                },
            );
            self.trunk.push(new_tip.clone());
            self.insert_header(new_tip.clone(), stored.clone());
            return Ok(Some((stored, None, Some(vec![new_tip]))));
        }
    }

    /// Writes a CachedHeader to the backing store.
    fn insert_header(&mut self, header_id: Sha256dHash, header: CachedHeader) {}
    fn get_header(&mut self, header_id: &Sha256dHash) -> Option<CachedHeader> {
        None
    }

    fn log2(work: Uint256) -> f64 {
        // we will have u256 faster in Rust than 2^128 total work in Bitcoin
        assert!(work.0[2] == 0 && work.0[3] == 0);
        ((work.0[0] as u128 + ((work.0[1] as u128) << 64)) as f64).log2()
    }

    fn exp2(n: f64) -> Uint256 {
        // we will have u256 faster in Rust than 2^128 total work in Bitcoin
        assert!(n < 128.0);
        let e: u128 = n.exp2() as u128;
        let mut b = [0u64; 4];
        b[0] = e as u64;
        b[1] = (e >> 64) as u64;
        Uint256(b)
    }

    fn max_target() -> Uint256 {
        Uint256::from_u64(0xFFFF).unwrap() << 208
    }

    // add header to tree, return stored, optional list of unwinds, optional list of extensions
    fn add_header_to_tree(
        &mut self,
        prev: &CachedHeader,
        next: &BlockHeader,
    ) -> Result<
        (
            CachedHeader,
            Option<Vec<Sha256dHash>>,
            Option<Vec<Sha256dHash>>,
        ),
        Error,
    > {
        const DIFFCHANGE_INTERVAL: u32 = 2016;
        const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
        const TARGET_BLOCK_SPACING: u32 = 600;

        let required_work =
        // Compute required difficulty if this is a diffchange block
            if (prev.stored.height + 1) % DIFFCHANGE_INTERVAL == 0 {
                let timespan = {
                    // Scan back DIFFCHANGE_INTERVAL blocks
                    let mut scan = prev.clone();
                    if self.tip_hash() == Some(scan.stored.header.prev_blockhash) {
                        scan = self.get_header(&self.trunk[self.trunk.len() - DIFFCHANGE_INTERVAL as usize - 2]).unwrap().clone();
                    } else {
                        for _ in 0..(DIFFCHANGE_INTERVAL - 1) {
                            if let Some(header) = self.get_header(&scan.stored.header.prev_blockhash) {
                                scan = header.clone();
                            } else {
                                return Err(Error::UnconnectedHeader);
                            }
                        }
                    }
                    // Get clamped timespan between first and last blocks
                    match prev.stored.header.time - scan.stored.header.time {
                        n if n < DIFFCHANGE_TIMESPAN / 4 => DIFFCHANGE_TIMESPAN / 4,
                        n if n > DIFFCHANGE_TIMESPAN * 4 => DIFFCHANGE_TIMESPAN * 4,
                        n => n
                    }
                };
                // Compute new target
                let mut target = prev.stored.header.target();
                target = target.mul_u32(timespan);
                target = target / Uint256::from_u64(DIFFCHANGE_TIMESPAN as u64).unwrap();
                // Clamp below MAX_TARGET (difficulty 1)
                let max = Self::max_target();
                if target > max { target = max };
                // Compactify (make expressible in the 8+24 nBits float format)
                Self::satoshi_the_precision(target)
                // On non-diffchange blocks, Testnet has a rule that any 20-minute-long
                // block interval resets the difficulty to 1
            } else if self.network == Network::Testnet &&
                next.time > prev.stored.header.time + 2 * TARGET_BLOCK_SPACING {
                Self::max_target()
                // On the other hand, if we are in Testnet and the block interval is less
                // than 20 minutes, we need to scan backward to find a block for which the
                // previous rule did not apply, to find the "real" difficulty.
            } else if self.network == Network::Testnet {
                // Scan back DIFFCHANGE_INTERVAL blocks
                let mut scan = prev.clone();
                let mut height = prev.stored.height;
                let max_target = Self::max_target();
                while height % DIFFCHANGE_INTERVAL != 0 && scan.stored.header.prev_blockhash != Sha256dHash::default() && scan.stored.header.target() == max_target {
                    if let Some(header) = self.get_header(&scan.stored.header.prev_blockhash) {
                        scan = header.clone();
                        height = header.stored.height;
                    } else {
                        return Err(Error::UnconnectedHeader);
                    }
                }
                scan.stored.header.target()
                // Otherwise just use the last block's difficulty
            } else {
                prev.stored.header.target()
            };

        let cached = CachedHeader::new(
            &next.bitcoin_hash(),
            StoredHeader {
                header: next.clone(),
                height: prev.stored.height + 1,
                log2work: Self::log2(next.work() + Self::exp2(prev.stored.log2work)),
            },
        );

        // Check POW
        if cached.spv_validate(&required_work).is_err() {
            return Err(Error::SpvBadProofOfWork);
        }

        let next_hash = cached.bitcoin_hash();

        // store header in cache
        self.insert_header(next_hash.clone(), cached.clone());
        if let Some(tip) = self.tip() {
            if tip.stored.log2work < cached.stored.log2work {
                // higher POW than previous tip

                // compute path to new tip
                let mut forks_at = next.prev_blockhash;
                let mut path_to_new_tip = Vec::new();
                while self.pos_on_trunk(&forks_at).is_none() {
                    if let Some(h) = self.get_header(&forks_at) {
                        forks_at = h.stored.header.prev_blockhash;
                        path_to_new_tip.push(forks_at);
                    } else {
                        return Err(Error::UnconnectedHeader);
                    }
                }
                path_to_new_tip.reverse();
                path_to_new_tip.push(next_hash);

                // compute list of headers no longer on trunk
                if forks_at != next.prev_blockhash {
                    let mut unwinds = Vec::new();

                    if let Some(pos) = self.trunk.iter().rposition(|h| *h == forks_at) {
                        if pos < self.trunk.len() - 1 {
                            // store and cut headers that are no longer on trunk
                            unwinds.extend(self.trunk[pos + 1..].iter().rev().map(|h| *h));
                            self.trunk.truncate(pos + 1);
                        }
                    } else {
                        return Err(Error::UnconnectedHeader);
                    }
                    self.trunk.extend(path_to_new_tip.iter().map(|h| *h));
                    return Ok((cached, Some(unwinds), Some(path_to_new_tip)));
                } else {
                    self.trunk.extend(path_to_new_tip.iter().map(|h| *h));
                    return Ok((cached, None, Some(path_to_new_tip)));
                }
            } else {
                return Ok((cached, None, None));
            }
        } else {
            return Err(Error::NoTip);
        }
    }

    /// position on trunk (chain with most work from genesis to tip)
    pub fn pos_on_trunk(&self, hash: &Sha256dHash) -> Option<u32> {
        self.trunk
            .iter()
            .rev()
            .position(|e| *e == *hash)
            .map(|p| (self.trunk.len() - p - 1) as u32)
    }

    /// retrieve the id of the block/header with most work
    pub fn tip(&self) -> Option<CachedHeader> {
        if let Some(id) = self.tip_hash() {
            return self.get_header(&id);
        }
        None
    }

    pub fn tip_hash(&self) -> Option<Sha256dHash> {
        if let Some(tip) = self.trunk.last() {
            return Some(*tip);
        }
        None
    }

    /// taken from an early rust-bitcoin by Andrew Poelstra:
    /// This function emulates the `GetCompact(SetCompact(n))` in the Satoshi code,
    /// which drops the precision to something that can be encoded precisely in
    /// the nBits block header field. Savour the perversity. This is in Bitcoin
    /// consensus code. What. Gaah!
    fn satoshi_the_precision(n: Uint256) -> Uint256 {
        use bitcoin::util::BitArray;

        // Shift by B bits right then left to turn the low bits to zero
        let bits = 8 * ((n.bits() + 7) / 8 - 3);
        let mut ret = n >> bits;
        // Oh, did I say B was that fucked up formula? I meant sometimes also + 8.
        if ret.bit(23) {
            ret = (ret >> 8) << 8;
        }
        ret << bits
    }

    pub fn get_header_for_height(&self, height: u32) -> Option<CachedHeader> {
        if height < self.trunk.len() as u32 {
            self.get_header(&self.trunk[height as usize])
        } else {
            None
        }
    }

    /*pub fn iter_trunk<'b>(&'b self, from: u32) -> Box<dyn Iterator<Item = &'b CachedHeader> + 'b> {
        Box::new(
            self.trunk
                .iter()
                .skip(from as usize)
                .map(move |b| self.get_header(&*b).unwrap()),
        )
    }

    pub fn iter_trunk_rev<'b>(
        &'b self,
        from: Option<u32>,
    ) -> Box<dyn Iterator<Item = &'b CachedHeader> + 'b> {
        let len = self.trunk.len();
        if let Some(from) = from {
            Box::new(
                self.trunk
                    .iter()
                    .rev()
                    .skip(len - from as usize)
                    .map(move |b| self.get_header(&*b).unwrap()),
            )
        } else {
            Box::new(
                self.trunk
                    .iter()
                    .rev()
                    .map(move |b| self.get_header(&*b).unwrap()),
            )
        }
    } */

    // locator for getheaders message
    pub fn locator_hashes(&self) -> Vec<Sha256dHash> {
        let mut locator = vec![];
        let mut skip = 1;
        let mut count = 0;
        let mut s = 0;

        let iterator = self.trunk.iter().rev();
        for h in iterator {
            if s == 0 {
                locator.push(h.clone());
                count += 1;
                s = skip;
                if count > 10 {
                    skip *= 2;
                }
            }
            s -= 1;
        }

        locator
    }
}
