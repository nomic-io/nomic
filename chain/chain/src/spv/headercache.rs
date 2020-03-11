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
use bitcoin::hash_types::BlockHash as Sha256dHash;
use bitcoin::{
    blockdata::block::BlockHeader, hashes as bitcoin_hashes, network::constants::Network,
    util::uint::Uint256, BitcoinHash,
};
use bitcoin_hashes::Hash;
use failure::bail;
use nomic_bitcoin::bitcoin;
use orga::Result as OrgaResult;
use orga::Store;
use serde::{Deserialize, Serialize};

/// A header enriched with information about its position on the blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHeader {
    /// header
    pub header: BlockHeader,
    /// chain height
    pub height: u32,
    /// log2 of total work
    pub work_bytes: [u64; 4],
}

impl StoredHeader {
    pub fn work(&self) -> Uint256 {
        Uint256(self.work_bytes)
    }
}

// need to implement if put_hash_keyed and get_hash_keyed should be used
impl BitcoinHash<Sha256dHash> for StoredHeader {
    fn bitcoin_hash(&self) -> bitcoin::hash_types::BlockHash {
        self.header.bitcoin_hash()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl BitcoinHash<Sha256dHash> for CachedHeader {
    fn bitcoin_hash(&self) -> Sha256dHash {
        self.id
    }
}

pub struct HeaderCache<'a> {
    // network
    network: Network,
    // header chain with most work
    pub trunk: Vec<Sha256dHash>,
    // orga store to use instead of headers hashmap
    store: &'a mut dyn Store,
}

impl<'a> HeaderCache<'a> {
    pub fn new(network: Network, store: &'a mut dyn Store) -> HeaderCache {
        HeaderCache {
            network,
            store,
            trunk: Vec::new(),
        }
    }

    /// Adds a trusted header without any verification.
    ///
    /// Useful for configuring the SPV to work from some checkpoint sufficiently deep in the
    /// past.
    pub fn add_header_raw(&mut self, header: BlockHeader, height: u32) -> Result<(), Error> {
        let stored = StoredHeader {
            work_bytes: header.work().to_bytes(),
            header,
            height,
        };
        self.add_header_unchecked(&header.bitcoin_hash(), &stored)
    }
    fn add_header_unchecked(
        &mut self,
        id: &Sha256dHash,
        stored: &StoredHeader,
    ) -> Result<(), Error> {
        self.load_trunk();
        let cached = CachedHeader::new(id, stored.clone());
        let result = self.insert_header(id.clone(), cached);

        if let Err(header_insert_err) = result {
            return Err(header_insert_err.into());
        }

        self.trunk.push(id.clone());
        self.save_trunk()?;
        Ok(())
    }

    /// add a Bitcoin header
    pub fn add_header(
        &mut self,
        header: &BlockHeader,
    ) -> OrgaResult<
        Option<(
            CachedHeader,
            Option<Vec<Sha256dHash>>,
            Option<Vec<Sha256dHash>>,
        )>,
    > {
        self.load_trunk();
        if self.get_header(&header.bitcoin_hash())?.is_some() {
            // ignore already known header
            return Ok(None);
        }
        if header.prev_blockhash != Sha256dHash::default() {
            // regular update
            let previous;
            if let Some(prev) = self.get_header(&header.prev_blockhash)? {
                previous = prev.clone();
            } else {
                // reject unconnected
                return Err(Error::UnconnectedHeader.into());
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
                    work_bytes: header.work().to_bytes(),
                },
            );
            self.trunk.push(new_tip.clone());
            self.insert_header(new_tip.clone(), stored.clone())?;
            self.save_trunk()?;
            return Ok(Some((stored, None, Some(vec![new_tip]))));
        }
    }

    /// Writes a CachedHeader to the backing store.
    fn insert_header(&mut self, header_id: Sha256dHash, header: CachedHeader) -> OrgaResult<()> {
        let header_bytes = serde_json::to_vec(&header)?;
        let key = header_id.to_vec();

        self.store.put(key, header_bytes)
    }
    fn get_header(&self, header_id: &Sha256dHash) -> OrgaResult<Option<CachedHeader>> {
        let maybe_header_bytes = self.store.get(header_id)?;

        if let Some(header_bytes) = maybe_header_bytes {
            let header = serde_json::from_slice(&header_bytes)?;
            Ok(header)
        } else {
            Ok(None)
        }
    }

    /// Load and deserialize trunk from store.
    pub fn load_trunk(&mut self) -> Option<&Vec<Sha256dHash>> {
        self.store
            .get(b"trunk")
            .expect("Failed to get trunk from store")
            .map(move |trunk_bytes| {
                let trunk =
                    bytes_to_hashes(trunk_bytes.as_slice()).expect("Failed to read trunk hashes");
                self.trunk = trunk;
                &self.trunk
            })
    }

    /// Serialize and save current trunk to store.
    fn save_trunk(&mut self) -> OrgaResult<()> {
        if self.trunk.len() > 2018 {
            self.trunk = self.trunk.drain((self.trunk.len() - 2018)..).collect();
        }
        let trunk_bytes = hashes_to_bytes(&self.trunk);
        self.store.put(b"trunk".to_vec(), trunk_bytes)
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
        self.load_trunk();
        let required_work =
        // Compute required difficulty if this is a diffchange block
            if (prev.stored.height + 1) % DIFFCHANGE_INTERVAL == 0 {
                let timespan = {
                    // Scan back DIFFCHANGE_INTERVAL blocks
                    let mut scan = prev.clone();
                    if self.tip_hash() == Some(scan.stored.header.prev_blockhash) {
                        scan = self.get_header(&self.trunk[self.trunk.len() - DIFFCHANGE_INTERVAL as usize - 2])?.unwrap().clone();
                    } else {
                        for _ in 0..(DIFFCHANGE_INTERVAL - 1) {
                            if let Some(header) = self.get_header(&scan.stored.header.prev_blockhash)? {
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
                    if let Some(header) = self.get_header(&scan.stored.header.prev_blockhash)? {
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

        let combined_work: Uint256 = next.work() + prev.stored.header.work();
        let cached = CachedHeader::new(
            &next.bitcoin_hash(),
            StoredHeader {
                header: next.clone(),
                height: prev.stored.height + 1,
                work_bytes: combined_work.to_bytes(),
            },
        );

        // Check POW
        if cached.spv_validate(&required_work).is_err() {
            return Err(Error::SpvBadProofOfWork);
        }

        let next_hash = cached.bitcoin_hash();

        // store header in cache
        let result = self.insert_header(next_hash.clone(), cached.clone());
        if let Err(e) = result {
            return Err(Error::Downstream(format!("{}", e)));
        }
        if let Some(tip) = self.tip()? {
            if tip.stored.work() < cached.stored.work() {
                // higher POW than previous tip

                // compute path to new tip
                let mut forks_at = next.prev_blockhash;
                let mut path_to_new_tip = Vec::new();
                while self.pos_on_trunk(&forks_at).is_none() {
                    if let Some(h) = self.get_header(&forks_at)? {
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
                    self.save_trunk()?;
                    return Ok((cached, Some(unwinds), Some(path_to_new_tip)));
                } else {
                    self.trunk.extend(path_to_new_tip.iter().map(|h| *h));
                    self.save_trunk()?;
                    return Ok((cached, None, Some(path_to_new_tip)));
                }
            } else {
                self.save_trunk()?;
                return Ok((cached, None, None));
            }
        } else {
            self.save_trunk()?;
            return Err(Error::NoTip);
        }
    }

    /// position on trunk (chain with most work from genesis to tip)
    pub fn pos_on_trunk(&mut self, hash: &Sha256dHash) -> Option<u32> {
        self.load_trunk();
        self.trunk
            .iter()
            .rev()
            .position(|e| *e == *hash)
            .map(|p| (self.trunk.len() - p - 1) as u32)
    }

    /// retrieve the id of the block/header with most work
    pub fn tip(&mut self) -> OrgaResult<Option<CachedHeader>> {
        if let Some(id) = self.tip_hash() {
            return Ok(self.get_header(&id)?);
        }
        Ok(None)
    }

    pub fn tip_hash(&mut self) -> Option<Sha256dHash> {
        self.load_trunk();
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

    pub fn get_header_for_height(&mut self, height: u32) -> OrgaResult<Option<CachedHeader>> {
        self.load_trunk();
        if height < self.trunk.len() as u32 {
            println!("height greater than len");
            Ok(self.get_header(&self.trunk[height as usize])?)
        } else {
            println!("height less than len");
            Ok(None)
        }
    }
}

pub fn bytes_to_hashes(bytes: &[u8]) -> Result<Vec<Sha256dHash>, failure::Error> {
    if bytes.len() % 32 != 0 {
        bail!("Byte length should be a multiple of 32");
    }

    Ok(bytes
        .chunks_exact(32)
        .map(Sha256dHash::from_slice)
        .collect::<Result<Vec<Sha256dHash>, bitcoin::hashes::Error>>()?)
}

pub fn hashes_to_bytes<T>(hashes: T) -> Vec<u8>
where
    T: AsRef<[Sha256dHash]>,
{
    let hashes = hashes.as_ref();
    let mut bytes = Vec::with_capacity(hashes.len() * 32);
    for hash in hashes {
        bytes.extend(&hash.into_inner());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use nomic_bitcoin::bitcoin::hash_types::BlockHash as Sha256dHash;

    #[test]
    fn test_bytes_to_hashes() {
        let bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        ];
        let hashes = bytes_to_hashes(&bytes).unwrap();
        assert_eq!(
            hashes,
            [
                Sha256dHash::from_slice(&[0; 32]).unwrap(),
                Sha256dHash::from_slice(&[1; 32]).unwrap(),
                Sha256dHash::from_slice(&[2; 32]).unwrap(),
                Sha256dHash::from_slice(&[3; 32]).unwrap()
            ]
        );
    }

    #[test]
    fn test_hashes_to_bytes() {
        let hashes = [
            Sha256dHash::from_slice(&[0; 32]).unwrap(),
            Sha256dHash::from_slice(&[1; 32]).unwrap(),
            Sha256dHash::from_slice(&[2; 32]).unwrap(),
            Sha256dHash::from_slice(&[3; 32]).unwrap(),
        ];
        let bytes = hashes_to_bytes(&hashes);
        assert_eq!(
            bytes,
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3
            ]
        );
    }
}
