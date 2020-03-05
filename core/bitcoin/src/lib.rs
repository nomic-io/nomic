pub use bitcoin;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::BlockHeader;
pub use bitcoincore_rpc;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(remote = "BlockHeader")]
pub struct BlockHeaderDef {
    /// The protocol version. Should always be 1.
    pub version: u32,
    /// Reference to the previous block in the chain
    pub prev_blockhash: Sha256dHash,
    /// The root hash of the merkle tree of transactions in the block
    pub merkle_root: Sha256dHash,
    /// The timestamp of the block, as claimed by the miner
    pub time: u32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course)
    pub bits: u32,
    /// The nonce, selected to obtain a low enough blockhash
    pub nonce: u32,
}

#[derive(Serialize, Deserialize)]
pub struct EnrichedHeader {
    pub height: u32,
    #[serde(with = "BlockHeaderDef")]
    pub header: BlockHeader,
}
