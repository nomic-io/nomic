use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::BlockHeader;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Transaction {
    Header(HeaderTransaction),
    WorkProof(WorkProofTransaction),
    Deposit,
    SignatoryCommitment,
    SignatorySignature,
}

#[derive(Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderTransaction {
    #[serde(
        deserialize_with = "deserialize_vec_blockheaders",
        serialize_with = "serialize_vec_blockheaders"
    )]
    pub block_headers: Vec<BlockHeader>,
}

fn serialize_vec_blockheaders<'de, S>(
    block_headers: &Vec<BlockHeader>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    #[derive(Serialize)]
    struct Wrapper<'a>(#[serde(with = "BlockHeaderDef")] &'a BlockHeader);

    let wrappers: Vec<Wrapper> = block_headers.iter().map(Wrapper).collect();
    wrappers.serialize(serializer)
}

fn deserialize_vec_blockheaders<'de, D>(deserializer: D) -> Result<Vec<BlockHeader>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrapper(#[serde(with = "BlockHeaderDef")] BlockHeader);

    let v = Vec::deserialize(deserializer)?;
    Ok(v.into_iter().map(|Wrapper(a)| a).collect())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkProofTransaction {
    public_key: Vec<u8>,
    nonce: u64,
}
