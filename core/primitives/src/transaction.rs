use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::BlockHeader;
use nomic_bitcoin::bitcoin;

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
    pub version: u32,
    pub prev_blockhash: Sha256dHash,
    pub merkle_root: Sha256dHash,
    pub time: u32,
    pub bits: u32,
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
    pub public_key: Vec<u8>,
    pub nonce: u64,
}
