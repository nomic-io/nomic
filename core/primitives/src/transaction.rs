use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::BlockHeader;
use nomic_bitcoin::bitcoin;
use serde::{de::Deserializer, ser::SerializeSeq, Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Transaction {
    Header(HeaderTransaction),
    WorkProof(WorkProofTransaction),
    Deposit(DepositTransaction),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderTransaction {
    pub block_headers: Vec<BlockHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkProofTransaction {
    pub public_key: Vec<u8>,
    pub nonce: u64,
}

fn encode_partial_merkle_tree<S: Serializer>(
    proof: &PartialMerkleTree,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let encoded = serialize(proof);
    let mut seq = serializer.serialize_seq(Some(encoded.len()))?;
    for byte in encoded {
        seq.serialize_element(&byte)?;
    }
    seq.end()
}

fn decode_partial_merkle_tree<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<PartialMerkleTree, D::Error> {
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    let bytes: PartialMerkleTree = deserialize(&bytes[..]).map_err(|_e| {
        serde::de::Error::custom(format!("Failed to deserialize bitcoin merkle proof"))
    })?;
    Ok(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositTransaction {
    pub height: u32,
    #[serde(
        serialize_with = "encode_partial_merkle_tree",
        deserialize_with = "decode_partial_merkle_tree"
    )]
    pub proof: bitcoin::util::merkleblock::PartialMerkleTree,
    pub tx: bitcoin::Transaction,
    pub block_index: u32,
    pub recipients: Vec<Vec<u8>>,
}
