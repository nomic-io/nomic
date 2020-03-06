use bitcoin::BlockHeader;
use nomic_bitcoin::bitcoin;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Transaction {
    Header(HeaderTransaction),
    WorkProof(WorkProofTransaction),
    Deposit,
    SignatoryCommitment,
    SignatorySignature,
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
