use bitcoin::BlockHeader;

#[derive(Debug, Clone)]
pub enum Transaction {
    Header(HeaderTransaction),
    Deposit,
    SignatoryCommitment,
    SignatorySignature,
}

#[derive(Debug, Clone)]
pub struct HeaderTransaction {
    pub block_headers: Vec<BlockHeader>,
}
