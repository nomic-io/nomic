use bitcoin::BlockHeader;

pub enum Transaction {
    Headers(HeaderTransaction),
    Deposit,
    SignatoryCommitment,
    SignatorySignature,
}

#[derive(Debug)]
pub struct HeaderTransaction {
    pub block_headers: Vec<BlockHeader>,
}
