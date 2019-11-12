use bitcoin::BlockHeader;

#[derive(Debug)]
pub enum Transaction {
    Header(HeaderTransaction),
    Deposit,
    SignatoryCommitment,
    SignatorySignature,
}

#[derive(Debug)]
pub struct HeaderTransaction {
    pub block_headers: Vec<BlockHeader>,
}
