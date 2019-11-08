use bitcoin::BlockHeader;

pub enum Transaction {
    Headers(HeaderTransaction),
    Deposit,
    SignatoryCommitment,
    SignatorySignature,
}

#[derive(Debug)]
pub struct HeaderTransaction {
    block_headers: Vec<BlockHeader>,
}
