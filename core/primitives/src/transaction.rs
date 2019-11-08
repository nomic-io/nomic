use bitcoin::BlockHeader;

pub enum Transaction {
    Headers { block_headers: Vec<BlockHeader> },
    Deposit,
    SignatoryCommitment,
    SignatorySignature,
}
