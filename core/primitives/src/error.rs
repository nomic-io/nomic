use failure::Fail;
use nomic_bitcoin::bitcoin::util::merkleblock::MerkleBlockError;
use std::fmt;

pub type Result<T> = std::result::Result<T, failure::Error>;

#[derive(Debug, Fail)]
pub enum Error {
    BitcoinMerkleBlockError(MerkleBlockError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BitcoinMerkleBlockError(err) => write!(f, "{:?}", err),
        }
    }
}

impl From<MerkleBlockError> for Error {
    fn from(err: MerkleBlockError) -> Self {
        Error::BitcoinMerkleBlockError(err)
    }
}
