#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Bitcoin(#[from] bitcoin::Error),
    #[error(transparent)]
    BitcoinHash(#[from] bitcoin::hashes::Error),
    #[error(transparent)]
    BitcoinEncode(#[from] bitcoin::consensus::encode::Error),
    #[error("Could not verify merkle proof")]
    BitcoinMerkleBlockError,
    #[error(transparent)]
    SapioBitcoin(#[from] bitcoincore_rpc_async::bitcoin::util::Error),
    #[error(transparent)]
    SapioBitcoinHash(#[from] bitcoincore_rpc_async::bitcoin::hashes::Error),
    #[error(transparent)]
    SapioBitcoinEncode(#[from] bitcoincore_rpc_async::bitcoin::consensus::encode::Error),
    #[cfg(feature = "full")]
    #[error(transparent)]
    BitcoinRpc(#[from] bitcoincore_rpc_async::Error),
    #[error("{0}")]
    Header(String),
    #[error(transparent)]
    Orga(#[from] orga::Error),
    #[error("{0}")]
    Relayer(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Unknown Error")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, Error>;
