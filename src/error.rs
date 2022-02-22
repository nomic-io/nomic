#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Bitcoin(#[from] bitcoin::util::Error),
    #[error(transparent)]
    BitcoinHash(#[from] bitcoin::hashes::Error),
    #[error(transparent)]
    BitcoinRpc(#[from] bitcoincore_rpc::Error),
    #[error("{0}")]
    Header(String),
    #[error(transparent)]
    Orga(#[from] orga::Error),
    #[error("{0}")]
    Relayer(String),
    #[error("Unknown Error")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, Error>;
