#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Bitcoin(#[from] bitcoin::util::Error),
    #[error(transparent)]
    BitcoinHash(#[from] bitcoin::hashes::Error),
    #[error(transparent)]
    SapioBitcoin(#[from] bitcoincore_rpc_async::bitcoin::util::Error),
    #[error(transparent)]
    SapioBitcoinHash(#[from] bitcoincore_rpc_async::bitcoin::hashes::Error),
    #[cfg(feature = "full")]
    #[error(transparent)]
    BitcoinRpc(#[from] bitcoincore_rpc_async::Error),
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
