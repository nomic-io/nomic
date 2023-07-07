#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Bitcoin(#[from] bitcoin::Error),
    #[error(transparent)]
    BitcoinHash(#[from] bitcoin::hashes::Error),
    #[error("{0}")]
    BitcoinPubkeyHash(String),
    #[cfg(feature = "full")]
    #[error(transparent)]
    BitcoinCoreRpc(#[from] bitcoind::bitcoincore_rpc::Error),
    #[error(transparent)]
    BitcoinEncode(#[from] bitcoin::consensus::encode::Error),
    #[error(transparent)]
    Bip32(#[from] bitcoin::util::bip32::Error),
    #[error(transparent)]
    Sighash(#[from] bitcoin::util::sighash::Error),
    #[error(transparent)]
    TryFrom(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Secp(#[from] bitcoin::secp256k1::Error),
    #[error("Invalid Deposit Address")]
    InvalidDepositAddress,
    #[error("Could not verify merkle proof")]
    BitcoinMerkleBlockError,
    #[cfg(feature = "full")]
    #[error(transparent)]
    BitcoinRpc(#[from] bitcoincore_rpc_async::Error),
    #[cfg(feature = "csv")]
    #[error(transparent)]
    Csv(#[from] csv::Error),
    #[error("{0}")]
    Test(String),
    #[error("{0}")]
    Address(String),
    #[error("{0}")]
    Header(String),
    #[error("{0}")]
    Ibc(String),
    #[error(transparent)]
    Orga(#[from] orga::Error),
    #[error(transparent)]
    Ed(#[from] ed::Error),
    #[error("{0}")]
    Relayer(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Warp Rejection")]
    WarpRejection(),
    #[error("Unknown Error")]
    Unknown,
}

#[cfg(feature = "full")]
impl From<warp::Rejection> for Error {
    fn from(_: warp::Rejection) -> Self {
        Error::WarpRejection()
    }
}

#[cfg(feature = "full")]
impl warp::reject::Reject for Error {}

impl From<Error> for orga::Error {
    fn from(err: Error) -> Self {
        if let Error::Orga(err) = err {
            err
        } else {
            orga::Error::App(err.to_string())
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
