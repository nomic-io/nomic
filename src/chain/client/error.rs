pub use failure::Error;
pub type Result<T> = std::result::Result<T, Error>;

pub use tendermint_rpc::Error as RpcError;
