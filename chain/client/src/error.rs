pub use failure::Error;
pub type Result<T> = std::result::Result<T, Error>;

pub use tendermint::rpc::Error as RpcError;
