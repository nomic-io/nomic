#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Bitcoin(#[from] bitcoin::util::Error),
    #[error("{0}")]
    Header(String),
    #[error(transparent)]
    Orga(#[from] orga::Error),
    #[error("Unknown Error")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, Error>;
