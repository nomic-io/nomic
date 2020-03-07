//
// Copyright 2018-2019 Tamas Blummer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//!
//! # Murmel Error
//!
//! All modules of this library use this error class to indicate problems.
//!
use bitcoin::consensus::encode;
use bitcoin::util;
use bitcoin::util::bip158;
use nomic_bitcoin::bitcoin;
use std::convert;
use std::fmt;
use std::io;

/// An error class to offer a unified error interface upstream
pub enum Error {
    /// the block's work target is not correct
    SpvBadTarget,
    /// bad proof of work
    SpvBadProofOfWork,
    /// unconnected header chain detected
    UnconnectedHeader,
    /// no chain tip found
    NoTip,
    /// no peers to connect to
    NoPeers,
    /// unknown UTXO referred
    UnknownUTXO,
    /// Merkle root of block does not match the header
    BadMerkleRoot,
    /// downstream error
    Downstream(String),
    /// Network IO error
    IO(io::Error),
    /// Bitcoin util error
    Util(util::Error),
    /// Bitcoinserialize error
    Serialize(encode::Error),
    /// Handshake failure
    Handshake,
    /// lost connection
    Lost(String),
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::SpvBadTarget => "bad proof of work target",
            Error::SpvBadProofOfWork => "bad proof of work",
            Error::UnconnectedHeader => "unconnected header",
            Error::NoTip => "no chain tip found",
            Error::UnknownUTXO => "unknown utxo",
            Error::NoPeers => "no peers",
            Error::BadMerkleRoot => "merkle root of header does not match transaction list",
            Error::Downstream(ref s) => s,
            Error::IO(ref err) => err.description(),
            Error::Util(ref err) => err.description(),
            Error::Serialize(ref err) => err.description(),
            Error::Handshake => "handshake",
            Error::Lost(ref s) => s,
        }
    }

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::SpvBadTarget => None,
            Error::SpvBadProofOfWork => None,
            Error::UnconnectedHeader => None,
            Error::NoTip => None,
            Error::NoPeers => None,
            Error::UnknownUTXO => None,
            Error::Downstream(_) => None,
            Error::BadMerkleRoot => None,
            Error::IO(ref err) => Some(err),
            Error::Util(ref err) => Some(err),
            Error::Serialize(ref err) => Some(err),
            Error::Handshake => None,
            Error::Lost(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            Error::SpvBadTarget
            | Error::SpvBadProofOfWork
            | Error::UnconnectedHeader
            | Error::NoTip
            | Error::NoPeers
            | Error::BadMerkleRoot
            | Error::Handshake
            | Error::UnknownUTXO => {
                use std::error::Error;
                write!(f, "{}", self.description())
            }
            Error::Lost(ref s) | Error::Downstream(ref s) => write!(f, "{}", s),
            Error::IO(ref err) => write!(f, "IO error: {}", err),
            Error::Util(ref err) => write!(f, "Util error: {}", err),
            Error::Serialize(ref err) => write!(f, "Serialize error: {}", err),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self as &dyn fmt::Display).fmt(f)
    }
}

impl convert::From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        match err {
            Error::IO(e) => e,
            _ => {
                use std::error::Error;
                io::Error::new(io::ErrorKind::Other, err.description())
            }
        }
    }
}

impl convert::From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl convert::From<util::Error> for Error {
    fn from(err: util::Error) -> Error {
        Error::Util(err)
    }
}

impl convert::From<encode::Error> for Error {
    fn from(err: encode::Error) -> Error {
        Error::Serialize(err)
    }
}

impl convert::From<Box<dyn std::error::Error>> for Error {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        Error::Downstream(err.description().to_owned())
    }
}

impl convert::From<bip158::Error> for Error {
    fn from(err: bip158::Error) -> Self {
        match err {
            bip158::Error::Io(io) => Error::IO(io),
            bip158::Error::UtxoMissing(_) => Error::UnknownUTXO,
        }
    }
}
