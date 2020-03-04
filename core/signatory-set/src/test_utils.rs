use super::*;
use bitcoin::{PublicKey, PrivateKey};
use bitcoin::secp256k1::{Secp256k1, SecretKey};

pub fn mock_pubkey(byte: u8) -> PublicKey {
    let secp = Secp256k1::new();
    let privkey = PrivateKey {
        compressed: true,
        network: bitcoin::Network::Regtest,
        key: SecretKey::from_slice(&[byte; 32]).unwrap()
    };
    privkey.public_key(&secp)
}

pub fn mock_signatory(key_byte: u8, voting_power: u32) -> Signatory {
    Signatory::new(mock_pubkey(key_byte), voting_power)
}

pub fn mock_signatory_set(count: usize) -> SignatorySet {
    let mut signatories = SignatorySet::new();
    for i in 1..=count {
        signatories.set(mock_signatory(i as u8, i as u32));
    }
    signatories
}
