use log::info;
use nomic_bitcoin::bitcoin;
use nomic_primitives::Result;
use nomic_signatory_set::SignatorySet;
use sha2::Digest;
use std::fs;
use std::path::Path;

pub struct Wallet {
    privkey: secp256k1::SecretKey,
}

impl Wallet {
    pub fn load_or_generate<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        let privkey_bytes = if path.exists() {
            info!("Loading existing wallet from {:?}", path);
            fs::read(path)?
        } else {
            info!("Generating new wallet at {:?}", path);
            let bytes: [u8; 32] = rand::random();
            fs::write(path, bytes)?;
            bytes.to_vec()
        };

        let privkey = secp256k1::SecretKey::from_slice(privkey_bytes.as_slice())?;

        Ok(Wallet { privkey })
    }

    pub fn pubkey(&self) -> bitcoin::PublicKey {
        let secp = secp256k1::Secp256k1::signing_only();
        let key = secp256k1::PublicKey::from_secret_key(&secp, &self.privkey);
        bitcoin::PublicKey {
            compressed: true,
            key,
        }
    }

    pub fn deposit_address(&self, signatories: &SignatorySet) -> bitcoin::Address {
        let script = nomic_signatory_set::redeem_script(signatories, self.receive_address());
        bitcoin::Address::p2wsh(&script, bitcoin::Network::Testnet)
    }

    pub fn receive_address(&self) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.input(self.pubkey().to_bytes());
        hasher.result().to_vec()
    }
}
