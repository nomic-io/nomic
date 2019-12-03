use nomic_client::{Client as PegClient, ClientError as PegClientError};
use nomic_work::work;
use rand::random;
use sha2::{Digest, Sha256};

const MIN_WORK: u64 = 1 << 20;

pub fn main() {
    println!("Running work program");
    let pub_key = base64::decode("mcobVGU+QG/nJHrlUL3v06aIFbhSEhPJ+GApWjh411Q=")
        .expect("Invalid base64 validator public key");
    let mut rpc = PegClient::new("localhost:26657").unwrap();
    let mut nonce = random::<u64>();
    loop {
        let work_value = try_nonce(&pub_key, nonce);
        if work_value >= MIN_WORK {
            rpc.submit_work_proof(&pub_key.to_vec(), nonce);
        }
        nonce += 1;
    }
}

fn try_nonce(pub_key_bytes: &[u8], nonce: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.input(pub_key_bytes);
    let nonce_bytes = nonce.to_be_bytes();
    hasher.input(&nonce_bytes);
    let hash = hasher.result().to_vec();

    work(&hash)
}
