use crate::error::Result;
use crate::{Address, Signature};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::BlockHeader;
use nomic_bitcoin::bitcoin;
use secp256k1::{Secp256k1, VerifyOnly};
use serde::{de::Deserializer, ser::SerializeSeq, Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Transaction {
    Header(HeaderTransaction),
    WorkProof(WorkProofTransaction),
    Deposit(DepositTransaction),
    Transfer(TransferTransaction),
    Withdrawal(WithdrawalTransaction),
    Signature(SignatureTransaction),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderTransaction {
    pub block_headers: Vec<BlockHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkProofTransaction {
    pub public_key: Vec<u8>,
    pub nonce: u64,
}

fn encode_partial_merkle_tree<S: Serializer>(
    proof: &PartialMerkleTree,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    let encoded = serialize(proof);
    let mut seq = serializer.serialize_seq(Some(encoded.len()))?;
    for byte in encoded {
        seq.serialize_element(&byte)?;
    }
    seq.end()
}

fn decode_partial_merkle_tree<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<PartialMerkleTree, D::Error> {
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    let bytes: PartialMerkleTree = deserialize(&bytes[..]).map_err(|_e| {
        serde::de::Error::custom(format!("Failed to deserialize bitcoin merkle proof"))
    })?;
    Ok(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositTransaction {
    pub height: u32,
    #[serde(
        serialize_with = "encode_partial_merkle_tree",
        deserialize_with = "decode_partial_merkle_tree"
    )]
    pub proof: bitcoin::util::merkleblock::PartialMerkleTree,
    pub tx: bitcoin::Transaction,
    pub block_index: u32,
    pub recipients: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WithdrawalTransaction {
    pub from: Vec<u8>,
    pub to: bitcoin::Script,
    pub amount: u64,
    pub signature: Vec<u8>,
    pub nonce: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignatureTransaction {
    pub signature: Vec<u8>,
    pub signatory_index: u16,
}

/// Transfer coins from one account to another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTransaction {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub amount: u64,
    pub signature: Vec<u8>,
    pub nonce: u64,
    pub fee_amount: u64,
}

fn verify_signature<S: Sighash>(
    secp: &Secp256k1<VerifyOnly>,
    signature: &[u8],
    pubkey: &[u8],
    tx: &S
) -> Result<bool> {
    use secp256k1::{Message, PublicKey, Signature};
    let sighash = Message::from_slice(tx.sighash()?.as_slice())?;
    let signature = Signature::from_compact(signature)?;
    let pubkey = PublicKey::from_slice(pubkey)?;
    if let Err(_) = secp.verify(&sighash, &signature, &pubkey) {
        Ok(false)
    } else {
        Ok(true)
    }
}

impl TransferTransaction {
    pub fn verify_signature(&self, secp: &Secp256k1<VerifyOnly>) -> Result<bool> {
        verify_signature(
            secp,
            self.signature.as_slice(),
            self.from.as_slice(),
            self
        )
    }
}
impl WithdrawalTransaction {
    pub fn verify_signature(&self, secp: &Secp256k1<VerifyOnly>) -> Result<bool> {
        verify_signature(
            secp,
            self.signature.as_slice(),
            self.from.as_slice(),
            self
        )
    }
}
pub trait Sighash {
    fn sighash_input(&self) -> Result<Vec<u8>>;

    fn sighash(&self) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.input(self.sighash_input()?.as_slice());
        Ok(hasher.result().to_vec())
    }

   
}

impl Sighash for TransferTransaction {
    fn sighash_input(&self) -> Result<Vec<u8>> {
        let mut sighash_tx = self.clone();
        sighash_tx.signature = vec![];
        Ok(bincode::serialize(&sighash_tx)?)
    }
}

impl Sighash for WithdrawalTransaction {
    fn sighash_input(&self) -> Result<Vec<u8>> {
        let mut sighash_tx = self.clone();
        sighash_tx.signature = vec![];
        Ok(bincode::serialize(&sighash_tx)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_sighash_input() {
        let tx = TransferTransaction {
            from: vec![1; 33],
            to: vec![2; 33],
            amount: 123,
            signature: vec![1, 2, 3, 4],
            nonce: 5,
            fee_amount: 1000,
        };

        assert_eq!(
            tx.sighash_input().unwrap(),
            vec![
                33, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 33, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 232, 3,
                0, 0, 0, 0, 0, 0
            ]
        );
    }
}
