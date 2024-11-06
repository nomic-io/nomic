use crate::error::Error;
use crate::error::Result as AppResult;
use alloy_primitives::Address as EthAddress;
use alloy_rlp::Decodable;
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use ethereum_triedb::{
    keccak::{keccak_256, KeccakHasher},
    EIP1186Layout, StorageProof,
};
use orga::coins::Amount;
use orga::encoding::LengthString;
use orga::encoding::{Decode, Encode};
use orga::{coins::Address, encoding::LengthVec};
use primitive_types::{H256, U256};
use rlp::{Decodable as _, Rlp};
use rlp_derive::RlpDecodable;
use trie_db::{Trie, TrieDBBuilder};

/// Account data from the Ethereum trie.
#[derive(RlpDecodable, Debug)]
struct Account {
    _nonce: u64,
    _balance: U256,
    storage_root: H256,
    _code_hash: H256,
}

// TODO: change error variants

/// Encoded raw merkle trie nodes
type EncodedProof = LengthVec<u8, LengthVec<u16, u8>>;
/// Proof of (dest, amount, sender) for a single index
type IndexProof = LengthVec<u8, EncodedProof>;

/// Minimal proof data to be included in a call.
#[derive(Debug, Encode, Decode, Clone)]
pub struct StateProof {
    pub address: Address,
    pub start_index: u64,
    pub account_proof: EncodedProof,
    pub storage_proofs: LengthVec<u16, IndexProof>,
}

impl StateProof {
    /// Creates a new `StateProof` from the given account proof and list of dest
    /// strings.
    pub fn from_response(
        proof: EIP1186AccountProofResponse,
        dests: Vec<(String, u64)>,
    ) -> AppResult<Self> {
        let start_index = dests[0].1;
        type Bytes = LengthVec<u16, u8>;
        let account_proof = proof
            .account_proof
            .into_iter()
            .map(|b| b.0.to_vec())
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()?;

        let mut state_proofs: Vec<IndexProof> = vec![];
        let mut cursor = 0;
        for (dest, _index) in dests {
            let mut state_proof_for_index: Vec<EncodedProof> = vec![];
            let n = 3 + extra_slots_required(dest.len());
            let storage_proofs_for_index = proof.storage_proof[cursor..cursor + n].to_vec();
            cursor += n;

            for spi in storage_proofs_for_index {
                let storage_proof: EncodedProof = spi
                    .proof
                    .iter()
                    .map(|b| b.0.to_vec())
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<Bytes>, _>>()?
                    .try_into()?;
                state_proof_for_index.push(storage_proof);
            }

            state_proofs.push(
                state_proof_for_index
                    .try_into()
                    .map_err(|_e| Error::Relayer("Invalid storage proof".to_string()))?,
            );
        }

        Ok(Self {
            address: Address::from(proof.address.0 .0),
            start_index,
            account_proof,
            storage_proofs: state_proofs
                .try_into()
                .map_err(|_e| Error::Relayer("Invalid storage proof".to_string()))?,
        })
    }

    /// Verifies the proof against the given state root and returns the decoded
    /// data.
    pub fn verify(self, state_root: [u8; 32]) -> AppResult<Vec<BridgeContractData>> {
        let result = verify_key(
            state_root,
            keccak_256(self.address.bytes().as_slice()).as_slice(),
            &self.account_proof,
        )?
        .ok_or_else(|| Error::Relayer("Empty account".to_string()))?;
        let account = Account::decode(&Rlp::new(&result))
            .map_err(|e| Error::Relayer(format!("Failed to decode account: {}", e)))?;

        let mut verified = vec![];
        let root = account.storage_root.0;

        for (i, storage_proof) in self.storage_proofs.iter().enumerate() {
            if storage_proof.len() < 3 {
                return Err(Error::Relayer("Storage proof is too short".to_string()));
            }
            let index = self.start_index + i as u64;
            let dest_key = BridgeContractData::dest_key(index);
            let amount_key = BridgeContractData::amount_key(index);
            let sender_key = BridgeContractData::sender_key(index);

            let dest_bytes = verify_key(
                root,
                keccak_256(dest_key.as_slice()).as_slice(),
                &storage_proof[0],
            )?
            .ok_or_else(|| Error::Relayer("Empty dest".to_string()))?;

            let amount_bytes = verify_key(
                root,
                keccak_256(amount_key.as_slice()).as_slice(),
                &storage_proof[1],
            )?;
            let return_amount: u64 = amount_bytes
                .map(|b| Decodable::decode(&mut b.as_slice()))
                .transpose()
                .map_err(|e| Error::Relayer(format!("Failed to decode return amount: {}", e)))?
                .unwrap_or_default();

            let sender_bytes_rlp = verify_key(
                root,
                keccak_256(sender_key.as_slice()).as_slice(),
                &storage_proof[2],
            )?
            .ok_or_else(|| Error::Relayer("Empty sender".to_string()))?;
            let sender_bytes = Rlp::new(&sender_bytes_rlp).data().map_err(|e| {
                Error::Relayer(format!("Failed to decode return sender RLP: {}", e))
            })?;
            if sender_bytes.len() > 20 {
                return Err(Error::Relayer("Invalid sender address length".to_string()));
            }
            let mut sender_bytes_buf = [0u8; 20];
            sender_bytes_buf[20 - sender_bytes.len()..].copy_from_slice(sender_bytes);
            let sender_addr = EthAddress::from_slice(&sender_bytes_buf);

            // check if dest_bytes low bit is set
            let lowest_bit = dest_bytes[dest_bytes.len() - 1] & 1;
            let dest_str: String = if lowest_bit == 1 {
                // length is stored

                let dest_len: u64 = Decodable::decode(&mut dest_bytes.as_slice()).map_err(|e| {
                    Error::Relayer(format!("Failed to decode return dest length: {}", e))
                })?;

                let dest_len = (dest_len / 2).saturating_sub(1);

                let extra_storage_slots = (dest_len + 31) / 32;

                if storage_proof.len() as u64 != 3 + extra_storage_slots {
                    return Err(Error::Relayer(
                        "Invalid number of dest storage proofs".to_string(),
                    ));
                }

                let mut dest_str = String::new();

                for i in 0..extra_storage_slots {
                    let dest_chunk = verify_key(
                        root,
                        keccak_256(BridgeContractData::dest_chunk_key(index, i).as_slice())
                            .as_slice(),
                        &storage_proof[i as usize + 3],
                    )?
                    .ok_or_else(|| Error::Relayer("Empty dest chunk".to_string()))?;

                    let chunk_str: String =
                        Decodable::decode(&mut dest_chunk.as_slice()).map_err(|e| {
                            Error::Relayer(format!("Failed to decode return dest part: {}", e))
                        })?;
                    dest_str += chunk_str.as_str().trim_end_matches(char::from(0));
                }

                Ok(dest_str)
            } else {
                // string stored inline
                let data = Rlp::new(&dest_bytes).data().map_err(|e| {
                    Error::Relayer(format!("Failed to decode return dest RLP: {}", e))
                })?;
                if data.len() != 32 {
                    return Err(Error::Relayer("Invalid dest data length".to_string()));
                }
                let length = (data[31] / 2) as usize;
                // TODO: handle strings with invalid utf8
                String::from_utf8(data[..length].to_vec())
                    .map_err(|e| Error::Relayer(format!("Failed to decode return dest: {}", e)))
            }
            .map_err(|e| Error::Relayer(format!("Failed to decode return dest: {}", e)))?;

            verified.push(BridgeContractData {
                dest: dest_str.try_into()?,
                amount: return_amount.into(),
                sender: Address::from(sender_addr.0 .0),
                index,
            });
        }

        Ok(verified)
    }
}

/// Verifies and returns the value at the provided key in the trie with the
/// given root and encoded proof.
fn verify_key(root: [u8; 32], key: &[u8], proof: &EncodedProof) -> AppResult<Option<Vec<u8>>> {
    let root = H256(root);
    let proof_data: Vec<_> = proof.iter().map(|b| b.to_vec()).collect();
    let db = StorageProof::new(proof_data).into_memory_db::<KeccakHasher>();
    let trie = TrieDBBuilder::<EIP1186Layout<KeccakHasher>>::new(&db, &root).build();
    trie.get(key)
        .map_err(|e| Error::Relayer(format!("TrieError: {}", e)))
}

/// Data proven by a [StateProof].
#[derive(Debug, Clone)]
pub struct BridgeContractData {
    pub dest: LengthString<u16>,
    pub amount: Amount,
    pub sender: Address,
    pub index: u64,
}

impl BridgeContractData {
    /// Slot in the trie for the dest strings of the return message queue.
    pub const RETURN_DESTS_SLOT: u64 = 7;
    /// Slot in the trie for the fund amounts of the return message queue.
    pub const RETURN_AMOUNTS_SLOT: u64 = 8;
    /// Slot in the trie for the sender addresses of the return message queue.
    pub const RETURN_SENDERS_SLOT: u64 = 9;

    /// Returns the trie keys for the given dest string at the given return
    /// queue index.
    pub fn dest_keys(value: &str, index: u64) -> Vec<[u8; 32]> {
        let num_keys = 1 + (value.len() + 31) / 32;

        let mut res = vec![];
        let slot_key = Self::get_key(index.into(), Self::RETURN_DESTS_SLOT.into());

        res.push(slot_key);
        let base = keccak_256(slot_key.as_slice());

        for i in 0..num_keys - 1 {
            let key = U256::from_big_endian(base.as_slice()).saturating_add(U256::from(i));
            let mut key_bytes = [0u8; 32];
            key.to_big_endian(&mut key_bytes);

            res.push(key_bytes)
        }

        res
    }

    /// Returns the trie key for the head of the dest string at the given return
    /// queue index.
    pub fn dest_key(index: u64) -> [u8; 32] {
        let index = U256::from(index);
        Self::get_key(index, Self::RETURN_DESTS_SLOT.into())
    }

    /// Returns the trie key for the sender address at the given return queue
    /// index.
    pub fn sender_key(index: u64) -> [u8; 32] {
        let index = U256::from(index);
        Self::get_key(index, Self::RETURN_SENDERS_SLOT.into())
    }

    /// Returns the trie key for the fund amount at the given return queue
    /// index.
    pub fn amount_key(index: u64) -> [u8; 32] {
        let index = U256::from(index);
        Self::get_key(index, Self::RETURN_AMOUNTS_SLOT.into())
    }

    /// Returns the trie key for the chunk of the dest string at the given
    /// return queue index.
    pub fn dest_chunk_key(index: u64, chunk_index: u64) -> [u8; 32] {
        let slot_key = Self::dest_key(index);
        let chunk_base = keccak_256(slot_key.as_slice());
        let key =
            U256::from_big_endian(chunk_base.as_slice()).saturating_add(U256::from(chunk_index));
        let mut key_bytes = [0u8; 32];
        key.to_big_endian(&mut key_bytes);

        key_bytes
    }

    /// Returns the trie key for the given index and slot.
    fn get_key(index: U256, slot: U256) -> [u8; 32] {
        let mut index_bytes = [0u8; 32];
        index.to_big_endian(&mut index_bytes);
        let mut slot_bytes = [0u8; 32];
        slot.to_big_endian(&mut slot_bytes);

        keccak_256([index_bytes, slot_bytes].concat().as_slice())
    }
}

/// Returns the number of extra 32-byte slots required to store the given length
/// of string data.
///
/// Strings less than 32 bytes can be stored inline in one slot, while longer
/// strings are chunked across additional slots.
pub fn extra_slots_required(len: usize) -> usize {
    (len + 31) / 32
}
