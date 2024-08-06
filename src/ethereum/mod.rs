use alloy_core::{primitives::keccak256, sol_types::SolValue};
use bitcoin::secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};
use std::u64;

use ed::{Decode, Encode};
use orga::{
    coins::{Address, Coin, Give},
    collections::{ChildMut, Deque, Ref},
    encoding::LengthVec,
    migrate::Migrate,
    orga,
    query::FieldQuery,
    state::State,
    store::Store,
    Error,
};
use serde::Serialize;

use crate::{
    bitcoin::{
        signatory::SignatorySet,
        threshold_sig::{Pubkey, Signature, ThresholdSig},
        Nbtc,
    },
    error::Result,
};

// TODO: message ttl/pruning
// TODO: message signing
// TODO: multi-token support

pub const VALSET_INTERVAL: u64 = 60 * 60 * 24;

fn bytes32(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() > 32 {
        return Err(Error::App("bytes too long".to_string()).into());
    }

    let mut padded = [0; 32];
    padded[..bytes.len()].copy_from_slice(bytes);
    Ok(padded)
}

fn uint256(n: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    bytes
}

fn addr_to_bytes32(addr: Address) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[12..].copy_from_slice(&addr.bytes());
    bytes
}

#[orga]
pub struct Ethereum {
    pub id: [u8; 32],
    pub token_contract: Address,
    pub outbox: Deque<OutMessage>,
    pub outbox_index: u64,
    pub coins: Coin<Nbtc>,
    pub valset: SignatorySet,
}

#[orga]
impl Ethereum {
    pub fn step(&mut self, active_sigset: &SignatorySet) -> Result<()> {
        if active_sigset.create_time - self.valset.create_time >= VALSET_INTERVAL {
            let mut new_valset = active_sigset.clone();
            new_valset.normalize_vp(u32::MAX as u64);
            new_valset.index = self.valset.index + 1;
            self.update_valset(new_valset)?;
        }

        Ok(())
    }

    pub fn transfer(&mut self, _to: Address, coins: Coin<Nbtc>) -> Result<()> {
        self.coins.give(coins)?;

        // TODO: push to building transfer batch

        todo!()
    }

    pub fn logic_call(
        &mut self,
        _contract: Address,
        coins: Coin<Nbtc>,
        _payload: LengthVec<u16, u8>,
    ) -> Result<()> {
        self.coins.give(coins)?;

        // TODO: push logic call to outbox

        todo!()
    }

    fn update_valset(&mut self, new_valset: SignatorySet) -> Result<()> {
        assert_eq!(new_valset.index, self.valset.index + 1);

        self.push_outbox(OutMessage {
            sigs: ThresholdSig::from_sigset(&self.valset)?,
            msg: OutMessageArgs::UpdateValset(new_valset.clone()),
        })?;

        self.valset = new_valset;

        Ok(())
    }

    fn push_outbox(&mut self, msg: OutMessage) -> Result<()> {
        self.outbox.push_back(msg)?;
        self.outbox_index += 1;
        Ok(())
    }

    pub fn sign(&mut self, msg_index: u64, pubkey: Pubkey, sig: Signature) -> Result<()> {
        let mut msg = self.get_mut(msg_index)?;
        msg.sigs.sign(pubkey, sig)?;
        Ok(())
    }

    pub fn get(&self, msg_index: u64) -> Result<Ref<OutMessage>> {
        let index = self.abs_index(msg_index)?;
        Ok(self.outbox.get(index)?.unwrap())
    }

    pub fn get_mut(&mut self, msg_index: u64) -> Result<ChildMut<u64, OutMessage>> {
        let index = self.abs_index(msg_index)?;
        Ok(self.outbox.get_mut(index)?.unwrap())
    }

    fn abs_index(&self, msg_index: u64) -> Result<u64> {
        if msg_index > self.outbox_index {
            return Err(Error::App("message index out of bounds".to_string()).into());
        }

        let index = self.outbox_index - msg_index;
        if index >= self.outbox.len() {
            return Err(Error::App("message index out of bounds".to_string()).into());
        }

        Ok(index)
    }
}

#[orga]
pub struct OutMessage {
    pub sigs: ThresholdSig,
    pub msg: OutMessageArgs,
}

#[derive(Encode, Decode, Debug, Clone, Serialize)]
pub enum OutMessageArgs {
    Batch {
        transfers: LengthVec<u16, Transfer>,
        timeout: u64,
    },
    LogicCall(LogicCall),
    UpdateValset(SignatorySet),
}

impl OutMessageArgs {
    pub fn hash(&self, id: [u8; 32], nonce: u64, token_contract: Address) -> [u8; 32] {
        match self {
            OutMessageArgs::Batch { transfers, timeout } => {
                batch_hash(id, nonce, transfers, token_contract, timeout)
            }
            OutMessageArgs::LogicCall(call) => call.hash(id, token_contract),
            OutMessageArgs::UpdateValset(valset) => checkpoint_hash(id, valset),
        }
    }
}

impl State for OutMessageArgs {
    fn load(_store: Store, bytes: &mut &[u8]) -> orga::Result<Self> {
        Ok(Self::decode(bytes)?)
    }

    fn attach(&mut self, _store: Store) -> orga::Result<()> {
        Ok(())
    }

    fn flush<W: std::io::Write>(self, out: &mut W) -> orga::Result<()> {
        Ok(self.encode_into(out)?)
    }

    fn field_keyop(_field_name: &str) -> Option<orga::describe::KeyOp> {
        todo!()
    }
}

impl FieldQuery for OutMessageArgs {
    type FieldQuery = ();

    fn field_query(&self, _query: Self::FieldQuery) -> orga::Result<()> {
        Ok(())
    }
}

impl Migrate for OutMessageArgs {}

// TODO: we shouldn't require all orga types to have Default
impl Default for OutMessageArgs {
    fn default() -> Self {
        OutMessageArgs::Batch {
            transfers: LengthVec::default(),
            timeout: u64::MAX,
        }
    }
}

#[orga]
#[derive(Debug, Clone)]
pub struct LogicCall {
    pub logic_contract: Address,
    pub transfer_amount: u64,
    pub fee_amount: u64,
    pub payload: LengthVec<u16, u8>,
    pub timeout: u64,
    pub invalidation_id: [u8; 32],
    pub invalidation_nonce: [u8; 32],
}

impl LogicCall {
    pub fn hash(&self, id: [u8; 32], token_contract: Address) -> [u8; 32] {
        let bytes = (
            id,
            bytes32(b"logicCall").unwrap(),
            self.logic_contract.bytes(),
            vec![self.transfer_amount],
            vec![token_contract.bytes()],
            vec![self.fee_amount],
            vec![token_contract.bytes()],
            self.payload.as_slice(),
            self.timeout,
            self.invalidation_id,
            self.invalidation_nonce,
        )
            .abi_encode_params();

        keccak256(bytes).0
    }
}

#[orga]
#[derive(Debug, Clone)]
pub struct Transfer {
    pub dest: Address,
    pub amount: u64,
    pub fee_amount: u64,
}

pub fn checkpoint_hash(id: [u8; 32], valset: &SignatorySet) -> [u8; 32] {
    let powers = valset
        .signatories
        .iter()
        .map(|s| s.voting_power)
        .collect::<Vec<_>>();

    let bytes = (
        id,
        bytes32(b"checkpoint").unwrap(),
        uint256(valset.index as u64),
        valset
            .eth_addresses()
            .iter()
            .cloned()
            .map(addr_to_bytes32)
            .collect::<Vec<_>>(),
        powers,
        [0u8; 20],
        [0u8; 32],
    )
        .abi_encode_params();
    keccak256(bytes).0
}

pub fn batch_hash(
    id: [u8; 32],
    nonce: u64,
    transfers: &LengthVec<u16, Transfer>,
    token_contract: Address,
    timeout: &u64,
) -> [u8; 32] {
    let dests = transfers.iter().map(|t| t.dest.bytes()).collect::<Vec<_>>();
    let amounts = transfers.iter().map(|t| t.amount).collect::<Vec<_>>();
    let fees = transfers.iter().map(|t| t.fee_amount).collect::<Vec<_>>();

    let bytes = (
        id,
        bytes32(b"transactionBatch").unwrap(),
        amounts,
        dests,
        fees,
        nonce,
        token_contract.bytes(),
        timeout,
    )
        .abi_encode_params();
    keccak256(bytes).0
}

pub fn sighash(message: [u8; 32]) -> [u8; 32] {
    let mut bytes = b"\x19Ethereum Signed Message:\n32".to_vec();
    bytes.extend_from_slice(&message);

    keccak256(bytes).0
}

pub fn to_eth_sig(
    sig: &bitcoin::secp256k1::ecdsa::Signature,
    pubkey: &PublicKey,
    msg: &Message,
) -> (u8, [u8; 32], [u8; 32]) {
    let secp = Secp256k1::new();

    let rs = sig.serialize_compact();

    let mut recid = None;
    for i in 0..=1 {
        let sig =
            RecoverableSignature::from_compact(&rs, RecoveryId::from_i32(i).unwrap()).unwrap();
        let pk = secp.recover_ecdsa(msg, &sig).unwrap();
        if pk == *pubkey {
            recid = Some(i);
            break;
        }
    }
    let v = recid.unwrap() as u8 + 27;

    let mut r = [0; 32];
    r.copy_from_slice(&rs[0..32]);

    let mut s = [0; 32];
    s.copy_from_slice(&rs[32..]);

    (v, r, s)
}

impl SignatorySet {
    pub fn eth_addresses(&self) -> Vec<Address> {
        self.signatories
            .iter()
            .map(|s| {
                let pk = PublicKey::from_slice(s.pubkey.as_slice()).unwrap();
                let mut uncompressed = [0; 64];
                uncompressed.copy_from_slice(&pk.serialize_uncompressed()[1..]);
                Address::from_pubkey_eth(uncompressed)
            })
            .collect()
    }

    pub fn normalize_vp(&mut self, total: u64) {
        let adjust = |n: u64| (n as u128 * total as u128 / self.present_vp as u128) as u64;

        for s in self.signatories.iter_mut() {
            s.voting_power = adjust(s.voting_power);
        }
        self.possible_vp = adjust(self.possible_vp);
        self.present_vp = total;
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    use crate::bitcoin::{signatory::Signatory, threshold_sig::Pubkey};

    use super::*;

    #[test]
    fn checkpoint_fixture() {
        let secp = Secp256k1::new();

        let privkey = SecretKey::from_slice(&bytes32(b"test").unwrap()).unwrap();
        let pubkey = privkey.public_key(&secp);

        let valset = SignatorySet {
            index: 0,
            signatories: vec![Signatory {
                pubkey: pubkey.into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 0,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };

        let id = bytes32(b"test").unwrap();

        assert_eq!(
            hex::encode(checkpoint_hash(id, &valset)),
            "61fe378d7a8aac20d5882ff4696d9c14c0db93b583fcd25f0616ce5187efae69",
        );

        let valset2 = SignatorySet {
            index: 1,
            signatories: vec![Signatory {
                pubkey: pubkey.into(),
                voting_power: 10_000_000_001,
            }],
            create_time: 0,
            present_vp: 10_000_000_001,
            possible_vp: 10_000_000_001,
        };

        let updated_checkpoint = checkpoint_hash(id, &valset2);
        assert_eq!(
            hex::encode(updated_checkpoint),
            "0b73bc9926c210f36673973a0ecb0a5f337ca1c7f99ba44ecf3624c891a8ab2b",
        );

        let valset_update_sighash = sighash(updated_checkpoint);
        let msg = Message::from_slice(&valset_update_sighash).unwrap();
        let sig = secp.sign_ecdsa(&msg, &privkey);
        let vrs = to_eth_sig(&sig, &pubkey, &msg);

        assert_eq!(vrs.0, 27);
        assert_eq!(
            hex::encode(vrs.1),
            "060215a246c6439b1ba1cf29577936ef20912e9e97b44326fd063b22221f69d8",
        );
        assert_eq!(
            hex::encode(vrs.2),
            "24d9924b969a742b877831a43b14e0ea88886308ecf0e37ee70a096346966a43",
        );
    }

    #[test]
    fn normalize_vp() {
        let mut valset = SignatorySet {
            index: 0,
            signatories: vec![
                Signatory {
                    pubkey: Pubkey::new([2; 33]).unwrap(),
                    voting_power: 10,
                },
                Signatory {
                    pubkey: Pubkey::new([2; 33]).unwrap(),
                    voting_power: 20,
                },
                Signatory {
                    pubkey: Pubkey::new([2; 33]).unwrap(),
                    voting_power: 30,
                },
            ],
            create_time: 0,
            present_vp: 60,
            possible_vp: 60,
        };

        valset.normalize_vp(6);
        assert_eq!(valset.signatories[0].voting_power, 1);
        assert_eq!(valset.signatories[1].voting_power, 2);
        assert_eq!(valset.signatories[2].voting_power, 3);
        assert_eq!(valset.possible_vp, 6);
        assert_eq!(valset.present_vp, 6);

        valset.normalize_vp(u32::MAX as u64);
        assert_eq!(valset.signatories[0].voting_power, 715_827_882);
        assert_eq!(valset.signatories[1].voting_power, 1_431_655_765);
        assert_eq!(valset.signatories[2].voting_power, 2_147_483_647);
        assert_eq!(valset.possible_vp, u32::MAX as u64);
        assert_eq!(valset.present_vp, u32::MAX as u64);
    }
}
