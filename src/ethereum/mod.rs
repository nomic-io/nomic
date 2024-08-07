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
    describe::Describe,
    encoding::LengthVec,
    migrate::Migrate,
    orga,
    query::FieldQuery,
    state::State,
    store::Store,
    Error,
};
use serde::{Deserialize, Serialize};

use crate::{
    bitcoin::{
        exempt_from_fee,
        signatory::SignatorySet,
        threshold_sig::{Pubkey, Signature, ThresholdSig},
        Nbtc,
    },
    error::Result,
};

// TODO: message ttl/pruning
// TODO: multi-token support

pub mod relayer;
pub mod signer;

pub const VALSET_INTERVAL: u64 = 60 * 60 * 24;

#[orga]
pub struct Ethereum {
    pub id: [u8; 32],
    pub token_contract: Address,
    pub outbox: Deque<OutMessage>,
    pub message_index: u64,
    pub batch_index: u64,
    pub valset_index: u64,
    pub coins: Coin<Nbtc>,
    pub valset_interval: u64,
    pub valset: SignatorySet,
}

#[orga]
impl Ethereum {
    pub fn new(id: &[u8], token_contract: Address, valset: SignatorySet) -> Self {
        Self {
            id: bytes32(id).unwrap(),
            token_contract,
            outbox: Deque::new(),
            message_index: 1,
            batch_index: 0,
            valset_index: 0,
            coins: Coin::default(),
            valset_interval: VALSET_INTERVAL,
            valset,
        }
    }

    pub fn step(&mut self, active_sigset: &SignatorySet) -> Result<()> {
        if active_sigset.create_time - self.valset.create_time >= self.valset_interval
            && self.valset.index != active_sigset.index
        {
            let mut new_valset = active_sigset.clone();
            new_valset.normalize_vp(u32::MAX as u64);
            self.update_valset(new_valset)?;
        }

        Ok(())
    }

    pub fn transfer(&mut self, dest: Address, coins: Coin<Nbtc>) -> Result<()> {
        // TODO: validation (min amount, etc)

        // TODO: batch transfers
        let transfer = Transfer {
            dest,
            amount: coins.amount.into(),
            fee_amount: 0, // TODO: deduct fee
        };
        let transfers = vec![transfer].try_into().unwrap();
        let timeout = u64::MAX; // TODO: set based on current ethereum height, or let user specify

        self.coins.give(coins)?;
        self.push_outbox(OutMessageArgs::Batch { transfers, timeout })
    }

    pub fn call(&mut self, call: ContractCall, coins: Coin<Nbtc>) -> Result<()> {
        // TODO: validation (amount in call vs coins supplied, etc)

        self.coins.give(coins)?;
        self.push_outbox(OutMessageArgs::LogicCall(call))
    }

    fn update_valset(&mut self, new_valset: SignatorySet) -> Result<()> {
        self.push_outbox(OutMessageArgs::UpdateValset(new_valset.clone()))?;
        self.valset = new_valset;
        self.valset_index += 1;

        Ok(())
    }

    fn push_outbox(&mut self, msg: OutMessageArgs) -> Result<()> {
        let hash = self.message_hash(&msg);
        let mut sigs = ThresholdSig::from_sigset(&self.valset)?;
        sigs.threshold = u32::MAX as u64 * 2 / 3;
        sigs.set_message(hash);
        let sigset_index = self.valset.index;

        if !self.outbox.is_empty() {
            self.message_index += 1;
        }
        self.outbox.push_back(OutMessage {
            sigs,
            msg,
            sigset_index,
        })?;

        Ok(())
    }

    #[call]
    pub fn sign(&mut self, msg_index: u64, pubkey: Pubkey, sig: Signature) -> Result<()> {
        exempt_from_fee()?;

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
        if msg_index > self.message_index {
            return Err(Error::App("message index out of bounds".to_string()).into());
        }

        let index = self.message_index - msg_index;
        if index >= self.outbox.len() {
            return Err(Error::App("message index out of bounds".to_string()).into());
        }

        Ok(index)
    }

    pub fn message_hash(&self, msg: &OutMessageArgs) -> [u8; 32] {
        match msg {
            OutMessageArgs::Batch { transfers, timeout } => batch_hash(
                self.id,
                self.batch_index,
                transfers,
                self.token_contract,
                timeout,
            ),
            OutMessageArgs::LogicCall(call) => {
                call.hash(self.id, self.token_contract, self.message_index)
            }
            OutMessageArgs::UpdateValset(valset) => {
                checkpoint_hash(self.id, valset, self.valset_index)
            }
        }
    }
}

#[orga]
pub struct OutMessage {
    pub sigset_index: u32,
    pub sigs: ThresholdSig,
    pub msg: OutMessageArgs,
}

#[derive(Encode, Decode, Debug, Clone, Serialize)]
pub enum OutMessageArgs {
    Batch {
        transfers: LengthVec<u16, Transfer>,
        timeout: u64,
    },
    LogicCall(ContractCall),
    UpdateValset(SignatorySet),
}

impl Describe for OutMessageArgs {
    fn describe() -> orga::describe::Descriptor {
        <()>::describe()
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

#[derive(Debug, Clone, Encode, Decode, Default, Serialize, Deserialize)]
pub struct ContractCall {
    pub contract: Address,
    pub transfer_amount: u64,
    pub fee_amount: u64,
    pub payload: LengthVec<u16, u8>,
    pub timeout: u64,
}

impl ContractCall {
    pub fn hash(&self, id: [u8; 32], token_contract: Address, nonce_id: u64) -> [u8; 32] {
        let bytes = (
            id,
            bytes32(b"logicCall").unwrap(),
            self.contract.bytes(),
            vec![self.transfer_amount],
            vec![token_contract.bytes()],
            vec![self.fee_amount],
            vec![token_contract.bytes()],
            self.payload.as_slice(),
            self.timeout,
            uint256(nonce_id),
            uint256(0),
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

pub fn checkpoint_hash(id: [u8; 32], valset: &SignatorySet, valset_index: u64) -> [u8; 32] {
    let powers = valset
        .signatories
        .iter()
        .map(|s| s.voting_power)
        .collect::<Vec<_>>();

    let bytes = (
        id,
        bytes32(b"checkpoint").unwrap(),
        uint256(valset_index),
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
    batch_index: u64,
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
        batch_index,
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
    use bitcoin::{
        secp256k1::{Message, Secp256k1, SecretKey},
        util::bip32::{ExtendedPrivKey, ExtendedPubKey},
    };
    use orga::{context::Context, plugins::Paid};

    use crate::bitcoin::{
        signatory::{derive_pubkey, Signatory},
        threshold_sig::Pubkey,
    };

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
            hex::encode(checkpoint_hash(id, &valset, 0)),
            "61fe378d7a8aac20d5882ff4696d9c14c0db93b583fcd25f0616ce5187efae69",
        );

        let valset2 = SignatorySet {
            index: 0,
            signatories: vec![Signatory {
                pubkey: pubkey.into(),
                voting_power: 10_000_000_001,
            }],
            create_time: 0,
            present_vp: 10_000_000_001,
            possible_vp: 10_000_000_001,
        };

        let updated_checkpoint = checkpoint_hash(id, &valset2, 1);
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
    fn ss_normalize_vp() {
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

    #[test]
    fn signing() {
        Context::add(Paid::default());

        let secp = Secp256k1::new();

        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Regtest, &[0]).unwrap();
        let xpub = ExtendedPubKey::from_priv(&secp, &xpriv);

        let valset = SignatorySet {
            index: 0,
            signatories: vec![Signatory {
                pubkey: derive_pubkey(&secp, xpub.into(), 0).unwrap().into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 0,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };

        let mut ethereum = Ethereum::new(b"test", Address::NULL, valset);

        let new_valset = SignatorySet {
            index: 1,
            signatories: vec![Signatory {
                pubkey: derive_pubkey(&secp, xpub.into(), 1).unwrap().into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 1_000_000_000,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };
        ethereum.step(&new_valset).unwrap();
        assert_eq!(ethereum.outbox.len(), 1);

        let msg = ethereum.get(1).unwrap().sigs.message;
        let sig = crate::bitcoin::signer::sign(&Secp256k1::signing_only(), &xpriv, &[(msg, 0)])
            .unwrap()[0];
        let pubkey = derive_pubkey(&secp, xpub.into(), 0).unwrap();
        ethereum.sign(1, pubkey.into(), sig).unwrap();
        assert!(ethereum.get(1).unwrap().sigs.signed());

        Context::remove::<Paid>();
    }
}
