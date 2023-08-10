use super::SignatorySet;
use bitcoin::blockdata::transaction::EcdsaSighashType;
use bitcoin::secp256k1::{
    self,
    constants::{COMPACT_SIGNATURE_SIZE, MESSAGE_SIZE, PUBLIC_KEY_SIZE},
    ecdsa, PublicKey, Secp256k1,
};
use derive_more::{Deref, From};
use orga::collections::{Map, Next};
use orga::encoding::{Decode, Encode};
use orga::macros::Describe;
use orga::migrate::Migrate;
use orga::prelude::FieldCall;
use orga::query::FieldQuery;
use orga::state::State;
use orga::store::Store;
use orga::{orga, Error, Result};
use serde::Serialize;

pub type Message = [u8; MESSAGE_SIZE];

#[derive(Encode, Decode, State, Debug, Clone, Deref, From, Copy, Migrate, Serialize, Describe)]
pub struct Signature(
    #[serde(serialize_with = "<[_]>::serialize")] pub [u8; COMPACT_SIGNATURE_SIZE],
);

#[derive(
    Encode,
    Decode,
    State,
    FieldQuery,
    FieldCall,
    Clone,
    Debug,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Describe,
)]
pub struct Pubkey {
    #[serde(serialize_with = "<[_]>::serialize")]
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl Migrate for Pubkey {
    fn migrate(_src: Store, _dest: Store, bytes: &mut &[u8]) -> Result<Self> {
        Ok(Self::decode(bytes)?)
    }
}

impl Next for Pubkey {
    fn next(&self) -> Option<Self> {
        let mut output = *self;
        for (i, value) in self.bytes.iter().enumerate().rev() {
            match value.next() {
                Some(new_value) => {
                    output.bytes[i] = new_value;
                    return Some(output);
                }
                None => {
                    output.bytes[i] = 0;
                }
            }
        }
        None
    }
}

impl Default for Pubkey {
    fn default() -> Self {
        Pubkey {
            bytes: [0; PUBLIC_KEY_SIZE],
        }
    }
}

impl Pubkey {
    pub fn new(pubkey: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Pubkey { bytes: pubkey }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<PublicKey> for Pubkey {
    fn from(pubkey: PublicKey) -> Self {
        Pubkey {
            bytes: pubkey.serialize(),
        }
    }
}

#[derive(
    Encode,
    Decode,
    State,
    FieldQuery,
    FieldCall,
    Clone,
    Debug,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Describe,
    Migrate,
)]
pub struct VersionedPubkey {
    #[serde(serialize_with = "<[_]>::serialize")]
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl Default for VersionedPubkey {
    fn default() -> Self {
        VersionedPubkey {
            bytes: [0; PUBLIC_KEY_SIZE],
        }
    }
}

impl VersionedPubkey {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Pubkey> for VersionedPubkey {
    fn from(pubkey: Pubkey) -> Self {
        VersionedPubkey {
            bytes: pubkey.bytes,
        }
    }
}

impl From<VersionedPubkey> for Pubkey {
    fn from(pubkey: VersionedPubkey) -> Self {
        Pubkey {
            bytes: pubkey.bytes,
        }
    }
}

impl From<PublicKey> for VersionedPubkey {
    fn from(pubkey: PublicKey) -> Self {
        VersionedPubkey {
            bytes: pubkey.serialize(),
        }
    }
}

// TODO: update for taproot-based design (musig rounds, fallback path)

#[orga]
pub struct ThresholdSig {
    pub threshold: u64,
    pub signed: u64,
    pub message: Message,
    pub len: u16,
    pub sigs: Map<Pubkey, Share>,
}

#[orga]
impl ThresholdSig {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u16 {
        self.len
    }

    pub fn set_message(&mut self, message: Message) {
        self.message = message;
    }

    pub fn clear_sigs(&mut self) -> Result<()> {
        self.signed = 0;

        let mut entries: Vec<_> = self
            .sigs
            .iter()?
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|(k, _)| k.clone())
            .collect();
        for k in entries {
            let mut sig = self.sigs.get_mut(k)?.unwrap();
            sig.sig = None;
        }

        Ok(())
    }

    pub fn message(&self) -> Message {
        self.message
    }

    pub fn from_sigset(signatories: &SignatorySet) -> Result<Self> {
        let mut ts = ThresholdSig::default();
        let mut total_vp = 0;

        for signatory in signatories.iter() {
            ts.sigs.insert(
                signatory.pubkey.into(),
                Share {
                    power: signatory.voting_power,
                    sig: None,
                },
            )?;

            ts.len += 1;
            total_vp += signatory.voting_power;
        }

        // TODO: get threshold ratio from somewhere else
        ts.threshold = ((total_vp as u128) * 2 / 3) as u64;

        Ok(ts)
    }

    pub fn from_shares(shares: Vec<(Pubkey, Share)>) -> Result<Self> {
        let mut ts = ThresholdSig::default();
        let mut total_vp = 0;
        let mut len = 0;

        for (pubkey, share) in shares.into_iter() {
            assert!(share.sig.is_none());
            total_vp += share.power;
            len += 1;
            ts.sigs.insert(pubkey, share)?;
        }

        // TODO: get threshold ratio from somewhere else
        ts.threshold = ((total_vp as u128) * 2 / 3) as u64;
        ts.len = len;

        Ok(ts)
    }

    #[query]
    pub fn done(&self) -> bool {
        self.signed > self.threshold
    }

    #[query]
    pub fn sigs(&self) -> Result<Vec<(Pubkey, Signature)>> {
        self.sigs
            .iter()?
            .filter_map(|entry| {
                let (pubkey, share) = match entry {
                    Err(e) => return Some(Err(e)),
                    Ok(entry) => entry,
                };
                share.sig.as_ref().map(|sig| Ok((*pubkey, *sig)))
            })
            .collect::<Result<_>>()
    }

    // TODO: should be iterator?
    pub fn shares(&self) -> Result<Vec<(Pubkey, Share)>> {
        self.sigs
            .iter()?
            .map(|entry| entry.map(|(pubkey, share)| (*pubkey, share.clone())))
            .collect::<Result<_>>()
    }

    #[query]
    pub fn contains_key(&self, pubkey: Pubkey) -> Result<bool> {
        self.sigs.contains_key(pubkey)
    }

    #[query]
    pub fn needs_sig(&self, pubkey: Pubkey) -> Result<bool> {
        Ok(self
            .sigs
            .get(pubkey)?
            .map(|share| share.sig.is_none())
            .unwrap_or(false))
    }

    // TODO: exempt from fee
    pub fn sign(&mut self, pubkey: Pubkey, sig: Signature) -> Result<()> {
        if self.done() {
            return Err(Error::App("Threshold signature is done".into()))?;
        }

        let share = self
            .sigs
            .get(pubkey)?
            .ok_or_else(|| Error::App("Pubkey is not part of threshold signature".into()))?;

        if share.sig.is_some() {
            return Err(Error::App("Pubkey already signed".into()))?;
        }

        self.verify(pubkey, sig)?;

        let mut share = self
            .sigs
            .get_mut(pubkey)?
            .ok_or_else(|| Error::App("Pubkey is not part of threshold signature".into()))?;

        share.sig = Some(sig);
        self.signed += share.power;

        Ok(())
    }

    pub fn verify(&self, pubkey: Pubkey, sig: Signature) -> crate::error::Result<()> {
        // TODO: re-use secp context
        let secp = Secp256k1::verification_only();
        let pubkey = PublicKey::from_slice(&pubkey.bytes)?;
        let msg = secp256k1::Message::from_slice(self.message.as_slice())?;
        let sig = ecdsa::Signature::from_compact(sig.as_slice())?;

        #[cfg(not(fuzzing))]
        secp.verify_ecdsa(&msg, &sig, &pubkey)?;

        Ok(())
    }

    // TODO: this shouldn't know so much about bitcoin-specific structure,
    // decouple by exposing a power-ordered iterator of Option<Signature>
    pub fn to_witness(&self) -> crate::error::Result<Vec<Vec<u8>>> {
        if !self.done() {
            return Ok(vec![]);
        }

        let mut entries: Vec<_> = self.sigs.iter()?.collect::<Result<_>>()?;
        entries.sort_by(|a, b| (a.1.power, &a.0).cmp(&(b.1.power, &b.0)));

        entries
            .into_iter()
            .map(|(_, share)| {
                share.sig.map_or(Ok(vec![]), |sig| {
                    let sig = ecdsa::Signature::from_compact(sig.as_slice())?;
                    let mut v = sig.serialize_der().to_vec();
                    v.push(EcdsaSighashType::All.to_u32() as u8);
                    Ok(v)
                })
            })
            .collect()
    }
}

use std::fmt::Debug;
impl Debug for ThresholdSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdSig")
            .field("threshold", &self.threshold)
            .field("signed", &self.signed)
            .field("message", &self.message)
            .field("len", &self.len)
            .field("sigs", &"TODO")
            .finish()
    }
}

#[orga]
#[derive(Clone)]
pub struct Share {
    pub power: u64,
    pub(super) sig: Option<Signature>,
}
