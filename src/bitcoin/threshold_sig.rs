use orga::call::Call;
use orga::client::Client;
use orga::collections::{Map, Next};
use orga::encoding::{Decode, Encode};
use orga::query::Query;
use orga::state::State;
use orga::{Error, Result};
use secp256k1::constants::{COMPACT_SIGNATURE_SIZE, MESSAGE_SIZE, PUBLIC_KEY_SIZE};
use serde::Serialize;

pub type Message = [u8; MESSAGE_SIZE];
pub type Signature = [u8; COMPACT_SIGNATURE_SIZE];

#[derive(
    Encode, Decode, State, Query, Call, Client, Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Pubkey([u8; PUBLIC_KEY_SIZE]);

impl Next for Pubkey {
    fn next(&self) -> Option<Self> {
        let mut output = self.clone();
        for (i, value) in self.0.iter().enumerate().rev() {
            match value.next() {
                Some(new_value) => {
                    output.0[i] = new_value;
                    return Some(output);
                }
                None => {
                    output.0[i] = 0;
                }
            }
        }
        None
    }
}

impl Default for Pubkey {
    fn default() -> Self {
        Pubkey([0; PUBLIC_KEY_SIZE])
    }
}

impl Pubkey {
    pub fn new(pubkey: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Pubkey(pubkey)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<bitcoin::PublicKey> for Pubkey {
    fn from(pubkey: bitcoin::PublicKey) -> Self {
        Pubkey(pubkey.key.serialize())
    }
}

// TODO: update for taproot-based design (musig rounds, fallback path)

#[derive(State, Call, Client, Query)]
pub struct ThresholdSig {
    threshold: u64,
    signed: u64,
    sigs: Map<Pubkey, Share>,
    message: Message,
}

impl ThresholdSig {
    #[query]
    pub fn done(&self) -> bool {
        self.signed >= self.threshold
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
                share.sig.map(|sig| Ok((pubkey.clone(), sig)))
            })
            .collect()
    }

    #[query]
    pub fn signed(&self, pubkey: Pubkey) -> Result<bool> {
        self.sigs
            .get(pubkey)?
            .ok_or_else(|| Error::App("Pubkey is not part of threshold signature".into()))
            .map(|share| share.sig.is_some())
    }

    // TODO: exempt from fee
    #[call]
    pub fn sign(&mut self, pubkey: Pubkey, sig: Signature) -> Result<()> {
        if self.done() {
            return Err(Error::App("Threshold signature is done".into()));
        }

        self.verify(pubkey, sig)?;

        let mut share = self
            .sigs
            .get_mut(pubkey)?
            .ok_or_else(|| Error::App("Pubkey is not part of threshold signature".into()))?;

        if share.sig.is_some() {
            return Err(Error::App("Pubkey already signed".into()));
        }

        share.sig = Some(sig);
        self.signed += share.power;

        Ok(())
    }

    pub fn verify(&self, pubkey: Pubkey, sig: Signature) -> Result<()> {
        // TODO: re-use secp context
        let secp = secp256k1::Secp256k1::verification_only();

        let msg = secp256k1::Message::from_slice(&self.message)?;
        let sig = secp256k1::ecdsa::Signature::from_compact(&sig)?;
        let pubkey = secp256k1::PublicKey::from_slice(&pubkey.0)?;

        #[cfg(not(fuzzing))]
        secp.verify_ecdsa(&msg, &sig, &pubkey)?;

        Ok(())
    }
}

#[derive(State, Call, Client, Query)]
pub struct Share {
    sig: Option<Signature>,
    power: u64,
}
