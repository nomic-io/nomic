use orga::call::Call;
use orga::client::Client;
use orga::collections::{Map, Next};
use orga::encoding::{Decode, Encode, Terminated, Result as EdResult, Error as EdError};
use orga::query::Query;
use orga::state::State;
use orga::{Error, Result};
use secp256k1::{
    PublicKey,
    Secp256k1,
    ecdsa,
    constants::{COMPACT_SIGNATURE_SIZE, MESSAGE_SIZE, PUBLIC_KEY_SIZE}
};

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
    message: Message,
    sigs: Map<Pubkey, Share>,
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
                share.sig.as_ref().map(|sig| Ok((pubkey.clone(), sig.clone())))
            })
            .collect()
    }

    #[query]
    pub fn contains_key(&self, pubkey: Pubkey) -> Result<bool> {
        self.sigs.contains_key(pubkey)
    }

    // TODO: exempt from fee
    pub fn sign(&mut self, pubkey: Pubkey, sig: Signature) -> Result<()> {
        if self.done() {
            return Err(Error::App("Threshold signature is done".into()));
        }

        let share = self
            .sigs
            .get(pubkey)?
            .ok_or_else(|| Error::App("Pubkey is not part of threshold signature".into()))?;
        
        if share.sig.is_some() {
            return Err(Error::App("Pubkey already signed".into()));
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

    pub fn verify(&self, pubkey: Pubkey, sig: Signature) -> Result<()> {
        // TODO: re-use secp context
        let secp = Secp256k1::verification_only();
        let pubkey = PublicKey::from_slice(&pubkey.0)?;
        let msg = secp256k1::Message::from_slice(self.message.as_slice())?;
        let sig = ecdsa::Signature::from_compact(sig.as_slice())?;

        #[cfg(not(fuzzing))]
        secp.verify_ecdsa(&msg, &sig, &pubkey)?;

        Ok(())
    }
}

#[derive(State, Call, Client, Query)]
pub struct Share {
    power: u64,
    sig: Option<Signature>,
}

// TODO: move this into ed
use std::convert::{TryInto, TryFrom};
use derive_more::{Deref, DerefMut, Into};

#[derive(Deref, DerefMut, Encode, Into, Default)]
pub struct LengthVec<P, T>
where
    P: Encode + Terminated,
    T: Encode + Terminated,
{
    len: P,

    #[deref]
    #[deref_mut]
    #[into]
    values: Vec<T>,
}

impl<P, T> LengthVec<P, T>
where
    P: Encode + Terminated,
    T: Encode + Terminated,
{
    pub fn new(len: P, values: Vec<T>) -> Self {
        LengthVec { len, values }
    }
}

impl<P, T> State for LengthVec<P, T>
where
    P: Encode + Decode + Terminated + TryInto<usize> + Clone,
    T: Encode + Decode + Terminated,
{
    type Encoding = Self;
    
    fn create(_: orga::store::Store, data: Self::Encoding) -> Result<Self> {
        Ok(data)
    }

    fn flush(self) -> Result<Self::Encoding> {
        Ok(self)
    }
}

impl<P, T> From<Vec<T>> for LengthVec<P, T>
where
    P: Encode + Terminated + TryFrom<usize>,
    T: Encode + Terminated,
    <P as TryFrom<usize>>::Error: std::fmt::Debug,
{
    fn from(values: Vec<T>) -> Self {
        LengthVec::new(P::try_from(values.len()).unwrap(), values)
    }
}

impl<P, T> Terminated for LengthVec<P, T>
where
    P: Encode + Terminated,
    T: Encode + Terminated,
{}

impl<P, T> Decode for LengthVec<P, T>
where
    P: Encode + Decode + Terminated + TryInto<usize> + Clone,
    T: Encode + Decode + Terminated,
{
    fn decode<R: std::io::Read>(mut input: R) -> EdResult<Self> {
        let len = P::decode(&mut input)?;
        let len_usize = len.clone().try_into()
            .map_err(|_| EdError::UnexpectedByte(80))?;

        let mut values = Vec::with_capacity(len_usize);
        for i in 0..len_usize {
            let value = T::decode(&mut input)?;
            values.push(value);
        }

        Ok(LengthVec { len, values })
    }
}
