use std::ops::{Deref, DerefMut};

use bitcoin::consensus::encode;
use ed::{Decode, Encode, Terminated};
use helios_consensus_core::types::{
    bls::PublicKey as HeliosPublicKey, Header as HeliosHeader, LightClientStore,
    SyncCommittee as HeliosSyncCommittee,
};
use orga::orga;
use serde::{Deserialize, Serialize};
use ssz::{Decode as SszDecode, Encode as SszEncode};
use ssz_types::FixedVector;

#[cfg(feature = "ethereum-full")]
pub mod relayer;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LightClient(LightClientStore);

impl LightClient {
    pub fn into_inner(self) -> LightClientStore {
        self.0
    }
}

impl Deref for LightClient {
    type Target = LightClientStore;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for LightClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for LightClient {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        encode_header(&self.finalized_header, dest)?;
        encode_sync_committee(&self.current_sync_committee, dest)?;
        self.next_sync_committee
            .as_ref()
            .map(|_| ())
            .encode_into(dest)?;
        if let Some(sc) = &self.next_sync_committee {
            encode_sync_committee(sc, dest)?;
        }
        encode_header(&self.optimistic_header, dest)?;
        self.0.previous_max_active_participants.encode_into(dest)?;
        self.0.current_max_active_participants.encode_into(dest)
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        Ok(Header(self.0.finalized_header.clone()).encoding_length()?
            + SyncCommittee(self.0.current_sync_committee.clone()).encoding_length()?
            + self
                .0
                .next_sync_committee
                .clone()
                .map(SyncCommittee)
                .encoding_length()?
            + Header(self.0.optimistic_header.clone()).encoding_length()?
            + self.0.previous_max_active_participants.encoding_length()?
            + self.0.current_max_active_participants.encoding_length()?)
    }
}

impl Decode for LightClient {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let finalized_header = Header::decode(&mut input)?;
        let current_sync_committee = SyncCommittee::decode(&mut input)?;
        let next_sync_committee = Option::<SyncCommittee>::decode(&mut input)?;
        let optimistic_header = Header::decode(&mut input)?;
        let previous_max_active_participants = u64::decode(&mut input)?;
        let current_max_active_participants = u64::decode(&mut input)?;

        Ok(LightClient(LightClientStore {
            finalized_header: finalized_header.into_inner(),
            current_sync_committee: current_sync_committee.into_inner(),
            next_sync_committee: next_sync_committee.map(|sc| sc.into_inner()),
            optimistic_header: optimistic_header.into_inner(),
            previous_max_active_participants,
            current_max_active_participants,
        }))
    }
}

impl Terminated for LightClient {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Header(HeliosHeader);

impl Header {
    pub fn into_inner(self) -> HeliosHeader {
        self.0
    }
}

impl Deref for Header {
    type Target = HeliosHeader;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Header {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for Header {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        encode_header(&self.0, dest)
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        Ok(8 + 8 + 32 + 32 + 32)
    }
}

pub fn encode_header<W: std::io::Write>(header: &HeliosHeader, dest: &mut W) -> ed::Result<()> {
    header.slot.encode_into(dest)?;
    header.proposer_index.encode_into(dest)?;
    header.parent_root.0.encode_into(dest)?;
    header.state_root.0.encode_into(dest)?;
    header.body_root.0.encode_into(dest)
}

impl Decode for Header {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let slot = u64::decode(&mut input)?;
        let proposer_index = u64::decode(&mut input)?;
        let parent_root = <[u8; 32]>::decode(&mut input)?;
        let state_root = <[u8; 32]>::decode(&mut input)?;
        let body_root = <[u8; 32]>::decode(&mut input)?;

        Ok(Header(HeliosHeader {
            slot,
            proposer_index,
            parent_root: parent_root.into(),
            state_root: state_root.into(),
            body_root: body_root.into(),
        }))
    }
}

impl Terminated for Header {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyncCommittee(HeliosSyncCommittee);

impl SyncCommittee {
    pub fn into_inner(self) -> HeliosSyncCommittee {
        self.0
    }
}

impl Deref for SyncCommittee {
    type Target = HeliosSyncCommittee;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SyncCommittee {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for SyncCommittee {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        encode_sync_committee(&self.0, dest)
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        Ok(512 * 48 + 48)
    }
}

pub fn encode_sync_committee<W: std::io::Write>(
    sc: &HeliosSyncCommittee,
    dest: &mut W,
) -> ed::Result<()> {
    for i in 0..512 {
        PublicKey(sc.pubkeys[i].clone()).encode_into(dest)?;
    }
    PublicKey(sc.aggregate_pubkey.clone()).encode_into(dest)
}

impl Decode for SyncCommittee {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let mut pubkeys = Vec::with_capacity(512);
        for i in 0..512 {
            pubkeys.push(PublicKey::decode(&mut input)?.into_inner());
        }
        let aggregate_pubkey = PublicKey::decode(&mut input)?.into_inner();

        Ok(SyncCommittee(HeliosSyncCommittee {
            pubkeys: FixedVector::new(pubkeys).unwrap(),
            aggregate_pubkey,
        }))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PublicKey(HeliosPublicKey);

impl PublicKey {
    pub fn into_inner(self) -> HeliosPublicKey {
        self.0
    }
}

impl From<HeliosPublicKey> for PublicKey {
    fn from(value: HeliosPublicKey) -> Self {
        PublicKey(value)
    }
}

impl Deref for PublicKey {
    type Target = HeliosPublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PublicKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for PublicKey {
    fn encode(&self) -> ed::Result<Vec<u8>> {
        Ok(self.0.as_ssz_bytes())
    }

    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        self.0.as_ssz_bytes().encode_into(dest)?;
        Ok(())
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        Ok(self.0.ssz_bytes_len())
    }
}

impl Decode for PublicKey {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let mut bytes = [0u8; 48];
        input.read_exact(&mut bytes)?;
        // TODO: pass through error
        let value =
            HeliosPublicKey::from_ssz_bytes(&bytes).map_err(|e| ed::Error::UnexpectedByte(33))?;
        Ok(PublicKey(value))
    }
}

impl Terminated for PublicKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode() {
        let pk = PublicKey(HeliosPublicKey::default());
        let bytes = pk.encode().unwrap();
        let pk2 = PublicKey::decode(&bytes[..]).unwrap();

        let lcs = LightClient(LightClientStore::default());
        let bytes = lcs.encode().unwrap();
        let lcs = LightClient::decode(&bytes[..]).unwrap();
    }
}
