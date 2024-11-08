use std::{
    fmt::Display,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use ed::{Decode, Encode, Terminated};
use helios_consensus_core::{
    apply_bootstrap, apply_finality_update, apply_update,
    types::{
        bls::{PublicKey as HeliosPublicKey, Signature as HeliosSignature},
        bytes::{ByteList, ByteVector},
        BeaconBlockHeader as HeliosBeaconBlockHeader, Bootstrap as HeliosBootstrap,
        ExecutionPayloadHeader as HeliosExecutionPayloadHeaderOuter,
        ExecutionPayloadHeaderDeneb as HeliosExecutionPayloadHeader,
        FinalityUpdate as HeliosFinalityUpdate, Forks,
        LightClientHeader as HeliosLightClientHeader, LightClientStore,
        SyncAggregate as HeliosSyncAggregate, SyncCommittee as HeliosSyncCommittee,
        Update as HeliosUpdate,
    },
    verify_bootstrap, verify_finality_update, verify_update,
};
use orga::{
    call::FieldCall, describe::Describe, encoding::LengthVec, migrate::Migrate,
    query::FieldQuery, state::State,
};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use ssz::{Decode as SszDecode, Encode as SszEncode};
use ssz_types::{Bitfield, FixedVector};
use tree_hash::TreeHash;

use crate::error::Result;

#[cfg(feature = "ethereum-full")]
pub mod relayer;

/// Maintains the consensus state of an Ethereum chain, which can be updated via
/// consensus proofs based on the Altair light client protocol.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LightClient {
    lcs: LightClientStore,
    network: Network,
}

impl LightClient {
    /// Create a new `LightClient` with the given bootstrap data and network
    /// configuration.
    pub fn new(bootstrap: Bootstrap, network: Network) -> Result<Self> {
        let bootstrap = bootstrap.into();

        let mut forks = Forks::default();
        forks.deneb.fork_version = (network.deneb_fork_version.to_be_bytes()).into();

        verify_bootstrap(&bootstrap, bootstrap.header.beacon.tree_hash_root(), &forks)
            .map_err(|e| orga::Error::App(format!("Invalid bootstrap: {}", e)))?;

        let mut lcs = LightClientStore::default();
        apply_bootstrap(&mut lcs, &bootstrap);

        Ok(LightClient { lcs, network })
    }

    /// Verify and apply the update to the light client state.
    ///
    /// To minimize updates, this is designed to only allow updates that advance
    /// to the next finalized slot, or to the next sync committee period.
    /// There should be at most one update per epoch.
    pub fn update(&mut self, update: Update, now_seconds: u64) -> Result<()> {
        let expected_slot = (now_seconds - self.network.genesis_time) / 12;
        let genesis_root = (&self.network.genesis_vals_root.0).into();

        let mut forks = Forks::default();
        forks.deneb.fork_version = (&self.network.deneb_fork_version.to_be_bytes()).into();

        if update.next_sync_committee.is_some() {
            let update: HeliosUpdate = update.try_into().unwrap();
            verify_update(&update, expected_slot, &self.lcs, genesis_root, &forks)
                .map_err(|e| orga::Error::App(format!("Invalid update: {}", e)))?;
            apply_update(&mut self.lcs, &update);
        } else {
            let update: HeliosFinalityUpdate = update.into();
            verify_finality_update(&update, expected_slot, &self.lcs, genesis_root, &forks)
                .map_err(|e| orga::Error::App(format!("Invalid update: {}", e)))?;
            apply_finality_update(&mut self.lcs, &update);
        }

        Ok(())
    }

    /// Get the most recently finalized slot.
    pub fn slot(&self) -> u64 {
        self.lcs.finalized_header.beacon.slot
    }

    /// Get the most recently finalized block number.
    pub fn block_number(&self) -> u64 {
        *self
            .lcs
            .finalized_header
            .execution
            .as_ref()
            .unwrap() // TODO: guarantee execution header is always present?
            .block_number()
    }

    /// Get the most recently finalized execution state root.
    pub fn state_root(&self) -> Bytes32 {
        self.lcs
            .finalized_header
            .execution
            .as_ref()
            .unwrap() // TODO: guarantee execution header is always present?
            .state_root()
            .0
            .into()
    }

    #[cfg(feature = "devnet")]
    pub fn unsafe_update_consensus(
        &mut self,
        state_root: [u8; 32],
        block_number: u64,
    ) -> Result<()> {
        self.lcs
            .finalized_header
            .execution
            .as_mut()
            .unwrap()
            .state_root_mut()
            .copy_from_slice(&state_root);
        *self
            .lcs
            .finalized_header
            .execution
            .as_mut()
            .unwrap()
            .block_number_mut() = block_number;

        Ok(())
    }

    /// Get the underlying `LightClientStore`.
    pub fn light_client_store(&self) -> &LightClientStore {
        &self.lcs
    }
}

impl State for LightClient {
    fn attach(&mut self, _store: orga::prelude::Store) -> orga::Result<()> {
        Ok(())
    }

    fn field_keyop(_field_name: &str) -> Option<orga::describe::KeyOp> {
        // TODO
        None
    }

    fn flush<W: std::io::Write>(self, out: &mut W) -> orga::Result<()> {
        Ok(self.encode_into(out)?)
    }

    fn load(_store: orga::prelude::Store, bytes: &mut &[u8]) -> orga::Result<Self> {
        Ok(Self::decode(bytes)?)
    }
}

impl Migrate for LightClient {
    fn migrate(
        _src: orga::prelude::Store,
        _dest: orga::prelude::Store,
        bytes: &mut &[u8],
    ) -> orga::Result<Self> {
        Ok(Self::decode(bytes)?)
    }
}

impl FieldCall for LightClient {
    type FieldCall = ();

    fn field_call(&mut self, _call: ()) -> orga::Result<()> {
        Err(orga::Error::App("FieldCall not supported".to_string()))
    }
}

impl FieldQuery for LightClient {
    type FieldQuery = ();

    fn field_query(&self, _query: ()) -> orga::Result<()> {
        Err(orga::Error::App("FieldQuery not supported".to_string()))
    }
}

impl Deref for LightClient {
    type Target = LightClientStore;

    fn deref(&self) -> &Self::Target {
        &self.lcs
    }
}

impl DerefMut for LightClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.lcs
    }
}

impl Encode for LightClient {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        encode_lc_header(&self.finalized_header, dest)?;
        encode_sync_committee(&self.current_sync_committee, dest)?;
        (self.next_sync_committee.is_some() as u8).encode_into(dest)?;
        if let Some(sc) = &self.next_sync_committee {
            encode_sync_committee(sc, dest)?;
        }
        encode_lc_header(&self.optimistic_header, dest)?;
        self.lcs
            .previous_max_active_participants
            .encode_into(dest)?;
        self.lcs.current_max_active_participants.encode_into(dest)?;
        self.network.encode_into(dest)
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        // TODO: remove need for copying
        Ok(
            LightClientHeader(self.lcs.finalized_header.clone()).encoding_length()?
                + SyncCommittee(self.lcs.current_sync_committee.clone()).encoding_length()?
                + self
                    .lcs
                    .next_sync_committee
                    .clone()
                    .map(SyncCommittee)
                    .encoding_length()?
                + LightClientHeader(self.lcs.optimistic_header.clone()).encoding_length()?
                + self
                    .lcs
                    .previous_max_active_participants
                    .encoding_length()?
                + self.lcs.current_max_active_participants.encoding_length()?
                + self.network.encoding_length()?,
        )
    }
}

impl Decode for LightClient {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let finalized_header = LightClientHeader::decode(&mut input)?;
        let current_sync_committee = SyncCommittee::decode(&mut input)?;
        let next_sync_committee = Option::<SyncCommittee>::decode(&mut input)?;
        let optimistic_header = LightClientHeader::decode(&mut input)?;
        let previous_max_active_participants = u64::decode(&mut input)?;
        let current_max_active_participants = u64::decode(&mut input)?;
        let network = Network::decode(&mut input)?;

        Ok(LightClient {
            lcs: LightClientStore {
                finalized_header: finalized_header.into_inner(),
                current_sync_committee: current_sync_committee.into_inner(),
                next_sync_committee: next_sync_committee.map(|sc| sc.into_inner()),
                optimistic_header: optimistic_header.into_inner(),
                previous_max_active_participants,
                current_max_active_participants,
            },
            network,
        })
    }
}

impl Terminated for LightClient {}

impl Describe for LightClient {
    fn describe() -> orga::describe::Descriptor {
        orga::describe::Builder::new::<Self>().meta::<()>().build()
    }
}

/// The network parameters for an Ethereum chain.
#[derive(Clone, Debug, Default, Encode, Decode, Serialize, Deserialize)]
pub struct Network {
    pub genesis_vals_root: Bytes32,
    pub deneb_fork_version: u32,
    pub genesis_time: u64,
}

impl Network {
    /// Network parameters for the Ethereum mainnet.
    pub fn ethereum_mainnet() -> Self {
        Network {
            genesis_vals_root: "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
                .parse()
                .unwrap(),
            deneb_fork_version: 4,
            genesis_time: 1606824023,
        }
    }

    /// Network parameters for the Ethereum Sepolia testnet.
    pub fn ethereum_sepolia() -> Self {
        Network {
            genesis_vals_root: "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
                .parse()
                .unwrap(),
            deneb_fork_version: 0x90000073,
            genesis_time: 1655733600,
        }
    }
}

/// An update to the light client state, and all necessary proof and signature
/// data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Update {
    pub attested_header: LightClientHeader,
    pub next_sync_committee: Option<SyncCommittee>,
    pub next_sync_committee_branch: Option<LengthVec<u8, Bytes32>>,
    pub finalized_header: LightClientHeader,
    pub finality_branch: LengthVec<u8, Bytes32>,
    pub sync_aggregate: SyncAggregate,
    #[serde(with = "u64_string")]
    pub signature_slot: u64,
}

impl Encode for Update {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        let json = serde_json::to_string(self).unwrap();
        let len = json.len() as u32;
        len.encode_into(dest)?;
        dest.write_all(json.as_bytes())?;
        Ok(())
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        let json = serde_json::to_string(self).unwrap();
        Ok(4 + json.len())
    }
}

impl Decode for Update {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let len = u32::decode(&mut input)?;
        if len > 1_000_000 {
            return Err(ed::Error::UnexpectedByte(100));
        }
        let mut buf = vec![0; len as usize];
        input.read_exact(&mut buf)?;
        let update: Update = serde_json::from_slice(&buf).unwrap();
        Ok(update)
    }
}

impl Terminated for Update {}

impl TryFrom<Update> for HeliosUpdate {
    type Error = crate::error::Error;

    fn try_from(value: Update) -> Result<Self> {
        let attested_header = value.attested_header.into_inner();
        let next_sync_committee = value
            .next_sync_committee
            .map(|sc| sc.into_inner())
            .ok_or_else(|| orga::Error::App("next_sync_committee is required".to_string()))?;
        let next_sync_committee_branch = value
            .next_sync_committee_branch
            .map(|branch| {
                Vec::from(branch)
                    .into_iter()
                    .map(|b| b.into_inner().into())
                    .collect()
            })
            .ok_or_else(|| {
                orga::Error::App("next_sync_committee_branch is required".to_string())
            })?;
        let finalized_header = value.finalized_header.into_inner();
        let finality_branch = Vec::from(value.finality_branch)
            .into_iter()
            .map(|b| b.into_inner().into())
            .collect();
        let sync_aggregate = value.sync_aggregate.into_inner();
        let signature_slot = value.signature_slot;

        Ok(HeliosUpdate {
            attested_header,
            next_sync_committee,
            next_sync_committee_branch,
            finalized_header,
            finality_branch,
            sync_aggregate,
            signature_slot,
        })
    }
}

impl From<Update> for HeliosFinalityUpdate {
    fn from(value: Update) -> Self {
        let attested_header = value.attested_header.into_inner();
        let finalized_header = value.finalized_header.into_inner();
        let finality_branch = Vec::from(value.finality_branch)
            .into_iter()
            .map(|b| b.into_inner().into())
            .collect();
        let sync_aggregate = value.sync_aggregate.into_inner();
        let signature_slot = value.signature_slot;

        HeliosFinalityUpdate {
            attested_header,
            finalized_header,
            finality_branch,
            sync_aggregate,
            signature_slot,
        }
    }
}

mod u64_string {
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val: String = serde::Deserialize::deserialize(deserializer)?;
        val.parse().map_err(D::Error::custom)
    }
}

#[derive(Clone, Default, Debug, Encode, Decode, Serialize, Deserialize)]
pub struct Bootstrap {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: LengthVec<u8, Bytes32>,
}

impl From<Bootstrap> for HeliosBootstrap {
    fn from(value: Bootstrap) -> Self {
        let header = value.header.into_inner();
        let current_sync_committee = value.current_sync_committee.into_inner();
        let current_sync_committee_branch = Vec::from(value.current_sync_committee_branch)
            .into_iter()
            .map(|b| b.into_inner().into())
            .collect();

        HeliosBootstrap {
            header,
            current_sync_committee,
            current_sync_committee_branch,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LightClientHeader(HeliosLightClientHeader);

impl LightClientHeader {
    pub fn into_inner(self) -> HeliosLightClientHeader {
        self.0
    }
}

impl Deref for LightClientHeader {
    type Target = HeliosLightClientHeader;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for LightClientHeader {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for LightClientHeader {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        encode_lc_header(&self.0, dest)
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        // TODO
        let mut vec = Vec::with_capacity(1_000);
        self.encode_into(&mut vec)?;
        Ok(vec.len())
    }
}

pub fn encode_lc_header<W: std::io::Write>(
    header: &HeliosLightClientHeader,
    dest: &mut W,
) -> ed::Result<()> {
    encode_bb_header(&header.beacon, dest)?;

    (header.execution.is_some() as u8).encode_into(dest)?;
    if let Some(HeliosExecutionPayloadHeaderOuter::Deneb(execution)) = &header.execution {
        encode_ep_header(execution, dest)?;
    }

    (header.execution_branch.is_some() as u8).encode_into(dest)?;
    if let Some(execution) = &header.execution_branch {
        let branch: Vec<Bytes32> = execution.iter().map(|b| b.0.into()).collect();
        if branch.len() > u8::MAX as usize {
            return Err(ed::Error::UnexpectedByte(0));
        }
        let branch = LengthVec::<u8, _>::new(branch.len() as u8, branch);
        branch.encode_into(dest)?;
    }
    Ok(())
}

impl Decode for LightClientHeader {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let beacon = BeaconBlockHeader::decode(&mut input)?;

        let has_execution = u8::decode(&mut input)?;
        let execution = if has_execution == 1 {
            Some(ExecutionPayloadHeader::decode(&mut input)?)
        } else {
            None
        };

        let has_execution_branch = u8::decode(&mut input)?;
        let execution_branch = if has_execution_branch == 1 {
            Some(LengthVec::<u8, Bytes32>::decode(&mut input)?)
        } else {
            None
        };

        Ok(LightClientHeader(HeliosLightClientHeader {
            beacon: beacon.into_inner(),
            execution: execution.map(|e| e.into_inner().into()),
            execution_branch: execution_branch.map(|b| {
                Vec::from(b)
                    .into_iter()
                    .map(|b| b.into_inner().into())
                    .collect()
            }),
        }))
    }
}

impl Terminated for LightClientHeader {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionPayloadHeader(HeliosExecutionPayloadHeader);

impl ExecutionPayloadHeader {
    pub fn into_inner(self) -> HeliosExecutionPayloadHeader {
        self.0
    }
}

impl Deref for ExecutionPayloadHeader {
    type Target = HeliosExecutionPayloadHeader;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ExecutionPayloadHeader {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for ExecutionPayloadHeader {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        encode_ep_header(&self.0, dest)
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        // TODO
        let mut vec = Vec::with_capacity(1_000);
        self.encode_into(&mut vec)?;
        Ok(vec.len())
    }
}

fn encode_ep_header<W: std::io::Write>(
    header: &HeliosExecutionPayloadHeader,
    dest: &mut W,
) -> ed::Result<()> {
    header.parent_hash.0.encode_into(dest)?;
    header.fee_recipient.encode_into(dest)?;
    header.state_root.0.encode_into(dest)?;
    header.receipts_root.0.encode_into(dest)?;
    header.logs_bloom.inner.to_vec().encode_into(dest)?;
    header.prev_randao.0.encode_into(dest)?;
    header.block_number.encode_into(dest)?;
    header.gas_limit.encode_into(dest)?;
    header.gas_used.encode_into(dest)?;
    header.timestamp.encode_into(dest)?;
    LengthVec::<u8, u8>::new(
        header.extra_data.inner.to_vec().len() as u8,
        header.extra_data.inner.to_vec(),
    )
    .encode_into(dest)?;
    header
        .base_fee_per_gas
        .to_be_bytes::<32>()
        .encode_into(dest)?;
    header.block_hash.0.encode_into(dest)?;
    header.transactions_root.0.encode_into(dest)?;
    header.withdrawals_root.0.encode_into(dest)?;
    header.blob_gas_used.encode_into(dest)?;
    header.excess_blob_gas.encode_into(dest)
}

impl Decode for ExecutionPayloadHeader {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let parent_hash = <[u8; 32]>::decode(&mut input)?;
        let fee_recipient = <[u8; 20]>::decode(&mut input)?;
        let state_root = <[u8; 32]>::decode(&mut input)?;
        let receipts_root = <[u8; 32]>::decode(&mut input)?;
        let logs_bloom = <[u8; 256]>::decode(&mut input)?;
        let prev_randao = <[u8; 32]>::decode(&mut input)?;
        let block_number = u64::decode(&mut input)?;
        let gas_limit = u64::decode(&mut input)?;
        let gas_used = u64::decode(&mut input)?;
        let timestamp = u64::decode(&mut input)?;
        let extra_data = LengthVec::<u8, u8>::decode(&mut input)?;
        let base_fee_per_gas = <[u8; 32]>::decode(&mut input)?;
        let block_hash = <[u8; 32]>::decode(&mut input)?;
        let transactions_root = <[u8; 32]>::decode(&mut input)?;
        let withdrawals_root = <[u8; 32]>::decode(&mut input)?;
        let blob_gas_used = u64::decode(&mut input)?;
        let excess_blob_gas = u64::decode(&mut input)?;

        Ok(ExecutionPayloadHeader(HeliosExecutionPayloadHeader {
            parent_hash: parent_hash.into(),
            fee_recipient: fee_recipient.into(),
            state_root: state_root.into(),
            receipts_root: receipts_root.into(),
            logs_bloom: ByteVector {
                inner: logs_bloom.to_vec().into(),
            },
            prev_randao: prev_randao.into(),
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data: ByteList {
                inner: extra_data.to_vec().into(),
            },
            base_fee_per_gas: ruint::Uint::from_be_bytes(base_fee_per_gas),
            block_hash: block_hash.into(),
            transactions_root: transactions_root.into(),
            withdrawals_root: withdrawals_root.into(),
            blob_gas_used,
            excess_blob_gas,
        }))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BeaconBlockHeader(HeliosBeaconBlockHeader);

impl BeaconBlockHeader {
    pub fn into_inner(self) -> HeliosBeaconBlockHeader {
        self.0
    }
}

impl Deref for BeaconBlockHeader {
    type Target = HeliosBeaconBlockHeader;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BeaconBlockHeader {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for BeaconBlockHeader {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        encode_bb_header(&self.0, dest)
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        Ok(8 + 8 + 32 + 32 + 32)
    }
}

pub fn encode_bb_header<W: std::io::Write>(
    header: &HeliosBeaconBlockHeader,
    dest: &mut W,
) -> ed::Result<()> {
    header.slot.encode_into(dest)?;
    header.proposer_index.encode_into(dest)?;
    header.parent_root.0.encode_into(dest)?;
    header.state_root.0.encode_into(dest)?;
    header.body_root.0.encode_into(dest)
}

impl Decode for BeaconBlockHeader {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let slot = u64::decode(&mut input)?;
        let proposer_index = u64::decode(&mut input)?;
        let parent_root = <[u8; 32]>::decode(&mut input)?;
        let state_root = <[u8; 32]>::decode(&mut input)?;
        let body_root = <[u8; 32]>::decode(&mut input)?;

        Ok(BeaconBlockHeader(HeliosBeaconBlockHeader {
            slot,
            proposer_index,
            parent_root: parent_root.into(),
            state_root: state_root.into(),
            body_root: body_root.into(),
        }))
    }
}

impl Terminated for BeaconBlockHeader {}

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
        encode_public_key(&sc.pubkeys[i], dest)?;
    }
    encode_public_key(&sc.aggregate_pubkey, dest)
}

impl Decode for SyncCommittee {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let mut pubkeys = Vec::with_capacity(512);
        for _ in 0..512 {
            pubkeys.push(PublicKey::decode(&mut input)?.into_inner());
        }
        let aggregate_pubkey = PublicKey::decode(&mut input)?.into_inner();

        Ok(SyncCommittee(HeliosSyncCommittee {
            pubkeys: FixedVector::new(pubkeys).unwrap(),
            aggregate_pubkey,
        }))
    }
}

impl Terminated for SyncCommittee {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyncAggregate(HeliosSyncAggregate);

impl SyncAggregate {
    pub fn into_inner(self) -> HeliosSyncAggregate {
        self.0
    }
}

impl Deref for SyncAggregate {
    type Target = HeliosSyncAggregate;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SyncAggregate {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for SyncAggregate {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        encode_sync_aggregate(&self.0, dest)
    }

    fn encoding_length(&self) -> ed::Result<usize> {
        Ok(64 + 96)
    }
}

pub fn encode_sync_aggregate<W: std::io::Write>(
    sa: &HeliosSyncAggregate,
    dest: &mut W,
) -> ed::Result<()> {
    sa.sync_committee_bits.as_slice().encode_into(dest)?;
    encode_signature(&sa.sync_committee_signature, dest)
}

impl Decode for SyncAggregate {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let sync_committee_bits = Vec::<u8>::decode(&mut input)?;
        let sync_committee_signature = Signature::decode(&mut input)?.into_inner();

        Ok(SyncAggregate(HeliosSyncAggregate {
            sync_committee_bits: Bitfield::from_ssz_bytes(&sync_committee_bits)
                // TODO: pass through error
                .map_err(|_| ed::Error::UnexpectedByte(34))?,
            sync_committee_signature,
        }))
    }
}

impl Terminated for SyncAggregate {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
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

fn encode_public_key<W: std::io::Write>(pk: &HeliosPublicKey, dest: &mut W) -> ed::Result<()> {
    pk.as_ssz_bytes().encode_into(dest)
}

impl Decode for PublicKey {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let mut bytes = [0u8; 48];
        input.read_exact(&mut bytes)?;
        // TODO: pass through error
        let value =
            HeliosPublicKey::from_ssz_bytes(&bytes).map_err(|_| ed::Error::UnexpectedByte(33))?;
        Ok(PublicKey(value))
    }
}

impl Terminated for PublicKey {}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature(HeliosSignature);

impl Signature {
    pub fn into_inner(self) -> HeliosSignature {
        self.0
    }
}

impl From<HeliosSignature> for Signature {
    fn from(value: HeliosSignature) -> Self {
        Signature(value)
    }
}

impl Deref for Signature {
    type Target = HeliosSignature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Signature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for Signature {
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

fn encode_signature<W: std::io::Write>(sig: &HeliosSignature, dest: &mut W) -> ed::Result<()> {
    sig.as_ssz_bytes().encode_into(dest)
}

impl Decode for Signature {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let mut bytes = [0u8; 96];
        input.read_exact(&mut bytes)?;
        // TODO: pass through error
        let value =
            HeliosSignature::from_ssz_bytes(&bytes).map_err(|_| ed::Error::UnexpectedByte(33))?;

        Ok(Signature(value))
    }
}

impl Terminated for Signature {}

#[derive(Clone, Debug, Default, Encode, Decode, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bytes32(#[serde(with = "SerHex::<StrictPfx>")] pub [u8; 32]);

impl Bytes32 {
    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(value: [u8; 32]) -> Self {
        Bytes32(value)
    }
}

impl Display for Bytes32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl FromStr for Bytes32 {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|_| orga::Error::App("Invalid hex".to_string()))?;
        let bytes = bytes
            .as_slice()
            .try_into()
            .map_err(|_| orga::Error::App("Invalid length".to_string()))?;
        Ok(Bytes32(bytes))
    }
}

#[cfg(test)]
mod tests {
    use relayer::Response;

    use super::*;

    #[test]
    fn encode_decode() {
        let pk = PublicKey(HeliosPublicKey::default());
        let bytes = pk.encode().unwrap();
        let pk2 = PublicKey::decode(&bytes[..]).unwrap();

        let lc = LightClient::default();
        let bytes = lc.encode().unwrap();
        let lc = LightClient::decode(&bytes[..]).unwrap();
    }

    #[test]
    fn serialize_deserialize() {
        let pk = PublicKey(HeliosPublicKey::default());
        let pk_str = serde_json::to_string(&pk).unwrap();
        assert_eq!(pk_str, "\"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"");
        let pk2: PublicKey = serde_json::from_str(&pk_str).unwrap();

        let sig = Signature(HeliosSignature::default());
        let sig_str = serde_json::to_string(&sig).unwrap();
        assert_eq!(sig_str, "\"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"");
        let sig2: Signature = serde_json::from_str(&sig_str).unwrap();
    }

    #[tokio::test]
    async fn update() {
        let fixtures = include_str!("test_fixtures.json");
        let (bootstrap, updates, finality_update): (
            Response<Bootstrap>,
            Vec<Response<Update>>,
            Response<Update>,
        ) = serde_json::from_str(fixtures).unwrap();

        let mut client = LightClient::new(bootstrap.data, Network::ethereum_mainnet()).unwrap();
        for update in updates {
            client.update(update.data, 1727740110).unwrap();
        }
        client.update(finality_update.data, 1727740110).unwrap();

        assert_eq!(client.lcs.finalized_header.beacon.slot, 10076224);
    }
}
