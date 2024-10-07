// @generated
/// Params defines the parameters for the module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    /// ibc_packet_timeout_seconds is the time period after which an unrelayed 
    /// IBC packet becomes timeout, measured in seconds
    #[prost(uint32, tag="1")]
    pub ibc_packet_timeout_seconds: u32,
}
/// GenesisState defines the zoneconcierge module's genesis state.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
    #[prost(string, tag="1")]
    pub port_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<Params>,
}
/// IndexedHeader is the metadata of a CZ header
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IndexedHeader {
    /// chain_id is the unique ID of the chain
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    /// hash is the hash of this header
    #[prost(bytes="vec", tag="2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    /// height is the height of this header on CZ ledger
    /// (hash, height) jointly provides the position of the header on CZ ledger
    #[prost(uint64, tag="3")]
    pub height: u64,
    /// time is the timestamp of this header on CZ ledger
    /// it is needed for CZ to unbond all mature validators/delegations
    /// before this timestamp when this header is BTC-finalised
    #[prost(message, optional, tag="4")]
    pub time: ::core::option::Option<::prost_types::Timestamp>,
    /// babylon_header_hash is the hash of the babylon block that includes this CZ
    /// header
    #[prost(bytes="vec", tag="5")]
    pub babylon_header_hash: ::prost::alloc::vec::Vec<u8>,
    /// babylon_header_height is the height of the babylon block that includes this CZ
    /// header
    #[prost(uint64, tag="6")]
    pub babylon_header_height: u64,
    /// epoch is the epoch number of this header on Babylon ledger
    #[prost(uint64, tag="7")]
    pub babylon_epoch: u64,
    /// babylon_tx_hash is the hash of the tx that includes this header
    /// (babylon_block_height, babylon_tx_hash) jointly provides the position of
    /// the header on Babylon ledger
    #[prost(bytes="vec", tag="8")]
    pub babylon_tx_hash: ::prost::alloc::vec::Vec<u8>,
}
/// Forks is a list of non-canonical `IndexedHeader`s at the same height.
/// For example, assuming the following blockchain
/// ```
/// A <- B <- C <- D <- E
///             \ -- D1
///             \ -- D2
/// ```
/// Then the fork will be {\[D1, D2\]} where each item is in struct `IndexedBlock`.
///
/// Note that each `IndexedHeader` in the fork should have a valid quorum
/// certificate. Such forks exist since Babylon considers CZs might have
/// dishonest majority. Also note that the IBC-Go implementation will only
/// consider the first header in a fork valid, since the subsequent headers
/// cannot be verified without knowing the validator set in the previous header.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Forks {
    /// blocks is the list of non-canonical indexed headers at the same height
    #[prost(message, repeated, tag="3")]
    pub headers: ::prost::alloc::vec::Vec<IndexedHeader>,
}
/// ChainInfo is the information of a CZ
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainInfo {
    /// chain_id is the ID of the chain
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    /// latest_header is the latest header in CZ's canonical chain
    #[prost(message, optional, tag="2")]
    pub latest_header: ::core::option::Option<IndexedHeader>,
    /// latest_forks is the latest forks, formed as a series of IndexedHeader (from
    /// low to high)
    #[prost(message, optional, tag="3")]
    pub latest_forks: ::core::option::Option<Forks>,
    /// timestamped_headers_count is the number of timestamped headers in CZ's
    /// canonical chain
    #[prost(uint64, tag="4")]
    pub timestamped_headers_count: u64,
}
/// FinalizedChainInfo is the information of a CZ that is BTC-finalised
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizedChainInfo {
    /// chain_id is the ID of the chain
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    /// finalized_chain_info is the info of the CZ
    #[prost(message, optional, tag="2")]
    pub finalized_chain_info: ::core::option::Option<ChainInfo>,
    /// epoch_info is the metadata of the last BTC-finalised epoch
    #[prost(message, optional, tag="3")]
    pub epoch_info: ::core::option::Option<super::super::epoching::v1::Epoch>,
    /// raw_checkpoint is the raw checkpoint of this epoch
    #[prost(message, optional, tag="4")]
    pub raw_checkpoint: ::core::option::Option<super::super::checkpointing::v1::RawCheckpoint>,
    /// btc_submission_key is position of two BTC txs that include the raw
    /// checkpoint of this epoch
    #[prost(message, optional, tag="5")]
    pub btc_submission_key: ::core::option::Option<super::super::btccheckpoint::v1::SubmissionKey>,
    /// proof is the proof that the chain info is finalized
    #[prost(message, optional, tag="6")]
    pub proof: ::core::option::Option<ProofFinalizedChainInfo>,
}
/// ProofEpochSealed is the proof that an epoch is sealed by the sealer header,
/// i.e., the 2nd header of the next epoch With the access of metadata
/// - Metadata of this epoch, which includes the sealer header
/// - Raw checkpoint of this epoch
/// The verifier can perform the following verification rules:
/// - The raw checkpoint's `app_hash` is same as in the sealer header
/// - More than 2/3 (in voting power) validators in the validator set of this
/// epoch have signed `app_hash` of the sealer header
/// - The epoch metadata is committed to the `app_hash` of the sealer header
/// - The validator set is committed to the `app_hash` of the sealer header
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofEpochSealed {
    /// validator_set is the validator set of the sealed epoch
    /// This validator set has generated a BLS multisig on `app_hash` of
    /// the sealer header
    #[prost(message, repeated, tag="1")]
    pub validator_set: ::prost::alloc::vec::Vec<super::super::checkpointing::v1::ValidatorWithBlsKey>,
    /// proof_epoch_info is the Merkle proof that the epoch's metadata is committed
    /// to `app_hash` of the sealer header
    #[prost(message, optional, tag="2")]
    pub proof_epoch_info: ::core::option::Option<super::super::super::tendermint::crypto::ProofOps>,
    /// proof_epoch_info is the Merkle proof that the epoch's validator set is
    /// committed to `app_hash` of the sealer header
    #[prost(message, optional, tag="3")]
    pub proof_epoch_val_set: ::core::option::Option<super::super::super::tendermint::crypto::ProofOps>,
}
/// ProofFinalizedChainInfo is a set of proofs that attest a chain info is
/// BTC-finalised
///
///
/// The following fields include proofs that attest the chain info is
/// BTC-finalised
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofFinalizedChainInfo {
    /// proof_cz_header_in_epoch is the proof that the CZ header is timestamped
    /// within a certain epoch
    #[prost(message, optional, tag="1")]
    pub proof_cz_header_in_epoch: ::core::option::Option<super::super::super::tendermint::crypto::ProofOps>,
    /// proof_epoch_sealed is the proof that the epoch is sealed
    #[prost(message, optional, tag="2")]
    pub proof_epoch_sealed: ::core::option::Option<ProofEpochSealed>,
    /// proof_epoch_submitted is the proof that the epoch's checkpoint is included
    /// in BTC ledger It is the two TransactionInfo in the best (i.e., earliest)
    /// checkpoint submission
    #[prost(message, repeated, tag="3")]
    pub proof_epoch_submitted: ::prost::alloc::vec::Vec<super::super::btccheckpoint::v1::TransactionInfo>,
}
/// Btc light client chain segment grown during last finalized epoch
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcChainSegment {
    #[prost(message, repeated, tag="1")]
    pub btc_headers: ::prost::alloc::vec::Vec<super::super::btclightclient::v1::BtcHeaderInfo>,
}
/// ZoneconciergePacketData is the message that defines the IBC packets of
/// ZoneConcierge
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ZoneconciergePacketData {
    /// packet is the actual message carried in the IBC packet
    #[prost(oneof="zoneconcierge_packet_data::Packet", tags="1")]
    pub packet: ::core::option::Option<zoneconcierge_packet_data::Packet>,
}
/// Nested message and enum types in `ZoneconciergePacketData`.
pub mod zoneconcierge_packet_data {
    /// packet is the actual message carried in the IBC packet
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Packet {
        #[prost(message, tag="1")]
        BtcTimestamp(super::BtcTimestamp),
    }
}
/// BTCTimestamp is a BTC timestamp that carries information of a BTC-finalised epoch
/// It includes a number of BTC headers, a raw checkpoint, an epoch metadata, and 
/// a CZ header if there exists CZ headers checkpointed to this epoch.
/// Upon a newly finalised epoch in Babylon, Babylon will send a BTC timestamp to each
/// Cosmos zone that has phase-2 integration with Babylon via IBC.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcTimestamp {
    /// header is the last CZ header in the finalized Babylon epoch
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<IndexedHeader>,
    //
    // Data for BTC light client

    /// btc_headers is BTC headers between
    /// - the block AFTER the common ancestor of BTC tip at epoch `lastFinalizedEpoch-1` and BTC tip at epoch `lastFinalizedEpoch`
    /// - BTC tip at epoch `lastFinalizedEpoch`
    /// where `lastFinalizedEpoch` is the last finalised epoch in Babylon
    #[prost(message, repeated, tag="2")]
    pub btc_headers: ::prost::alloc::vec::Vec<super::super::btclightclient::v1::BtcHeaderInfo>,
    //
    // Data for Babylon epoch chain

    /// epoch_info is the metadata of the sealed epoch
    #[prost(message, optional, tag="3")]
    pub epoch_info: ::core::option::Option<super::super::epoching::v1::Epoch>,
    /// raw_checkpoint is the raw checkpoint that seals this epoch
    #[prost(message, optional, tag="4")]
    pub raw_checkpoint: ::core::option::Option<super::super::checkpointing::v1::RawCheckpoint>,
    /// btc_submission_key is position of two BTC txs that include the raw checkpoint of this epoch
    #[prost(message, optional, tag="5")]
    pub btc_submission_key: ::core::option::Option<super::super::btccheckpoint::v1::SubmissionKey>,
    /// 
    /// Proofs that the header is finalized
    #[prost(message, optional, tag="6")]
    pub proof: ::core::option::Option<ProofFinalizedChainInfo>,
}
/// QueryParamsRequest is the request type for the Query/Params RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryParamsRequest {
}
/// QueryParamsResponse is the response type for the Query/Params RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryParamsResponse {
    /// params holds all the parameters of this module.
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<Params>,
}
/// QueryHeaderRequest is request type for the Query/Header RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryHeaderRequest {
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="2")]
    pub height: u64,
}
/// QueryHeaderResponse is response type for the Query/Header RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryHeaderResponse {
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<IndexedHeader>,
    #[prost(message, optional, tag="2")]
    pub fork_headers: ::core::option::Option<Forks>,
}
/// QueryChainListRequest is request type for the Query/ChainList RPC method
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryChainListRequest {
    /// pagination defines whether to have the pagination in the request
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryChainListResponse is response type for the Query/ChainList RPC method
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryChainListResponse {
    /// chain_ids are IDs of the chains in ascending alphabetical order
    #[prost(string, repeated, tag="1")]
    pub chain_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// pagination defines the pagination in the response
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryChainsInfoRequest is request type for the Query/ChainsInfo RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryChainsInfoRequest {
    #[prost(string, repeated, tag="1")]
    pub chain_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// QueryChainsInfoResponse is response type for the Query/ChainsInfo RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryChainsInfoResponse {
    #[prost(message, repeated, tag="1")]
    pub chains_info: ::prost::alloc::vec::Vec<ChainInfo>,
}
/// QueryEpochChainsInfoRequest is request type for the Query/EpochChainsInfo RPC
/// method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryEpochChainsInfoRequest {
    #[prost(uint64, tag="1")]
    pub epoch_num: u64,
    #[prost(string, repeated, tag="2")]
    pub chain_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// QueryEpochChainsInfoResponse is response type for the Query/EpochChainsInfo RPC
/// method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryEpochChainsInfoResponse {
    /// chain_info is the info of the CZ
    #[prost(message, repeated, tag="1")]
    pub chains_info: ::prost::alloc::vec::Vec<ChainInfo>,
}
/// QueryListHeadersRequest is request type for the Query/ListHeaders RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryListHeadersRequest {
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    /// pagination defines whether to have the pagination in the request
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryListHeadersResponse is response type for the Query/ListHeaders RPC
/// method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryListHeadersResponse {
    /// headers is the list of headers
    #[prost(message, repeated, tag="1")]
    pub headers: ::prost::alloc::vec::Vec<IndexedHeader>,
    /// pagination defines the pagination in the response
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryListEpochHeadersRequest is request type for the Query/ListEpochHeaders
/// RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryListEpochHeadersRequest {
    #[prost(uint64, tag="1")]
    pub epoch_num: u64,
    #[prost(string, tag="2")]
    pub chain_id: ::prost::alloc::string::String,
}
/// QueryListEpochHeadersResponse is response type for the Query/ListEpochHeaders
/// RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryListEpochHeadersResponse {
    /// headers is the list of headers
    #[prost(message, repeated, tag="1")]
    pub headers: ::prost::alloc::vec::Vec<IndexedHeader>,
}
/// QueryFinalizedChainsInfoRequest is request type for the
/// Query/FinalizedChainsInfo RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalizedChainsInfoRequest {
    /// chain_ids is the list of ids of CZs
    #[prost(string, repeated, tag="1")]
    pub chain_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// prove indicates whether the querier wants to get proofs of this timestamp
    #[prost(bool, tag="2")]
    pub prove: bool,
}
/// QueryFinalizedChainsInfoResponse is response type for the
/// Query/FinalizedChainsInfo RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalizedChainsInfoResponse {
    #[prost(message, repeated, tag="1")]
    pub finalized_chains_info: ::prost::alloc::vec::Vec<FinalizedChainInfo>,
}
/// QueryFinalizedChainInfoUntilHeightRequest is request type for the
/// Query/FinalizedChainInfoUntilHeight RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalizedChainInfoUntilHeightRequest {
    /// chain_id is the ID of the CZ
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    /// height is the height of the CZ chain
    /// such that the returned finalised chain info will be no later than this
    /// height
    #[prost(uint64, tag="2")]
    pub height: u64,
    /// prove indicates whether the querier wants to get proofs of this timestamp
    #[prost(bool, tag="3")]
    pub prove: bool,
}
/// QueryFinalizedChainInfoUntilHeightResponse is response type for the
/// Query/FinalizedChainInfoUntilHeight RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalizedChainInfoUntilHeightResponse {
    /// finalized_chain_info is the info of the CZ
    #[prost(message, optional, tag="1")]
    pub finalized_chain_info: ::core::option::Option<ChainInfo>,
    /// epoch_info is the metadata of the last BTC-finalised epoch
    #[prost(message, optional, tag="2")]
    pub epoch_info: ::core::option::Option<super::super::epoching::v1::Epoch>,
    /// raw_checkpoint is the raw checkpoint of this epoch
    #[prost(message, optional, tag="3")]
    pub raw_checkpoint: ::core::option::Option<super::super::checkpointing::v1::RawCheckpoint>,
    /// btc_submission_key is position of two BTC txs that include the raw
    /// checkpoint of this epoch
    #[prost(message, optional, tag="4")]
    pub btc_submission_key: ::core::option::Option<super::super::btccheckpoint::v1::SubmissionKey>,
    /// proof is the proof that the chain info is finalized
    #[prost(message, optional, tag="5")]
    pub proof: ::core::option::Option<ProofFinalizedChainInfo>,
}
/// MsgUpdateParams defines a message for updating zoneconcierge module parameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateParams {
    /// authority is the address of the governance account.
    /// just FYI: cosmos.AddressString marks that this field should use type alias
    /// for AddressString instead of string, but the functionality is not yet implemented
    /// in cosmos-proto
    #[prost(string, tag="1")]
    pub authority: ::prost::alloc::string::String,
    /// params defines the zoneconcierge parameters to update.
    ///
    /// NOTE: All parameters must be supplied.
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<Params>,
}
/// MsgUpdateParamsResponse is the response to the MsgUpdateParams message.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateParamsResponse {
}
// @@protoc_insertion_point(module)
