// @generated
/// IndexedBlock is the necessary metadata and finalization status of a block
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IndexedBlock {
    /// height is the height of the block
    #[prost(uint64, tag="1")]
    pub height: u64,
    /// app_hash is the AppHash of the block
    #[prost(bytes="vec", tag="2")]
    pub app_hash: ::prost::alloc::vec::Vec<u8>,
    /// finalized indicates whether the IndexedBlock is finalised by 2/3
    /// finality providers or not
    #[prost(bool, tag="3")]
    pub finalized: bool,
}
/// Evidence is the evidence that a finality provider has signed finality
/// signatures with correct public randomness on two conflicting Babylon headers
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Evidence {
    /// fp_btc_pk is the BTC PK of the finality provider that casts this vote
    #[prost(bytes="vec", tag="1")]
    pub fp_btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// block_height is the height of the conflicting blocks
    #[prost(uint64, tag="2")]
    pub block_height: u64,
    /// pub_rand is the public randomness the finality provider has committed to
    #[prost(bytes="vec", tag="3")]
    pub pub_rand: ::prost::alloc::vec::Vec<u8>,
    /// canonical_app_hash is the AppHash of the canonical block
    #[prost(bytes="vec", tag="4")]
    pub canonical_app_hash: ::prost::alloc::vec::Vec<u8>,
    /// fork_app_hash is the AppHash of the fork block
    #[prost(bytes="vec", tag="5")]
    pub fork_app_hash: ::prost::alloc::vec::Vec<u8>,
    /// canonical_finality_sig is the finality signature to the canonical block
    /// where finality signature is an EOTS signature, i.e.,
    /// the `s` in a Schnorr signature `(r, s)`
    /// `r` is the public randomness that is already committed by the finality provider
    #[prost(bytes="vec", tag="6")]
    pub canonical_finality_sig: ::prost::alloc::vec::Vec<u8>,
    /// fork_finality_sig is the finality signature to the fork block
    /// where finality signature is an EOTS signature
    #[prost(bytes="vec", tag="7")]
    pub fork_finality_sig: ::prost::alloc::vec::Vec<u8>,
}
/// EventSlashedFinalityProvider is the event emitted when a finality provider is slashed
/// due to signing two conflicting blocks
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventSlashedFinalityProvider {
    /// evidence is the evidence that the finality provider double signs
    #[prost(message, optional, tag="1")]
    pub evidence: ::core::option::Option<Evidence>,
}
/// Params defines the parameters for the module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    /// min_pub_rand is the minimum number of public randomness each 
    /// message should commit
    #[prost(uint64, tag="1")]
    pub min_pub_rand: u64,
}
/// GenesisState defines the finality module's genesis state.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
    /// params the current params of the state.
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<Params>,
    /// indexed_blocks all the btc blocks and if their status are finalized.
    #[prost(message, repeated, tag="2")]
    pub indexed_blocks: ::prost::alloc::vec::Vec<IndexedBlock>,
    /// evidences all the evidences ever registered.
    #[prost(message, repeated, tag="3")]
    pub evidences: ::prost::alloc::vec::Vec<Evidence>,
    /// votes_sigs contains all the votes of finality providers ever registered.
    #[prost(message, repeated, tag="4")]
    pub vote_sigs: ::prost::alloc::vec::Vec<VoteSig>,
    /// public_randomness contains all the public randomness ever commited from the finality providers.
    #[prost(message, repeated, tag="5")]
    pub public_randomness: ::prost::alloc::vec::Vec<PublicRandomness>,
}
/// VoteSig the vote of an finality provider
/// with the block of the vote, the finality provider btc public key and the vote signature.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VoteSig {
    /// block_height is the height of the voted block.
    #[prost(uint64, tag="1")]
    pub block_height: u64,
    /// fp_btc_pk is the BTC PK of the finality provider that casts this vote
    #[prost(bytes="vec", tag="2")]
    pub fp_btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// finality_sig is the finality signature to this block
    /// where finality signature is an EOTS signature, i.e.
    #[prost(bytes="vec", tag="3")]
    pub finality_sig: ::prost::alloc::vec::Vec<u8>,
}
/// PublicRandomness the block height and public randomness that the finality provider has submitted.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicRandomness {
    /// block_height is the height of block which the finality provider submited public randomness.
    #[prost(uint64, tag="1")]
    pub block_height: u64,
    /// fp_btc_pk is the BTC PK of the finality provider that casts this vote.
    #[prost(bytes="vec", tag="2")]
    pub fp_btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// pub_rand is the public randomness the finality provider has committed to.
    #[prost(bytes="vec", tag="3")]
    pub pub_rand: ::prost::alloc::vec::Vec<u8>,
}
/// QueryParamsRequest is request type for the Query/Params RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryParamsRequest {
}
/// QueryParamsResponse is response type for the Query/Params RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryParamsResponse {
    /// params holds all the parameters of this module.
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<Params>,
}
/// QueryListPublicRandomnessRequest is the request type for the
/// Query/ListPublicRandomness RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryListPublicRandomnessRequest {
    /// fp_btc_pk_hex is the hex str of Bitcoin secp256k1 PK of the finality provider
    #[prost(string, tag="1")]
    pub fp_btc_pk_hex: ::prost::alloc::string::String,
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryListPublicRandomnessResponse is the response type for the
/// Query/ListPublicRandomness RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryListPublicRandomnessResponse {
    /// pub_rand_map is the map where the key is the height and the value
    /// is the public randomness at this height for the given finality provider
    #[prost(map="uint64, bytes", tag="1")]
    pub pub_rand_map: ::std::collections::HashMap<u64, ::prost::alloc::vec::Vec<u8>>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryBlockRequest is the request type for the
/// Query/Block RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBlockRequest {
    /// height is the height of the Babylon block
    #[prost(uint64, tag="1")]
    pub height: u64,
}
/// QueryBlockResponse is the response type for the
/// Query/Block RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBlockResponse {
    /// block is the Babylon at the given height
    #[prost(message, optional, tag="1")]
    pub block: ::core::option::Option<IndexedBlock>,
}
/// QueryListBlocksRequest is the request type for the
/// Query/ListBlocks RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryListBlocksRequest {
    /// status indicates the status of blocks that the querier wants to query
    #[prost(enumeration="QueriedBlockStatus", tag="1")]
    pub status: i32,
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryListBlocksResponse is the response type for the
/// Query/ListBlocks RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryListBlocksResponse {
    /// blocks is the list of blocks at the given status
    #[prost(message, repeated, tag="1")]
    pub blocks: ::prost::alloc::vec::Vec<IndexedBlock>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryVotesAtHeightRequest is the request type for the
/// Query/VotesAtHeight RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryVotesAtHeightRequest {
    /// height defines at which height to query the finality providers.
    #[prost(uint64, tag="1")]
    pub height: u64,
}
/// QueryVotesAtHeightResponse is the response type for the
/// Query/VotesAtHeight RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryVotesAtHeightResponse {
    /// btc_pk is the Bitcoin secp256k1 PK of finality providers who have signed the block at given height.
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="vec", repeated, tag="1")]
    pub btc_pks: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// QueryEvidenceRequest is the request type for the
/// Query/Evidence RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryEvidenceRequest {
    /// fp_btc_pk_hex is the hex str of Bitcoin secp256k1 PK
    /// (in BIP340 format) of the finality provider
    #[prost(string, tag="1")]
    pub fp_btc_pk_hex: ::prost::alloc::string::String,
}
/// QueryEvidenceResponse is the response type for the
/// Query/Evidence RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryEvidenceResponse {
    #[prost(message, optional, tag="1")]
    pub evidence: ::core::option::Option<Evidence>,
}
/// QueryListEvidencesRequest is the request type for the
/// Query/ListEvidences RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryListEvidencesRequest {
    /// start_height is the starting height that the querier specifies
    /// such that the RPC will only return evidences since this height
    #[prost(uint64, tag="1")]
    pub start_height: u64,
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryListEvidencesResponse is the response type for the
/// Query/ListEvidences RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryListEvidencesResponse {
    /// blocks is the list of evidences
    #[prost(message, repeated, tag="1")]
    pub evidences: ::prost::alloc::vec::Vec<Evidence>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueriedBlockStatus is the status of blocks that the querier wants to query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum QueriedBlockStatus {
    /// NON_FINALIZED means the block is not finalised
    NonFinalized = 0,
    /// FINALIZED means the block is finalized
    Finalized = 1,
    /// ANY means the block can be in any status
    Any = 2,
}
impl QueriedBlockStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            QueriedBlockStatus::NonFinalized => "NON_FINALIZED",
            QueriedBlockStatus::Finalized => "FINALIZED",
            QueriedBlockStatus::Any => "ANY",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NON_FINALIZED" => Some(Self::NonFinalized),
            "FINALIZED" => Some(Self::Finalized),
            "ANY" => Some(Self::Any),
            _ => None,
        }
    }
}
/// MsgAddFinalitySig defines a message for adding a finality vote
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgAddFinalitySig {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// fp_btc_pk is the BTC PK of the finality provider that casts this vote
    #[prost(bytes="vec", tag="2")]
    pub fp_btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// block_height is the height of the voted block
    #[prost(uint64, tag="3")]
    pub block_height: u64,
    /// block_app_hash is the AppHash of the voted block
    #[prost(bytes="vec", tag="4")]
    pub block_app_hash: ::prost::alloc::vec::Vec<u8>,
    /// finality_sig is the finality signature to this block
    /// where finality signature is an EOTS signature, i.e.,
    /// the `s` in a Schnorr signature `(r, s)`
    /// `r` is the public randomness that is already committed by the finality provider
    #[prost(bytes="vec", tag="5")]
    pub finality_sig: ::prost::alloc::vec::Vec<u8>,
}
/// MsgAddFinalitySigResponse is the response to the MsgAddFinalitySig message
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgAddFinalitySigResponse {
}
/// MsgCommitPubRandList defines a message for committing a list of public randomness for EOTS
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCommitPubRandList {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// fp_btc_pk is the BTC PK of the finality provider that commits the public randomness
    #[prost(bytes="vec", tag="2")]
    pub fp_btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// start_height is the start block height of the list of public randomness
    #[prost(uint64, tag="3")]
    pub start_height: u64,
    /// pub_rand_list is the list of public randomness
    #[prost(bytes="vec", repeated, tag="4")]
    pub pub_rand_list: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// sig is the signature on (start_height || pub_rand_list) signed by 
    /// SK corresponding to fp_btc_pk. This prevents others to commit public
    /// randomness on behalf of fp_btc_pk
    /// TODO: another option is to restrict signer to correspond to fp_btc_pk. This restricts
    /// the tx submitter to be the holder of fp_btc_pk. Decide this later
    #[prost(bytes="vec", tag="5")]
    pub sig: ::prost::alloc::vec::Vec<u8>,
}
/// MsgCommitPubRandListResponse is the response to the MsgCommitPubRandList message
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCommitPubRandListResponse {
}
/// MsgUpdateParams defines a message for updating finality module parameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateParams {
    /// authority is the address of the governance account.
    /// just FYI: cosmos.AddressString marks that this field should use type alias
    /// for AddressString instead of string, but the functionality is not yet implemented
    /// in cosmos-proto
    #[prost(string, tag="1")]
    pub authority: ::prost::alloc::string::String,
    /// params defines the finality parameters to update.
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
