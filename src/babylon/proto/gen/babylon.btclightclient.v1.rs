// @generated
/// BTCHeaderInfo is a structure that contains all relevant information about a
/// BTC header
///   - Full header bytes
///   - Header hash for easy retrieval
///   - Height of the header in the BTC chain
///   - Total work spent on the header. This is the sum of the work corresponding
///   to the header Bits field
///     and the total work of the header.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcHeaderInfo {
    #[prost(bytes="vec", tag="1")]
    pub header: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="3")]
    pub height: u64,
    #[prost(bytes="vec", tag="4")]
    pub work: ::prost::alloc::vec::Vec<u8>,
}
/// The header included in the event is the block in the history
/// of the current mainchain to which we are rolling back to.
/// In other words, there is one rollback event emitted per re-org, to the
/// greatest common ancestor of the old and the new fork.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventBtcRollBack {
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<BtcHeaderInfo>,
}
/// EventBTCRollForward is emitted on Msg/InsertHeader
/// The header included in the event is the one the main chain is extended with.
/// In the event of a reorg, each block on the new fork that comes after
/// the greatest common ancestor will have a corresponding roll forward event.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventBtcRollForward {
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<BtcHeaderInfo>,
}
/// EventBTCHeaderInserted is emitted on Msg/InsertHeader
/// The header included in the event is the one that was added to the
/// on chain BTC storage.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventBtcHeaderInserted {
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<BtcHeaderInfo>,
}
/// Params defines the parameters for the module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    /// List of addresses which are allowed to insert headers to btc light client
    /// if the list is empty, any address can insert headers
    #[prost(string, repeated, tag="1")]
    pub insert_headers_allow_list: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// GenesisState defines the btclightclient module's genesis state.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<Params>,
    #[prost(message, repeated, tag="2")]
    pub btc_headers: ::prost::alloc::vec::Vec<BtcHeaderInfo>,
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
/// QueryHashesRequest is request type for the Query/Hashes RPC method.
/// It involves retrieving all hashes that are maintained by the module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryHashesRequest {
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryHashesResponse is response type for the Query/Hashes RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryHashesResponse {
    #[prost(bytes="vec", repeated, tag="1")]
    pub hashes: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryContainsRequest is request type for the Query/Contains RPC method.
/// It involves checking whether a hash is maintained by the module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryContainsRequest {
    #[prost(bytes="vec", tag="1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// QueryContainsResponse is response type for the Query/Contains RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryContainsResponse {
    #[prost(bool, tag="1")]
    pub contains: bool,
}
/// QueryContainsRequest is request type for the temporary Query/ContainsBytes
/// RPC method. It involves checking whether a hash is maintained by the module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryContainsBytesRequest {
    #[prost(bytes="vec", tag="1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// QueryContainsResponse is response type for the temporary Query/ContainsBytes
/// RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryContainsBytesResponse {
    #[prost(bool, tag="1")]
    pub contains: bool,
}
/// QueryMainChainRequest is request type for the Query/MainChain RPC method.
/// It involves retrieving the canonical chain maintained by the module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryMainChainRequest {
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryMainChainResponse is response type for the Query/MainChain RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryMainChainResponse {
    #[prost(message, repeated, tag="1")]
    pub headers: ::prost::alloc::vec::Vec<BtcHeaderInfoResponse>,
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryTipRequest is the request type for the Query/Tip RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryTipRequest {
}
/// QueryTipResponse is the response type for the Query/Tip RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryTipResponse {
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<BtcHeaderInfoResponse>,
}
/// QueryBaseHeaderRequest is the request type for the Query/BaseHeader RPC
/// method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBaseHeaderRequest {
}
/// QueryBaseHeaderResponse is the response type for the Query/BaseHeader RPC
/// method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBaseHeaderResponse {
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<BtcHeaderInfoResponse>,
}
/// QueryMainChainDepthRequest is the request type for the Query/MainChainDepth RPC
/// it contains hex encoded hash of btc block header as parameter
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryHeaderDepthRequest {
    #[prost(string, tag="1")]
    pub hash: ::prost::alloc::string::String,
}
/// QueryMainChainDepthResponse is the response type for the Query/MainChainDepth RPC
/// it contains depth of the block in main chain
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryHeaderDepthResponse {
    #[prost(uint64, tag="1")]
    pub depth: u64,
}
/// BTCHeaderInfoResponse is a structure that contains all relevant information about a
/// BTC header response
///   - Full header as string hex.
///   - Header hash for easy retrieval as string hex.
///   - Height of the header in the BTC chain.
///   - Total work spent on the header. This is the sum of the work corresponding
///   to the header Bits field
///     and the total work of the header.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcHeaderInfoResponse {
    #[prost(string, tag="1")]
    pub header_hex: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub hash_hex: ::prost::alloc::string::String,
    #[prost(uint64, tag="3")]
    pub height: u64,
    /// Work is the sdkmath.Uint as string.
    #[prost(string, tag="4")]
    pub work: ::prost::alloc::string::String,
}
/// MsgInsertHeaders defines the message for multiple incoming header bytes
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgInsertHeaders {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    #[prost(bytes="vec", repeated, tag="2")]
    pub headers: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// MsgInsertHeadersResponse defines the response for the InsertHeaders transaction
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgInsertHeadersResponse {
}
/// MsgUpdateParams defines a message for updating btc light client module parameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateParams {
    /// authority is the address of the governance account.
    /// just FYI: cosmos.AddressString marks that this field should use type alias
    /// for AddressString instead of string, but the functionality is not yet implemented
    /// in cosmos-proto
    #[prost(string, tag="1")]
    pub authority: ::prost::alloc::string::String,
    /// params defines the btc light client parameters to update.
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
