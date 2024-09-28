// @generated
/// GenesisState defines the monitor module's genesis state.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
}
/// QueryEndedEpochBtcHeightRequest defines a query type for EndedEpochBtcHeight
/// RPC method
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryEndedEpochBtcHeightRequest {
    #[prost(uint64, tag="1")]
    pub epoch_num: u64,
}
/// QueryEndedEpochBtcHeightResponse defines a response type for
/// EndedEpochBtcHeight RPC method
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryEndedEpochBtcHeightResponse {
    /// height of btc light client when epoch ended
    #[prost(uint64, tag="1")]
    pub btc_light_client_height: u64,
}
/// QueryReportedCheckpointBtcHeightRequest defines a query type for
/// ReportedCheckpointBtcHeight RPC method
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryReportedCheckpointBtcHeightRequest {
    /// ckpt_hash is hex encoded byte string of the hash of the checkpoint
    #[prost(string, tag="1")]
    pub ckpt_hash: ::prost::alloc::string::String,
}
/// QueryReportedCheckpointBtcHeightResponse defines a response type for
/// ReportedCheckpointBtcHeight RPC method
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryReportedCheckpointBtcHeightResponse {
    /// height of btc light client when checkpoint is reported
    #[prost(uint64, tag="1")]
    pub btc_light_client_height: u64,
}
// @@protoc_insertion_point(module)
