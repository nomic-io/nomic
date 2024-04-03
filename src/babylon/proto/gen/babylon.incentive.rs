// @generated
/// Params defines the parameters for the module, including portions of rewards
/// distributed to each type of stakeholder. Note that sum of the portions should
/// be strictly less than 1 so that the rest will go to Comet validators/delegations
/// adapted from <https://github.com/cosmos/cosmos-sdk/blob/release/v0.47.x/proto/cosmos/distribution/v1beta1/distribution.proto>
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    /// submitter_portion is the portion of rewards that goes to submitter
    #[prost(string, tag="1")]
    pub submitter_portion: ::prost::alloc::string::String,
    /// reporter_portion is the portion of rewards that goes to reporter
    #[prost(string, tag="2")]
    pub reporter_portion: ::prost::alloc::string::String,
    /// btc_staking_portion is the portion of rewards that goes to Finality Providers/delegations
    /// NOTE: the portion of each Finality Provider/delegation is calculated by using its voting
    /// power and finality provider's commission
    #[prost(string, tag="3")]
    pub btc_staking_portion: ::prost::alloc::string::String,
}
/// GenesisState defines the incentive module's genesis state.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<Params>,
}
/// Gauge is an object that stores rewards to be distributed
/// code adapted from <https://github.com/osmosis-labs/osmosis/blob/v18.0.0/proto/osmosis/incentives/gauge.proto>
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Gauge {
    /// coins are coins that have been in the gauge
    /// Can have multiple coin denoms
    #[prost(message, repeated, tag="1")]
    pub coins: ::prost::alloc::vec::Vec<super::super::cosmos::base::v1beta1::Coin>,
}
/// RewardGauge is an object that stores rewards distributed to a BTC staking/timestamping stakeholder
/// code adapted from <https://github.com/osmosis-labs/osmosis/blob/v18.0.0/proto/osmosis/incentives/gauge.proto>
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RewardGauge {
    /// coins are coins that have been in the gauge
    /// Can have multiple coin denoms
    #[prost(message, repeated, tag="1")]
    pub coins: ::prost::alloc::vec::Vec<super::super::cosmos::base::v1beta1::Coin>,
    /// withdrawn_coins are coins that have been withdrawn by the stakeholder already
    #[prost(message, repeated, tag="2")]
    pub withdrawn_coins: ::prost::alloc::vec::Vec<super::super::cosmos::base::v1beta1::Coin>,
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
/// QueryRewardGaugesRequest is request type for the Query/RewardGauges RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryRewardGaugesRequest {
    /// address is the address of the stakeholder in bech32 string
    #[prost(string, tag="1")]
    pub address: ::prost::alloc::string::String,
}
/// QueryRewardGaugesResponse is response type for the Query/RewardGauges RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryRewardGaugesResponse {
    /// reward_gauges is the map of reward gauges, where key is the stakeholder type
    /// and value is the reward gauge holding all rewards for the stakeholder in that type
    #[prost(map="string, message", tag="1")]
    pub reward_gauges: ::std::collections::HashMap<::prost::alloc::string::String, RewardGauge>,
}
/// QueryBTCStakingGaugeRequest is request type for the Query/BTCStakingGauge RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBtcStakingGaugeRequest {
    /// height is the queried Babylon height
    #[prost(uint64, tag="1")]
    pub height: u64,
}
/// QueryBTCStakingGaugeResponse is response type for the Query/BTCStakingGauge RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBtcStakingGaugeResponse {
    /// gauge is the BTC staking gauge at the queried height 
    #[prost(message, optional, tag="1")]
    pub gauge: ::core::option::Option<Gauge>,
}
/// QueryBTCTimestampingGaugeRequest is request type for the Query/BTCTimestampingGauge RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBtcTimestampingGaugeRequest {
    /// epoch_num is the queried epoch number
    #[prost(uint64, tag="1")]
    pub epoch_num: u64,
}
/// QueryBTCTimestampingGaugeResponse is response type for the Query/BTCTimestampingGauge RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBtcTimestampingGaugeResponse {
    /// gauge is the BTC timestamping gauge at the queried epoch 
    #[prost(message, optional, tag="1")]
    pub gauge: ::core::option::Option<Gauge>,
}
/// MsgWithdrawReward defines a message for withdrawing reward of a stakeholder.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgWithdrawReward {
    /// {submitter, reporter, finality_provider, btc_delegation}
    #[prost(string, tag="1")]
    pub r#type: ::prost::alloc::string::String,
    /// address is the address of the stakeholder in bech32 string
    /// signer of this msg has to be this address
    #[prost(string, tag="2")]
    pub address: ::prost::alloc::string::String,
}
/// MsgWithdrawRewardResponse is the response to the MsgWithdrawReward message
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgWithdrawRewardResponse {
    /// coins is the withdrawed coins
    #[prost(message, repeated, tag="1")]
    pub coins: ::prost::alloc::vec::Vec<super::super::cosmos::base::v1beta1::Coin>,
}
/// MsgUpdateParams defines a message for updating incentive module parameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgUpdateParams {
    /// authority is the address of the governance account.
    /// just FYI: cosmos.AddressString marks that this field should use type alias
    /// for AddressString instead of string, but the functionality is not yet implemented
    /// in cosmos-proto
    #[prost(string, tag="1")]
    pub authority: ::prost::alloc::string::String,
    /// params defines the incentive parameters to update.
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
