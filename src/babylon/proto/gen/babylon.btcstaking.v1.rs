// @generated
/// ProofOfPossession is the proof of possession that a Babylon secp256k1
/// secret key and a Bitcoin secp256k1 secret key are held by the same
/// person
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofOfPossession {
    /// btc_sig_type indicates the type of btc_sig in the pop
    #[prost(enumeration="BtcSigType", tag="1")]
    pub btc_sig_type: i32,
    /// babylon_sig is the signature generated via sign(sk_babylon, pk_btc)
    #[prost(bytes="vec", tag="2")]
    pub babylon_sig: ::prost::alloc::vec::Vec<u8>,
    /// btc_sig is the signature generated via sign(sk_btc, babylon_sig)
    /// the signature follows encoding in either BIP-340 spec or BIP-322 spec
    #[prost(bytes="vec", tag="3")]
    pub btc_sig: ::prost::alloc::vec::Vec<u8>,
}
/// BIP322Sig is a BIP-322 signature together with the address corresponding to
/// the signer
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Bip322Sig {
    /// address is the signer's address
    #[prost(string, tag="1")]
    pub address: ::prost::alloc::string::String,
    /// sig is the actual signature in BIP-322 format
    #[prost(bytes="vec", tag="2")]
    pub sig: ::prost::alloc::vec::Vec<u8>,
}
/// BTCSigType indicates the type of btc_sig in a pop
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum BtcSigType {
    /// BIP340 means the btc_sig will follow the BIP-340 encoding
    Bip340 = 0,
    /// BIP322 means the btc_sig will follow the BIP-322 encoding
    Bip322 = 1,
    /// ECDSA means the btc_sig will follow the ECDSA encoding
    /// ref: <https://github.com/okx/js-wallet-sdk/blob/a57c2acbe6ce917c0aa4e951d96c4e562ad58444/packages/coin-bitcoin/src/BtcWallet.ts#L331>
    Ecdsa = 2,
}
impl BtcSigType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            BtcSigType::Bip340 => "BIP340",
            BtcSigType::Bip322 => "BIP322",
            BtcSigType::Ecdsa => "ECDSA",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "BIP340" => Some(Self::Bip340),
            "BIP322" => Some(Self::Bip322),
            "ECDSA" => Some(Self::Ecdsa),
            _ => None,
        }
    }
}
/// FinalityProvider defines a finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalityProvider {
    /// description defines the description terms for the finality provider.
    #[prost(message, optional, tag="1")]
    pub description: ::core::option::Option<super::super::super::cosmos::staking::v1beta1::Description>,
    /// commission defines the commission rate of the finality provider.
    #[prost(string, tag="2")]
    pub commission: ::prost::alloc::string::String,
    /// babylon_pk is the Babylon secp256k1 PK of this finality provider
    #[prost(message, optional, tag="3")]
    pub babylon_pk: ::core::option::Option<super::super::super::cosmos::crypto::secp256k1::PubKey>,
    /// btc_pk is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="vec", tag="4")]
    pub btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="5")]
    pub pop: ::core::option::Option<ProofOfPossession>,
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="6")]
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="7")]
    pub slashed_btc_height: u64,
}
/// FinalityProviderWithMeta wraps the FinalityProvider with metadata.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalityProviderWithMeta {
    /// btc_pk is the Bitcoin secp256k1 PK of thisfinality provider
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="vec", tag="1")]
    pub btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// height is the queried Babylon height
    #[prost(uint64, tag="2")]
    pub height: u64,
    /// voting_power is the voting power of this finality provider at the given height
    #[prost(uint64, tag="3")]
    pub voting_power: u64,
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="4")]
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="5")]
    pub slashed_btc_height: u64,
}
/// BTCDelegation defines a BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcDelegation {
    /// babylon_pk is the Babylon secp256k1 PK of this BTC delegation
    #[prost(message, optional, tag="1")]
    pub babylon_pk: ::core::option::Option<super::super::super::cosmos::crypto::secp256k1::PubKey>,
    /// btc_pk is the Bitcoin secp256k1 PK of this BTC delegation
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="vec", tag="2")]
    pub btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="3")]
    pub pop: ::core::option::Option<ProofOfPossession>,
    /// fp_btc_pk_list is the list of BIP-340 PKs of the finality providers that
    /// this BTC delegation delegates to
    /// If there is more than 1 PKs, then this means the delegation is restaked
    /// to multiple finality providers
    #[prost(bytes="vec", repeated, tag="4")]
    pub fp_btc_pk_list: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// start_height is the start BTC height of the BTC delegation
    /// it is the start BTC height of the timelock
    #[prost(uint64, tag="5")]
    pub start_height: u64,
    /// end_height is the end height of the BTC delegation
    /// it is the end BTC height of the timelock - w
    #[prost(uint64, tag="6")]
    pub end_height: u64,
    /// total_sat is the total amount of BTC stakes in this delegation
    /// quantified in satoshi
    #[prost(uint64, tag="7")]
    pub total_sat: u64,
    /// staking_tx is the staking tx
    #[prost(bytes="vec", tag="8")]
    pub staking_tx: ::prost::alloc::vec::Vec<u8>,
    /// staking_output_idx is the index of the staking output in the staking tx
    #[prost(uint32, tag="9")]
    pub staking_output_idx: u32,
    /// slashing_tx is the slashing tx
    /// It is partially signed by SK corresponding to btc_pk, but not signed by
    /// finality provider or covenant yet.
    #[prost(bytes="vec", tag="10")]
    pub slashing_tx: ::prost::alloc::vec::Vec<u8>,
    /// delegator_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It will be a part of the witness for the staking tx output.
    #[prost(bytes="vec", tag="11")]
    pub delegator_sig: ::prost::alloc::vec::Vec<u8>,
    /// covenant_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="12")]
    pub covenant_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
    /// unbonding_time describes how long the funds will be locked either in unbonding output
    /// or slashing change output
    #[prost(uint32, tag="13")]
    pub unbonding_time: u32,
    /// btc_undelegation is the information about the early unbonding path of the BTC delegation
    #[prost(message, optional, tag="14")]
    pub btc_undelegation: ::core::option::Option<BtcUndelegation>,
}
/// BTCUndelegation contains the information about the early unbonding path of the BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcUndelegation {
    /// unbonding_tx is the transaction which will transfer the funds from staking
    /// output to unbonding output. Unbonding output will usually have lower timelock
    /// than staking output.
    #[prost(bytes="vec", tag="1")]
    pub unbonding_tx: ::prost::alloc::vec::Vec<u8>,
    /// slashing_tx is the slashing tx for unbonding transactions
    /// It is partially signed by SK corresponding to btc_pk, but not signed by
    /// finality provider or covenant yet.
    #[prost(bytes="vec", tag="2")]
    pub slashing_tx: ::prost::alloc::vec::Vec<u8>,
    /// delegator_unbonding_sig is the signature on the unbonding tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It effectively proves that the delegator wants to unbond and thus
    /// Babylon will consider this BTC delegation unbonded. Delegator's BTC
    /// on Bitcoin will be unbonded after timelock
    #[prost(bytes="vec", tag="3")]
    pub delegator_unbonding_sig: ::prost::alloc::vec::Vec<u8>,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It will be a part of the witness for the unbonding tx output.
    #[prost(bytes="vec", tag="4")]
    pub delegator_slashing_sig: ::prost::alloc::vec::Vec<u8>,
    /// covenant_slashing_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="5")]
    pub covenant_slashing_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
    /// covenant_unbonding_sig_list is the list of signatures on the unbonding tx
    /// by covenant members
    /// It must be provided after processing undelegate message by Babylon
    #[prost(message, repeated, tag="6")]
    pub covenant_unbonding_sig_list: ::prost::alloc::vec::Vec<SignatureInfo>,
}
/// BTCDelegatorDelegations is a collection of BTC delegations from the same delegator.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcDelegatorDelegations {
    #[prost(message, repeated, tag="1")]
    pub dels: ::prost::alloc::vec::Vec<BtcDelegation>,
}
/// BTCDelegatorDelegationIndex is a list of staking tx hashes of BTC delegations from the same delegator.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcDelegatorDelegationIndex {
    #[prost(bytes="vec", repeated, tag="1")]
    pub staking_tx_hash_list: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// SignatureInfo is a BIP-340 signature together with its signer's BIP-340 PK
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureInfo {
    #[prost(bytes="vec", tag="1")]
    pub pk: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub sig: ::prost::alloc::vec::Vec<u8>,
}
/// CovenantAdaptorSignatures is a list adaptor signatures signed by the
/// covenant with different finality provider's public keys as encryption keys
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CovenantAdaptorSignatures {
    /// cov_pk is the public key of the covenant emulator, used as the public key of the adaptor signature
    #[prost(bytes="vec", tag="1")]
    pub cov_pk: ::prost::alloc::vec::Vec<u8>,
    /// adaptor_sigs is a list of adaptor signatures, each encrypted by a restaked BTC finality provider's public key
    #[prost(bytes="vec", repeated, tag="2")]
    pub adaptor_sigs: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// SelectiveSlashingEvidence is the evidence that the finality provider
/// selectively slashed a BTC delegation
/// NOTE: it's possible that a slashed finality provider exploits the
/// SelectiveSlashingEvidence endpoint while it is actually slashed due to
/// equivocation. But such behaviour does not affect the system's security
/// or gives any benefit for the adversary
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SelectiveSlashingEvidence {
    /// staking_tx_hash is the hash of the staking tx.
    /// It uniquely identifies a BTC delegation
    #[prost(string, tag="1")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// fp_btc_pk is the BTC PK of the finality provider who
    /// launches the selective slashing offence
    #[prost(bytes="vec", tag="2")]
    pub fp_btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// recovered_fp_btc_sk is the finality provider's BTC SK recovered from
    /// the covenant adaptor/Schnorr signature pair. It is the consequence
    /// of selective slashing.
    #[prost(bytes="vec", tag="3")]
    pub recovered_fp_btc_sk: ::prost::alloc::vec::Vec<u8>,
}
/// BTCDelegationStatus is the status of a delegation. The state transition path is
/// PENDING -> ACTIVE -> UNBONDED with two possibilities:
/// 1. the typical path when timelock of staking transaction expires.
/// 2. the path when staker requests early undelegation through MsgBTCUndelegate message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum BtcDelegationStatus {
    /// PENDING defines a delegation that is waiting for covenant signatures to become active.
    Pending = 0,
    /// ACTIVE defines a delegation that has voting power
    Active = 1,
    /// UNBONDED defines a delegation no longer has voting power:
    /// - either reaching the end of staking transaction timelock
    /// - or receiving unbonding tx with signatures from staker and covenant committee
    Unbonded = 2,
    /// ANY is any of the above status
    Any = 3,
}
impl BtcDelegationStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            BtcDelegationStatus::Pending => "PENDING",
            BtcDelegationStatus::Active => "ACTIVE",
            BtcDelegationStatus::Unbonded => "UNBONDED",
            BtcDelegationStatus::Any => "ANY",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PENDING" => Some(Self::Pending),
            "ACTIVE" => Some(Self::Active),
            "UNBONDED" => Some(Self::Unbonded),
            "ANY" => Some(Self::Any),
            _ => None,
        }
    }
}
/// EventNewFinalityProvider is the event emitted when a finality provider is created
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventNewFinalityProvider {
    #[prost(message, optional, tag="1")]
    pub fp: ::core::option::Option<FinalityProvider>,
}
/// EventBTCDelegationStateUpdate is the event emitted when a BTC delegation's state is
/// updated. There are the following possible state transitions:
/// - non-existing -> pending, which happens upon `MsgCreateBTCDelegation`
/// - pending -> active, which happens upon `MsgAddCovenantSigs`
/// - active -> unbonded, which happens upon `MsgBTCUndelegate` or upon staking tx timelock expires
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventBtcDelegationStateUpdate {
    /// staking_tx_hash is the hash of the staking tx.
    /// It uniquely identifies a BTC delegation
    #[prost(string, tag="1")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// new_state is the new state of this BTC delegation
    #[prost(enumeration="BtcDelegationStatus", tag="2")]
    pub new_state: i32,
}
/// EventSelectiveSlashing is the event emitted when an adversarial 
/// finality provider selectively slashes a BTC delegation. This will
/// result in slashing of all BTC delegations under this finality provider.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventSelectiveSlashing {
    /// evidence is the evidence of selective slashing
    #[prost(message, optional, tag="1")]
    pub evidence: ::core::option::Option<SelectiveSlashingEvidence>,
}
/// EventPowerDistUpdate is an event that affects voting power distirbution
/// of BTC staking protocol
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventPowerDistUpdate {
    /// ev is the event that affects voting power distribution
    #[prost(oneof="event_power_dist_update::Ev", tags="1, 2")]
    pub ev: ::core::option::Option<event_power_dist_update::Ev>,
}
/// Nested message and enum types in `EventPowerDistUpdate`.
pub mod event_power_dist_update {
    /// EventSlashedFinalityProvider defines an event that a finality provider
    /// is slashed
    /// TODO: unify with existing slashing events
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct EventSlashedFinalityProvider {
        #[prost(bytes="vec", tag="1")]
        pub pk: ::prost::alloc::vec::Vec<u8>,
    }
    /// ev is the event that affects voting power distribution
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Ev {
        /// slashed_fp means a finality provider is slashed
        #[prost(message, tag="1")]
        SlashedFp(EventSlashedFinalityProvider),
        /// btc_del_state_update means a BTC delegation's state is updated
        #[prost(message, tag="2")]
        BtcDelStateUpdate(super::EventBtcDelegationStateUpdate),
    }
}
/// Params defines the parameters for the module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    /// covenant_pks is the list of public keys held by the covenant committee
    /// each PK follows encoding in BIP-340 spec on Bitcoin
    #[prost(bytes="vec", repeated, tag="1")]
    pub covenant_pks: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// covenant_quorum is the minimum number of signatures needed for the covenant
    /// multisignature
    #[prost(uint32, tag="2")]
    pub covenant_quorum: u32,
    /// slashing address is the address that the slashed BTC goes to
    /// the address is in string on Bitcoin
    #[prost(string, tag="3")]
    pub slashing_address: ::prost::alloc::string::String,
    /// min_slashing_tx_fee_sat is the minimum amount of tx fee (quantified
    /// in Satoshi) needed for the pre-signed slashing tx
    /// TODO: change to satoshi per byte?
    #[prost(int64, tag="4")]
    pub min_slashing_tx_fee_sat: i64,
    /// min_commission_rate is the chain-wide minimum commission rate that a finality provider can charge their delegators
    #[prost(string, tag="5")]
    pub min_commission_rate: ::prost::alloc::string::String,
    /// slashing_rate determines the portion of the staked amount to be slashed,
    /// expressed as a decimal (e.g., 0.5 for 50%).
    #[prost(string, tag="6")]
    pub slashing_rate: ::prost::alloc::string::String,
    /// max_active_finality_providers is the maximum number of active finality providers in the BTC staking protocol
    #[prost(uint32, tag="7")]
    pub max_active_finality_providers: u32,
    /// min_unbonding_time is the minimum time for unbonding transaction timelock in BTC blocks
    #[prost(uint32, tag="8")]
    pub min_unbonding_time: u32,
    /// min_unbonding_rate is the minimum amount of BTC that are required in unbonding
    /// output, expressed as a fraction of staking output
    /// example: if min_unbonding_rate=0.9, then the unbonding output value
    /// must be at least 90% of staking output, for staking request to be considered
    /// valid
    #[prost(string, tag="9")]
    pub min_unbonding_rate: ::prost::alloc::string::String,
}
/// VotingPowerDistCache is the cache for voting power distribution of finality providers
/// and their BTC delegations at a height
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VotingPowerDistCache {
    #[prost(uint64, tag="1")]
    pub total_voting_power: u64,
    /// finality_providers is a list of finality providers' voting power information
    #[prost(message, repeated, tag="2")]
    pub finality_providers: ::prost::alloc::vec::Vec<FinalityProviderDistInfo>,
}
/// FinalityProviderDistInfo is the reward distribution of a finality provider and its BTC delegations
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalityProviderDistInfo {
    /// btc_pk is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="vec", tag="1")]
    pub btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// babylon_pk is the Babylon public key of the finality provider
    #[prost(message, optional, tag="2")]
    pub babylon_pk: ::core::option::Option<super::super::super::cosmos::crypto::secp256k1::PubKey>,
    /// commission defines the commission rate of finality provider
    #[prost(string, tag="3")]
    pub commission: ::prost::alloc::string::String,
    /// total_voting_power is the total voting power of the finality provider
    #[prost(uint64, tag="4")]
    pub total_voting_power: u64,
    /// btc_dels is a list of BTC delegations' voting power information under this finality provider
    #[prost(message, repeated, tag="5")]
    pub btc_dels: ::prost::alloc::vec::Vec<BtcDelDistInfo>,
}
/// BTCDelDistInfo contains the information related to reward distribution for a BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcDelDistInfo {
    /// btc_pk is the Bitcoin secp256k1 PK of this BTC delegation
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="vec", tag="1")]
    pub btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// babylon_pk is the Babylon public key of the BTC delegation
    #[prost(message, optional, tag="2")]
    pub babylon_pk: ::core::option::Option<super::super::super::cosmos::crypto::secp256k1::PubKey>,
    /// staking_tx_hash is the staking tx hash of the BTC delegation
    #[prost(string, tag="3")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// voting_power is the voting power of the BTC delegation
    #[prost(uint64, tag="4")]
    pub voting_power: u64,
}
/// GenesisState defines the btcstaking module's genesis state.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<Params>,
    /// finality_providers all the finality providers registered.
    #[prost(message, repeated, tag="2")]
    pub finality_providers: ::prost::alloc::vec::Vec<FinalityProvider>,
    /// btc_delegations all the btc delegations in the state.
    #[prost(message, repeated, tag="3")]
    pub btc_delegations: ::prost::alloc::vec::Vec<BtcDelegation>,
    /// voting_powers the voting power of every finality provider at every block height.
    #[prost(message, repeated, tag="4")]
    pub voting_powers: ::prost::alloc::vec::Vec<VotingPowerFp>,
    /// block_height_chains the block height of babylon and bitcoin.
    #[prost(message, repeated, tag="5")]
    pub block_height_chains: ::prost::alloc::vec::Vec<BlockHeightBbnToBtc>,
    /// btc_delegators contains all the btc delegators with the associated finality provider.
    #[prost(message, repeated, tag="6")]
    pub btc_delegators: ::prost::alloc::vec::Vec<BtcDelegator>,
    /// all the events and its indexes.
    #[prost(message, repeated, tag="7")]
    pub events: ::prost::alloc::vec::Vec<EventIndex>,
    /// vp_dst_cache is the table of all providers voting power with the total at one specific block.
    /// TODO: remove this after not storing in the keeper store it anymore.
    #[prost(message, repeated, tag="8")]
    pub vp_dst_cache: ::prost::alloc::vec::Vec<VotingPowerDistCacheBlkHeight>,
}
/// VotingPowerFP contains the information about the voting power
/// of an finality provider in a specific block height.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VotingPowerFp {
    /// block_height is the height of the block the voting power was stored.
    #[prost(uint64, tag="1")]
    pub block_height: u64,
    /// fp_btc_pk the finality provider btc public key.
    #[prost(bytes="vec", tag="2")]
    pub fp_btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// voting_power is the power of the finality provider at this specific block height.
    #[prost(uint64, tag="3")]
    pub voting_power: u64,
}
/// VotingPowerDistCacheBlkHeight the total voting power of the finality providers at one specific block height
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VotingPowerDistCacheBlkHeight {
    /// block_height is the height of the block the voting power distribution cached was stored.
    #[prost(uint64, tag="1")]
    pub block_height: u64,
    /// vp_distribution the finality providers distribution cache at that height.
    #[prost(message, optional, tag="2")]
    pub vp_distribution: ::core::option::Option<VotingPowerDistCache>,
}
/// BlockHeightBbnToBtc stores the btc <-> bbn block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockHeightBbnToBtc {
    /// block_height_bbn is the height of the block in the babylon chain.
    #[prost(uint64, tag="1")]
    pub block_height_bbn: u64,
    /// block_height_btc is the height of the block in the BTC.
    #[prost(uint64, tag="2")]
    pub block_height_btc: u64,
}
/// BTCDelegator BTC delegator information with the associated finality provider.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcDelegator {
    /// idx the btc delegator index.
    #[prost(message, optional, tag="1")]
    pub idx: ::core::option::Option<BtcDelegatorDelegationIndex>,
    /// fp_btc_pk the finality provider btc public key.
    #[prost(bytes="vec", tag="2")]
    pub fp_btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// del_btc_pk the delegator btc public key.
    #[prost(bytes="vec", tag="3")]
    pub del_btc_pk: ::prost::alloc::vec::Vec<u8>,
}
/// EventIndex contains the event and its index.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventIndex {
    /// idx is the index the event was stored.
    #[prost(uint64, tag="1")]
    pub idx: u64,
    /// block_height_btc is the height of the block in the BTC chain.
    #[prost(uint64, tag="2")]
    pub block_height_btc: u64,
    /// event the event stored.
    #[prost(message, optional, tag="3")]
    pub event: ::core::option::Option<EventPowerDistUpdate>,
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
/// QueryFinalityProvidersRequest is the request type for the
/// Query/FinalityProviders RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProvidersRequest {
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="1")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryFinalityProvidersResponse is the response type for the
/// Query/FinalityProviders RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProvidersResponse {
    /// finality_providers contains all the finality providers
    #[prost(message, repeated, tag="1")]
    pub finality_providers: ::prost::alloc::vec::Vec<FinalityProviderResponse>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryFinalityProviderRequest requests information about a finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProviderRequest {
    /// fp_btc_pk_hex is the hex str of Bitcoin secp256k1 PK of the finality provider
    #[prost(string, tag="1")]
    pub fp_btc_pk_hex: ::prost::alloc::string::String,
}
/// QueryFinalityProviderResponse contains information about a finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProviderResponse {
    /// finality_provider contains the FinalityProvider
    #[prost(message, optional, tag="1")]
    pub finality_provider: ::core::option::Option<FinalityProviderResponse>,
}
/// QueryBTCDelegationsRequest is the request type for the
/// Query/BTCDelegations RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBtcDelegationsRequest {
    /// status is the queried status for BTC delegations
    #[prost(enumeration="BtcDelegationStatus", tag="1")]
    pub status: i32,
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryBTCDelegationsResponse is the response type for the
/// Query/BTCDelegations RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBtcDelegationsResponse {
    /// btc_delegations contains all the queried BTC delegations under the given status
    #[prost(message, repeated, tag="1")]
    pub btc_delegations: ::prost::alloc::vec::Vec<BtcDelegationResponse>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryFinalityProviderPowerAtHeightRequest is the request type for the
/// Query/FinalityProviderPowerAtHeight RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProviderPowerAtHeightRequest {
    /// fp_btc_pk_hex is the hex str of Bitcoin secp256k1 PK of the finality provider that
    /// this BTC delegation delegates to
    /// the PK follows encoding in BIP-340 spec
    #[prost(string, tag="1")]
    pub fp_btc_pk_hex: ::prost::alloc::string::String,
    /// height is used for querying the given finality provider's voting power at this height
    #[prost(uint64, tag="2")]
    pub height: u64,
}
/// QueryFinalityProviderPowerAtHeightResponse is the response type for the
/// Query/FinalityProviderPowerAtHeight RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProviderPowerAtHeightResponse {
    /// voting_power is the voting power of the finality provider
    #[prost(uint64, tag="1")]
    pub voting_power: u64,
}
/// QueryFinalityProviderCurrentPowerRequest is the request type for the
/// Query/FinalityProviderCurrentPower RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProviderCurrentPowerRequest {
    /// fp_btc_pk_hex is the hex str of Bitcoin secp256k1 PK of the finality provider that
    /// this BTC delegation delegates to
    /// the PK follows encoding in BIP-340 spec
    #[prost(string, tag="1")]
    pub fp_btc_pk_hex: ::prost::alloc::string::String,
}
/// QueryFinalityProviderCurrentPowerResponse is the response type for the
/// Query/FinalityProviderCurrentPower RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProviderCurrentPowerResponse {
    /// height is the current height
    #[prost(uint64, tag="1")]
    pub height: u64,
    /// voting_power is the voting power of the finality provider
    #[prost(uint64, tag="2")]
    pub voting_power: u64,
}
/// QueryActiveFinalityProvidersAtHeightRequest is the request type for the
/// Query/ActiveFinalityProvidersAtHeight RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryActiveFinalityProvidersAtHeightRequest {
    /// height defines at which Babylon height to query the finality providers info.
    #[prost(uint64, tag="1")]
    pub height: u64,
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryActiveFinalityProvidersAtHeightResponse is the response type for the
/// Query/ActiveFinalityProvidersAtHeight RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryActiveFinalityProvidersAtHeightResponse {
    /// finality_providers contains all the queried finality providersn.
    #[prost(message, repeated, tag="1")]
    pub finality_providers: ::prost::alloc::vec::Vec<FinalityProviderWithMeta>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryActivatedHeightRequest is the request type for the Query/ActivatedHeight RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryActivatedHeightRequest {
}
/// QueryActivatedHeightResponse is the response type for the Query/ActivatedHeight RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryActivatedHeightResponse {
    #[prost(uint64, tag="1")]
    pub height: u64,
}
/// QueryFinalityProviderDelegationsRequest is the request type for the
/// Query/FinalityProviderDelegations RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProviderDelegationsRequest {
    /// fp_btc_pk_hex is the hex str of Bitcoin secp256k1 PK of the finality providerthat
    /// this BTC delegation delegates to
    /// the PK follows encoding in BIP-340 spec
    #[prost(string, tag="1")]
    pub fp_btc_pk_hex: ::prost::alloc::string::String,
    /// pagination defines an optional pagination for the request.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageRequest>,
}
/// QueryFinalityProviderDelegationsResponse is the response type for the
/// Query/FinalityProviderDelegations RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProviderDelegationsResponse {
    /// btc_delegator_delegations contains all the queried BTC delegations.
    #[prost(message, repeated, tag="1")]
    pub btc_delegator_delegations: ::prost::alloc::vec::Vec<BtcDelegatorDelegationsResponse>,
    /// pagination defines the pagination in the response.
    #[prost(message, optional, tag="2")]
    pub pagination: ::core::option::Option<super::super::super::cosmos::base::query::v1beta1::PageResponse>,
}
/// QueryBTCDelegationRequest is the request type to retrieve a BTC delegation by
/// staking tx hash
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBtcDelegationRequest {
    /// Hash of staking transaction in btc format
    #[prost(string, tag="1")]
    pub staking_tx_hash_hex: ::prost::alloc::string::String,
}
/// QueryBTCDelegationResponse is response type matching QueryBTCDelegationRequest
/// and containing BTC delegation information
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryBtcDelegationResponse {
    /// BTCDelegation represents the client needed information of an BTCDelegation.
    #[prost(message, optional, tag="1")]
    pub btc_delegation: ::core::option::Option<BtcDelegationResponse>,
}
/// BTCDelegationResponse is the client needed information from a BTCDelegation with the current status based on parameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcDelegationResponse {
    /// btc_pk is the Bitcoin secp256k1 PK of this BTC delegation
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="vec", tag="1")]
    pub btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// fp_btc_pk_list is the list of BIP-340 PKs of the finality providers that
    /// this BTC delegation delegates to
    #[prost(bytes="vec", repeated, tag="2")]
    pub fp_btc_pk_list: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// start_height is the start BTC height of the BTC delegation
    /// it is the start BTC height of the timelock
    #[prost(uint64, tag="3")]
    pub start_height: u64,
    /// end_height is the end height of the BTC delegation
    /// it is the end BTC height of the timelock - w
    #[prost(uint64, tag="4")]
    pub end_height: u64,
    /// total_sat is the total amount of BTC stakes in this delegation
    /// quantified in satoshi
    #[prost(uint64, tag="5")]
    pub total_sat: u64,
    /// staking_tx_hex is the hex string of staking tx
    #[prost(string, tag="6")]
    pub staking_tx_hex: ::prost::alloc::string::String,
    /// slashing_tx_hex is the hex string of slashing tx
    #[prost(string, tag="7")]
    pub slashing_tx_hex: ::prost::alloc::string::String,
    /// delegator_slash_sig_hex is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk) as string hex.
    /// It will be a part of the witness for the staking tx output.
    #[prost(string, tag="8")]
    pub delegator_slash_sig_hex: ::prost::alloc::string::String,
    /// covenant_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="9")]
    pub covenant_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
    /// staking_output_idx is the index of the staking output in the staking tx
    #[prost(uint32, tag="10")]
    pub staking_output_idx: u32,
    /// whether this delegation is active
    #[prost(bool, tag="11")]
    pub active: bool,
    /// descriptive status of current delegation.
    #[prost(string, tag="12")]
    pub status_desc: ::prost::alloc::string::String,
    /// unbonding_time used in unbonding output timelock path and in slashing transactions
    /// change outputs
    #[prost(uint32, tag="13")]
    pub unbonding_time: u32,
    /// undelegation_response is the undelegation info of this delegation.
    #[prost(message, optional, tag="14")]
    pub undelegation_response: ::core::option::Option<BtcUndelegationResponse>,
}
/// BTCUndelegationResponse provides all necessary info about the undeleagation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcUndelegationResponse {
    /// unbonding_tx is the transaction which will transfer the funds from staking
    /// output to unbonding output. Unbonding output will usually have lower timelock
    /// than staking output. The unbonding tx as string hex.
    #[prost(string, tag="1")]
    pub unbonding_tx_hex: ::prost::alloc::string::String,
    /// delegator_unbonding_sig is the signature on the unbonding tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It effectively proves that the delegator wants to unbond and thus
    /// Babylon will consider this BTC delegation unbonded. Delegator's BTC
    /// on Bitcoin will be unbonded after timelock. The unbonding delegator sig as string hex.
    #[prost(string, tag="2")]
    pub delegator_unbonding_sig_hex: ::prost::alloc::string::String,
    /// covenant_unbonding_sig_list is the list of signatures on the unbonding tx
    /// by covenant members
    #[prost(message, repeated, tag="3")]
    pub covenant_unbonding_sig_list: ::prost::alloc::vec::Vec<SignatureInfo>,
    /// slashingTxHex is the hex string of slashing tx
    #[prost(string, tag="4")]
    pub slashing_tx_hex: ::prost::alloc::string::String,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It will be a part of the witness for the unbonding tx output.
    /// The delegator slashing sig as string hex.
    #[prost(string, tag="5")]
    pub delegator_slashing_sig_hex: ::prost::alloc::string::String,
    /// covenant_slashing_sigs is a list of adaptor signatures on the
    /// unbonding slashing tx by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="6")]
    pub covenant_slashing_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
}
/// BTCDelegatorDelegationsResponse is a collection of BTC delegations responses from the same delegator.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcDelegatorDelegationsResponse {
    #[prost(message, repeated, tag="1")]
    pub dels: ::prost::alloc::vec::Vec<BtcDelegationResponse>,
}
/// FinalityProviderResponse defines a finality provider with voting power information.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalityProviderResponse {
    /// description defines the description terms for the finality provider.
    #[prost(message, optional, tag="1")]
    pub description: ::core::option::Option<super::super::super::cosmos::staking::v1beta1::Description>,
    /// commission defines the commission rate of the finality provider.
    #[prost(string, tag="2")]
    pub commission: ::prost::alloc::string::String,
    /// babylon_pk is the Babylon secp256k1 PK of this finality provider
    #[prost(message, optional, tag="3")]
    pub babylon_pk: ::core::option::Option<super::super::super::cosmos::crypto::secp256k1::PubKey>,
    /// btc_pk is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="vec", tag="4")]
    pub btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="5")]
    pub pop: ::core::option::Option<ProofOfPossession>,
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="6")]
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="7")]
    pub slashed_btc_height: u64,
    /// height is the queried Babylon height
    #[prost(uint64, tag="8")]
    pub height: u64,
    /// voting_power is the voting power of this finality provider at the given height
    #[prost(uint64, tag="9")]
    pub voting_power: u64,
}
/// MsgCreateFinalityProvider is the message for creating a finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateFinalityProvider {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// description defines the description terms for the finality provider
    #[prost(message, optional, tag="2")]
    pub description: ::core::option::Option<super::super::super::cosmos::staking::v1beta1::Description>,
    /// commission defines the commission rate of the finality provider
    #[prost(string, tag="3")]
    pub commission: ::prost::alloc::string::String,
    /// babylon_pk is the Babylon secp256k1 PK of this finality provider
    #[prost(message, optional, tag="4")]
    pub babylon_pk: ::core::option::Option<super::super::super::cosmos::crypto::secp256k1::PubKey>,
    /// btc_pk is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="vec", tag="5")]
    pub btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="6")]
    pub pop: ::core::option::Option<ProofOfPossession>,
}
/// MsgCreateFinalityProviderResponse is the response for MsgCreateFinalityProvider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateFinalityProviderResponse {
}
/// MsgEditFinalityProvider is the message for editing an existing finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgEditFinalityProvider {
    /// NOTE: this signer needs to correspond to babylon_pk of the finality provider
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// btc_pk is the Bitcoin secp256k1 PK of the finality provider to be edited
    #[prost(bytes="vec", tag="2")]
    pub btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// description defines the updated description terms for the finality provider
    #[prost(message, optional, tag="3")]
    pub description: ::core::option::Option<super::super::super::cosmos::staking::v1beta1::Description>,
    /// commission defines the updated commission rate of the finality provider
    #[prost(string, tag="4")]
    pub commission: ::prost::alloc::string::String,
}
/// MsgEditFinalityProviderResponse is the response for MsgEditFinalityProvider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgEditFinalityProviderResponse {
}
/// MsgCreateBTCDelegation is the message for creating a BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateBtcDelegation {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// babylon_pk is the Babylon secp256k1 PK of this BTC delegation
    #[prost(message, optional, tag="2")]
    pub babylon_pk: ::core::option::Option<super::super::super::cosmos::crypto::secp256k1::PubKey>,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="3")]
    pub pop: ::core::option::Option<ProofOfPossession>,
    /// btc_pk is the Bitcoin secp256k1 PK of the BTC delegator
    #[prost(bytes="vec", tag="4")]
    pub btc_pk: ::prost::alloc::vec::Vec<u8>,
    /// fp_btc_pk_list is the list of Bitcoin secp256k1 PKs of the finality providers, if there is more than one
    /// finality provider pk it means that delegation is re-staked
    #[prost(bytes="vec", repeated, tag="5")]
    pub fp_btc_pk_list: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// staking_time is the time lock used in staking transaction
    #[prost(uint32, tag="6")]
    pub staking_time: u32,
    /// staking_value  is the amount of satoshis locked in staking output
    #[prost(int64, tag="7")]
    pub staking_value: i64,
    /// staking_tx is the staking tx along with the merkle proof of inclusion in btc block
    #[prost(message, optional, tag="8")]
    pub staking_tx: ::core::option::Option<super::super::btccheckpoint::v1::TransactionInfo>,
    /// slashing_tx is the slashing tx
    /// Note that the tx itself does not contain signatures, which are off-chain.
    #[prost(bytes="vec", tag="9")]
    pub slashing_tx: ::prost::alloc::vec::Vec<u8>,
    /// delegator_slashing_sig is the signature on the slashing tx by the delegator (i.e., SK corresponding to btc_pk).
    /// It will be a part of the witness for the staking tx output.
    /// The staking tx output further needs signatures from covenant and finality provider in
    /// order to be spendable.
    #[prost(bytes="vec", tag="10")]
    pub delegator_slashing_sig: ::prost::alloc::vec::Vec<u8>,
    /// unbonding_time is the time lock used when funds are being unbonded. It is be used in:
    /// - unbonding transaction, time lock spending path
    /// - staking slashing transaction, change output
    /// - unbonding slashing transaction, change output
    /// It must be smaller than math.MaxUInt16 and larger that max(MinUnbondingTime, CheckpointFinalizationTimeout)
    #[prost(uint32, tag="11")]
    pub unbonding_time: u32,
    /// fields related to unbonding transaction
    /// unbonding_tx is a bitcoin unbonding transaction i.e transaction that spends
    /// staking output and sends it to the unbonding output
    #[prost(bytes="vec", tag="12")]
    pub unbonding_tx: ::prost::alloc::vec::Vec<u8>,
    /// unbonding_value is amount of satoshis locked in unbonding output.
    /// NOTE: staking_value and unbonding_value could be different because of the difference between the fee for staking tx and that for unbonding
    #[prost(int64, tag="13")]
    pub unbonding_value: i64,
    /// unbonding_slashing_tx is the slashing tx which slash unbonding contract
    /// Note that the tx itself does not contain signatures, which are off-chain.
    #[prost(bytes="vec", tag="14")]
    pub unbonding_slashing_tx: ::prost::alloc::vec::Vec<u8>,
    /// delegator_unbonding_slashing_sig is the signature on the slashing tx by the delegator (i.e., SK corresponding to btc_pk).
    #[prost(bytes="vec", tag="15")]
    pub delegator_unbonding_slashing_sig: ::prost::alloc::vec::Vec<u8>,
}
/// MsgCreateBTCDelegationResponse is the response for MsgCreateBTCDelegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateBtcDelegationResponse {
}
/// MsgAddCovenantSigs is the message for handling signatures from a covenant member
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgAddCovenantSigs {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// pk is the BTC public key of the covenant member
    #[prost(bytes="vec", tag="2")]
    pub pk: ::prost::alloc::vec::Vec<u8>,
    /// staking_tx_hash is the hash of the staking tx.
    /// It uniquely identifies a BTC delegation
    #[prost(string, tag="3")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// sigs is a list of adaptor signatures of the covenant
    /// the order of sigs should respect the order of finality providers
    /// of the corresponding delegation
    #[prost(bytes="vec", repeated, tag="4")]
    pub slashing_tx_sigs: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// unbonding_tx_sig is the signature of the covenant on the unbonding tx submitted to babylon
    /// the signature follows encoding in BIP-340 spec
    #[prost(bytes="vec", tag="5")]
    pub unbonding_tx_sig: ::prost::alloc::vec::Vec<u8>,
    /// slashing_unbonding_tx_sigs is a list of adaptor signatures of the covenant
    /// on slashing tx corresponding to unbonding tx submitted to babylon
    /// the order of sigs should respect the order of finality providers
    /// of the corresponding delegation
    #[prost(bytes="vec", repeated, tag="6")]
    pub slashing_unbonding_tx_sigs: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// MsgAddCovenantSigsResponse is the response for MsgAddCovenantSigs
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgAddCovenantSigsResponse {
}
/// MsgBTCUndelegate is the message for handling signature on unbonding tx
/// from its delegator. This signature effectively proves that the delegator
/// wants to unbond this BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgBtcUndelegate {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// staking_tx_hash is the hash of the staking tx.
    /// It uniquely identifies a BTC delegation
    #[prost(string, tag="2")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// unbonding_tx_sig is the signature of the staker on the unbonding tx submitted to babylon
    /// the signature follows encoding in BIP-340 spec
    #[prost(bytes="vec", tag="3")]
    pub unbonding_tx_sig: ::prost::alloc::vec::Vec<u8>,
}
/// MsgBTCUndelegateResponse is the response for MsgBTCUndelegate
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgBtcUndelegateResponse {
}
/// MsgSelectiveSlashingEvidence is the message for handling evidence of selective slashing
/// launched by a finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSelectiveSlashingEvidence {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// staking_tx_hash is the hash of the staking tx.
    /// It uniquely identifies a BTC delegation
    #[prost(string, tag="2")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// recovered_fp_btc_sk is the BTC SK of the finality provider who
    /// launches the selective slashing offence. The SK is recovered by
    /// using a covenant adaptor signature and the corresponding Schnorr
    /// signature
    #[prost(bytes="vec", tag="3")]
    pub recovered_fp_btc_sk: ::prost::alloc::vec::Vec<u8>,
}
/// MsgSelectiveSlashingEvidenceResponse is the response for MsgSelectiveSlashingEvidence
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSelectiveSlashingEvidenceResponse {
}
/// MsgUpdateParams defines a message for updating btcstaking module parameters.
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
