//! The top-level application state and logic of the Nomic protocol. The main
//! state type is the [InnerApp] struct.

#![allow(clippy::too_many_arguments)]
// TODO: remove after switching from "testnet" feature flag to orga channels
#![allow(unused_variables)]
#![allow(unused_imports)]

use crate::airdrop::Airdrop;
#[cfg(feature = "babylon")]
use crate::babylon::{self, Babylon, Params};
use crate::bitcoin::adapter::Adapter;
use crate::bitcoin::threshold_sig::Signature;
use crate::bitcoin::{exempt_from_fee, Bitcoin, Nbtc};
use crate::bitcoin::{matches_bitcoin_network, NETWORK};
use crate::cosmos::{Chain, Cosmos, Proof};
#[cfg(feature = "ethereum")]
use crate::ethereum::Ethereum;
#[cfg(feature = "frost")]
use crate::frost::{Config as FrostConfig, Frost, FrostGroup};

#[cfg(feature = "ethereum")]
use crate::ethereum::Connection;
use crate::incentives::Incentives;
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{PublicKey, Script, Transaction, TxOut};
use orga::coins::{
    Accounts, Address, Amount, Coin, Faucet, FaucetOptions, Give, Staking, Symbol, Take,
};
use orga::context::{Context, GetContext};
use orga::cosmrs::bank::MsgSend;
use orga::describe::{Describe, Descriptor};
use orga::encoding::{Decode, Encode, LengthString, LengthVec};
use orga::ibc::ibc_rs::apps::transfer::types::Memo;
use orga::ibc::ClientIdKey as ClientId;

use std::io::Read;
use std::str::FromStr;
use std::time::Duration;

use orga::ibc::ibc_rs::apps::transfer::context::TokenTransferExecutionContext;
use orga::ibc::ibc_rs::apps::transfer::types::msgs::transfer::MsgTransfer;
use orga::ibc::ibc_rs::apps::transfer::types::packet::PacketData;
use orga::ibc::ibc_rs::core::channel::types::timeout::{TimeoutHeight, TimeoutTimestamp};
use orga::ibc::ibc_rs::core::host::types::identifiers::{ChannelId, PortId};
use orga::ibc::ibc_rs::core::primitives::Timestamp;
use orga::ibc::{Ibc, IbcTx};

use orga::ibc::ibc_rs::core::primitives::Signer as IbcSigner;

use orga::coins::Declaration;
use orga::encoding::Adapter as EdAdapter;
use orga::macros::build_call;
use orga::migrate::Migrate;
use orga::orga;
use orga::plugins::sdk_compat::{sdk, sdk::Tx as SdkTx, ConvertSdkTx};
use orga::plugins::{disable_fee, DefaultPlugins, Events, Paid, PaidCall, Signer, Time, MIN_FEE};
use orga::prelude::*;
use orga::upgrade::Version;
use orga::upgrade::{Upgrade, UpgradeV0};
use orga::Error;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, Strict, StrictPfx};
use std::convert::TryInto;
use std::fmt::Debug;

mod migrations;

/// The top-level application state type, wrapped with the Orga default plugins.
pub type App = DefaultPlugins<Nom, InnerApp>;

/// The symbol for the NOM token.
#[derive(State, Debug, Clone, Encode, Decode, Default, Migrate, Serialize)]
pub struct Nom(());
impl Symbol for Nom {
    const INDEX: u8 = 69;
    const NAME: &'static str = "unom";
}

/// The recipient address for the NOM developer rewards faucet on Nomic
/// Stakenet.
#[cfg(feature = "full")]
const DEV_ADDRESS: &str = "nomic14z79y3yrghqx493mwgcj0qd2udy6lm26lmduah";
/// The recipient address for the NOM strategic reserve tokens on Nomic
/// Stakenet.
#[cfg(feature = "full")]
const STRATEGIC_RESERVE_ADDRESS: &str = "nomic1d5n325zrf4elfu0heqd59gna5j6xyunhev23cj";
/// An address to receive a small portion of the strategic reserve tokens in
/// order to send a small portion of tokens to validators for declaration fees
/// on Nomic Stakenet.
#[cfg(feature = "full")]
const VALIDATOR_BOOTSTRAP_ADDRESS: &str = "nomic1fd9mxxt84lw3jdcsmjh6jy8m6luafhqd8dcqeq";

/// The fixed amount of nBTC fee required to relay IBC messages, in
/// micro-satoshis.
const IBC_FEE_USATS: u64 = 1_000_000;
/// The fixed amount of nBTC fee required to make any application call, in
/// micro-satoshis.
const CALL_FEE_USATS: u64 = 100_000_000;
/// The fixed amount of nBTC fee required to create a new Ethereum connection,
/// in micro-satoshis.
const ETH_CREATE_CONNECTION_FEE_USATS: u64 = 10_000_000_000;

const OSMOSIS_CHANNEL_ID: &str = "channel-1";

#[cfg(feature = "frost")]
const FROST_GROUP_INTERVAL: i64 = 10 * 60;
#[cfg(feature = "frost")]
const FROST_TOP_N: u16 = 5;
#[cfg(feature = "frost")]
const FROST_THRESHOLD: u16 = 3;

/// The top-level application state type and logic. This contains the major
/// state types for the various subsystems of the Nomic protocol.
#[orga(version = 5..=7)]
pub struct InnerApp {
    /// Account state for the NOM token.
    #[call]
    pub accounts: Accounts<Nom>,
    /// Staking and validator state, including the validator set and staking
    /// rewards. This ultimately sets the voting power of Tendermint consensus
    /// based on the amount staked to each validator.
    #[call]
    pub staking: Staking<Nom>,
    /// Airdrop state, which can be claimed by eligible accounts.
    #[call]
    pub airdrop: Airdrop,

    /// A balance of NOM tokens that are reserved for the protocol community
    /// pool.
    pub community_pool: Coin<Nom>,
    /// A balance of NOM tokens that are reserved for the protocol incentive
    /// pool.
    incentive_pool: Coin<Nom>,

    /// A stream of tokens that pays out over time to NOM stakers, based on a
    /// defined inflation schedule.
    staking_rewards: Faucet<Nom>,
    /// A stream of tokens that pays out over time to the NOM developer wallet,
    /// based on a defined inflation schedule.
    dev_rewards: Faucet<Nom>,
    /// A stream of tokens that pays out over time to the NOM community pool,
    /// based on a defined inflation schedule.
    community_pool_rewards: Faucet<Nom>,
    /// A stream of tokens that pays out over time to the NOM incentive pool,
    /// based on a defined inflation schedule.
    incentive_pool_rewards: Faucet<Nom>,

    /// The Bitcoin state, including a chain of verified Bitcoin headers and
    /// logic for processing Bitcoin transactions.
    #[call]
    pub bitcoin: Bitcoin,
    /// A timer to support paying out accumulated Bitcoin rewards periodically.
    pub reward_timer: RewardTimer,

    /// The IBC state, including the IBC client, connection, and channel
    /// states. This is used to relay messages between Nomic and other IBC
    /// enabled blockchains.
    #[call]
    pub ibc: Ibc,

    /// The upgrade state, including the current version of the application and
    /// logic for upgrading to a new version of the protocol once sufficient
    /// network voting power has signaled readiness.
    pub upgrade: Upgrade,

    /// Incentive state, allowing eligible users to claim tokens based on
    /// participation in the Nomic ecosystem.
    #[call]
    pub incentives: Incentives,

    /// The Cosmos state, allowing for relaying data about remote Cosmos chains
    /// which is not available in the IBC module.
    pub cosmos: Cosmos,

    #[cfg(all(feature = "ethereum", feature = "testnet"))]
    #[orga(version(V5, V6))]
    #[call]
    pub ethereum: Connection,
    #[cfg(all(feature = "ethereum", feature = "testnet"))]
    #[orga(version(V7))]
    #[call]
    pub ethereum: Ethereum,

    #[cfg(all(feature = "babylon", feature = "testnet"))]
    #[orga(version(V7))]
    #[call]
    pub babylon: Babylon,

    #[cfg(all(feature = "frost", feature = "testnet"))]
    #[orga(version(V7))]
    #[call]
    pub frost: Frost,
}

#[orga]
impl InnerApp {
    /// The current version of the Nomic protocol. This is incremented when
    /// breaking changes are made to either the state encoding or logic of the
    /// protocol, and requires a network upgrade to be coordinated via the
    /// upgrade module.
    pub const CONSENSUS_VERSION: u8 = 13;

    #[cfg(feature = "full")]
    fn configure_faucets(&mut self) -> Result<()> {
        let day = 60 * 60 * 24;
        let year = Duration::from_secs(60 * 60 * 24 * 365);
        let two_thirds = (Amount::new(2) / Amount::new(3))?;

        let genesis_time = self
            .context::<Time>()
            .ok_or_else(|| Error::App("No Time context available".into()))?
            .seconds;

        self.staking_rewards.configure(FaucetOptions {
            num_periods: 9,
            period_length: year,
            total_coins: 49_875_000_000_000.into(),
            period_decay: two_thirds,
            start_seconds: genesis_time + day,
        })?;

        self.dev_rewards.configure(FaucetOptions {
            num_periods: 9,
            period_length: year,
            total_coins: 49_875_000_000_000.into(),
            period_decay: two_thirds,
            start_seconds: genesis_time + day,
        })?;

        self.community_pool_rewards.configure(FaucetOptions {
            num_periods: 9,
            period_length: year,
            total_coins: 9_975_000_000_000.into(),
            period_decay: two_thirds,
            start_seconds: genesis_time + day,
        })?;

        self.incentive_pool_rewards.configure(FaucetOptions {
            num_periods: 9,
            period_length: year,
            total_coins: 89_775_000_000_000.into(),
            period_decay: two_thirds,
            start_seconds: genesis_time + day,
        })?;

        Ok(())
    }

    #[call]
    pub fn deposit_rewards(&mut self) -> Result<()> {
        self.accounts.give_from_funding_all()?;
        self.bitcoin.accounts.give_from_funding_all()?;
        Ok(())
    }

    #[call]
    pub fn ibc_transfer_nbtc(&mut self, dest: IbcDest, amount: Amount) -> Result<()> {
        crate::bitcoin::exempt_from_fee()?;

        dest.validate()?;

        let signer = self.signer()?;
        let mut coins = self.bitcoin.accounts.withdraw(signer, amount)?;

        let fee = if dest.is_fee_exempt() {
            IBC_FEE_USATS.into()
        } else {
            ibc_fee(amount)?
        };
        let fee = coins.take(fee)?;
        self.bitcoin.give_rewards(fee)?;

        let dest = Dest::Ibc { data: dest };
        let sender = Identity::from_signer()?;
        self.bitcoin.insert_pending(dest, coins, sender)?;

        Ok(())
    }

    #[call]
    pub fn ibc_withdraw_nbtc(&mut self, amount: Amount) -> Result<()> {
        crate::bitcoin::exempt_from_fee()?;

        let signer = self.signer()?;
        let coins: Coin<Nbtc> = amount.into();
        self.ibc
            .transfer_mut()
            .burn_coins_execute(&signer, &coins.into(), &"".parse().unwrap())?;
        self.bitcoin.accounts.deposit(signer, amount.into())?;

        Ok(())
    }

    #[call]
    pub fn eth_transfer_nbtc(
        &mut self,
        network: u32,
        connection: Address,
        address: Address,
        amount: Amount,
    ) -> Result<()> {
        #[cfg(feature = "ethereum")]
        {
            crate::bitcoin::exempt_from_fee()?;

            // TODO: fee

            let signer = self.signer()?;
            let coins = self.bitcoin.accounts.withdraw(signer, amount)?;

            let dest = Dest::EthAccount {
                network,
                connection: connection.into(),
                address: address.into(),
            };
            let sender = Identity::from_signer()?;
            self.bitcoin.insert_pending(dest, coins, sender)?;

            Ok(())
        }

        #[cfg(not(feature = "ethereum"))]
        {
            Err(Error::App("Ethereum feature not enabled".into()))
        }
    }

    #[query]
    pub fn total_supply(&self) -> Result<Amount> {
        let initial_supply: u64 = 17_500_000_000_000;

        let staking_rewards_minted: u64 = self.staking_rewards.amount_minted.into();
        let dev_rewards_minted: u64 = self.dev_rewards.amount_minted.into();
        let community_pool_rewards_minted: u64 = self.community_pool_rewards.amount_minted.into();
        let incentive_pool_rewards_minted: u64 = self.incentive_pool_rewards.amount_minted.into();

        Ok(Amount::new(
            initial_supply
                + staking_rewards_minted
                + dev_rewards_minted
                + community_pool_rewards_minted
                + incentive_pool_rewards_minted,
        ))
    }

    #[query]
    pub fn escrowed_nbtc(&self, address: Address) -> Result<Amount> {
        self.ibc.transfer().symbol_balance::<Nbtc>(address)
    }

    #[call]
    pub fn claim_escrowed_nbtc(&mut self) -> Result<()> {
        let signer = self.signer()?;
        let balance = self.escrowed_nbtc(signer)?;
        self.ibc_withdraw_nbtc(balance)
    }

    #[call]
    pub fn relay_deposit(
        &mut self,
        btc_tx: Adapter<Transaction>,
        btc_height: u32,
        btc_proof: Adapter<PartialMerkleTree>,
        btc_vout: u32,
        sigset_index: u32,
        dest: Dest,
    ) -> Result<()> {
        let amount_after_fee =
            self.bitcoin
                .amount_after_deposit_fee(&btc_tx, btc_vout, sigset_index, &dest)?;
        self.validate_dest(&dest, amount_after_fee.into(), Identity::None)?;

        Ok(self.bitcoin.relay_deposit(
            btc_tx,
            btc_height,
            btc_proof,
            btc_vout,
            sigset_index,
            dest,
        )?)
    }

    #[call]
    pub fn relay_op_key(
        &mut self,
        client_id: ClientId,
        height: (u64, u64),
        cons_key: LengthVec<u8, u8>,
        op_addr: Proof,
        acc: Proof,
    ) -> Result<()> {
        self.deduct_nbtc_fee(IBC_FEE_USATS.into())?;

        Ok(self
            .cosmos
            .relay_op_key(&self.ibc, client_id, height, cons_key, op_addr, acc)?)
    }

    pub fn validate_dest(&self, dest: &Dest, amount: Amount, sender: Identity) -> Result<()> {
        match dest {
            Dest::NativeAccount { address } => {}
            Dest::Ibc { data } => data.validate()?,
            Dest::RewardPool => {}
            #[cfg(feature = "ethereum")]
            Dest::EthAccount {
                network,
                connection,
                address,
            } => {
                self.ethereum
                    .network(*network)?
                    .connection((*connection).into())?
                    .validate_transfer((*address).into(), amount.into())?;
            }
            #[cfg(feature = "ethereum")]
            Dest::EthCall {
                network,
                connection,
                fallback_address,
                max_gas,
                ..
            } => {
                self.ethereum
                    .network(*network)?
                    .connection((*connection).into())?
                    .validate_contract_call(*max_gas, (*fallback_address).into(), amount.into())?;
            }
            Dest::Bitcoin { data } => self.bitcoin.validate_withdrawal(data, amount)?,
            #[cfg(feature = "babylon")]
            Dest::Stake {
                return_dest,
                finality_provider,
                staking_period,
            } => {
                // TODO: move into babylon
                let params = &self.babylon.params;
                let amount: u64 = amount.into();
                if amount < params.min_staking_amount || amount > params.max_staking_amount {
                    return Err(Error::App("Invalid stake amount".to_string()));
                }

                if *staking_period < params.min_staking_time
                    || *staking_period > params.max_staking_time
                {
                    return Err(Error::App("Invalid staking period".to_string()));
                }

                let _: Dest = return_dest.parse()?;

                if self.frost.most_recent_with_key()?.is_none() {
                    return Err(Error::App("No Frost DKG groups".to_string()));
                }
            }
            #[cfg(feature = "babylon")]
            Dest::Unstake { index } => {
                // TODO: move into babylon
                let owner_dels = self
                    .babylon
                    .delegations
                    .get(sender)?
                    .ok_or_else(|| Error::App("No delegations found for owner".to_string()))?;
                let del = owner_dels
                    .get(*index)?
                    .ok_or_else(|| Error::App("Delegation not found".to_string()))?;
                if del.status() == babylon::DelegationStatus::Withdrawn {
                    return Err(Error::App("Delegation already withdrawn".to_string()));
                }
            }
            Dest::AdjustEmergencyDisbursalBalance { data, difference } => {
                // TODO
            }
        }

        Ok(())
    }

    fn try_credit_dest(
        &mut self,
        dest: Dest,
        mut coins: Coin<Nbtc>,
        sender: Identity,
    ) -> Result<()> {
        let mut succeeded = false;
        let amount = coins.amount;
        if self.validate_dest(&dest, amount, sender).is_ok() {
            if let Err(e) = self.credit_dest(dest.clone(), coins.take(amount)?, sender) {
                log::debug!("Error crediting transfer: {:?}", e);
                // TODO: ensure no errors can happen after mutating
                // state in credit_dest since state won't be reverted

                // Assume coins passed into credit_dest are burnt,
                // replace them in `coins`
                coins.give(Coin::mint(amount))?;
            } else {
                succeeded = true;
            }
        }

        // Handle failures
        if !succeeded {
            log::debug!(
                "Failed to credit transfer to {} (amount: {}, sender: {})",
                dest,
                amount,
                sender,
            );

            match sender {
                Identity::NativeAccount { address } => {
                    self.bitcoin.accounts.deposit(address, coins)?;
                }
                #[cfg(feature = "ethereum")]
                Identity::EthAccount {
                    network,
                    connection,
                    address,
                } => {
                    self.ethereum
                        .network_mut(network)?
                        .connection_mut(connection.into())?
                        .transfer(address.into(), coins)?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn credit_dest(&mut self, dest: Dest, nbtc: Coin<Nbtc>, sender: Identity) -> Result<()> {
        log::debug!(
            "Crediting dest: {} (amount: {}, sender: {})",
            &dest,
            nbtc.amount,
            &sender
        );
        match dest {
            Dest::NativeAccount { address } => self.bitcoin.accounts.deposit(address, nbtc)?,
            Dest::Ibc { data: dest } => dest.transfer(nbtc, &mut self.bitcoin, &mut self.ibc)?,
            Dest::RewardPool => self.bitcoin.give_rewards(nbtc)?,
            #[cfg(feature = "ethereum")]
            Dest::EthAccount {
                network,
                connection,
                address,
            } => self
                .ethereum
                .network_mut(network)?
                .connection_mut(connection.into())?
                .transfer(address.into(), nbtc)?,
            #[cfg(feature = "ethereum")]
            Dest::EthCall {
                network,
                connection,
                contract_address,
                data,
                max_gas,
                fallback_address,
            } => self
                .ethereum
                .network_mut(network)?
                .connection_mut(connection.into())?
                .call_contract(contract_address, data, max_gas, fallback_address, nbtc)?,
            Dest::Bitcoin { data } => self.bitcoin.add_withdrawal(data, nbtc)?,
            #[cfg(feature = "babylon")]
            Dest::Stake {
                return_dest,
                finality_provider,
                staking_period,
            } => {
                let return_dest = return_dest.parse()?;
                self.babylon.stake(
                    &mut self.bitcoin,
                    &mut self.frost,
                    sender,
                    return_dest,
                    finality_provider,
                    staking_period,
                    nbtc,
                )?;
            }
            #[cfg(feature = "babylon")]
            Dest::Unstake { index } => {
                self.babylon
                    .unstake(sender, index, &mut self.frost, &self.bitcoin)?;
                nbtc.burn();
            }
            Dest::AdjustEmergencyDisbursalBalance { data, difference } => {
                #[cfg(feature = "ethereum")]
                if let Identity::EthAccount {
                    network,
                    connection,
                    ..
                } = sender
                {
                    self.ethereum
                        .network_mut(network)?
                        .connection_mut(connection.into())?
                        .adjust_emergency_disbursal_balance(data, difference)?;
                }
                nbtc.burn();
            }
        };

        Ok(())
    }

    #[call]
    pub fn withdraw_nbtc(
        &mut self,
        script_pubkey: Adapter<bitcoin::Script>,
        amount: Amount,
    ) -> Result<()> {
        Ok(self.bitcoin.withdraw(script_pubkey, amount)?)
    }

    #[call]
    fn join_accounts(&mut self, dest_addr: Address) -> Result<()> {
        disable_fee();

        self.airdrop.join_accounts(dest_addr)?;
        self.incentives.join_accounts(dest_addr)?;

        Ok(())
    }

    fn signer(&mut self) -> Result<Address> {
        self.context::<Signer>()
            .ok_or_else(|| Error::Signer("No Signer context available".into()))?
            .signer
            .ok_or_else(|| Error::Coins("Unauthorized account action".into()))
    }

    #[call]
    pub fn signal(&mut self, version: Version) -> Result<()> {
        self.upgrade.signal(version)
    }

    #[call]
    pub fn ibc_deliver(&mut self, messages: RawIbcTx) -> Result<()> {
        self.deduct_nbtc_fee(IBC_FEE_USATS.into())?;
        let incoming_transfers = self.ibc.deliver(messages)?;

        for transfer in incoming_transfers {
            if transfer.denom.to_string() != "usat" || transfer.memo.is_empty() {
                continue;
            }

            let receiver: Address = transfer
                .receiver
                .parse()
                .map_err(|_| Error::Coins("Invalid address".to_string()))?;
            let amount = transfer.amount;

            let Ok(dest) = transfer.memo.parse::<Dest>() else {
                continue;
            };

            let coins = Coin::<Nbtc>::mint(amount);
            self.ibc.transfer_mut().burn_coins_execute(
                &receiver,
                &coins.into(),
                &"".parse().unwrap(),
            )?;

            let coins = Coin::<Nbtc>::mint(amount);
            let sender = Identity::None; // TODO
            self.bitcoin.insert_pending(dest, coins, sender)?;
        }

        Ok(())
    }

    #[call]
    pub fn declare_with_nbtc(&mut self, declaration: Declaration) -> Result<()> {
        self.deduct_nbtc_fee(CALL_FEE_USATS.into())?;
        let signer = self.signer()?;
        self.staking.declare(signer, declaration, 0.into())
    }

    #[call]
    pub fn pay_nbtc_fee(&mut self) -> Result<()> {
        self.deduct_nbtc_fee(CALL_FEE_USATS.into())
    }

    fn deduct_nbtc_fee(&mut self, amount: Amount) -> Result<()> {
        disable_fee();
        let signer = self.signer()?;
        let fee = self.bitcoin.accounts.withdraw(signer, amount)?;
        self.bitcoin.give_rewards(fee)?;
        Ok(())
    }

    // TODO: temporary workaround, will be exposed by client soon
    pub fn height(&self) -> u64 {
        self.ibc.ctx.query_height().unwrap()
    }

    #[call]
    pub fn stake_nbtc(
        &mut self,
        amount: Amount,
        finality_provider: [u8; 32],
        staking_period: u16,
    ) -> Result<()> {
        #[cfg(feature = "babylon")]
        {
            // TODO: validate staking/unbonding periods
            // TODO: go through dest flow
            let signer = self.signer()?;
            let stake = self.bitcoin.accounts.withdraw(signer, amount)?;
            self.babylon.stake(
                &mut self.bitcoin,
                &mut self.frost,
                Identity::from_signer()?,
                Dest::NativeAccount { address: signer },
                finality_provider,
                staking_period,
                stake,
            )?;

            Ok(())
        }

        #[cfg(not(feature = "babylon"))]
        {
            Err(Error::App("Babylon feature not enabled".into()))
        }
    }

    // TODO: move into babylon module, get HeaderQueue via context
    #[call]
    pub fn relay_btc_staking_tx(
        &mut self,
        del_owner: Identity,
        del_index: u64,
        height: u32,
        proof: Adapter<PartialMerkleTree>,
        tx: Adapter<Transaction>,
        vout: u32,
    ) -> Result<()> {
        #[cfg(feature = "babylon")]
        {
            exempt_from_fee()?;

            self.babylon
                .delegations
                .get_mut(del_owner)?
                .ok_or_else(|| Error::App("No delegations found with given owner".into()))?
                .get_mut(del_index)?
                .ok_or_else(|| Error::App("Delegation not found".into()))?
                .relay_staking_tx(
                    &self.bitcoin.headers,
                    height,
                    proof.into_inner(),
                    tx.into_inner(),
                    vout,
                    &self.babylon.params,
                    &mut self.babylon.staked,
                    &mut self.frost,
                    &self.bitcoin,
                )?;

            Ok(())
        }

        #[cfg(not(feature = "babylon"))]
        {
            Err(Error::App("Babylon feature not enabled".into()))
        }
    }

    // TODO: move into babylon module, get HeaderQueue via context
    #[call]
    pub fn relay_btc_unbonding_tx(
        &mut self,
        del_owner: Identity,
        del_index: u64,
        height: u32,
        proof: Adapter<PartialMerkleTree>,
        tx: Adapter<Transaction>,
    ) -> Result<()> {
        #[cfg(feature = "babylon")]
        {
            exempt_from_fee()?;

            self.babylon
                .delegations
                .get_mut(del_owner)?
                .ok_or_else(|| Error::App("No delegations found with given owner".into()))?
                .get_mut(del_index)?
                .ok_or_else(|| Error::App("Delegation not found".into()))?
                .relay_unbonding_tx(
                    &self.bitcoin.headers,
                    height,
                    proof.into_inner(),
                    tx.into_inner(),
                    &self.babylon.params,
                    &mut self.babylon.unbonding,
                    &mut self.babylon.staked,
                )?;

            Ok(())
        }

        #[cfg(not(feature = "babylon"))]
        {
            Err(Error::App("Babylon feature not enabled".into()))
        }
    }

    #[call]
    pub fn eth_create_connection(
        &mut self,
        chain_id: u32,
        bridge_contract: Address,
        token_contract: Address,
    ) -> Result<()> {
        #[cfg(feature = "ethereum")]
        {
            self.deduct_nbtc_fee(ETH_CREATE_CONNECTION_FEE_USATS.into())?;
            // TODO: confirm that this is the right valset to use
            let valset = self.bitcoin.checkpoints.active_sigset()?;

            Ok(self.ethereum.create_connection(
                chain_id,
                bridge_contract,
                token_contract,
                valset,
            )?)
        }

        #[cfg(not(feature = "ethereum"))]
        {
            Err(Error::App("Ethereum feature not enabled".into()))
        }
    }

    #[call]
    pub fn app_noop(&mut self) -> Result<()> {
        Ok(())
    }

    #[query]
    pub fn app_noop_query(&self) -> Result<()> {
        Ok(())
    }

    #[cfg(all(feature = "frost", feature = "testnet"))]
    fn step_frost(&mut self, now: i64) -> Result<()> {
        let last_frost_group = self.frost.groups.back()?;
        let last_frost_group_time = last_frost_group.as_ref().map(|g| g.created_at).unwrap_or(0);
        let absent = last_frost_group
            .map(|v| v.absent().unwrap_or_default())
            .unwrap_or_default();

        if now > last_frost_group_time + FROST_GROUP_INTERVAL {
            let frost_config =
                FrostConfig::from_staking(&self.staking, FROST_TOP_N, FROST_THRESHOLD, &absent)?;

            if frost_config.participants.len() < 2 {
                return Ok(());
            }
            let group = FrostGroup::with_config(frost_config, now)?;

            self.frost.groups.push_back(group)?;
        }

        self.frost.advance_with_timeout(60 * 5)?;
        Ok(())
    }
}

#[cfg(feature = "full")]
mod abci {
    use orga::{
        abci::{messages, AbciQuery, BeginBlock, EndBlock, InitChain},
        coins::{Give, Take},
        collections::Map,
        plugins::{BeginBlockCtx, EndBlockCtx, InitChainCtx, Validators},
    };

    #[cfg(feature = "ethereum")]
    use crate::ethereum::bytes32;
    #[cfg(feature = "frost")]
    use crate::frost::FrostGroup;

    use super::*;

    impl InitChain for InnerApp {
        fn init_chain(&mut self, _ctx: &InitChainCtx) -> Result<()> {
            self.staking.max_validators = 30;
            self.staking.max_offline_blocks = 20_000;
            self.staking.downtime_jail_seconds = 60 * 30; // 30 minutes
            self.staking.slash_fraction_downtime = (Amount::new(1) / Amount::new(1000))?;
            self.staking.slash_fraction_double_sign = (Amount::new(1) / Amount::new(20))?;
            self.staking.min_self_delegation_min = 0;

            let sr_address = STRATEGIC_RESERVE_ADDRESS.parse().unwrap();

            self.accounts.allow_transfers(true);
            self.bitcoin.accounts.allow_transfers(true);

            self.accounts.add_transfer_exception(sr_address)?;

            let vb_address = VALIDATOR_BOOTSTRAP_ADDRESS.parse().unwrap();
            self.accounts.add_transfer_exception(vb_address)?;

            self.configure_faucets()?;

            self.upgrade
                .current_version
                .insert((), vec![Self::CONSENSUS_VERSION].try_into().unwrap())?;

            #[cfg(feature = "testnet")]
            {
                self.upgrade.activation_delay_seconds = 20 * 60;
                self.bitcoin.config.min_confirmations = 0;
                self.bitcoin.config.min_withdrawal_checkpoints = 0;
                self.bitcoin.checkpoints.config.min_checkpoint_interval = 60;

                include_str!("../testnet_addresses.csv")
                    .lines()
                    .try_for_each(|line| {
                        let address = line.parse().unwrap();
                        self.accounts.deposit(address, Coin::mint(10_000_000_000))
                    })?;
            }

            Ok(())
        }
    }

    impl BeginBlock for InnerApp {
        fn begin_block(&mut self, ctx: &BeginBlockCtx) -> Result<()> {
            let now = ctx.header.time.as_ref().unwrap().seconds;
            self.upgrade.step(
                &vec![Self::CONSENSUS_VERSION].try_into().unwrap(),
                in_upgrade_window(now),
            )?;
            self.staking.begin_block(ctx)?;

            self.ibc.begin_block(ctx)?;

            let has_stake = self.staking.staked()? > 0;
            if has_stake {
                let reward = self.staking_rewards.mint()?;
                self.staking.give(reward)?;
            }

            let dev_reward = self.dev_rewards.mint()?;
            let dev_address = DEV_ADDRESS.parse().unwrap();
            self.accounts.deposit(dev_address, dev_reward)?;

            let cp_reward = self.community_pool_rewards.mint()?;
            self.community_pool.give(cp_reward)?;

            let ip_reward = self.incentive_pool_rewards.mint()?;
            self.incentive_pool.give(ip_reward)?;

            #[cfg(all(feature = "frost", feature = "testnet"))]
            if !self.bitcoin.checkpoints.is_empty()? {
                self.step_frost(now)?;
            }

            #[cfg(feature = "ethereum")]
            {
                if !self.bitcoin.checkpoints.is_empty()? {
                    self.ethereum
                        .step(&self.bitcoin.checkpoints.active_sigset()?)?;
                }

                let pending = &mut self.bitcoin.checkpoints.building_mut()?.pending;
                for (dest, coins, sender) in self.ethereum.take_pending()? {
                    pending.insert((dest, sender), coins)?;
                }
            }

            let pending_nbtc_transfers = self.bitcoin.take_pending()?;
            for (dest, coins, sender) in pending_nbtc_transfers {
                self.try_credit_dest(dest, coins, sender)?;
            }

            let external_outputs = if self.bitcoin.should_push_checkpoint()? {
                self.cosmos
                    .build_outputs(&self.ibc, self.bitcoin.checkpoints.index)?
            } else {
                vec![]
            };
            let offline_signers = self
                .bitcoin
                .begin_block_step(external_outputs.into_iter().map(Ok), ctx.hash.clone())?;
            for cons_key in offline_signers {
                let address = self.staking.address_by_consensus_key(cons_key)?.unwrap();
                self.staking.punish_downtime(address)?;
            }

            let has_nbtc_rewards = self.bitcoin.reward_pool.amount > 0;
            if self.reward_timer.tick(now) && has_stake && has_nbtc_rewards {
                let reward_rate = (Amount::new(1) / Amount::new(2377))?; // ~0.00042069
                let reward_amount = (self.bitcoin.reward_pool.amount * reward_rate)?.amount()?;
                let reward = self.bitcoin.reward_pool.take(reward_amount)?;
                self.staking.give(reward)?;
            }

            #[cfg(feature = "babylon")]
            self.babylon.step(&mut self.frost, &mut self.bitcoin)?;

            Ok(())
        }
    }

    impl EndBlock for InnerApp {
        fn end_block(&mut self, ctx: &EndBlockCtx) -> Result<()> {
            self.staking.end_block(ctx)
        }
    }

    impl AbciQuery for InnerApp {
        fn abci_query(&self, request: &messages::RequestQuery) -> Result<messages::ResponseQuery> {
            self.ibc.abci_query(request)
        }
    }
}

impl ConvertSdkTx for InnerApp {
    type Output = PaidCall<<Self as Call>::Call>;

    fn convert(&self, sdk_tx: &SdkTx) -> Result<PaidCall<<Self as Call>::Call>> {
        let sender_address = sdk_tx.sender_address()?;
        match sdk_tx {
            SdkTx::Protobuf(tx) => {
                if IbcTx::try_from(tx.clone()).is_ok() {
                    let raw_ibc_tx = RawIbcTx(tx.clone());
                    let payer = build_call!(self.ibc_deliver(raw_ibc_tx));
                    let paid = build_call!(self.app_noop());

                    return Ok(PaidCall { payer, paid });
                }

                if tx.body.messages.len() != 1 {
                    return Err(Error::App(
                        "Only transactions with one message are supported".into(),
                    ));
                }

                let msg = &tx.body.messages[0];
                if msg.type_url.as_str() == "cosmos-sdk/MsgSend" {
                    use orga::cosmrs::tx::Msg;
                    let msg =
                        MsgSend::from_any(msg).map_err(|_| Error::App("Invalid MsgSend".into()))?;

                    let from_bytes: [u8; Address::LENGTH] = msg
                        .from_address
                        .to_bytes()
                        .try_into()
                        .map_err(|_| Error::App("Invalid sender address".into()))?;
                    let from: Address = from_bytes.into();

                    if from != sender_address {
                        return Err(Error::App(
                            "'from_address' must match sender address".to_string(),
                        ));
                    }

                    let to_bytes: [u8; Address::LENGTH] = msg
                        .to_address
                        .to_bytes()
                        .try_into()
                        .map_err(|_| Error::App("Invalid receiver address".into()))?;
                    let to: Address = to_bytes.into();

                    if msg.amount.len() != 1 {
                        return Err(Error::App(
                            "'amount' must have exactly one element".to_string(),
                        ));
                    }

                    match msg.amount[0].denom.to_string().as_str() {
                        "unom" => {
                            let amount: u64 = msg.amount[0]
                                .amount
                                .to_string()
                                .parse()
                                .map_err(|_| Error::App("Invalid amount".to_string()))?;

                            let payer = build_call!(self.accounts.take_as_funding(MIN_FEE.into()));
                            let paid = build_call!(self.accounts.transfer(to, amount.into()));

                            return Ok(PaidCall { payer, paid });
                        }
                        "usat" => {
                            let amount: u64 = msg.amount[0]
                                .amount
                                .to_string()
                                .parse()
                                .map_err(|_| Error::App("Invalid amount".to_string()))?;

                            let payer = build_call!(self.bitcoin.transfer(to, amount.into()));
                            let paid = build_call!(self.app_noop());

                            return Ok(PaidCall { payer, paid });
                        }
                        _ => return Err(Error::App("Unknown denom".to_string())),
                    }
                }

                Err(Error::App("Unsupported protobuf transaction".into()))
            }

            SdkTx::Amino(tx) => {
                if tx.msg.len() != 1 {
                    return Err(Error::App("Invalid number of messages".into()));
                }

                let msg = &tx.msg[0];

                let get_amount = |coin: Option<&sdk::Coin>, expected_denom| -> Result<Amount> {
                    let coin = coin.map_or_else(|| Err(Error::App("Empty amount".into())), Ok)?;
                    if coin.denom != expected_denom {
                        return Err(Error::App(format!(
                            "Invalid denom in amount: {}",
                            coin.denom,
                        )));
                    }

                    let amount: u64 = coin.amount.parse()?;
                    Ok(Amount::new(amount))
                };

                // TODO: move message validation/parsing into orga (e.g. with a message enum)

                match msg.type_.as_str() {
                    "cosmos-sdk/MsgSend" => {
                        let msg: sdk::MsgSend = serde_json::value::from_value(msg.value.clone())
                            .map_err(|e| Error::App(e.to_string()))?;

                        let from: Address = msg
                            .from_address
                            .parse()
                            .map_err(|e: bech32::Error| Error::App(e.to_string()))?;
                        if from != sender_address {
                            return Err(Error::App(
                                "'from_address' must match sender address".to_string(),
                            ));
                        }

                        let to: Address = msg
                            .to_address
                            .parse()
                            .map_err(|e: bech32::Error| Error::App(e.to_string()))?;

                        if msg.amount.len() != 1 {
                            return Err(Error::App(
                                "'amount' must have exactly one element".to_string(),
                            ));
                        }

                        match msg.amount[0].denom.as_str() {
                            "unom" => {
                                let amount = get_amount(msg.amount.first(), "unom")?;

                                let payer =
                                    build_call!(self.accounts.take_as_funding(MIN_FEE.into()));
                                let paid = build_call!(self.accounts.transfer(to, amount));

                                Ok(PaidCall { payer, paid })
                            }
                            "usat" => {
                                let amount = get_amount(msg.amount.first(), "usat")?;

                                let payer = build_call!(self.bitcoin.transfer(to, amount));
                                let paid = build_call!(self.app_noop());

                                Ok(PaidCall { payer, paid })
                            }
                            _ => Err(Error::App("Unknown denom".to_string())),
                        }
                    }

                    "cosmos-sdk/MsgDelegate" => {
                        let msg: sdk::MsgDelegate =
                            serde_json::value::from_value(msg.value.clone())
                                .map_err(|e| Error::App(e.to_string()))?;

                        let del_addr: Address = msg
                            .delegator_address
                            .parse()
                            .map_err(|e: bech32::Error| Error::App(e.to_string()))?;
                        if del_addr != sender_address {
                            return Err(Error::App(
                                "'delegator_address' must match sender address".to_string(),
                            ));
                        }

                        let val_addr: Address = msg
                            .validator_address
                            .parse()
                            .map_err(|e: bech32::Error| Error::App(e.to_string()))?;
                        let amount: u64 = get_amount(msg.amount.as_ref(), "unom")?.into();

                        let funding_amt = MIN_FEE + amount;
                        let payer = build_call!(self.accounts.take_as_funding(funding_amt.into()));
                        let paid =
                            build_call!(self.staking.delegate_from_self(val_addr, amount.into()));

                        Ok(PaidCall { payer, paid })
                    }

                    "cosmos-sdk/MsgBeginRedelegate" => {
                        let msg: sdk::MsgBeginRedelegate =
                            serde_json::value::from_value(msg.value.clone())
                                .map_err(|e| Error::App(e.to_string()))?;

                        let del_addr: Address = msg
                            .delegator_address
                            .parse()
                            .map_err(|e: bech32::Error| Error::App(e.to_string()))?;
                        if del_addr != sender_address {
                            return Err(Error::App(
                                "'delegator_address' must match sender address".to_string(),
                            ));
                        }

                        let val_src_addr: Address = msg
                            .validator_src_address
                            .parse()
                            .map_err(|e: bech32::Error| Error::App(e.to_string()))?;
                        let val_dst_addr: Address = msg
                            .validator_dst_address
                            .parse()
                            .map_err(|e: bech32::Error| Error::App(e.to_string()))?;

                        let amount = get_amount(msg.amount.as_ref(), "unom")?;

                        let funding_amt = MIN_FEE;
                        let payer = build_call!(self.accounts.take_as_funding(funding_amt.into()));

                        let paid = build_call!(self.staking.redelegate_self(
                            val_src_addr,
                            val_dst_addr,
                            amount
                        ));

                        Ok(PaidCall { payer, paid })
                    }

                    "cosmos-sdk/MsgUndelegate" => {
                        let msg: sdk::MsgUndelegate =
                            serde_json::value::from_value(msg.value.clone())
                                .map_err(|e| Error::App(e.to_string()))?;

                        let del_addr: Address = msg
                            .delegator_address
                            .parse()
                            .map_err(|e: bech32::Error| Error::App(e.to_string()))?;
                        if del_addr != sender_address {
                            return Err(Error::App(
                                "'delegator_address' must match sender address".to_string(),
                            ));
                        }

                        let val_addr: Address = msg
                            .validator_address
                            .parse()
                            .map_err(|e: bech32::Error| Error::App(e.to_string()))?;
                        let amount = get_amount(msg.amount.as_ref(), "unom")?;

                        let funding_amt = MIN_FEE;
                        let payer = build_call!(self.accounts.take_as_funding(funding_amt.into()));
                        let paid = build_call!(self.staking.unbond_self(val_addr, amount));

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgClaimRewards" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }

                        let payer = build_call!(self.staking.claim_all());
                        let paid = build_call!(self.deposit_rewards());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgClaimAirdrop1" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }

                        let payer = build_call!(self.airdrop.claim_airdrop1());
                        let paid = build_call!(self.accounts.give_from_funding_all());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgClaimAirdrop2" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }

                        let payer = build_call!(self.airdrop.claim_airdrop2());
                        let paid = build_call!(self.accounts.give_from_funding_all());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgWithdraw" => {
                        let msg: MsgWithdraw = serde_json::value::from_value(msg.value.clone())
                            .map_err(|e| Error::App(e.to_string()))?;

                        let dest_addr: bitcoin::Address = msg.dst_address.parse().map_err(
                            |e: bitcoin::util::address::Error| Error::App(e.to_string()),
                        )?;
                        if !matches_bitcoin_network(&dest_addr.network) {
                            return Err(Error::App(format!(
                                "Invalid network for destination address. Got {}, Expected {}",
                                dest_addr.network,
                                crate::bitcoin::NETWORK
                            )));
                        }

                        let dest_script =
                            crate::bitcoin::adapter::Adapter::new(dest_addr.script_pubkey());

                        let amount: u64 = msg
                            .amount
                            .parse()
                            .map_err(|e: std::num::ParseIntError| Error::App(e.to_string()))?;

                        let payer = build_call!(self.withdraw_nbtc(dest_script, amount.into()));
                        let paid = build_call!(self.app_noop());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgClaimIbcBitcoin" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }

                        let payer = build_call!(self.claim_escrowed_nbtc());
                        let paid = build_call!(self.app_noop());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgIbcTransferOut" => {
                        let msg: MsgIbcTransfer = serde_json::value::from_value(msg.value.clone())
                            .map_err(|e| Error::App(e.to_string()))?;

                        let channel_id = msg
                            .channel_id
                            .parse::<ChannelId>()
                            .map_err(|_| Error::Ibc("Invalid channel id".into()))?;

                        let port_id = msg
                            .port_id
                            .parse::<PortId>()
                            .map_err(|_| Error::Ibc("Invalid port".into()))?;

                        let denom = msg.denom.as_str();
                        if denom != "usat" {
                            return Err(Error::App("Unsupported denom for IBC transfer".into()));
                        }

                        let amount: u64 = msg
                            .amount
                            .parse()
                            .map_err(|e: std::num::ParseIntError| Error::App(e.to_string()))?;

                        let ibc_sender_addr = msg
                            .sender
                            .parse::<Address>()
                            .map_err(|_| Error::Ibc("Invalid sender address".into()))?;

                        if ibc_sender_addr != sender_address {
                            return Err(Error::App(
                                "'sender' must match sender address".to_string(),
                            ));
                        }

                        let timeout_timestamp = msg
                            .timeout_timestamp
                            .parse::<u64>()
                            .map_err(|_| Error::Ibc("Invalid timeout timestamp".into()))?;

                        let dest = IbcDest {
                            source_port: port_id.to_string().try_into()?,
                            source_channel: channel_id.to_string().try_into()?,
                            sender: msg.sender.try_into()?,
                            receiver: msg.receiver.try_into()?,
                            timeout_timestamp,
                            memo: msg.memo.try_into()?,
                        };

                        let payer = build_call!(self.ibc_transfer_nbtc(dest, amount.into()));
                        let paid = build_call!(self.app_noop());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgJoinRewardAccounts" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;

                        let dest_addr: Address = msg
                            .get("dest_address")
                            .ok_or_else(|| Error::App("Missing destination address".to_string()))?
                            .as_str()
                            .ok_or_else(|| Error::App("Invalid destination address".to_string()))?
                            .parse()
                            .map_err(|_| Error::App("Invalid destination address".to_string()))?;

                        let payer = build_call!(self.join_accounts(dest_addr));
                        let paid = build_call!(self.app_noop());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgClaimTestnetParticipationIncentives" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }
                        let payer =
                            build_call!(self.incentives.claim_testnet_participation_incentives());
                        let paid = build_call!(self.accounts.give_from_funding_all());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgSetRecoveryAddress" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;

                        let recovery_addr: bitcoin::Address = msg
                            .get("recovery_address")
                            .ok_or_else(|| Error::App("Missing reovery address".to_string()))?
                            .as_str()
                            .ok_or_else(|| Error::App("Invalid recovery address".to_string()))?
                            .parse()
                            .map_err(|_| Error::App("Invalid recovery address".to_string()))?;

                        if !matches_bitcoin_network(&recovery_addr.network) {
                            return Err(Error::App(format!(
                                "Invalid network for recovery address. Got {}, Expected {}",
                                recovery_addr.network,
                                crate::bitcoin::NETWORK
                            )));
                        }

                        let script =
                            crate::bitcoin::adapter::Adapter::new(recovery_addr.script_pubkey());

                        let funding_amt = MIN_FEE;
                        let payer = build_call!(self.pay_nbtc_fee());
                        let paid = build_call!(self.bitcoin.set_recovery_script(script.clone()));

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgPayToFeePool" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;

                        let amount: u64 = msg
                            .get("amount")
                            .ok_or_else(|| Error::App("Missing amount".to_string()))?
                            .as_str()
                            .ok_or_else(|| Error::App("Invalid amount".to_string()))?
                            .parse()
                            .map_err(|e: std::num::ParseIntError| Error::App(e.to_string()))?;

                        let payer = build_call!(self.bitcoin.transfer_to_fee_pool(amount.into()));
                        let paid = build_call!(self.app_noop());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgStakeNbtc" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;

                        let amount: u64 = msg
                            .get("amount")
                            .ok_or_else(|| Error::App("Invalid amount".to_string()))?
                            .as_str()
                            .ok_or_else(|| Error::App("Invalid amount".to_string()))?
                            .parse()
                            .map_err(|e: std::num::ParseIntError| Error::App(e.to_string()))?;

                        let fp_vec = hex::decode(
                            msg.get("finality_provider")
                                .ok_or_else(|| Error::App("Invalid finality provider".to_string()))?
                                .as_str()
                                .ok_or_else(|| {
                                    Error::App("Invalid finality provider".to_string())
                                })?,
                        )
                        .map_err(|e| Error::App(e.to_string()))?;
                        if fp_vec.len() != 32 {
                            return Err(Error::App("Invalid finality provider".to_string()));
                        }
                        let mut fp = [0; 32];
                        fp.copy_from_slice(&fp_vec);

                        let staking_period: u16 = msg
                            .get("staking_period")
                            .ok_or_else(|| Error::App("Invalid staking period".to_string()))?
                            .as_str()
                            .ok_or_else(|| Error::App("Invalid staking period".to_string()))?
                            .parse()
                            .map_err(|e: std::num::ParseIntError| Error::App(e.to_string()))?;

                        let unbonding_period: u16 = msg
                            .get("unbonding_period")
                            .ok_or_else(|| Error::App("Invalid unbonding period".to_string()))?
                            .as_str()
                            .ok_or_else(|| Error::App("Invalid unbonding period".to_string()))?
                            .parse()
                            .map_err(|e: std::num::ParseIntError| Error::App(e.to_string()))?;

                        let payer = build_call!(self.pay_nbtc_fee());
                        let paid = build_call!(self.stake_nbtc(amount.into(), fp, staking_period));

                        Ok(PaidCall { payer, paid })
                    }

                    _ => Err(Error::App("Unsupported message type".into())),
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct MsgWithdraw {
    pub amount: String,
    pub dst_address: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MsgIbcTransfer {
    pub channel_id: String,
    pub port_id: String,
    pub amount: String,
    pub denom: String,
    pub receiver: String,
    pub sender: String,
    pub timeout_timestamp: String,
    pub memo: String,
}

use orga::ibc::{IbcMessage, PortChannel, RawIbcTx};

#[derive(Clone, Debug, Encode, Decode, Serialize, Deserialize, State)]
pub struct IbcDest {
    pub source_port: LengthString<u8>,
    pub source_channel: LengthString<u8>,
    pub receiver: LengthString<u8>,
    pub sender: LengthString<u8>,
    pub timeout_timestamp: u64,
    pub memo: LengthString<u8>,
}

impl IbcDest {
    pub fn transfer(
        &self,
        mut coins: Coin<Nbtc>,
        bitcoin: &mut Bitcoin,
        ibc: &mut Ibc,
    ) -> Result<()> {
        use orga::ibc::ibc_rs::apps::transfer::types::msgs::transfer::MsgTransfer;

        if !self.is_fee_exempt() {
            let fee_amount = ibc_fee(coins.amount)?;
            let fee = coins.take(fee_amount)?;
            bitcoin.give_rewards(fee)?;
        }
        let nbtc_amount = coins.amount;

        ibc.transfer_mut()
            .mint_coins_execute(&self.sender_address()?, &coins.into())?;

        let msg_transfer = MsgTransfer {
            port_id_on_a: self.source_port()?,
            chan_id_on_a: self.source_channel()?,
            packet_data: PacketData {
                token: Nbtc::mint(nbtc_amount).into(),
                receiver: self.receiver_signer()?,
                sender: self.sender_signer()?,
                memo: self.memo()?,
            },
            timeout_height_on_b: TimeoutHeight::Never,
            timeout_timestamp_on_b: TimeoutTimestamp::from_nanoseconds(self.timeout_timestamp),
        };
        if let Err(err) = ibc.deliver_message(IbcMessage::Ics20(msg_transfer)) {
            log::debug!("Failed IBC transfer: {}", err);
        }

        Ok(())
    }

    pub fn sender_address(&self) -> Result<Address> {
        self.sender
            .to_string()
            .parse()
            .map_err(|e: bech32::Error| Error::Coins(e.to_string()))
    }

    pub fn sender_signer(&self) -> Result<IbcSigner> {
        Ok(self.sender.to_string().into())
    }

    pub fn receiver_signer(&self) -> Result<IbcSigner> {
        Ok(self.receiver.to_string().into())
    }

    pub fn source_channel(&self) -> Result<ChannelId> {
        self.source_channel
            .to_string()
            .parse()
            .map_err(|_| Error::Ibc("Invalid channel id".into()))
    }

    pub fn source_port(&self) -> Result<PortId> {
        self.source_port
            .to_string()
            .parse()
            .map_err(|_| Error::Ibc("Invalid port id".into()))
    }

    pub fn memo(&self) -> Result<Memo> {
        Ok(self.memo.to_string().into())
    }

    pub fn is_fee_exempt(&self) -> bool {
        self.source_channel()
            .map_or(false, |channel| channel.to_string() == OSMOSIS_CHANNEL_ID)
    }

    pub fn validate(&self) -> Result<()> {
        self.source_port()?;
        self.source_channel()?;
        self.sender_address()?;

        Ok(())
    }

    pub fn legacy_encode(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![];
        self.source_port.encode_into(&mut bytes)?;
        self.source_channel.encode_into(&mut bytes)?;
        EdAdapter(self.receiver_signer()?).encode_into(&mut bytes)?;
        EdAdapter(self.sender_signer()?).encode_into(&mut bytes)?;
        self.timeout_timestamp.encode_into(&mut bytes)?;
        self.memo.encode_into(&mut bytes)?;

        Ok(bytes)
    }
}

#[derive(Encode, Decode, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Dest {
    NativeAccount {
        address: Address,
    },
    Ibc {
        data: IbcDest,
    },
    RewardPool,
    Bitcoin {
        #[serde(with = "address_or_script")]
        data: Adapter<Script>,
    },
    #[cfg(feature = "ethereum")]
    EthAccount {
        network: u32,
        // TODO: ethaddress type
        #[serde(with = "SerHex::<StrictPfx>")]
        connection: [u8; 20],
        // TODO: ethaddress type
        #[serde(with = "SerHex::<StrictPfx>")]
        address: [u8; 20],
    },
    #[cfg(feature = "ethereum")]
    EthCall {
        network: u32,
        // TODO: ethaddress type
        #[serde(with = "SerHex::<StrictPfx>")]
        connection: [u8; 20],
        // TODO: ethaddress type
        #[serde(with = "SerHex::<StrictPfx>")]
        contract_address: [u8; 20],
        data: LengthVec<u16, u8>,
        max_gas: u64,
        // TODO: ethaddress type
        #[serde(with = "SerHex::<StrictPfx>")]
        fallback_address: [u8; 20],
    },
    #[cfg(feature = "babylon")]
    Stake {
        // TODO: this should be a Dest, but the cycle prevents the macro-generated Terminated impl
        // from applying
        return_dest: LengthString<u16>,
        #[serde(with = "SerHex::<Strict>")]
        finality_provider: [u8; 32],
        staking_period: u16,
    },
    #[cfg(feature = "babylon")]
    Unstake {
        index: u64,
    },
    AdjustEmergencyDisbursalBalance {
        #[serde(with = "address_or_script")]
        data: Adapter<Script>,
        difference: i64,
    },
}

mod address_or_script {
    use serde::{Deserializer, Serializer};
    use std::result::Result;

    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Adapter<Script>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let dest = String::deserialize(deserializer)?;
        let script = if let Ok(addr) = bitcoin::Address::from_str(&dest) {
            if !matches_bitcoin_network(&addr.network) {
                return Err(serde::de::Error::custom(format!(
                    "Invalid network for Bitcoin dest. Got {}, Expected {}",
                    addr.network,
                    crate::bitcoin::NETWORK
                )));
            }
            addr.script_pubkey()
        } else {
            bitcoin::Script::from_str(&dest)
                .map_err(|e| serde::de::Error::custom("Invalid Bitcoin script"))?
        };

        Ok(script.into())
    }

    pub fn serialize<S>(script: &Adapter<Script>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Ok(addr) =
            bitcoin::Address::from_script(&script.clone().into_inner(), crate::bitcoin::NETWORK)
        {
            addr.serialize(serializer)
        } else {
            script.serialize(serializer)
        }
    }
}

#[test]
fn dest_json() {
    assert_eq!(
        Dest::NativeAccount {
            address: Address::NULL
        }
        .to_string(),
        "{\"type\":\"nativeAccount\",\"address\":\"nomic1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0mn95h\"}"
    );

    assert_eq!(
        Dest::Ibc { data: IbcDest{source_port:"transfer".try_into().unwrap(),source_channel:"channel-0".try_into().unwrap(),sender:"nomic1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0mn95h".try_into().unwrap(),receiver:"nomic1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0mn95h".try_into().unwrap(),timeout_timestamp:123_456_789,memo:"memo".try_into().unwrap(),} }
        .to_string(),
        "{\"type\":\"ibc\",\"data\":{\"source_port\":\"transfer\",\"source_channel\":\"channel-0\",\"receiver\":\"nomic1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0mn95h\",\"sender\":\"nomic1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0mn95h\",\"timeout_timestamp\":123456789,\"memo\":\"memo\"}}"
    );

    // TODO: use an eth address type
    #[cfg(feature = "ethereum")]
    assert_eq!(
        Dest::EthAccount {
            network: 123,
            connection: [0; 20],
            address: [0; 20],
        }
        .to_string(),
        "{\"type\":\"ethAccount\",\"network\":123,\"connection\":\"0x0000000000000000000000000000000000000000\",\"address\":\"0x0000000000000000000000000000000000000000\"}"
    );

    assert_eq!(Dest::RewardPool.to_string(), "{\"type\":\"rewardPool\"}");

    let out = "{\"type\":\"bitcoin\",\"data\":\"6a03010203\"}";
    assert_eq!(
        Dest::Bitcoin {
            data: Adapter::new(Script::new_op_return(&[1, 2, 3]))
        }
        .to_string(),
        out
    );
    let Dest::Bitcoin { data } = Dest::from_str(out).unwrap() else {
        unreachable!();
    };
    assert_eq!(*data, Script::new_op_return(&[1, 2, 3]));

    let addr = bitcoin::Address::p2wpkh(
        &bitcoin::PublicKey::from_slice(&[2; 33]).unwrap(),
        bitcoin::Network::Bitcoin,
    )
    .unwrap();

    #[cfg(all(feature = "testnet", not(feature = "devnet")))]
    let out = "{\"type\":\"bitcoin\",\"data\":\"tb1q2xq57yyxwzkw6tthcxq9mhtxxj7f63e3dgldfj\"}";
    #[cfg(all(not(feature = "testnet"), not(feature = "devnet")))]
    let out = "{\"type\":\"bitcoin\",\"data\":\"bc1q2xq57yyxwzkw6tthcxq9mhtxxj7f63e38wy7jp\"}";
    #[cfg(all(feature = "devnet", feature = "testnet"))]
    let out = "{\"type\":\"bitcoin\",\"data\":\"tb1q2xq57yyxwzkw6tthcxq9mhtxxj7f63e3dgldfj\"}";
    assert_eq!(
        Dest::Bitcoin {
            data: Adapter::new(addr.script_pubkey())
        }
        .to_string(),
        out
    );

    let Dest::Bitcoin { data } = Dest::from_str(out).unwrap() else {
        unreachable!();
    };
    assert_eq!(*data, addr.script_pubkey());

    // TODO: other Dest variants
}

impl Dest {
    pub fn to_receiver_addr(&self) -> Option<String> {
        Some(match self {
            Dest::NativeAccount { address } => address.to_string(),
            Dest::Ibc { data } => data.receiver.to_string(),
            Dest::RewardPool => return None,
            #[cfg(feature = "ethereum")]
            Dest::EthAccount { address, .. } => hex::encode(address),
            #[cfg(feature = "ethereum")]
            Dest::EthCall {
                contract_address, ..
            } => hex::encode(contract_address),
            Dest::Bitcoin { .. } => return None,
            #[cfg(feature = "babylon")]
            Dest::Stake { return_dest, .. } => {
                let return_dest: Dest = return_dest.parse().ok()?;
                return return_dest.to_receiver_addr();
            }
            #[cfg(feature = "babylon")]
            Dest::Unstake { .. } => return None,
            Dest::AdjustEmergencyDisbursalBalance { .. } => {
                return None;
            }
        })
    }

    pub fn commitment_bytes(&self) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};

        let bytes = self.encode()?;
        let hash = Sha256::digest(bytes);

        let mut bytes = Vec::with_capacity(hash.len() + 1);
        bytes.push(0); // version byte
        bytes.extend_from_slice(&hash);
        Ok(bytes)
    }

    // TODO: remove once there are no legacy commitments in-flight
    pub fn legacy_commitment_bytes(&self) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let bytes = match self {
            Dest::NativeAccount { address } => address.bytes().into(),
            Dest::Ibc { data } => Sha256::digest(data.legacy_encode()?).to_vec(),
            _ => return Err(Error::App("Invalid dest for legacy commitment".to_string())),
        };

        Ok(bytes)
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes =
            base64::decode(s).map_err(|_| Error::App("Failed to decode base64".to_string()))?;
        Ok(Self::decode(&mut &bytes[..])?)
    }

    pub fn to_base64(&self) -> Result<String> {
        let bytes = self.encode()?;
        Ok(base64::encode(bytes))
    }

    pub fn to_output_script(
        &self,
        recovery_scripts: &orga::collections::Map<Address, Adapter<Script>>,
    ) -> Result<Option<Script>> {
        match self {
            Dest::NativeAccount { address: addr } => Ok(recovery_scripts
                .get(*addr)?
                .map(|script| script.clone().into_inner())),
            // TODO
            _ => Ok(None),
        }
    }

    pub fn is_fee_exempt(&self) -> bool {
        if let Dest::Ibc { data: dest } = self {
            dest.is_fee_exempt()
        } else {
            false
        }
    }
}

impl std::fmt::Display for Dest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl FromStr for Dest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::App(e.to_string()))
    }
}

impl State for Dest {
    fn attach(&mut self, store: Store) -> Result<()> {
        Ok(())
    }

    fn load(_store: Store, bytes: &mut &[u8]) -> Result<Self> {
        Ok(Self::decode(bytes)?)
    }

    fn flush<W: std::io::Write>(self, out: &mut W) -> Result<()> {
        self.encode_into(out)?;
        Ok(())
    }
}

impl Query for Dest {
    type Query = ();

    fn query(&self, query: Self::Query) -> Result<()> {
        Ok(())
    }
}

impl Migrate for Dest {
    fn migrate(src: Store, dest: Store, bytes: &mut &[u8]) -> Result<Self> {
        Self::load(src, bytes)
    }
}

impl Describe for Dest {
    fn describe() -> Descriptor {
        ::orga::describe::Builder::new::<Self>()
            .meta::<()>()
            .build()
    }
}

impl Default for Dest {
    fn default() -> Self {
        Dest::NativeAccount {
            address: Address::NULL,
        }
    }
}

#[derive(Encode, Decode, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Identity {
    None,
    NativeAccount {
        address: Address,
    },
    #[cfg(feature = "ethereum")]
    EthAccount {
        network: u32,
        // TODO: ethaddress type
        #[serde(with = "SerHex::<StrictPfx>")]
        connection: [u8; 20],
        // TODO: ethaddress type
        #[serde(with = "SerHex::<StrictPfx>")]
        address: [u8; 20],
    },
}

impl Identity {
    pub fn from_signer() -> Result<Self> {
        Ok(Context::resolve::<Signer>()
            .ok_or_else(|| Error::Signer("No Signer context available".into()))?
            .signer
            .map(|address| Identity::NativeAccount { address })
            .unwrap_or(Identity::None))
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl FromStr for Identity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::App(e.to_string()))
    }
}

impl State for Identity {
    fn attach(&mut self, store: Store) -> Result<()> {
        Ok(())
    }

    fn load(_store: Store, bytes: &mut &[u8]) -> Result<Self> {
        Ok(Self::decode(bytes)?)
    }

    fn flush<W: std::io::Write>(self, out: &mut W) -> Result<()> {
        self.encode_into(out)?;
        Ok(())
    }
}

impl Query for Identity {
    type Query = ();

    fn query(&self, query: Self::Query) -> Result<()> {
        Ok(())
    }
}

impl Migrate for Identity {
    fn migrate(src: Store, dest: Store, bytes: &mut &[u8]) -> Result<Self> {
        Self::load(src, bytes)
    }
}

impl Describe for Identity {
    fn describe() -> Descriptor {
        ::orga::describe::Builder::new::<Self>()
            .meta::<()>()
            .build()
    }
}

impl Default for Identity {
    fn default() -> Self {
        Identity::None
    }
}

pub fn ibc_fee(amount: Amount) -> Result<Amount> {
    let fee_rate: orga::coins::Decimal = "0.005".parse().unwrap();
    (amount * fee_rate)?.amount()
}

const REWARD_TIMER_PERIOD: i64 = 120;

#[orga]
pub struct RewardTimer {
    last_period: i64,
}

impl RewardTimer {
    pub fn tick(&mut self, now: i64) -> bool {
        if now - self.last_period < REWARD_TIMER_PERIOD {
            return false;
        }

        self.last_period = now;
        true
    }
}

pub fn in_upgrade_window(now_seconds: i64) -> bool {
    #[cfg(not(feature = "testnet"))]
    {
        use chrono::prelude::*;
        let now = Utc.timestamp_opt(now_seconds, 0).unwrap();
        let valid_weekday = now.weekday().num_days_from_monday() < 5; // Monday - Friday
        let valid_time = now.hour() == 17 && now.minute() < 10; // 17:00 - 17:10 UTC
        valid_weekday && valid_time
    }

    #[cfg(feature = "testnet")]
    true // No restrictions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_date() {
        #[cfg(not(feature = "testnet"))]
        {
            assert!(in_upgrade_window(1690218300)); // Monday 17:05 UTC
            assert!(in_upgrade_window(1690391100)); // Wednesday 17:05 UTC
            assert!(!in_upgrade_window(1690392000)); // Wednesday 17:15 UTC
            assert!(!in_upgrade_window(1690736700)); // Sunday 17:05 UTC
        }

        #[cfg(feature = "testnet")]
        {
            assert!(in_upgrade_window(1690218300)); // Monday 17:05 UTC
            assert!(in_upgrade_window(1690391100)); // Wednesday 17:05 UTC
            assert!(in_upgrade_window(1690392000)); // Wednesday 17:15 UTC
            assert!(in_upgrade_window(1690736700)); // Sunday 17:05 UTC
        }
    }
}
