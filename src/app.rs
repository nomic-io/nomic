#![allow(clippy::too_many_arguments)]
// TODO: remove after swtiching from "testnet" feature flag to orga channels
#![allow(unused_variables)]
#![allow(unused_imports)]

use crate::airdrop::Airdrop;
use crate::bitcoin::adapter::Adapter;
use crate::bitcoin::{Bitcoin, Nbtc};
use crate::incentives::Incentives;
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::Transaction;
use orga::coins::{
    Accounts, Address, Amount, Coin, Faucet, FaucetOptions, Give, Staking, Symbol, Take,
};
use orga::context::GetContext;
use orga::cosmrs::bank::MsgSend;
use orga::encoding::{Decode, Encode};
use orga::plugins::Time;
use std::time::Duration;

use orga::ibc::ibc_rs::applications::transfer::context::TokenTransferExecutionContext;
use orga::ibc::ibc_rs::applications::transfer::msgs::transfer::MsgTransfer;
use orga::ibc::ibc_rs::applications::transfer::packet::PacketData;
use orga::ibc::ibc_rs::core::ics04_channel::timeout::TimeoutHeight;
use orga::ibc::ibc_rs::core::ics24_host::identifier::{ChannelId, PortId};
use orga::ibc::ibc_rs::core::timestamp::Timestamp;
#[cfg(feature = "testnet")]
use orga::ibc::{Ibc, IbcTx};

use orga::ibc::ibc_rs::Signer as IbcSigner;

use orga::encoding::Adapter as EdAdapter;
use orga::macros::build_call;
use orga::migrate::MigrateFrom;
use orga::orga;
use orga::plugins::sdk_compat::{sdk, sdk::Tx as SdkTx, ConvertSdkTx};
use orga::plugins::{DefaultPlugins, PaidCall, Signer, MIN_FEE};
use orga::prelude::*;
use orga::upgrade::Version;
use orga::upgrade::{Upgrade, UpgradeV0};
use orga::Error;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::Debug;

mod migrations;

pub const CHAIN_ID: &str = "nomic-testnet-4d";
pub type AppV0 = DefaultPlugins<Nom, InnerAppV0>;
pub type App = DefaultPlugins<Nom, InnerApp>;

#[derive(State, Debug, Clone, Encode, Decode, Default, MigrateFrom, Serialize)]
pub struct Nom(());
impl Symbol for Nom {
    const INDEX: u8 = 69;
}
const DEV_ADDRESS: &str = "nomic14z79y3yrghqx493mwgcj0qd2udy6lm26lmduah";
const STRATEGIC_RESERVE_ADDRESS: &str = "nomic1d5n325zrf4elfu0heqd59gna5j6xyunhev23cj";
const VALIDATOR_BOOTSTRAP_ADDRESS: &str = "nomic1fd9mxxt84lw3jdcsmjh6jy8m6luafhqd8dcqeq";

#[orga(version = 2)]
pub struct InnerApp {
    #[call]
    pub accounts: Accounts<Nom>,
    #[call]
    pub staking: Staking<Nom>,
    #[call]
    pub airdrop: Airdrop,

    community_pool: Coin<Nom>,
    incentive_pool: Coin<Nom>,

    staking_rewards: Faucet<Nom>,
    dev_rewards: Faucet<Nom>,
    community_pool_rewards: Faucet<Nom>,
    incentive_pool_rewards: Faucet<Nom>,

    #[call]
    pub bitcoin: Bitcoin,
    pub reward_timer: RewardTimer,

    #[cfg(feature = "testnet")]
    #[call]
    #[orga(version(V1, V2))]
    pub ibc: Ibc,

    #[orga(version(V1, V2))]
    upgrade: Upgrade,

    #[orga(version(V2))]
    pub incentives: Incentives,
}

#[orga]
impl InnerApp {
    pub const CONSENSUS_VERSION: u8 = 1;

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
    pub fn ibc_deposit_nbtc(&mut self, to: Address, amount: Amount) -> Result<()> {
        #[cfg(feature = "testnet")]
        {
            crate::bitcoin::exempt_from_fee()?;

            let signer = self.signer()?;
            let mut coins = self.bitcoin.accounts.withdraw(signer, amount)?;
            if let Some(mut acct) = self.airdrop.get_mut(signer)? {
                acct.ibc_transfer.unlock();
            }

            let fee = ibc_fee(amount)?;
            let fee = coins.take(fee)?;
            self.ibc.mint_coins_execute(&to, &coins.into())?;
            self.bitcoin.reward_pool.give(fee)?;

            Ok(())
        }

        #[cfg(not(feature = "testnet"))]
        Err(orga::Error::Unknown)
    }

    #[call]
    pub fn ibc_withdraw_nbtc(&mut self, amount: Amount) -> Result<()> {
        #[cfg(feature = "testnet")]
        {
            crate::bitcoin::exempt_from_fee()?;

            let signer = self.signer()?;
            let coins: Coin<Nbtc> = amount.into();
            self.ibc.burn_coins_execute(&signer, &coins.into())?;
            self.bitcoin.accounts.deposit(signer, amount.into())?;

            Ok(())
        }

        #[cfg(not(feature = "testnet"))]
        Err(orga::Error::Unknown)
    }

    #[query]
    pub fn escrowed_nbtc(&self, address: Address) -> Result<Amount> {
        #[cfg(feature = "testnet")]
        {
            self.ibc.transfer.symbol_balance::<Nbtc>(address)
        }

        #[cfg(not(feature = "testnet"))]
        Err(orga::Error::Unknown)
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
        dest: DepositCommitment,
    ) -> Result<()> {
        #[cfg(feature = "testnet")]
        {
            let nbtc = self.bitcoin.relay_deposit(
                btc_tx,
                btc_height,
                btc_proof,
                btc_vout,
                sigset_index,
                dest.commitment_bytes()?.as_slice(),
            )?;
            match dest {
                DepositCommitment::Address(addr) => {
                    if let Some(mut acct) = self.airdrop.get_mut(addr)? {
                        acct.btc_deposit.unlock();
                    }
                    self.bitcoin.accounts.deposit(addr, nbtc.into())?
                }
                DepositCommitment::Ibc(dest) => {
                    use orga::ibc::ibc_rs::applications::transfer::msgs::transfer::MsgTransfer;
                    let fee = ibc_fee(nbtc)?;
                    let nbtc_after_fee = (nbtc - fee).result()?;
                    let coins: Coin<Nbtc> = nbtc_after_fee.into();
                    let src = dest.source;
                    let msg_transfer = MsgTransfer {
                        port_id_on_a: src.port_id()?,
                        chan_id_on_a: src.channel_id()?,
                        packet_data: PacketData {
                            token: coins.into(),
                            receiver: dest.receiver.0,
                            sender: dest.sender.0.clone(),
                            memo: "".to_string().into(),
                        },
                        timeout_height_on_b: TimeoutHeight::Never,
                        timeout_timestamp_on_b: Timestamp::from_nanoseconds(dest.timeout_timestamp)
                            .map_err(|e| Error::App(e.to_string()))?,
                    };

                    let coins: Coin<Nbtc> = nbtc_after_fee.into();
                    self.ibc.mint_coins_execute(
                        &dest
                            .sender
                            .0
                            .try_into()
                            .map_err(|_| Error::App("Invalid sender address".into()))?,
                        &coins.into(),
                    )?;
                    self.bitcoin.reward_pool.give(fee.into())?;

                    self.ibc.deliver_message(IbcMessage::Ics20(msg_transfer))?;
                }
            }

            Ok(())
        }

        #[cfg(not(feature = "testnet"))]
        Err(orga::Error::Unknown)
    }

    #[call]
    pub fn withdraw_nbtc(
        &mut self,
        script_pubkey: Adapter<bitcoin::Script>,
        amount: Amount,
    ) -> Result<()> {
        let signer = self.signer()?;
        if let Some(mut acct) = self.airdrop.get_mut(signer)? {
            acct.btc_withdraw.unlock();
        }

        Ok(self.bitcoin.withdraw(script_pubkey, amount)?)
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
    pub fn app_noop(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(feature = "full")]
mod abci {
    use orga::{
        abci::{messages, AbciQuery, BeginBlock, EndBlock, InitChain},
        coins::{Give, Take},
        plugins::{BeginBlockCtx, EndBlockCtx, InitChainCtx},
    };

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

            self.airdrop
                .init_from_airdrop1_csv(include_bytes!("../airdrop1_snapshot.csv"))?;
            self.airdrop
                .init_from_airdrop2_csv(include_bytes!("../airdrop2_snapshot.csv"))?;

            self.accounts.allow_transfers(true);
            self.bitcoin.accounts.allow_transfers(true);

            self.accounts.add_transfer_exception(sr_address)?;

            let vb_address = VALIDATOR_BOOTSTRAP_ADDRESS.parse().unwrap();
            self.accounts.add_transfer_exception(vb_address)?;

            self.configure_faucets()?;

            self.upgrade
                .current_version
                .insert((), vec![Self::CONSENSUS_VERSION].try_into().unwrap())?;

            Ok(())
        }
    }

    impl BeginBlock for InnerApp {
        fn begin_block(&mut self, ctx: &BeginBlockCtx) -> Result<()> {
            self.upgrade
                .step(&vec![Self::CONSENSUS_VERSION].try_into().unwrap())?;
            self.staking.begin_block(ctx)?;

            #[cfg(feature = "testnet")]
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

            self.accounts
                .deposit(
                    "nomic124j0ky0luh9jzqh9w2dk77cze9v0ckdupk50ny"
                        .parse()
                        .unwrap(),
                    Nom::mint(100000000),
                )
                .unwrap();

            self.bitcoin.begin_block(ctx)?;

            let now = ctx.header.time.as_ref().unwrap().seconds;
            let has_nbtc_rewards = self.bitcoin.reward_pool.amount > 0;
            if self.reward_timer.tick(now) && has_stake && has_nbtc_rewards {
                let reward_rate = (Amount::new(1) / Amount::new(2377))?; // ~0.00042069
                let reward_amount = (self.bitcoin.reward_pool.amount * reward_rate)?.amount()?;
                let reward = self.bitcoin.reward_pool.take(reward_amount)?;
                self.staking.give(reward)?;
            }

            Ok(())
        }
    }

    impl EndBlock for InnerApp {
        fn end_block(&mut self, ctx: &EndBlockCtx) -> Result<()> {
            self.staking.end_block(ctx)
        }
    }

    #[cfg(feature = "testnet")]
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
                #[cfg(feature = "testnet")]
                if IbcTx::try_from(tx.clone()).is_ok() {
                    let funding_amt = MIN_FEE;
                    let payer = build_call!(self.accounts.take_as_funding(funding_amt.into()));

                    let raw_ibc_tx = RawIbcTx(tx.clone());
                    let paid = build_call!(self.ibc.deliver(raw_ibc_tx.clone()));

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
                            let amount: u64 = msg.amount[0].amount.to_string().parse().unwrap();

                            let payer = build_call!(self.accounts.take_as_funding(MIN_FEE.into()));
                            let paid = build_call!(self.accounts.transfer(to, amount.into()));

                            return Ok(PaidCall { payer, paid });
                        }
                        "usat" => {
                            let amount: u64 = msg.amount[0].amount.to_string().parse().unwrap();

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

                    "nomic/MsgClaimBtcDepositAirdrop" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }

                        let payer = build_call!(self.airdrop.claim_btc_deposit());
                        let paid = build_call!(self.accounts.give_from_funding_all());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgClaimBtcWithdrawAirdrop" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }

                        let payer = build_call!(self.airdrop.claim_btc_withdraw());
                        let paid = build_call!(self.accounts.give_from_funding_all());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgClaimIbcTransferAirdrop" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }

                        let payer = build_call!(self.airdrop.claim_ibc_transfer());
                        let paid = build_call!(self.accounts.give_from_funding_all());

                        Ok(PaidCall { payer, paid })
                    }

                    #[cfg(feature = "stakenet")]
                    "nomic/MsgClaimTestnetParticipationAirdrop" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }

                        let payer = build_call!(self.airdrop.claim_testnet_participation());
                        let paid = build_call!(self.accounts.give_from_funding_all());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgWithdraw" => {
                        let msg: MsgWithdraw = serde_json::value::from_value(msg.value.clone())
                            .map_err(|e| Error::App(e.to_string()))?;

                        let dest_addr: bitcoin::Address = msg.dst_address.parse().map_err(
                            |e: bitcoin::util::address::Error| Error::App(e.to_string()),
                        )?;
                        let dest_script =
                            crate::bitcoin::adapter::Adapter::new(dest_addr.script_pubkey());

                        let amount: u64 = msg
                            .amount
                            .parse()
                            .map_err(|e: std::num::ParseIntError| Error::App(e.to_string()))?;

                        let funding_amt = MIN_FEE;
                        let payer = build_call!(self.accounts.take_as_funding(funding_amt.into()));
                        let paid = build_call!(self.withdraw_nbtc(dest_script, amount.into()));

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

                    #[cfg(feature = "testnet")]
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

                        let amount = msg.amount.into();

                        let receiver: IbcSigner = msg.receiver.into();

                        let sender: IbcSigner = msg.sender.clone().into();

                        let ibc_sender_addr = msg
                            .sender
                            .parse::<Address>()
                            .map_err(|_| Error::Ibc("Invalid sender address".into()))?;

                        if ibc_sender_addr != sender_address {
                            return Err(Error::App(
                                "'sender' must match sender address".to_string(),
                            ));
                        }

                        let timestamp = msg
                            .timeout_timestamp
                            .parse::<u64>()
                            .map_err(|_| Error::Ibc("Invalid timeout timestamp".into()))?;

                        let timeout_timestamp: Timestamp =
                            Timestamp::from_nanoseconds(timestamp)
                                .map_err(|_| Error::Ibc("Invalid timeout timestamp".into()))?;

                        let ibc_fee = ibc_fee(amount)?;

                        let amount_after_fee = (amount - ibc_fee).result()?;
                        let coins: Coin<Nbtc> = amount_after_fee.into();
                        let msg_transfer = MsgTransfer {
                            chan_id_on_a: channel_id,
                            port_id_on_a: port_id,
                            packet_data: PacketData {
                                token: coins.into(),
                                memo: "".to_string().into(),
                                receiver,
                                sender,
                            },
                            timeout_height_on_b: TimeoutHeight::Never,
                            timeout_timestamp_on_b: timeout_timestamp,
                        };

                        let payer = build_call!(self.ibc_deposit_nbtc(sender_address, amount));
                        let paid = build_call!(self.ibc.raw_transfer(msg_transfer.clone().into()));

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgJoinAirdropAccounts" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;

                        let dest_addr: Address = msg["dest_address"]
                            .as_str()
                            .ok_or_else(|| Error::App("Invalid destination address".to_string()))?
                            .parse()
                            .map_err(|_| Error::App("Invalid destination address".to_string()))?;

                        let payer = build_call!(self.airdrop.join_accounts(dest_addr));
                        let paid = build_call!(self.app_noop());

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
    pub amount: u64,
    pub denom: String,
    pub receiver: String,
    pub sender: String,
    pub timeout_timestamp: String,
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum DepositCommitment {
    Address(Address),
    Ibc(IbcDepositCommitment),
}

use orga::ibc::{IbcMessage, PortChannel, RawIbcTx};

#[derive(Clone, Debug, Encode, Decode)]
pub struct IbcDepositCommitment {
    pub source: PortChannel,
    pub receiver: EdAdapter<IbcSigner>,
    pub sender: EdAdapter<IbcSigner>,
    pub timeout_timestamp: u64,
}

impl DepositCommitment {
    pub fn commitment_bytes(&self) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        use DepositCommitment::*;
        let bytes = match self {
            Address(addr) => addr.bytes().into(),
            Ibc(dest) => Sha256::digest(dest.encode()?).to_vec(),
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
}

pub fn ibc_fee(amount: Amount) -> Result<Amount> {
    let fee_rate: orga::coins::Decimal = "0.015".parse().unwrap();
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
