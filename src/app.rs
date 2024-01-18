#![allow(clippy::too_many_arguments)]
// TODO: remove after switching from "testnet" feature flag to orga channels
#![allow(unused_variables)]
#![allow(unused_imports)]

use crate::bitcoin::adapter::Adapter;
use crate::bitcoin::{Bitcoin, Nbtc};
use crate::cosmos::{Chain, Cosmos, Proof};

use crate::constants::{
    BTC_NATIVE_TOKEN_DENOM, DECLARE_FEE_USATS, IBC_FEE, IBC_FEE_USATS, INITIAL_SUPPLY_ORAIBTC,
    INITIAL_SUPPLY_USATS_FOR_RELAYER, MAIN_NATIVE_TOKEN_DENOM,
};
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{Script, Transaction, TxOut};
use orga::coins::{
    Accounts, Address, Amount, Coin, Faucet, FaucetOptions, Give, Staking, Symbol, Take,
};
use orga::context::GetContext;
use orga::cosmrs::bank::MsgSend;
use orga::cosmrs::tendermint::crypto::Sha256;
use orga::describe::{Describe, Descriptor};
use orga::encoding::{Decode, Encode, LengthVec};
use orga::ibc::ibc_rs::applications::transfer::Memo;
use std::str::FromStr;
use std::time::Duration;

use orga::ibc::ibc_rs::applications::transfer::context::TokenTransferExecutionContext;
use orga::ibc::ibc_rs::applications::transfer::msgs::transfer::MsgTransfer;
use orga::ibc::ibc_rs::applications::transfer::packet::PacketData;
use orga::ibc::ibc_rs::core::ics04_channel::timeout::TimeoutHeight;
use orga::ibc::ibc_rs::core::ics24_host::identifier::{ChannelId, PortId};
use orga::ibc::ibc_rs::core::timestamp::Timestamp;
use orga::ibc::{ClientId, Ibc, IbcTx};

use orga::ibc::ibc_rs::Signer as IbcSigner;

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
use std::convert::TryInto;
use std::env;
use std::fmt::Debug;

mod migrations;

pub type AppV0 = DefaultPlugins<Nom, InnerAppV0>;
pub type App = DefaultPlugins<Nom, InnerApp>;

#[derive(State, Debug, Clone, Encode, Decode, Default, Migrate, Serialize)]
pub struct Nom(());
impl Symbol for Nom {
    const INDEX: u8 = 69;
    const NAME: &'static str = MAIN_NATIVE_TOKEN_DENOM;
}

#[orga(version = 4)]
pub struct InnerApp {
    #[call]
    pub accounts: Accounts<Nom>,
    #[call]
    pub staking: Staking<Nom>,

    community_pool: Coin<Nom>,

    staking_rewards: Faucet<Nom>,
    community_pool_rewards: Faucet<Nom>,

    #[call]
    pub bitcoin: Bitcoin,
    pub reward_timer: RewardTimer,

    #[cfg(feature = "testnet")]
    #[call]
    pub ibc: Ibc,
    #[cfg(not(feature = "testnet"))]
    #[orga(version(V4))]
    #[call]
    pub ibc: Ibc,

    pub upgrade: Upgrade,

    #[cfg(feature = "testnet")]
    pub cosmos: Cosmos,
    #[cfg(not(feature = "testnet"))]
    #[orga(version(V4))]
    pub cosmos: Cosmos,
}

#[orga]
impl InnerApp {
    pub const CONSENSUS_VERSION: u8 = 11;

    #[call]
    pub fn deposit_rewards(&mut self) -> Result<()> {
        self.accounts.give_from_funding_all()?;
        self.bitcoin.accounts.give_from_funding_all()?;
        Ok(())
    }

    #[call]
    pub fn ibc_transfer_nbtc(&mut self, dest: IbcDest, amount: Amount) -> Result<()> {
        crate::bitcoin::exempt_from_fee()?;

        dest.source_port()?;
        dest.source_channel()?;
        dest.sender_address()?;

        let signer = self.signer()?;
        let mut coins = self.bitcoin.accounts.withdraw(signer, amount)?;

        let fee = ibc_fee(amount)?;
        let fee = coins.take(fee)?;
        self.bitcoin.reward_pool.give(fee)?;

        let building = &mut self.bitcoin.checkpoints.building_mut()?;
        let dest = Dest::Ibc(dest);
        building.insert_pending(dest, coins)?;

        Ok(())
    }

    #[call]
    pub fn ibc_withdraw_nbtc(&mut self, amount: Amount) -> Result<()> {
        crate::bitcoin::exempt_from_fee()?;

        let signer = self.signer()?;
        let coins: Coin<Nbtc> = amount.into();
        self.ibc
            .transfer_mut()
            .burn_coins_execute(&signer, &coins.into())?;
        self.bitcoin.accounts.deposit(signer, amount.into())?;

        Ok(())
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
        if let Dest::Ibc(dest) = dest.clone() {
            dest.source_port()?;
            dest.source_channel()?;
            dest.sender_address()?;
        }

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

    pub fn credit_transfer(&mut self, dest: Dest, nbtc: Coin<Nbtc>) -> Result<()> {
        match dest {
            Dest::Address(addr) => self.bitcoin.accounts.deposit(addr, nbtc),
            Dest::Ibc(dest) => dest.transfer(nbtc, &mut self.bitcoin, &mut self.ibc),
        }
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
            if transfer.denom.to_string() != BTC_NATIVE_TOKEN_DENOM {
                continue;
            }
            let memo: NbtcMemo = transfer.memo.parse().unwrap_or_default();
            if let NbtcMemo::Withdraw(script) = memo {
                let amount = transfer.amount;
                let receiver: Address = transfer
                    .receiver
                    .parse()
                    .map_err(|_| Error::Coins("Invalid address".to_string()))?;
                let coins = Coin::<Nbtc>::mint(amount);
                self.ibc
                    .transfer_mut()
                    .burn_coins_execute(&receiver, &coins.into())?;
                if self.bitcoin.add_withdrawal(script, amount.into()).is_err() {
                    let coins = Coin::<Nbtc>::mint(amount);
                    self.ibc
                        .transfer_mut()
                        .mint_coins_execute(&receiver, &coins.into())?;
                }
            }
        }

        Ok(())
    }

    #[call]
    pub fn declare_with_nbtc(&mut self, declaration: Declaration) -> Result<()> {
        self.deduct_nbtc_fee(DECLARE_FEE_USATS.into())?;
        let signer = self.signer()?;
        self.staking.declare(signer, declaration, 0.into())
    }

    fn deduct_nbtc_fee(&mut self, amount: Amount) -> Result<()> {
        disable_fee();
        let signer = self.signer()?;
        self.bitcoin.accounts.withdraw(signer, amount)?.burn();

        Ok(())
    }

    #[call]
    pub fn app_noop(&mut self) -> Result<()> {
        Ok(())
    }

    #[query]
    pub fn app_noop_query(&self) -> Result<()> {
        Ok(())
    }

    #[call]
    pub fn mint_initial_supply(&mut self) -> Result<String> {
        {
            // mint uoraibtc and nbtc for a funded address given in the env variable
            let funded_address = env::var("FUNDED_ADDRESS").map_err(|err| {
                orga::Error::Client(format!(
                    "Get funded address with error: {}",
                    err.to_string()
                ))
            })?;
            let funded_oraibtc_amount = env::var("FUNDED_ORAIBTC_AMOUNT").unwrap_or_default();
            let funded_usat_amount = env::var("FUNDED_USAT_AMOUNT").unwrap_or_default();

            let unom_coin: Coin<Nom> = Amount::new(
                funded_oraibtc_amount
                    .parse::<u64>()
                    .unwrap_or(INITIAL_SUPPLY_ORAIBTC),
            )
            .into();

            // mint new uoraibtc coin for funded address
            self.accounts
                .deposit(funded_address.parse().unwrap(), unom_coin)?;

            let nbtc_coin: Coin<Nbtc> = Amount::new(
                funded_usat_amount
                    .parse::<u64>()
                    .unwrap_or(INITIAL_SUPPLY_USATS_FOR_RELAYER),
            )
            .into();
            // add new nbtc coin to the funded address
            self.credit_transfer(Dest::Address(funded_address.parse().unwrap()), nbtc_coin)?;
            self.accounts
                .add_transfer_exception(funded_address.parse().unwrap())?;
            Ok(funded_address)
        }
        // #[cfg(not(feature = "faucet-test"))]
        // Err(orga::Error::Unknown)
    }

    // #[call]
    // pub fn mint_initial_supply(&mut self) -> Result<String> {
    //     let unom_coin: Coin<Nom> = Amount::new(INITIAL_SUPPLY_ORAIBTC).into();

    //     // mint new uoraibtc coin for funded address
    //     self.accounts
    //         .deposit(GOVERNANCE_ADDRESS.parse().unwrap(), unom_coin)?;

    //     let nbtc_coin: Coin<Nbtc> = Amount::new(INITIAL_SUPPLY_USATS_FOR_RELAYER).into();
    //     // add new nbtc coin to the funded address
    //     self.credit_transfer(
    //         Dest::Address(GOVERNANCE_ADDRESS.parse().unwrap()),
    //         nbtc_coin,
    //     )?;
    //     self.accounts
    //         .add_transfer_exception(GOVERNANCE_ADDRESS.parse().unwrap())?;
    //     Ok(GOVERNANCE_ADDRESS.to_string())
    // }
}

#[derive(Debug, Clone, Default)]
pub enum NbtcMemo {
    Withdraw(Adapter<bitcoin::Script>),
    #[default]
    Empty,
}
impl FromStr for NbtcMemo {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            Ok(NbtcMemo::Empty)
        } else {
            let parts = s.split(':').collect::<Vec<_>>();
            if parts.len() != 2 {
                return Err(Error::App("Invalid memo".into()));
            }
            if parts[0] != "withdraw" {
                return Err(Error::App("Only withdraw memo action is supported".into()));
            }
            let dest = parts[1];
            let script = if let Ok(addr) = bitcoin::Address::from_str(dest) {
                addr.script_pubkey()
            } else {
                bitcoin::Script::from_str(parts[1]).map_err(|e| Error::App(e.to_string()))?
            };

            Ok(NbtcMemo::Withdraw(script.into()))
        }
    }
}

#[cfg(feature = "full")]
mod abci {
    use orga::{
        abci::{messages, AbciQuery, BeginBlock, EndBlock, InitChain},
        coins::{Give, Take, UNBONDING_SECONDS},
        collections::Map,
        ibc::ibc_rs::core::ics02_client::error::ClientError,
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
            self.staking.unbonding_seconds = UNBONDING_SECONDS;

            self.accounts.allow_transfers(true);
            self.bitcoin.accounts.allow_transfers(true);

            self.upgrade
                .current_version
                .insert((), vec![Self::CONSENSUS_VERSION].try_into().unwrap())?;

            self.mint_initial_supply()?;
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

            // let has_stake = self.staking.staked()? > 0;
            // if has_stake {
            //     let reward = self.staking_rewards.mint()?;
            //     self.staking.give(reward)?;
            // }

            let pending_nbtc_transfers = self.bitcoin.take_pending()?;
            for (dest, coins) in pending_nbtc_transfers {
                self.credit_transfer(dest, coins)?;
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

            // let has_nbtc_rewards = self.bitcoin.reward_pool.amount > 0;
            // if self.reward_timer.tick(now) && has_stake && has_nbtc_rewards {
            //     let reward_rate = (Amount::new(1) / Amount::new(2377))?; // ~0.00042069
            //     let reward_amount = (self.bitcoin.reward_pool.amount * reward_rate)?.amount()?;
            //     let reward = self.bitcoin.reward_pool.take(reward_amount)?;
            //     self.staking.give(reward)?;
            // }

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
                if msg.type_url.as_str() == "/cosmos.bank.v1beta1.MsgSend" {
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
                        MAIN_NATIVE_TOKEN_DENOM => {
                            let amount: u64 = msg.amount[0].amount.to_string().parse().unwrap();

                            let payer = build_call!(self.accounts.take_as_funding(MIN_FEE.into()));
                            let paid = build_call!(self.accounts.transfer(to, amount.into()));

                            return Ok(PaidCall { payer, paid });
                        }
                        BTC_NATIVE_TOKEN_DENOM => {
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
                            MAIN_NATIVE_TOKEN_DENOM => {
                                let amount =
                                    get_amount(msg.amount.first(), MAIN_NATIVE_TOKEN_DENOM)?;

                                let payer =
                                    build_call!(self.accounts.take_as_funding(MIN_FEE.into()));
                                let paid = build_call!(self.accounts.transfer(to, amount));

                                Ok(PaidCall { payer, paid })
                            }
                            BTC_NATIVE_TOKEN_DENOM => {
                                let amount =
                                    get_amount(msg.amount.first(), BTC_NATIVE_TOKEN_DENOM)?;

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
                        let amount: u64 =
                            get_amount(msg.amount.as_ref(), MAIN_NATIVE_TOKEN_DENOM)?.into();

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

                        let amount = get_amount(msg.amount.as_ref(), MAIN_NATIVE_TOKEN_DENOM)?;

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
                        let amount = get_amount(msg.amount.as_ref(), MAIN_NATIVE_TOKEN_DENOM)?;

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
                        if denom != BTC_NATIVE_TOKEN_DENOM {
                            return Err(Error::App("Unsupported denom for IBC transfer".into()));
                        }

                        let amount = msg.amount.into();

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
                            sender: EdAdapter(msg.sender.into()),
                            receiver: EdAdapter(msg.receiver.into()),
                            timeout_timestamp,
                            memo: msg.memo.try_into()?,
                        };

                        let payer = build_call!(self.ibc_transfer_nbtc(dest, amount));
                        let paid = build_call!(self.app_noop());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgJoinRewardAccounts" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;

                        let dest_addr: Address = msg["dest_address"]
                            .as_str()
                            .ok_or_else(|| Error::App("Invalid destination address".to_string()))?
                            .parse()
                            .map_err(|_| Error::App("Invalid destination address".to_string()))?;

                        let payer = build_call!(self.join_accounts(dest_addr));
                        let paid = build_call!(self.app_noop());

                        Ok(PaidCall { payer, paid })
                    }

                    "nomic/MsgSetRecoveryAddress" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;

                        let recovery_addr: bitcoin::Address = msg["recovery_address"]
                            .as_str()
                            .ok_or_else(|| Error::App("Invalid recovery address".to_string()))?
                            .parse()
                            .map_err(|_| Error::App("Invalid recovery address".to_string()))?;

                        let script =
                            crate::bitcoin::adapter::Adapter::new(recovery_addr.script_pubkey());

                        let funding_amt = MIN_FEE;
                        let payer = build_call!(self.accounts.take_as_funding(funding_amt.into()));
                        let paid = build_call!(self.bitcoin.set_recovery_script(script.clone()));

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
    pub memo: String,
}

#[derive(Encode, Decode, Debug, Clone, Serialize)]
pub enum Dest {
    Address(Address),
    Ibc(IbcDest),
}

impl Dest {
    pub fn to_receiver_addr(&self) -> String {
        match self {
            Dest::Address(addr) => addr.to_string(),
            Dest::Ibc(dest) => dest.receiver.0.to_string(),
        }
    }
}

use orga::ibc::{IbcMessage, PortChannel, RawIbcTx};

#[derive(Clone, Debug, Encode, Decode, Serialize)]
pub struct IbcDest {
    pub source_port: LengthVec<u8, u8>,
    pub source_channel: LengthVec<u8, u8>,
    #[serde(skip)]
    pub receiver: EdAdapter<IbcSigner>,
    #[serde(skip)]
    pub sender: EdAdapter<IbcSigner>,
    pub timeout_timestamp: u64,
    pub memo: LengthVec<u8, u8>,
}

impl IbcDest {
    pub fn transfer(
        &self,
        mut coins: Coin<Nbtc>,
        bitcoin: &mut Bitcoin,
        ibc: &mut Ibc,
    ) -> Result<()> {
        use orga::ibc::ibc_rs::applications::transfer::msgs::transfer::MsgTransfer;

        let fee_amount = ibc_fee(coins.amount)?;
        let fee = coins.take(fee_amount)?;
        bitcoin.reward_pool.give(fee)?;
        let nbtc_amount = coins.amount;

        ibc.transfer_mut()
            .mint_coins_execute(&self.sender_address()?, &coins.into())?;

        let msg_transfer = MsgTransfer {
            port_id_on_a: self.source_port()?,
            chan_id_on_a: self.source_channel()?,
            packet_data: PacketData {
                token: Nbtc::mint(nbtc_amount).into(),
                receiver: self.receiver.0.clone(),
                sender: self.sender.0.clone(),
                memo: self.memo()?,
            },
            timeout_height_on_b: TimeoutHeight::Never,
            timeout_timestamp_on_b: Timestamp::from_nanoseconds(self.timeout_timestamp)
                .map_err(|e| Error::App(e.to_string()))?,
        };
        if let Err(err) = ibc.deliver_message(IbcMessage::Ics20(msg_transfer)) {
            log::debug!("Failed IBC transfer: {}", err);
        }

        Ok(())
    }

    pub fn sender_address(&self) -> Result<Address> {
        self.sender
            .0
            .to_string()
            .parse()
            .map_err(|e: bech32::Error| Error::Coins(e.to_string()))
    }

    pub fn source_channel(&self) -> Result<ChannelId> {
        let channel_id: String = self.source_channel.clone().try_into()?;
        channel_id
            .parse()
            .map_err(|_| Error::Ibc("Invalid channel id".into()))
    }

    pub fn source_port(&self) -> Result<PortId> {
        let port_id: String = self.source_port.clone().try_into()?;
        port_id
            .parse()
            .map_err(|_| Error::Ibc("Invalid port id".into()))
    }

    pub fn memo(&self) -> Result<Memo> {
        let memo: String = self.memo.clone().try_into()?;

        Ok(memo.into())
    }
}

impl Dest {
    pub fn commitment_bytes(&self) -> Result<Vec<u8>> {
        use sha2::Sha256;
        use Dest::*;
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

    pub fn to_output_script(
        &self,
        recovery_scripts: &orga::collections::Map<Address, Adapter<Script>>,
    ) -> Result<Option<Script>> {
        match self {
            Dest::Address(addr) => Ok(recovery_scripts
                .get(*addr)?
                .map(|script| script.clone().into_inner())),
            _ => Ok(None),
        }
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
    fn migrate(src: Store, _dest: Store, bytes: &mut &[u8]) -> Result<Self> {
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

pub fn ibc_fee(amount: Amount) -> Result<Amount> {
    let fee_rate: orga::coins::Decimal = IBC_FEE.to_string().parse().unwrap();
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
