#![allow(clippy::too_many_arguments)]

use crate::airdrop::Airdrop;
use crate::bitcoin::adapter::Adapter;
use crate::bitcoin::{Bitcoin, Nbtc};
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::Transaction;
use orga::call::{BuildCall, FieldCall, MethodCall};
use orga::coins::{Accounts, Address, Amount, Coin, Faucet, Give, Staking, Symbol, Take};
use orga::context::GetContext;
use orga::cosmrs::bank::MsgSend;
use orga::encoding::{Decode, Encode};

use orga::ibc::ibc_rs::applications::transfer::context::TokenTransferExecutionContext;
#[cfg(feature = "testnet")]
use orga::ibc::{Ibc, IbcTx};

use orga::ibc::ibc_rs::Signer as IbcSigner;

use orga::encoding::Adapter as EdAdapter;
use orga::macros::build_call;
use orga::migrate::MigrateFrom;
use orga::orga;
use orga::plugins::sdk_compat::{sdk, sdk::Tx as SdkTx, ConvertSdkTx};
use orga::plugins::{DefaultPlugins, PaidCall, Signer, MIN_FEE};
use orga::upgrade::Upgrade;
use orga::upgrade::Version;
use orga::Error;
use orga::{ibc, prelude::*};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::Debug;

mod migrations;

pub const CHAIN_ID: &str = "nomic-testnet-4d";
pub type AppV0 = DefaultPlugins<Nom, InnerAppTestnetV0>;
pub type App = DefaultPlugins<Nom, InnerAppTestnet>;

#[derive(State, Debug, Clone, Encode, Decode, Default, MigrateFrom, Serialize)]
pub struct Nom(());
impl Symbol for Nom {
    const INDEX: u8 = 69;
}
const DEV_ADDRESS: &str = "nomic14z79y3yrghqx493mwgcj0qd2udy6lm26lmduah";
const STRATEGIC_RESERVE_ADDRESS: &str = "nomic1d5n325zrf4elfu0heqd59gna5j6xyunhev23cj";
const VALIDATOR_BOOTSTRAP_ADDRESS: &str = "nomic1fd9mxxt84lw3jdcsmjh6jy8m6luafhqd8dcqeq";

#[orga(version = 1, channels(Testnet))]
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

    #[orga(version(V1), channel(Testnet))]
    #[call]
    pub ibc: Ibc,

    #[orga(version(V1))]
    upgrade: Upgrade,
}

#[orga(channels(Testnet))]
impl InnerApp {
    #[orga(channel(Testnet))]
    const CONSENSUS_VERSION: u8 = 0;

    #[call]
    pub fn deposit_rewards(&mut self) -> Result<()> {
        self.accounts.give_from_funding_all()?;
        self.bitcoin.accounts.give_from_funding_all()?;
        Ok(())
    }

    #[orga(channel(Testnet))]
    #[call]
    pub fn ibc_deposit_nbtc(&mut self, to: Address, amount: Amount) -> Result<()> {
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

    #[orga(channel(Testnet))]
    #[call]
    pub fn ibc_withdraw_nbtc(&mut self, amount: Amount) -> Result<()> {
        crate::bitcoin::exempt_from_fee()?;

        let signer = self.signer()?;
        let coins: Coin<Nbtc> = amount.into();
        self.ibc.burn_coins_execute(&signer, &coins.into())?;
        self.bitcoin.accounts.deposit(signer, amount.into())?;

        Ok(())
    }

    #[orga(channel(Testnet))]
    #[query]
    pub fn escrowed_nbtc(&self, address: Address) -> Result<Amount> {
        self.ibc.transfer.symbol_balance::<Nbtc>(address)
    }

    #[orga(channel(Testnet))]
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
            DepositCommitment::Ibc(_dest) => {
                todo!()
            }
        }

        Ok(())
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

    #[orga(channels(Testnet))]
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

            Ok(())
        }
    }

    #[orga(channels(Testnet))]
    impl BeginBlock for InnerApp {
        fn begin_block(&mut self, ctx: &BeginBlockCtx) -> Result<()> {
            self.upgrade
                .step(&vec![Self::CONSENSUS_VERSION].try_into().unwrap())?;
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

    #[orga(channels(Testnet))]
    impl EndBlock for InnerApp {
        fn end_block(&mut self, ctx: &EndBlockCtx) -> Result<()> {
            self.staking.end_block(ctx)
        }
    }

    #[orga(channels(Testnet))]
    impl AbciQuery for InnerApp {
        fn abci_query(&self, request: &messages::RequestQuery) -> Result<messages::ResponseQuery> {
            self.ibc.abci_query(request)
        }
    }
}

#[orga(channels(Testnet))]
impl ConvertSdkTx for InnerApp {
    type Output = PaidCall<<Self as Call>::Call>;

    fn convert(&self, sdk_tx: &SdkTx) -> Result<PaidCall<<Self as Call>::Call>> {
        let sender_address = sdk_tx.sender_address()?;
        match sdk_tx {
            SdkTx::Protobuf(tx) => {
                // #[cfg(feature = "testnet")]
                // {
                //     let tx_bytes = sdk_tx.encode()?;
                //     if IbcTx::decode(tx_bytes.as_slice()).is_ok() {
                //         let funding_amt = MIN_FEE;
                //         let funding_call =
                //             AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                //         let funding_call_bytes = funding_call.encode()?;
                //         let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                //         let deliver_msg_call_bytes = [vec![2], tx_bytes].concat();
                //         let paid_call = AppCall::FieldIbc(deliver_msg_call_bytes);
                //         return Ok(PaidCall {
                //             payer: payer_call,
                //             paid: paid_call,
                //         });
                //     }
                // }

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

                                // let funding_call = BitcoinCall::MethodTransfer(to, amount, vec![]);
                                // let funding_call_bytes = funding_call.encode()?;
                                // let payer_call =
                                // AppCall::FieldBitcoin(funding_call_bytes);
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
                        todo!()
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

use orga::ibc::PortChannel;

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
