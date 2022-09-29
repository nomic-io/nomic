use std::convert::TryInto;

use crate::bitcoin::adapter::Adapter;
use crate::bitcoin::Bitcoin;

use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::Transaction;
use orga::cosmrs::bank::MsgSend;
use orga::ibc::ibc_rs::core::ics04_channel::timeout::TimeoutHeight;
use orga::ibc::ibc_rs::core::ics24_host::identifier::{ChannelId, PortId};
use orga::ibc::ibc_rs::timestamp::Timestamp;
#[cfg(feature = "feat-ibc")]
use orga::ibc::{Ibc, IbcTx};
#[cfg(feature = "full")]
use orga::migrate::{exec_migration, Migrate};
use orga::plugins::sdk_compat::{sdk, sdk::Tx as SdkTx, ConvertSdkTx};
use orga::Error;
use orga::{ibc, prelude::*};
use serde::{Deserialize, Serialize};

pub const CHAIN_ID: &str = "nomic-testnet-4b-0";
pub type App = DefaultPlugins<Nom, InnerApp, CHAIN_ID>;

#[derive(State, Debug, Clone)]
pub struct Nom(());
impl Symbol for Nom {
    const INDEX: u8 = 69;
}
const DEV_ADDRESS: &str = "nomic14z79y3yrghqx493mwgcj0qd2udy6lm26lmduah";
const STRATEGIC_RESERVE_ADDRESS: &str = "nomic1d5n325zrf4elfu0heqd59gna5j6xyunhev23cj";
const VALIDATOR_BOOTSTRAP_ADDRESS: &str = "nomic1fd9mxxt84lw3jdcsmjh6jy8m6luafhqd8dcqeq";

#[derive(State, Call, Query, Client)]
pub struct InnerApp {
    #[call]
    pub accounts: Accounts<Nom>,
    #[call]
    pub staking: Staking<Nom>,
    #[call]
    pub atom_airdrop: Airdrop<Nom>,

    community_pool: Coin<Nom>,
    incentive_pool: Coin<Nom>,

    staking_rewards: Faucet<Nom>,
    dev_rewards: Faucet<Nom>,
    community_pool_rewards: Faucet<Nom>,
    incentive_pool_rewards: Faucet<Nom>,

    #[call]
    pub bitcoin: Bitcoin,
    pub reward_timer: RewardTimer,

    #[call]
    pub ibc: Ibc,
}

impl InnerApp {
    #[call]
    pub fn noop(&mut self) {}

    #[call]
    pub fn deposit_rewards(&mut self) -> Result<()> {
        self.accounts.give_from_funding_all()?;
        self.bitcoin.accounts.give_from_funding_all()?;
        Ok(())
    }

    #[call]
    pub fn ibc_deposit_nbtc(&mut self, to: Address, amount: Amount) -> crate::error::Result<()> {
        let signer = self.signer()?;
        crate::bitcoin::exempt_from_fee()?;
        let _coins = self.bitcoin.accounts.withdraw(signer, amount)?;
        self.ibc
            .bank_mut()
            .mint(to, after_ibc_fee(amount)?, "usat".parse()?)?;

        Ok(())
    }

    #[call]
    pub fn ibc_withdraw_nbtc(&mut self, amount: Amount) -> crate::error::Result<()> {
        let signer = self.signer()?;
        crate::bitcoin::exempt_from_fee()?;
        self.ibc.bank_mut().burn(signer, amount, "usat".parse()?)?;
        self.bitcoin.accounts.deposit(signer, amount.into())?;

        Ok(())
    }

    #[query]
    pub fn escrowed_nbtc(&self, address: Address) -> Result<Amount> {
        Ok(*self
            .ibc
            .bank()
            .balances
            .get_or_default("usat".parse()?)?
            .get_or_default(address)?)
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
    ) -> crate::error::Result<()> {
        let nbtc = self.bitcoin.relay_deposit(
            btc_tx,
            btc_height,
            btc_proof,
            btc_vout,
            sigset_index,
            dest.commitment_bytes()?.as_slice(),
        )?;
        match dest {
            DepositCommitment::Address(addr) => self.bitcoin.accounts.deposit(addr, nbtc.into())?,
            DepositCommitment::Ibc(dest) => {
                use orga::ibc::ibc_rs::applications::transfer::msgs::transfer::MsgTransfer;
                use orga::ibc::proto::cosmos::base::v1beta1::Coin;

                let IbcDepositCommitment {
                    source_port,
                    source_channel,
                    receiver,
                    sender,
                    timeout_timestamp,
                } = dest;
                let msg_transfer = MsgTransfer {
                    sender: sender.clone().into_inner(),
                    source_port: source_port.into_inner(),
                    source_channel: source_channel.into_inner(),
                    token: Coin {
                        amount: after_ibc_fee(nbtc)?.to_string(),
                        denom: "usat".to_string(),
                    },
                    receiver: receiver.into_inner(),
                    timeout_height: TimeoutHeight::Never,
                    timeout_timestamp: Timestamp::from_nanoseconds(timeout_timestamp)
                        .map_err(|e| Error::App(e.to_string()))?,
                };
                self.ibc.bank_mut().mint(
                    sender
                        .into_inner()
                        .try_into()
                        .map_err(|_| Error::App("Invalid sender address".into()))?,
                    after_ibc_fee(nbtc)?,
                    "usat".parse()?,
                )?;
                self.ibc.raw_transfer(msg_transfer)?
            }
        }

        Ok(())
    }

    fn signer(&mut self) -> Result<Address> {
        self.context::<Signer>()
            .ok_or_else(|| Error::Signer("No Signer context available".into()))?
            .signer
            .ok_or_else(|| Error::Coins("Unauthorized account action".into()))
    }
}

#[cfg(feature = "full")]
impl Migrate<nomicv3::app::InnerApp> for InnerApp {
    fn migrate(&mut self, legacy: nomicv3::app::InnerApp) -> Result<()> {
        self.community_pool.migrate(legacy.community_pool())?;
        self.incentive_pool.migrate(legacy.incentive_pool())?;

        self.staking_rewards.migrate(legacy.staking_rewards())?;
        self.dev_rewards.migrate(legacy.dev_rewards())?;
        self.community_pool_rewards
            .migrate(legacy.community_pool_rewards())?;
        self.incentive_pool_rewards
            .migrate(legacy.incentive_pool_rewards())?;

        self.accounts.migrate(legacy.accounts)?;
        self.staking.migrate(legacy.staking)?;
        self.atom_airdrop.migrate(legacy.atom_airdrop)?;
        self.bitcoin.migrate(legacy.bitcoin)?;

        Ok(())
    }
}

#[cfg(feature = "full")]
mod abci {

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

            let old_home_path = nomicv3::orga::abci::Node::<()>::home(nomicv3::app::CHAIN_ID);
            exec_migration(self, old_home_path.join("merk"), &[0, 1, 0])?;

            self.accounts.allow_transfers(true);
            self.bitcoin.accounts.allow_transfers(true);

            self.accounts.add_transfer_exception(sr_address)?;

            let vb_address = VALIDATOR_BOOTSTRAP_ADDRESS.parse().unwrap();
            self.accounts.add_transfer_exception(vb_address)?;

            Ok(())
        }
    }

    impl BeginBlock for InnerApp {
        fn begin_block(&mut self, ctx: &BeginBlockCtx) -> Result<()> {
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

#[derive(State, Query, Call, Client)]
pub struct Airdrop<S: Symbol> {
    claimable: Accounts<S>,
}

impl<S: Symbol> Airdrop<S> {
    #[query]
    pub fn balance(&self, address: Address) -> Result<Option<Amount>> {
        let exists = self.claimable.exists(address)?;
        if !exists {
            return Ok(None);
        }

        let balance = self.claimable.balance(address)?;
        Ok(Some(balance))
    }

    #[call]
    pub fn claim(&mut self) -> Result<()> {
        let signer = self
            .context::<Signer>()
            .ok_or_else(|| Error::Signer("No Signer context available".into()))?
            .signer
            .ok_or_else(|| Error::Coins("Unauthorized account action".into()))?;

        let amount = self.claimable.balance(signer)?;
        self.claimable.take_as_funding(amount)
    }
}

#[cfg(feature = "full")]
impl Migrate<nomicv3::app::Airdrop<nomicv3::app::Nom>> for Airdrop<Nom> {
    fn migrate(&mut self, legacy: nomicv3::app::Airdrop<nomicv3::app::Nom>) -> Result<()> {
        self.claimable.migrate(legacy.accounts())
    }
}

impl ConvertSdkTx for InnerApp {
    type Output = PaidCall<<InnerApp as Call>::Call>;

    fn convert(&self, sdk_tx: &SdkTx) -> Result<PaidCall<<InnerApp as Call>::Call>> {
        let sender_address = sdk_tx.sender_address()?;
        type AppCall = <InnerApp as Call>::Call;
        type AccountCall = <Accounts<Nom> as Call>::Call;
        type StakingCall = <Staking<Nom> as Call>::Call;
        type AirdropCall = <Airdrop<Nom> as Call>::Call;
        type BitcoinCall = <Bitcoin as Call>::Call;
        match sdk_tx {
            SdkTx::Protobuf(tx) => {
                let tx_bytes = sdk_tx.encode()?;
                if IbcTx::decode(tx_bytes.as_slice()).is_ok() {
                    let funding_amt = MIN_FEE;
                    let funding_call = AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                    let funding_call_bytes = funding_call.encode()?;
                    let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                    let deliver_msg_call_bytes = [vec![2], tx_bytes].concat();
                    let paid_call = AppCall::FieldIbc(deliver_msg_call_bytes);
                    return Ok(PaidCall {
                        payer: payer_call,
                        paid: paid_call,
                    });
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
                    // msg.

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

                            let funding_call =
                                AccountCall::MethodTakeAsFunding(MIN_FEE.into(), vec![]);
                            let funding_call_bytes = funding_call.encode()?;
                            let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                            let transfer_call =
                                AccountCall::MethodTransfer(to, amount.into(), vec![]);
                            let transfer_call_bytes = transfer_call.encode()?;
                            let paid_call = AppCall::FieldAccounts(transfer_call_bytes);

                            return Ok(PaidCall {
                                payer: payer_call,
                                paid: paid_call,
                            });
                        }
                        "usat" => {
                            let amount: u64 = msg.amount[0].amount.to_string().parse().unwrap();

                            let funding_call =
                                BitcoinCall::MethodTransfer(to, amount.into(), vec![]);
                            let funding_call_bytes = funding_call.encode()?;
                            let payer_call = AppCall::FieldBitcoin(funding_call_bytes);

                            return Ok(PaidCall {
                                payer: payer_call,
                                paid: AppCall::MethodNoop(vec![]),
                            });
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

                                let funding_call =
                                    AccountCall::MethodTakeAsFunding(MIN_FEE.into(), vec![]);
                                let funding_call_bytes = funding_call.encode()?;
                                let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                                let transfer_call = AccountCall::MethodTransfer(to, amount, vec![]);
                                let transfer_call_bytes = transfer_call.encode()?;
                                let paid_call = AppCall::FieldAccounts(transfer_call_bytes);

                                Ok(PaidCall {
                                    payer: payer_call,
                                    paid: paid_call,
                                })
                            }
                            "usat" => {
                                let amount = get_amount(msg.amount.first(), "usat")?;

                                let funding_call = BitcoinCall::MethodTransfer(to, amount, vec![]);
                                let funding_call_bytes = funding_call.encode()?;
                                let payer_call = AppCall::FieldBitcoin(funding_call_bytes);

                                Ok(PaidCall {
                                    payer: payer_call,
                                    paid: AppCall::MethodNoop(vec![]),
                                })
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
                        let funding_call =
                            AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                        let funding_call_bytes = funding_call.encode()?;
                        let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                        let delegate_call =
                            StakingCall::MethodDelegateFromSelf(val_addr, amount.into(), vec![]);
                        let delegate_call_bytes = delegate_call.encode()?;
                        let paid_call = AppCall::FieldStaking(delegate_call_bytes);

                        Ok(PaidCall {
                            payer: payer_call,
                            paid: paid_call,
                        })
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
                        let funding_call =
                            AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                        let funding_call_bytes = funding_call.encode()?;
                        let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                        let redelegate_call = StakingCall::MethodRedelegateSelf(
                            val_src_addr,
                            val_dst_addr,
                            amount,
                            vec![],
                        );
                        let redelegate_call_bytes = redelegate_call.encode()?;
                        let paid_call = AppCall::FieldStaking(redelegate_call_bytes);

                        Ok(PaidCall {
                            payer: payer_call,
                            paid: paid_call,
                        })
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
                        let funding_call =
                            AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                        let funding_call_bytes = funding_call.encode()?;
                        let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                        let undelegate_call =
                            StakingCall::MethodUnbondSelf(val_addr, amount, vec![]);
                        let undelegate_call_bytes = undelegate_call.encode()?;
                        let paid_call = AppCall::FieldStaking(undelegate_call_bytes);

                        Ok(PaidCall {
                            payer: payer_call,
                            paid: paid_call,
                        })
                    }

                    "nomic/MsgClaimRewards" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }

                        let claim_call = StakingCall::MethodClaimAll(vec![]);
                        let claim_call_bytes = claim_call.encode()?;
                        let payer_call = AppCall::FieldStaking(claim_call_bytes);

                        let paid_call = AppCall::MethodDepositRewards(vec![]);

                        Ok(PaidCall {
                            payer: payer_call,
                            paid: paid_call,
                        })
                    }

                    "nomic/MsgClaimAirdrop" => {
                        let msg = msg
                            .value
                            .as_object()
                            .ok_or_else(|| Error::App("Invalid message value".to_string()))?;
                        if !msg.is_empty() {
                            return Err(Error::App("Message should be empty".to_string()));
                        }

                        let claim_call = AirdropCall::MethodClaim(vec![]);
                        let claim_call_bytes = claim_call.encode()?;
                        let payer_call = AppCall::FieldAtomAirdrop(claim_call_bytes);

                        let give_call = AccountCall::MethodGiveFromFundingAll(vec![]);
                        let give_call_bytes = give_call.encode()?;
                        let paid_call = AppCall::FieldAccounts(give_call_bytes);

                        Ok(PaidCall {
                            payer: payer_call,
                            paid: paid_call,
                        })
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
                        let funding_call =
                            AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                        let funding_call_bytes = funding_call.encode()?;
                        let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                        let withdraw_call =
                            BitcoinCall::MethodWithdraw(dest_script, amount.into(), vec![]);
                        let withdraw_call_bytes = withdraw_call.encode()?;
                        let paid_call = AppCall::FieldBitcoin(withdraw_call_bytes);

                        Ok(PaidCall {
                            payer: payer_call,
                            paid: paid_call,
                        })
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

use ibc::encoding::Adapter as IbcAdapter;
use ibc::ibc_rs::signer::Signer as IbcSigner;

#[derive(Encode, Decode, Debug, Clone)]
pub enum DepositCommitment {
    Address(Address),
    Ibc(IbcDepositCommitment),
}

#[derive(Encode, Decode, Clone, Debug)]
pub struct IbcDepositCommitment {
    pub source_port: IbcAdapter<PortId>,
    pub source_channel: IbcAdapter<ChannelId>,
    pub receiver: IbcAdapter<IbcSigner>,
    pub sender: IbcAdapter<IbcSigner>,
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

pub fn after_ibc_fee(amount: Amount) -> Result<Amount> {
    let fee_rate: orga::coins::Decimal = "0.015".parse().unwrap();
    (amount - amount * fee_rate)?.amount()
}

const REWARD_TIMER_PERIOD: i64 = 120;

#[derive(State, Call, Query, Client)]
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
