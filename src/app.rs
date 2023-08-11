use crate::bitcoin::Bitcoin;

#[cfg(feature = "full")]
use orga::plugins::sdk_compat::{sdk, sdk::Tx as SdkTx, ConvertSdkTx};
use orga::prelude::*;
use orga::Error;
use serde::{Deserialize, Serialize};

pub const CHAIN_ID: &str = "nomic-internalnet-6";
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
    pub accounts: Accounts<Nom>,
    pub staking: Staking<Nom>,
    pub atom_airdrop: Airdrop<Nom>,

    community_pool: Coin<Nom>,
    incentive_pool: Coin<Nom>,

    staking_rewards: Faucet<Nom>,
    dev_rewards: Faucet<Nom>,
    community_pool_rewards: Faucet<Nom>,
    incentive_pool_rewards: Faucet<Nom>,

    pub bitcoin: Bitcoin,
    pub reward_timer: RewardTimer,
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
}

#[cfg(feature = "full")]
mod abci {
    use std::time::Duration;

    use super::*;

    impl InitChain for InnerApp {
        fn init_chain(&mut self, _ctx: &InitChainCtx) -> Result<()> {
            self.staking.max_validators = 100;
            self.staking.max_offline_blocks = 20_000;
            self.staking.downtime_jail_seconds = 60 * 30; // 30 minutes
            self.staking.slash_fraction_downtime = (Amount::new(1) / Amount::new(1000))?;
            self.staking.slash_fraction_double_sign = (Amount::new(1) / Amount::new(20))?;
            self.staking.min_self_delegation_min = 0;

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
                start_seconds: genesis_time,
            })?;

            self.dev_rewards.configure(FaucetOptions {
                num_periods: 9,
                period_length: year,
                total_coins: 49_875_000_000_000.into(),
                period_decay: two_thirds,
                start_seconds: genesis_time,
            })?;

            self.community_pool_rewards.configure(FaucetOptions {
                num_periods: 9,
                period_length: year,
                total_coins: 9_975_000_000_000.into(),
                period_decay: two_thirds,
                start_seconds: genesis_time,
            })?;

            self.incentive_pool_rewards.configure(FaucetOptions {
                num_periods: 9,
                period_length: year,
                total_coins: 89_775_000_000_000.into(),
                period_decay: two_thirds,
                start_seconds: genesis_time,
            })?;

            self.accounts.allow_transfers(true);
            self.bitcoin.accounts.allow_transfers(true);

            let sr_address = STRATEGIC_RESERVE_ADDRESS.parse().unwrap();
            self.accounts.add_transfer_exception(sr_address)?;

            let vb_address = VALIDATOR_BOOTSTRAP_ADDRESS.parse().unwrap();
            self.accounts.add_transfer_exception(vb_address)?;

            let addresses = [
                "nomic10s0k46fppc9wheenkq9r8pgdv7zm6ewyfsv53n",
                "nomic1rk07saqmvfle50h4h9hul00g67xzrcc5ytfxjm",
                "nomic1v2etn3ttwvra63m7esgmpqd3n2tf62nu5xgj5l",
                "nomic124j0ky0luh9jzqh9w2dk77cze9v0ckdupk50ny",
                "nomic1lrjlnj228jqr0m9ucd637knw974gga98eezpxm",
                "nomic1nx0kr57khqxvn4my79vqrmm3u0057f856fn55k",
                "nomic1yza655dh6mszhq9pq6geuv97ujuherlhsjn28z",
                "nomic1uhnm7ymaqz9dkjf28l377uy0kv5vgdw36kev0f",
                "nomic1e9ypzs3qgrkwzpstvw7z4ag96qzv9qtdhvrcyj",
                "nomic10lggm4znqtt50tgtjfdgz4qkmpe2s92dn6qzfd",
                "nomic1eteh34vue8ze54atdsdnjedun8gx9f47kwz3r4",
                "nomic14dq60x66p45yx2wxufy8m2plwpur8yvr09uhrx",
                "nomic1krucz9xtj3z3drjgje6mkrwetw635w2zazkja2",
            ];
            for addr in addresses {
                self.atom_airdrop
                    .accounts_mut()
                    .deposit(addr.parse().unwrap(), Coin::mint(1_000_000_000_000))?;
                self.accounts
                    .deposit(addr.parse().unwrap(), Coin::mint(1_000_000_000_000))?;
            }

            self.incentive_pool.give(Coin::mint(2_000_000_000_000))?;

            Ok(())
        }
    }

    impl BeginBlock for InnerApp {
        fn begin_block(&mut self, ctx: &BeginBlockCtx) -> Result<()> {
            self.staking.begin_block(ctx)?;

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
}

#[derive(State, Query, Call, Client)]
pub struct Airdrop<S: Symbol> {
    claimable: Accounts<S>,
}

impl<S: Symbol> Airdrop<S> {
    pub fn accounts_mut(&mut self) -> &mut Accounts<S> {
        &mut self.claimable
    }

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

impl ConvertSdkTx for InnerApp {
    type Output = PaidCall<<InnerApp as Call>::Call>;

    fn convert(&self, sdk_tx: &SdkTx) -> Result<PaidCall<<InnerApp as Call>::Call>> {
        let sender_address = sdk_tx.sender_address()?;

        if sdk_tx.msg.len() != 1 {
            return Err(Error::App("Invalid number of messages".into()));
        }
        let msg = &sdk_tx.msg[0];

        type AppCall = <InnerApp as Call>::Call;
        type AccountCall = <Accounts<Nom> as Call>::Call;
        type StakingCall = <Staking<Nom> as Call>::Call;
        type AirdropCall = <Airdrop<Nom> as Call>::Call;
        type BitcoinCall = <Bitcoin as Call>::Call;

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

                        let funding_call = AccountCall::MethodTakeAsFunding(MIN_FEE.into(), vec![]);
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
                let msg: sdk::MsgDelegate = serde_json::value::from_value(msg.value.clone())
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
                let funding_call = AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
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
                let msg: sdk::MsgBeginRedelegate = serde_json::value::from_value(msg.value.clone())
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
                let funding_call = AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                let funding_call_bytes = funding_call.encode()?;
                let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                let redelegate_call =
                    StakingCall::MethodRedelegateSelf(val_src_addr, val_dst_addr, amount, vec![]);
                let redelegate_call_bytes = redelegate_call.encode()?;
                let paid_call = AppCall::FieldStaking(redelegate_call_bytes);

                Ok(PaidCall {
                    payer: payer_call,
                    paid: paid_call,
                })
            }

            "cosmos-sdk/MsgUndelegate" => {
                let msg: sdk::MsgUndelegate = serde_json::value::from_value(msg.value.clone())
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
                let funding_call = AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                let funding_call_bytes = funding_call.encode()?;
                let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                let undelegate_call = StakingCall::MethodUnbondSelf(val_addr, amount, vec![]);
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

                let dest_addr: bitcoin::Address = msg
                    .dst_address
                    .parse()
                    .map_err(|e: bitcoin::util::address::Error| Error::App(e.to_string()))?;
                let dest_script = crate::bitcoin::adapter::Adapter::new(dest_addr.script_pubkey());

                let amount: u64 = msg
                    .amount
                    .parse()
                    .map_err(|e: std::num::ParseIntError| Error::App(e.to_string()))?;

                let funding_amt = MIN_FEE;
                let funding_call = AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                let funding_call_bytes = funding_call.encode()?;
                let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                let withdraw_call = BitcoinCall::MethodWithdraw(dest_script, amount.into(), vec![]);
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

#[derive(Serialize, Deserialize)]
pub struct MsgWithdraw {
    pub amount: String,
    pub dst_address: String,
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
