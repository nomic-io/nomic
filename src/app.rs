use crate::bitcoin::Bitcoin;
#[cfg(feature = "full")]
use orga::migrate::{exec_migration, Migrate};
use orga::plugins::sdk_compat::{sdk::Tx as SdkTx, ConvertSdkTx};
use orga::prelude::*;
use orga::Error;

pub const CHAIN_ID: &str = "nomic-practicenet-3-post";
pub type App = DefaultPlugins<Nom, InnerApp, CHAIN_ID>;

#[derive(State, Debug, Clone)]
pub struct Nom(());
impl Symbol for Nom {}

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
}

#[cfg(feature = "full")]
impl Migrate<nomicv1::app::InnerApp> for InnerApp {
    fn migrate(&mut self, legacy: nomicv1::app::InnerApp) -> Result<()> {
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

        Ok(())
    }
}

#[cfg(feature = "full")]
mod abci {
    use super::*;

    impl InitChain for InnerApp {
        fn init_chain(&mut self, _ctx: &InitChainCtx) -> Result<()> {
            self.staking.max_validators = 100;
            self.staking.max_offline_blocks = 5_000;
            self.staking.downtime_jail_seconds = 60 * 30; // 30 minutes
            self.staking.slash_fraction_downtime = (Amount::new(1) / Amount::new(20))?;
            self.staking.slash_fraction_double_sign = (Amount::new(1) / Amount::new(4))?;
            self.staking.min_self_delegation_min = 1;

            let old_home_path = nomicv1::orga::abci::Node::<()>::home(nomicv1::app::CHAIN_ID);
            exec_migration(self, old_home_path.join("merk"), &[0, 1, 0])?;

            let sr_address = STRATEGIC_RESERVE_ADDRESS.parse().unwrap();
            self.accounts.add_transfer_exception(sr_address)?;

            let vb_address = VALIDATOR_BOOTSTRAP_ADDRESS.parse().unwrap();
            self.accounts.add_transfer_exception(vb_address)?;

            Ok(())
        }
    }

    impl BeginBlock for InnerApp {
        fn begin_block(&mut self, ctx: &BeginBlockCtx) -> Result<()> {
            self.staking.begin_block(ctx)?;

            if self.staking.staked()? > 0 {
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
impl Migrate<nomicv1::app::Airdrop<nomicv1::app::Nom>> for Airdrop<Nom> {
    fn migrate(&mut self, legacy: nomicv1::app::Airdrop<nomicv1::app::Nom>) -> Result<()> {
        self.claimable.migrate(legacy.accounts())
    }
}

impl ConvertSdkTx for InnerApp {
    type Output = PaidCall<<InnerApp as Call>::Call>;

    fn convert(&self, sdk_tx: &SdkTx) -> Result<PaidCall<<InnerApp as Call>::Call>> {
        if sdk_tx.msg.len() != 1 {
            return Err(Error::App("Invalid number of messages".into()));
        }
        let msg = &sdk_tx.msg[0];

        type AppCall = <InnerApp as Call>::Call;
        type AccountCall = <Accounts<Nom> as Call>::Call;
        type StakingCall = <Staking<Nom> as Call>::Call;

        let get_addr = |name: &str| -> Result<Address> {
            msg.value
                .get(name)
                .ok_or_else(|| Error::App(format!("No field named '{}'", name)))?
                .as_str()
                .ok_or_else(|| Error::App(format!("{} is not a string", name)))?
                .parse()
                .map_err(|e| Error::App(format!("Invalid {}: {}", name, e)))
        };

        let get_amount = |expected_denom| -> Result<Amount> {
            let amount = msg
                .value
                .get("amount")
                .ok_or_else(|| Error::App("No amount".into()))?
                .get(0)
                .ok_or_else(|| Error::App("Empty amount".into()))?;

            let denom = amount
                .get("denom")
                .ok_or_else(|| Error::App("No denom in amount".into()))?;
            if denom != expected_denom {
                return Err(Error::App(format!("Invalid denom in amount: {}", denom)));
            }

            let amount: u64 = amount
                .get("amount")
                .ok_or_else(|| Error::App("No 'amount' field in amount".into()))?
                .as_str()
                .ok_or_else(|| Error::App("amount is not a string".into()))?
                .parse()?;

            Ok(Amount::new(amount))
        };

        match msg.type_.as_str() {
            "cosmos-sdk/MsgSend" => {
                let to = get_addr("to_address")?;
                let amount = get_amount("unom")?;

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

            "cosmos-sdk/MsgDelegate" => {
                let val_addr = get_addr("validator_adddress")?;
                let _del_addr = get_addr("delegator_address")?;

                let amount: u64 = get_amount("unom")?.into();

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
                let val_src_addr = get_addr("validator_src_address")?;
                let val_dst_addr = get_addr("validator_dst_address")?;

                let amount = get_amount("unom")?;

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
                let val_addr = get_addr("validator_address")?;
                let amount = get_amount("unom")?;

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

            _ => Err(Error::App("Unsupported message type".into())),
        }
    }
}
