use crate::bitcoin::Bitcoin;
use orga::migrate::{exec_migration, Migrate};
use orga::plugins::sdk_compat::{sdk::Tx as SdkTx, ConvertSdkTx};
use orga::prelude::*;
use orga::Error;
use std::convert::TryInto;

pub const CHAIN_ID: &str = "nomic-stakenet-test-2";
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

impl Migrate<nomicv1::app::InnerApp> for InnerApp {
    fn migrate(&mut self, legacy: nomicv1::app::InnerApp) -> Result<()> {
        self.accounts.migrate(legacy.accounts)?;
        self.staking.migrate(legacy.staking)?;
        // TODO: migrate airdrop

        self.community_pool.migrate(legacy.community_pool)?;
        self.incentive_pool.migrate(legacy.incentive_pool)?;

        self.staking_rewards.migrate(legacy.staking_rewards)?;
        self.dev_rewards.migrate(legacy.dev_rewards)?;
        self.community_pool_rewards
            .migrate(legacy.community_pool_rewards)?;
        self.incentive_pool_rewards
            .migrate(legacy.incentive_pool_rewards)?;

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

    fn init_account(&mut self, address: Address, liquid: Amount, staked: Amount) -> Result<Amount> {
        let liquid_capped = Amount::min(liquid, 1_000_000_000.into());
        let staked_capped = Amount::min(staked, 1_000_000_000.into());

        let units = (liquid_capped + staked_capped * Amount::from(4))?;
        let units_per_nom = Decimal::from(20_299325) / Decimal::from(1_000_000);
        let nom_amount = (Decimal::from(units) / units_per_nom)?.amount()?;

        let payout = Coin::mint(nom_amount);
        self.claimable.deposit(address, payout)?;

        Ok(nom_amount)
    }
}

#[cfg(feature = "full")]
impl<S: Symbol> InitChain for Airdrop<S> {
    fn init_chain(&mut self, _ctx: &InitChainCtx) -> Result<()> {
        let target_csv = include_str!("../atom_snapshot.csv");
        let mut rdr = csv::Reader::from_reader(target_csv.as_bytes());
        let snapshot = rdr.records();

        println!("Initializing balances from airdrop snapshot...");

        let mut minted = Amount::from(0);

        for row in snapshot {
            let row = row.map_err(|e| Error::App(e.to_string()))?;

            let (_, address_b32, _) = bech32::decode(&row[0]).unwrap();
            let address_vec: Vec<u8> = bech32::FromBase32::from_base32(&address_b32).unwrap();
            let address_buf: [u8; 20] = address_vec.try_into().unwrap();

            let liquid: u64 = row[1].parse().unwrap();
            let staked: u64 = row[2].parse().unwrap();

            let minted_for_account =
                self.init_account(address_buf.into(), liquid.into(), staked.into())?;
            minted = (minted + minted_for_account)?;
        }

        println!("Total amount minted for airdrop: {} uNOM", minted);

        Ok(())
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

        match msg.type_.as_str() {
            "cosmos-sdk/MsgSend" => {
                let to: Address = msg
                    .value
                    .get("to_address")
                    .ok_or_else(|| Error::App("No to_address in MsgSend".into()))?
                    .as_str()
                    .ok_or_else(|| Error::App("to_address is not a string".into()))?
                    .parse()
                    .map_err(|e| Error::App(format!("Invalid to_address in MsgSend: {}", e)))?;

                let amount = msg
                    .value
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgSend".into()))?
                    .get(0)
                    .ok_or_else(|| Error::App("Empty amount in MsgSend".into()))?;
                let denom = amount
                    .get("denom")
                    .ok_or_else(|| Error::App("No denom in MsgSend amount".into()))?;
                if denom != "unom" {
                    return Err(Error::App(format!(
                        "Invalid denom in MsgSend amount: {}",
                        denom
                    )));
                }
                let amount: u64 = amount
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgSend amount".into()))?
                    .as_str()
                    .ok_or_else(|| Error::App("amount is not a string".into()))?
                    .parse()?;

                let funding_call = AccountCall::MethodTakeAsFunding(MIN_FEE.into(), vec![]);
                let funding_call_bytes = funding_call.encode()?;
                let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                let transfer_call = AccountCall::MethodTransfer(to, amount.into(), vec![]);
                let transfer_call_bytes = transfer_call.encode()?;
                let paid_call = AppCall::FieldAccounts(transfer_call_bytes);

                Ok(PaidCall {
                    payer: payer_call,
                    paid: paid_call,
                })
            }

            "cosmos-sdk/MsgDelegate" => {
                let val_addr: Address = msg
                    .value
                    .get("validator_address")
                    .ok_or_else(|| Error::App("No validator_address in MsgDelegate".into()))?
                    .as_str()
                    .ok_or_else(|| Error::App("validator_address is not a string".into()))?
                    .parse()
                    .map_err(|e| Error::App(format!("Invalid validator_address in MsgS: {}", e)))?;

                let _del_addr: Address = msg
                    .value
                    .get("delegator_address")
                    .ok_or_else(|| Error::App("No delegator_address in MsgDelegate".into()))?
                    .as_str()
                    .ok_or_else(|| Error::App("delegator_address is not a string".into()))?
                    .parse()
                    .map_err(|e| {
                        Error::App(format!("Invalid delegator_address in MsgDelegate: {}", e))
                    })?;

                let amount: u64 = msg
                    .value
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgDelegate".into()))?
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgDelegate amount".into()))?
                    .as_str()
                    .ok_or_else(|| Error::App("amount is not a string".into()))?
                    .parse()?;

                let denom = msg
                    .value
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in Delegate".into()))?
                    .get("denom")
                    .ok_or_else(|| Error::App("No denom in Delegate amount".into()))?;

                if denom != "unom" {
                    return Err(Error::App(format!(
                        "Invalid denom in Delegate amount: {}",
                        denom
                    )));
                }

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
                let val_src_addr: Address = msg
                    .value
                    .get("validator_src_address")
                    .ok_or_else(|| {
                        Error::App("No validator_src_address in MsgBeginRedelegate".into())
                    })?
                    .as_str()
                    .ok_or_else(|| Error::App("validator_src_address is not a string".into()))?
                    .parse()
                    .map_err(|e| {
                        Error::App(format!(
                            "Invalid validator_src_address in MsgBeginRedelegate: {}",
                            e
                        ))
                    })?;

                let val_dst_addr: Address = msg
                    .value
                    .get("validator_dst_address")
                    .ok_or_else(|| {
                        Error::App("No validator_dst_address in MsgBeginRedelegate".into())
                    })?
                    .as_str()
                    .ok_or_else(|| Error::App("validator_dst_address is not a string".into()))?
                    .parse()
                    .map_err(|e| {
                        Error::App(format!(
                            "Invalid validator_dst_address in MsgBeginRedelegate: {}",
                            e
                        ))
                    })?;

                let amount = msg
                    .value
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgBeginRedelegate".into()))?
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgBeginRedelegate amount".into()))?;

                let denom = msg
                    .value
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgBeginRedelegate".into()))?
                    .get("denom")
                    .ok_or_else(|| Error::App("No denom in MsgBeginRedelegate amount".into()))?;

                if denom != "unom" {
                    return Err(Error::App(format!(
                        "Invalid denom in MsgBeginRedelegate amount: {}",
                        denom
                    )));
                }
                let amount: u64 = amount
                    .as_str()
                    .ok_or_else(|| Error::App("amount is not a string".into()))?
                    .parse()?;

                let funding_amt = MIN_FEE;
                let funding_call = AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                let funding_call_bytes = funding_call.encode()?;
                let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                let redelegate_call = StakingCall::MethodRedelegateSelf(
                    val_src_addr,
                    val_dst_addr,
                    amount.into(),
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
                let val_addr: Address = msg
                    .value
                    .get("validator_address")
                    .ok_or_else(|| Error::App("No validator_address in MsgUndelegate".into()))?
                    .as_str()
                    .ok_or_else(|| Error::App("validator_address is not a string".into()))?
                    .parse()
                    .map_err(|e| {
                        Error::App(format!("Invalid validator_address in MsgUndelegate: {}", e))
                    })?;

                let amount = msg
                    .value
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgUndelegate".into()))?
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgUndelegate amount".into()))?;

                let denom = msg
                    .value
                    .get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgUndelegate".into()))?
                    .get("denom")
                    .ok_or_else(|| Error::App("No denom in MsgUndelegate amount".into()))?;

                if denom != "unom" {
                    return Err(Error::App(format!(
                        "Invalid denom in MsgUndelegate amount: {}",
                        denom
                    )));
                }

                let amount: u64 = amount
                    .as_str()
                    .ok_or_else(|| Error::App("amount is not a string".into()))?
                    .parse()?;

                let funding_amt = MIN_FEE;
                let funding_call = AccountCall::MethodTakeAsFunding(funding_amt.into(), vec![]);
                let funding_call_bytes = funding_call.encode()?;
                let payer_call = AppCall::FieldAccounts(funding_call_bytes);

                let undelegate_call =
                    StakingCall::MethodUnbondSelf(val_addr, amount.into(), vec![]);
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
