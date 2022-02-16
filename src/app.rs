use orga::prelude::*;
use orga::plugins::sdk_compat::{sdk::{self, Tx as SdkTx}, ConvertSdkTx};
use orga::Error;
use std::convert::TryInto;
use std::time::Duration;
use std::ops::{Deref, DerefMut};

pub const CHAIN_ID: &str = "stakenet";
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
}

impl InnerApp {
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
            total_coins: 47_250_000_000_000.into(),
            period_decay: two_thirds,
            start_seconds: genesis_time + day,
        })?;

        self.dev_rewards.configure(FaucetOptions {
            num_periods: 9,
            period_length: year,
            total_coins: 47_250_000_000_000.into(),
            period_decay: two_thirds,
            start_seconds: genesis_time + day,
        })?;

        self.community_pool_rewards.configure(FaucetOptions {
            num_periods: 9,
            period_length: year,
            total_coins: 9_450_000_000_000.into(),
            period_decay: two_thirds,
            start_seconds: genesis_time + day,
        })?;

        self.incentive_pool_rewards.configure(FaucetOptions {
            num_periods: 9,
            period_length: year,
            total_coins: 85_050_000_000_000.into(),
            period_decay: two_thirds,
            start_seconds: genesis_time + day,
        })?;

        Ok(())
    }
}

#[cfg(feature = "full")]
mod abci {
    use super::*;

    impl InitChain for InnerApp {
        fn init_chain(&mut self, ctx: &InitChainCtx) -> Result<()> {
            self.staking.set_min_self_delegation(100_000);
            self.staking.set_max_validators(100);
            self.accounts.allow_transfers(true);

            self.configure_faucets()?;

            self.accounts.init_chain(ctx)?;
            self.staking.init_chain(ctx)?;
            self.atom_airdrop.init_chain(ctx)?;

            // 100 tokens of strategic reserve are paid to the validator bootstrap account,
            // a hot wallet to be sent to validators so they can declare themselves
            let sr_funds = Nom::mint(10_499_900_000_000);
            let vb_funds = Nom::mint(100_000_000);

            let sr_address = STRATEGIC_RESERVE_ADDRESS.parse().unwrap();
            self.accounts.deposit(sr_address, sr_funds)?;
            self.accounts.add_transfer_exception(sr_address)?;

            let vb_address = VALIDATOR_BOOTSTRAP_ADDRESS.parse().unwrap();
            self.accounts.deposit(vb_address, vb_funds)?;
            self.accounts.add_transfer_exception(vb_address)?;

            let dev_address = "nomic1ud2dhntvve2quwt6txh7te0x5985j8ek6r4t2y".parse().unwrap();
            self.accounts.deposit(dev_address, Nom::mint(1_000_000_000))?;

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

        match msg.type_.as_str() {
            "cosmos-sdk/MsgSend" => {
                type AppCall = <InnerApp as Call>::Call;
                type AccountCall = <Accounts<Nom> as Call>::Call;

                let to: Address = msg.value.get("to_address")
                    .ok_or_else(|| Error::App("No to_address in MsgSend".into()))?
                    .as_str()
                    .ok_or_else(|| Error::App("to_address is not a string".into()))?
                    .parse()
                    .map_err(|e| Error::App(format!("Invalid to_address in MsgSend: {}", e)))?;

                let amount = msg.value.get("amount")
                    .ok_or_else(|| Error::App("No amount in MsgSend".into()))?
                    .get(0)
                    .ok_or_else(|| Error::App("Empty amount in MsgSend".into()))?;
                let denom = amount.get("denom")
                    .ok_or_else(|| Error::App("No denom in MsgSend amount".into()))?;
                if denom != "unom" {
                    return Err(Error::App(format!("Invalid denom in MsgSend amount: {}", denom)));
                }
                let amount: u64 = amount.get("amount")
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

                Ok(PaidCall { payer: payer_call, paid: paid_call })
            }
            _ => Err(Error::App("Unsupported message type".into())),
        }
    }
}
