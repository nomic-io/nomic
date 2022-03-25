use orga::prelude::*;
use orga::Error;
use std::convert::TryInto;
use std::time::Duration;

pub const CHAIN_ID: &str = "nomic-practicenet-4-pre";
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

    pub fn community_pool(&self) -> Coin<Nom> {
        self.community_pool.amount.into()
    }

    pub fn incentive_pool(&self) -> Coin<Nom> {
        self.incentive_pool.amount.into()
    }

    pub fn staking_rewards(&self) -> Faucet<Nom> {
        self.staking_rewards.clone()
    }

    pub fn dev_rewards(&self) -> Faucet<Nom> {
        self.dev_rewards.clone()
    }

    pub fn community_pool_rewards(&self) -> Faucet<Nom> {
        self.community_pool_rewards.clone()
    }

    pub fn incentive_pool_rewards(&self) -> Faucet<Nom> {
        self.incentive_pool_rewards.clone()
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

            Ok(())
        }
    }

    impl BeginBlock for InnerApp {
        fn begin_block(&mut self, ctx: &BeginBlockCtx) -> Result<()> {
            if ctx.height == 1800 {
                let _ = self.staking.slash(
                    "nomic197hzw237p7hd6ru9gz328uh74yc52qt8zprlya"
                        .parse()
                        .unwrap(),
                    0,
                )?;
            }
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

    pub fn accounts(self) -> Accounts<S> {
        self.claimable
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
