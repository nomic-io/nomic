use crate::bitcoin::header_queue::HeaderQueue;
use orga::prelude::*;

#[derive(State, Debug, Clone)]
pub struct Gucci(());
impl Symbol for Gucci {}

#[derive(State, Call, Query, Client)]
pub struct InnerApp {
    pub accounts: Accounts<Gucci>,
    pub staking: Staking<Gucci>,
    pub btc_headers: HeaderQueue,
}

impl InitChain for InnerApp {
    fn init_chain(&mut self, _ctx: &InitChainCtx) -> Result<()> {
        self.accounts.deposit(
            "nomic1cg4t0gpmgn944jpa0dlxa9ke7hz94vajk0qkkasdwhp7e074jx2qktweh2"
                .parse()
                .unwrap(),
            100_000_000_000.into(),
        )?;
        self.accounts.deposit(
            "nomic1lwgt239mwclgepyuwdpe2qqf6nalxdt3pj0teh6l0fdrd2ssl74qvww96r"
                .parse()
                .unwrap(),
            100_000_000_000.into(),
        )?;
        self.accounts.deposit(
            "nomic1gzw7mjms49mpaccemvl60awdpe8prta48947tx2cvy5lymwcaets96gm4h"
                .parse()
                .unwrap(),
            100_000_000_000.into(),
        )?;
        Ok(())
    }
}

impl BeginBlock for InnerApp {
    fn begin_block(&mut self, ctx: &BeginBlockCtx) -> Result<()> {
        self.staking.begin_block(ctx)?;

        if self.staking.staked() > 0 {
            let divisor: Amount = 50_000.into();
            let reward = (self.staking.staked() / divisor)?.amount()?;
            self.staking.give(reward.into())?;
        }

        Ok(())
    }
}

pub type App = DefaultPlugins<InnerApp>;
