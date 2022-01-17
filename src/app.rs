#[cfg(full)]
use crate::bitcoin::header_queue::HeaderQueue;
use orga::prelude::*;

#[derive(State, Debug, Clone)]
pub struct Gucci(());
impl Symbol for Gucci {}

#[derive(State, Call, Query, Client)]
pub struct InnerApp {
    pub accounts: Accounts<Gucci>,
    pub staking: Staking<Gucci>,
    // pub btc_headers: HeaderQueue,
}

#[cfg(feature = "full")]
impl InitChain for InnerApp {
    fn init_chain(&mut self, _ctx: &InitChainCtx) -> Result<()> {
        self.accounts.deposit(
            "nomic18m73q0542w8vlt0s23sazy62hq6tfnl9pjpslh"
                .parse()
                .unwrap(),
            100_000_000_000.into(),
        )?;
        Ok(())
    }
}

#[cfg(feature = "full")]
impl BeginBlock for InnerApp {
    fn begin_block(&mut self, ctx: &BeginBlockCtx) -> Result<()> {
        self.staking.begin_block(ctx)?;

        if self.staking.staked()? > 0 {
            let divisor: Amount = 50_000.into();
            let reward = (self.staking.staked()? / divisor)?.amount()?;
            self.staking.give(reward.into())?;
        }

        Ok(())
    }
}

pub type App = DefaultPlugins<InnerApp>;
