use orga::prelude::*;

#[derive(State, Debug, Clone)]
pub struct Gucci(());
impl Symbol for Gucci {}

#[derive(State, Call, Query, Client)]
pub struct InnerApp {
    pub accounts: Accounts<Gucci>,
    pub staking: Staking<Gucci>,
}

#[cfg(feature = "full")]
impl InitChain for InnerApp {
    fn init_chain(&mut self, _ctx: &InitChainCtx) -> Result<()> {
        self.staking.set_min_self_delegation(100_000);
        self.staking.set_max_validators(3);
        self.accounts.allow_transfers(true);

        self.accounts.deposit(
            "nomic1ns0gwwx7pp0f3gdhal5t77msvdkj6trgu2mdek"
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
            let divisor: Amount = 100_000.into();
            let reward = (self.staking.staked()? / divisor)?.amount()?;
            self.staking.give(reward.into())?;
        }

        Ok(())
    }
}

#[cfg(feature = "full")]
impl EndBlock for InnerApp {
    fn end_block(&mut self, ctx: &EndBlockCtx) -> Result<()> {
        self.staking.end_block(ctx)
    }
}

pub type App = DefaultPlugins<InnerApp>;
