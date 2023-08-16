use crate::incentives::Incentives;

use super::{InnerAppV0, InnerAppV1, InnerAppV2};
use orga::{
    coins::Take,
    migrate::{Migrate, MigrateFrom},
    state::State,
    store::Store,
    upgrade::Upgrade,
    Result,
};

impl MigrateFrom<InnerAppV0> for InnerAppV1 {
    #[allow(unused_mut)]
    fn migrate_from(other: InnerAppV0) -> Result<Self> {
        let mut app = Self {
            accounts: other.accounts,
            staking: other.staking,
            airdrop: other.airdrop,
            community_pool: other.community_pool,
            incentive_pool: other.incentive_pool,
            staking_rewards: other.staking_rewards,
            dev_rewards: other.dev_rewards,
            community_pool_rewards: other.community_pool_rewards,
            incentive_pool_rewards: other.incentive_pool_rewards,
            bitcoin: other.bitcoin,
            reward_timer: other.reward_timer,
            #[cfg(feature = "testnet")]
            ibc: orga::ibc::Ibc::default(),
            upgrade: Upgrade::default(),
        };

        #[cfg(feature = "full")]
        app.airdrop
            .init_from_airdrop2_csv(include_bytes!("../../airdrop2_snapshot.csv"))?;

        Ok(app)
    }
}

impl MigrateFrom<InnerAppV1> for InnerAppV2 {
    fn migrate_from(mut other: InnerAppV1) -> Result<Self> {
        let testnet_incentive_funds = other.incentive_pool.take(1_000_000_000_000)?;
        Ok(Self {
            accounts: other.accounts,
            staking: other.staking,
            airdrop: other.airdrop,
            community_pool: other.community_pool,
            incentive_pool: other.incentive_pool,
            staking_rewards: other.staking_rewards,
            dev_rewards: other.dev_rewards,
            community_pool_rewards: other.community_pool_rewards,
            incentive_pool_rewards: other.incentive_pool_rewards,
            bitcoin: other.bitcoin,
            reward_timer: other.reward_timer,
            #[cfg(feature = "testnet")]
            ibc: other.ibc,
            upgrade: other.upgrade,
            incentives: Incentives::from_csv(
                include_bytes!("../../testnet_incentive_snapshot.csv"),
                testnet_incentive_funds,
            )?,
        })
    }
}
