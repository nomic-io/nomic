use crate::incentives::Incentives;

use super::{InnerAppV0, InnerAppV1, InnerAppV2};
use orga::{
    coins::Take,
    migrate::{MigrateFrom, MigrateInto},
    upgrade::Upgrade,
};

impl MigrateFrom<InnerAppV0> for InnerAppV1 {
    #[allow(unused_mut)]
    fn migrate_from(mut other: InnerAppV0) -> orga::Result<Self> {
        let mut app = Self {
            accounts: other.accounts.migrate_into()?,
            staking: other.staking.migrate_into()?,
            airdrop: other.airdrop,
            community_pool: other.community_pool.migrate_into()?,
            incentive_pool: other.incentive_pool.migrate_into()?,
            staking_rewards: other.staking_rewards.migrate_into()?,
            dev_rewards: other.dev_rewards.migrate_into()?,
            community_pool_rewards: other.community_pool_rewards.migrate_into()?,
            incentive_pool_rewards: other.incentive_pool_rewards.migrate_into()?,
            bitcoin: other.bitcoin.migrate_into()?,
            reward_timer: other.reward_timer.migrate_into()?,
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
    fn migrate_from(mut other: InnerAppV1) -> orga::Result<Self> {
        let testnet_incentive_funds = other.incentive_pool.take(1_000_000)?;

        let app = Self {
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
            ibc: other.ibc.migrate_into()?,
            upgrade: other.upgrade.migrate_into()?,
            incentives: Incentives::from_csv(
                include_bytes!("../../testnet_incentive_snapshot.csv"),
                testnet_incentive_funds,
            )?,
        };

        Ok(app)
    }
}
