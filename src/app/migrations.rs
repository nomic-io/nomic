use super::{InnerAppV0, InnerAppV1};
use orga::{
    ibc::Ibc,
    migrate::{MigrateFrom, MigrateInto},
    upgrade::Upgrade,
};

impl MigrateFrom<InnerAppV0> for InnerAppV1 {
    fn migrate_from(mut other: InnerAppV0) -> orga::Result<Self> {
        Ok(Self {
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
            ibc: Ibc::default(),
            upgrade: Upgrade::default(),
        })
    }
}
