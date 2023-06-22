use super::{InnerAppTestnetV0, InnerAppTestnetV1};
use orga::{
    migrate::{MigrateFrom, MigrateInto},
    upgrade::Upgrade,
};

impl MigrateFrom<InnerAppTestnetV0> for InnerAppTestnetV1 {
    #[allow(unused_mut)]
    fn migrate_from(mut other: InnerAppTestnetV0) -> orga::Result<Self> {
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
            ibc: orga::ibc::Ibc::default(),
            upgrade: Upgrade::default(),
        };

        app.airdrop
            .init_from_airdrop2_csv(include_bytes!("../../airdrop2_snapshot.csv"))?;

        Ok(app)
    }
}
