use crate::incentives::Incentives;

use super::{InnerAppV0, InnerAppV1, InnerAppV2, InnerAppV3, InnerAppV4};
use orga::{
    coins::Take,
    ibc::Ibc,
    migrate::{Migrate, MigrateFrom},
    state::State,
    store::Store,
    upgrade::Upgrade,
    Result,
};

impl MigrateFrom<InnerAppV0> for InnerAppV1 {
    fn migrate_from(_other: InnerAppV0) -> Result<Self> {
        unreachable!()
    }
}

impl MigrateFrom<InnerAppV1> for InnerAppV2 {
    fn migrate_from(_other: InnerAppV1) -> Result<Self> {
        unreachable!()
    }
}

impl MigrateFrom<InnerAppV2> for InnerAppV3 {
    fn migrate_from(other: InnerAppV2) -> Result<Self> {
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
            incentives: other.incentives,
            #[cfg(feature = "testnet")]
            cosmos: Default::default(),
        })
    }
}

impl MigrateFrom<InnerAppV3> for InnerAppV4 {
    #[allow(unused_mut)]
    fn migrate_from(mut other: InnerAppV3) -> Result<Self> {
        #[cfg(feature = "testnet")]
        {
            other.upgrade.activation_delay_seconds = 60 * 20;
        }

        #[cfg(not(feature = "testnet"))]
        {
            other.bitcoin.config.min_confirmations = 5;
        }

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
            upgrade: other.upgrade,
            incentives: other.incentives,

            #[cfg(feature = "testnet")]
            ibc: other.ibc,
            #[cfg(not(feature = "testnet"))]
            ibc: Ibc::default(),

            #[cfg(feature = "testnet")]
            cosmos: other.cosmos,
            #[cfg(not(feature = "testnet"))]
            cosmos: Default::default(),
        })
    }
}
