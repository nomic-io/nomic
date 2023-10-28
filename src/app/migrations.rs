use crate::{bitcoin::checkpoint::BatchType, incentives::Incentives};

use super::{InnerAppV0, InnerAppV1, InnerAppV2, InnerAppV3, InnerAppV4, InnerAppV5};
use orga::{
    coins::Take,
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
    fn migrate_from(mut other: InnerAppV3) -> Result<Self> {
        #[cfg(feature = "testnet")]
        {
            other.upgrade.activation_delay_seconds = 60 * 20;
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
            ibc: other.ibc,
            upgrade: other.upgrade,
            incentives: other.incentives,
            cosmos: other.cosmos,
        })
    }
}

impl MigrateFrom<InnerAppV4> for InnerAppV5 {
    fn migrate_from(mut other: InnerAppV4) -> Result<Self> {
        #[cfg(feature = "testnet")]
        {
            other.bitcoin.checkpoints.rewind(11445)?;
            assert_eq!(
                other
                    .bitcoin
                    .checkpoints
                    .building()?
                    .batches
                    .get(BatchType::Checkpoint as u64)?
                    .unwrap()
                    .front()?
                    .unwrap()
                    .input
                    .front()?
                    .unwrap()
                    .script_pubkey
                    .clone()
                    .into_inner(),
                other
                    .bitcoin
                    .checkpoints
                    .get(other.bitcoin.checkpoints.index - 1)?
                    .batches
                    .get(BatchType::Checkpoint as u64)?
                    .unwrap()
                    .front()?
                    .unwrap()
                    .output
                    .front()?
                    .unwrap()
                    .script_pubkey
                    .clone()
            );
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
            ibc: other.ibc,
            upgrade: other.upgrade,
            incentives: other.incentives,
            cosmos: other.cosmos,
        })
    }
}
