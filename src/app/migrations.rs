use crate::{
    bitcoin::{
        adapter::Adapter,
        header_queue::{WorkHeader, WrappedHeader},
    },
    incentives::Incentives,
};

use super::{InnerAppV5, InnerAppV6};
use bitcoin::{
    util::{uint::Uint256, BitArray},
    BlockHeader,
};
use orga::{
    coins::Take,
    ibc::Ibc,
    migrate::{Migrate, MigrateFrom},
    state::State,
    store::Store,
    upgrade::Upgrade,
    Result,
};

impl MigrateFrom<InnerAppV5> for InnerAppV6 {
    #[allow(unused_mut)]
    fn migrate_from(mut other: InnerAppV5) -> Result<Self> {
        #[cfg(not(feature = "testnet"))]
        {
            other.bitcoin.checkpoints.config.max_age = 60 * 60 * 24 * 30 * 12;
            other.bitcoin.headers.config.max_length = 52_560;

            // remove headers and revert to checkpoint so we can regain history which was
            // pruned
            other
                .bitcoin
                .headers
                .deque
                .retain_unordered(|_| Ok(false))?;
            let checkpoint_json = include_str!("../bitcoin/checkpoint.json");
            let header: (u32, BlockHeader) = serde_json::from_str(checkpoint_json)?;
            let wrapped_header = WrappedHeader::new(Adapter::new(header.1), header.0);
            let work_header = WorkHeader::new(wrapped_header.clone(), wrapped_header.work());
            other.bitcoin.headers.current_work = Adapter::new(work_header.work());
            other.bitcoin.headers.deque.push_back(work_header)?;

            // backfill checkpoint history
            use bitcoin::hashes::hex::FromHex;
            let scripts = include_str!("../../stakenet_reserve_scripts.csv")
                .lines()
                .map(|line| {
                    let mut parts = line.split(',');
                    parts.next().unwrap();
                    parts.next().unwrap()
                })
                .map(|script_hex| bitcoin::Script::from_hex(script_hex).unwrap());
            other.bitcoin.checkpoints.backfill(
                todo!(),
                scripts,
                other.bitcoin.checkpoints.config.sigset_threshold,
            )?;
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
            ibc: other.ibc,
            cosmos: other.cosmos,
            #[cfg(feature = "ethereum")]
            ethereum: Default::default(), // TODO
        })
    }
}
