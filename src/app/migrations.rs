#[cfg(feature = "babylon")]
use crate::babylon::Babylon;
#[cfg(feature = "ethereum")]
use crate::ethereum::{bytes32, Connection, Ethereum, Network};
use crate::{
    bitcoin::{
        adapter::Adapter,
        header_queue::{WorkHeader, WrappedHeader},
    },
    incentives::Incentives,
};

use super::{InnerAppV5, InnerAppV6, InnerAppV7};
use bitcoin::{
    util::{uint::Uint256, BitArray},
    BlockHeader,
};
use orga::{
    coins::Take,
    collections::Map,
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
                5276,
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

impl MigrateFrom<InnerAppV6> for InnerAppV7 {
    fn migrate_from(other: InnerAppV6) -> Result<Self> {
        #[cfg(all(feature = "testnet", feature = "ethereum"))]
        let mut ethereum = Ethereum::default();

        #[cfg(all(feature = "testnet", feature = "ethereum"))]
        {
            let mut sigset = other.bitcoin.checkpoints.get(0)?.sigset.clone();
            sigset.normalize_vp(u32::MAX as u64);

            // Sepolia (existing)
            {
                let mut connections = Map::default();
                connections.insert(other.ethereum.bridge_contract, other.ethereum)?;
                ethereum.networks.insert(
                    11155111,
                    Network {
                        id: 11155111,
                        connections,
                    },
                )?;
            }

            // Holesky
            {
                let bridge_contract =
                    alloy_core::primitives::address!("936366c13b43Ab6eC8f70A69038E9187fED0Cd1e")
                        .0
                         .0
                        .into();
                let token_contract =
                    alloy_core::primitives::address!("54360db096a2cb43b411f89a584da69a7bac0663")
                        .0
                         .0
                        .into();
                let mut connections = Map::default();
                connections.insert(
                    bridge_contract,
                    Connection::new(17000, bridge_contract, token_contract, sigset.clone()),
                )?;
                ethereum.networks.insert(
                    17000,
                    Network {
                        id: 17000,
                        connections,
                    },
                )?;
            }

            // Berachain
            {
                let bridge_contract =
                    alloy_core::primitives::address!("ea55b1E6df415b96C194146abCcE85e6f811CAb7")
                        .0
                         .0
                        .into();
                let token_contract =
                    alloy_core::primitives::address!("45a1947cb7315ce9c569b011a6dee4f67813bb75")
                        .0
                         .0
                        .into();
                let mut connections = Map::default();
                connections.insert(
                    bridge_contract,
                    Connection::new(80084, bridge_contract, token_contract, sigset.clone()),
                )?;
                ethereum.networks.insert(
                    80084,
                    Network {
                        id: 80084,
                        connections,
                    },
                )?;
            }
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
            #[cfg(feature = "babylon")]
            babylon: Default::default(),
            #[cfg(feature = "frost")]
            frost: Default::default(),
            #[cfg(feature = "ethereum")]
            ethereum,
        })
    }
}
