#[cfg(feature = "babylon")]
use crate::babylon::Babylon;
#[cfg(feature = "ethereum")]
use crate::ethereum::{bytes32, Connection, Ethereum, Network};
use crate::{
    app::{Dest, IbcDest, Identity},
    bitcoin::{
        adapter::Adapter,
        header_queue::{WorkHeader, WrappedHeader},
        Nbtc,
    },
    incentives::Incentives,
};

use super::{InnerAppV5, InnerAppV6, InnerAppV7, InnerAppV8, InnerAppV9};
use bitcoin::{
    util::{uint::Uint256, BitArray},
    BlockHeader,
};
use orga::{
    coins::{Address, Coin, Take},
    collections::Map,
    ibc::{
        ibc_rs::{
            core::host::types::identifiers::{ChannelId, PortId},
            cosmos_host::utils::cosmos_adr028_escrow_address,
        },
        Ibc,
    },
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
            #[cfg(all(feature = "ethereum", feature = "testnet"))]
            ethereum: Default::default(),
        })
    }
}

impl MigrateFrom<InnerAppV6> for InnerAppV7 {
    fn migrate_from(mut other: InnerAppV6) -> Result<Self> {
        other
            .ibc
            .update_client_from_header(0, 1, include_str!("./kujira-header.json"))?;

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
            #[cfg(all(feature = "ethereum", feature = "testnet"))]
            ethereum: Default::default(),
            #[cfg(all(feature = "babylon", feature = "testnet"))]
            babylon: Default::default(),
            #[cfg(all(feature = "frost", feature = "testnet"))]
            frost: Default::default(),
        })
    }
}

impl MigrateFrom<InnerAppV7> for InnerAppV8 {
    fn migrate_from(other: InnerAppV7) -> Result<Self> {
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
            #[cfg(all(feature = "ethereum", feature = "testnet"))]
            ethereum: other.ethereum,
            #[cfg(all(feature = "ethereum", not(feature = "testnet")))]
            ethereum: Default::default(),
            #[cfg(all(feature = "babylon", feature = "testnet"))]
            babylon: other.babylon,
            #[cfg(all(feature = "babylon", not(feature = "testnet")))]
            babylon: Default::default(),
            #[cfg(all(feature = "frost", feature = "testnet"))]
            frost: other.frost,
            #[cfg(all(feature = "frost", not(feature = "testnet")))]
            frost: Default::default(),
            #[cfg(feature = "frost")]
            aux_frost: Default::default(),
        })
    }
}

impl MigrateFrom<InnerAppV8> for InnerAppV9 {
    fn migrate_from(mut other: InnerAppV8) -> Result<Self> {
        // Re-trigger nBTC transfer to Osmosis which failed in Osmosis transaction
        // 32F54466B740ACE357378E628C1EA6B590ACBDD9E7B261AE022865DC11281103.
        #[cfg(not(feature = "testnet"))]
        {
            use orga::ibc::ibc_rs::apps::transfer::context::TokenTransferExecutionContext;

            let usat_amount = 199_993_033_000_000;
            let coins = Coin::<Nbtc>::mint(usat_amount);
            let escrow_address = cosmos_adr028_escrow_address(
                &PortId::new("transfer".to_string()).unwrap(),
                &ChannelId::new(1),
            );
            let bytes: [u8; 20] = escrow_address.try_into().unwrap();
            other.ibc.transfer_mut().burn_coins_execute(
                &bytes.into(),
                &coins.into(),
                &"".parse().unwrap(),
            )?;

            let coins = Coin::<Nbtc>::mint(usat_amount);
            let sender: Address = "nomic163gdzl33kjdxac6h6clt827fczjc456f4g5vf9"
                .parse()
                .unwrap();

            let dest = Dest::Ibc {
                data: IbcDest {
                    source_port: "transfer".try_into().unwrap(),
                    source_channel: "channel-1".try_into().unwrap(),
                    receiver: "osmo1vkdakqqg5htq5c3wy2kj2geq536q665xdexrtjuwqckpads2c2nsvhhcyv".try_into().unwrap(),
                    sender: sender.to_string().try_into().unwrap(),
                    timeout_timestamp: 1738793046000000000, // 2025-02-05
                    memo: "{\"wasm\":{\"contract\":\"osmo1vkdakqqg5htq5c3wy2kj2geq536q665xdexrtjuwqckpads2c2nsvhhcyv\",\"msg\":{\"swap_and_action\":{\"user_swap\":{\"swap_exact_asset_in\":{\"swap_venue_name\":\"osmosis-poolmanager\",\"operations\":[{\"denom_in\":\"ibc/75345531D87BD90BF108BE7240BD721CB2CB0A1F16D4EBA71B09EC3C43E15C8F\",\"denom_out\":\"factory/osmo1z6r6qdknhgsc0zeracktgpcxf43j6sekq07nw8sxduc9lg0qjjlqfu25e3/alloyed/allBTC\",\"pool\":\"1868\"}]}},\"timeout_timestamp\":1738793046000000000,\"min_asset\":{\"native\":{\"denom\":\"factory/osmo1z6r6qdknhgsc0zeracktgpcxf43j6sekq07nw8sxduc9lg0qjjlqfu25e3/alloyed/allBTC\",\"amount\":\"1\"}},\"post_swap_action\":{\"transfer\":{\"to_address\":\"osmo163gdzl33kjdxac6h6clt827fczjc456fpt5xva\"}},\"affiliates\":[]}}}}".try_into().unwrap(),
                },
            };

            other
                .bitcoin
                .insert_pending(dest, coins, Identity::NativeAccount { address: sender })
                .unwrap();
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
            ethereum: other.ethereum,
            #[cfg(feature = "babylon")]
            babylon: other.babylon,
            #[cfg(feature = "frost")]
            frost: other.frost,
            #[cfg(feature = "frost")]
            aux_frost: other.aux_frost,
        })
    }
}
