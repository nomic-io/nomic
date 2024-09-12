use crate::{
    bitcoin::{
        adapter::Adapter,
        header_queue::{WorkHeader, WrappedHeader},
    },
    incentives::Incentives,
};

use super::{InnerAppV4, InnerAppV5};
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

impl MigrateFrom<InnerAppV4> for InnerAppV5 {
    #[allow(unused_mut)]
    fn migrate_from(mut other: InnerAppV4) -> Result<Self> {
        unreachable!()
    }
}
