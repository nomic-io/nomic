use crate::{
    bitcoin::{
        adapter::Adapter,
        header_queue::{WorkHeader, WrappedHeader},
    },
    incentives::Incentives,
};

use super::{InnerAppV0, InnerAppV1, InnerAppV2, InnerAppV3, InnerAppV4, InnerAppV5};
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
        unreachable!()
    }
}

impl MigrateFrom<InnerAppV3> for InnerAppV4 {
    #[allow(unused_mut)]
    fn migrate_from(mut other: InnerAppV3) -> Result<Self> {
        unreachable!()
    }
}

impl MigrateFrom<InnerAppV4> for InnerAppV5 {
    #[allow(unused_mut)]
    fn migrate_from(mut other: InnerAppV4) -> Result<Self> {
        unreachable!()
    }
}
