use crate::incentives::Incentives;

use super::{InnerAppV0, InnerAppV1, InnerAppV2};
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
