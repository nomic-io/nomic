pub use bitcoin;
pub use bitcoincore_rpc;

use bitcoin::BlockHeader;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EnrichedHeader {
    pub height: u32,
    pub header: BlockHeader,
}
