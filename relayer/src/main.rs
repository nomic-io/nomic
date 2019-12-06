use bitcoin::hashes::sha256d::Hash;
use relayer::relayer::{RelayerEvent, RelayerState, RelayerStateMachine};
use std::{thread, time};

fn main() {
    let mut sm = RelayerStateMachine::new();
    let mut latest_tip: Option<Hash> = None;

    println!("Relayer process started. Watching Bitcoin network for new block headers.");
    loop {
        let event = sm.run();
        if let RelayerEvent::ComputeCommonAncestorSuccess { common_block_hash } = event {
            if Some(common_block_hash) != latest_tip && latest_tip.is_some() {
                println!("New tip hash: {:?}", common_block_hash);
            } else {
                thread::sleep(time::Duration::from_secs(10));
            }
            latest_tip = Some(common_block_hash);
        }
        sm.state = sm.state.next(event);
    }
}
