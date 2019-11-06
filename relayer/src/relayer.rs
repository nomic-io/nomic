use nomic_primitives::transaction::Transaction;

#[derive(Debug)]
pub enum RelayerState {
    ScanningBitcoin,
    Failure,
}

#[derive(Debug)]
pub enum RelayerEvent {
    NewHeader,
}

impl RelayerState {
    pub fn next(self, event: RelayerEvent) -> Self {
        use self::RelayerEvent::*;
        use self::RelayerState::*;
        match (self, event) {
            (s, e) => Failure,
        }
    }
}

pub struct RelayerStateMachine {
    pub state: RelayerState,
}

impl RelayerStateMachine {
    pub fn new() -> Self {
        RelayerStateMachine {
            state: RelayerState::ScanningBitcoin,
        }
    }

    pub fn run(&mut self) -> RelayerEvent {
        match &mut self.state {
            _ => RelayerEvent::NewHeader,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn run_relayer_state_machine() {
        let mut sm = RelayerStateMachine::new();
        let event = sm.run();

        println!("got an event: {:?}", event);
    }
}
