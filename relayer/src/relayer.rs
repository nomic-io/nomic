enum RelayerState {
    ScanningBitcoin,
    Failure,
}

enum RelayerEvent {
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

struct RelayerStateMachine {
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
