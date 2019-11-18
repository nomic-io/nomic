use orga::{StateMachine, Store};

/// Main entrypoint to the core bitcoin peg state machine.
///
/// This function implements the conventions set by Orga, though this may change as our core
/// framework design settles.
pub fn run(store: &mut dyn Store, action: Action) {}

pub enum Action {}
