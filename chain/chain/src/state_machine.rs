use crate::Action;
use orga::{StateMachine, Store};

/// Main entrypoint to the core bitcoin peg state machine.
///
/// This function implements the conventions set by Orga, though this may change as our core
/// framework design settles.
pub fn run(store: &mut dyn Store, action: Action) {
    println!("Got action: {:?}", action);
    store.put(b"hello".to_vec(), b"world".to_vec());
}
