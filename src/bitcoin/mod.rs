use orga::client::Client;
use orga::call::Call;
use orga::query::Query;
use orga::state::State;

pub mod adapter;
pub mod header_queue;
pub mod relayer;
pub mod threshold_sig;

#[derive(State, Call, Query, Client)]
pub struct Bitcoin {
    pub headers: header_queue::HeaderQueue,
}
