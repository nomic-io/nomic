use crate::bitcoin::header_queue::HeaderQueue;
use orga::prelude::*;

#[derive(State, Call, Query, Client)]
pub struct App {
  pub btc_headers: HeaderQueue,
}
