use nomic_primitives::transaction::Transaction;
use orga::abci::messages::Header;

#[derive(Clone, Debug)]
pub enum Action {
    BeginBlock(Header),
    Transaction(Transaction),
}
