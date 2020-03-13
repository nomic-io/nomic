use nomic_primitives::transaction::Transaction;

#[derive(Clone, Debug)]
pub enum Action {
    Transaction(Transaction),
}
