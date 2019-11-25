use nomic_primitives::transaction::Transaction;

#[derive(Debug)]
pub enum Action {
    Transaction(Transaction),
}
