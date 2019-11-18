use nomic_primitives::transaction::Transaction;

#[derive(Debug)]
pub enum Action {
    Foo,
    Transaction(Transaction),
}
