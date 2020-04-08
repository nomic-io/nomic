use crate::Result;
use orga::Store;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct Account {
    pub nonce: u64,
    pub balance: u64,
}


fn store_key(address: &[u8]) -> Vec<u8> {
    [b"accounts/", address].concat()
}

impl Account {
    pub fn get(store: &mut dyn Store, address: &[u8]) -> Result<Option<Account>> {
        let account_key = store_key(address);
        let maybe_account = store
            .get(account_key.as_slice())?
            .map(|account_bytes| bincode::deserialize(account_bytes.as_slice()))
            .transpose()?;
        Ok(maybe_account)
    }

    pub fn set(store: &mut dyn Store, address: &[u8], account: Account) -> Result<()> {
        let account_key = store_key(address);
        let account_bytes = bincode::serialize(&account)?;
        store.put(account_key, account_bytes)
    }
}
