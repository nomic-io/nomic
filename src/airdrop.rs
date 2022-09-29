use orga::call::Call;
use orga::client::Client;
use orga::coins::{Address, Amount, Coin, Symbol};
use orga::collections::{Map, ChildMut};
use orga::context::GetContext;
use orga::migrate::Migrate;
use orga::plugins::{Signer, Paid};
use orga::query::Query;
use orga::state::State;
use orga::{Error, Result};

use super::app::Nom;

#[derive(State, Query, Call, Client)]
pub struct Airdrop {
    accounts: Map<Address, Account>,
}

impl Airdrop {
    #[query]
    pub fn get(&self, address: Address) -> Result<Option<Account>> {
        Ok(self.accounts.get(address)?.map(|a| a.clone()))
    }

    pub fn signer_acct_mut(&mut self) -> Result<ChildMut<Address, Account>> {
        let signer = self
            .context::<Signer>()
            .ok_or_else(|| Error::Signer("No Signer context available".into()))?
            .signer
            .ok_or_else(|| Error::Coins("Unauthorized account action".into()))?;

        self
            .accounts
            .get_mut(signer)?
            .ok_or_else(|| Error::Coins("No airdrop account for signer".into()))
    }

    fn pay_as_funding(&mut self, amount: u64) -> Result<()> {
        let paid = self
            .context::<Paid>()
            .ok_or_else(|| Error::Coins("No Paid context found".into()))?;

        paid.give::<Nom, _>(amount)
    }

    #[call]
    pub fn claim_airdrop1(&mut self) -> Result<()> {
        let mut acct = self.signer_acct_mut()?;
        let amount = acct.airdrop1.claim()?;
        self.pay_as_funding(amount)?;
        Ok(())
    }

    #[call]
    pub fn claim_btc_deposit(&mut self) -> Result<()> {
        let mut acct = self.signer_acct_mut()?;
        let amount = acct.btc_deposit.claim()?;
        self.pay_as_funding(amount)?;
        Ok(())
    }

    #[call]
    pub fn claim_btc_withdraw(&mut self) -> Result<()> {
        let mut acct = self.signer_acct_mut()?;
        let amount = acct.btc_withdraw.claim()?;
        self.pay_as_funding(amount)?;
        Ok(())
    }

    #[call]
    pub fn claim_ibc_transfer(&mut self) -> Result<()> {
        let mut acct = self.signer_acct_mut()?;
        let amount = acct.ibc_transfer.claim()?;
        self.pay_as_funding(amount)?;
        Ok(())
    }
}

#[cfg(feature = "full")]
impl Migrate<nomicv3::app::Airdrop<nomicv3::app::Nom>> for Airdrop {
    fn migrate(&mut self, legacy: nomicv3::app::Airdrop<nomicv3::app::Nom>) -> Result<()> {
        // self.claimable.migrate(legacy.accounts())
        todo!()
    }
}

#[derive(State, Query, Call, Client, Clone, Debug)]
pub struct Account {
    pub airdrop1: Part,
    pub btc_deposit: Part,
    pub btc_withdraw: Part,
    pub ibc_transfer: Part,
}

#[derive(State, Query, Call, Client, Clone, Debug)]
pub struct Part {
    pub locked: u64,
    pub claimable: u64,
    pub claimed: u64,
}

impl Part {
    pub fn unlock(&mut self) {
        self.claimable += self.locked;
        self.locked = 0;
    }

    pub fn claim(&mut self) -> Result<u64> {
        let amount = self.claimable;
        if amount == 0 {
            return Err(Error::Coins("No balance to claim".to_string()));
        }

        self.claimed += amount;
        self.claimable = 0;
        Ok(amount)
    }
}
