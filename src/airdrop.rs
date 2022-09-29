use orga::call::Call;
use orga::client::Client;
use orga::coins::{Address, Amount, Coin, Symbol};
use orga::collections::{ChildMut, Map};
use orga::context::GetContext;
use orga::migrate::Migrate;
use orga::plugins::{Paid, Signer};
use orga::query::Query;
use orga::state::State;
use orga::{Error, Result};

use super::app::Nom;

const MAX_STAKED: u64 = 10_000_000_000;
const AIRDROP_II_TOTAL: u64 = 3_500_000_000_000;

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

        self.accounts
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

    pub fn init_from_csv(&mut self, data: &[u8]) -> Result<()> {
        let recipients = Self::get_recipients_from_csv(data);
        
        let len = recipients[0].1.len();
        let mut totals = vec![0u64; len];

        for (_, networks) in recipients.iter() {
            for (i, (staked, count)) in networks.iter().enumerate() {
                let score = Self::score(*staked, *count);
                totals[i] += score;
            }
        }

        let precision = 1_000_000_000;
        let unom_per_network = AIRDROP_II_TOTAL / len as u64;
        let unom_per_score: Vec<_> = totals.iter().map(|n| {
            unom_per_network * precision / n
        }).collect();

        dbg!(&unom_per_score);

        let total_airdropped: u64 = recipients.iter().map(|(addr, networks)| {
            let unom: u64 = networks.iter().enumerate().map(|(i, (staked, count))| {
                let score = Self::score(*staked, *count);
                let unom_per_score = unom_per_score[i];
                score * unom_per_score / precision
            }).sum();

            self.airdrop_to(*addr, unom)?;

            Ok(unom)
        }).sum::<Result<_>>()?;

        dbg!(AIRDROP_II_TOTAL);
        dbg!(total_airdropped);

        Ok(())
    }

    fn airdrop_to(&mut self, addr: Address, unom: u64) -> Result<()> {
        let mut acct = Account::default();
        acct.btc_deposit.locked = unom / 3;
        acct.btc_withdraw.locked = unom / 3;
        acct.ibc_transfer.locked = unom / 3;

        self.accounts.insert(addr, acct.into())
    }

    fn score(staked: u64, count: u64) -> u64 {
        staked.min(MAX_STAKED) * count
    }

    fn get_recipients_from_csv(data: &[u8]) -> Vec<(Address, Vec<(u64, u64)>)> {
        let mut reader = csv::Reader::from_reader(data);

        reader.records().map(|row| {
            let row = row.unwrap();

            let addr: Address = row[0].parse().unwrap();
            let values: Vec<_> = row
                .into_iter()
                .skip(1)
                .map(|s| -> u64 { s.parse().unwrap() })
                .collect();
            let pairs: Vec<_> = values.chunks_exact(2).map(|arr| (arr[0], arr[1])).collect();

            (addr, pairs)
        }).collect()
    }
}

#[cfg(feature = "full")]
impl Migrate<nomicv3::app::Airdrop<nomicv3::app::Nom>> for Airdrop {
    fn migrate(&mut self, legacy: nomicv3::app::Airdrop<nomicv3::app::Nom>) -> Result<()> {
        // self.claimable.migrate(legacy.accounts())
        todo!()
    }
}

#[derive(State, Query, Call, Client, Clone, Debug, Default)]
pub struct Account {
    pub airdrop1: Part,
    pub btc_deposit: Part,
    pub btc_withdraw: Part,
    pub ibc_transfer: Part,
}

#[derive(State, Query, Call, Client, Clone, Debug, Default)]
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
