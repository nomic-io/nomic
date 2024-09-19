//! This module creates incentive accounts, allowing eligible users to claim
//! tokens based on participation in the Nomic ecosystem.

use crate::airdrop::Part;
use crate::{
    app::Nom,
    error::{Error, Result},
};
use orga::migrate::MigrateFrom;
use orga::{
    coins::{Address, Amount, Coin},
    collections::{ChildMut, Map},
    context::GetContext,
    orga,
    plugins::{Paid, Signer},
    Error as OrgaError, Result as OrgaResult,
};

#[orga]
pub struct Incentives {
    accounts: Map<Address, Account>,
}

#[orga(version = 1)]
pub struct Account {
    pub testnet_participation: Part,
}

impl Clone for AccountV1 {
    fn clone(&self) -> Self {
        Self {
            testnet_participation: self.testnet_participation.clone(),
        }
    }
}

impl MigrateFrom<AccountV0> for AccountV1 {
    fn migrate_from(_old: AccountV0) -> orga::Result<Self> {
        unreachable!()
    }
}

impl Account {
    #[orga(version(V1))]
    pub fn is_empty(&self) -> bool {
        self.testnet_participation.is_empty()
    }
}

#[orga]
impl Incentives {
    pub fn from_csv(data: &[u8], funds: Coin<Nom>) -> Result<Self> {
        let mut accounts = Map::new();
        let mut rdr = csv::Reader::from_reader(data);
        let total_score = rdr.records().try_fold(0, |mut sum, row| {
            let row = row?;
            let mut maybe_increment = |v| {
                if v == "true" {
                    sum += 1;
                }
            };
            maybe_increment(&row[1]);
            maybe_increment(&row[2]);
            maybe_increment(&row[3]);
            Ok::<_, Error>(sum)
        })?;

        let rate: u64 = (funds.amount / Amount::new(total_score))
            .result()?
            .amount()?
            .into();

        let mut rdr = csv::Reader::from_reader(data);
        for res in rdr.records() {
            let row = res?;
            let address: Address = row[0].parse().unwrap();
            let mut claimable: u64 = 0;
            let mut maybe_increment = |v| {
                if v == "true" {
                    claimable += rate;
                }
            };
            maybe_increment(&row[1]);
            maybe_increment(&row[2]);
            maybe_increment(&row[3]);

            if claimable > 0 {
                let account = Account {
                    testnet_participation: Part {
                        locked: 0,
                        claimable,
                        claimed: 0,
                    },
                };
                accounts.insert(address, account)?;
            }
        }

        Ok(Incentives { accounts })
    }

    #[query]
    pub fn get(&self, address: Address) -> Result<Option<Account>> {
        Ok(self.accounts.get(address)?.map(|a| a.clone()))
    }

    pub fn signer_acct_mut(&mut self) -> OrgaResult<ChildMut<Address, Account>> {
        let signer = self
            .context::<Signer>()
            .ok_or_else(|| OrgaError::Signer("No Signer context available".into()))?
            .signer
            .ok_or_else(|| OrgaError::Coins("Unauthorized account action".into()))?;

        self.accounts
            .get_mut(signer)?
            .ok_or_else(|| OrgaError::App("No incentive account for signer".into()))
    }

    fn pay_as_funding(&mut self, amount: u64) -> Result<()> {
        let paid = self
            .context::<Paid>()
            .ok_or_else(|| OrgaError::Coins("No Paid context found".into()))?;

        Ok(paid.give::<Nom, _>(amount)?)
    }

    #[call]
    pub fn claim_testnet_participation_incentives(&mut self) -> OrgaResult<()> {
        let mut acct = self.signer_acct_mut()?;
        let amount = acct.testnet_participation.claim()?;
        self.pay_as_funding(amount)?;
        Ok(())
    }

    #[orga(version(V1))]
    pub fn join_accounts(&mut self, dest_addr: Address) -> OrgaResult<u64> {
        let mut acct = match self.signer_acct_mut() {
            Ok(acct) => acct,
            Err(OrgaError::App(_)) => return Ok(0),
            Err(e) => return Err(e),
        };

        if acct.is_empty() {
            return Ok(0);
        }

        let src = acct.clone();
        *acct = Account::default();

        let mut dest = self.accounts.entry(dest_addr)?.or_default()?;

        let add_part = |dest: &mut Part, src: Part| {
            if dest.claimable > 0 || dest.claimed > 0 {
                dest.claimable += src.locked;
            } else {
                dest.locked += src.locked;
            }
            dest.claimable += src.claimable;
            dest.claimed += src.claimed;

            src.total()
        };

        let testnet_participation =
            add_part(&mut dest.testnet_participation, src.testnet_participation);

        Ok(testnet_participation)
    }
}
