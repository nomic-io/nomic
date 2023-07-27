use crate::airdrop::Part;
use crate::{
    app::Nom,
    error::{Error, Result},
};
use orga::{
    coins::{Address, Amount, Coin, Take},
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

#[orga]
#[derive(Clone, PartialEq, Eq)]
pub struct Account {
    testnet_participation: Part,
}

impl Account {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[orga]
impl Incentives {
    pub fn from_csv(data: &[u8], mut funds: Coin<Nom>) -> Result<Self> {
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

        let rate = (funds.amount / Amount::new(total_score))
            .result()?
            .amount()?;

        let mut rdr = csv::Reader::from_reader(data);
        for res in rdr.records() {
            let row = res?;
            let address: Address = row[0].parse().unwrap();
            let mut account = Account::default();
            let mut maybe_increment = |v| {
                if v == "true" {
                    account.testnet_participation = Part {
                        locked: 0,
                        claimable: funds.take(rate)?.amount.into(),
                        claimed: 0,
                    }
                }
                Ok::<_, Error>(())
            };
            maybe_increment(&row[1])?;
            maybe_increment(&row[2])?;
            maybe_increment(&row[3])?;
            accounts.insert(address, account)?;
        }

        Ok(Incentives { accounts })
    }

    pub fn signer_acct_mut(&mut self) -> OrgaResult<ChildMut<Address, Account>> {
        let signer = self
            .context::<Signer>()
            .ok_or_else(|| OrgaError::Signer("No Signer context available".into()))?
            .signer
            .ok_or_else(|| OrgaError::Coins("Unauthorized account action".into()))?;

        self.accounts
            .get_mut(signer)?
            .ok_or_else(|| OrgaError::Coins("No airdrop account for signer".into()))
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

    pub fn join_accounts(&mut self, dest_addr: Address) -> OrgaResult<()> {
        let mut acct = self.signer_acct_mut()?;
        if acct.is_empty() {
            return Err(OrgaError::App("Account has no airdrop balance".to_string()));
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
        };

        add_part(&mut dest.testnet_participation, src.testnet_participation);

        Ok(())
    }
}
