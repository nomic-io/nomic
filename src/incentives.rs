use orga::{
    coins::{Address, Amount, Coin, Give, Take},
    collections::Map,
    orga,
};

use crate::{
    app::Nom,
    error::{Error, Result},
};

#[orga]
pub struct Incentives {
    accounts: Map<Address, Account>,
}

#[orga]
pub struct Account {
    testnet_participation: Coin<Nom>,
}

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
                    account.testnet_participation.give(funds.take(rate)?)?;
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
}
