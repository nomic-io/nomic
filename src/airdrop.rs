use orga::coins::{Address, Amount};
use orga::collections::{ChildMut, Map};
use orga::context::GetContext;
use orga::orga;
use orga::plugins::{Paid, Signer};
use orga::prelude::{Decimal, MIN_FEE};
use orga::{Error, Result};
use split_iter::Splittable;

use super::app::Nom;

const MAX_STAKED: u64 = 1_000_000_000;
const AIRDROP_II_TOTAL: u64 = 3_000_000_000_000;
#[cfg(feature = "stakenet")]
const AIRDROP_II_TESTNET_PARTICIPATION_TOTAL: u64 = 500_000_000_000;

#[orga]
pub struct Airdrop {
    accounts: Map<Address, Account>,
}

type Recipients = Vec<(Address, Vec<(u64, u64)>, Vec<bool>)>;

impl Airdrop {
    #[query]
    pub fn get(&self, address: Address) -> Result<Option<Account>> {
        Ok(self.accounts.get(address)?.map(|a| a.clone()))
    }

    pub fn get_mut(&mut self, address: Address) -> Result<Option<ChildMut<Address, Account>>> {
        self.accounts.get_mut(address)
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

    #[call]
    pub fn claim_testnet_participation(&mut self) -> Result<()> {
        #[cfg(feature = "stakenet")]
        {
            let mut acct = self.signer_acct_mut()?;
            let amount = acct.testnet_participation.claim()?;
            self.pay_as_funding(amount)?;
        }
        Ok(())
    }

    #[call]
    pub fn join_accounts(&mut self, dest_addr: Address) -> Result<()> {
        self.pay_as_funding(MIN_FEE)?;

        let mut acct = self.signer_acct_mut()?;
        if acct.is_empty() {
            return Err(Error::App("Account has no airdrop balance".to_string()));
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

        add_part(&mut dest.airdrop1, src.airdrop1);
        add_part(&mut dest.btc_deposit, src.btc_deposit);
        add_part(&mut dest.ibc_transfer, src.ibc_transfer);
        add_part(&mut dest.btc_withdraw, src.btc_withdraw);

        #[cfg(feature = "stakenet")]
        add_part(&mut dest.testnet_participation, src.testnet_participation);

        Ok(())
    }

    #[cfg(feature = "full")]
    pub fn init_from_airdrop2_csv(&mut self, data: &[u8]) -> Result<()> {
        println!("Initializing balances from airdrop 2 snapshot...");

        let recipients = Self::get_recipients_from_csv(data);
        let len = recipients[0].1.len();
        let mut totals = vec![0u64; len];

        for (_, networks, _) in recipients.iter() {
            for (i, (staked, count)) in networks.iter().enumerate() {
                let score = Self::score(*staked, *count);
                totals[i] += score;
            }
        }

        let precision = 1_000_000u128;
        let unom_per_network = AIRDROP_II_TOTAL / (len as u64);
        let unom_per_score: Vec<_> = totals
            .iter()
            .map(|n| unom_per_network as u128 * precision / *n as u128)
            .collect();

        let mut modified_recipients = Vec::new();
        let mut airdrop_total = 0;
        let mut accounts = 0;
        for (address, networks, claims) in recipients.iter() {
            let unom: u64 = networks
                .iter()
                .zip(unom_per_score.iter())
                .map(|((staked, count), unom_per_score)| {
                    let score = Self::score(*staked, *count) as u128;
                    (score * unom_per_score / precision) as u64
                })
                .sum();

            self.airdrop_to(*address, unom)?;
            airdrop_total += unom;
            accounts += 1;
            modified_recipients.push((*address, unom, claims));
        }

        #[cfg(feature = "stakenet")]
        {
            for (address, _, claims) in recipients {
                let account = self.accounts.entry(address)?.or_default()?;
                let testnet_allocation =
                    Self::get_individual_testnet_allocation(&*account, &claims)?;
                self.airdrop_testnet_allocation_to(&address, testnet_allocation)?;
                airdrop_total += testnet_allocation;
            }
        }

        println!(
            "Total amount minted for airdrop 2: {} uNOM across {} accounts",
            airdrop_total, accounts,
        );
        Ok(())
    }

    fn airdrop_to(&mut self, addr: Address, unom: u64) -> Result<()> {
        let mut acct = self.accounts.entry(addr)?.or_insert_default()?;

        acct.btc_deposit.locked = unom / 3;
        acct.btc_withdraw.locked = unom / 3;
        acct.ibc_transfer.locked = unom / 3;

        Ok(())
    }

    #[cfg(feature = "stakenet")]
    fn airdrop_testnet_allocation_to(&mut self, address: &Address, unom: u64) -> Result<()> {
        let mut account = self.accounts.entry(*address)?.or_default()?;
        account.testnet_participation.claimable = unom;

        Ok(())
    }

    fn score(staked: u64, _count: u64) -> u64 {
        staked.min(MAX_STAKED)
    }

    #[cfg(feature = "stakenet")]
    fn get_individual_testnet_allocation(airdrop: &Account, claims: &Vec<bool>) -> Result<u64> {
        let num_claims: u64 = claims.len().try_into()?;
        let claims: u64 = claims.iter().filter(|val| **val).count().try_into()?;

        let airdrop2_allocated_total = Amount::from(
            airdrop.btc_deposit.locked + airdrop.btc_withdraw.locked + airdrop.ibc_transfer.locked,
        );
        let ratio_claimed = airdrop2_allocated_total / Amount::from(AIRDROP_II_TOTAL);
        let total_claimable = ratio_claimed * Amount::from(AIRDROP_II_TESTNET_PARTICIPATION_TOTAL);
        let result = (total_claimable * (Amount::from(claims) / Amount::from(num_claims)))
            .result()
            .unwrap()
            .amount()
            .unwrap();
        Ok(result.into())
    }

    #[cfg(feature = "full")]
    fn get_recipients_from_csv(data: &[u8]) -> Recipients {
        let mut reader = csv::Reader::from_reader(data);

        reader
            .records()
            .filter_map(|row| {
                let row = row.unwrap();

                if row[0].len() != 44 {
                    return None;
                }
                let addr: Address = row[0].parse().unwrap();
                let (claims, values) = row
                    .into_iter()
                    .skip(1)
                    .split(|item| item.parse::<u64>().is_ok());
                let values: Vec<_> = values.map(|s| -> u64 { s.parse().unwrap() }).collect();
                let claims: Vec<_> = claims.map(|s| -> bool { s.parse().unwrap() }).collect();
                let pairs: Vec<_> = values.chunks_exact(2).map(|arr| (arr[0], arr[1])).collect();

                Some((addr, pairs, claims))
            })
            .collect()
    }

    fn init_airdrop1_amount(
        &mut self,
        addr: Address,
        liquid: Amount,
        staked: Amount,
    ) -> Result<Amount> {
        let liquid_capped = Amount::min(liquid, 1_000_000_000.into());
        let staked_capped = Amount::min(staked, 1_000_000_000.into());

        let units = (liquid_capped + staked_capped * Amount::from(4))?;
        let units_per_nom = Decimal::from(20_299325) / Decimal::from(1_000_000);
        let nom_amount = (Decimal::from(units) / units_per_nom)?.amount()?;

        let mut acct = self.accounts.entry(addr)?.or_insert_default()?;
        acct.airdrop1.claimable = nom_amount.into();

        Ok(nom_amount)
    }

    #[cfg(feature = "full")]
    pub fn init_from_airdrop1_csv(&mut self, data: &[u8]) -> Result<()> {
        let mut rdr = csv::Reader::from_reader(data);
        let snapshot = rdr.records();

        println!("Initializing balances from airdrop 1 snapshot...");

        let mut minted = Amount::from(0);
        let mut accounts = 0;

        for row in snapshot {
            let row = row.map_err(|e| Error::App(e.to_string()))?;

            let (_, address_b32, _) = bech32::decode(&row[0]).unwrap();
            let address_vec: Vec<u8> = bech32::FromBase32::from_base32(&address_b32).unwrap();
            let address_buf: [u8; 20] = address_vec.try_into().unwrap();

            let liquid: u64 = row[1].parse().unwrap();
            let staked: u64 = row[2].parse().unwrap();

            let minted_for_account =
                self.init_airdrop1_amount(address_buf.into(), liquid.into(), staked.into())?;
            minted = (minted + minted_for_account)?;
            accounts += 1;
        }

        println!(
            "Total amount minted for airdrop 1: {} uNOM across {} accounts",
            minted, accounts
        );

        Ok(())
    }
}

#[orga]
#[derive(Clone, Debug)]
pub struct Account {
    pub airdrop1: Part,
    pub btc_deposit: Part,
    pub btc_withdraw: Part,
    pub ibc_transfer: Part,
    #[cfg(feature = "stakenet")]
    pub testnet_participation: Part,
}

impl Account {
    pub fn is_empty(&self) -> bool {
        self.airdrop1.is_empty()
            && self.btc_deposit.is_empty()
            && self.btc_withdraw.is_empty()
            && self.ibc_transfer.is_empty()
    }
}

#[orga]
#[derive(Clone, Debug)]
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

    pub fn is_empty(&self) -> bool {
        (self.locked + self.claimable + self.claimed) == 0
    }

    pub fn total(&self) -> u64 {
        self.locked + self.claimable + self.claimed
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use orga::prelude::Amount;
    use std::str::FromStr;

    #[cfg(not(feature = "stakenet"))]
    #[test]
    fn airdrop_allocation_no_testnet() {
        let mut airdrop = Airdrop::default();
        let csv = "address,evmos_9000-1_staked,evmos_9000-1_count,kaiyo-1_staked,kaiyo-1_count,cosmoshub-4_staked,cosmoshub-4_count,juno-1_staked,juno-1_count,osmosis-1_staked,osmosis-1_count,btc_deposit_claimed,btc_withdraw_claimed,ibc_transfer_claimed
nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x,1,1,1,1,1,1,1,1,1,1,true,true,true".as_bytes();

        airdrop.init_from_airdrop2_csv(csv).unwrap();

        let account = airdrop
            .get_mut(Address::from_str("nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x").unwrap())
            .unwrap()
            .unwrap();
        let airdrop2_total = account.btc_deposit.total()
            + account.btc_withdraw.total()
            + account.ibc_transfer.total();

        assert_eq!(airdrop2_total, AIRDROP_II_TOTAL);
    }

    #[cfg(feature = "stakenet")]
    #[test]
    fn airdrop_allocation() {
        let mut airdrop = Airdrop::default();
        let csv = "address,evmos_9000-1_staked,evmos_9000-1_count,kaiyo-1_staked,kaiyo-1_count,cosmoshub-4_staked,cosmoshub-4_count,juno-1_staked,juno-1_count,osmosis-1_staked,osmosis-1_count,btc_deposit_claimed,btc_withdraw_claimed,ibc_transfer_claimed
nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x,1,1,1,1,1,1,1,1,1,1,true,true,true".as_bytes();

        airdrop.init_from_airdrop2_csv(csv).unwrap();

        let account = airdrop
            .get_mut(Address::from_str("nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x").unwrap())
            .unwrap()
            .unwrap();
        let airdrop2_total = account.btc_deposit.total()
            + account.btc_withdraw.total()
            + account.ibc_transfer.total()
            + account.testnet_participation.total();

        assert_eq!(
            airdrop2_total,
            AIRDROP_II_TOTAL + AIRDROP_II_TESTNET_PARTICIPATION_TOTAL
        );
    }

    #[cfg(feature = "stakenet")]
    #[test]
    fn airdrop_allocation_multiple() {
        let mut airdrop = Airdrop::default();
        let csv = "address,evmos_9000-1_staked,evmos_9000-1_count,kaiyo-1_staked,kaiyo-1_count,cosmoshub-4_staked,cosmoshub-4_count,juno-1_staked,juno-1_count,osmosis-1_staked,osmosis-1_count,btc_deposit_claimed,btc_withdraw_claimed,ibc_transfer_claimed
nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x,1,1,1,1,1,1,1,1,1,1,true,true,true
nomic10005vr6w230rer02rgwsvmhh0vdpk9hvxkv8zs,1,1,1,1,1,1,1,1,1,1,true,true,true".as_bytes();

        airdrop.init_from_airdrop2_csv(csv).unwrap();

        let account = airdrop
            .get_mut(Address::from_str("nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x").unwrap())
            .unwrap()
            .unwrap();
        let airdrop2_total = account.btc_deposit.total()
            + account.btc_withdraw.total()
            + account.ibc_transfer.total()
            + account.testnet_participation.total();
        let expected: u64 = ((Amount::from(AIRDROP_II_TOTAL)
            + Amount::from(AIRDROP_II_TESTNET_PARTICIPATION_TOTAL))
            / Amount::from(2))
        .result()
        .unwrap()
        .amount()
        .unwrap()
        .into();

        assert_eq!(airdrop2_total, expected);

        let account = airdrop
            .get_mut(Address::from_str("nomic10005vr6w230rer02rgwsvmhh0vdpk9hvxkv8zs").unwrap())
            .unwrap()
            .unwrap();
        let airdrop2_total = account.btc_deposit.total()
            + account.btc_withdraw.total()
            + account.ibc_transfer.total()
            + account.testnet_participation.total();

        assert_eq!(airdrop2_total, expected);
    }

    #[cfg(feature = "stakenet")]
    #[test]
    fn airdrop_allocation_multiple_uneven() {
        let mut airdrop = Airdrop::default();
        let csv = "address,evmos_9000-1_staked,evmos_9000-1_count,kaiyo-1_staked,kaiyo-1_count,cosmoshub-4_staked,cosmoshub-4_count,juno-1_staked,juno-1_count,osmosis-1_staked,osmosis-1_count,btc_deposit_claimed,btc_withdraw_claimed,ibc_transfer_claimed
nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x,1,1,1,1,1,1,1,1,1,1,true,true,true
nomic10005vr6w230rer02rgwsvmhh0vdpk9hvxkv8zs,1,1,1,1,1,1,1,1,1,1,false,false,false".as_bytes();

        airdrop.init_from_airdrop2_csv(csv).unwrap();

        let account = airdrop
            .get_mut(Address::from_str("nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x").unwrap())
            .unwrap()
            .unwrap();
        let airdrop2_total = account.btc_deposit.total()
            + account.btc_withdraw.total()
            + account.ibc_transfer.total()
            + account.testnet_participation.total();
        let expected: u64 = ((Amount::from(AIRDROP_II_TOTAL)
            + Amount::from(AIRDROP_II_TESTNET_PARTICIPATION_TOTAL))
            / Amount::from(2))
        .result()
        .unwrap()
        .amount()
        .unwrap()
        .into();
        assert_eq!(airdrop2_total, expected);

        let account = airdrop
            .get_mut(Address::from_str("nomic10005vr6w230rer02rgwsvmhh0vdpk9hvxkv8zs").unwrap())
            .unwrap()
            .unwrap();
        let airdrop2_total = account.btc_deposit.total()
            + account.btc_withdraw.total()
            + account.ibc_transfer.total()
            + account.testnet_participation.total();
        let expected: u64 = (Amount::from(AIRDROP_II_TOTAL) / Amount::from(2))
            .result()
            .unwrap()
            .amount()
            .unwrap()
            .into();

        assert_eq!(airdrop2_total, expected);
    }

    #[cfg(feature = "stakenet")]
    #[test]
    fn airdrop_allocation_multiple_one_claim() {
        let mut airdrop = Airdrop::default();
        let csv = "address,evmos_9000-1_staked,evmos_9000-1_count,kaiyo-1_staked,kaiyo-1_count,cosmoshub-4_staked,cosmoshub-4_count,juno-1_staked,juno-1_count,osmosis-1_staked,osmosis-1_count,btc_deposit_claimed,btc_withdraw_claimed,ibc_transfer_claimed
nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x,1,1,1,1,1,1,1,1,1,1,true,true,true
nomic10005vr6w230rer02rgwsvmhh0vdpk9hvxkv8zs,1,1,1,1,1,1,1,1,1,1,true,false,false".as_bytes();

        airdrop.init_from_airdrop2_csv(csv).unwrap();

        let account = airdrop
            .get_mut(Address::from_str("nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x").unwrap())
            .unwrap()
            .unwrap();
        let airdrop2_total = account.btc_deposit.total()
            + account.btc_withdraw.total()
            + account.ibc_transfer.total()
            + account.testnet_participation.total();
        let expected: u64 = ((Amount::from(AIRDROP_II_TOTAL)
            + Amount::from(AIRDROP_II_TESTNET_PARTICIPATION_TOTAL))
            / Amount::from(2))
        .result()
        .unwrap()
        .amount()
        .unwrap()
        .into();
        assert_eq!(airdrop2_total, expected);

        let account = airdrop
            .get_mut(Address::from_str("nomic10005vr6w230rer02rgwsvmhh0vdpk9hvxkv8zs").unwrap())
            .unwrap()
            .unwrap();
        let airdrop2_total = account.btc_deposit.total()
            + account.btc_withdraw.total()
            + account.ibc_transfer.total()
            + account.testnet_participation.total();
        let expected: u64 = ((Amount::from(AIRDROP_II_TOTAL) / Amount::from(2))
            + (Amount::from(AIRDROP_II_TESTNET_PARTICIPATION_TOTAL) / Amount::from(6)))
        .result()
        .unwrap()
        .amount()
        .unwrap()
        .into();
        assert_eq!(airdrop2_total, expected);
    }

    #[cfg(feature = "stakenet")]
    #[test]
    fn airdrop_allocation_multiple_two_claim() {
        let mut airdrop = Airdrop::default();
        let csv = "address,evmos_9000-1_staked,evmos_9000-1_count,kaiyo-1_staked,kaiyo-1_count,cosmoshub-4_staked,cosmoshub-4_count,juno-1_staked,juno-1_count,osmosis-1_staked,osmosis-1_count,btc_deposit_claimed,btc_withdraw_claimed,ibc_transfer_claimed
nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x,1,1,1,1,1,1,1,1,1,1,true,true,true
nomic10005vr6w230rer02rgwsvmhh0vdpk9hvxkv8zs,1,1,1,1,1,1,1,1,1,1,true,true,false".as_bytes();

        airdrop.init_from_airdrop2_csv(csv).unwrap();

        let account = airdrop
            .get_mut(Address::from_str("nomic100000aeu2lh0jrrnmn2npc88typ25u7t3aa64x").unwrap())
            .unwrap()
            .unwrap();
        let airdrop_total_1 = account.btc_deposit.total()
            + account.btc_withdraw.total()
            + account.ibc_transfer.total()
            + account.testnet_participation.total();
        let expected: u64 = ((Amount::from(AIRDROP_II_TOTAL)
            + Amount::from(AIRDROP_II_TESTNET_PARTICIPATION_TOTAL))
            / Amount::from(2))
        .result()
        .unwrap()
        .amount()
        .unwrap()
        .into();
        assert_eq!(airdrop_total_1, expected);

        let account = airdrop
            .get_mut(Address::from_str("nomic10005vr6w230rer02rgwsvmhh0vdpk9hvxkv8zs").unwrap())
            .unwrap()
            .unwrap();
        let airdrop_total_2 = account.btc_deposit.total()
            + account.btc_withdraw.total()
            + account.ibc_transfer.total()
            + account.testnet_participation.total();
        let expected: u64 = (Amount::from(AIRDROP_II_TOTAL) / Amount::from(2)
            + (Amount::from(AIRDROP_II_TESTNET_PARTICIPATION_TOTAL) / Amount::from(3)))
        .result()
        .unwrap()
        .amount()
        .unwrap()
        .into();
        assert_eq!(airdrop_total_2, expected);

        let expected: u64 = (Amount::from(AIRDROP_II_TOTAL)
            + (Amount::from(AIRDROP_II_TESTNET_PARTICIPATION_TOTAL) * Amount::from(5)
                / Amount::from(6)))
        .result()
        .unwrap()
        .amount()
        .unwrap()
        .into();
        assert_eq!(airdrop_total_1 + airdrop_total_2, expected);
    }
}
