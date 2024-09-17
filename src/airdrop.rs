//! State and logic for airdrop accounts which can be claimed by users.

use orga::coins::Address;
#[cfg(feature = "full")]
use orga::coins::{Amount, Decimal};
use orga::collections::{ChildMut, Map};
use orga::context::GetContext;
use orga::migrate::MigrateFrom;
use orga::orga;
use orga::plugins::{Paid, Signer};
use orga::{Error, Result};
#[cfg(feature = "full")]
use split_iter::Splittable;

use super::app::Nom;

/// The maximum units of stake counted when calculating airdrop II.
#[cfg(feature = "full")]
const MAX_STAKED: u64 = 1_000_000_000;
/// The total amount of token units claimable by users in airdrop II.
#[cfg(feature = "full")]
const AIRDROP_II_TOTAL: u64 = 3_500_000_000_000;

/// Airdrop account state.
#[orga(version = 1)]
pub struct Airdrop {
    accounts: Map<Address, Account>,
}

impl MigrateFrom<AirdropV0> for AirdropV1 {
    fn migrate_from(_value: AirdropV0) -> Result<Self> {
        unreachable!()
    }
}

type Recipients = Vec<(Address, Vec<(u64, u64)>, u64)>;

#[orga]
impl Airdrop {
    /// Gets the account at the given address.
    #[query]
    pub fn get(&self, address: Address) -> Result<Option<Account>> {
        Ok(self.accounts.get(address)?.map(|a| a.clone()))
    }

    /// Gets a mutable reference to the account at the given address.
    pub fn get_mut(&mut self, address: Address) -> Result<Option<ChildMut<Address, Account>>> {
        self.accounts.get_mut(address)
    }

    /// Gets a mutable reference to the account for the signer of the
    /// transaction.
    pub fn signer_acct_mut(&mut self) -> Result<ChildMut<Address, Account>> {
        let signer = self
            .context::<Signer>()
            .ok_or_else(|| Error::Signer("No Signer context available".into()))?
            .signer
            .ok_or_else(|| Error::Coins("Unauthorized account action".into()))?;

        self.accounts
            .get_mut(signer)?
            .ok_or_else(|| Error::App("No airdrop account for signer".into()))
    }

    /// Pays into the Paid context as funding.
    fn pay_as_funding(&mut self, amount: u64) -> Result<()> {
        let paid = self
            .context::<Paid>()
            .ok_or_else(|| Error::Coins("No Paid context found".into()))?;

        paid.give::<Nom, _>(amount)
    }

    /// Claims the signer's airdrop I balance to the funding context.
    #[call]
    pub fn claim_airdrop1(&mut self) -> Result<()> {
        let mut acct = self.signer_acct_mut()?;
        let amount = acct.airdrop1.claim()?;
        self.pay_as_funding(amount)?;
        Ok(())
    }

    /// Claims the signer's airdrop II balance to the funding context.
    #[call]
    pub fn claim_airdrop2(&mut self) -> Result<()> {
        let mut acct = self.signer_acct_mut()?;
        let amount = acct.airdrop2.claim()?;
        self.pay_as_funding(amount)?;
        Ok(())
    }

    /// Joins the signer's account to a destination account (e.g. when the user
    /// received the airdrop to multiple addresses but would like to consolidate
    /// into one account).
    pub fn join_accounts(&mut self, dest_addr: Address) -> Result<()> {
        let mut acct = self.signer_acct_mut()?;

        if acct.joined {
            return Err(Error::App("Account already joined".to_string()));
        }
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
        add_part(&mut dest.airdrop2, src.airdrop2);

        dest.joined = true;

        Ok(())
    }

    /// Initializes unclaimed airdrop accounts from a CSV file.
    #[cfg(feature = "full")]
    pub fn init_from_airdrop2_csv(&mut self, data: &[u8]) -> Result<()> {
        log::info!("Initializing balances from airdrop 2 snapshot...");

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

        let mut airdrop_total = 0;
        let mut accounts = 0;

        #[cfg(not(feature = "testnet"))]
        let mut testnet_locked = 0;
        #[cfg(not(feature = "testnet"))]
        let mut testnet_claimable = 0;

        #[allow(unused_variables)]
        for (address, networks, testnet_completions) in recipients.iter() {
            let unom: u64 = networks
                .iter()
                .zip(unom_per_score.iter())
                .map(|((staked, count), unom_per_score)| {
                    let score = Self::score(*staked, *count) as u128;
                    (score * unom_per_score / precision) as u64
                })
                .sum();

            let res = self.airdrop_to(*address, unom, *testnet_completions)?;
            airdrop_total += unom;
            accounts += 1;

            #[cfg(not(feature = "testnet"))]
            {
                testnet_locked += res.0;
                testnet_claimable += res.1;
            }
        }

        log::info!(
            "Total amount minted for airdrop 2: {} uNOM across {} accounts",
            airdrop_total,
            accounts,
        );

        #[cfg(not(feature = "testnet"))]
        log::info!(
            "Testnet participation allocation: {} uNOM locked, {} uNOM claimable",
            testnet_locked,
            testnet_claimable,
        );

        Ok(())
    }

    /// Initializes and pays into a new airdrop account.
    #[allow(unused_variables)]
    #[cfg(feature = "full")]
    fn airdrop_to(
        &mut self,
        addr: Address,
        unom: u64,
        testnet_completions: u64,
    ) -> Result<(u64, u64)> {
        let mut acct = self.accounts.entry(addr)?.or_insert_default()?;

        acct.airdrop2.claimable = unom;

        Ok((0, 0))
    }

    /// Returns the score for a given staked amount and delegation count. The
    /// score is further used in the calculation of the amount of tokens to
    /// receive.
    #[cfg(feature = "full")]
    fn score(staked: u64, _count: u64) -> u64 {
        staked.min(MAX_STAKED)
    }

    /// Parses the CSV data into a list of recipients.
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
                let claims = claims
                    .map(|s| -> bool { s.parse().unwrap() })
                    .filter(|b| *b)
                    .count() as u64;
                let pairs = values.chunks_exact(2).map(|arr| (arr[0], arr[1])).collect();

                Some((addr, pairs, claims))
            })
            .collect()
    }

    /// Initializes the airdrop I balances for a given address.
    #[cfg(feature = "full")]
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

    /// Initializes the airdrop I balances for all the accounts in the given
    /// CSV.
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

/// An airdrop account.
#[orga(version = 1..=2)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// The part of the airdrop received in airdrop I.
    pub airdrop1: Part,
    /// The part of the airdrop received in airdrop II.
    pub airdrop2: Part,
    /// Whether or not the account has been joined into from another account.
    /// This is tracked to prevent a DoS vector where an attacker could spam
    /// transactions by repeatedly joining into different accounts without
    /// paying a fee.
    pub joined: bool,
}

impl Account {
    /// Returns `true` if the account is empty.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl MigrateFrom<AccountV1> for AccountV2 {
    fn migrate_from(_value: AccountV1) -> Result<Self> {
        unreachable!()
    }
}

/// A part of an airdrop account, e.g. the balances from either airdrop I or
/// airdrop II.
#[orga]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// A balance for the user which is locked and cannot be claimed. This will
    /// typically be unlocked after some external event occurs.
    pub locked: u64,
    /// A balance for the user which can be claimed by the user.
    pub claimable: u64,
    /// The amount of balance which has already been claimed. This is not a
    /// balance, since upon claiming the balance was moved elsewhere, e.g. the
    /// user's normal balance.
    pub claimed: u64,
}

impl Part {
    /// Unlocks the locked balance, making it claimable.
    pub fn unlock(&mut self) {
        self.claimable += self.locked;
        self.locked = 0;
    }

    /// Claims the claimable balance, marking the amount as claimed and
    /// returning the amount to be paid to the account's normal balance.
    pub fn claim(&mut self) -> Result<u64> {
        let amount = self.claimable;
        if amount == 0 {
            return Err(Error::Coins("No balance to claim".to_string()));
        }

        self.claimed += amount;
        self.claimable = 0;
        Ok(amount)
    }

    /// Returns `true` if the part has no locked or claimable balances and has
    /// not been claimed.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Returns the total balance across all states.
    pub fn total(&self) -> u64 {
        self.locked + self.claimable + self.claimed
    }
}

#[cfg(feature = "full")]
#[cfg(test)]
mod test {
    use super::*;
    #[cfg(not(feature = "testnet"))]
    use orga::coins::Amount;
    use std::str::FromStr;

    fn assert_approx_eq(a: u64, b: u64) {
        assert!((a as i64 - b as i64).abs() <= 2, "{} !~= {}", a, b);
    }

    #[cfg(not(feature = "testnet"))]
    fn amount_airdropped(acct: &Account) -> u64 {
        acct.airdrop2.claimable
    }

    #[cfg(feature = "testnet")]
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
        let airdrop2_total = account.airdrop2.total();

        assert_approx_eq(airdrop2_total, AIRDROP_II_TOTAL);
    }

    #[cfg(not(feature = "testnet"))]
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
        let airdrop2_total = amount_airdropped(&*account);

        assert_approx_eq(airdrop2_total, AIRDROP_II_TOTAL);
    }

    #[cfg(not(feature = "testnet"))]
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
        let airdrop2_total = amount_airdropped(&*account);
        let expected: u64 = (Amount::from(AIRDROP_II_TOTAL) / Amount::from(2))
            .result()
            .unwrap()
            .amount()
            .unwrap()
            .into();

        assert_approx_eq(airdrop2_total, expected);

        let account = airdrop
            .get_mut(Address::from_str("nomic10005vr6w230rer02rgwsvmhh0vdpk9hvxkv8zs").unwrap())
            .unwrap()
            .unwrap();
        let airdrop2_total = amount_airdropped(&*account);

        assert_approx_eq(airdrop2_total, expected);
    }
}
