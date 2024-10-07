use std::collections::{BTreeMap, HashSet};
use std::ops::Range;

use orga::coins::{Address, Symbol};
use orga::collections::Deque;
use orga::context::GetContext;
use orga::encoding::LengthVec;

use orga::plugins::{disable_fee, Signer as SignerCtx, Time};
use orga::Result;
use orga::{orga, Error};

pub mod dkg;
pub mod encoding;
#[cfg(feature = "full")]
pub mod signer;
pub mod signing;
pub use encoding::Adapter;
use frost_secp256k1_tr::keys::{dkg as frost_dkg, PublicKeyPackage};
use frost_secp256k1_tr::round1::SigningCommitments;
use frost_secp256k1_tr::round2::SignatureShare;
use frost_secp256k1_tr::{Identifier, Signature, SigningPackage};

use self::dkg::{Dkg, DkgState};
use self::signing::{Signing, SigningState};

#[orga]
#[derive(Debug, Clone)]
pub struct Config {
    pub threshold: u16,
    pub participants: LengthVec<u16, Participant>,
}

impl Config {
    pub fn from_staking<S: Symbol>(
        staking: &orga::coins::Staking<S>,
        top_n: u16,
        threshold: u16,
        absent: &HashSet<Address>,
    ) -> Result<Self> {
        let mut validators = staking.all_validators()?;
        validators.sort_by_key(|v| {
            if absent.contains(&v.address.into()) {
                0
            } else {
                v.amount_staked.into()
            }
        });

        let threshold = std::cmp::min(threshold, validators.len() as u16);

        let participants: Vec<_> = validators
            .into_iter()
            .take(top_n as usize)
            .map(|v| Participant {
                address: v.address.into(),
                shares: 1,
            })
            .collect();

        Ok(Self {
            participants: participants.try_into()?,
            threshold,
        })
    }
    pub fn total_shares(&self) -> u16 {
        self.participants.iter().map(|p| p.shares).sum()
    }

    pub fn contains(&self, address: Address) -> bool {
        self.participants.iter().any(|p| p.address == address)
    }

    pub fn share_range(&self, address: Address) -> Result<Range<u16>> {
        let mut index = 0;
        for participant in self.participants.iter() {
            if participant.address == address {
                return Ok(index..index + participant.shares);
            }
            index += participant.shares;
        }

        Err(Error::App(format!("Participant not found: {}", address)))
    }
}

#[orga]
pub struct FrostGroup {
    pub config: Config,
    pub dkg: dkg::Dkg,
    pub signing: Deque<Signing>,
    pub created_at: i64,
}

#[orga]
pub struct Frost {
    pub groups: Deque<FrostGroup>,
}

#[orga]
#[derive(Debug, Clone)]
pub struct Participant {
    pub address: Address,
    pub shares: u16,
}

impl FrostGroup {
    pub fn with_config(config: Config, now: i64) -> Result<Self> {
        let dkg = Dkg::from_config(&config)?;
        Ok(Self {
            config,
            dkg,
            signing: Deque::new(),
            created_at: now,
        })
    }

    pub fn push_message(&mut self, message: LengthVec<u16, u8>) -> Result<()> {
        let now = self.now()?;
        self.signing
            .push_back(Signing::new(self.config.clone(), message, now))?;

        Ok(())
    }

    fn signer(&mut self) -> Result<Address> {
        self.context::<SignerCtx>()
            .ok_or_else(|| Error::Coins("No Signer context available".into()))?
            .signer
            .ok_or_else(|| Error::Coins("Call must be signed".into()))
    }

    fn now(&mut self) -> Result<i64> {
        Ok(self
            .context::<Time>()
            .ok_or_else(|| Error::App("No time context available".into()))?
            .seconds)
    }

    pub fn submit_dkg_round1(
        &mut self,
        packages: LengthVec<u16, Adapter<frost_dkg::round1::Package>>,
    ) -> Result<()> {
        let packages: Vec<_> = packages.into();
        let address = self.signer()?;
        let share_range = self.config.share_range(address)?;
        if share_range.len() != packages.len() {
            return Err(Error::App("Invalid number of packages".into()));
        }

        for (offset, package) in packages.into_iter().enumerate() {
            let participant = share_range.start + offset as u16;
            self.dkg.submit_round1(participant, package)?;
        }

        Ok(())
    }

    pub fn submit_dkg_round2(
        &mut self,
        packages: LengthVec<u16, LengthVec<u16, (u16, Adapter<frost_dkg::round2::Package>)>>,
    ) -> Result<()> {
        let packages: Vec<_> = packages.into();
        let address = self.signer()?;
        let share_range = self.config.share_range(address)?;
        if share_range.len() != packages.len() {
            return Err(Error::App("Invalid number of packages".into()));
        }

        for (offset, packages) in packages.into_iter().enumerate() {
            let participant = share_range.start + offset as u16;

            self.dkg.submit_round2(participant, packages)?;
        }

        Ok(())
    }

    pub fn attest_pubkey_package(
        &mut self,
        pubkey_package: Adapter<PublicKeyPackage>,
    ) -> Result<()> {
        let address = self.signer()?;
        let share_range = self.config.share_range(address)?;
        for i in share_range {
            self.dkg.attest_pubkey_package(i, pubkey_package.clone())?;
        }

        Ok(())
    }

    pub fn submit_commitments(
        &mut self,
        sig_index: u64,
        iteration: u32,
        commitments: LengthVec<u16, Adapter<SigningCommitments>>,
    ) -> Result<()> {
        let address = self.signer()?;
        let share_range = self.config.share_range(address)?;
        let mut sig = self
            .signing
            .get_mut(sig_index)?
            .ok_or(Error::App("Signing not found".into()))?;
        let commitments: Vec<Adapter<SigningCommitments>> = commitments.into();
        for (i, commitment) in commitments.into_iter().enumerate() {
            let participant = share_range.start + i as u16;
            sig.submit_commitments(iteration, participant, commitment)?;
        }

        Ok(())
    }

    pub fn submit_sig_shares(
        &mut self,
        sig_index: u64,
        iteration: u32,
        shares: LengthVec<u16, Adapter<SignatureShare>>,
    ) -> Result<()> {
        let address = self.signer()?;
        let share_range = self.config.share_range(address)?;

        let pubkey_package = &self
            .dkg
            .group_pubkey()?
            .ok_or(Error::App("Pubkey not yet generated for group".into()))?
            .inner;
        let mut sig = self
            .signing
            .get_mut(sig_index)?
            .ok_or(Error::App("Signing not found".into()))?;
        let shares: Vec<Adapter<SignatureShare>> = shares.into();
        for (i, share) in shares.into_iter().enumerate() {
            let participant = share_range.start + i as u16;
            sig.submit_sig_share(iteration, participant, share, pubkey_package)?;
        }

        Ok(())
    }

    pub fn advance_with_timeout(&mut self, timeout: i64) -> Result<()> {
        let now = self.now()?;
        for i in 0..self.signing.len() {
            let mut sig = self
                .signing
                .get_mut(i)?
                .ok_or(Error::App("Signing not found".into()))?;
            sig.advance_with_timeout(now, timeout)?;
        }

        Ok(())
    }

    pub fn absent(&self) -> Result<HashSet<Address>> {
        let mut res = HashSet::new();
        if self.dkg.state() != DkgState::Round1 {
            return Ok(res);
        }
        for participant in self.config.participants.iter() {
            for i in self.config.share_range(participant.address)? {
                if self.dkg.absent(i)? {
                    res.insert(participant.address);
                }
            }
        }

        Ok(res)
    }
}

#[orga]
impl Frost {
    #[call]
    pub fn noop_call(&mut self) -> Result<()> {
        Ok(())
    }

    #[call]
    pub fn submit_dkg_round1(
        &mut self,
        index: u64,
        packages: LengthVec<u16, Adapter<frost_dkg::round1::Package>>,
    ) -> Result<()> {
        disable_fee();
        let mut group = self
            .groups
            .get_mut(index)?
            .ok_or(Error::App("Sig not found".into()))?;

        group.submit_dkg_round1(packages)
    }

    #[call]
    pub fn submit_dkg_round2(
        &mut self,
        index: u64,
        packages: LengthVec<u16, LengthVec<u16, (u16, Adapter<frost_dkg::round2::Package>)>>,
    ) -> Result<()> {
        disable_fee();
        let mut group = self
            .groups
            .get_mut(index)?
            .ok_or(Error::App("Sig not found".into()))?;

        group.submit_dkg_round2(packages)
    }

    #[call]
    pub fn attest_dkg_pubkey(
        &mut self,
        index: u64,
        package: Adapter<PublicKeyPackage>,
    ) -> Result<()> {
        disable_fee();
        let mut group = self
            .groups
            .get_mut(index)?
            .ok_or(Error::App("Sig not found".into()))?;

        group.attest_pubkey_package(package)
    }

    #[call]
    pub fn submit_commitments(
        &mut self,
        group_index: u64,
        sig_index: u64,
        iteration: u32,
        commitments: LengthVec<u16, Adapter<SigningCommitments>>,
    ) -> Result<()> {
        disable_fee();
        let mut group = self
            .groups
            .get_mut(group_index)?
            .ok_or(Error::App("Sig not found".into()))?;

        group.submit_commitments(sig_index, iteration, commitments)
    }

    #[call]
    pub fn submit_sig_shares(
        &mut self,
        group_index: u64,
        sig_index: u64,
        iteration: u32,
        shares: LengthVec<u16, Adapter<SignatureShare>>,
    ) -> Result<()> {
        disable_fee();
        let mut group = self
            .groups
            .get_mut(group_index)?
            .ok_or(Error::App("Sig not found".into()))?;

        group.submit_sig_shares(sig_index, iteration, shares)
    }

    #[query]
    pub fn dkg_round1_packages(
        &self,
        index: u64,
    ) -> Result<Vec<(u16, frost_dkg::round1::Package)>> {
        self.groups
            .get(index)?
            .map(|sig| sig.dkg.round1_packages())
            .ok_or(Error::App("Sig not found".into()))?
    }

    #[query]
    pub fn dkg_round2_packages(
        &self,
        index: u64,
        receiver: u16,
    ) -> Result<Vec<(u16, frost_dkg::round2::Package)>> {
        self.groups
            .get(index)?
            .map(|sig| sig.dkg.round2_packages(receiver))
            .ok_or(Error::App("Sig not found".into()))?
    }

    #[query]
    pub fn dkg_state(&self, index: u64) -> Result<DkgState> {
        self.groups
            .get(index)?
            .map(|sig| sig.dkg.state())
            .ok_or(Error::App("Sig not found".into()))
    }

    #[query]
    pub fn signing_state(&self, group_index: u64, sig_index: u64) -> Result<SigningState> {
        let group = self
            .groups
            .get(group_index)?
            .ok_or(Error::App("Sig not found".into()))?;

        let sig = group
            .signing
            .get(sig_index)?
            .ok_or(Error::App("Signing not found".into()))?;

        Ok(sig.state())
    }

    #[query]
    pub fn signing_state_with_iteration(
        &self,
        group_index: u64,
        sig_index: u64,
    ) -> Result<(u32, SigningState)> {
        let group = self
            .groups
            .get(group_index)?
            .ok_or(Error::App("Sig not found".into()))?;

        let sig = group
            .signing
            .get(sig_index)?
            .ok_or(Error::App("Signing not found".into()))?;

        Ok((sig.iteration, sig.state()))
    }

    #[query]
    pub fn config(&self, index: u64) -> Result<Config> {
        self.groups
            .get(index)?
            .map(|sig| sig.config.clone())
            .ok_or(Error::App("Sig not found".into()))
    }

    #[query]
    pub fn group_pubkey(&self, index: u64) -> Result<Option<Adapter<PublicKeyPackage>>> {
        self.groups
            .get(index)?
            .ok_or(Error::App("Sig not found".into()))?
            .dkg
            .group_pubkey()
    }

    #[query]
    pub fn dkg_action_required(&self, address: Address) -> Result<Vec<u64>> {
        let mut res = vec![];
        for i in 0..self.groups.len() {
            if i != self.groups.len() - 1 {
                // Temporary constraint to only participate in the most recent
                // group's DKG
                continue;
            }
            let group = self
                .groups
                .get(i)?
                .ok_or(Error::App("Sig not found".into()))?;

            if group.config.contains(address) {
                for participant in group.config.share_range(address)? {
                    if group.dkg.requires_action_from(participant)? {
                        res.push(i);
                        break;
                    }
                }
            }
        }

        Ok(res)
    }

    #[query]
    pub fn signing_action_required(&self, address: Address) -> Result<Vec<(u64, u64)>> {
        let mut res = vec![];
        for i in 0..self.groups.len() {
            let group = self
                .groups
                .get(i)?
                .ok_or(Error::App("Sig not found".into()))?;
            if group.dkg.state() != DkgState::Complete {
                continue;
            }

            if !group.config.contains(address) {
                continue;
            }

            for j in 0..group.signing.len() {
                if let Some(signing) = group.signing.get(j)? {
                    for participant in group.config.share_range(address)? {
                        if signing.requires_action_from(participant)? {
                            res.push((i, j));
                            break;
                        }
                    }
                }
            }
        }

        Ok(res)
    }

    #[query]
    pub fn signing_package(
        &self,
        group_index: u64,
        sig_index: u64,
    ) -> Result<Option<Adapter<SigningPackage>>> {
        Ok(self
            .groups
            .get(group_index)?
            .ok_or(Error::App("Group not found".into()))?
            .signing
            .get(sig_index)?
            .ok_or(Error::App("Sig not found".into()))?
            .signing_package
            .clone())
    }

    #[query]
    pub fn signature(
        &self,
        group_index: u64,
        sig_index: u64,
    ) -> Result<Option<Adapter<Signature>>> {
        Ok(self
            .groups
            .get(group_index)?
            .ok_or(Error::App("Group not found".into()))?
            .signing
            .get(sig_index)?
            .ok_or(Error::App("Sig not found".into()))?
            .signature
            .clone())
    }

    #[query]
    pub fn most_recent_with_key(&self) -> Result<Option<u64>> {
        for i in (0..self.groups.len()).rev() {
            if self.group_pubkey(i)?.is_some() {
                return Ok(Some(i));
            }
        }

        Ok(None)
    }

    pub fn advance_with_timeout(&mut self, timeout: i64) -> Result<()> {
        for i in 0..self.groups.len() {
            let mut group = self
                .groups
                .get_mut(i)?
                .ok_or(Error::App("Group not found".into()))?;

            group.advance_with_timeout(timeout)?;
        }
        Ok(())
    }
}

fn identifier(participant_index: u16) -> Identifier {
    Identifier::try_from(participant_index + 1).unwrap()
}

fn assemble_by_identifier<T>(packages: impl Iterator<Item = (u16, T)>) -> BTreeMap<Identifier, T> {
    packages
        .map(|(i, p)| (identifier(i), p))
        .collect::<BTreeMap<_, _>>()
}

fn disassemble_by_identifier<T: Clone>(map: &BTreeMap<Identifier, T>) -> Vec<(u16, T)> {
    let mut res = vec![];
    for i in 0..=map.len() {
        let id = identifier(i as u16);
        if let Some(p) = map.get(&id) {
            res.push((i as u16, p.clone()));
        }
    }

    res
}

// #[cfg(test)]
// mod tests {
//     use frost_secp256k1_tr::{SigningParameters, SigningTarget};

//     use orga::client::mock::MockClient;
//     use orga::client::wallet::DerivedKey;
//     use orga::client::AppClient;

//     use orga::state::State;
//     use orga::store::{Read, Store, Write};

//     use self::signer::Signer;

//     use super::*;

//     fn setup(mut store: Store) -> Result<()> {
//         let mut app = App::default();
//         app.attach(store.clone())?;

//         {
//             app.inner.inner.borrow_mut().inner.inner.chain_id =
// b"foo".to_vec().try_into()?;

//             let inner_app = &mut app
//                 .inner
//                 .inner
//                 .borrow_mut()
//                 .inner
//                 .inner
//                 .inner
//                 .inner
//                 .inner
//                 .inner;

//             inner_app
//                 .frost
//                 .groups
//                 .push_back(FrostGroup::with_config(Config {
//                     threshold: 2,
//                     participants: vec![
//                         Participant {
//                             address: DerivedKey::new(b"alice")?.address(),
//                             shares: 1,
//                         },
//                         Participant {
//                             address: DerivedKey::new(b"bob")?.address(),
//                             shares: 1,
//                         },
//                     ]
//                     .try_into()?,
//                 })?)?;
//         };

//         let mut bytes = vec![];
//         app.flush(&mut bytes)?;
//         store.put(vec![], bytes)?;

//         Ok(())
//     }

//     fn with_app<F: FnMut(&mut TestApp) -> Result<()>>(mut store: Store, mut
// op: F) -> Result<()> {         let bytes =
// store.get(&[])?.unwrap_or_default();         let app: App =
// State::load(store.clone(), &mut bytes.as_slice())?;         {
//             let inner_app = &mut app
//                 .inner
//                 .inner
//                 .borrow_mut()
//                 .inner
//                 .inner
//                 .inner
//                 .inner
//                 .inner
//                 .inner;

//             op(inner_app)?;
//         }
//         let mut bytes = vec![];
//         app.flush(&mut bytes)?;

//         store.put(vec![], bytes)?;

//         Ok(())
//     }

//     #[tokio::test]
//     async fn two_signers_basic() -> Result<()> {
//         let store = Store::with_map_store();
//         setup(store.clone())?;

//         let alice_secret_store = Store::with_map_store();
//         let mock_client = MockClient::<App>::with_store(store.clone());
//         let client: AppClient<TestApp, TestApp, MockClient<App>, Simp,
// DerivedKey> =             AppClient::<TestApp, TestApp, _, _, _>::new(
//                 mock_client,
//                 DerivedKey::new(b"alice").unwrap(),
//             );

//         let client = client.sub(|app| app);
//         let mut alice = Signer::new(alice_secret_store, client);

//         let bob_secret_store = Store::with_map_store();
//         let mock_client = MockClient::<App>::with_store(store.clone());
//         let client: AppClient<TestApp, TestApp, _, Simp, _> =
//             AppClient::<TestApp, TestApp, _, _, _>::new(
//                 mock_client,
//                 DerivedKey::new(b"bob").unwrap(),
//             );
//         let mut bob = Signer::new(bob_secret_store, client);

//         with_app(store.clone(), |app| {
//             let mut group = app.frost.groups.front_mut().unwrap().unwrap();
//             assert_eq!(group.dkg.state(), DkgState::Round1);
//             Ok(())
//         })?;
//         alice.step().await?;
//         bob.step().await?;
//         with_app(store.clone(), |app| {
//             let mut group = app.frost.groups.front_mut().unwrap().unwrap();
//             assert_eq!(group.dkg.state(), DkgState::Round2);
//             Ok(())
//         })?;

//         alice.step().await?;
//         bob.step().await?;
//         with_app(store.clone(), |app| {
//             let mut group = app.frost.groups.front_mut().unwrap().unwrap();
//             assert_eq!(group.dkg.state(), DkgState::Attesting);
//             Ok(())
//         })?;

//         alice.step().await?;
//         bob.step().await?;

//         with_app(store.clone(), |app| {
//             let mut group = app.frost.groups.front_mut().unwrap().unwrap();
//             assert_eq!(group.dkg.state(), DkgState::Complete);
//             Ok(())
//         })?;

//         alice.step().await?;
//         bob.step().await?;

//         with_app(store.clone(), |app| {
//             let mut group = app.frost.groups.front_mut().unwrap().unwrap();
//             assert_eq!(group.dkg.state(), DkgState::Complete);

//             group.push_message(vec![1, 2, 3].try_into()?)?;

//             assert_eq!(app.frost.signing_state(0, 0)?, SigningState::Round1);

//             Ok(())
//         })?;

//         alice.step().await?;
//         bob.step().await?;

//         with_app(store.clone(), |app| {
//             assert_eq!(app.frost.signing_state(0, 0)?, SigningState::Round2);

//             Ok(())
//         })?;

//         alice.step().await?;
//         bob.step().await?;

//         with_app(store.clone(), |app| {
//             assert_eq!(app.frost.signing_state(0, 0)?,
// SigningState::Complete);             let signature = app.frost.signature(0,
// 0)?.unwrap().inner;             let group_key =
// &app.frost.group_pubkey(0)?.unwrap().inner;             let signing_params =
// SigningParameters {                 tapscript_merkle_root: Some(vec![0]),
//             };

//             assert!(group_key
//                 .verifying_key()
//                 .effective_key(&signing_params)
//                 .verify([1, 2, 3], &signature)
//                 .is_ok());

//             Ok(())
//         })?;

//         Ok(())
//     }
// }
