#![allow(clippy::type_complexity)]

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
pub use encoding::{Adapter, Encrypted};
use frost_secp256k1_tr::keys::{dkg as frost_dkg, PublicKeyPackage};
use frost_secp256k1_tr::round1::SigningCommitments;
use frost_secp256k1_tr::round2::SignatureShare;
use frost_secp256k1_tr::{Identifier, Signature, SigningPackage};

use self::dkg::{Dkg, DkgState};
use self::signing::{Signing, SigningState};
use crate::bitcoin::threshold_sig::Pubkey;

#[orga]
#[derive(Debug, Clone)]
pub struct Config {
    /// The number of shares required to sign a message.
    pub threshold: u16,
    /// The participants in the group, with their respective addresses and share
    /// counts.
    pub participants: LengthVec<u16, Participant>,
}

impl Config {
    /// Creates a new [`Config`] with the given parameters from the [`Staking`]
    /// state.
    ///
    /// The `top_n` validators with the highest stake are selected to
    /// participate in the group, ignoring any validators considered absent
    /// (via the `absent` set).
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

    /// Returns the total number of shares in the group.
    pub fn total_shares(&self) -> u16 {
        self.participants.iter().map(|p| p.shares).sum()
    }

    /// Returns `true` if the given address is a participant in the group.
    pub fn contains(&self, address: Address) -> bool {
        self.participants.iter().any(|p| p.address == address)
    }

    /// Returns the range of shares for which the given address is responsible.
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

    pub fn nth_quorum(&self, n: u32) -> HashSet<Address> {
        let mut participants = self.participants.clone();

        let len = participants.len();
        let mut factorials = vec![1; len];
        for i in 1..len {
            factorials[i] = factorials[i - 1] * i;
        }

        let mut n = n as usize;
        let mut perm = Vec::with_capacity(len);
        for i in (1..=len).rev() {
            let idx = n / factorials[i - 1];
            n %= factorials[i - 1];
            perm.push(participants.remove(idx));
        }

        let mut res = HashSet::new();
        let mut total_shares = 0;
        for p in perm {
            res.insert(p.address);
            total_shares += p.shares;
            if total_shares >= self.threshold {
                break;
            }
        }
        res
    }
}

/// A single Frost group.
#[orga]
pub struct FrostGroup {
    /// The configuration for this group, describing the share distribution and
    /// signing parameters.
    pub config: Config,
    /// The Distributed Key Generation state for this group.
    pub dkg: dkg::Dkg,
    /// A queue of messages signed by or requiring signatures from this group.
    pub signing: Deque<Signing>,
    /// The timestamp at which this group was created in unix seconds.
    pub created_at: i64,
}

/// The main Frost module, which manages a queue of [`FrostGroup`]s.
#[orga]
pub struct Frost {
    /// A queue of groups.
    pub groups: Deque<FrostGroup>,
}

/// A participant in a Frost group.
#[orga]
#[derive(Debug, Clone)]
pub struct Participant {
    /// The operator address of the participant.
    pub address: Address,
    /// The number of shares the participant has in the group.
    pub shares: u16,
}

impl FrostGroup {
    /// Creates a new [`FrostGroup`] with the given [`Config`] and current
    /// timestamp.
    pub fn with_config(config: Config, now: i64) -> Result<Self> {
        let dkg = Dkg::from_config(&config)?;
        Ok(Self {
            config,
            dkg,
            signing: Deque::new(),
            created_at: now,
        })
    }

    /// Adds a new message for this group to sign.
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

    /// Submits the round 1 DKG packages for this group. `packages.len()` must
    /// equal the number of shares controlled by the calling participant.
    ///
    /// See [`frost_secp256k1_tr::keys::dkg::part1`].
    pub fn submit_dkg_round1(
        &mut self,
        packages: LengthVec<u16, (Adapter<frost_dkg::round1::Package>, Pubkey)>,
    ) -> Result<()> {
        let packages: Vec<_> = packages.into();
        let address = self.signer()?;
        let share_range = self.config.share_range(address)?;
        if share_range.len() != packages.len() {
            return Err(Error::App("Invalid number of packages".into()));
        }

        log::debug!(
            "DKG round 1 submitted by {} {:?}",
            &address,
            &share_range.clone().collect::<Vec<_>>()
        );
        for (offset, (package, comm_pubkey)) in packages.into_iter().enumerate() {
            let participant = share_range.start + offset as u16;
            self.dkg.submit_round1(participant, package, comm_pubkey)?;
        }

        Ok(())
    }

    /// Submits the round 2 DKG packages for this group.
    ///
    /// See [`frost_secp256k1_tr::keys::dkg::part2`].
    pub fn submit_dkg_round2(
        &mut self,
        packages: LengthVec<
            u16,
            LengthVec<u16, (u16, Encrypted<Adapter<frost_dkg::round2::Package>>)>,
        >,
    ) -> Result<()> {
        let packages: Vec<_> = packages.into();
        let address = self.signer()?;
        let share_range = self.config.share_range(address)?;
        if share_range.len() != packages.len() {
            return Err(Error::App("Invalid number of packages".into()));
        }

        log::debug!(
            "DKG round 2 submitted by {} {:?}",
            &address,
            &share_range.clone().collect::<Vec<_>>()
        );
        for (offset, packages) in packages.into_iter().enumerate() {
            let participant = share_range.start + offset as u16;

            self.dkg.submit_round2(participant, packages)?;
        }

        Ok(())
    }

    /// Submits the DKG public key package for this group. `pubkey_package`
    /// will be the result of a successful DKG round 2, and must be attested to
    /// by all participants in the group to complete the DKG process.
    pub fn attest_pubkey_package(
        &mut self,
        pubkey_package: Adapter<PublicKeyPackage>,
    ) -> Result<()> {
        let address = self.signer()?;
        let share_range = self.config.share_range(address)?;

        log::debug!(
            "DKG attest pubkey by {} {:?}",
            &address,
            &share_range.clone().collect::<Vec<_>>()
        );
        for i in share_range {
            self.dkg.attest_pubkey_package(i, pubkey_package.clone())?;
        }

        Ok(())
    }

    /// Submits the round 1 signing commitments for a single participant in this
    /// group.
    ///
    /// See [`frost_secp256k1_tr::round1::commit`].
    pub fn submit_commitments(
        &mut self,
        sig_index: u64,
        iteration: u32,
        commitments: LengthVec<u16, Adapter<SigningCommitments>>,
    ) -> Result<()> {
        let address = self.signer()?;
        if iteration > 0 {
            let quorum = self.config.nth_quorum(iteration);
            if !quorum.contains(&address) {
                return Err(Error::App("Not in quorum".into()));
            }
        }
        let share_range = self.config.share_range(address)?;
        let mut sig = self
            .signing
            .get_mut(sig_index)?
            .ok_or(Error::App("Signing not found".into()))?;
        let commitments: Vec<Adapter<SigningCommitments>> = commitments.into();

        log::debug!(
            "Signing round 1 submitted by {} {:?} iteration {}",
            &address,
            &share_range.clone().collect::<Vec<_>>(),
            iteration
        );

        for (i, commitment) in commitments.into_iter().enumerate() {
            let participant = share_range.start + i as u16;
            sig.submit_commitments(iteration, participant, commitment)?;
            if sig.state() == SigningState::Round2 {
                break;
            }
        }

        Ok(())
    }

    /// Submits the round 2 signature shares for a single participant in this
    /// group.
    ///
    /// See [`frost_secp256k1_tr::round2::sign`].
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

        log::debug!(
            "Signing round 2 submitted by {} {:?} iteration {}",
            &address,
            &share_range.clone().collect::<Vec<_>>(),
            iteration
        );

        for (i, share) in shares.into_iter().enumerate() {
            let participant = share_range.start + i as u16;
            sig.submit_sig_share(iteration, participant, share, pubkey_package)?;
        }

        Ok(())
    }

    /// Advances to the next signing iteration for this group if the
    /// signing process has not been completed within the provided timeout.
    /// `timeout` is the number of seconds since the beginning of the current
    /// iteration.
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

    /// Returns the set of participant addresses that are absent from this
    /// group's DKG process.
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

    /// Submits a participant's round 1 DKG packages for the provided
    /// group index.
    ///
    /// See [`FrostGroup::submit_dkg_round1`].
    #[call]
    pub fn submit_dkg_round1(
        &mut self,
        index: u64,
        packages: LengthVec<u16, (Adapter<frost_dkg::round1::Package>, Pubkey)>,
    ) -> Result<()> {
        disable_fee();
        let mut group = self
            .groups
            .get_mut(index)?
            .ok_or(Error::App("Sig not found".into()))?;

        group.submit_dkg_round1(packages)
    }

    /// Submits the participant's round 2 DKG packages for the provided
    /// group index.
    ///
    /// See [`FrostGroup::submit_dkg_round2`].
    #[call]
    pub fn submit_dkg_round2(
        &mut self,
        index: u64,
        packages: LengthVec<
            u16,
            LengthVec<u16, (u16, Encrypted<Adapter<frost_dkg::round2::Package>>)>,
        >,
    ) -> Result<()> {
        disable_fee();
        let mut group = self
            .groups
            .get_mut(index)?
            .ok_or(Error::App("Sig not found".into()))?;

        group.submit_dkg_round2(packages)
    }

    /// Submits the participant's DKG public key attestation package for the
    /// provided group index.
    ///
    /// See [`FrostGroup::attest_pubkey_package`].
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

    /// Submits the participant's round 1 signing commitments for the provided
    /// group index.
    ///
    /// See [`FrostGroup::submit_commitments`].
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

    /// Submits the participant's round 2 signature shares for the provided
    /// group index.
    ///
    /// See [`FrostGroup::submit_sig_shares`].
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

    /// Returns the round 1 DKG packages for the provided group index.
    #[query]
    pub fn dkg_round1_packages(
        &self,
        index: u64,
    ) -> Result<Vec<(u16, (frost_dkg::round1::Package, Pubkey))>> {
        self.groups
            .get(index)?
            .map(|sig| sig.dkg.round1_packages())
            .ok_or(Error::App("Sig not found".into()))?
    }

    /// Returns the round 2 DKG packages for the provided group index and
    /// receiver share index.
    #[query]
    pub fn dkg_round2_packages(
        &self,
        index: u64,
        receiver: u16,
    ) -> Result<Vec<(u16, Encrypted<Adapter<frost_dkg::round2::Package>>)>> {
        self.groups
            .get(index)?
            .map(|sig| sig.dkg.round2_packages(receiver))
            .ok_or(Error::App("Sig not found".into()))?
    }

    /// Returns the current DKG state for the provided group index.
    #[query]
    pub fn dkg_state(&self, index: u64) -> Result<DkgState> {
        self.groups
            .get(index)?
            .map(|group| group.dkg.state())
            .ok_or(Error::App("Group not found".into()))
    }

    /// Returns the current signing state for a single message within a group's
    /// message queue.
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

    /// Returns the current signing state and iteration for a single message
    /// within a group's message queue.
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

    /// Returns the configuration for the provided group index.
    #[query]
    pub fn config(&self, index: u64) -> Result<Config> {
        self.groups
            .get(index)?
            .map(|sig| sig.config.clone())
            .ok_or(Error::App("Sig not found".into()))
    }

    /// Returns the current DKG group public key for the provided group index,
    /// if the DKG process has been completed.
    #[query]
    pub fn group_pubkey(&self, index: u64) -> Result<Option<Adapter<PublicKeyPackage>>> {
        self.groups
            .get(index)?
            .ok_or(Error::App("Sig not found".into()))?
            .dkg
            .group_pubkey()
    }

    /// Returns the group indices for which the provided participant address
    /// requires DKG participation (which currently may only be the most recent
    /// group).
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

    /// Returns the group indices and signing indices for which action is
    /// required from the provided participant address.
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

    /// Returns the [`SigningPackage`] for a single message within a group's
    /// message queue.
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

    /// Returns the completed signature for a message within a group's message
    /// queue.
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

    /// Returns the index of the latest group to have successfully generated a
    /// key.
    #[query]
    pub fn most_recent_with_key(&self) -> Result<Option<u64>> {
        for i in (0..self.groups.len()).rev() {
            if self.group_pubkey(i)?.is_some() {
                return Ok(Some(i));
            }
        }

        Ok(None)
    }

    #[query]
    pub fn completed_groups_for_address(&self, address: Address) -> Result<Vec<(u64, Vec<u16>)>> {
        let mut res = vec![];
        for i in 0..self.groups.len() {
            let group = self
                .groups
                .get(i)?
                .ok_or(Error::App("Group not found".into()))?;
            if group.dkg.state() == DkgState::Complete && group.config.contains(address) {
                let shares = group.config.share_range(address)?;
                res.push((i, shares.collect()));
            }
        }
        Ok(res)
    }

    /// Advances to the next signing iteration for all groups according to the
    /// provided `timeout` limit in seconds.
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

/// Returns an [`Identifier`] for the provided participant index.
fn identifier(participant_index: u16) -> Identifier {
    Identifier::try_from(participant_index + 1).unwrap()
}

/// Assembles a collection of items by their participant index (converted to an
/// [`Identifier`] as required by the operations in [`frost_secp256k1_tr`]).
fn assemble_by_identifier<T>(packages: impl Iterator<Item = (u16, T)>) -> BTreeMap<Identifier, T> {
    packages
        .map(|(i, p)| (identifier(i), p))
        .collect::<BTreeMap<_, _>>()
}

/// Disassembles a map of items indexed by [`Identifier`] into a vector of
/// tuples of participant index and items, using the indexing scheme of the
/// [`Frost`] module.
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use frost_secp256k1_tr::SigningParameters;

    use orga::client::mock::MockClient;
    use orga::client::wallet::DerivedKey;
    use orga::client::AppClient;

    use orga::context::Context;
    use orga::state::State;
    use orga::store::{Read, Store, Write};
    use serial_test::serial;
    use signer::AuxSigner;

    use self::signer::Signer;
    use crate::app::{App as TestApp, InnerApp};
    use orga::plugins::ABCIPlugin;
    type App = ABCIPlugin<TestApp>;

    use super::*;

    fn setup(mut store: Store, config: Config, aux: bool) -> Result<()> {
        let mut app = App::default();
        app.attach(store.clone())?;

        {
            app.inner.inner.borrow_mut().inner.inner.chain_id = vec![3, 3, 3].try_into()?;
            let inner_app: &mut InnerApp = &mut app
                .inner
                .inner
                .borrow_mut()
                .inner
                .inner
                .inner
                .inner
                .inner
                .inner;

            let frost = if aux {
                &mut inner_app.aux_frost
            } else {
                &mut inner_app.frost
            };
            frost
                .groups
                .push_back(FrostGroup::with_config(config, 0)?)?;
        };

        let mut bytes = vec![];
        app.flush(&mut bytes)?;
        store.put(vec![], bytes)?;

        Ok(())
    }

    fn with_app<F: FnMut(&mut InnerApp) -> Result<T>, T>(mut store: Store, mut op: F) -> Result<T> {
        let bytes = store.get(&[])?.unwrap_or_default();
        let app: App = State::load(store.clone(), &mut bytes.as_slice())?;
        let res = {
            let inner_app: &mut InnerApp = &mut app
                .inner
                .inner
                .borrow_mut()
                .inner
                .inner
                .inner
                .inner
                .inner
                .inner;

            op(inner_app)?
        };
        let mut bytes = vec![];
        app.flush(&mut bytes)?;

        store.put(vec![], bytes)?;

        Ok(res)
    }

    #[tokio::test]
    #[serial]
    async fn two_signers_basic() -> Result<()> {
        Context::add(Time::from_seconds(0));
        let store = Store::with_map_store();
        let config = Config {
            threshold: 2,
            participants: vec![
                Participant {
                    address: DerivedKey::new(b"alice")?.address(),
                    shares: 1,
                },
                Participant {
                    address: DerivedKey::new(b"bob")?.address(),
                    shares: 1,
                },
            ]
            .try_into()?,
        };
        setup(store.clone(), config, false)?;

        let make_signer = |store: Store, name: &[u8]| {
            let secret_store = Store::with_map_store();
            let name = name.to_vec();
            let name_clone = name.clone();
            let make_client = move || {
                let mock_client = MockClient::<App>::with_store(store.clone());
                let wallet = DerivedKey::new(&name_clone).unwrap();
                AppClient::<_, _, _, _, _>::new(mock_client, wallet)
            };
            Signer::new(
                secret_store,
                make_client,
                DerivedKey::new(&name).unwrap().address(),
            )
        };

        let mut alice = make_signer(store.clone(), b"alice");
        let mut bob = make_signer(store.clone(), b"bob");

        with_app(store.clone(), |app| {
            let group = app.frost.groups.front_mut().unwrap().unwrap();
            assert_eq!(group.dkg.state(), DkgState::Round1);
            Ok(())
        })?;
        alice.step().await?;
        bob.step().await?;
        with_app(store.clone(), |app| {
            let group = app.frost.groups.front_mut().unwrap().unwrap();
            assert_eq!(group.dkg.state(), DkgState::Round2);
            Ok(())
        })?;

        alice.step().await?;
        bob.step().await?;
        with_app(store.clone(), |app| {
            let group = app.frost.groups.front_mut().unwrap().unwrap();
            assert_eq!(group.dkg.state(), DkgState::Attesting);
            Ok(())
        })?;

        alice.step().await?;
        bob.step().await?;

        with_app(store.clone(), |app| {
            let group = app.frost.groups.front_mut().unwrap().unwrap();
            assert_eq!(group.dkg.state(), DkgState::Complete);
            Ok(())
        })?;

        alice.step().await?;
        bob.step().await?;

        with_app(store.clone(), |app| {
            let mut group = app.frost.groups.front_mut().unwrap().unwrap();
            assert_eq!(group.dkg.state(), DkgState::Complete);

            group.push_message(vec![1, 2, 3].try_into()?)?;

            assert_eq!(app.frost.signing_state(0, 0)?, SigningState::Round1);

            Ok(())
        })?;

        alice.step().await?;
        bob.step().await?;

        with_app(store.clone(), |app| {
            assert_eq!(app.frost.signing_state(0, 0)?, SigningState::Round2);

            Ok(())
        })?;

        alice.step().await?;
        bob.step().await?;

        with_app(store.clone(), |app| {
            assert_eq!(app.frost.signing_state(0, 0)?, SigningState::Complete);
            let signature = app.frost.signature(0, 0)?.unwrap().inner;
            let group_key = &app.frost.group_pubkey(0)?.unwrap().inner;
            let signing_params = SigningParameters {
                tapscript_merkle_root: None,
            };

            assert!(group_key
                .verifying_key()
                .effective_key(&signing_params)
                .verify([1, 2, 3], &signature)
                .is_ok());

            Ok(())
        })?;

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn aux_signers_full() -> Result<()> {
        Context::add(Time::from_seconds(0));
        let store = Store::with_map_store();
        let config = Config {
            threshold: 3,
            participants: (0..4)
                .map(|i| Participant {
                    address: DerivedKey::new(&[i as u8]).unwrap().address(),
                    shares: if i == 0 { 2 } else { 1 },
                })
                .collect::<Vec<_>>()
                .try_into()?,
        };

        setup(store.clone(), config, true)?;

        let make_signer = |store: Store, name: &[u8]| {
            let secret_store = Store::with_map_store();
            let name = name.to_vec();
            let name_clone = name.clone();
            let make_client = move || {
                let mock_client = MockClient::<App>::with_store(store.clone());
                let wallet = DerivedKey::new(&name_clone).unwrap();
                AppClient::<_, _, _, _, _>::new(mock_client, wallet)
            };
            AuxSigner::new(
                secret_store,
                make_client,
                DerivedKey::new(&name).unwrap().address(),
            )
        };

        let mut signers = (0..4)
            .map(|i| make_signer(store.clone(), &[i as u8]))
            .collect::<Vec<_>>();

        for signer in signers.iter_mut() {
            signer.audit().await?;
        }

        with_app(store.clone(), |app| {
            let group = app.aux_frost.groups.front_mut().unwrap().unwrap();
            assert_eq!(group.dkg.state(), DkgState::Round1);
            Ok(())
        })?;

        for signer in signers.iter_mut() {
            signer.step().await?;
        }

        with_app(store.clone(), |app| {
            let group = app.aux_frost.groups.front_mut().unwrap().unwrap();
            assert_eq!(group.dkg.state(), DkgState::Round2);
            Ok(())
        })?;

        for signer in signers.iter_mut() {
            signer.step().await?;
        }

        with_app(store.clone(), |app| {
            let group = app.aux_frost.groups.front_mut().unwrap().unwrap();
            assert_eq!(group.dkg.state(), DkgState::Attesting);
            Ok(())
        })?;

        for signer in signers.iter_mut() {
            signer.step().await?;
        }

        with_app(store.clone(), |app| {
            let group = app.aux_frost.groups.front_mut().unwrap().unwrap();
            assert_eq!(group.dkg.state(), DkgState::Complete);
            Ok(())
        })?;

        with_app(store.clone(), |app| {
            let mut group = app.aux_frost.groups.front_mut().unwrap().unwrap();
            assert_eq!(group.dkg.state(), DkgState::Complete);

            group.push_message(vec![1, 2, 3, 4].try_into()?)?;
            group.push_message(vec![1, 2, 3, 4, 5].try_into()?)?;

            assert_eq!(app.aux_frost.signing_state(0, 0)?, SigningState::Round1);
            assert_eq!(app.aux_frost.signing_state(0, 1)?, SigningState::Round1);

            Ok(())
        })?;

        for signer in signers.iter_mut() {
            signer.step().await?;
        }

        with_app(store.clone(), |app| {
            assert_eq!(app.aux_frost.signing_state(0, 0)?, SigningState::Round2);
            assert_eq!(app.aux_frost.signing_state(0, 1)?, SigningState::Round2);

            Ok(())
        })?;

        loop {
            for signer in signers.iter_mut().take(2) {
                signer.step().await?;
            }
            if with_app(store.clone(), |app| {
                let time_ctx = Context::resolve::<Time>().unwrap();
                app.step_frost(time_ctx.seconds)?;
                time_ctx.seconds += 6 * 60;

                Ok(app.aux_frost.signing_state(0, 0)? == SigningState::Complete)
            })? {
                break;
            }
        }
        for signer in signers.iter_mut() {
            signer.audit().await?;
        }

        signers[2] = make_signer(store.clone(), &[2]);

        assert!(signers[2].audit().await.is_err());

        with_app(store.clone(), |app| {
            assert_eq!(app.aux_frost.signing_state(0, 0)?, SigningState::Complete);
            let signature1 = app.aux_frost.signature(0, 0)?.unwrap().inner;
            let signature2 = app.aux_frost.signature(0, 1)?.unwrap().inner;
            let group_key = &app.aux_frost.group_pubkey(0)?.unwrap().inner;
            let signing_params = SigningParameters {
                tapscript_merkle_root: None,
            };

            assert!(group_key
                .verifying_key()
                .effective_key(&signing_params)
                .verify([1, 2, 3, 4], &signature1)
                .is_ok());

            assert!(group_key
                .verifying_key()
                .effective_key(&signing_params)
                .verify([1, 2, 3, 4, 5], &signature2)
                .is_ok());

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn nth_quorum_3_of_5() {
        let participants = vec![
            Participant {
                address: [0; 20].into(),
                shares: 1,
            },
            Participant {
                address: [1; 20].into(),
                shares: 1,
            },
            Participant {
                address: [2; 20].into(),
                shares: 1,
            },
            Participant {
                address: [3; 20].into(),
                shares: 1,
            },
            Participant {
                address: [4; 20].into(),
                shares: 1,
            },
        ];

        let config = Config {
            threshold: 3,
            participants: participants.try_into().unwrap(),
        };

        let mut quorums = vec![];
        for i in 0..100 {
            let q = config.nth_quorum(i);
            quorums.push(q);
        }

        let unique_sets: HashSet<BTreeSet<String>> = quorums
            .iter()
            .map(|q| q.iter().map(|a| a.to_string()).collect())
            .collect();

        assert_eq!(unique_sets.len(), 10);
    }
}
